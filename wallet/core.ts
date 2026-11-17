/**
 * The reference wallet's core (bft-core#1107): one wallet directory on disk, opened on the TypeScript plug-in (`NativeBridgeV2`), and one
 * function per bridge step. The command-line wallet (nb2-wallet.ts) is a thin shell over it, and the bft-core testnet lane
 * (deploy/testnet/bridge/nb2/driver.ts) drives the same functions, so the flow the guide shows is the flow the lane tests.
 *
 * A wallet directory holds:
 *   config.json          where the deployment's files and endpoints are (written by `init`)
 *   secret.hex           the wallet secret (32 bytes, unencrypted: a test wallet), unless the config names an environment variable
 *   journal.json         the plug-in's journal (docs/nb2-journal.md); one JSON file written by rename
 *   backup.json          the intent high-water mark handed to the backup callback (a real wallet stores it with its seed backup)
 *   tokens.json          the wallet's names for its tokens; the token bytes in tokens/<name>.cbor
 *   trust-history.cbor   the trust-base history, the shipped bundle extended by refreshes
 *
 * Every key derives from the one secret: the EVM key is the secret itself, the bridge key k_w and the Unicity owner keys are tagged hashes
 * of it. That is a test derivation; a production wallet derives them from its own seed scheme.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';

import { concat, eq, toHex } from '../packages/native-bridge-plugin/src/bytes.js';
import {
  HttpJsonRpc, LocalKeySigner, NativeBridgeV2, Nb2Error, WalletError, decodeRevert, deriveBridgeKey, evidenceOf, localOwner,
  type DepositPlan, type DeploymentPins, type JournalStore, type JsonRpc, type ReconcileResult, type ReturnPlan, type ReturnRecord,
} from '../packages/native-bridge-plugin/src/nb2/index.js';
import { TrustInput } from '../packages/native-bridge-plugin/src/trust.js';
import { refreshAll } from './trust.js';

export const unhex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s.trim().replace(/^0x/, ''), 'hex'));
export const hx = (b: Uint8Array): string => `0x${toHex(b)}`;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// ---- the deployment ------------------------------------------------------------------------------------------------------------------------

/** The wallet pins of a release manifest (nb2-release.json `pins`, spec section 4.3). */
export function pinsOf(release: { pins: Record<string, unknown> }): DeploymentPins {
  const p = release.pins as Record<string, string | boolean | number>;
  return {
    gamma: unhex(p.gamma as string), build: p.build as 'test' | 'production', vaultRuntimeCodeHash: unhex(p.vaultRuntimeCodeHash as string),
    maxEncodedTxBytes: BigInt(p.maxEncodedTxBytes as number), userGasLimit: BigInt(p.userGasLimit as string), gasReserve: BigInt(p.gasReserve as string),
    returnReserveSegments: BigInt(p.returnReserveSegments as number), deploymentBlock: BigInt(p.deploymentBlock as number), stateReadOnly: p.stateReadOnly as boolean,
  };
}

/** Where a wallet finds its deployment: the release manifest, the trust bundle and its pin, and the public gateway. */
export interface Connection {
  /** nb2-release.json, as the operator publishes it */
  release: string;
  /** the trust-base bundle and its genesis EntryID pin, published beside the manifest */
  trustBundle: string;
  trustPin: string;
  /** the gateway's JSON-RPC URL and its aggregator route */
  rpc: string;
  aggregator: string;
}

/** config.json of a wallet directory: the connection, and where the secret comes from. */
export interface WalletConfig extends Connection {
  /** the environment variable holding the secret (hex); without it the secret is secret.hex in the wallet directory */
  keyEnv?: string;
}

/** A connection with the manifest's neighbours as defaults: the bundle and pin the manifest names, the gateway's /aggregator route. */
export function connectionOf(o: { release: string; rpc: string; trustBundle?: string; trustPin?: string; aggregator?: string }): Connection {
  const release = resolve(o.release);
  const m = JSON.parse(readFileSync(release, 'utf8')) as { trust?: { bundle?: string } };
  const here = dirname(release);
  return {
    release,
    trustBundle: resolve(o.trustBundle ?? join(here, m.trust?.bundle ?? 'trust-base.bundle.cbor')),
    trustPin: resolve(o.trustPin ?? join(here, 'trust-base.genesis.entryid')),
    rpc: o.rpc,
    aggregator: o.aggregator ?? `${o.rpc.replace(/\/+$/, '')}/aggregator`,
  };
}

// ---- storage ---------------------------------------------------------------------------------------------------------------------------------

/** Write a file by rename, so a crash leaves the old or the new content, never a torn one. */
function writeAtomic(file: string, data: string | Uint8Array): void {
  writeFileSync(`${file}.tmp`, data);
  renameSync(`${file}.tmp`, file);
}

/**
 * The plug-in's JournalStore as one JSON file, written by rename. Its compare-and-swap is atomic for one process at a time, which is what this
 * wallet runs (one command per process, one process per wallet directory); it is not a store for concurrent writers.
 */
export class FileJournalStore implements JournalStore {
  public constructor(private readonly file: string) {}
  private load(): Record<string, string> {
    return existsSync(this.file) ? JSON.parse(readFileSync(this.file, 'utf8')) : {};
  }
  public get(key: string): Promise<string | null> {
    return Promise.resolve(this.load()[key] ?? null);
  }
  public putIf(key: string, expected: string | null, value: string): Promise<boolean> {
    const m = this.load();
    if ((m[key] ?? null) !== expected) return Promise.resolve(false);
    m[key] = value;
    writeAtomic(this.file, JSON.stringify(m));
    return Promise.resolve(true);
  }
  public list(prefix: string): Promise<string[]> {
    return Promise.resolve(Object.keys(this.load()).filter((k) => k.startsWith(prefix)).sort());
  }
}

/** A token the wallet holds, by the name the user gave it. */
export interface TokenEntry { file: string; owner: number; amount: string; intent?: string; returnId?: string; note?: string }

// ---- the aggregator ------------------------------------------------------------------------------------------------------------------------

/** The SDK aggregator client through the gateway's /aggregator route: submit, then poll for the proof of exactly this request; a busy route is retried. */
export class GatewayAggregator {
  private readonly client: AggregatorClient;
  public constructor(url: string) {
    this.client = new AggregatorClient(url);
  }
  public async submit(request: Uint8Array): Promise<void> {
    const cd = CertificationData.fromCBOR(request);
    for (let attempt = 0; ; attempt++) {
      try {
        const r = await this.client.submitCertificationRequest(cd);
        if (!r.isAccepted && !r.isAlreadySubmitted && !r.isStateIdQueued) throw new WalletError('Reverted', `aggregator: ${r.status}`);
        return;
      } catch (e) {
        if (e instanceof WalletError || attempt >= 20) throw e;
        await sleep(1000 * (attempt + 1));
      }
    }
  }
  public async proof(request: Uint8Array, timeoutMs = 300_000): Promise<Uint8Array> {
    const cd = CertificationData.fromCBOR(request);
    const sid = await StateId.fromCertificationData(cd);
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        const p = (await this.client.getInclusionProof(sid, { waitMs: 2_000 })).inclusionProof;
        if (p !== null) {
          if (!eq(p.certificationData.toCBOR(), request)) throw new WalletError('ProviderFault', 'the aggregator certified another request for this state');
          return p.toCBOR();
        }
      } catch (e) {
        if (e instanceof WalletError) throw e;
      }
      if (Date.now() > deadline) throw new WalletError('Unconfirmed', 'no inclusion proof in time');
      await sleep(1_000);
    }
  }
  public async certify(request: Uint8Array): Promise<Uint8Array> {
    await this.submit(request);
    return this.proof(request);
  }
}

// ---- the wallet ------------------------------------------------------------------------------------------------------------------------------

const tag = (s: string): Uint8Array => new TextEncoder().encode(s);

export interface OpenOptions {
  /** run the installation check (chain ID, config() = Γ, the vault's runtime code hash); default true */
  check?: boolean;
  /** wrap the gateway RPC (the lane counts and injects broadcasts through it) */
  wrapRpc?: (rpc: HttpJsonRpc) => JsonRpc;
}

export class Wallet {
  public readonly signer: LocalKeySigner;
  public bridge!: NativeBridgeV2;
  public trust!: TrustInput;
  public readonly pins: DeploymentPins;
  public readonly release: Record<string, unknown> & { pins: Record<string, unknown> };

  /** A wallet in DIR with SECRET (32 bytes) on CONNECTION. */
  public constructor(public readonly dir: string, private readonly secret: Uint8Array, public readonly conn: Connection) {
    if (secret.length !== 32) throw new Error('the wallet secret is 32 bytes');
    mkdirSync(join(dir, 'tokens'), { recursive: true });
    this.signer = new LocalKeySigner(secret);
    this.release = JSON.parse(readFileSync(conn.release, 'utf8'));
    this.pins = pinsOf(this.release);
  }

  /** The wallet in DIR as its config.json describes it. */
  public static load(dir: string): Wallet {
    const f = join(dir, 'config.json');
    if (!existsSync(f)) throw new Error(`${dir} is not a wallet: run init first`);
    const c = JSON.parse(readFileSync(f, 'utf8')) as WalletConfig;
    let secret: string | undefined;
    if (c.keyEnv) {
      secret = process.env[c.keyEnv];
      if (!secret) throw new Error(`the wallet's secret is in ${c.keyEnv}, which is not set`);
    } else {
      secret = readFileSync(join(dir, 'secret.hex'), 'utf8');
    }
    return new Wallet(dir, unhex(secret), c);
  }

  /** The EVM key (the wallet secret): the lane signs its own measurement transactions with it. */
  public get evmKey(): Uint8Array {
    return this.secret;
  }
  /** Unicity owner key i of this wallet. */
  public ownerKey(i: number): Uint8Array {
    return sha256(concat(tag(`nb2-reference-wallet/owner/${i}/`), this.secret));
  }
  public owner(i: number) {
    return localOwner(this.ownerKey(i));
  }
  public ownerPub(i: number): Uint8Array {
    return secp256k1.getPublicKey(this.ownerKey(i), true);
  }
  public get historyFile(): string {
    return join(this.dir, 'trust-history.cbor');
  }

  /**
   * Open the plug-in: the held trust (the shipped bundle under its pin, extended by the wallet's own history), the journal, the backup of
   * the intent high-water mark and the trust refresh through the gateway's trust-base pages.
   */
  public async open(opts: OpenOptions = {}): Promise<this> {
    const pin = unhex(readFileSync(this.conn.trustPin, 'utf8'));
    const shipped = await TrustInput.fromBundle(Uint8Array.from(readFileSync(this.conn.trustBundle)), pin);
    this.trust = shipped;
    if (existsSync(this.historyFile)) {
      const held = await TrustInput.fromBundle(Uint8Array.from(readFileSync(this.historyFile)), pin);
      for (const e of shipped.history.entries) await held.history.append(e);
      this.trust = held;
    }
    const source = new AggregatorClient(this.conn.aggregator);
    const rpc = new HttpJsonRpc(this.conn.rpc, { retries: 20, timeoutMs: 120_000 });
    this.bridge = await NativeBridgeV2.open({
      pins: this.pins, trust: this.trust, rpc: opts.wrapRpc ? opts.wrapRpc(rpc) : rpc, aggregator: new GatewayAggregator(this.conn.aggregator),
      journal: new FileJournalStore(join(this.dir, 'journal.json')),
      bridgeKey: deriveBridgeKey(sha256(concat(tag('nb2-reference-wallet/seed/'), this.secret))),
      // the intent high-water mark goes with the seed backup before any deposit is sent (section 12.1): here a file beside the journal
      backup: async (intents) => writeAtomic(join(this.dir, 'backup.json'), JSON.stringify(intents)),
      refreshTrust: async () => { await refreshAll(this.trust, source, 64, (b) => writeAtomic(this.historyFile, b)); },
      receiptTimeoutMs: 180_000, pollMs: 1_000,
    }, opts.check ?? true);
    return this;
  }

  private get index(): Record<string, TokenEntry> {
    const f = join(this.dir, 'tokens.json');
    return existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : {};
  }
  private set index(idx: Record<string, TokenEntry>) {
    writeAtomic(join(this.dir, 'tokens.json'), JSON.stringify(idx, null, 2));
  }
  public labels(): string[] {
    return Object.keys(this.index).sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
  }
  public has(label: string): boolean {
    return this.index[label] !== undefined;
  }
  public entry(label: string): TokenEntry {
    const e = this.index[label];
    if (!e) throw new Error(`the wallet holds no token named ${label}`);
    return e;
  }
  public token(label: string): Uint8Array {
    return Uint8Array.from(readFileSync(join(this.dir, 'tokens', this.entry(label).file)));
  }
  public keep(label: string, token: Uint8Array, owner: number, extra: Partial<TokenEntry> = {}): void {
    if (!/^[A-Za-z0-9_.-]+$/.test(label)) throw new Error(`a token name is letters, digits, '.', '_' or '-': ${label}`);
    writeAtomic(join(this.dir, 'tokens', `${label}.cbor`), token);
    const idx = this.index;
    idx[label] = { ...(idx[label] ?? {}), file: `${label}.cbor`, owner, amount: '0', ...extra };
    this.index = idx;
  }
  public update(label: string, extra: Partial<TokenEntry>): void {
    const idx = this.index;
    idx[label] = { ...this.entry(label), ...extra };
    this.index = idx;
  }
  public async returnRecord(label: string): Promise<ReturnRecord> {
    const id = this.entry(label).returnId;
    if (!id) throw new Error(`${label} has no planned return`);
    const r = await this.bridge.journal.ret(id);
    if (r === null) throw new Error(`${label}: return ${id} is not journaled`);
    return r;
  }
}

// ---- the steps ---------------------------------------------------------------------------------------------------------------------------------

/** The rule or reason of a plug-in refusal ('' for anything else). */
export const reasonOf = (e: unknown): string => (e instanceof WalletError ? e.reason : e instanceof Nb2Error ? e.rule : '');

/** The refusals that mean "not yet": call again after a block or a moment. */
export const RETRYABLE = ['CompanionUnknown', 'Unconfirmed', 'NotPending', 'NoEntryForEpoch'];

/** F again while it refuses with a retryable reason, up to TRIES times; NOTE is told the first time and every tenth. */
export async function retry<T>(f: () => Promise<T>, note: (reason: string) => void = () => undefined, tries = 120, ms = 2_000): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await f();
    } catch (e) {
      const reason = reasonOf(e);
      if (i >= tries || !RETRYABLE.includes(reason)) throw e;
      if (i % 10 === 0) note(reason);
      await sleep(ms);
    }
  }
}

/** Deposit: plan an intent (the secret is derived, the high-water mark backed up) and journal it under LABEL. Nothing is sent. */
export async function planDeposit(w: Wallet, label: string, amount: bigint): Promise<DepositPlan> {
  if (w.has(label)) throw new Error(`the wallet already has a token named ${label}`);
  const plan = await w.bridge.planDeposit(amount, w.ownerPub(0));
  w.keep(label, new Uint8Array(), 0, { intent: plan.intent.toString(), amount: amount.toString(), note: 'deposit planned' });
  return plan;
}

/**
 * Deposit: send LABEL's planned deposit, or reconcile an earlier send (a retry never deposits twice; a deposit sent elsewhere with this
 * intent's rho is adopted). The receipt's deposit number and block.
 */
export async function sendDeposit(w: Wallet, label: string): Promise<{ txHash: Uint8Array; depositNumber: bigint; blockNumber: bigint }> {
  const e = w.entry(label);
  if (e.intent === undefined) throw new Error(`${label} is not a deposit`);
  const r = await w.bridge.submitDeposit(BigInt(e.intent), w.signer);
  w.update(label, { note: 'deposited' });
  return r;
}

/** Mint: the deposit's receipt proof J once its block is certified (retried while the certificate is not served yet), then the mint. */
export async function mint(w: Wallet, label: string, note?: (reason: string) => void): Promise<{ intent: bigint; depositNumber: bigint; reasonBytes: number; tokenId: Uint8Array; amount: bigint }> {
  const e = w.entry(label);
  if (e.intent === undefined) throw new Error(`${label} is not a deposit`);
  const intent = BigInt(e.intent);
  const p = await retry(() => w.bridge.collectDepositProof(intent), note);
  const token = await w.bridge.mint(intent);
  const v = await w.bridge.verifyToken(token);
  w.keep(label, token, 0, { intent: e.intent, amount: v.amount.toString(), note: undefined });
  return { intent, depositNumber: p.depositNumber, reasonBytes: p.reason.length, tokenId: v.tokenId, amount: v.amount };
}

/** An ordinary Unicity transfer of FROM, kept as TO: to the wallet's own owner key OWNER, or to another wallet's key TOKEY. */
export async function transfer(w: Wallet, from: string, to: string, owner: number, toKey?: Uint8Array): Promise<Uint8Array> {
  const e = w.entry(from);
  const t = await w.bridge.transfer(w.token(from), w.owner(e.owner), toKey ?? w.ownerPub(owner));
  w.keep(to, t, owner, { amount: e.amount, note: toKey ? `sent to ${hx(toKey)}` : undefined });
  return t;
}

/** Split FROM into whole parts (name, amount), all to the wallet's owner key OWNER. */
export async function split(w: Wallet, from: string, owner: number, parts: { label: string; amount: bigint }[]): Promise<Uint8Array[]> {
  const e = w.entry(from);
  for (const p of parts) if (w.has(p.label)) throw new Error(`the wallet already has a token named ${p.label}`);
  const res = await w.bridge.split(w.token(from), w.owner(e.owner), parts.map((p) => ({ ownerKey: w.ownerPub(owner), amount: p.amount })));
  res.forEach((t, i) => w.keep(parts[i].label, t, owner, { amount: parts[i].amount.toString() }));
  w.update(from, { note: `split into ${parts.map((p) => p.label).join(', ')}` });
  return res;
}

/**
 * Return, step 1: plan LABEL's return to RECIPIENT (default: the wallet's EVM address) and run the capacity preflight. Nothing is burned;
 * a refusal (CapacityPreflight, InsufficientFunds, RecipientRefused) leaves the token as it was.
 */
export async function planReturn(w: Wallet, label: string, recipient?: Uint8Array): Promise<ReturnPlan> {
  const plan = await w.bridge.planReturn(w.token(label), recipient ?? w.signer.address, w.signer.address);
  w.update(label, { returnId: hx(plan.returnId) });
  return plan;
}

/**
 * Return, step 2: burn LABEL. The plan is made again first, so the preflight runs on fresh chain state right before the irreversible step
 * (a limit measured earlier is never reused); the plug-in repeats it once more before it signs. A burned return resumes.
 */
export async function burn(w: Wallet, label: string, recipient?: Uint8Array, note?: (reason: string) => void): Promise<{ plan: ReturnPlan | null; burned: Uint8Array; eta: Uint8Array; evidenceBytes: number }> {
  const e = w.entry(label);
  let plan: ReturnPlan | null = null;
  const rec = e.returnId ? await w.bridge.journal.ret(e.returnId) : null;
  if (rec === null || rec.status === 'planned') plan = await planReturn(w, label, recipient);
  const b = await retry(() => w.bridge.burn(unhex(w.entry(label).returnId!), w.owner(e.owner)), note);
  w.update(label, { note: 'burned' });
  return { plan, burned: b.burned, eta: b.eta, evidenceBytes: evidenceOf(b.burned).length };
}

/**
 * The deployed verifier's QuorumNotMet inside VerifierRefused: right after a burn's certification the EVM chain's seal registry may not have
 * imported the root round the burn's certificate names yet, and on chain that reads as a bad quorum (bft-core#1125). The plug-in and the Go
 * reference accept the same bytes; the vault accepts them a few blocks later.
 */
export function isRegistryLag(e: unknown): boolean {
  if (!(e instanceof Nb2Error) || e.rule !== 'VerifierRefused' || typeof e.args?.[0] !== 'string') return false;
  return decodeRevert(unhex(e.args[0]))?.rule === 'QuorumNotMet';
}

/** How long a redemption waits out the registry lag (#1125) before it reports the refusal. */
export const REGISTRY_LAG_MS = 120_000;

/**
 * Return, step 3: redeem LABEL's burn on the EVM: the witness (one SegmentSealed log per segment since the burn's index, the gap proofs) is
 * built from the chain, sent, and reconciled until the payment's block is certified. A paid return answers paid without a send. A
 * QuorumNotMet from the verifier within REGISTRY_LAG_MS of the first try is the registry lag of #1125: wait and build again (the burn
 * never changes); after that it is reported.
 */
export async function redeem(w: Wallet, label: string, polls = 60, pollMs = 3_000, note: (reason: string) => void = () => undefined): Promise<ReconcileResult> {
  const id = unhex((await w.returnRecord(label)).returnId);
  const t0 = Date.now();
  let r: ReconcileResult;
  for (let told = false; ; ) {
    try {
      r = await w.bridge.submitRedeem(id, w.signer);
      break;
    } catch (e) {
      if (!isRegistryLag(e) || Date.now() - t0 > REGISTRY_LAG_MS) throw e;
      if (!told) note('the verifier answers QuorumNotMet: the seal registry has not imported the burn\'s root round yet (#1125)');
      told = true;
      await sleep(pollMs);
    }
  }
  for (let i = 0; r.state === 'pending' && i < polls; i++) {
    await sleep(pollMs);
    r = await w.bridge.reconcile(id);
  }
  if (r.state === 'paid') w.update(label, { note: 'paid' });
  return r;
}

/** What to run next for a deposit or a return, by its journal status. */
const NEXT_DEPOSIT: Record<string, string> = { planned: 'deposit', submitted: 'deposit', deposited: 'mint', proven: 'mint' };
const NEXT_RETURN: Record<string, string> = { planned: 'burn', 'burn-requested': 'burn', burned: 'redeem', submitted: 'redeem' };

/**
 * Where every deposit and return stands, by token name: the plug-in's wording (bridge.status), the command that moves it on, and for a burn
 * the history its redemption owes (one gap proof per sealed segment since its index).
 */
export async function status(w: Wallet): Promise<string[]> {
  const byIntent = new Map<string, string>();
  const byReturn = new Map<string, string>();
  for (const l of w.labels()) {
    const e = w.entry(l);
    if (e.intent !== undefined && !byIntent.has(e.intent)) byIntent.set(e.intent, l);
    if (e.returnId !== undefined) byReturn.set(e.returnId.toLowerCase(), l);
  }
  const st = await w.bridge.evm.vaultState(w.bridge.cfg.vault);
  const lines: string[] = [`vault ${hx(w.bridge.cfg.vault)}: segment ${st.segment}, ${st.deposits} deposits, ${st.outstanding} wei outstanding`];
  const words = await w.bridge.status();
  const deposits = await w.bridge.journal.deposits();
  const returns = await w.bridge.journal.returns();
  deposits.forEach((d, i) => {
    const l = byIntent.get(d.intent);
    const next = NEXT_DEPOSIT[d.status];
    lines.push(`${l ?? '?'}: ${words[i]}${d.depositNumber ? ` (deposit ${d.depositNumber}, block ${d.blockNumber})` : ''}${next && l ? `; next: ${next} ${l}` : ''}`);
  });
  returns.forEach((r, i) => {
    const l = byReturn.get(r.returnId.toLowerCase());
    const next = NEXT_RETURN[r.status];
    const owed = r.status === 'burned' || r.status === 'submitted' ? `; the witness proves ${st.segment - BigInt(r.a)} sealed segments` : '';
    lines.push(`${l ?? '?'}: ${words[deposits.length + i]}${owed}${next && l ? `; next: ${next} ${l}` : ''}`);
  });
  return lines;
}
