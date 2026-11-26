/**
 * The reference wallet's core (bft-core#1107): one wallet directory on disk, opened on the TypeScript plug-in (`NativeBridgeV2`), and one
 * function per bridge step. The command-line wallet (nb2-wallet.ts) is a thin shell over it, and the bft-core testnet lane
 * (deploy/testnet/bridge/nb2/driver.ts) drives the same functions, so the flow the guide shows is the flow the lane tests.
 *
 * A wallet directory holds:
 *   config.json          where the deployment's files and endpoints are (written by `init`, once the installation check passed)
 *   secret.hex           the wallet secret (32 bytes, unencrypted: a test wallet), unless the config names an environment variable
 *   journal.json         the plug-in's journal (docs/nb2-journal.md); one JSON file
 *   backup.json          the intent high-water mark handed to the backup callback (a real wallet stores it with its seed backup)
 *   tokens.json          the wallet's names for its tokens; the token bytes in tokens/<name>.cbor
 *   tokens/<name>.pending.json   a transfer between its request and its saved result (the one step the plug-in does not journal)
 *   trust-history.cbor   the trust-base history, the shipped bundle extended by refreshes
 *   lock                 held by the one process that uses the wallet
 *
 * Every file is written durably: a temporary file, fsynced, renamed over the old one, then the directory fsynced. A write has returned only
 * once it survives a power loss, which is what the journal contract asks of `putIf`.
 *
 * Every key derives from the one secret: the EVM key is the secret itself, the bridge key k_w and the Unicity owner keys are tagged hashes
 * of it. That is a test derivation; a production wallet derives them from its own seed scheme.
 */
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type { ITrustBaseSource } from '@unicitylabs/state-transition-sdk/lib/api/ITrustBaseSource.js';
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { RootTrustBaseV2 } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/RootTrustBaseV2.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';

import { concat, eq, toHex } from '../packages/native-bridge-plugin/src/bytes.js';
import {
  HttpJsonRpc, LocalKeySigner, NativeBridgeV2, PRODUCTION_TRUST_FRESHNESS_MS, TESTNET_TRUST_FRESHNESS_MS, Nb2Error, RpcError, WalletError, appendTransfer, certifyChecked, decodeToken, deriveBridgeKey, evidenceOf,
  freshMask, localOwner, transferRequest, verifyHeld,
  type Aggregator, type DepositPlan, type DeploymentPins, type GasModel, type JournalStore, type JsonRpc, type ReconcileResult, type ReturnPlan,
  type ReturnRecord,
} from '../packages/native-bridge-plugin/src/nb2/index.js';
import { HU, parseKey } from '../packages/native-bridge-plugin/src/nb2/crypto.js';
import { signaturePredicate } from '../packages/native-bridge-plugin/src/nb2/token.js';
import { transferProofLimit } from '../packages/native-bridge-plugin/src/nb2/tokenops.js';
import { isCertificationTrustPending } from '../packages/native-bridge-plugin/src/nb2/trust.js';
import { TrustInput } from '../packages/native-bridge-plugin/src/trust.js';
import { hasPeerComplete, pollOrdinaryPayout, qualifyExistingRecovery, redeemOrdinary, recoverStep, retainTerminal, returnHeadroom, walletAdmission, type PayerPolicy, type RecoveryResult } from './recovery.js';
import { refreshAll } from './trust.js';

export const unhex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s.trim().replace(/^0x/, ''), 'hex'));
export const hx = (b: Uint8Array): string => `0x${toHex(b)}`;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// ---- amounts -------------------------------------------------------------------------------------------------------------------------------

const DECIMALS = 18n;

/** AMOUNT UCT as wei: a decimal with at most 18 fractional digits. */
export function parseAmount(s: string): bigint {
  const m = /^(\d+)(?:\.(\d{1,18}))?$/.exec(s);
  if (!m) throw new Error(`not an amount: ${s} (UCT, for example 0.25)`);
  const wei = BigInt(m[1]) * 10n ** DECIMALS + BigInt((m[2] ?? '').padEnd(Number(DECIMALS), '0') || '0');
  if (wei === 0n) throw new Error('an amount is positive');
  return wei;
}

/** wei as a UCT decimal, without trailing zeros (what parseAmount reads back). */
export function uct(wei: bigint | string): string {
  const w = BigInt(wei);
  const whole = w / 10n ** DECIMALS;
  const frac = (w % 10n ** DECIMALS).toString().padStart(Number(DECIMALS), '0').replace(/0+$/, '');
  return `${whole}${frac ? `.${frac}` : ''}`;
}

// ---- the deployment ------------------------------------------------------------------------------------------------------------------------

/** The wallet pins of a release manifest (nb2-release.json `pins`, spec section 4.3). */
export function pinsOf(release: { pins: Record<string, unknown> }): DeploymentPins {
  const p = release.pins as Record<string, string | boolean | number>;
  return {
    gamma: unhex(p.gamma as string), build: p.build as 'test' | 'production', vaultRuntimeCodeHash: unhex(p.vaultRuntimeCodeHash as string),
    maxEncodedTxBytes: BigInt(p.maxEncodedTxBytes as number), userGasLimit: BigInt(p.userGasLimit as string), gasReserve: BigInt(p.gasReserve as string),
    returnReserveSegments: BigInt(p.returnReserveSegments as number), deploymentBlock: BigInt(p.deploymentBlock as number), stateReadOnly: p.stateReadOnly as boolean,
    ...(typeof p.nativeGasSchedule === 'string' ? { nativeGasSchedule: p.nativeGasSchedule } : {}),
  };
}

/** Where a wallet finds its deployment: the release manifest, the trust bundle and its pin, and the public gateway. */
export interface Connection {
  /** nb2-release.json, as the operator publishes it */
  release: string;
  /** the trust-base bundle and its genesis EntryID pin, published beside the manifest */
  trustBundle: string;
  trustPin: string;
  rpc: string;
  aggregator: string;
}

/** config.json of a wallet directory: the connection, and where the secret comes from. */
export interface WalletConfig extends Connection {
  /** the environment variable holding the secret (hex); without it the secret is secret.hex in the wallet directory */
  keyEnv?: string;
}

/** A connection with the manifest's neighbours as defaults: the bundle and pin the manifest names, the gateway's /aggregator route, a sibling of the RPC path (the release names no aggregator URL). */
export function connectionOf(o: { release: string; rpc: string; trustBundle?: string; trustPin?: string; aggregator?: string }): Connection {
  const release = resolve(o.release);
  const m = JSON.parse(readFileSync(release, 'utf8')) as { trust?: { bundle?: string } };
  const here = dirname(release);
  return {
    release,
    trustBundle: resolve(o.trustBundle ?? join(here, m.trust?.bundle ?? 'trust-base.bundle.cbor')),
    trustPin: resolve(o.trustPin ?? join(here, 'trust-base.genesis.entryid')),
    rpc: o.rpc,
    aggregator: o.aggregator ?? `${new URL(o.rpc).origin}/aggregator`,
  };
}

// ---- storage ---------------------------------------------------------------------------------------------------------------------------------

/** Test seams: the fsync the durable writes use, and a hook told when a file's new content is durable (what survives a power loss). */
export const io = {
  fsync: (fd: number): void => fsyncSync(fd),
  durable: (_file: string, _data: string | Uint8Array | null): void => undefined,
};

export function fsyncDir(dir: string): void {
  const fd = openSync(dir, 'r');
  try {
    io.fsync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Write FILE durably: a temporary file, fsynced, renamed over the old one, then the directory fsynced. A crash or a power loss leaves the old
 * or the new content, never a torn one, and the new content survives once this returns. MODE applies to a new file.
 */
export function writeDurable(file: string, data: string | Uint8Array, mode = 0o600): void {
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, 'w', mode);
  try {
    const b = typeof data === 'string' ? Buffer.from(data) : data;
    for (let at = 0; at < b.length;) at += writeSync(fd, b, at, b.length - at);
    io.fsync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  fsyncDir(dirname(file));
  io.durable(file, data);
}

/** Remove FILE durably (the directory fsynced). */
export function removeDurable(file: string): void {
  if (!existsSync(file)) return;
  unlinkSync(file);
  fsyncDir(dirname(file));
  io.durable(file, null);
}

/**
 * The exclusive lock of a wallet directory: the file `lock` holds the owner's process ID and host. A lock left by a process that no longer
 * runs on this host is taken over; one held elsewhere (another live process, or another host or container, whose liveness this process
 * cannot see) refuses, naming the file to delete once nothing else uses the wallet. Released when the process exits.
 */
export function lockWallet(dir: string): void {
  const file = join(dir, 'lock');
  const me = { pid: process.pid, host: hostname() };
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(file, 'wx', 0o600);
      writeSync(fd, JSON.stringify({ ...me, at: new Date().toISOString() }));
      io.fsync(fd);
      closeSync(fd);
      process.once('exit', () => {
        try {
          const held = JSON.parse(readFileSync(file, 'utf8')) as { pid: number; host: string };
          if (held.pid === me.pid && held.host === me.host) unlinkSync(file);
        } catch { /* gone already */ }
      });
      return;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    }
    let held: { pid?: number; host?: string; at?: string } = {};
    try {
      held = JSON.parse(readFileSync(file, 'utf8'));
    } catch { /* a torn lock file is treated as held */ }
    if (held.pid === me.pid && held.host === me.host) return; // this process holds it already
    let alive = true;
    if (held.host === me.host && typeof held.pid === 'number') {
      try {
        process.kill(held.pid, 0);
      } catch (e) {
        alive = (e as NodeJS.ErrnoException).code === 'EPERM';
      }
    }
    if (alive) throw new Error(`the wallet ${dir} is in use by process ${held.pid ?? '?'} on ${held.host ?? '?'} (since ${held.at ?? '?'}): one process per wallet. If nothing else uses it, delete ${file}`);
    unlinkSync(file); // its owner no longer runs
  }
  throw new Error(`could not lock the wallet ${dir}`);
}

/**
 * The plug-in's JournalStore as one JSON file, written durably (writeDurable). Its compare-and-swap is atomic within one process; the wallet
 * lock (lockWallet) keeps every other process out of the directory, so `putIf` meets the journal contract (docs/nb2-journal.md): atomic, and
 * durable once it resolves.
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
    writeDurable(this.file, JSON.stringify(m));
    return Promise.resolve(true);
  }
  public list(prefix: string): Promise<string[]> {
    return Promise.resolve(Object.keys(this.load()).filter((k) => k.startsWith(prefix)).sort());
  }
}

/** A token the wallet holds, by the name the user gave it. `spent` says why it is no longer held (split, transferred, burned, sent). */
export interface TokenEntry { file: string; owner: number; amount: string; intent?: string; returnId?: string; authorizedRecipient?: string; note?: string; spent?: string; splitInto?: string[] }

/** A transfer between its request and its saved result: tokens/<to>.pending.json. */
interface PendingTransfer { from: string; to: string; owner: number; toKey?: string; tx: string; cd: string; proof?: string }

const NAME = /^[A-Za-z0-9_.-]{1,64}$/;
const PENDING = 'transfer pending as ';
const BURNED = 'burned for its return';
const BURNING = 'burn in progress';
/** A spent mark a return's own steps may pass: the token is being, or has been, burned for it. */
const burnMark = (sp: string | undefined): boolean => sp === BURNED || sp === BURNING;

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
    const cd = CertificationData.fromCBOR(request);
    const sid = await StateId.fromCertificationData(cd);
    let existing;
    try {
      existing = (await this.client.getInclusionProof(sid, { waitMs: 0 })).inclusionProof;
    } catch {
      // The exact same request can be submitted if the read is unavailable.
    }
    if (existing) {
      if (!eq(existing.certificationData.toCBOR(), request)) throw new WalletError('ProviderFault', 'the aggregator certified another request for this state');
      return existing.toCBOR();
    }
    await this.submit(request);
    return this.proof(request);
  }
}

// ---- the wallet ------------------------------------------------------------------------------------------------------------------------------

const tag = (s: string): Uint8Array => new TextEncoder().encode(s);

export interface OpenOptions {
  trustFreshnessMs?: number;
  /** run the installation check (chain ID, config() = Γ, the vault's runtime code hash); default true */
  check?: boolean;
  /** take the wallet directory's exclusive lock (lockWallet); default true. The lane runs one command at a time and opts out. */
  lock?: boolean;
  /** wrap the gateway RPC (the lane counts and injects broadcasts through it) */
  wrapRpc?: (rpc: HttpJsonRpc) => JsonRpc;
  /** test seams: another RPC and aggregator than the connection's, and a gas model in place of the plug-in's default */
  rpc?: JsonRpc;
  aggregator?: Aggregator;
  trustSource?: ITrustBaseSource;
  gas?: GasModel;
}

export class Wallet {
  public readonly signer: LocalKeySigner;
  public bridge!: NativeBridgeV2;
  public trust!: TrustInput;
  public aggregator!: Aggregator;
  public readonly pins: DeploymentPins;
  public readonly release: Record<string, unknown> & { pins: Record<string, unknown> };

  /** A wallet in DIR with SECRET (32 bytes) on CONNECTION. Nothing is written until a step runs. */
  public constructor(public readonly dir: string, private readonly secret: Uint8Array, public readonly conn: Connection) {
    if (secret.length !== 32) throw new Error('the wallet secret is 32 bytes');
    const created = mkdirSync(join(dir, 'tokens'), { recursive: true, mode: 0o700 });
    if (created !== undefined) {
      // Persist both directory entries before any journal or transaction can depend on them.
      fsyncDir(join(dir, 'tokens'));
      fsyncDir(dir);
      for (let parent = dirname(dir);; parent = dirname(parent)) {
        fsyncDir(parent);
        if (parent === dirname(created) || parent === dirname(parent)) break;
      }
    }
    this.signer = new LocalKeySigner(secret);
    this.release = JSON.parse(readFileSync(conn.release, 'utf8'));
    this.pins = pinsOf(this.release);
  }

  /** The secret a config names: the environment variable, or secret.hex in DIR. */
  private static secretOf(dir: string, c: WalletConfig): Uint8Array {
    if (c.keyEnv) {
      const v = process.env[c.keyEnv];
      if (!v) throw new Error(`the wallet's secret is in ${c.keyEnv}, which is not set`);
      return unhex(v);
    }
    return unhex(readFileSync(join(dir, 'secret.hex'), 'utf8'));
  }

  /** The wallet in DIR as its config.json describes it. */
  public static load(dir: string): Wallet {
    const f = join(dir, 'config.json');
    if (!existsSync(f)) throw new Error(`${dir} is not a wallet: run init first`);
    const c = JSON.parse(readFileSync(f, 'utf8')) as WalletConfig;
    return new Wallet(dir, Wallet.secretOf(dir, c), c);
  }

  /**
   * A new wallet in DIR for CONFIG: the installation check runs first, and only once it passed are the secret (a new random one, unless the
   * config names an environment variable) and config.json written. A refused check leaves no wallet behind.
   */
  public static async create(dir: string, config: WalletConfig, random: () => Uint8Array, opts: OpenOptions = {}): Promise<Wallet> {
    if (existsSync(join(dir, 'config.json'))) throw new Error(`${dir} is already a wallet`);
    const secret = config.keyEnv ? Wallet.secretOf(dir, config) : random();
    const w = await new Wallet(dir, secret, config).open({ ...opts, check: true });
    if (!config.keyEnv) {
      if (existsSync(join(dir, 'secret.hex'))) throw new Error(`${dir} already holds a secret`);
      writeDurable(join(dir, 'secret.hex'), `${hx(secret)}\n`, 0o600);
    }
    writeDurable(join(dir, 'config.json'), JSON.stringify(config, null, 2) + '\n');
    return w;
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
   * Open the plug-in: the wallet lock, the held trust (the shipped bundle under its pin, extended by the wallet's own history), the journal,
   * the backup of the intent high-water mark, the trust refresh through the gateway's trust-base pages, and the installation check.
   */
  private source!: ITrustBaseSource;
  private get authorityFile(): string { return join(this.dir, 'recovery-authority.json'); }

  /** These entries were locally authenticated when saved. Replay them under the shipped pin on reopen. */
  public async persistAuthority(trust: TrustInput): Promise<void> {
    writeDurable(this.authorityFile, JSON.stringify({ entries: trust.history.entries.map((entry) => hx(entry.encode())) }));
  }

  private refreshingAuthority?: Promise<TrustInput>;

  public refreshAuthority(): Promise<TrustInput> {
    return this.refreshingAuthority ??= this.syncAuthority().finally(() => { this.refreshingAuthority = undefined; });
  }

  private async syncAuthority(): Promise<TrustInput> {
    const next = await this.trust.snapshot();
    try {
      await refreshAll(next, this.source, 64, () => undefined, AbortSignal.timeout(15_000));
    } catch (error) {
      if (next.history.tip!.epoch > this.trust.history.tip!.epoch) {
        await this.persistAuthority(next);
        this.trust = next;
      }
      throw error;
    }
    try {
      await this.persistAuthority(next);
    } catch (e) {
      throw new WalletError('TrustInput', 'could not persist the authority extension', e);
    }
    this.trust = next;
    return next;
  }

  public async open(opts: OpenOptions = {}): Promise<this> {
    if (opts.lock ?? true) lockWallet(this.dir);
    fsyncDir(this.dir);
    fsyncDir(dirname(this.dir));
    const pin = unhex(readFileSync(this.conn.trustPin, 'utf8'));
    const shipped = await TrustInput.fromBundle(Uint8Array.from(readFileSync(this.conn.trustBundle)), pin);
    this.trust = shipped;
    if (existsSync(this.historyFile)) {
      const held = await TrustInput.fromBundle(Uint8Array.from(readFileSync(this.historyFile)), pin);
      for (const e of shipped.history.entries) await held.history.append(e);
      this.trust = held;
    }
    const saved = existsSync(this.authorityFile) ? JSON.parse(readFileSync(this.authorityFile, 'utf8')) as {
      entries: string[];
    } : undefined;
    if (saved) for (const entry of saved.entries) await this.trust.history.append(RootTrustBaseV2.decode(unhex(entry)));
    if (saved?.entries.length !== this.trust.history.entries.length) await this.persistAuthority(this.trust);
    this.source = opts.trustSource ?? new AggregatorClient(this.conn.aggregator);
    const http = new HttpJsonRpc(this.conn.rpc, { timeoutMs: 120_000 });
    this.aggregator = opts.aggregator ?? new GatewayAggregator(this.conn.aggregator);
    this.bridge = await NativeBridgeV2.open({
      pins: this.pins, trust: this.trust, rpc: opts.rpc ?? (opts.wrapRpc ? opts.wrapRpc(http) : http), aggregator: this.aggregator,
      journal: new FileJournalStore(join(this.dir, 'journal.json')),
      bridgeKey: deriveBridgeKey(sha256(concat(tag('nb2-reference-wallet/seed/'), this.secret))),
      // the intent high-water mark goes with the seed backup before any deposit is sent (section 12.1): here a file beside the journal
      backup: async (intents) => writeDurable(join(this.dir, 'backup.json'), JSON.stringify(intents)),
      refreshTrust: () => this.refreshAuthority(),
      unsafeTestTrust: !!opts.rpc,
      trustFreshnessMs: opts.trustFreshnessMs ?? (opts.rpc ? undefined :
        this.release.status === 'testnet-provisional' ? TESTNET_TRUST_FRESHNESS_MS : PRODUCTION_TRUST_FRESHNESS_MS),
      receiptTimeoutMs: 180_000, pollMs: 1_000, ...(opts.gas ? { gas: opts.gas } : {}),
    }, opts.check ?? true);
    return this;
  }

  private get index(): Record<string, TokenEntry> {
    const f = join(this.dir, 'tokens.json');
    return existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : {};
  }
  private set index(idx: Record<string, TokenEntry>) {
    writeDurable(join(this.dir, 'tokens.json'), JSON.stringify(idx, null, 2));
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
  /** Refuse LABEL as the name of a new token: not a valid name, already held, or the target of a pending transfer. */
  public checkNewName(label: string): void {
    if (!NAME.test(label)) throw new Error(`a token name is 1 to 64 letters, digits, '.', '_' or '-': ${JSON.stringify(label)}`);
    if (this.has(label)) throw new Error(`the wallet already has a token named ${label}`);
    if (existsSync(this.pendingFile(label))) throw new Error(`a transfer to ${label} is pending: finish it first (status)`);
    // the parts of an unfinished split are reserved: its resume saves them under these names
    for (const l of this.labels()) {
      const e = this.entry(l);
      if (e.splitInto?.includes(label) && e.spent?.endsWith('(in progress)')) throw new Error(`${label} is reserved by the unfinished split of ${l}: finish it first (status)`);
    }
  }
  /** LABEL as a token that can be spent: held, minted, and not spent already. */
  public spendable(label: string): TokenEntry {
    const e = this.entry(label);
    if (e.spent) throw new Error(`${label} is spent (${e.spent})`);
    if (this.token(label).length === 0) throw new Error(`${label} is not minted yet (status)`);
    return e;
  }
  public keep(label: string, token: Uint8Array, owner: number, extra: Partial<TokenEntry> = {}): void {
    if (!NAME.test(label)) throw new Error(`a token name is 1 to 64 letters, digits, '.', '_' or '-': ${JSON.stringify(label)}`);
    writeDurable(join(this.dir, 'tokens', `${label}.cbor`), token);
    const idx = this.index;
    idx[label] = { ...(idx[label] ?? {}), file: `${label}.cbor`, owner, amount: '0', ...extra };
    this.index = idx;
  }
  public update(label: string, extra: Partial<TokenEntry>): void {
    const idx = this.index;
    idx[label] = { ...this.entry(label), ...extra };
    this.index = idx;
  }
  public pendingFile(to: string): string {
    return join(this.dir, 'tokens', `${to}.pending.json`);
  }
  /** Every transfer between its request and its saved result. */
  public pendingTransfers(): PendingTransfer[] {
    const out: PendingTransfer[] = [];
    for (const l of this.labels()) {
      const sp = this.entry(l).spent;
      if (!sp?.startsWith(PENDING)) continue;
      const f = this.pendingFile(sp.slice(PENDING.length));
      if (existsSync(f)) out.push(JSON.parse(readFileSync(f, 'utf8')));
    }
    return out;
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
/** The ones a step that reads chain evidence waits out (a certificate not served yet, a trust history to extend). */
const NOT_YET = ['CompanionUnknown', 'Unconfirmed', 'NoEntryForEpoch'];

export interface TransportRetryOptions { budgetMs?: number; baseMs?: number; capMs?: number; sleep?: (ms: number) => Promise<void>; random?: () => number }

/**
 * F again while it fails with a retryable transport error (HTTP 429/502/503/504, a network failure), with exponential backoff and jitter,
 * for about 100 s in all (the old per-call absorption). Anything else, and a retryable error after the budget, is thrown at once. The
 * transport itself retries only briefly; this is the one outer loop, and it is only for idempotent reads and polls.
 */
export async function transportRetry<T>(f: () => Promise<T>, note: (reason: string) => void = () => undefined, o: TransportRetryOptions = {}): Promise<T> {
  const nap = o.sleep ?? sleep;
  const random = o.random ?? Math.random;
  const budget = o.budgetMs ?? 100_000;
  let waited = 0;
  for (let i = 0; ; i++) {
    try {
      return await f();
    } catch (e) {
      if (!(e instanceof RpcError && e.retryable)) throw e;
      const step = Math.min(o.capMs ?? 20_000, (o.baseMs ?? 2_000) * 2 ** i);
      const delay = Math.max(e.retryAfterMs ?? 0, Math.round(step / 2 + random() * step / 2));
      if (waited + delay > budget) throw e;
      if (i % 5 === 0) note('RPC rate-limited, waiting');
      waited += delay;
      await nap(delay);
    }
  }
}

/**
 * F again while it refuses with a reason in WHICH, up to TRIES times; NOTE is told the first time and every tenth. A retryable transport
 * error is waited out separately (`transportRetry`, its own budget) unless TRANSPORT is false, and never counts as a refusal.
 */
export async function retry<T>(f: () => Promise<T>, note: (reason: string) => void = () => undefined, tries = 120, ms = 2_000, which = RETRYABLE, transport = true): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await (transport ? transportRetry(f, note) : f());
    } catch (e) {
      const reason = reasonOf(e);
      if (i >= tries || !which.includes(reason)) throw e;
      if (i % 10 === 0) note(reason);
      await sleep(ms);
    }
  }
}

/** Deposit: plan an intent (the secret is derived, the high-water mark backed up) and journal it under LABEL. Nothing is sent. */
export async function planDeposit(w: Wallet, label: string, amount: bigint): Promise<DepositPlan> {
  w.checkNewName(label); // before an intent is used up
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

/**
 * Mint: the deposit's receipt proof J once its block is certified (waited out while the certificate is not served yet), then the mint. A
 * deposit that has not landed is refused at once (NotPending): send it first.
 */
export async function mint(w: Wallet, label: string, note?: (reason: string) => void, recoverProof = false): Promise<{ intent: bigint; depositNumber: bigint; reasonBytes: number; tokenId: Uint8Array; amount: bigint }> {
  const e = w.entry(label);
  if (e.intent === undefined) throw new Error(`${label} is not a deposit`);
  const intent = BigInt(e.intent);
  const p = await retry(() => w.bridge.collectDepositProof(intent), note, 120, 2_000, NOT_YET);
  const token = await w.bridge.mint(intent, { recoverProof });
  const v = await w.bridge.verifyToken(token);
  w.keep(label, token, 0, { intent: e.intent, amount: v.amount.toString(), note: undefined });
  return { intent, depositNumber: p.depositNumber, reasonBytes: p.reason.length, tokenId: v.tokenId, amount: v.amount };
}

/**
 * An ordinary Unicity transfer of FROM, kept as TO: to the wallet's own owner key OWNER, or to another wallet's key TOKEY (the result is then
 * kept as sent: hand tokens/TO.cbor to its owner). The CLI keeps the signed request under its destination name:
 *   1. TO is checked (a valid, new name) and FROM must be spendable, before anything is submitted;
 *   2. the exact request (its random mask included) is written durably to tokens/TO.pending.json, and FROM is marked spent;
 *   3. the request is certified, the result verified and saved as TO, and the pending file removed.
 * A rerun resumes the same signed request and uses the retained proof once one has been saved.
 */
export async function transfer(w: Wallet, from: string, to: string, owner: number, toKey?: Uint8Array, recoverProof = false): Promise<Uint8Array> {
  let p: PendingTransfer;
  const file = w.pendingFile(to);
  if (NAME.test(to) && existsSync(file)) {
    p = JSON.parse(readFileSync(file, 'utf8'));
    if (p.from !== from) throw new Error(`a transfer of ${p.from} to ${to} is pending: run transfer ${p.from} ${to} to finish it`);
  } else {
    w.checkNewName(to);
    const e = w.spendable(from);
    if (to === from) throw new Error('a transfer needs a new name for its result');
    const src = w.token(from);
    await w.bridge.verifyToken(src);
    const key = toKey ?? w.ownerPub(owner);
    parseKey(key);
    const req = await transferRequest(src, w.owner(e.owner), { recipient: signaturePredicate(key), mask: freshMask(), data: null, deadline: null });
    p = { from, to, owner, ...(toKey ? { toKey: hx(toKey) } : {}), tx: hx(req.tx), cd: hx(req.cd) };
    writeDurable(file, JSON.stringify(p));
    w.update(from, { spent: `${PENDING}${to}` });
  }
  const tx = unhex(p.tx);
  const verify = async (proof: Uint8Array, heldOnly = false) => {
    const token = appendTransfer(w.token(p.from), tx, proof);
    if (heldOnly) await w.bridge.verifyWithTrust((trust) => verifyHeld(w.bridge.cfg, w.bridge.domain, trust, decodeToken(token)), false);
    else await w.bridge.verifyToken(token);
    return token;
  };
  let t: Uint8Array | undefined;
  let rejected = false;
  if (p.proof !== undefined) {
    try { t = await verify(unhex(p.proof), recoverProof); } catch (error) {
      if (!(error instanceof Nb2Error) || (isCertificationTrustPending(error) && !recoverProof)) throw error;
      rejected = !isCertificationTrustPending(error);
    }
  }
  if (t === undefined) {
    const proof = await certifyChecked(w.aggregator, unhex(p.cd), transferProofLimit(tx));
    const save = () => {
      p.proof = hx(proof);
      writeDurable(file, JSON.stringify(p));
    };
    if (p.proof !== undefined) {
      try { t = await verify(proof, true); } catch (error) {
        if (!rejected || !isCertificationTrustPending(error)) throw error;
      }
    }
    save();
    t ??= await verify(proof);
  }
  const e = w.entry(p.from);
  w.keep(to, t, p.owner, { amount: e.amount, ...(p.toKey ? { spent: `sent to ${p.toKey}` } : {}) });
  w.update(p.from, { spent: `transferred as ${to}` });
  removeDurable(file);
  return t;
}

/**
 * Split FROM into whole parts (name, amount), all to the wallet's owner key OWNER. The names are checked before anything is submitted; the
 * plug-in journals the split itself (its ID derives from FROM), and FROM records the names, so a rerun with the same parts resumes.
 */
export async function split(w: Wallet, from: string, owner: number, parts: { label: string; amount: bigint }[]): Promise<Uint8Array[]> {
  const names = parts.map((p) => p.label);
  if (new Set(names).size !== names.length) throw new Error('the parts need distinct names');
  const e = w.entry(from);
  const resuming = e.splitInto !== undefined && e.splitInto.join(',') === names.join(',');
  if (!resuming) {
    w.spendable(from);
    for (const n of names) w.checkNewName(n);
    w.update(from, { splitInto: names, spent: `split into ${names.join(', ')} (in progress)` });
  }
  const res = await w.bridge.split(w.token(from), w.owner(e.owner), parts.map((p) => ({ ownerKey: w.ownerPub(owner), amount: p.amount })));
  res.forEach((t, i) => w.keep(parts[i].label, t, owner, { amount: parts[i].amount.toString() }));
  w.update(from, { spent: `split into ${names.join(', ')}` });
  return res;
}

/**
 * Return, step 1: plan LABEL's return to RECIPIENT (default: the wallet's EVM address) and run the capacity preflight. Nothing is burned;
 * a refusal (CapacityPreflight, InsufficientFunds, RecipientRefused) leaves the token as it was.
 */
export async function planReturn(w: Wallet, label: string, recipient?: Uint8Array, note?: (reason: string) => void, policy?: PayerPolicy): Promise<ReturnPlan> {
  const e = w.entry(label);
  if (e.spent && !burnMark(e.spent)) throw new Error(`${label} is spent (${e.spent})`);
  const target = Uint8Array.from(recipient ?? w.signer.address);
  const plan = await retry(() => w.bridge.planReturn(w.token(label), target, w.signer.address, { admission: walletAdmission(w, policy) }), note, 30, 2_000, NOT_YET, false);
  w.update(label, { returnId: hx(plan.returnId), authorizedRecipient: hx(target) });
  return plan;
}

/**
 * Return, step 2: burn LABEL. The plan is made again first, so the preflight runs on fresh chain state right before the irreversible step
 * (a limit measured earlier is never reused); the plug-in repeats it once more before it signs. Without RECIPIENT the burn keeps the one
 * plan-return chose. A burned return resumes.
 */
export async function burn(w: Wallet, label: string, recipient?: Uint8Array, note?: (reason: string) => void, policy?: PayerPolicy, backup?: string): Promise<{ plan: ReturnPlan | null; burned: Uint8Array; eta: Uint8Array; evidenceBytes: number }> {
  const e = w.entry(label);
  if (e.spent && !burnMark(e.spent)) throw new Error(`${label} is spent (${e.spent})`);
  let plan: ReturnPlan | null = null;
  const source = w.token(label);
  const sourceId = hx(HU(source));
  const lookupId = e.returnId ?? sourceId;
  const rec = await w.bridge.journal.ret(lookupId);
  if (rec && (rec.returnId !== sourceId || rec.returnId !== lookupId || rec.source !== hx(source))) {
    throw new WalletError('BadInput', 'journaled return does not match the labeled source');
  }
  let expectedRecipient: Uint8Array | undefined;
  if (rec === null || rec.status === 'planned') {
    if (recipient === undefined && (e.returnId || rec) && !e.authorizedRecipient) {
      throw new WalletError('BadInput', 'resume requires the holder to authorize the recipient explicitly');
    }
    const held = e.authorizedRecipient && unhex(e.authorizedRecipient);
    if (recipient === undefined && rec && held && !eq(unhex(rec.recipient), held)) {
      throw new WalletError('BadInput', 'planned recipient differs from the saved holder authorization');
    }
    expectedRecipient = Uint8Array.from(recipient ?? (held || w.signer.address));
    plan = await planReturn(w, label, expectedRecipient, note, policy);
  }
  // the token is marked before its burn request is journaled, so nothing else can spend the state the burn spends; a burn that never got
  // that far (a refused last preflight) takes the mark back
  const id = plan ? hx(plan.returnId) : lookupId;
  if (!e.returnId && !plan) w.update(label, { returnId: id });
  const authorization = join(w.dir, `backup-${id.slice(2)}.txt`);
  if (backup) {
    const target = resolve(backup);
    if (existsSync(authorization) && readFileSync(authorization, 'utf8') !== target) throw new Error('return already has an authorized backup destination');
    writeDurable(authorization, target);
  }
  const authorized = existsSync(authorization) ? readFileSync(authorization, 'utf8') : undefined;
  w.update(label, { spent: BURNING });
  let b: Awaited<ReturnType<typeof w.bridge.burn>>;
  try {
    b = await retry(() => w.bridge.burn(unhex(id), w.owner(e.owner), walletAdmission(w, policy, authorized), expectedRecipient), note, 120, 2_000, RETRYABLE, false);
  } catch (err) {
    const r = await w.bridge.journal.ret(id);
    if (r === null || r.status === 'planned') w.update(label, { spent: undefined });
    throw err;
  }
  const confirmed = (await w.bridge.journal.ret(id))!;
  if (confirmed.status !== 'paid') await retainTerminal(w, confirmed);
  w.update(label, { note: confirmed.status === 'paid' ? 'paid' : 'burned', spent: BURNED });
  return { plan, burned: b.burned, eta: b.eta, evidenceBytes: evidenceOf(b.burned).length };
}

/**
 * The deployed verifier reports QuorumNotMet for both a seal awaiting import and an invalid quorum. Only the
 * vault's wrapped refusal is eligible for the bounded seal-import wait.
 */
export function isRegistryLag(e: unknown): e is Nb2Error | WalletError {
  return e instanceof WalletError && e.reason === 'ImportLag' || e instanceof Nb2Error && e.rule === 'VerifierRefused' && e.inner?.rule === 'QuorumNotMet';
}

/** How long a redemption waits out the registry lag (#1125) before it reports the refusal. */
export const REGISTRY_LAG_MS = 120_000;

/** The refusal of a redemption that waited out REGISTRY_LAG_MS: the burn is intact, and `redeem` can run again. */
export class RegistryLagExpired extends Error {
  public constructor(public readonly label: string, public readonly refusal: unknown) {
    super(`the B1 registry is still unavailable for this return after ${REGISTRY_LAG_MS / 1000} s (bft-core#1125). The burn is intact: run redeem ${label} again later. If it persists, the certificate may really lack its quorum: report it`);
  }
}

/**
 * Return, step 3: redeem LABEL's burn on the EVM: the witness (one SegmentSealed log per segment since the burn's index, the gap proofs) is
 * built from the chain, sent, and reconciled until the payment's block is certified. A paid return answers paid without a send.
 * Wrapped QuorumNotMet may be seal import lag. Start retries only within REGISTRY_LAG_MS, then report RegistryLagExpired if still refused.
 * An in-flight attempt may finish later. LAG, when given, is told how long the wait took.
 */
export async function redeem(w: Wallet, label: string, polls = 60, pollMs = 3_000, note: (reason: string) => void = () => undefined, lag?: (ms: number) => void, policy?: PayerPolicy): Promise<ReconcileResult> {
  const rec = await w.returnRecord(label);
  const started = performance.now();
  const deadline = started + REGISTRY_LAG_MS;
  let r: ReconcileResult;
  let lastRefusal: Nb2Error | WalletError | undefined;
  for (;;) {
    if (lastRefusal !== undefined) {
      const remaining = deadline - performance.now();
      if (remaining > 0) await sleep(Math.min(pollMs, remaining));
      if (performance.now() >= deadline) throw new RegistryLagExpired(label, lastRefusal);
    }
    try {
      r = await transportRetry(() => redeemOrdinary(w, rec, policy), note);
      break;
    } catch (e) {
      if (!isRegistryLag(e)) throw e;
      if (lastRefusal === undefined && performance.now() < deadline) {
        note(e instanceof WalletError ? 'waiting for B1 registry import' : 'waiting for possible seal registry lag');
      }
      lastRefusal = e;
    }
  }
  if (lastRefusal !== undefined) lag?.(performance.now() - started);
  for (let i = 0; r.state === 'pending' && i < polls; i++) {
    await sleep(pollMs);
    const txHash = r.txHash;
    r = await transportRetry(() => pollOrdinaryPayout(w, rec, txHash, policy), note);
  }
  if (r.state === 'paid') w.update(label, { note: 'paid' });
  return r;
}

/** The CLI routes a signed cold return through the durable packet runner. */
export async function resumePayout(w: Wallet, rec: ReturnRecord, policy: PayerPolicy, ordinary = false, cold = false): Promise<RecoveryResult | ReconcileResult> {
  rec = (await w.bridge.journal.ret(rec.returnId)) ?? rec;
  if (cold) rec = await qualifyExistingRecovery(w, rec, policy);
  return (rec.recovery || hasPeerComplete(w, rec)) && !ordinary ? recoverStep(w, rec, policy) : redeemOrdinary(w, rec, policy);
}

/** Receive and verify the complete held lineage before adding it to spendable storage. */
export async function receive(w: Wallet, label: string, token: Uint8Array, owner: number): Promise<string> {
  w.checkNewName(label);
  const snapshot = Uint8Array.from(token);
  const headroom = await returnHeadroom(w, snapshot);
  const held = await w.bridge.verifyReceivedToken(snapshot);
  if (!held.owner || !eq(held.owner, w.ownerPub(owner))) throw new Error('the verified token belongs to another owner');
  w.keep(label, snapshot, owner, { amount: String(held.amount) });
  return headroom;
}

/** What to run next for a deposit or a return, by its journal status. */
const NEXT_RETURN: Record<string, string> = { planned: 'burn', 'burn-requested': 'burn', burned: 'redeem', submitted: 'redeem' };

/**
 * Where every deposit, transfer and return stands, by token name: the plug-in's wording (bridge.status), the command that moves it on, and
 * for a burn the history its redemption owes (one gap proof per sealed segment since its index).
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
  const lines: string[] = [`vault ${hx(w.bridge.cfg.vault)}: segment ${st.segment}, ${st.deposits} deposits, ${uct(st.outstanding)} UCT outstanding`];
  const words = await w.bridge.status();
  const deposits = await w.bridge.journal.deposits();
  const returns = await w.bridge.journal.returns();
  deposits.forEach((d, i) => {
    const l = byIntent.get(d.intent);
    const next = !l ? '' : d.status === 'planned' || d.status === 'submitted' ? `deposit ${l} ${uct(d.amount)}` : d.status === 'deposited' || d.status === 'proven' ? `mint ${l}` : '';
    lines.push(`${l ?? '?'}: ${words[i]}${d.depositNumber ? ` (deposit ${d.depositNumber}, block ${d.blockNumber})` : ''}${next ? `; next: ${next}` : ''}`);
  });
  for (const p of w.pendingTransfers()) lines.push(`${p.to}: transfer of ${p.from} requested, not saved yet; next: transfer ${p.from} ${p.to}`);
  for (const l of w.labels()) {
    const e = w.entry(l);
    if (e.splitInto && e.spent?.endsWith('(in progress)')) lines.push(`${l}: split into ${e.splitInto.join(', ')} not finished; next: split ${l} with the same parts`);
  }
  returns.forEach((r, i) => {
    const l = byReturn.get(r.returnId.toLowerCase());
    const abandoned = r.status === 'planned' && l !== undefined && w.entry(l).spent !== undefined && !burnMark(w.entry(l).spent);
    const next = abandoned ? undefined : NEXT_RETURN[r.status];
    const owed = r.status === 'burned' || r.status === 'submitted' ? `; the witness proves ${st.segment - BigInt(r.a)} sealed segments` : '';
    lines.push(`${l ?? '?'}: ${words[deposits.length + i]}${owed}${next && l ? `; next: ${next} ${l}` : ''}`);
  });
  return lines;
}
