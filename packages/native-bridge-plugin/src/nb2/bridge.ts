/**
 * The native bridge v2 wallet API (NB2-07, bft-core#1103). A wallet bridges native UCT with these calls and does not handle segments,
 * gap proofs or receipt tries itself:
 *
 *   EVM -> Unicity   planDeposit, submitDeposit, collectDepositProof, mint
 *   circulation      transfer, split (ordinary token operations; nothing touches the EVM)
 *   Unicity -> EVM   planReturn, burn, buildRedeem, submitRedeem, reconcile
 *
 * Network adapters fetch bytes; pure functions verify them offline. Every step is journaled BEFORE the step it enables, so a crash at
 * any point resumes by calling the same function again with the same identifier:
 *   - the deposit secret's intent and its backed-up high-water mark exist before value is sent (`submitDeposit` refuses otherwise);
 *   - every signed EVM transaction is journaled before it is broadcast, and an earlier send is reconciled before any new one;
 *   - a burn's exact request is journaled before it is certified, and the certified burn before success is reported;
 *   - the burn index comes from a verified SegmentSealed receipt (or is zero), never from a plain RPC number outside test deployments.
 */
import { concat, eq, toHex } from '../bytes.js';
import { classifyRedeemError, decodeDeposited, decodePaid, decodeRevert, depositCalldata, redeemCalldata, redeemCalldataLength, type DecodedError, type RedeemAction } from './abi.js';
import { ascii, beInt, cArr, cBytes } from './cbor.js';
import { ASSET_UCT, buildParams, decodeConfig, domainOf, log2, type Build, type Config } from './config.js';
import { HE, HU, parseKey } from './crypto.js';
import {
  TOPIC, decodeDepositProof, decodeReceiptBacking, depositIntentSecret, depositSalt, encodeReceiptBacking, firstOwnerOf, rhoOf, verifyDepositEvidence, verifyReceiptLog,
} from './deposit.js';
import { Nb2Error, WalletError, fail, refuse } from './errors.js';
import { decodeSignedTx, signTx, type EvmSigner, type SignedTx } from './evm.js';
import { ProvisionalGasModel, redeemTxFraming, type GasModel } from './gas.js';
import {
  Journal, dec, hex, undec, unhex, type DepositRecord, type IntentsRecord, type JournalStore, type ReturnRecord, type SendRecord, type SplitRecord,
} from './journal.js';
import { burnIndex, capacityExceeded, capacityPreflight, checkStateRead, verifySealReceipt, type SealReceipt } from './rules.js';
import { AmbiguousBroadcast, EvmReader, type JsonRpc, type ReceiptJson } from './rpc.js';
import type { RawLog } from './abi.js';
import { buildHistory, checkSegmentLog, gapProofLen, genesisHead, type Segment } from './segment.js';
import { encodeToken, decodeToken, burnPredicate, signaturePredicate, tokenIdOf, valueData, type Token } from './token.js';
import {
  appendTransfer, certifyChecked, childMint, freshMask, mintRequest, splitPlan, tokenOfMint, transferRequest, type Aggregator, type OwnerSigner,
} from './tokenops.js';
import { bindTrust, type TrustInput } from './trust.js';
import { decodeEvidence, encodeReturnData, evidenceOf, verifyHeld, verifyPart, type Verdict } from './verify.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { decodeSplitJustification } from './split.js';
import { headTag } from './cbor.js';
import { TAG } from './config.js';

/** The deployment manifest pins outside D (section 4.3; the manifest schema is NB2-09's). */
export interface DeploymentPins {
  gamma: Uint8Array;
  build: Build;
  vaultRuntimeCodeHash: Uint8Array;
  maxEncodedTxBytes: bigint;
  userGasLimit: bigint;
  gasReserve: bigint;
  returnReserveSegments: bigint;
  deploymentBlock: bigint;
  stateReadOnly: boolean;
  /** The plausibility bound of a stateReadOnly index read (default 64). */
  maxJump?: bigint;
}

export interface BridgeOptions {
  pins: DeploymentPins;
  trust: TrustInput;
  rpc: JsonRpc;
  aggregator: Aggregator;
  journal: JournalStore;
  /** k_w: the 32-byte wallet bridge key, derived from the wallet seed (see {@link deriveBridgeKey}). */
  bridgeKey: Uint8Array;
  /** The wallet-versioned name of the k_w derivation, recorded in the journal. */
  keyScheme?: string;
  /** Back up the intent high-water mark with the seed (section 12.1). Required unless `requireBackup` is false. */
  backup?: (intents: IntentsRecord) => Promise<void>;
  /** Default true: a deposit is not sent before its intent's high-water mark is backed up. */
  requireBackup?: boolean;
  gas?: GasModel;
  /** Use the provisional (unmeasured) verifier gas terms on a non-test deployment; without it a measured `gas` model is required. */
  allowProvisionalGas?: boolean;
  /** Blocks the head must advance, after a send's nonce is seen used without its success receipt, before the send counts as dead. */
  deadAfterBlocks?: bigint;
  /** A seal receipt older than this many blocks gives a warning: the index then reflects a stale view (default 7,200). */
  maxSealAgeBlocks?: bigint;
  /**
   * Extend the trust-base history (append the authenticated successor entries) when a certificate's epoch is not held yet. A seal
   * receipt or a token refused with the retryable NoEntryForEpoch is retried once after it; it is never treated as invalid.
   */
  refreshTrust?: () => Promise<void>;
  /** Receipt polling. */
  receiptTimeoutMs?: number;
  pollMs?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export const DEFAULT_KEY_SCHEME = 'nb2-hmac-sha256-v1';

/** k_w = HMAC-SHA256(key = seed, "unicity-nb2/wallet-bridge-key/v1"): the {@link DEFAULT_KEY_SCHEME} derivation. */
export const deriveBridgeKey = (seed: Uint8Array): Uint8Array => hmac(sha256, seed, ascii('unicity-nb2/wallet-bridge-key/v1'));

export interface DepositPlan { intent: bigint; amount: bigint; rho: Uint8Array; firstOwner: Uint8Array; calldata: Uint8Array; record: DepositRecord }

export interface ReturnPlan {
  returnId: Uint8Array;
  amount: bigint;
  recipient: Uint8Array;
  a: bigint;
  /** The endpoint estimate and the history already owed from a. */
  cObs: bigint;
  pNow: bigint;
  /** The proofs that fit beside the evidence (bytes) and the remaining margin: pMax - (pNow + returnReserveSegments). */
  pMax: bigint;
  marginSegments: bigint;
  gasLimit: bigint;
  warnings: string[];
  record: ReturnRecord;
}

export interface RedeemTx { returnId: Uint8Array; calldata: Uint8Array; gasLimit: bigint; P: bigint; endpoint: bigint; history: Uint8Array; eta: Uint8Array; claimedStart: bigint }

export type ReconcileResult =
  | { state: 'paid'; txHash: Uint8Array; blockNumber: bigint }
  | { state: 'pending'; txHash: Uint8Array }
  | { state: 'not-paid'; lastFailure?: { txHash: Uint8Array; action: RedeemAction; error: DecodedError | null } };

const hexq = (b: Uint8Array): string => `0x${toHex(b)}`;

export class NativeBridgeV2 {
  public readonly cfg: Config;
  public readonly domain: Uint8Array;
  public readonly journal: Journal;
  public readonly evm: EvmReader;
  public readonly gas: GasModel;
  private readonly keyScheme: string;
  /** k_w, kept out of the options object. */
  readonly #kw: Uint8Array;
  private readonly opts: Omit<BridgeOptions, 'bridgeKey'>;
  /** In-process serialization per journal key (with the store's compare-and-swap across processes). */
  private readonly locks = new Map<string, Promise<unknown>>();

  private constructor(options: BridgeOptions) {
    const { bridgeKey, ...opts } = options;
    this.opts = opts;
    this.cfg = decodeConfig(opts.pins.gamma, buildParams(opts.pins.build));
    this.domain = domainOf(opts.pins.gamma);
    bindTrust(opts.trust, this.cfg);
    if (bridgeKey.length !== 32) refuse('BadInput', 'k_w is 32 bytes');
    this.#kw = bridgeKey.slice();
    if (opts.requireBackup !== false && opts.backup === undefined) refuse('BadInput', 'a backup of the intent high-water mark is required (or requireBackup: false on a test deployment)');
    if (opts.gas === undefined && opts.pins.build !== 'test' && opts.allowProvisionalGas !== true) {
      refuse('BadInput', 'no measured gas model: pass one, or opt in to the provisional verifier terms with allowProvisionalGas');
    }
    this.journal = new Journal(opts.journal, this.domain);
    this.evm = new EvmReader(opts.rpc);
    this.gas = opts.gas ?? new ProvisionalGasModel();
    this.keyScheme = opts.keyScheme ?? DEFAULT_KEY_SCHEME;
  }

  /**
   * Open the bridge for one pinned deployment. The installation check (section 4.3): the chain ID, the vault's exact Γ through config()
   * and its runtime code hash. These come from the RPC, which the wallet trusts here exactly as far as its manifest source.
   */
  public static async open(opts: BridgeOptions, check = true): Promise<NativeBridgeV2> {
    const b = new NativeBridgeV2(opts);
    if (check) {
      if ((await b.evm.chainId()) !== b.cfg.chainId) refuse('BadDeployment', 'the RPC serves another chain');
      if (!eq(await b.evm.vaultConfig(b.cfg.vault), opts.pins.gamma)) refuse('BadDeployment', 'the vault\'s config() is not the pinned Γ');
      if (!eq(HE(await b.evm.code(b.cfg.vault)), opts.pins.vaultRuntimeCodeHash)) refuse('BadDeployment', 'the vault runtime code hash is not the pinned one');
    }
    return b;
  }

  private sleep(ms: number): Promise<void> {
    return (this.opts.sleep ?? ((x) => new Promise((r) => setTimeout(r, x))))(ms);
  }
  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  /** Run `f` after every earlier call holding `key` in this instance has finished. */
  private async locked<T>(key: string, f: () => Promise<T>): Promise<T> {
    const prev = this.locks.get(key) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => { release = r; });
    const chained = prev.then(() => mine);
    this.locks.set(key, chained);
    await prev.catch(() => undefined);
    try {
      return await f();
    } finally {
      release();
      if (this.locks.get(key) === chained) this.locks.delete(key);
    }
  }

  // ==== EVM -> Unicity ==================================================================================================

  /** r for intent i (never stored unless the wallet asks: it is derivable from k_w and i). */
  public secretOf(i: bigint): Uint8Array {
    return depositIntentSecret(this.#kw, this.domain, i);
  }

  /**
   * Plan a deposit of `amount` to the Unicity owner `ownerKey` (compressed key): allocate a never-used intent i, derive r and rho, and
   * journal the plan with the new high-water mark, which is handed to the backup. Serialized: two plans never share an intent.
   */
  public planDeposit(amount: bigint, ownerKey: Uint8Array): Promise<DepositPlan> {
    if (amount <= 0n) refuse('BadInput', 'a deposit amount is positive');
    parseKey(ownerKey);
    return this.locked('intents', async () => {
      const cur = await this.journal.intents();
      if (cur !== null && cur.keyScheme !== this.keyScheme) refuse('BadInput', `the journal's intents use key scheme ${cur.keyScheme}`);
      const i = cur === null ? 0n : undec(cur.next);
      const intents: IntentsRecord = { ...this.journal.base(), kind: 'intents', keyScheme: this.keyScheme, next: dec(i + 1n) };
      // the counter moves first, by compare-and-swap: a crash wastes intent i, another writer makes this one fail; i is never reused
      await this.journal.putIntents(intents);
      const r = this.secretOf(i);
      const rho = rhoOf(this.domain, r);
      const firstOwner = firstOwnerOf(ownerKey);
      const rec: DepositRecord = {
        ...this.journal.base(), kind: 'deposit', keyScheme: this.keyScheme, intent: dec(i), amount: dec(amount), ownerKey: hex(ownerKey),
        firstOwner: hex(firstOwner), rho: hex(rho), status: 'planned', backedUp: false, sends: [], plannedBlock: dec(await this.evm.blockNumber()),
      };
      await this.journal.putDeposit(rec);
      if (this.opts.backup) {
        await this.opts.backup(intents);
        rec.backedUp = true;
        await this.journal.putDeposit(rec);
      }
      return { intent: i, amount, rho, firstOwner, calldata: depositCalldata(firstOwner, rho), record: rec };
    });
  }

  /** Record that the wallet backed up the high-water mark covering this intent by other means. */
  public markBackedUp(intent: bigint): Promise<void> {
    return this.locked(`deposit/${intent}`, async () => {
      const rec = await this.depositRecord(intent);
      rec.backedUp = true;
      await this.journal.putDeposit(rec);
    });
  }

  private async depositRecord(i: bigint): Promise<DepositRecord> {
    return (await this.journal.deposit(i)) ?? refuse('JournalNotPersisted', `no journal entry for intent ${i}`);
  }

  /** Every Deposited event of the vault carrying `rho`, from block `from`, in chain order. */
  private async depositsWithRho(rho: Uint8Array, from: bigint): Promise<{ l: RawLog; n: bigint; amount: bigint; firstOwner: Uint8Array }[]> {
    const out: { l: RawLog; n: bigint; amount: bigint; firstOwner: Uint8Array }[] = [];
    for (const l of await this.evm.logs(this.cfg.vault, [hexq(TOPIC.Deposited)], from, await this.evm.blockNumber())) {
      const d = decodeDeposited(l);
      if (d !== null && eq(l.address, this.cfg.vault) && eq(d.domain, this.domain) && eq(d.rho, rho)) out.push({ l, n: d.n, amount: d.amount, firstOwner: d.firstOwner });
    }
    return out;
  }

  /**
   * Send the deposit. Refuses a plan whose journal entry is not persisted exactly as planned, or whose high-water mark is not backed
   * up. Earlier sends of the intent are reconciled first, and before the first send the vault's events are searched for a deposit that
   * already carries this rho (another device on the same backup), so a retry never deposits twice.
   */
  public submitDeposit(plan: DepositPlan | bigint, signer: EvmSigner): Promise<{ txHash: Uint8Array; depositNumber: bigint; blockNumber: bigint }> {
    const i = typeof plan === 'bigint' ? plan : plan.intent;
    return this.locked(`deposit/${i}`, async () => {
      const rec = await this.journal.deposit(i);
      if (rec === null) refuse('JournalNotPersisted', `intent ${i} is not in the journal: plan it first`);
      if (typeof plan !== 'bigint' && (rec!.rho !== hex(plan.rho) || rec!.amount !== dec(plan.amount))) refuse('JournalNotPersisted', 'the journal entry is not this plan');
      if (!eq(rhoOf(this.domain, this.secretOf(i)), unhex(rec!.rho))) refuse('JournalNotPersisted', 'the journal entry does not derive from this wallet key');
      const hw = await this.journal.intents();
      if (hw === null || undec(hw.next) <= i) refuse('JournalNotPersisted', 'the intent high-water mark does not cover this intent');
      if (this.opts.requireBackup !== false && !rec!.backedUp) refuse('JournalNotPersisted', 'the high-water mark covering this intent is not backed up');
      if (rec!.status !== 'planned' && rec!.status !== 'submitted') {
        return { txHash: unhex(rec!.depositTx!), depositNumber: undec(rec!.depositNumber!), blockNumber: undec(rec!.blockNumber!) };
      }
      const landed = await this.landedSend(rec!.sends, () => this.journal.putDeposit(rec!));
      if (landed === 'pending') refuse('Unconfirmed', 'an earlier deposit transaction may still be pending: wait or reconcile, never resend blindly');
      if (landed !== null) return this.recordDeposit(rec!, landed);
      if (rec!.sends.length === 0) {
        const seen = await this.depositsWithRho(unhex(rec!.rho), rec!.plannedBlock === undefined ? this.opts.pins.deploymentBlock : undec(rec!.plannedBlock));
        if (seen.length > 0) return this.adoptDeposits(rec!, seen);
      }
      const value = undec(rec!.amount);
      const tx = await this.signed(signer, this.cfg.vault, depositCalldata(unhex(rec!.firstOwner), unhex(rec!.rho)), value, this.gas.depositGasLimit());
      rec!.sends.push(this.sendRecord(tx));
      rec!.status = 'submitted';
      await this.journal.putDeposit(rec!);
      const r = await this.broadcastAndWait(tx);
      if (r === null) refuse('Unconfirmed', `deposit 0x${toHex(tx.hash)} has no receipt yet: call submitDeposit again to reconcile`);
      if (BigInt(r!.status) !== 1n) refuse('Reverted', `deposit 0x${toHex(tx.hash)} reverted`);
      return this.recordDeposit(rec!, r!);
    });
  }

  private async recordDeposit(rec: DepositRecord, r: ReceiptJson): Promise<{ txHash: Uint8Array; depositNumber: bigint; blockNumber: bigint }> {
    const l = r.logs.find((x) => eq(unhex(x.address.toLowerCase()), this.cfg.vault) && x.topics.length === 2 && x.topics[0].toLowerCase() === hex(TOPIC.Deposited));
    if (l === undefined) refuse('ProviderFault', 'the deposit receipt has no Deposited log');
    const d = decodeDeposited({ address: this.cfg.vault, topics: l!.topics.map((x) => unhex(x.toLowerCase())), data: unhex(l!.data.toLowerCase()), blockNumber: 0n, blockHash: new Uint8Array(32), transactionHash: new Uint8Array(32), logIndex: 0n });
    if (d === null || !eq(d.rho, unhex(rec.rho))) refuse('ProviderFault', 'the Deposited log is not this intent\'s');
    rec.depositTx = r.transactionHash.toLowerCase();
    rec.blockNumber = dec(BigInt(r.blockNumber));
    rec.depositNumber = dec(d!.n);
    rec.status = 'deposited';
    // merge, never replace: the record's own deposit, what was journaled before, and every deposit carrying this rho on chain
    const own = { tx: rec.depositTx, depositNumber: rec.depositNumber, blockNumber: rec.blockNumber, amount: dec(d!.amount), firstOwner: hex(d!.firstOwner) };
    const scan = await this.depositsWithRho(unhex(rec.rho), rec.plannedBlock === undefined ? this.opts.pins.deploymentBlock : undec(rec.plannedBlock));
    this.mergeSeen(rec, [own, ...scan.map((x) => ({ tx: hex(x.l.transactionHash), depositNumber: dec(x.n), blockNumber: dec(x.l.blockNumber), amount: dec(x.amount), firstOwner: hex(x.firstOwner) }))]);
    await this.journal.putDeposit(rec);
    return { txHash: unhex(rec.depositTx), depositNumber: d!.n, blockNumber: BigInt(r.blockNumber) };
  }

  /** Merge deposit entries into `seenDeposits` by deposit number, keeping journaled tokens, in number order. */
  private mergeSeen(rec: DepositRecord, entries: NonNullable<DepositRecord['seenDeposits']>): void {
    const known = new Map((rec.seenDeposits ?? []).map((x) => [x.depositNumber, x]));
    for (const e of entries) if (!known.has(e.depositNumber)) known.set(e.depositNumber, e);
    rec.seenDeposits = [...known.values()].sort((a, b) => (undec(a.depositNumber) < undec(b.depositNumber) ? -1 : 1));
  }

  /** Journal the deposits found for a record's rho: the first becomes its own, every one is listed (each is a separate root token). */
  private async adoptDeposits(rec: DepositRecord, seen: { l: RawLog; n: bigint; amount: bigint; firstOwner: Uint8Array }[]): Promise<{ txHash: Uint8Array; depositNumber: bigint; blockNumber: bigint }> {
    this.mergeSeen(rec, seen.map((s) => ({ tx: hex(s.l.transactionHash), depositNumber: dec(s.n), blockNumber: dec(s.l.blockNumber), amount: dec(s.amount), firstOwner: hex(s.firstOwner) })));
    if (rec.status === 'planned' || rec.status === 'submitted') {
      const first = seen[0];
      rec.depositTx = hex(first.l.transactionHash);
      rec.blockNumber = dec(first.l.blockNumber);
      rec.depositNumber = dec(first.n);
      rec.amount = dec(first.amount);
      rec.firstOwner = hex(first.firstOwner);
      rec.ownerKey = hex(first.firstOwner.subarray(9));
      rec.status = 'deposited';
    }
    await this.journal.putDeposit(rec);
    return { txHash: unhex(rec.depositTx!), depositNumber: undec(rec.depositNumber!), blockNumber: undec(rec.blockNumber!) };
  }

  /** The receipt proof and J of deposit number `n` of intent `i`, verified offline. */
  private async proveDeposit(i: bigint, tx: Uint8Array, n: bigint, amount: bigint, firstOwner: Uint8Array): Promise<{ receiptProof: Uint8Array; reason: Uint8Array }> {
    const rp = await this.evm.receiptProof(tx, this.cfg.vault, TOPIC.Deposited);
    const j = { d: this.domain, n, r: this.secretOf(i), proof: rp.proof };
    const ev = await this.retryingTrust(() => verifyDepositEvidence(this.cfg, this.domain, this.opts.trust, j));
    if (ev.v !== amount || !eq(ev.firstOwner, firstOwner)) refuse('ProviderFault', 'the certified deposit is not the planned one');
    return { receiptProof: rp.encoded, reason: encodeReceiptBacking(j) };
  }

  /** The ordinary mint with reason J, certified by the aggregator and verified offline. */
  private async mintWith(reason: Uint8Array, ownerKey: Uint8Array, amount: bigint): Promise<Uint8Array> {
    const j = decodeReceiptBacking(reason);
    const m = {
      network: this.cfg.network, recipient: signaturePredicate(ownerKey), salt: depositSalt(this.domain, j.n, j.r), type: this.cfg.ty,
      justification: reason, data: valueData(this.cfg.aid, amount), deadline: null,
    };
    const { tx, cd } = mintRequest(m);
    const token = tokenOfMint(tx, await certifyChecked(this.opts.aggregator, cd));
    const held = await this.retryingTrust(() => verifyHeld(this.cfg, this.domain, this.opts.trust, decodeToken(token)));
    if (held.amount !== amount) refuse('ProviderFault', 'the minted amount differs');
    return token;
  }

  /**
   * Fetch the certified header evidence and the block's receipts, build the receipt proof and verify it offline (section 6.2 steps 1 to
   * 7), then journal J. Retry `CompanionUnknown` after a round (the block's certificate is served once its child block exists).
   */
  public collectDepositProof(intent: bigint): Promise<{ reason: Uint8Array; depositNumber: bigint }> {
    return this.locked(`deposit/${intent}`, async () => {
      const rec = await this.depositRecord(intent);
      if (rec.status === 'proven' || rec.status === 'minted') return { reason: unhex(rec.reason!), depositNumber: undec(rec.depositNumber!) };
      if (rec.status !== 'deposited') refuse('NotPending', `intent ${intent} is ${rec.status}: submit the deposit first`);
      const n = undec(rec.depositNumber!);
      const p = await this.proveDeposit(intent, unhex(rec.depositTx!), n, undec(rec.amount), unhex(rec.firstOwner));
      rec.receiptProof = hex(p.receiptProof);
      rec.reason = hex(p.reason);
      rec.status = 'proven';
      await this.journal.putDeposit(rec);
      return { reason: p.reason, depositNumber: n };
    });
  }

  /** The ordinary SDK mint with the receipt-backed reason J, certified by the aggregator and verified offline. */
  public mint(intent: bigint): Promise<Uint8Array> {
    return this.locked(`deposit/${intent}`, async () => {
      const rec = await this.depositRecord(intent);
      if (rec.status === 'minted') return unhex(rec.token!);
      if (rec.status !== 'proven') refuse('NotPending', `intent ${intent} is ${rec.status}: collect the deposit proof first`);
      const token = await this.mintWith(unhex(rec.reason!), unhex(rec.ownerKey), undec(rec.amount));
      rec.token = hex(token);
      rec.status = 'minted';
      const mine = rec.seenDeposits?.find((x) => x.depositNumber === rec.depositNumber);
      if (mine !== undefined) mine.token = rec.token;
      await this.journal.putDeposit(rec);
      return token;
    });
  }

  /**
   * Mint a further deposit that carries this intent's rho (`seenDeposits`): a reused secret, or a second device. Its value is a
   * separate root token with its own deposit number; nothing is lost.
   */
  public mintExtraDeposit(intent: bigint, depositNumber: bigint): Promise<Uint8Array> {
    return this.locked(`deposit/${intent}`, async () => {
      const rec = await this.depositRecord(intent);
      const x = (rec.seenDeposits ?? []).find((s) => s.depositNumber === dec(depositNumber));
      if (x === undefined) refuse('NotPending', `no deposit number ${depositNumber} is journaled for intent ${intent}`);
      if (x!.token !== undefined) return unhex(x!.token);
      // the entry's own first owner: another device may have deposited this rho to another key
      const firstOwner = unhex(x!.firstOwner);
      const p = await this.proveDeposit(intent, unhex(x!.tx), depositNumber, undec(x!.amount), firstOwner);
      const token = await this.mintWith(p.reason, firstOwner.subarray(9), undec(x!.amount));
      x!.token = hex(token);
      await this.journal.putDeposit(rec);
      return token;
    });
  }

  /**
   * Recover deposits from the seed (k_w) and a backed-up high-water mark (section 5.1): every intent below `next` is matched by its rho
   * against the vault's Deposited events. A match upgrades a planned or submitted record (or creates the record) to deposited; every
   * deposit number seen for a rho is journaled. Intents without a matching event were never funded. A look-ahead past the mark does
   * not replace it.
   */
  public async recoverDeposits(next: bigint): Promise<bigint[]> {
    await this.locked('intents', async () => {
      const cur = await this.journal.intents();
      if (cur === null || undec(cur.next) < next) await this.journal.putIntents({ ...this.journal.base(), kind: 'intents', keyScheme: this.keyScheme, next: dec(next) });
    });
    const want = new Map<string, bigint>();
    for (let i = 0n; i < next; i++) want.set(toHex(rhoOf(this.domain, this.secretOf(i))), i);
    const byIntent = new Map<bigint, { l: RawLog; n: bigint; amount: bigint; firstOwner: Uint8Array }[]>();
    for (const l of await this.evm.logs(this.cfg.vault, [hexq(TOPIC.Deposited)], this.opts.pins.deploymentBlock, await this.evm.blockNumber())) {
      const d = decodeDeposited(l);
      if (d === null || !eq(l.address, this.cfg.vault) || !eq(d.domain, this.domain)) continue;
      const i = want.get(toHex(d.rho));
      if (i === undefined) continue;
      byIntent.set(i, [...(byIntent.get(i) ?? []), { l, n: d.n, amount: d.amount, firstOwner: d.firstOwner }]);
    }
    const found: bigint[] = [];
    for (const [i, seen] of [...byIntent].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
      await this.locked(`deposit/${i}`, async () => {
        const rec: DepositRecord = (await this.journal.deposit(i)) ?? {
          ...this.journal.base(), kind: 'deposit', keyScheme: this.keyScheme, intent: dec(i), amount: dec(seen[0].amount),
          ownerKey: hex(seen[0].firstOwner.subarray(9)), firstOwner: hex(seen[0].firstOwner), rho: hex(rhoOf(this.domain, this.secretOf(i))),
          status: 'planned', backedUp: true, sends: [],
        };
        await this.adoptDeposits(rec, seen);
      });
      found.push(i);
    }
    return found;
  }

  // ==== circulation =====================================================================================================

  /** Verify a held token fully offline (receipt origin, lineage, every certificate): its ID, amount and owner. */
  public async verifyToken(token: Uint8Array): Promise<{ tokenId: Uint8Array; amount: bigint; owner: Uint8Array | null }> {
    const h = await this.retryingTrust(() => verifyHeld(this.cfg, this.domain, this.opts.trust, decodeToken(token)));
    return { tokenId: h.tokenId, amount: h.amount, owner: h.owner.type === 1n ? h.owner.params : null };
  }

  /** An ordinary transfer to `toKey`; the result is verified before it is returned. */
  public async transfer(token: Uint8Array, owner: OwnerSigner, toKey: Uint8Array): Promise<Uint8Array> {
    await this.verifyToken(token);
    parseKey(toKey);
    const { tx, cd } = await transferRequest(token, owner, { recipient: signaturePredicate(toKey), mask: freshMask(), data: null, deadline: null });
    const out = appendTransfer(token, tx, await certifyChecked(this.opts.aggregator, cd));
    await this.verifyToken(out);
    return out;
  }

  /**
   * Split a held token into whole parts (burn-and-mint with the protocol 6 lineage formats). The plan is journaled first, then the burn's
   * exact request, the burned parent and each child as it is minted; a call with the same `splitId` resumes.
   */
  public split(token: Uint8Array, owner: OwnerSigner, outputs: { ownerKey: Uint8Array; amount: bigint }[], splitId?: Uint8Array): Promise<Uint8Array[]> {
    const id = splitId ?? HU(cArr(cBytes(ascii('UNICITY_NB2_WALLET_SPLIT')), cBytes(token)));
    return this.locked(`split/${toHex(id)}`, () => this.splitInner(token, owner, outputs, id));
  }

  private async splitInner(token: Uint8Array, owner: OwnerSigner, outputs: { ownerKey: Uint8Array; amount: bigint }[], id: Uint8Array): Promise<Uint8Array[]> {
    let rec = await this.journal.split(hex(id));
    if (rec === null) {
      const held = await this.verifyToken(token);
      if (outputs.length < 2) refuse('BadInput', 'a split has at least two outputs');
      let sum = 0n;
      for (const o of outputs) {
        if (o.amount <= 0n) refuse('BadInput', 'every output amount is positive');
        parseKey(o.ownerKey);
        sum += o.amount;
      }
      if (sum !== held.amount) refuse('BadInput', `the outputs sum to ${sum}, the token holds ${held.amount}`);
      rec = {
        ...this.journal.base(), kind: 'split', splitId: hex(id), source: hex(token), mask: hex(freshMask()), status: 'planned',
        outputs: outputs.map((o) => ({ ownerKey: hex(o.ownerKey), amount: dec(o.amount), salt: hex(crypto.getRandomValues(new Uint8Array(32))), token: null })),
      };
      await this.journal.putSplit(rec);
    }
    const parent = decodeToken(unhex(rec.source));
    const plan = splitPlan(parent, rec.outputs.map((o) => ({ ownerKey: unhex(o.ownerKey), amount: undec(o.amount), salt: unhex(o.salt) })), this.cfg.ty, this.cfg.aid, unhex(rec.mask));
    if (rec.status === 'planned') {
      const { tx, cd } = await transferRequest(unhex(rec.source), owner, plan.burn);
      rec.burnTx = hex(tx);
      rec.burnRequest = hex(cd);
      rec.status = 'burn-requested';
      await this.journal.putSplit(rec);
    }
    if (rec.status === 'burn-requested') {
      const proof = await certifyChecked(this.opts.aggregator, unhex(rec.burnRequest!));
      rec.burned = hex(appendTransfer(unhex(rec.source), unhex(rec.burnTx!), proof));
      rec.status = 'burned';
      await this.journal.putSplit(rec);
    }
    const burned = unhex(rec.burned!);
    for (let k = 0; k < rec.outputs.length; k++) {
      if (rec.outputs[k].token !== null) continue;
      const m = childMint(burned, plan.tree, plan.children[k]);
      const { tx, cd } = mintRequest(m);
      const child = tokenOfMint(tx, await certifyChecked(this.opts.aggregator, cd));
      const v = await this.verifyToken(child);
      if (v.amount !== undec(rec.outputs[k].amount)) refuse('ProviderFault', 'a split child has another amount');
      rec.outputs[k].token = hex(child);
      await this.journal.putSplit(rec);
    }
    rec.status = 'minted';
    await this.journal.putSplit(rec);
    return rec.outputs.map((o) => unhex(o.token!));
  }

  // ==== Unicity -> EVM ==================================================================================================

  /** The newest verified seal receipt (section 12.2) and its container, or null when the vault has never sealed. */
  public async newestSealReceipt(): Promise<{ receipt: SealReceipt; encoded: Uint8Array } | null> {
    const log = await this.evm.newestSeal(this.cfg.vault, this.opts.pins.deploymentBlock);
    if (log === null) return null;
    const rp = await this.evm.receiptProof(log.transactionHash, this.cfg.vault, TOPIC.SegmentSealed);
    const receipt = await this.retryingTrust(() => verifySealReceipt(this.cfg, this.domain, this.opts.trust, rp.encoded));
    return { receipt, encoded: rp.encoded };
  }

  /** Run `f`; on a retryable NoEntryForEpoch extend the history (if the wallet gave a way) and run it once more. */
  private async retryingTrust<T>(f: () => Promise<T>): Promise<T> {
    try {
      return await f();
    } catch (e) {
      if (!(e instanceof Nb2Error) || !e.retryable || this.opts.refreshTrust === undefined) throw e;
      await this.opts.refreshTrust();
      return f();
    }
  }

  /**
   * Plan the return of a whole held part to `recipient` on the EVM: verify its full provenance, pick the index from a verified seal
   * receipt, and run the capacity preflight (section 12.5): the complete prospective return with the history already owed from `a` plus
   * `returnReserveSegments` must fit the encoded-transaction limit and `userGasLimit`, and `payer` must fund that gas limit. Journals the
   * plan; nothing irreversible happens here.
   */
  public async planReturn(token: Uint8Array, recipient: Uint8Array, payer: Uint8Array, opts: { useStateRead?: boolean; verifiedIndex?: bigint } = {}): Promise<ReturnPlan> {
    const returnId = HU(token);
    return this.locked(`return/${toHex(returnId)}`, async () => {
      const part = decodeToken(token);
      const held = await this.retryingTrust(() => verifyHeld(this.cfg, this.domain, this.opts.trust, part));
      if (recipient.length !== 20) refuse('BadInput', 'an EVM recipient is 20 bytes');
      if (recipient.every((x) => x === 0) || eq(recipient, this.cfg.vault)) refuse('RecipientRefused', 'the zero address and the vault are refused');
      const warnings: string[] = [];
      if ((await this.evm.code(recipient)).length > 0) warnings.push('the recipient is a contract: a payout it refuses strands the burn (simulation is not a guarantee)');
      // the index
      let a: bigint;
      let startHead: Uint8Array;
      let fromBlock = this.opts.pins.deploymentBlock;
      let sealReceipt: Uint8Array | undefined;
      if (opts.useStateRead) {
        const st = await this.evm.vaultState(this.cfg.vault);
        checkStateRead(this.opts.pins.stateReadOnly, st.segment, opts.verifiedIndex ?? 0n, this.opts.pins.maxJump ?? 64n);
        a = st.segment;
        startHead = a === 0n ? genesisHead(this.domain, this.cfg.K) : st.head;
      } else {
        const sr = await this.newestSealReceipt();
        ({ a, startHead } = burnIndex(this.cfg, this.domain, sr?.receipt ?? null));
        if (sr !== null) {
          fromBlock = sr.receipt.blockNumber;
          sealReceipt = sr.encoded;
          // availability, not safety: an old receipt anchors the burn low (more history to prove), never in the future
          const age = (await this.evm.blockNumber()) - sr.receipt.blockNumber;
          if (age > (this.opts.maxSealAgeBlocks ?? 7_200n)) warnings.push(`the newest seal receipt served is ${age} blocks old: the provider may be hiding newer seals; the burn then owes more history`);
        }
      }
      const pf = await this.preflight(token, held.amount, recipient, a, payer);
      const existing = await this.journal.ret(hex(returnId));
      if (existing !== null && existing.status !== 'planned') refuse('NotPending', `this part's return is already ${existing.status}`);
      const record: ReturnRecord = {
        ...this.journal.base(), kind: 'return', returnId: hex(returnId), source: hex(token), amount: dec(held.amount), recipient: hex(recipient), a: dec(a),
        startHead: hex(startHead), fromBlock: dec(fromBlock), ...(sealReceipt ? { sealReceipt: hex(sealReceipt) } : {}), payer: hex(payer), status: 'planned', sends: [],
      };
      await this.journal.putReturn(record);
      return { returnId, amount: held.amount, recipient, a, cObs: pf.cObs, pNow: pf.pNow, pMax: pf.pMax, marginSegments: pf.pMax - pf.need, gasLimit: pf.gas, warnings, record };
    });
  }

  /**
   * The section 12.5 preflight for burning `token` at index `a` to `recipient`, with a fresh endpoint estimate (c_obs = max(c, a); the
   * state read is an availability assumption, not evidence) and the payer's funds for the worst-case gas limit.
   */
  private async preflight(token: Uint8Array, amount: bigint, recipient: Uint8Array, a: bigint, payer: Uint8Array): Promise<{ cObs: bigint; pNow: bigint; need: bigint; pMax: bigint; gas: bigint }> {
    const st = await this.evm.vaultState(this.cfg.vault);
    const cObs = st.segment > a ? st.segment : a;
    const R = encodeReturnData({ d: this.domain, asset: ASSET_UCT, recipient, amount, minIndex: a });
    const lT = BigInt(evidenceOf(token).length + burnPairBound(R.length));
    const lO = BigInt(otherBytes(Number(lT)));
    const lineage = lineageOf(decodeToken(token));
    const gasAt = (p: bigint): bigint | null => this.gas.redeemGasLimit({ evidenceBytes: Number(lT), lineage, pendingTransactions: 1, proofs: p, K: this.cfg.K });
    const pins = this.opts.pins;
    const pf = capacityPreflight({ lMax: pins.maxEncodedTxBytes, lT, lO, K: this.cfg.K, a, cObs, reserve: pins.returnReserveSegments, gasAt, userGasLimit: pins.userGasLimit });
    // the payer must fund the worst-case gas limit at the current fee level (twice the base fee plus the priority fee)
    const fees = await this.evm.fees();
    const cost = pf.gas * (2n * fees.baseFee + fees.priority);
    const bal = await this.evm.balance(payer);
    if (bal < cost) refuse('InsufficientFunds', `the payer holds ${bal} wei, the worst-case gas limit ${pf.gas} needs ${cost}`);
    return { cObs, ...pf };
  }

  private async returnRecord(id: Uint8Array): Promise<ReturnRecord> {
    return (await this.journal.ret(hex(id))) ?? refuse('JournalNotPersisted', `no journal entry for return ${hexq(id)}`);
  }

  /**
   * Certify the terminal burn of a planned return: R signs the recipient, the amount and the index. The exact request is journaled
   * before certification, the certified burn before this returns; a second call resumes the same burn and never makes another.
   */
  public burn(returnId: Uint8Array, owner: OwnerSigner): Promise<{ burned: Uint8Array; eta: Uint8Array; verdict: Verdict }> {
    return this.locked(`return/${toHex(returnId)}`, () => this.burnInner(returnId, owner));
  }

  private async burnInner(returnId: Uint8Array, owner: OwnerSigner): Promise<{ burned: Uint8Array; eta: Uint8Array; verdict: Verdict }> {
    const rec = await this.returnRecord(returnId);
    if (rec.status === 'planned') {
      // the last check before the irreversible step: the preflight again, at the journaled index, against a fresh state
      await this.preflight(unhex(rec.source), undec(rec.amount), unhex(rec.recipient), undec(rec.a), rec.payer === undefined ? unhex(rec.recipient) : unhex(rec.payer));
      const R = encodeReturnData({ d: this.domain, asset: ASSET_UCT, recipient: unhex(rec.recipient), amount: undec(rec.amount), minIndex: undec(rec.a) });
      const { tx, cd } = await transferRequest(unhex(rec.source), owner, { recipient: burnPredicate(HU(R)), mask: freshMask(), data: R, deadline: null });
      rec.burnTx = hex(tx);
      rec.burnRequest = hex(cd);
      rec.status = 'burn-requested';
      await this.journal.putReturn(rec);
    }
    if (rec.status === 'burn-requested') {
      const proof = await certifyChecked(this.opts.aggregator, unhex(rec.burnRequest!));
      const burned = appendTransfer(unhex(rec.source), unhex(rec.burnTx!), proof);
      const v = await verifyPart(this.cfg, this.domain, this.opts.trust, decodeEvidence(evidenceOf(burned)));
      if (v.minSegment !== undec(rec.a) || v.amount !== undec(rec.amount) || !eq(v.recipient, unhex(rec.recipient))) refuse('ProviderFault', 'the certified burn is not the planned one');
      rec.burned = hex(burned);
      rec.eta = hex(v.eta);
      rec.status = 'burned';
      await this.journal.putReturn(rec);
    }
    const burned = unhex(rec.burned!);
    const verdict = await verifyPart(this.cfg, this.domain, this.opts.trust, decodeEvidence(evidenceOf(burned)));
    return { burned, eta: verdict.eta, verdict };
  }

  /**
   * Build the redeem transaction of a burned return: one SegmentSealed log per segment a .. c-1 from any provider, each checked
   * (length, order, M_j, head link from the journaled start head), the gap proofs, and the gas limit (expected cost plus gasReserve).
   * A missing or reordered log is missing evidence, never absence. Refuses with `CapacityExceeded` when the claim does not fit.
   */
  public buildRedeem(returnId: Uint8Array): Promise<RedeemTx> {
    return this.locked(`return/${toHex(returnId)}`, () => this.buildRedeemInner(returnId));
  }

  private async buildRedeemInner(returnId: Uint8Array): Promise<RedeemTx> {
    const rec = await this.returnRecord(returnId);
    if (rec.status !== 'burned' && rec.status !== 'submitted') refuse('NotPending', `return ${hexq(returnId)} is ${rec.status}`);
    const a = undec(rec.a);
    const eta = unhex(rec.eta!);
    const evidence = evidenceOf(unhex(rec.burned!));
    for (let attempt = 0; ; attempt++) {
      const st = await this.evm.vaultState(this.cfg.vault);
      if (st.segment < a) refuse('NotPending', `the vault is at segment ${st.segment}, below the burn index ${a}: wait (FutureIndex)`);
      const logs = await this.evm.segmentLogs(this.cfg.vault, undec(rec.fromBlock), a, st.segment);
      const segs: Segment[] = [];
      let before = unhex(rec.startHead);
      for (const l of logs) {
        const j = BigInt(hexq(l.topics[1]));
        const s = checkSegmentLog(this.domain, this.cfg.K, j, before, l.data);
        segs.push(s);
        before = s.after;
      }
      if (!eq(before, st.head)) {
        // the chain moved between the reads, or the provider is inconsistent: read again once
        if (attempt < 2) continue;
        refuse('ProviderFault', 'the served segment logs do not fold to the vault\'s current head');
      }
      const { history, paid } = buildHistory(segs, eta, a, st.segment, unhex(rec.startHead));
      if (paid !== null) refuse('AlreadyPaid', `the redemption ID is in sealed segment ${paid}: reconcile`);
      const P = st.segment - a;
      const calldata = redeemCalldata(evidence, eta, a, history);
      const pins = this.opts.pins;
      const lO = BigInt(otherBytes(evidence.length));
      let gasLimit = this.gas.redeemGasLimit({ evidenceBytes: evidence.length, lineage: lineageOf(decodeToken(unhex(rec.burned!))), pendingTransactions: 0, proofs: P, K: this.cfg.K });
      if (gasLimit === null) fail('CapacityExceeded', 'the gas cannot be bounded');
      const est = await this.evm.estimateGas({ from: unhex(rec.recipient), to: this.cfg.vault, data: calldata });
      if ('gas' in est) gasLimit = est.gas + pins.gasReserve;
      else {
        const e = decodeRevert(est.revert ?? new Uint8Array());
        const action = classifyRedeemError(e);
        if (action === 'rebuild-history' && attempt < 2) continue;
        if (action === 'reconcile') refuse('AlreadyPaid', 'the vault reports AlreadyPaid: reconcile');
        if (e !== null) throw new Nb2Error(e.rule, `simulation refused (${action})`, e.args.map((x) => (typeof x === 'bigint' ? String(x) : hexq(x))));
        // no rule: an RPC without simulation; the model's bound stands
      }
      capacityExceeded(pins.maxEncodedTxBytes, BigInt(evidence.length), lO, this.cfg.K, P, gasLimit!, pins.userGasLimit);
      return { returnId, calldata, gasLimit: gasLimit!, P, endpoint: st.segment, history, eta, claimedStart: a };
    }
  }

  /**
   * Send the redeem. Earlier sends are reconciled first (a pending one is never doubled; a landed one is the answer). Every signed
   * transaction is journaled before broadcast; an ambiguous broadcast is resolved by its receipt. A stale endpoint is rebuilt, never
   * the burn; failures are classified by error selector.
   */
  public submitRedeem(returnId: Uint8Array, signer: EvmSigner): Promise<ReconcileResult> {
    return this.locked(`return/${toHex(returnId)}`, () => this.submitRedeemInner(returnId, signer));
  }

  private async submitRedeemInner(returnId: Uint8Array, signer: EvmSigner): Promise<ReconcileResult> {
    const prior = await this.reconcileInner(returnId);
    if (prior.state === 'paid' || prior.state === 'pending') return prior;
    let gasBump = 1n;
    for (let attempt = 0; attempt < 4; attempt++) {
      const rtx = await this.buildRedeemInner(returnId);
      const gas = rtx.gasLimit * gasBump > this.opts.pins.userGasLimit ? this.opts.pins.userGasLimit : rtx.gasLimit * gasBump;
      const tx = await this.signed(signer, this.cfg.vault, rtx.calldata, 0n, gas);
      const fresh = (await this.returnRecord(returnId));
      fresh.sends.push(this.sendRecord(tx));
      fresh.status = 'submitted';
      fresh.firstSendBlock = fresh.firstSendBlock ?? dec(await this.evm.blockNumber());
      await this.journal.putReturn(fresh);
      const r = await this.broadcastAndWait(tx);
      if (r === null) return { state: 'pending', txHash: tx.hash };
      if (BigInt(r.status) === 1n) return (await this.verifiedPaid(await this.returnRecord(returnId), tx.hash)) ?? { state: 'pending', txHash: tx.hash };
      // reverted: classify by simulating the same call at the current state
      const re = await this.evm.estimateGas({ from: signer.address, to: this.cfg.vault, data: rtx.calldata });
      const e = 'revert' in re ? decodeRevert(re.revert ?? new Uint8Array()) : null;
      const action = 'gas' in re ? 'retry-later' : classifyRedeemError(e);
      if (action === 'reconcile') return this.reconcileInner(returnId);
      if (action === 'rebuild-history' || action === 'repair-proof') continue;
      if (action === 'retry-later') {
        gasBump = 2n; // an out-of-gas or a transient payout failure: one retry with more gas
        continue;
      }
      throw new Nb2Error(e?.rule ?? 'PayoutFailed', `redeem 0x${toHex(tx.hash)} reverted: stop and tell the user`);
    }
    return { state: 'not-paid' };
  }

  /**
   * Look for Paid(eta) and the receipts of every journaled send; never changes the burn. A Paid log counts only from the vault and only
   * once its receipt is verified under the block's EVM UC (section 6.2 steps 2 to 5): a provider that invents or withholds Paid can
   * delay the wallet, never stop its redemption.
   */
  public reconcile(returnId: Uint8Array): Promise<ReconcileResult> {
    return this.locked(`return/${toHex(returnId)}`, () => this.reconcileInner(returnId));
  }

  private async reconcileInner(returnId: Uint8Array): Promise<ReconcileResult> {
    const rec = await this.returnRecord(returnId);
    if (rec.status === 'paid') return { state: 'paid', txHash: unhex(rec.paid!.txHash), blockNumber: undec(rec.paid!.blockNumber) };
    if (rec.eta === undefined) return { state: 'not-paid' };
    const eta = unhex(rec.eta);
    for (const l of await this.evm.paid(this.cfg.vault, eta, undec(rec.fromBlock))) {
      const p = decodePaid(l);
      if (p === null || !eq(l.address, this.cfg.vault) || !eq(p.eta, eta)) continue;
      const v = await this.verifiedPaid(rec, l.transactionHash);
      if (v !== null) return v;
    }
    const landed = await this.landedSend(rec.sends, () => this.journal.putReturn(rec));
    if (landed === 'pending') return { state: 'pending', txHash: unhex(rec.sends[rec.sends.length - 1].hash) };
    if (landed !== null) {
      const v = await this.verifiedPaid(rec, unhex(landed.transactionHash.toLowerCase()));
      return v ?? { state: 'pending', txHash: unhex(landed.transactionHash.toLowerCase()) };
    }
    return { state: 'not-paid' };
  }

  /**
   * Verify that transaction `tx` paid this return: its Paid log, from the vault, with topics [Paid, eta, recipient] and data the amount,
   * in a receipt verified under the block's certificate. Journals `paid` and returns it; 'pending' while the block is not certified yet;
   * null when the claim does not verify (it is ignored).
   */
  private async verifiedPaid(rec: ReturnRecord, tx: Uint8Array): Promise<ReconcileResult | null> {
    const eta = unhex(rec.eta!);
    try {
      const rp = await this.evm.receiptProof(tx, this.cfg.vault, TOPIC.Paid);
      const log = await this.retryingTrust(() => verifyReceiptLog(this.cfg, this.opts.trust, rp.proof));
      const recipientWord = concat(new Uint8Array(12), unhex(rec.recipient));
      if (log.topics.length !== 3 || !eq(log.topics[0], TOPIC.Paid) || !eq(log.topics[1], eta) || !eq(log.topics[2], recipientWord)
        || log.data.length !== 32 || beInt(log.data) !== undec(rec.amount)) return null;
      rec.paid = { txHash: hex(tx), blockNumber: dec(rp.blockNumber) };
      rec.status = 'paid';
      await this.journal.putReturn(rec);
      return { state: 'paid', txHash: tx, blockNumber: rp.blockNumber };
    } catch (e) {
      if (e instanceof WalletError && e.reason === 'CompanionUnknown') return { state: 'pending', txHash: tx };
      if (e instanceof Nb2Error || e instanceof WalletError) return null;
      throw e;
    }
  }

  // ==== status ==========================================================================================================

  /** Where every journaled deposit and return stands, in words. */
  public async status(): Promise<string[]> {
    const out: string[] = [];
    const say: Record<string, string> = {
      planned: 'planned: the secret is journaled; send the deposit', submitted: 'sent: waiting for the receipt (submitDeposit again reconciles)',
      deposited: 'deposited: waiting for the block certificate (collectDepositProof)', proven: 'proven: J is journaled; mint', minted: 'minted',
    };
    for (const d of await this.journal.deposits()) out.push(`deposit intent ${d.intent} of ${d.amount}: ${say[d.status]}`);
    const rsay: Record<string, string> = {
      planned: 'planned: preflight passed; burn', 'burn-requested': 'burn requested: call burn again to finish certification',
      burned: 'burned: build and submit the redeem', submitted: 'redeem sent: reconcile', paid: 'paid',
    };
    for (const r of await this.journal.returns()) out.push(`return ${r.returnId.slice(0, 18)} of ${r.amount} to ${r.recipient} (a = ${r.a}): ${rsay[r.status]}`);
    return out;
  }

  // ==== EVM plumbing ====================================================================================================

  private async signed(signer: EvmSigner, to: Uint8Array, data: Uint8Array, value: bigint, gas: bigint): Promise<SignedTx> {
    const [nonce, fees] = await Promise.all([this.evm.nonce(signer.address), this.evm.fees()]);
    return signTx(signer, { chainId: this.cfg.chainId, nonce, maxPriorityFeePerGas: fees.priority, maxFeePerGas: 2n * fees.baseFee + fees.priority, gas, to, value, data });
  }

  private sendRecord(tx: SignedTx): SendRecord {
    return { hash: hex(tx.hash), raw: hex(tx.raw), nonce: dec(tx.request.nonce), gas: dec(tx.request.gas), at: dec(this.now()) };
  }

  /** Broadcast and poll the receipt of the locally computed hash; null when none arrived in time (the send stays journaled). */
  private async broadcastAndWait(tx: SignedTx): Promise<ReceiptJson | null> {
    try {
      await this.evm.sendRaw(tx.raw);
    } catch (e) {
      if (!(e instanceof AmbiguousBroadcast)) throw e;
    }
    const deadline = this.now() + (this.opts.receiptTimeoutMs ?? 60_000);
    for (;;) {
      const r = await this.evm.receipt(tx.hash);
      if (r !== null) return r;
      if (this.now() >= deadline) return null;
      await this.sleep(this.opts.pollMs ?? 1_000);
    }
  }

  /**
   * The outcome of a record's earlier sends: a success receipt (the answer), 'pending', or null (none is alive: a new send is safe).
   * The order defends against a send mined between reads and against load-balanced backends at different heights: the account's MINED
   * nonce is read first, then every send's receipt; a success receipt is the answer whenever it is seen. A send whose nonce is used
   * without a success receipt is dead only after the head has advanced `deadAfterBlocks` since that was first seen (journaled in
   * `nonceUsedAt`), the block at `nonceUsedAt` has a certificate (a found companion), and every receipt is read again; until then it
   * is pending. A send still in a pool is broadcast again (same bytes).
   */
  private async landedSend(sends: SendRecord[], save: () => Promise<void>): Promise<ReceiptJson | 'pending' | null> {
    if (sends.length === 0) return null;
    const last = sends[sends.length - 1];
    const from = decodeSignedTx(unhex(last.raw)).from;
    const mined = await this.evm.nonce(from, 'latest');
    for (const s of sends) {
      const r = await this.evm.receipt(unhex(s.hash));
      if (r !== null && BigInt(r.status) === 1n) return r;
    }
    if (mined <= undec(last.nonce)) {
      // the nonce is unused by any mined transaction: the send is alive, in a pool or lost; offer the same bytes again
      try {
        await this.evm.sendRaw(unhex(last.raw));
      } catch (e) {
        if (!(e instanceof AmbiguousBroadcast)) throw e;
      }
      return 'pending';
    }
    // a mined transaction used the nonce, and no success receipt is visible: wait for depth before calling it dead
    const head = await this.evm.blockNumber();
    if (last.nonceUsedAt === undefined) {
      last.nonceUsedAt = dec(head);
      await save();
      return 'pending';
    }
    if (head < undec(last.nonceUsedAt) + (this.opts.deadAfterBlocks ?? 6n)) return 'pending';
    // and the block at which the nonce was seen used is certified (a found companion, section 12.7): depth alone is not finality
    const at = await this.evm.headerByNumber(undec(last.nonceUsedAt));
    if (at === null) return 'pending';
    try {
      await this.evm.certificateOf(at.header, at.hash);
    } catch (e) {
      if (e instanceof WalletError || e instanceof Nb2Error) return 'pending';
      throw e;
    }
    for (const s of sends) {
      const r = await this.evm.receipt(unhex(s.hash));
      if (r !== null && BigInt(r.status) === 1n) return r;
    }
    return null;
  }
}

/** The lineage of a part, root first. */
export function lineageOf(part: Token): Token[] {
  const chain: Token[] = [part];
  for (let cur = part; cur.mint.justification !== null && headTag(cur.mint.justification) === TAG.splitJustification;) {
    cur = decodeSplitJustification(cur.mint.justification).parent;
    chain.unshift(cur);
  }
  return chain;
}

/**
 * An upper bound of the encoded [burn transfer, inclusion proof] pair with return data of `rLen` bytes: the transfer, the
 * certification data, the reference time, an RSMT path of at most 256 siblings and an aggregator UC at its decoder bound.
 */
export const burnPairBound = (rLen: number): number => {
  const transfer = 3 + 1 + 45 + 34 + 3 + rLen + 9;
  const cd = 3 + 1 + 45 + 34 + 34 + 9 + 67;
  return 4 + transfer + 3 + 1 + cd + 9 + 3 + 32 + 32 * 256 + (24 << 10);
};

/** Everything of the redeem transaction besides the evidence and the gap proofs: ABI heads and padding, the start head, the envelope. */
export const otherBytes = (evidence: number): number => {
  const calldata = redeemCalldataLength(evidence, 32) + 31; // the start head, and the history's padding at most 31 bytes
  return calldata - evidence + redeemTxFraming(calldata);
};

export { encodeToken, log2, gapProofLen, decodeDepositProof };
