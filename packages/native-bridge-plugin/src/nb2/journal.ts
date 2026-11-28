/**
 * The wallet journal (format `unicity-nb2-journal`, version 1), documented byte for byte in `docs/nb2-journal.md` so the Rust plug-in
 * (#1104) reads and writes the same records. A journal is a key-value store of JSON records, one per key:
 *
 *   nb2/v1/<D>/intents          the intent counter: the next unused intent i (its high-water mark is next - 1)
 *   nb2/v1/<D>/deposit/<i>      one deposit, from its plan to the minted token
 *   nb2/v1/<D>/split/<id>       one split, from its plan to the minted children
 *   nb2/v1/<D>/transfer/<id>    one ordinary transfer and its retained certification
 *   nb2/v1/<D>/return/<id>      one return, from its plan to the Paid event
 *
 * <D> is the deployment domain in lowercase hex without 0x. Byte strings are 0x-prefixed lowercase hex; integers are decimal strings
 * (they exceed 2^53). A record is written whole; `put` resolves only once the record is durable. The plug-in writes each record
 * BEFORE the step it enables (secret before value, burn request before certification, every signed transaction before broadcast).
 */
import { eq as eqBytes, fromHex, toHex } from '../bytes.js';
import { fail, refuse } from './errors.js';
import { decodeSignedTx } from './evm.js';

export const JOURNAL_FORMAT = 'unicity-nb2-journal';
export const JOURNAL_VERSION = 1;

/**
 * Durable key-value storage. `putIf` is a compare-and-swap: it writes `value` only when the stored value is exactly `expected` (null:
 * absent) and reports whether it did; it must not resolve before the value survives a crash. Two wallets (or two processes) sharing a
 * store therefore never both advance the same record: the second write is refused and the plug-in stops with `JournalConflict`.
 */
export interface JournalStore {
  get(key: string): Promise<string | null>;
  putIf(key: string, expected: string | null, value: string): Promise<boolean>;
  list(prefix: string): Promise<string[]>;
}

export class MemoryJournalStore implements JournalStore {
  public readonly map = new Map<string, string>();
  public get(key: string): Promise<string | null> {
    return Promise.resolve(this.map.get(key) ?? null);
  }
  public putIf(key: string, expected: string | null, value: string): Promise<boolean> {
    if ((this.map.get(key) ?? null) !== expected) return Promise.resolve(false);
    this.map.set(key, value);
    return Promise.resolve(true);
  }
  public list(prefix: string): Promise<string[]> {
    return Promise.resolve([...this.map.keys()].filter((k) => k.startsWith(prefix)).sort());
  }
}

export type Hex = string; // 0x-prefixed lowercase
export type Dec = string; // decimal

/** A signed EVM transaction the wallet broadcast (or is about to). */
export interface SendRecord {
  hash: Hex;
  raw: Hex;
  nonce: Dec;
  gas: Dec;
  at: Dec;
  /** The head block when a mined transaction of the account was first seen past this nonce without this send's success receipt. */
  nonceUsedAt?: Dec;
  /** Marks that a failed receipt of this send was seen (no blind resend); capped, never a verdict. */
  failureProofReads?: number;
  /** The block that failed receipt was last seen in: a receipt gone CERTIFICATION_DEPTH past it was rolled back. */
  failureBlock?: Dec;
  /** Certified exact failure, verified before the send became eligible for retry. */
  failed?: { txHash: Hex; blockHash: Hex };
}

interface Base { format: typeof JOURNAL_FORMAT; version: typeof JOURNAL_VERSION; domain: Hex }

export interface IntentsRecord extends Base {
  kind: 'intents';
  /** The wallet-versioned derivation of k_w from the seed, e.g. "nb2-hmac-sha256-v1". */
  keyScheme: string;
  next: Dec;
}

export type DepositStatus = 'planned' | 'submitted' | 'deposited' | 'proven' | 'minted';

export interface DepositRecord extends Base {
  kind: 'deposit';
  keyScheme: string;
  intent: Dec;
  amount: Dec;
  /** ERC20 intent fields survive reconciliation of the certified net credit. */
  erc20Token?: Hex;
  requested?: Dec;
  minCredit?: Dec;
  approvalSends?: SendRecord[];
  /** The first owner's compressed key and its 42-byte predicate. */
  ownerKey: Hex;
  firstOwner: Hex;
  rho: Hex;
  status: DepositStatus;
  /** The intent's high-water mark has been handed to the wallet's backup (section 12.1). */
  backedUp: boolean;
  sends: SendRecord[];
  /** The transaction that executed the deposit, its block and the vault's deposit number. */
  depositTx?: Hex;
  blockNumber?: Dec;
  depositNumber?: Dec;
  /** The DepositProof container and the mint reason J. */
  receiptProof?: Hex;
  reason?: Hex;
  /** The certified token. */
  token?: Hex;
  /** Exact mint proof, awaiting offline verification. */
  mintProof?: Hex;
  /** Optional: r itself, when the wallet backs up secrets rather than the high-water mark. */
  secret?: Hex;
  /** The head block when the plan was made: a deposit carrying this rho is looked for from here before the first send. */
  plannedBlock?: Dec;
  /**
   * Every Deposited event seen with this rho (a faulty wallet that reused r, or two devices). The first is the record's own deposit;
   * each further one is a separate root token (its own n), minted with `mintExtraDeposit`.
   */
  seenDeposits?: { tx: Hex; depositNumber: Dec; blockNumber: Dec; amount: Dec; firstOwner: Hex; token?: Hex; mintProof?: Hex; reason?: Hex }[];
}

export type SplitStatus = 'planned' | 'burn-requested' | 'burned' | 'minted';

export interface SplitOutputRecord { ownerKey: Hex; amount: Dec; salt: Hex; token: Hex | null; mintProof?: Hex }

export interface SplitRecord extends Base {
  kind: 'split';
  splitId: Hex;
  source: Hex;
  outputs: SplitOutputRecord[];
  mask: Hex;
  status: SplitStatus;
  /** The manifest burn transaction and its certification request, journaled before the first submission. */
  burnTx?: Hex;
  burnRequest?: Hex;
  burnProof?: Hex;
  burned?: Hex;
}

export interface TransferRecord extends Base {
  kind: 'transfer';
  transferId: Hex;
  recipient: Hex;
  tx: Hex;
  request: Hex;
  proof?: Hex;
}

export type ReturnStatus = 'planned' | 'burn-requested' | 'burned' | 'submitted' | 'paid';

export interface ReturnRecord extends Base {
  kind: 'return';
  returnId: Hex;
  /** The held part before its burn. */
  source: Hex;
  amount: Dec;
  recipient: Hex;
  /** The signed minimum segment index and the start head it came with (H_{j+1} of the seal receipt, or H_0). */
  a: Dec;
  startHead: Hex;
  /** The block of the seal receipt that gave `a` (the deployment block when there was none): history logs are read from here. */
  fromBlock: Dec;
  /** The verified seal receipt (a DepositProof container), absent when a = 0. */
  sealReceipt?: Hex;
  status: ReturnStatus;
  burnTx?: Hex;
  burnRequest?: Hex;
  burnProof?: Hex;
  /** SID from which the exact signed request can be reconciled. */
  certificationLocator?: Hex;
  /** The authenticated cold route and the admission bound used at signing. */
  recovery?: {
    generation: Hex; calls: Dec; totalFee: Dec; runCuts: number[]; advanceGaps: number;
    observed: Dec; receiptP99Ms: Dec; finalInclusionMs: Dec; qualifiedForMs: Dec;
    /** Maximum segment already covered by the Run arrival allowance at signing. */
    progressEnd?: Dec;
    /** ERC20 signing ceilings used to price portable calls. */
    envelope?: { gas: Dec; signedBytes: number; calldataBytes: number; maxNonce: Dec; maxFeePerGas: Dec; maxPriorityFeePerGas: Dec };
    ordinary?: { gas: Dec; calldataBytes: number; maxFeePerGas: Dec; attemptsBeforeFallback: Dec };
  };
  /** The certified burned part: the redeem evidence's token. */
  burned?: Hex;
  eta?: Hex;
  sends: SendRecord[];
  /** The payer of the first durable payout send, shared by both routes. */
  executionPayer?: Hex;
  /** A mined payment hint whose certified proof is still being fetched. */
  paidProof?: { txHash: Hex; reads: number; block?: Dec };
  /** The head when this return first saw an unproven claim of another party's payment: the start of VANISHED_CLAIM_HORIZON. */
  peerClaimSince?: Dec;
  /** The EVM account that pays the redeem's gas (its funds are checked before the burn). */
  payer?: Hex;
  /** The first block at which a redeem was broadcast: Paid(eta) cannot appear before it. */
  firstSendBlock?: Dec;
  paid?: { txHash: Hex; blockNumber: Dec; blockHash?: Hex; receipt?: Hex; txIndex?: Dec; logIndex?: Dec };
}

export type AnyRecord = IntentsRecord | DepositRecord | SplitRecord | ReturnRecord | TransferRecord;

export const hex = (b: Uint8Array): Hex => `0x${toHex(b)}`;
export function unhex(s: Hex): Uint8Array {
  if (!/^0x([0-9a-f]{2})*$/.test(s)) refuse('BadInput', `journal field ${s.slice(0, 20)} is not lowercase 0x hex`);
  return fromHex(s.slice(2))!;
}
export const dec = (v: bigint | number): Dec => BigInt(v).toString(10);
export function undec(s: Dec): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(s)) refuse('BadInput', `journal field ${s} is not a decimal`);
  return BigInt(s);
}

const returnKey = /^nb2\/v1\/([0-9a-f]{64})\/return\/([0-9a-f]{64})$/;

export interface PayerCheck {
  mode?: 'admit' | 'drain';
  finalizedNonce?: () => Promise<bigint>;
  finalizedBlock?: (number: bigint, hash: Uint8Array) => Promise<boolean>;
  /** A unique fence for a new holder signing attempt. */
  fence?: Hex;
  /** The exact nonce to fence before invoking an EVM signer. */
  signingNonce?: bigint;
  /** Remaining calls, after replaying verified progress, including the packet about to be signed. */
  remainingCalls?: bigint;
  maxNonce?: bigint;
  beforeSigning?: (commitments: PayerCommitments) => Promise<void>;
}

export interface PayerCommitments {
  fees: bigint;
  calls: bigint;
  nonceWindows?: { calls: bigint; maxNonce?: bigint }[];
  finalizedNonce?: bigint;
  contestedDrain?: boolean;
  cancel?: () => Promise<void>;
  retain?: () => Promise<void>;
}

/** Calls still reserved after a verified prefix of the admitted continuation. */
export function remainingRecoveryCalls(plan: NonNullable<ReturnRecord['recovery']>, completed: bigint, ordinaryUsed = 0n): bigint {
  const prior = undec(plan.ordinary?.attemptsBeforeFallback ?? '0');
  const spent = ordinaryUsed > prior ? prior : ordinaryUsed;
  const continuation = undec(plan.calls) - prior - completed;
  return (continuation > 0n ? continuation : 1n) + prior - spent;
}

export function remainingOrdinaryAttempts(plan?: ReturnRecord['recovery'], used = 0n): bigint {
  const prior = undec(plan?.ordinary?.attemptsBeforeFallback ?? '0');
  return used < prior ? prior - used : 0n;
}

export function continuationReserve(continuation: bigint, ordinary: bigint, attempts: bigint): bigint {
  return (attempts > 0n && ordinary > continuation ? ordinary : continuation) + attempts * ordinary;
}

interface RecoveryProgress { completed: bigint; continuationGas?: bigint }
interface StoredRecoveryProgress { completed: Dec; continuationGas?: Dec }

function recoveryProgressOf(value: string): RecoveryProgress {
  const { completed, continuationGas } = JSON.parse(value) as StoredRecoveryProgress;
  return { completed: undec(completed), continuationGas: continuationGas === undefined ? undefined : undec(continuationGas) };
}

/** Price other returns at their admitted ceiling. A verified checkpoint can supply the remaining gas. */
function remainingRecoveryFee(plan: NonNullable<ReturnRecord['recovery']>, progress: RecoveryProgress | undefined,
  ordinaryUsed: bigint): bigint {
  const total = undec(plan.totalFee);
  const savedBid = plan.envelope?.maxFeePerGas ?? plan.ordinary?.maxFeePerGas;
  if (savedBid === undefined) return total;
  const admitted = undec(savedBid);
  if (admitted === 0n) fail('CapacityPreflight', 'invalid continuation fee ceiling');
  const ordinary = undec(plan.ordinary?.gas ?? '0');
  const attempts = remainingOrdinaryAttempts(plan, ordinaryUsed);
  if (progress?.continuationGas !== undefined) return continuationReserve(progress.continuationGas, ordinary, attempts) * admitted;
  const spent = remainingOrdinaryAttempts(plan) - attempts;
  const left = total - spent * ordinary * admitted;
  return left > 0n ? left : 0n;
}
/** Last nonce this return may use while leaving feasible nonce windows for the older returns. */
export function payerNonceLimit(maxNonce: bigint, other: PayerCommitments): bigint {
  const windows = (other.nonceWindows ?? []).map((w) => ({ ...w, maxNonce: w.maxNonce ?? maxNonce }));
  windows.sort((a, b) => a.maxNonce === b.maxNonce ? 0 : a.maxNonce < b.maxNonce ? -1 : 1);
  let calls = 0n;
  let limit = maxNonce;
  for (const window of windows) {
    calls += window.calls;
    const before = window.maxNonce - calls;
    if (before < limit) limit = before;
  }
  return limit;
}

/** The first ordinary sender binds legacy records that predate the execution-payer field. */
export function executionPayerOf(record: ReturnRecord): Uint8Array | undefined {
  const first = record.sends[0] && decodeSignedTx(unhex(record.sends[0].raw)).from;
  if (record.executionPayer === undefined) return first;
  const payer = unhex(record.executionPayer);
  if (payer.length !== 20 || (first && !eqBytes(payer, first))) {
    refuse('BadInput', 'execution payer disagrees with the return journal');
  }
  return payer;
}

function requireExecutionPayer(record: ReturnRecord, payer: Uint8Array): void {
  const bound = executionPayerOf(record);
  if (bound && !eqBytes(bound, payer)) refuse('NotPending', `return is bound to execution payer ${hex(bound)}`);
}

/** The typed journal over a store, keyed by deployment. */
export class Journal {
  public readonly prefix: string;
  /** The stored text of every record this instance last read or wrote: the `expected` of its next compare-and-swap. */
  private readonly seen = new Map<string, string | null>();
  public constructor(public readonly store: JournalStore, public readonly domain: Uint8Array) {
    this.prefix = `nb2/v1/${toHex(domain)}/`;
  }

  private key(kind: string, id?: string): string {
    return id === undefined ? `${this.prefix}${kind}` : `${this.prefix}${kind}/${id}`;
  }

  /**
   * Read a record. Only a read `forUpdate` (taken under the key's lock, by the operation that then writes the record) sets the
   * `expected` of the next compare-and-swap; any other read leaves it alone, so an unlocked reader (`status`, a listing, a wallet's
   * own look) can never move a locked operation's comparison past another process's write.
   */
  private async read<T extends AnyRecord>(key: string, kind: T['kind'], forUpdate = false): Promise<T | null> {
    const s = await this.store.get(key);
    if (forUpdate) this.seen.set(key, s);
    if (s === null) return null;
    const r = JSON.parse(s) as T;
    if (r.format !== JOURNAL_FORMAT || r.version !== JOURNAL_VERSION || r.kind !== kind || r.domain !== hex(this.domain)) {
      refuse('BadInput', `journal record ${key} is not a version ${JOURNAL_VERSION} ${kind} record of this deployment`);
    }
    return r;
  }

  /** Write a record and read it back: the plug-in proceeds only on a record that is in the store. */
  private async write(key: string, r: AnyRecord): Promise<void> {
    const s = JSON.stringify(r);
    const expected = this.seen.has(key) ? this.seen.get(key)! : await this.store.get(key);
    if (expected === s) return;
    if (!(await this.store.putIf(key, expected, s))) {
      this.seen.delete(key);
      refuse('JournalConflict', `journal record ${key} changed under this wallet (another process?): reload and retry`);
    }
    if ((await this.store.get(key)) !== s) refuse('JournalNotPersisted', `journal record ${key} did not read back`);
    this.seen.set(key, s);
  }

  public base(): Base {
    return { format: JOURNAL_FORMAT, version: JOURNAL_VERSION, domain: hex(this.domain) };
  }

  public intents(): Promise<IntentsRecord | null> {
    return this.read<IntentsRecord>(this.key('intents'), 'intents');
  }
  /** The intents record, read for the write that follows (under its lock). */
  public intentsForUpdate(): Promise<IntentsRecord | null> {
    return this.read<IntentsRecord>(this.key('intents'), 'intents', true);
  }
  public putIntents(r: IntentsRecord): Promise<void> {
    return this.write(this.key('intents'), r);
  }

  public deposit(i: bigint): Promise<DepositRecord | null> {
    return this.read<DepositRecord>(this.key('deposit', dec(i)), 'deposit');
  }
  public depositForUpdate(i: bigint): Promise<DepositRecord | null> {
    return this.read<DepositRecord>(this.key('deposit', dec(i)), 'deposit', true);
  }
  public putDeposit(r: DepositRecord): Promise<void> {
    return this.write(this.key('deposit', r.intent), r);
  }
  public async deposits(): Promise<DepositRecord[]> {
    const keys = await this.store.list(this.key('deposit/'));
    const out: DepositRecord[] = [];
    for (const k of keys) out.push((await this.read<DepositRecord>(k, 'deposit'))!);
    return out.sort((a, b) => (undec(a.intent) < undec(b.intent) ? -1 : 1));
  }

  public split(id: Hex): Promise<SplitRecord | null> {
    return this.read<SplitRecord>(this.key('split', id.slice(2)), 'split');
  }
  public splitForUpdate(id: Hex): Promise<SplitRecord | null> {
    return this.read<SplitRecord>(this.key('split', id.slice(2)), 'split', true);
  }
  public putSplit(r: SplitRecord): Promise<void> {
    return this.write(this.key('split', r.splitId.slice(2)), r);
  }

  public transferForUpdate(id: Hex): Promise<TransferRecord | null> {
    return this.read<TransferRecord>(this.key('transfer', id.slice(2)), 'transfer', true);
  }

  public putTransfer(r: TransferRecord): Promise<void> {
    return this.write(this.key('transfer', r.transferId.slice(2)), r);
  }

  public ret(id: Hex): Promise<ReturnRecord | null> {
    return this.read<ReturnRecord>(this.key('return', id.slice(2)), 'return');
  }
  public retForUpdate(id: Hex): Promise<ReturnRecord | null> {
    return this.read<ReturnRecord>(this.key('return', id.slice(2)), 'return', true);
  }
  public putReturn(r: ReturnRecord): Promise<void> {
    return this.write(this.key('return', r.returnId.slice(2)), r);
  }
  public async returns(): Promise<ReturnRecord[]> {
    const keys = await this.store.list(this.key('return/'));
    const out: ReturnRecord[] = [];
    for (const k of keys) out.push((await this.read<ReturnRecord>(k, 'return'))!);
    return out;
  }

  public async allReturns(): Promise<{ key: string; record: ReturnRecord }[]> {
    const records: { key: string; record: ReturnRecord }[] = [];
    for (const key of await this.store.list('nb2/v1/')) {
      const match = returnKey.exec(key);
      if (!match) continue;
      const raw = await this.store.get(key);
      if (raw === null) refuse('JournalNotPersisted', 'return disappeared during payer reconciliation');
      const record = JSON.parse(raw) as ReturnRecord;
      if (record.domain !== '0x' + match[1] || record.returnId !== '0x' + match[2] || record.kind !== 'return'
        || record.format !== JOURNAL_FORMAT || record.version !== JOURNAL_VERSION) refuse('BadInput', 'invalid return in shared journal');
      records.push({ key, record });
    }
    return records;
  }

  /** Record the highest signed nonce before offering an exact transaction to any RPC. */
  public async retainPayerSend(record: ReturnRecord, raw: Uint8Array): Promise<void> {
    const { from, request } = decodeSignedTx(raw);
    requireExecutionPayer(record, from);
    const payer = this.payerSendPath(request.chainId, from, record);
    await this.retainPayerMaximum(`nb2/payer-fees/v1/${payer}/${request.nonce}`, request.gas * request.maxFeePerGas);
    await this.retainPayerMaximum(`nb2/payer-sends/v1/${payer}`, request.nonce);
  }

  private payerSendPath(chainId: bigint, payer: Uint8Array, record: ReturnRecord): string {
    return `${chainId}/${toHex(payer)}/${record.domain.slice(2)}/${record.returnId.slice(2)}`;
  }

  private async retainPayerMaximum(key: string, value: bigint): Promise<void> {
    for (;;) {
      const previous = await this.store.get(key);
      if ((previous !== null && undec(previous) >= value) || await this.store.putIf(key, previous, dec(value))) return;
    }
  }

  /** Pin this deployment domain to the chain authenticated by the SDK. */
  public async registerPayerChain(chainId: bigint): Promise<void> {
    const key = `nb2/domain-chain/v1/${toHex(this.domain)}`;
    await this.store.putIf(key, null, dec(chainId));
    if (await this.store.get(key) !== dec(chainId)) refuse('BadInput', 'journal domain has another chain ID');
  }

  private async payerHistoryComplete(path: string): Promise<boolean> {
    return await this.store.get(`nb2/payer-fee-index/v2/${path}`) === '1';
  }

  private async completePayerHistory(path: string): Promise<void> {
    await this.store.putIf(`nb2/payer-fee-index/v2/${path}`, null, '1');
    if (!await this.payerHistoryComplete(path)) refuse('JournalNotPersisted', 'payer fee index completion was not persisted');
  }

  /** Import the caller's complete local signed history. Unregistered domains cannot be marked complete. */
  public async indexPayerSends(record: ReturnRecord, raw: readonly Uint8Array[]): Promise<void> {
    const chain = await this.store.get(`nb2/domain-chain/v1/${record.domain.slice(2)}`);
    const bound = executionPayerOf(record);
    const covered = new Map<string, bigint>();
    for (const [index, signed] of [...raw, ...record.sends.map(({ raw }) => unhex(raw))].entries()) {
      const { from, request } = decodeSignedTx(signed);
      if (chain !== dec(request.chainId) || (bound && !eqBytes(bound, from))) continue;
      await this.retainPayerSend(record, signed);
      // Ordinary records alone cannot prove the separate recovery history of a recorded executor.
      const path = this.payerSendPath(request.chainId, from, record);
      if (record.executionPayer !== undefined && index >= raw.length && !covered.has(path)) continue;
      if (!covered.has(path) || request.nonce > covered.get(path)!) covered.set(path, request.nonce);
    }
    for (const [path, highest] of covered) {
      if (await this.store.get(`nb2/payer-sends/v1/${path}`) === dec(highest)) {
        await this.completePayerHistory(path);
      }
    }
  }

  /** Migrate ordinary sends after the wallet has established that its local recovery journal contains no sends. */
  public async indexOrdinaryPayerSends(record: ReturnRecord, chainId: bigint): Promise<void> {
    const payer = executionPayerOf(record);
    if (!payer || !record.sends.length) return;
    const path = this.payerSendPath(chainId, payer, record);
    if (await this.payerHistoryComplete(path)) return;
    const ordinary = record.sends.map(({ raw }) => unhex(raw));
    const maxima = new Map<bigint, bigint>();
    for (const raw of ordinary) {
      const { from, request } = decodeSignedTx(raw);
      if (request.chainId !== chainId || !eqBytes(from, payer)) return;
      const fee = request.gas * request.maxFeePerGas;
      if (fee > (maxima.get(request.nonce) ?? 0n)) maxima.set(request.nonce, fee);
    }
    const prefix = `nb2/payer-fees/v1/${path}/`;
    for (const key of await this.store.list(prefix)) {
      const value = await this.store.get(key);
      const fee = maxima.get(undec(key.slice(prefix.length)));
      if (value === null || fee === undefined || undec(value) > fee) return;
    }
    const claim = await this.store.get(`nb2/payer/v1/${chainId}/${toHex(payer)}`);
    const [owner, state] = claim?.split('#') ?? [];
    const returned = `nb2/v1/${record.domain.slice(2)}/return/${record.returnId.slice(2)}`;
    if (owner === returned && state?.startsWith('nonce:') && !maxima.has(undec(state.slice(6)))) return;
    await this.indexPayerSends(record, ordinary);
  }

  /** Read the maximum signed fee at each nonce across both return routes. */
  public async payerFeeMaxima(record: ReturnRecord, chainId: bigint, payer: Uint8Array): Promise<Map<bigint, bigint>> {
    if (record.domain !== hex(this.domain)) refuse('BadInput', 'return belongs to another payer journal domain');
    if (await this.store.get(`nb2/domain-chain/v1/${toHex(this.domain)}`) !== dec(chainId)) {
      fail('CapacityPreflight', 'payer fee history needs an authenticated chain association');
    }
    requireExecutionPayer(record, payer);
    const history = await this.ret(record.returnId) ?? record;
    requireExecutionPayer(history, payer);
    const path = this.payerSendPath(chainId, payer, history);
    const ordinary = history.sends.map(({ raw }) => decodeSignedTx(unhex(raw))).filter(({ from, request }) =>
      request.chainId === chainId && eqBytes(from, payer));
    if (history.executionPayer === undefined && ordinary.length > 0 && !await this.payerHistoryComplete(path)) {
      await this.indexPayerSends(history, []);
    }
    const prefix = `nb2/payer-fees/v1/${path}/`;
    const keys = await this.store.list(prefix);
    if ((history.executionPayer !== undefined || ordinary.length > 0 || keys.length > 0 ||
        await this.store.get(`nb2/payer-sends/v1/${path}`) !== null) && !await this.payerHistoryComplete(path)) {
      fail('CapacityPreflight', 'return needs its local signed fees indexed');
    }
    const fees = new Map<bigint, bigint>();
    const recordFee = (nonce: bigint, fee: bigint) => {
      if (fee > (fees.get(nonce) ?? 0n)) fees.set(nonce, fee);
    };
    for (const key of keys) {
      const value = await this.store.get(key);
      if (value === null) refuse('JournalNotPersisted', 'signed fee disappeared during payer reconciliation');
      recordFee(undec(key.slice(prefix.length)), undec(value));
    }
    for (const { request } of ordinary) recordFee(request.nonce, request.gas * request.maxFeePerGas);
    return fees;
  }

  /** Check an existing scope or initialize an empty one before asking the payer to sign. */
  public async preparePayerSigning(record: ReturnRecord, chainId: bigint, payer: Uint8Array): Promise<Map<bigint, bigint>> {
    const fees = await this.payerFeeMaxima(record, chainId, payer);
    await this.completePayerHistory(this.payerSendPath(chainId, payer, record));
    return fees;
  }

  /** Revalidate an exact signed packet's scope and retain its maximum before handing it to an RPC. */
  public async preparePayerBroadcast(record: ReturnRecord, chainId: bigint, raw: Uint8Array): Promise<void> {
    const { from, request } = decodeSignedTx(raw);
    if (request.chainId !== chainId) refuse('BadInput', 'signed payer packet belongs to another chain');
    await this.payerFeeMaxima(record, chainId, from);
    if (!await this.payerHistoryComplete(this.payerSendPath(chainId, from, record))) {
      fail('CapacityPreflight', 'return needs its local signed fees indexed');
    }
    await this.retainPayerSend(record, raw);
  }

  public async payerFees(record: ReturnRecord, chainId: bigint, payer: Uint8Array, nonce: bigint): Promise<{ prior: bigint; atNonce: bigint }> {
    const fees = await this.payerFeeMaxima(record, chainId, payer);
    const atNonce = fees.get(nonce) ?? 0n;
    fees.delete(nonce);
    let prior = 0n;
    for (const fee of fees.values()) prior += fee;
    return { prior, atNonce };
  }

  /** Publish a replayed checkpoint. Readers independently check execution finality before giving credit. */
  public async indexRecoveryProgress(chainId: bigint, record: ReturnRecord, completed: bigint,
    block: { blockNumber: bigint; blockHash: Uint8Array }, continuationGas?: bigint): Promise<void> {
    const plan = record.recovery;
    if (!plan || completed < 1n) return;
    const path = this.recoveryProgressPath(chainId, record);
    const key = `${path}${dec(block.blockNumber)}/${toHex(block.blockHash)}`;
    const value = JSON.stringify({ completed: dec(completed), continuationGas: continuationGas === undefined ? undefined : dec(continuationGas) });
    for (;;) {
      const previous = await this.store.get(key);
      if (previous !== null) {
        const saved = recoveryProgressOf(previous);
        if (saved.completed > completed || (saved.completed === completed && saved.continuationGas !== undefined &&
          (continuationGas === undefined || saved.continuationGas >= continuationGas))) return;
      }
      if (await this.store.putIf(key, previous, value)) return;
    }
  }

  private recoveryProgressPath(chainId: bigint, record: ReturnRecord): string {
    const plan = record.recovery!;
    return `nb2/payer-progress/v2/${chainId}/${record.domain.slice(2)}/${record.returnId.slice(2)}/` +
      `${plan.generation.slice(2)}/${plan.calls}/${plan.ordinary?.attemptsBeforeFallback ?? '0'}/${plan.advanceGaps}/${plan.runCuts.join(',')}/`;
  }

  public async finalizedRecoveryProgress(chainId: bigint, record: ReturnRecord, finalizedBlock?: PayerCheck['finalizedBlock']): Promise<RecoveryProgress | undefined> {
    if (!record.recovery || !finalizedBlock) return;
    let progress: RecoveryProgress | undefined;
    const path = this.recoveryProgressPath(chainId, record);
    for (const key of await this.store.list(path)) {
      const value = await this.store.get(key);
      if (value === null) refuse('JournalNotPersisted', 'recovery checkpoint disappeared during payer reconciliation');
      const candidate = recoveryProgressOf(value);
      if (progress && (candidate.completed < progress.completed || (candidate.completed === progress.completed &&
        (candidate.continuationGas ?? 0n) <= (progress.continuationGas ?? 0n)))) continue;
      const [number, hash] = key.slice(path.length).split('/');
      if (await finalizedBlock(undec(number), unhex('0x' + hash))) progress = candidate;
    }
    return progress;
  }

  private async payerCommitments(chainId: bigint, payer: Uint8Array, target: string, ownsSlot: boolean, options: PayerCheck): Promise<PayerCommitments> {
    const address = hex(payer);
    const path = `nb2/payer-sends/v1/${chainId}/${toHex(payer)}/`;
    const [, domain, id] = returnKey.exec(target)!;
    const own = `${domain}/${id}`;
    let highest: bigint | undefined;
    const commitment: PayerCommitments = { fees: 0n, calls: 0n };
    const includeNonce = (nonce: bigint) => { if (highest === undefined || nonce > highest) highest = nonce; };
    const active = (rec: ReturnRecord) => rec.status !== 'planned' && rec.status !== 'paid' && !!rec.recovery &&
      ((rec.payer ?? rec.recipient) === address || rec.executionPayer === address);
    let draining = false;
    for (const { key, record: rec } of await this.allReturns()) {
      if (key === target) {
        draining = active(rec);
        continue;
      }
      const ordinary = new Set<bigint>();
      for (const send of rec.sends) {
        const { from, request } = decodeSignedTx(unhex(send.raw));
        if (request.chainId === chainId && eqBytes(from, payer)) {
          includeNonce(request.nonce);
          ordinary.add(request.nonce);
        }
      }
      const registered = await this.store.get(`nb2/domain-chain/v1/${rec.domain.slice(2)}`);
      // Pre-upgrade returns without chain metadata remain protected until their domain is opened.
      if (registered !== null && undec(registered) !== chainId) continue;
      if (rec.status !== 'planned' && rec.executionPayer === address &&
          (registered === null || !await this.payerHistoryComplete(this.payerSendPath(chainId, payer, rec)))) {
        fail('CapacityPreflight', 'another return needs its local signed sends indexed');
      }
      if (!active(rec)) continue;
      const progress = await this.finalizedRecoveryProgress(chainId, rec, options.finalizedBlock);
      const used = BigInt(ordinary.size);
      commitment.fees += remainingRecoveryFee(rec.recovery!, progress, used);
      // The signed-nonce check below must pass before any of these ordinary nonces can count as used.
      const calls = remainingRecoveryCalls(rec.recovery!, progress?.completed ?? 0n, used);
      commitment.calls += calls;
      const cap = rec.recovery!.envelope?.maxNonce;
      (commitment.nonceWindows ??= []).push({ calls, maxNonce: cap === undefined ? undefined : undec(cap) });
    }
    for (const key of await this.store.list(path)) {
      if (key === path + own) continue;
      const value = await this.store.get(key);
      if (value === null) refuse('JournalNotPersisted', 'signed nonce disappeared during payer reconciliation');
      includeNonce(undec(value));
    }
    if (highest !== undefined) {
      const finalized = await options.finalizedNonce?.();
      if (finalized === undefined || finalized <= highest) fail('CapacityPreflight', 'payer has a local signed nonce awaiting finalization');
      commitment.finalizedNonce = finalized;
    }
    if (commitment.calls !== 0n && (options.mode !== 'drain' || (!draining && !ownsSlot))) {
      fail('CapacityPreflight', 'payer already has an outstanding ERC20 return');
    }
    return commitment;
  }

  /** Admit one new return per payer. Existing funded returns can drain in sequence. */
  public async checkReturnPayer(chainId: bigint, payer: Uint8Array, id: Hex, reserve = false, options: PayerCheck = {}): Promise<PayerCommitments> {
    if (payer.length !== 20 || !/^0x[0-9a-f]{64}$/.test(id)) refuse('BadInput', 'invalid ERC20 payer or return ID');
    if (options.fence && options.signingNonce !== undefined) refuse('BadInput', 'payer claim cannot sign both a burn and an EVM packet');
    await this.registerPayerChain(chainId);
    const key = `nb2/payer/v1/${chainId}/${toHex(payer)}`;
    const target = this.key('return', id.slice(2));
    for (;;) {
      const held = await this.store.get(key);
      const [owner, state] = held?.split('#') ?? [];
      const heldNonce = state?.startsWith('nonce:') ? undec(state.slice(6)) : undefined;
      if (owner && owner !== target) {
        if (!returnKey.test(owner)) refuse('BadInput', 'invalid ERC20 payer reservation');
        const raw = await this.store.get(owner);
        const previous = raw === null ? null : JSON.parse(raw) as ReturnRecord;
        if (previous?.status !== 'paid' || !previous.paid) fail('CapacityPreflight', 'payer already has an outstanding ERC20 return');
      }
      const commitment = await this.payerCommitments(chainId, payer, target, owner === target, options);
      if (owner !== target && heldNonce !== undefined) {
        const finalized = commitment.finalizedNonce ?? await options.finalizedNonce?.();
        if (finalized === undefined || finalized <= heldNonce) fail('CapacityPreflight', 'payer has a local signing nonce awaiting finalization');
        commitment.finalizedNonce = finalized;
        if (reserve) {
          const [, domain, returned] = returnKey.exec(owner)!;
          await this.retainPayerMaximum(`nb2/payer-sends/v1/${chainId}/${toHex(payer)}/${domain}/${returned}`, heldNonce);
        }
      }
      if (!reserve) return commitment;

      const nonce = options.signingNonce;
      let claimed = owner === target ? held! : target;
      commitment.contestedDrain = owner !== target && options.mode === 'drain' && commitment.calls > 0n;
      if (nonce !== undefined || commitment.contestedDrain) {
        const current = await this.ret(id);
        if (!current || current.status === 'paid' || current.status === 'planned') {
          fail('CapacityPreflight', 'return is no longer eligible for payer signing');
        }
        if (nonce !== undefined) requireExecutionPayer(current, payer);
        const admitted = current.recovery?.envelope?.maxNonce;
        const cap = admitted === undefined ? (1n << 64n) - 1n : undec(admitted);
        const maxNonce = payerNonceLimit(options.maxNonce !== undefined && options.maxNonce < cap ? options.maxNonce : cap, commitment);
        const calls = commitment.contestedDrain
          ? options.remainingCalls ?? remainingRecoveryCalls(current.recovery!,
            (await this.finalizedRecoveryProgress(chainId, current, options.finalizedBlock))?.completed ?? 0n)
          : 1n;
        if (nonce === undefined || calls < 1n || nonce < (commitment.finalizedNonce ?? 0n) || nonce + calls - 1n > maxNonce) {
          fail('CapacityPreflight', 'remaining continuation schedule exceeds the payer nonce horizon');
        }
        await options.beforeSigning?.(commitment);
        claimed = target + '#nonce:' + dec(owner === target && heldNonce !== undefined && heldNonce > nonce ? heldNonce : nonce);
      }
      const attempts = state?.startsWith('burn:') ? state.slice(5).split(',') : undefined;
      const fence = options.fence;
      if (fence && (owner !== target || attempts)) {
        claimed = target + '#burn:' + [...(owner === target ? attempts ?? [] : []), fence].join(',');
      }
      if (claimed === held && nonce === undefined) return commitment;
      if (!await this.store.putIf(key, held, claimed)) continue;
      if (fence && claimed.startsWith(target + '#burn:')) {
        const finish = async (unsigned: boolean) => {
          const prefix = target + '#burn:';
          for (;;) {
            const live = await this.store.get(key);
            if (!live?.startsWith(prefix)) return;
            const attempts = live.slice(prefix.length).split(',');
            if (!attempts.includes(fence)) return;
            const current = await this.ret(id);
            const remaining = attempts.filter((attempt) => attempt !== fence);
            const next = unsigned && current?.status === 'planned' && !current.burnRequest
              ? remaining.length ? prefix + remaining.join(',') : ''
              : target;
            if (await this.store.putIf(key, live, next)) return;
          }
        };
        commitment.cancel = () => finish(true);
        commitment.retain = () => finish(false);
      }
      return commitment;
    }
  }

}

/**
 * The `putIf` contract every wallet journal store must meet, as a check any store can run (its own tests, or a wallet's start-up
 * self-test against a scratch location). `fresh` opens an empty store; `reopen` opens the same storage again (a new process after a
 * crash would). It checks the compare-and-swap (one write against absence wins, a stale or absent expectation loses and changes
 * nothing), atomicity (of `writers` concurrent writes against one text exactly one wins and its value is stored), persistence (a
 * reopened store reads back every won write) and `list` (sorted keys of a prefix). Throws on the first violation.
 */
export async function checkJournalStore<S extends JournalStore>(fresh: () => Promise<S> | S, reopen: (s: S) => Promise<S> | S, writers = 16): Promise<void> {
  const fail = (m: string): never => {
    throw new Error(`journal store: ${m}`);
  };
  const s = await fresh();
  const k = 'nb2/v1/conformance/a';
  const k2 = 'nb2/v1/conformance/b';
  if ((await s.get(k)) !== null) fail('a fresh store is not empty');
  if (!(await s.putIf(k, null, 'v1'))) fail('a write against absence lost on an empty key');
  if (await s.putIf(k, null, 'v1b')) fail('a second write against absence won');
  if (await s.putIf(k, 'other', 'v1c')) fail('a write against a stale text won');
  if ((await s.get(k)) !== 'v1') fail('a lost write changed the record');
  if (!(await s.putIf(k, 'v1', 'v2'))) fail('a write against the stored text lost');
  if (!(await s.putIf(k2, null, 'w1'))) fail('a write of a second key lost');
  const wins = await Promise.all(Array.from({ length: writers }, (_, i) => s.putIf(k, 'v2', `race-${i}`).catch(() => false)));
  const winners = wins.flatMap((w, i) => (w ? [i] : []));
  if (winners.length !== 1) fail(`${winners.length} of ${writers} concurrent writes against one text won`);
  if ((await s.get(k)) !== `race-${winners[0]}`) fail('the stored value is not the winner\'s');
  const again = await reopen(s);
  if ((await again.get(k)) !== `race-${winners[0]}` || (await again.get(k2)) !== 'w1') fail('a reopened store does not hold every won write');
  if (JSON.stringify(await again.list('nb2/v1/conformance/')) !== JSON.stringify([k, k2])) fail('list is not the sorted keys of the prefix');
}
