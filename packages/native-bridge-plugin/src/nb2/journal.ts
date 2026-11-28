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
  cancel?: () => Promise<void>;
  retain?: () => Promise<void>;
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
    const key = `nb2/payer-sends/v1/${request.chainId}/${toHex(from)}/${record.domain.slice(2)}/${record.returnId.slice(2)}`;
    await this.retainPayerNonce(key, request.nonce);
  }

  private async retainPayerNonce(key: string, nonce: bigint): Promise<void> {
    for (;;) {
      const previous = await this.store.get(key);
      if ((previous !== null && undec(previous) >= nonce) || await this.store.putIf(key, previous, dec(nonce))) return;
    }
  }

  /** Mark a return only after indexing every separately journaled signed recovery packet. */
  public async indexPayerSends(record: ReturnRecord, raw: readonly Uint8Array[]): Promise<void> {
    for (const signed of raw) await this.retainPayerSend(record, signed);
    const key = `nb2/payer-index/v1/${record.domain.slice(2)}/${record.returnId.slice(2)}`;
    await this.store.putIf(key, null, '1');
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
      for (const send of rec.sends) {
        const { from, request } = decodeSignedTx(unhex(send.raw));
        if (request.chainId === chainId && eqBytes(from, payer)) includeNonce(request.nonce);
      }
      const registered = await this.store.get(`nb2/domain-chain/v1/${rec.domain.slice(2)}`);
      // Pre-upgrade returns without chain metadata remain protected until their domain is opened.
      if (registered !== null && undec(registered) !== chainId) continue;
      if (rec.status !== 'planned' && rec.executionPayer === address &&
          await this.store.get(`nb2/payer-index/v1/${rec.domain.slice(2)}/${rec.returnId.slice(2)}`) !== '1') {
        fail('CapacityPreflight', 'another return needs its local signed sends indexed');
      }
      if (!active(rec)) continue;
      commitment.fees += undec(rec.recovery!.totalFee);
      const calls = undec(rec.recovery!.calls);
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
    const domainKey = `nb2/domain-chain/v1/${toHex(this.domain)}`;
    await this.store.putIf(domainKey, null, dec(chainId));
    if (await this.store.get(domainKey) !== dec(chainId)) refuse('BadInput', 'journal domain has another chain ID');
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
          await this.retainPayerNonce(`nb2/payer-sends/v1/${chainId}/${toHex(payer)}/${domain}/${returned}`, heldNonce);
        }
      }
      if (!reserve) return commitment;

      const nonce = options.signingNonce;
      let claimed = owner === target ? held! : target;
      if (nonce !== undefined || (owner !== target && options.mode === 'drain' && commitment.calls > 0n)) {
        const current = await this.ret(id);
        if (!current || current.status === 'paid' || current.status === 'planned') {
          fail('CapacityPreflight', 'return is no longer eligible for payer signing');
        }
        const admitted = current.recovery?.envelope?.maxNonce;
        const cap = admitted === undefined ? (1n << 64n) - 1n : undec(admitted);
        const maxNonce = payerNonceLimit(options.maxNonce !== undefined && options.maxNonce < cap ? options.maxNonce : cap, commitment);
        const calls = owner !== target && commitment.calls > 0n
          ? options.remainingCalls ?? undec(current.recovery!.calls)
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
