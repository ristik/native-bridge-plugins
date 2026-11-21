/** NB2 continuation v1.1 packet construction and authenticated checkpoint boundaries. */
import { concat, concatBytes, eq, toHex } from '../bytes.js';
import { abiEncode } from './abi.js';
import { ascii, be, beInt, cArr, cTag, head, raw, scanNative, u16, u64, u256 } from './cbor.js';
import { decodeConfig, domainOf, MAX_SEGMENT, type Config, type Params } from './config.js';
import { HE, HU } from './crypto.js';
import { decodeDepositProof, decodeReceiptBacking, encodeDepositProof, verifyReceiptLog } from './deposit.js';
import { fail, Nb2Error, refuse, WalletError } from './errors.js';
import { quoteRecovery, validRecoveryDeployment, type RecoveryCalibration, type RecoveryLimits, type RecoveryQuote, type RecoveryShape } from './recovery-cost.js';
import { verifySealReceipt } from './rules.js';
import { foldHistory, gapProofLen, GapTree } from './segment.js';
import { decodeSplitManifest, parentLink } from './split.js';
import { decodeToken, lineageOf, mintSourceHash, resultState, stateId, tokenIdOf } from './token.js';
import { bindTrust, decodeUc, SealAheadOfOrigin, type TrustInput } from './trust.js';
import { parseMintData, verdictAbi, verifyPart, type Verdict } from './verify.js';

const version = u16(0x0101);
const zero = new Uint8Array(32);
const pageSize = 4096;
const calldataCap = 393_216;
const receiptCap = 65_536;
const hash = (label: string, ...parts: Uint8Array[]): Uint8Array => HE(HE(ascii('UNICITY/NB2/CONT/1.1/' + label)), ...parts);
const u32 = (n: number | bigint): Uint8Array => be(n, 4);
const blob = (data: Uint8Array): Uint8Array => concat(u32(data.length), data);
const topics = {
  progress: HE(ascii('NB2Progress11(bytes32,uint64,bytes32)')),
  complete: HE(ascii('NB2Complete11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256)')),
  gap: HE(ascii('NB2Gap11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256,uint64,bytes32)')),
};
type Kind = keyof typeof topics;
type Entry = 'run' | 'advanceGaps' | 'redeemRecovered';
const coldCall = (entry: Entry, parts: Uint8Array[]): Uint8Array => {
  const body = concatBytes(parts);
  if (68 + Math.ceil(body.length / 32) * 32 > calldataCap) fail('InputTooLarge', 'cold calldata');
  return concat(HE(ascii(entry + '(bytes)')).subarray(0, 4), abiEncode([{ bytes: body }]));
};

class Pages {
  private readonly tree: Uint8Array[][];
  constructor(private readonly evidence: Uint8Array) {
    const count = Math.ceil(evidence.length / pageSize);
    const width = 2 ** Math.ceil(Math.log2(count));
    const pad = hash('PAD');
    const leaves = Array.from({ length: width }, (_, i) => {
      if (i >= count) return pad;
      const bytes = this.data(i);
      return hash('PAGE', u64(evidence.length), u64(i), u16(bytes.length), bytes);
    });
    this.tree = [leaves];
    for (let level = leaves; level.length > 1;) {
      const child = level;
      level = Array.from({ length: child.length / 2 }, (_, i) => hash('PAGE_NODE', child[2 * i], child[2 * i + 1]));
      this.tree.push(level);
    }
  }
  get root(): Uint8Array { return this.tree.at(-1)![0]; }
  private data(index: number): Uint8Array { return this.evidence.subarray(index * pageSize, (index + 1) * pageSize); }
  opening(index: number): Uint8Array {
    const parts = [u64(index), this.data(index)];
    for (const level of this.tree.slice(0, -1)) {
      parts.push(level[index % 2 === 0 ? index + 1 : index - 1]);
      index = Math.floor(index / 2);
    }
    return concatBytes(parts);
  }
}

class Sparse {
  private readonly nodes = Array.from({ length: 257 }, () => new Map<bigint, Uint8Array>());
  private readonly defaults: Uint8Array[] = [zero];
  constructor(private readonly label: string) {
    for (let i = 0; i < 256; i++) this.defaults.push(hash(label, this.defaults[i], this.defaults[i]));
  }
  get root(): Uint8Array { return this.nodes[256].get(0n) ?? this.defaults[256]; }
  /** Open the old leaf before optionally installing a new one. */
  open(key: Uint8Array, leaf?: Uint8Array): Uint8Array {
    let index = beInt(key);
    let bitmap = 0n;
    const siblings: Uint8Array[] = [];
    for (let h = 0; h < 256; h++, index >>= 1n) {
      const sibling = this.nodes[h].get(index ^ 1n);
      if (sibling !== undefined) {
        bitmap |= 1n << BigInt(h);
        siblings.push(sibling);
      }
      if (leaf !== undefined) {
        this.nodes[h].set(index, leaf);
        const other = sibling ?? this.defaults[h];
        leaf = (index & 1n) === 0n ? hash(this.label, leaf, other) : hash(this.label, other, leaf);
      }
    }
    if (leaf !== undefined) this.nodes[256].set(0n, leaf);
    return concat(u256(bitmap), ...siblings);
  }
}

interface ClaimOpening { key: string; full: Uint8Array }
interface Operation { start: number; end: number; code: number; sid: Uint8Array; claims: ClaimOpening[]; after: Uint8Array | null }
interface State {
  phase: number; pos: number; levels: number; transfers: number; owner: Uint8Array; state: Uint8Array;
  id: Uint8Array; amount: bigint; link: Uint8Array; manifest: Uint8Array;
}
const stateBody = (s: State, seen: Sparse, claims: Sparse): Uint8Array => concat(
  Uint8Array.of(s.phase), u64(s.pos), u64(s.levels), u64(s.transfers), seen.root, claims.root,
  s.owner, s.state, s.id, u256(s.amount), s.link, s.manifest,
);
const withSeq = (body: Uint8Array, seq: bigint): Uint8Array => concat(body.subarray(0, 1), u64(seq), body.subarray(1));

function operations(evidence: Uint8Array, token: ReturnType<typeof decodeToken>, cfg: Config, domain: Uint8Array): Operation[] {
  const seen = new Sparse('SID_NODE');
  const claims = new Sparse('CLAIM_NODE');
  const values = new Map<string, Uint8Array>();
  const claimOpening = (raw: Uint8Array): ClaimOpening => {
    const uc = decodeUc(raw);
    const shard = uc.shardTreeCertificate.shard.encode();
    const location = concat(u32(uc.unicityTreeCertificate.partitionIdentifier), u16(shard.length), shard);
    const root = uc.inputRecord.nullableHash;
    if (root === null || root.length !== 32) fail('CertStructure');
    const key = hash('CLAIM_KEY', HU(uc.unicitySeal.toCBOR()), location);
    const value = hash('CLAIM_VALUE', HU(location, uc.shardConfigurationHash, root!, HU(uc.inputRecord.toCBOR()), blob(raw)));
    const hex = toHex(key);
    const old = values.get(hex);
    if (old !== undefined && !eq(old, value)) fail('CertStructure', 'conflicting recovery claim');
    const opening = claims.open(key, old === undefined ? hash('CLAIM', key, value) : undefined);
    values.set(hex, value);
    return { key: hex, full: old === undefined ? concat(Uint8Array.of(0, 0), opening) : concat(Uint8Array.of(0, 1), old, opening) };
  };
  const result: Operation[] = [];
  const chain = lineageOf(token);
  const s: State = { phase: 1, pos: 14, levels: chain.length, transfers: 0, owner: new Uint8Array(33), state: zero, id: zero, amount: 0n, link: zero, manifest: zero };
  // decodeToken already checked complete consumption and all framing bounds.
  const view = new DataView(evidence.buffer, evidence.byteOffset, evidence.length);
  const skipBlob = (): void => { s.pos += 4 + view.getUint32(s.pos); };
  for (const [i, level] of chain.entries()) {
    const start = s.pos;
    skipBlob();
    skipBlob();
    skipBlob();
    s.pos += 8;
    const mint = level.mint;
    s.id = tokenIdOf(mint.salt, mint.network);
    s.amount = parseMintData(cfg, mint.data);
    s.owner = mint.recipient.params;
    s.state = resultState(mintSourceHash(s.id), s.id);
    s.phase = 3;
    s.transfers = level.transfers.length;
    s.link = zero;
    s.manifest = zero;
    const cd = level.mintProof.cd;
    const sid = stateId(cd.source, cd.sourceHash);
    const sidOpening = seen.open(sid, hash('SID', sid));
    const mintClaims = i === 0 ? [claimOpening(decodeReceiptBacking(mint.justification!).proof.uc)] : [];
    mintClaims.push(claimOpening(level.mintProof.uc));
    result.push({ start, end: s.pos, code: i === 0 ? 1 : 2, sid: sidOpening, claims: mintClaims, after: stateBody(s, seen, claims) });
    for (const [j, transfer] of level.transfers.entries()) {
      const start = s.pos;
      skipBlob();
      const proof = level.proofs[j];
      const cd = proof.cd;
      const sid = stateId(cd.source, cd.sourceHash);
      const opening = seen.open(sid, hash('SID', sid));
      const claim = claimOpening(proof.uc);
      s.transfers--;
      const terminal = s.transfers === 0 && s.levels === 1;
      if (s.transfers !== 0) {
        s.state = resultState(s.state, transfer.mask);
        s.owner = transfer.recipient.params;
      } else if (!terminal) {
        s.manifest = decodeSplitManifest(transfer.data!);
        s.link = parentLink(domain, s.id, sid, cd.txHash, s.manifest, s.amount);
        s.owner = new Uint8Array(33);
        s.state = zero;
        s.levels--;
        s.phase = 2;
      }
      result.push({ start, end: s.pos, code: 3, sid: opening, claims: [claim], after: terminal ? null : stateBody(s, seen, claims) });
    }
  }
  return result;
}

/** These identities must come from the authenticated deployment, including the recovery runtime hash and dependency pin. */
export interface RecoveryDeployment { salt: Uint8Array; recovery: Uint8Array; runtimeHash: Uint8Array; pins: Uint8Array; vaultRuntimeHash?: Uint8Array }
export interface RecoveryEvent { kind: Kind; topics: Uint8Array[]; data: Uint8Array }
export interface RecoveryReceipt {
  encoded: Uint8Array; blockNumber: bigint; blockHash: Uint8Array; txIndex: bigint; logIndex: bigint;
}
export type RecoveryReceiptSource = (emitter: Uint8Array, event: RecoveryEvent) => Promise<Uint8Array>;

export interface GapPrior { seq: bigint; cursor?: { next: bigint; head: Uint8Array } }
export interface GapPacket { shape: RecoveryShape; calldata: Uint8Array; event: RecoveryEvent | null; next: bigint; head: Uint8Array | undefined }
export interface RunPacket { shape: RecoveryShape; calldata: Uint8Array; end: number; state: Uint8Array | null; event: RecoveryEvent }

/** One authority for all sessions on a deployment. Restore the persisted checkpoint before reopening.
 * Supply an independently decoded history for each update. The callback durably saves
 * the authenticated origin and history before a newer checkpoint can be used.
 */
export class RecoveryAuthority {
  #pending: Promise<unknown> = Promise.resolve();
  #held: TrustInput;
  #persistedTip: TrustInput['history']['tip'];
  constructor(checkpoint: TrustInput, private readonly persist: (next: TrustInput) => Promise<void>) {
    this.#held = checkpoint;
    this.#persistedTip = checkpoint.history.tip;
  }
  get checkpoint(): TrustInput { return this.#held; }
  accept(offered: TrustInput, cfg: Config): Promise<TrustInput> {
    const next = this.#pending.then(async () => {
      const held = this.#held;
      bindTrust(held, cfg);
      bindTrust(offered, cfg);
      const tip = held.history.tip!;
      if (held === offered && tip === this.#persistedTip) return held;
      const prefix = offered.history.entryForEpoch(tip.epoch);
      if (prefix === null || !eq(await prefix.entryId(), await tip.entryId())
        || offered.origin!.rootRound < held.origin!.rootRound || offered.origin!.usableEpoch < held.origin!.usableEpoch) {
        refuse('TrustInput', 'recovery authority rolls back the held history or origin');
      }
      const offeredTip = offered.history.tip;
      if (held.history.tip !== tip) refuse('TrustInput', 'held history changed during recovery authority validation');
      try {
        await this.persist(offered);
      } catch (e) {
        throw new WalletError('TrustInput', 'could not persist recovery authority', e);
      }
      this.#held = offered;
      this.#persistedTip = offeredTip;
      return offered;
    });
    this.#pending = next.catch(() => {});
    return next;
  }
}

export class RecoverySession {
  private constructor(
    private readonly cfg: Config, private readonly deployment: RecoveryDeployment, private readonly pages: Pages,
    private readonly session: Uint8Array, private readonly header: Uint8Array, private readonly verdict: Verdict,
    private readonly ops: Operation[], private readonly authority: RecoveryAuthority,
  ) {}
  static async create(gamma: Uint8Array, evidence: Uint8Array, authority: RecoveryAuthority, params: Params, input: RecoveryDeployment): Promise<RecoverySession> {
    const deployment = { salt: Uint8Array.from(input.salt), recovery: Uint8Array.from(input.recovery), runtimeHash: Uint8Array.from(input.runtimeHash), pins: Uint8Array.from(input.pins),
      vaultRuntimeHash: input.vaultRuntimeHash && Uint8Array.from(input.vaultRuntimeHash) };
    const { salt, recovery, runtimeHash, pins } = deployment;
    if (!validRecoveryDeployment(deployment)) fail('ConfigShape');
    const config = Uint8Array.from(gamma);
    const cfg = decodeConfig(config, params);
    const domain = domainOf(config);
    const snapshot = Uint8Array.from(evidence);
    const token = decodeToken(snapshot);
    let trust: TrustInput;
    let verdict: Verdict;
    do {
      trust = authority.checkpoint;
      verdict = await verifyPart(cfg, domain, trust, token);
    } while (trust !== authority.checkpoint);
    const pages = new Pages(snapshot);
    const header = concat(version, u64(snapshot.length), pages.root);
    const generation = hash('GEN', salt, domain);
    const session = hash('SESSION', version, generation, domain, cfg.vault, recovery, runtimeHash, pins, header.subarray(2));
    return new RecoverySession(cfg, deployment, pages, session, header, verdict, operations(snapshot, token, cfg, domain), authority);
  }
  get id(): Uint8Array { return this.session.slice(); }
  get pageRoot(): Uint8Array { return this.pages.root.slice(); }
  get operationCount(): number { return this.ops.length; }
  private event(kind: Kind, data: Uint8Array): RecoveryEvent { return { kind, topics: [topics[kind].slice(), this.id], data }; }

  /** Produce one exact cut. Resume requires an authenticated receipt for the state derived from that prefix. */
  async run(from: number, count: number, trust: TrustInput, prior?: { seq: bigint; receipt: Uint8Array }): Promise<RunPacket> {
    if (!Number.isSafeInteger(from) || !Number.isSafeInteger(count) || from < 0 || count < 1 || count > 16 || from + count > this.ops.length || (from === 0) !== (prior === undefined)) fail('Shape', 'run cut');
    let prefix: Uint8Array = Uint8Array.of(0);
    const seq = prior === undefined ? 1n : prior.seq + 1n;
    if (seq >= 1n << 64n || (prior && prior.seq <= 0n)) fail('Shape', 'sequence');
    let receiptBytes = 0;
    if (prior !== undefined) {
      if (prior.receipt.length > receiptCap) fail('InputTooLarge', 'cold receipt');
      const receipt = Uint8Array.from(prior.receipt);
      receiptBytes = receipt.length;
      const state = withSeq(this.ops[from - 1].after!, prior.seq);
      await this.verifyEvent(trust, receipt, this.event('progress', concat(u256(prior.seq), hash('STATE', this.session, state))));
      prefix = concat(Uint8Array.of(1), state, blob(receipt));
    } else {
      await this.authority.accept(trust, this.cfg);
    }
    const end = from + count;
    const firstPage = from === 0 ? 0 : Math.floor(this.ops[from].start / pageSize);
    const lastPage = Math.floor((this.ops[end - 1].end - 1) / pageSize);
    const pages = lastPage - firstPage + 1;
    if (pages > 32) fail('InputTooLarge', 'run pages');
    const table = Array.from({ length: pages }, (_, i) => this.pages.opening(firstPage + i));
    const used = new Set<string>();
    const steps = this.ops.slice(from, end).map((op) => concat(Uint8Array.of(op.code), op.sid, ...op.claims.map((claim) => {
      const cached = used.has(claim.key);
      used.add(claim.key);
      return cached ? Uint8Array.of(1) : claim.full;
    })));
    const last = this.ops[end - 1].after;
    const state = last === null ? null : withSeq(last, seq);
    const event = state === null
      ? this.event('complete', concat(u256(seq), verdictAbi(this.verdict)))
      : this.event('progress', concat(u256(seq), hash('STATE', this.session, state)));
    const calldata = coldCall('run', [this.header, prefix, Uint8Array.of(pages), ...table, Uint8Array.of(count), ...steps]);
    const shape: RecoveryShape = { entry: 'run', calldataBytes: calldata.length, operations: count, pages, gaps: 0,
      receiptBytes, openingBytes: steps.reduce((sum, step) => sum + step.length - 1, 0) };
    return { shape, calldata, end, state, event };
  }

  private checkCalibration(calibration: RecoveryCalibration, limits: RecoveryLimits): void {
    if (!eq(this.deployment.pins, calibration.pins) || !eq(this.deployment.runtimeHash, calibration.runtimeHash)
      || this.cfg.chainId !== limits.chainId) fail('CapacityPreflight', 'unqualified recovery deployment');
  }

  /** Fit the largest prefix within the authenticated packet and transaction limits. */
  async runBounded(from: number, trust: TrustInput, calibration: RecoveryCalibration, limits: RecoveryLimits,
    prior?: { seq: bigint; receipt: Uint8Array }): Promise<{ packet: RunPacket; quote: RecoveryQuote }> {
    this.checkCalibration(calibration, limits);
    for (let count = Math.min(16, this.ops.length - from); count > 0; count--) {
      try {
        const packet = await this.run(from, count, trust, prior);
        const quote = quoteRecovery(packet.shape, calibration, limits);
        if (quote !== null) return { packet, quote };
      } catch (e) {
        if (!(e instanceof Nb2Error && e.rule === 'InputTooLarge' && (e.detail === 'run pages' || e.detail === 'cold calldata'))) throw e;
      }
    }
    return fail('CapacityPreflight', 'indivisible run operation');
  }

  private snapshotEvent(expected: RecoveryEvent): RecoveryEvent {
    const { kind, data } = expected;
    if (expected.topics.length !== 2 || !eq(expected.topics[0], topics[kind]) || !eq(expected.topics[1], this.session)) {
      refuse('ProviderFault', 'recovery expectation belongs to a different session or event');
    }
    return this.event(kind, Uint8Array.from(data));
  }

  async verifyEvent(trust: TrustInput, input: Uint8Array, expected: RecoveryEvent): Promise<RecoveryReceipt> {
    const event = this.snapshotEvent(expected);
    if (input.length > receiptCap) fail('InputTooLarge', 'cold receipt');
    const receipt = Uint8Array.from(input);
    const proof = decodeDepositProof(receipt);
    await this.authority.accept(trust, this.cfg);
    let held: TrustInput;
    let log: Awaited<ReturnType<typeof verifyReceiptLog>>;
    do {
      held = this.authority.checkpoint;
      log = await verifyReceiptLog(this.cfg, held, proof, this.deployment.recovery);
    } while (held !== this.authority.checkpoint);
    if (log.topics.length !== 2 || !eq(log.topics[0], event.topics[0])
      || !eq(log.topics[1], event.topics[1]) || !eq(log.data, event.data)) refuse('ProviderFault', 'recovery checkpoint mismatch');
    return { encoded: receipt, blockNumber: log.header.number, blockHash: HE(proof.header), txIndex: proof.txIndex, logIndex: proof.logIndex };
  }

  /** Trim only an external predecessor presentation, rechecking the actual historical quorum after each removal. */
  async trimReceipt(trust: TrustInput, receipt: Uint8Array, expected: RecoveryEvent): Promise<RecoveryReceipt> {
    const event = this.snapshotEvent(expected);
    let best = await this.verifyEvent(trust, receipt, event);
    const proof = decodeDepositProof(best.encoded);
    const uc = scanNative(proof.uc).kids[0].kids;
    const seal = uc[6].kids[0].kids;
    const entries = seal[7].kids;
    const prefix = uc.slice(0, 6).map((item) => raw(proof.uc, item));
    const sealPrefix = seal.slice(0, 7).map((item) => raw(proof.uc, item));
    let witnesses = Array.from({ length: entries.length / 2 }, (_, i) => concat(raw(proof.uc, entries[2 * i]), raw(proof.uc, entries[2 * i + 1])));
    for (let i = witnesses.length - 1; i >= 0; i--) {
      const kept = witnesses.filter((_, j) => i !== j);
      const signedSeal = cTag(39005, cArr(...sealPrefix, concat(head(5, kept.length), ...kept)));
      const candidate = encodeDepositProof({ ...proof, uc: cTag(39001, cArr(...prefix, signedSeal)) });
      try {
        best = await this.verifyEvent(trust, candidate, event);
        witnesses = kept;
      } catch (e) {
        if (!(e instanceof Nb2Error && e.innermost === 'QuorumNotMet')) throw e;
      }
    }
    return best;
  }

  /** Try independently authenticated sources. An unknown child remains retryable; pruning is an availability failure. */
  async acquire(trust: TrustInput, expected: RecoveryEvent, sources: readonly RecoveryReceiptSource[],
    refresh?: (held: TrustInput) => Promise<TrustInput>): Promise<{ receipt: RecoveryReceipt; trust: TrustInput }> {
    const event = this.snapshotEvent(expected);
    await this.authority.accept(trust, this.cfg);
    let unavailable: unknown;
    let fault: unknown;
    for (const source of sources) {
      try {
        const proof = await source(this.deployment.recovery.slice(), this.event(event.kind, event.data.slice()));
        try {
          const receipt = await this.verifyEvent(this.authority.checkpoint, proof, event);
          return { receipt, trust: this.authority.checkpoint };
        } catch (e) {
          let cause = e;
          while (cause instanceof Nb2Error && cause.inner && !(cause instanceof SealAheadOfOrigin)) cause = cause.inner;
          if (!refresh || (!(e instanceof Nb2Error && e.retryable) && !(cause instanceof SealAheadOfOrigin))) throw e;
          const fresh = await refresh(this.authority.checkpoint);
          await this.authority.accept(fresh, this.cfg);
          const receipt = await this.verifyEvent(this.authority.checkpoint, proof, event);
          return { receipt, trust: this.authority.checkpoint };
        }
      } catch (e) {
        if (e instanceof WalletError && e.reason === 'TrustInput') throw e;
        if (e instanceof WalletError && (e.reason === 'CompanionUnknown' || e.reason === 'EvidenceMissing')) unavailable = e;
        else if (e instanceof Nb2Error && e.rule === 'EvidencePruned') unavailable ??= e;
        else fault ??= e;
      }
    }
    if (fault !== undefined) throw fault;
    if (unavailable !== undefined) throw unavailable;
    return refuse('EvidenceMissing', 'no recovery receipt source');
  }

  /** Materialize consecutive exclusion proofs from certified vault seal receipts. */
  async certifiedGaps(trust: TrustInput, start: bigint, head: Uint8Array, receipts: readonly Uint8Array[]): Promise<Uint8Array[]> {
    if (start < this.verdict.minSegment || start + BigInt(receipts.length) > MAX_SEGMENT
      || head.length !== 32 || receipts.length > 1024) fail('Shape', 'certified gap range');
    await this.authority.accept(trust, this.cfg);
    const paths: Uint8Array[] = [];
    let next = start;
    let before: Uint8Array = Uint8Array.from(head);
    for (const receipt of receipts) {
      const { segment } = await verifySealReceipt(this.cfg, this.verdict.domain, this.authority.checkpoint, receipt);
      if (segment.index !== next || !eq(segment.before, before)) fail('SegmentLog', 'nonconsecutive certified seals');
      const path = GapTree.build(segment.z)!.prove(this.verdict.eta);
      if (path === null) refuse('AlreadyPaid', 'return appears in a certified sealed segment');
      paths.push(path);
      next++;
      before = segment.after;
    }
    return paths;
  }

  /** Authenticate Complete or Gap and fold exactly this consecutive suffix. */
  async gaps(entry: 'advanceGaps' | 'redeemRecovered', trust: TrustInput, input: Uint8Array,
    prior: GapPrior, inputGaps: readonly Uint8Array[], inputHead?: Uint8Array,
  ): Promise<GapPacket> {
    if (input.length > receiptCap || inputGaps.length > 1024) fail('InputTooLarge', 'cold gap transport');
    const receipt = Uint8Array.from(input);
    const gaps = inputGaps.map((gap) => Uint8Array.from(gap));
    const cursor = prior.cursor;
    const start = cursor?.next ?? this.verdict.minSegment;
    const head = cursor ? Uint8Array.from(cursor.head) : inputHead && Uint8Array.from(inputHead);
    const next = start + BigInt(gaps.length);
    const seq = prior.seq;
    const advance = entry === 'advanceGaps';
    if (gaps.length > 1024 || (advance && gaps.length === 0) || seq <= 0n || seq >= 1n << 64n
      || (advance && seq + 1n >= 1n << 64n) || start < this.verdict.minSegment || next > MAX_SEGMENT
      || (cursor && (head?.length !== 32 || inputHead !== undefined))
      || (!cursor && (gaps.length === 0 ? head !== undefined : head?.length !== 32))
      || gaps.some((gap) => gap.length !== gapProofLen(this.cfg.K))) fail('Shape', 'cold gap framing');
    const v = verdictAbi(this.verdict);
    const expected = cursor ? this.event('gap', concat(u256(seq), v, u256(start), head!)) : this.event('complete', concat(u256(seq), v));
    await this.verifyEvent(trust, receipt, expected);
    const after = gaps.length === 0 ? head : foldHistory(this.verdict.domain, this.cfg.K, this.verdict.eta, start, head!, gaps);
    const event = advance ? this.event('gap', concat(u256(seq + 1n), v, u256(next), after!)) : null;
    const calldata = coldCall(entry, [this.header, Uint8Array.of(cursor ? 2 : 1), blob(receipt), u16(gaps.length),
      ...(!cursor && head ? [head] : []), ...gaps]);
    const shape: RecoveryShape = { entry, calldataBytes: calldata.length, operations: 0, pages: 0,
      gaps: gaps.length, receiptBytes: receipt.length, openingBytes: 0 };
    return { shape, calldata, event, next, head: after };
  }

  /** Cut a gap suffix to the largest fitting advance. The caller retains the unconsumed suffix. */
  async advanceBounded(trust: TrustInput, receipt: Uint8Array, prior: GapPrior, gaps: readonly Uint8Array[],
    calibration: RecoveryCalibration, limits: RecoveryLimits, startHead?: Uint8Array,
  ): Promise<{ packet: GapPacket; quote: RecoveryQuote }> {
    this.checkCalibration(calibration, limits);
    if (receipt.length > receiptCap) fail('InputTooLarge', 'cold receipt');
    const prefix = 42 + 1 + 4 + receipt.length + 2 + (prior.cursor ? 0 : 32);
    const width = gapProofLen(this.cfg.K);
    for (let count = Math.min(1024, gaps.length); count > 0; count--) {
      const calldataBytes = 68 + 32 * Math.ceil((prefix + count * width) / 32);
      const shape: RecoveryShape = { entry: 'advanceGaps', calldataBytes, operations: 0, pages: 0,
        gaps: count, receiptBytes: receipt.length, openingBytes: 0 };
      const quote = quoteRecovery(shape, calibration, limits);
      if (quote !== null) return { packet: await this.gaps('advanceGaps', trust, receipt, prior, gaps.slice(0, count), startHead), quote };
    }
    return fail('CapacityPreflight', 'indivisible gap operation');
  }

}

export type RecoveryContractRefusal = 'BadPacket' | 'BadPredecessor' | 'BadPage' | 'BadStep';
const refusalSelectors = (['BadPacket', 'BadPredecessor', 'BadPage', 'BadStep'] as const)
  .map((name) => ({ name, selector: HE(ascii(name + '()')).subarray(0, 4) }));

/** Decode exact on-chain transport errors separately from local admission and provider refusals. */
export function decodeRecoveryRefusal(data: Uint8Array): RecoveryContractRefusal | null {
  return refusalSelectors.find(({ selector }) => eq(selector, data))?.name ?? null;
}
