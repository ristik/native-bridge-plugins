/**
 * The proof envelope `abi.encode(bytes policyBody, bytes history, Anchor[] anchors, LeafProof[] leafProofs)`.
 *
 * `Anchor = (uint32 partition, bytes shard, bytes32 shardConfHash, bytes32 expectedStateRoot,
 * bytes32 expectedIRHash, bytes uc, bytes inputRecord)`: the exact canonical native InputRecord
 * opening is appended after `uc`; all earlier fields keep their order.
 */
import { concat, eq, toHex } from './bytes.js';
import { fail } from './errors.js';
import {
  MAX_ANCHORS, MAX_ANCHOR_UC_BYTES, MAX_ENVELOPE_BYTES, MAX_INPUT_RECORD_BYTES, MAX_LEAVES, MAX_PATH_STEPS, MAX_POLICY_BYTES,
  MAX_RSMT_SIBLINGS, TAG_INPUT_RECORD,
} from './limits.js';
import { H, decodePolicy, policyBytes, shardId, shardRow, type Cfg, type Policy } from './profile.js';
import { arrayOf, bytesN, nullableBytes, scanOne, tagContent, uint, version } from './scan.js';

export interface Anchor {
  partition: number;
  shard: Uint8Array;
  shardConfHash: Uint8Array;
  expectedStateRoot: Uint8Array;
  expectedIRHash: Uint8Array;
  uc: Uint8Array;
  inputRecord: Uint8Array;
}

export interface LeafProof {
  anchorIndex: number;
  bitmap: Uint8Array;
  siblings: Uint8Array[];
}

export interface Envelope {
  policyBody: Uint8Array;
  history: Uint8Array;
  anchors: Anchor[];
  leafProofs: LeafProof[];
}

const word = (v: bigint | number): Uint8Array => {
  const w = new Uint8Array(32);
  for (let i = 31, x = BigInt(v); i >= 0; i--, x >>= 8n) w[i] = Number(x & 0xffn);
  return w;
};

const padTo32 = (b: Uint8Array): Uint8Array => concat(b, new Uint8Array((32 - (b.length % 32)) % 32));
const encBytes = (b: Uint8Array): Uint8Array => concat(word(b.length), padTo32(b));

function encArray(items: Uint8Array[]): Uint8Array {
  const heads: Uint8Array[] = [];
  let off = items.length * 32;
  for (const it of items) {
    heads.push(word(off));
    off += it.length;
  }
  return concat(word(items.length), ...heads, ...items);
}

export function encodeEnvelope(e: Envelope): Uint8Array {
  const a = encBytes(e.policyBody);
  const b = encBytes(e.history);
  const anchors = e.anchors.map((x) => {
    const shard = encBytes(x.shard);
    const uc = encBytes(x.uc);
    const ir = encBytes(x.inputRecord);
    return concat(
      word(x.partition), word(7 * 32), x.shardConfHash, x.expectedStateRoot, x.expectedIRHash,
      word(7 * 32 + shard.length), word(7 * 32 + shard.length + uc.length), shard, uc, ir,
    );
  });
  const c = encArray(anchors);
  const leaves = e.leafProofs.map((x) => concat(word(x.anchorIndex), x.bitmap, word(3 * 32), word(x.siblings.length), ...x.siblings));
  const d = encArray(leaves);
  const parts = [a, b, c, d];
  let off = 4 * 32;
  const heads: Uint8Array[] = [];
  for (const p of parts) {
    heads.push(word(off));
    off += p.length;
  }
  return concat(...heads, ...parts);
}

function wordAt(b: Uint8Array, off: number): number | null {
  if (off < 0 || off + 32 > b.length) return null;
  for (let i = 0; i < 24; i++) if (b[off + i] !== 0) return null;
  let v = 0n;
  for (let i = 24; i < 32; i++) v = (v << 8n) | BigInt(b[off + i]);
  return v > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(v);
}

function boundCounts(b: Uint8Array): void {
  const n = b.length;
  const w = (o: number): number => wordAt(b, o) ?? fail('ErrABIFraming');
  const offAnchors = w(64);
  const offLeaves = w(96);
  if (offAnchors > n || offLeaves > n) fail('ErrABIFraming');
  const na = w(offAnchors);
  if (na > n) fail('ErrABIFraming');
  if (na > MAX_ANCHORS) fail('ErrTooManyPaths');
  // Every anchor's UC is bounded from its declared length before anything is allocated.
  for (let i = 0; i < na; i++) {
    const t = offAnchors + 32 + w(offAnchors + 32 + 32 * i);
    if (w(t + w(t + 5 * 32)) > MAX_ANCHOR_UC_BYTES) fail('ErrInputTooLarge');
  }
  const nl = w(offLeaves);
  if (nl > n) fail('ErrABIFraming');
  if (nl > MAX_LEAVES) fail('ErrTooManyPaths');
  let steps = 0;
  for (let i = 0; i < nl; i++) {
    const rel = w(offLeaves + 32 + 32 * i);
    const t = offLeaves + 32 + rel;
    const sRel = w(t + 64);
    const sOff = t + sRel;
    const ns = w(sOff);
    if (ns > MAX_RSMT_SIBLINGS || ns > MAX_PATH_STEPS - steps) fail('ErrTooManyPaths');
    steps += ns;
  }
}

function decodeLenient(b: Uint8Array): Envelope | null {
  const w = (o: number): number | null => wordAt(b, o);
  const bytesAt = (off: number | null): Uint8Array | null => {
    if (off === null) return null;
    const len = w(off);
    if (len === null || off + 32 + len > b.length) return null;
    return b.slice(off + 32, off + 32 + len);
  };
  const fixed32 = (off: number): Uint8Array | null => (off + 32 <= b.length ? b.slice(off, off + 32) : null);
  const o0 = w(0), o1 = w(32), aBase = w(64), lBase = w(96);
  if (o0 === null || o1 === null || aBase === null || lBase === null) return null;
  const policyBody = bytesAt(o0);
  const history = bytesAt(o1);
  const na = w(aBase);
  if (policyBody === null || history === null || na === null) return null;
  const anchors: Anchor[] = [];
  for (let i = 0; i < na; i++) {
    const rel = w(aBase + 32 + i * 32);
    if (rel === null) return null;
    const t = aBase + 32 + rel;
    const part = w(t);
    const sOff = w(t + 32), ucOff = w(t + 160), irOff = w(t + 192);
    if (part === null || part > 0xffffffff || sOff === null || ucOff === null || irOff === null) return null;
    const shard = bytesAt(t + sOff), uc = bytesAt(t + ucOff), ir = bytesAt(t + irOff);
    const conf = fixed32(t + 64), root = fixed32(t + 96), irh = fixed32(t + 128);
    if (!shard || !uc || !ir || !conf || !root || !irh) return null;
    anchors.push({ partition: part, shard, shardConfHash: conf, expectedStateRoot: root, expectedIRHash: irh, uc, inputRecord: ir });
  }
  const nl = w(lBase);
  if (nl === null) return null;
  const leafProofs: LeafProof[] = [];
  for (let i = 0; i < nl; i++) {
    const head = w(lBase + 32 + i * 32);
    if (head === null) return null;
    const t = lBase + 32 + head;
    const idx = w(t);
    const sRel = w(t + 64);
    if (idx === null || idx > 0xffff || sRel === null) return null;
    const sOff = t + sRel;
    const ns = w(sOff);
    const bitmap = fixed32(t + 32);
    if (ns === null || !bitmap) return null;
    const siblings: Uint8Array[] = [];
    for (let j = 0; j < ns; j++) {
      const s = fixed32(sOff + 32 + j * 32);
      if (!s) return null;
      siblings.push(s);
    }
    leafProofs.push({ anchorIndex: idx, bitmap, siblings });
  }
  return { policyBody, history, anchors, leafProofs };
}

/** Decode, rejecting noncanonical offsets/padding/aliases/trailing data by exact re-encoding. */
export function decodeEnvelope(b: Uint8Array): Envelope {
  if (b.length > MAX_ENVELOPE_BYTES) fail('ErrInputTooLarge');
  if (b.length % 32 !== 0 || b.length < 128) fail('ErrABIFraming');
  boundCounts(b);
  const e = decodeLenient(b) ?? fail('ErrABIFraming');
  if (!eq(encodeEnvelope(e), b)) fail('ErrABIFraming');
  return e;
}

/**
 * The composing verifier's opening, run before the kernel and before any B1 call: the supplied body is
 * hashed against `Cfg.aggregatorPolicyHash` before it is interpreted, decoded, the aggregator partition
 * must differ from the EVM partition and the anchor count must be within the bound. A submitted anchor
 * table never chooses its own admission.
 */
export function checkPolicyBody(cfg: Cfg, e: Envelope): Policy {
  if (e.policyBody.length > MAX_POLICY_BYTES) fail('ErrInputTooLarge');
  if (!eq(H(e.policyBody), cfg.aggregatorPolicyHash)) fail('ErrPolicyHash');
  const pol = decodePolicy(e.policyBody);
  if (!eq(policyBytes(pol), e.policyBody)) fail('ErrNonCanonical');
  if (pol.partition === cfg.evmPartition) fail('ErrPolicyPartition');
  if (e.anchors.length === 0 || e.anchors.length > MAX_ANCHORS) fail('ErrPolicyAnchors');
  return pol;
}

/** The anchor each leaf is certified by: an index into the envelope's anchor table. */
export interface AnchorPlan {
  leafAnchor: number[];
}

/**
 * The envelope's anchor table must be exactly the function of the exported leaves the profile defines:
 * one leaf proof per leaf in kernel order; every anchor's partition, shard and configuration equal to a
 * policy row; anchors pairwise distinct by complete UC bytes (byte-identical UCs are one anchor, never
 * two); anchors numbered by first use in leaf order with none unused; and each leaf's `anchorIndex`
 * naming an anchor of the leaf's own shard (the top `depth` bits of its state ID). Different UCs of one
 * shard, even of one root round, are separate anchors. The number of anchors is not tied to the number
 * of shards.
 */
export function planAnchors(pol: Policy, e: Envelope, sids: Uint8Array[]): AnchorPlan {
  if (e.leafProofs.length !== sids.length) fail('ErrPolicyLeafCount');
  if (e.anchors.length === 0 || e.anchors.length > MAX_ANCHORS || e.anchors.length > sids.length) fail('ErrPolicyAnchors');
  const rowOf: number[] = [];
  const seen = new Set<string>();
  e.anchors.forEach((a) => {
    const row = pol.shardConfs.findIndex((_, r) => eq(a.shard, shardId(pol, r)));
    if (row < 0 || a.partition !== pol.partition || !eq(a.shardConfHash, pol.shardConfs[row])) fail('ErrPolicyTuple');
    rowOf.push(row);
    const key = toHex(H(a.uc));
    if (seen.has(key)) fail('ErrPolicyAnchors');
    seen.add(key);
  });
  const leafAnchor: number[] = [];
  let next = 0;
  sids.forEach((sid, i) => {
    const idx = e.leafProofs[i].anchorIndex;
    if (idx >= e.anchors.length || idx > next || rowOf[idx] !== shardRow(pol, sid)) fail('ErrPolicyLeafIndex');
    if (idx === next) next++;
    leafAnchor.push(idx);
  });
  if (next !== e.anchors.length) fail('ErrPolicyAnchors');
  return { leafAnchor };
}

export interface InputRecordOpening {
  round: bigint;
  epoch: bigint;
  stateHash: Uint8Array;
  timestamp: bigint;
}

/** Bound, scan and parse the exact canonical native InputRecord opening (tag 39002, v1, arity 10). */
export function parseInputRecord(raw: Uint8Array): InputRecordOpening {
  if (raw.length > MAX_INPUT_RECORD_BYTES) fail('ErrInputTooLarge');
  const k = arrayOf(tagContent(scanOne(raw), TAG_INPUT_RECORD), 10) ?? fail('ErrShape');
  version(k[0], 1n);
  for (const i of [3, 7, 9]) {
    const v = nullableBytes(k[i]);
    if (v !== null && v.length !== 32) fail('ErrLength');
  }
  nullableBytes(k[5]); // summary value: null or bytes
  uint(k[8]);
  return { round: uint(k[1]), epoch: uint(k[2]), stateHash: bytesN(k[4], 32), timestamp: uint(k[6]) };
}

/** `H(inputRecord)==expectedIRHash`, opened state hash == expectedStateRoot, every `t <=` timestamp. */
export function checkAnchor(a: Anchor, leafTimes: bigint[]): InputRecordOpening {
  if (!eq(H(a.inputRecord), a.expectedIRHash)) fail('ErrInputRecordMismatch');
  const ir = parseInputRecord(a.inputRecord);
  if (!eq(ir.stateHash, a.expectedStateRoot)) fail('ErrInputRecordMismatch');
  if (leafTimes.some((t) => t > ir.timestamp)) fail('ErrReferenceTimeFuture');
  return ir;
}

/**
 * Open every anchor and bound every leaf's reference time by the timestamp of the leaf's own anchor
 * (`t <=` its own IR time, never another anchor's).
 */
export function checkAnchors(e: Envelope, plan: AnchorPlan, leafTimes: bigint[]): InputRecordOpening[] {
  const opened = e.anchors.map((a) => {
    if (!eq(H(a.inputRecord), a.expectedIRHash)) fail('ErrInputRecordMismatch');
    const ir = parseInputRecord(a.inputRecord);
    if (!eq(ir.stateHash, a.expectedStateRoot)) fail('ErrInputRecordMismatch');
    return ir;
  });
  leafTimes.forEach((t, i) => {
    if (t > opened[plan.leafAnchor[i]].timestamp) fail('ErrReferenceTimeFuture');
  });
  return opened;
}
