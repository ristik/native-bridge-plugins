/**
 * The proof envelope `abi.encode(bytes policyBody, bytes history, Anchor[] anchors, LeafProof[] leafProofs)`.
 *
 * `Anchor = (uint32 partition, bytes shard, bytes32 shardConfHash, bytes32 expectedStateRoot,
 * bytes32 expectedIRHash, bytes uc, bytes inputRecord)`: the exact canonical native InputRecord
 * opening is appended after `uc`; all earlier fields keep their order.
 */
import { concat, eq } from './bytes.js';
import { fail } from './errors.js';
import {
  MAX_ANCHORS, MAX_ENVELOPE_BYTES, MAX_INPUT_RECORD_BYTES, MAX_LEAVES, MAX_PATH_STEPS, MAX_POLICY_BYTES, TAG_INPUT_RECORD,
} from './limits.js';
import { H, EMPTY_PREFIX_SHARD, decodePolicy, policyBytes, type Cfg, type Policy } from './profile.js';
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
    if (ns > MAX_PATH_STEPS - steps) fail('ErrTooManyPaths');
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

/** The composing verifier's opening and tuple check, run before any B1 call. */
export function checkPolicy(cfg: Cfg, e: Envelope, leafCount: number): Policy {
  if (e.policyBody.length > MAX_POLICY_BYTES) fail('ErrInputTooLarge');
  if (!eq(H(e.policyBody), cfg.aggregatorPolicyHash)) fail('ErrPolicyHash');
  const pol = decodePolicy(e.policyBody);
  if (!eq(policyBytes(pol), e.policyBody)) fail('ErrNonCanonical');
  if (pol.partition === cfg.evmPartition) fail('ErrPolicyPartition');
  if (e.anchors.length !== 1) fail('ErrPolicyAnchors');
  const a = e.anchors[0];
  if (a.partition !== pol.partition || !eq(a.shard, EMPTY_PREFIX_SHARD) || !eq(a.shardConfHash, pol.shardConf)) fail('ErrPolicyTuple');
  if (e.leafProofs.length !== leafCount) fail('ErrPolicyLeafCount');
  if (e.leafProofs.some((l) => l.anchorIndex !== 0)) fail('ErrPolicyLeafIndex');
  return pol;
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
