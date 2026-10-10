/**
 * The shared direct-call gas gate (interop.md "Direct-call gas gate"): the same formula, with the same
 * constants, as the oracle (`bridgeprofile/gas.go`) and the contract (`BridgeBounds.sol`, `UcScan.sol`).
 * Every term is the native price of a call the composing verifier makes, computed from complete
 * bounded scans, never from caller-declared costs. It is an admission rule, not a measured fit.
 */
import { fail } from './errors.js';
import type { Anchor, Envelope, LeafProof } from './envelope.js';
import {
  MAX_ANCHOR_UC_BYTES, MAX_INPUT_RECORD_BYTES, MAX_PATH_STEPS, MAX_RSMT_SIBLINGS, MAX_SIGNATURES, MAX_UNICITY_STEPS, GAS_RESERVE, TX_GAS_BUDGET,
} from './limits.js';
import type { Policy } from './profile.js';
import { eq } from './bytes.js';

const INTRINSIC_BASE = 21_000;
const PER_BYTE = 16;
const B2_BASE = 26_000;
const B2_PER_BYTE = 20;
const B2_PER_LEAF = 14_000;
const UC_BASE = 1_243_700;
const UC_PER_SIGNATURE = 6_000;
const PER_STEP = 250;
const RSMT_BASE = 2_000;
/** UC_V1 request without shard and UC: header 4, partition 4, shard length 2, three words, UC length 4. */
const UC_REQUEST_FIXED = 110;
/** RSMT_MEMBER_V1 request without siblings. */
const RSMT_REQUEST_FIXED = 136;

const pad32 = (n: number): number => (n + 31) & ~31;

/** `G_intrinsic = 21000 + 16*len(envelope)`. */
export const intrinsicGas = (envelopeBytes: number): number => INTRINSIC_BASE + PER_BYTE * envelopeBytes;

/** `len(abi.encode(uint8 op, bytes cfg, bytes payload))`. */
export const kernelRequestBytes = (cfgBytes: number, payloadBytes: number): number => 96 + 32 + pad32(cfgBytes) + 32 + pad32(payloadBytes);

/** `G_B2 = 26000 + 20*B_sem + 14000*L`. */
export const b2Gas = (requestBytes: number, leaves: number): number => B2_BASE + B2_PER_BYTE * requestBytes + B2_PER_LEAF * leaves;

/** `G_UC = 1243700 + 16*B_a + 6000*S_a + 250*P_a` with `B_a = 110 + len(shard) + len(uc)`. */
export const ucGas = (shardBytes: number, ucBytes: number, signatures: number, steps: number): number =>
  UC_BASE + PER_BYTE * (UC_REQUEST_FIXED + shardBytes + ucBytes) + UC_PER_SIGNATURE * signatures + PER_STEP * steps;

/** `G_RSMT = 2000 + 16*(136 + 32*s) + 250*(1 + s)`. */
export const rsmtGas = (siblings: number): number => RSMT_BASE + PER_BYTE * (RSMT_REQUEST_FIXED + 32 * siblings) + PER_STEP * (1 + siblings);

// ---- the bounded scan of an anchor's UnicityCertificate ---------------------------------------------

const TAG_UC = 39001n;
const TAG_SHARD_TREE = 39003n;
const TAG_UNICITY_TREE = 39004n;
const TAG_SEAL = 39005n;

interface Head { major: number; arg: bigint; next: number }

/** One strict head: shortest form, definite length. */
function head(b: Uint8Array, pos: number): Head {
  if (pos >= b.length) return fail('ErrTruncated');
  const ib = b[pos];
  const major = ib >> 5;
  const ai = ib & 0x1f;
  if (ai < 24) return { major, arg: BigInt(ai), next: pos + 1 };
  if (ai > 27) return fail(ai === 31 ? 'ErrForbiddenCBOR' : 'ErrNonCanonical');
  const n = 1 << (ai - 24);
  if (b.length - pos - 1 < n) return fail('ErrTruncated');
  let arg = 0n;
  for (let i = 0; i < n; i++) arg = (arg << 8n) | BigInt(b[pos + 1 + i]);
  if ((ai === 24 && arg < 24n) || (ai === 25 && arg <= 0xffn) || (ai === 26 && arg <= 0xffffn) || (ai === 27 && arg <= 0xffffffffn)) fail('ErrNonCanonical');
  return { major, arg, next: pos + 1 + n };
}

/** Skip one complete item. Every iteration consumes at least one byte. */
function skip(b: Uint8Array, start: number): number {
  let pos = start;
  let pending = 1n;
  while (pending !== 0n) {
    const h = head(b, pos);
    pos = h.next;
    pending -= 1n;
    if (h.major === 2 || h.major === 3) {
      if (h.arg > BigInt(b.length - pos)) fail('ErrTruncated');
      pos += Number(h.arg);
    } else if (h.major === 4 || h.major === 5) {
      if (h.arg > BigInt(b.length)) fail('ErrTruncated');
      pending += h.major === 5 ? 2n * h.arg : h.arg;
    } else if (h.major === 6) {
      pending += 1n;
    }
  }
  return pos;
}

function tagged(b: Uint8Array, pos: number, tag: bigint, n: bigint): number {
  const t = head(b, pos);
  if (t.major !== 6 || t.arg !== tag) fail('ErrTag');
  const a = head(b, t.next);
  if (a.major !== 4 || a.arg !== n) fail('ErrShape');
  return a.next;
}

/** Element count of an array (major 4) or map (major 5) at `pos`; null is empty. */
function count(b: Uint8Array, pos: number, want: number): { n: number; next: number } {
  if (pos < b.length && b[pos] === 0xf6) return { n: 0, next: pos + 1 };
  const h = head(b, pos);
  if (h.major !== want || h.arg > BigInt(b.length)) fail('ErrShape');
  return { n: Number(h.arg), next: h.next };
}

export interface AnchorScan {
  /** Single-claim 0x0100 request bytes. */
  request: number;
  /** Signature entries of the seal (`S`). */
  sigs: number;
  /** Shard-tree siblings plus unicity tree steps (`P`). */
  steps: number;
  /** `G_UC`. */
  gas: number;
}

/**
 * Bound the anchor's UC and price its 0x0100 call. The certificate must name the claim's shard and carry
 * exactly `depth` shard-tree siblings (the policy topology is complete and uniform); the unicity path
 * and the seal are bounded by B1's own sublimits.
 */
export function scanAnchor(a: Anchor, depth: number): AnchorScan {
  if (a.uc.length > MAX_ANCHOR_UC_BYTES) fail('ErrInputTooLarge');
  try {
    return scanUc(a, depth);
  } catch {
    // Whatever the shape failure, B1 would not authenticate this certificate (oracle `ErrAnchorAuth`).
    return fail('ErrAnchorAuth');
  }
}

function scanUc(a: Anchor, depth: number): AnchorScan {
  const b = a.uc;
  let pos = tagged(b, 0, TAG_UC, 7n);
  for (let i = 0; i < 4; i++) pos = skip(b, pos); // version, input record, technical hash, configuration hash
  pos = tagged(b, pos, TAG_SHARD_TREE, 3n);
  pos = skip(b, pos); // version
  const shard = head(b, pos);
  if (shard.major !== 2 || shard.arg > BigInt(b.length - shard.next) || !eq(b.subarray(shard.next, shard.next + Number(shard.arg)), a.shard)) fail('ErrShardMismatch');
  pos = shard.next + Number(shard.arg);
  const sib = count(b, pos, 4);
  if (sib.n !== depth) fail('ErrShardMismatch');
  pos = sib.next;
  for (let i = 0; i < sib.n; i++) pos = skip(b, pos);
  pos = tagged(b, pos, TAG_UNICITY_TREE, 3n);
  pos = skip(b, pos); // version
  pos = skip(b, pos); // partition
  const steps = count(b, pos, 4);
  if (steps.n > MAX_UNICITY_STEPS) fail('ErrShape');
  pos = steps.next;
  for (let i = 0; i < steps.n; i++) pos = skip(b, pos);
  pos = tagged(b, pos, TAG_SEAL, 8n);
  for (let i = 0; i < 7; i++) pos = skip(b, pos);
  const sigs = count(b, pos, 5);
  if (sigs.n > MAX_SIGNATURES) fail('ErrShape');
  const request = UC_REQUEST_FIXED + a.shard.length + b.length;
  const stepsTotal = sib.n + steps.n;
  return { request, sigs: sigs.n, steps: stepsTotal, gas: ucGas(a.shard.length, b.length, sigs.n, stepsTotal) };
}

const popcount = (b: Uint8Array): number => {
  let c = 0;
  for (let x of b) {
    while (x) { x &= x - 1; c++; }
  }
  return c;
};

/** Bound one leaf path (bitmap popcount equal to the sibling count, at most `MAX_RSMT_SIBLINGS`) and price its 0x0102 call. */
export function leafPathGas(p: LeafProof): { gas: number; steps: number } {
  const pop = popcount(p.bitmap);
  if (pop !== p.siblings.length) fail('ErrPathBitmap');
  if (pop > MAX_RSMT_SIBLINGS) fail('ErrTooManyPaths');
  return { gas: rsmtGas(pop), steps: pop };
}

export interface Gate {
  intrinsic: number;
  b2: number;
  uc: number;
  rsmt: number;
  steps: number;
  /** The gated sum including the fixed reserve. */
  total: number;
}

/** Price a complete bounded envelope against `budget`; above it is `ErrGasBudget` (BudgetExceeded). */
export function computeGate(envelopeBytes: number, kernelRequest: number, e: Envelope, pol: Policy, budget: number = TX_GAS_BUDGET): Gate {
  const g: Gate = { intrinsic: intrinsicGas(envelopeBytes), b2: b2Gas(kernelRequest, e.leafProofs.length), uc: 0, rsmt: 0, steps: 0, total: 0 };
  for (const a of e.anchors) {
    const s = scanAnchor(a, pol.depth);
    g.uc += s.gas;
    g.steps += s.steps;
  }
  for (const p of e.leafProofs) {
    const l = leafPathGas(p);
    g.rsmt += l.gas;
    g.steps += l.steps;
  }
  if (g.steps > MAX_PATH_STEPS) fail('ErrTooManyPaths');
  g.total = g.intrinsic + g.b2 + g.uc + g.rsmt + GAS_RESERVE;
  if (g.total > budget) fail('ErrGasBudget');
  return g;
}

/** The smallest certificate a real aggregator produces, for the best-case projection: ~1 KiB, one signature. */
export const BEST_UC_BYTES = 1024;
export const BEST_SIGNATURES = 1;

/**
 * The burn-time best-case projection: the gate of the redemption envelope a token with `leaves` leaves
 * (the burn included) and a `historyBytes` history would need if everything the burn cannot yet know turns
 * out as small as it can: the fewest anchors (`anchors`, the distinct shards the known leaves occupy),
 * the smallest certificates (`BEST_UC_BYTES`, one signature, only the depth-many shard siblings as steps)
 * and empty paths. The burn is refused, before any wallet burn is made, only when even this cannot pass the
 * gas gate; whether the bundle that is actually fetched passes is the gate's decision at redemption.
 */
export function projectedGate(cfgBytes: number, policyBytes: number, depth: number, anchors: number, leaves: number, historyBytes: number): { gate: Gate; envelopeBytes: number } {
  const word = 32;
  const uc = ucGas(1, BEST_UC_BYTES, BEST_SIGNATURES, depth);
  // abi.encode(bytes policy, bytes history, Anchor[] anchors, LeafProof[] leaves), best-case sizes.
  const bytesField = (n: number): number => word + pad32(n);
  const anchorBytes = 7 * word + bytesField(1) + bytesField(BEST_UC_BYTES) + bytesField(MAX_INPUT_RECORD_BYTES / 2);
  const leafBytes = 3 * word + word;
  const envelope = 4 * word + bytesField(policyBytes) + bytesField(historyBytes) +
    word + anchors * (word + anchorBytes) + word + leaves * (word + leafBytes);
  const g: Gate = {
    intrinsic: intrinsicGas(envelope),
    b2: b2Gas(kernelRequestBytes(cfgBytes, historyBytes), leaves),
    uc: anchors * uc,
    rsmt: leaves * rsmtGas(0),
    steps: anchors * depth,
    total: 0,
  };
  g.total = g.intrinsic + g.b2 + g.uc + g.rsmt + GAS_RESERVE;
  return { gate: g, envelopeBytes: envelope };
}
