/**
 * The gas estimate of a redemption. Since B7 direct PR 2 the composition is one native call, BRIDGE_COMPOSE_V1 at 0x0105, and its
 * charge is the trial schedule of bft-core `bridgeprofile/native.go` (`ComposeGas`), computed here from the same scans:
 *
 *   G_compose = 100000 + 2*B + 20*J + 16000*L + 6000*Q + 29900*E + 2000*A + 250*P + 50*K*ceil(log2 K)
 *
 * with B the native input bytes (`abi.encode(uint8 op, bytes cfg, bytes envelope)`), J the CBOR item heads of the Cfg, the policy
 * body, the history, every anchor UC and every anchor IR opening, L the leaves, Q/E/A/K the CERT_BATCH_V2 grouping of the anchor
 * table and P its certificate steps plus every leaf's RSMT siblings. The transaction estimate (`total`) adds the calldata intrinsic
 * gas and the fixed reserve for the wrapper and the vault. It is a number a wallet sets its gas limit from, never an admission rule
 * (owner section 36). The protocol-5 composite (`legacyTotal` and its components) is kept only because the corpus `gate` cases
 * still publish it.
 */
import { fail } from './errors.js';
import type { Envelope, LeafProof } from './envelope.js';
import { batchGas, countItems, measure, type Counts } from './certgroups.js';
import { NativeError } from './errors.js';
import { BRIDGE_ITEM_GAS, GAS_RESERVE, MAX_CBOR_ITEMS, MAX_RSMT_SIBLINGS } from './limits.js';

const INTRINSIC_BASE = 21_000;
const PER_BYTE = 16;
/** The composing verifier's own execution per envelope byte. */
const EXEC_PER_BYTE = 80;
const B2_BASE = 26_000;
const B2_PER_BYTE = 20;
const B2_PER_LEAF = 14_000;
const PER_STEP = 250;
const RSMT_BASE = 2_000;
/** RSMT_MEMBER_V1 request without siblings. */
const RSMT_REQUEST_FIXED = 136;
/** The canonical two-bytes-argument TokenVerifier call: selector 4, two offsets and two lengths 128. */
const CALL_FIXED = 4 + 128;

/** Items of the fixed-shape objects the verifier opens itself: Cfg (array head and 15 fields... as counted by the oracle), policy, one IR opening per anchor. */
export const CFG_ITEMS = 17;
export const POLICY_ITEMS = 4;
export const IR_ITEMS = 12;

const pad32 = (n: number): number => (n + 31) & ~31;

/** `D_max = 4 + 128 + pad32(B_cfg) + pad32(B_env)`: the calldata of the canonical call, an allowance. */
export const maxCalldata = (cfgBytes: number, envelopeBytes: number): number => CALL_FIXED + pad32(cfgBytes) + pad32(envelopeBytes);

/** `21000 + 16*D_max + 80*B_env`. */
export const intrinsicGas = (cfgBytes: number, envelopeBytes: number): number =>
  INTRINSIC_BASE + PER_BYTE * maxCalldata(cfgBytes, envelopeBytes) + EXEC_PER_BYTE * envelopeBytes;

/** `len(abi.encode(uint8 op, bytes cfg, bytes payload))`. */
export const kernelRequestBytes = (cfgBytes: number, payloadBytes: number): number => 96 + 32 + pad32(cfgBytes) + 32 + pad32(payloadBytes);

/** `G_kernel = 26000 + 20*B_kernel + 14000*L`. */
export const b2Gas = (requestBytes: number, leaves: number): number => B2_BASE + B2_PER_BYTE * requestBytes + B2_PER_LEAF * leaves;

/** `G_leaf = 2000 + 16*(136 + 32*s) + 250*(1 + s)`. */
export const rsmtGas = (siblings: number): number => RSMT_BASE + PER_BYTE * (RSMT_REQUEST_FIXED + 32 * siblings) + PER_STEP * (1 + siblings);

/** `G_items = 1000*J`. */
export const itemGas = (items: number): number => BRIDGE_ITEM_GAS * items;

/** The items the verifier itself opens besides the UC occurrences: Cfg, policy and one IR opening per anchor. */
export const fixedItems = (anchors: number): number => CFG_ITEMS + POLICY_ITEMS + IR_ITEMS * anchors;


const popcount = (b: Uint8Array): number => {
  let c = 0;
  for (let x of b) {
    while (x) { x &= x - 1; c++; }
  }
  return c;
};

/** Bound one leaf path (bitmap popcount equal to the sibling count, at most `MAX_RSMT_SIBLINGS`) and price its member call. */
export function leafPathGas(p: LeafProof): { gas: number; steps: number } {
  const pop = popcount(p.bitmap);
  if (pop !== p.siblings.length) fail('ErrPathBitmap');
  if (pop > MAX_RSMT_SIBLINGS) fail('ErrTooManyPaths');
  return { gas: rsmtGas(pop), steps: pop };
}

/** The dimensions the BRIDGE_COMPOSE_V1 schedule prices (bft-core `ComposeDims`). */
export interface ComposeDims { b: number; j: number; l: number; q: number; e: number; a: number; k: number; p: number }

export const COMPOSE_BASE = 100_000;
export const COMPOSE_PER_BYTE = 2;
export const COMPOSE_PER_ITEM = 20;
export const COMPOSE_PER_LEAF = 16_000;
export const COMPOSE_PER_SIGNATURE = 6_000;
export const COMPOSE_PER_EPOCH = 29_900;
export const COMPOSE_PER_CLAIM = 2_000;
export const COMPOSE_PER_STEP = 250;
export const COMPOSE_PER_GROUP_STEP = 50;

/** `50*K*ceil(log2 K)`: sort-based grouping of K claim occurrences (zero for K <= 1). */
export const composeGroupGas = (k: number): number => (k <= 1 ? 0 : COMPOSE_PER_GROUP_STEP * k * (k - 1).toString(2).length);

/** The native charge of a BRIDGE_COMPOSE_V1 call that succeeds. */
export const composeGas = (d: ComposeDims): number =>
  COMPOSE_BASE + COMPOSE_PER_BYTE * d.b + COMPOSE_PER_ITEM * d.j + COMPOSE_PER_LEAF * d.l + COMPOSE_PER_SIGNATURE * d.q +
  COMPOSE_PER_EPOCH * d.e + COMPOSE_PER_CLAIM * d.a + COMPOSE_PER_STEP * d.p + composeGroupGas(d.k);

/** The CBOR item heads of one object, 0 when it does not scan (bft-core charges an object's J only once it scans). */
const itemsOrZero = (b: Uint8Array): number => {
  try {
    return countItems(b, MAX_CBOR_ITEMS);
  } catch {
    return 0;
  }
};

export interface Gate {
  /** The BRIDGE_COMPOSE_V1 dimensions and their native charge. */
  compose: ComposeDims;
  native: number;
  intrinsic: number;
  b2: number;
  /** `G_batch`. */
  batch: number;
  /** `G_items`. */
  items: number;
  rsmt: number;
  steps: number;
  /** J, the bridge CBOR item occurrences. */
  j: number;
  /** The grouping the batch is priced by. */
  grouping: Counts;
  /** The transaction estimate: `21000 + 16*D_max + G_compose + 1,000,000`. */
  total: number;
  /** The protocol-5 composite of the corpus `gate` cases (`G_gate`). */
  legacyTotal: number;
}

/** `21000 + 16*D_max`: the calldata intrinsic gas of the canonical two-bytes-argument call. */
export const calldataGas = (cfgBytes: number, envelopeBytes: number): number => INTRINSIC_BASE + PER_BYTE * maxCalldata(cfgBytes, envelopeBytes);

function finish(g: Gate, cfgBytes: number, envelopeBytes: number): Gate {
  g.legacyTotal = g.intrinsic + g.b2 + g.batch + g.items + g.rsmt + GAS_RESERVE;
  g.native = composeGas(g.compose);
  g.total = calldataGas(cfgBytes, envelopeBytes) + g.native + GAS_RESERVE;
  return g;
}

/** Estimate a complete bounded envelope (never a refusal): the native charge, the transaction estimate and the legacy composite. */
export function computeGate(cfg: Uint8Array, envelopeBytes: number, kernelRequest: number, e: Envelope): Gate {
  const cfgBytes = cfg.length;
  // J: the item occurrences of the Cfg, the policy body, every anchor UC (counted by the batch scan) and every anchor IR opening,
  // each once. There is no shared budget: each object is bounded by its own native scan (ErrTooManyItems), and every item is
  // charged. A malformed object is its own shape failure.
  let spent = 0;
  const take = (b: Uint8Array, malformed: Parameters<typeof fail>[0]): void => {
    try {
      spent += countItems(b, MAX_CBOR_ITEMS);
    } catch (err) {
      if (err instanceof NativeError && err.reason === 'ErrTooManyItems') throw err;
      fail(malformed);
    }
  };
  take(cfg, 'ErrShape');
  take(e.policyBody, 'ErrShape');
  for (const a of e.anchors) take(a.inputRecord, 'ErrShape');
  const grouping = measure(e.anchors);
  const j = spent + grouping.items;
  let rsmt = 0;
  let steps = grouping.p;
  for (const p of e.leafProofs) {
    const l = leafPathGas(p);
    rsmt += l.gas;
    steps += l.steps;
  }
  const compose: ComposeDims = {
    b: kernelRequestBytes(cfgBytes, envelopeBytes), j: j + itemsOrZero(e.history), l: e.leafProofs.length,
    q: grouping.q, e: grouping.e, a: grouping.a, k: grouping.k, p: steps,
  };
  const g: Gate = {
    compose,
    native: 0,
    intrinsic: intrinsicGas(cfgBytes, envelopeBytes),
    b2: b2Gas(kernelRequest, e.leafProofs.length),
    batch: batchGas(grouping),
    items: itemGas(j),
    rsmt,
    steps,
    j,
    grouping,
    total: 0,
    legacyTotal: 0,
  };
  return finish(g, cfgBytes, envelopeBytes);
}

/**
 * Lower bounds for the best-case projection, each at most what a real bundle can cost: the smallest certificate in the corpus
 * (the one-signature fixture, 445 bytes at depth 0), one signature, and an input record of no bytes.
 */
export const BEST_UC_BYTES = 445;
export const BEST_IR_BYTES = 0;
export const BEST_SIGNATURES = 1;
/** The CBOR items of the smallest certificate: the fixture's depth-0 certificate has 45 with four signatures, each signature entry is two (key and value). */
export const BEST_UC_ITEMS = 39;

/**
 * The burn-time best-case projection: the estimate of the redemption envelope a token with `leaves` leaves (the burn included) and a
 * `historyBytes` history would need if everything the burn cannot yet know turns out as small as it can: the consolidated bundle,
 * `anchors` anchors (one per aggregator shard the leaves touch, at least 1, at most `leaves`) under ONE seal, the smallest
 * certificates and empty paths. With the shard count unknown the best case is one anchor (a single certificate may serve every leaf).
 * It is the burn-time estimate only: nothing is refused for its size (owner section 36); the bundle actually fetched is estimated at
 * redemption.
 */
export function projectedGate(cfgBytes: number, policyBytes: number, leaves: number, historyBytes: number, anchors = 1): { gate: Gate; envelopeBytes: number } {
  const k = Math.max(1, Math.min(anchors, leaves));
  const word = 32;
  // abi.encode(bytes policy, bytes history, Anchor[] anchors, LeafProof[] leaves), best-case sizes, k anchors under one seal.
  const bytesField = (n: number): number => word + pad32(n);
  const anchorBytes = 7 * word + bytesField(1) + bytesField(BEST_UC_BYTES) + bytesField(BEST_IR_BYTES);
  const leafBytes = 3 * word + word;
  const envelope = 4 * word + bytesField(policyBytes) + bytesField(historyBytes) +
    word + k * (word + anchorBytes) + word + leaves * (word + leafBytes);
  const grouping: Counts = { k, c: 4 + k * (106 + 1 + BEST_UC_BYTES), e: 1, s: 1, q: BEST_SIGNATURES, a: k, p: 0, items: k * BEST_UC_ITEMS };
  const j = fixedItems(k) + grouping.items;
  // The history's own items are not counted (a lower bound: the burn cannot see the final history's encoding).
  const compose: ComposeDims = { b: kernelRequestBytes(cfgBytes, envelope), j, l: leaves, q: BEST_SIGNATURES, e: 1, a: k, k, p: 0 };
  const g: Gate = {
    compose,
    native: 0,
    intrinsic: intrinsicGas(cfgBytes, envelope),
    b2: b2Gas(kernelRequestBytes(cfgBytes, historyBytes), leaves),
    batch: batchGas(grouping),
    items: itemGas(j),
    rsmt: leaves * rsmtGas(0),
    steps: 0,
    j,
    grouping,
    total: 0,
    legacyTotal: 0,
  };
  return { gate: finish(g, cfgBytes, envelope), envelopeBytes: envelope };
}
