/**
 * The shared direct-call gas gate (interop.md "Direct-call gas gate"): the same formula, with the same constants, as the oracle
 * (`bridgeprofile/gas.go`) and the contract (`BridgeBounds.sol`, `CertGroups.sol`). Every term is the native price of a call the
 * composing verifier makes, or the bounded execution of the verifier itself, computed from complete bounded scans, never from
 * caller-declared costs. It is an admission rule, not a measured fit:
 *
 *   G_gate = 21000 + 16*D_max + 80*B_env + 1000*J + G_kernel + G_batch + sum_i G_leaf(i) + 1,000,000
 */
import { fail } from './errors.js';
import type { Envelope, LeafProof } from './envelope.js';
import { batchGas, countItems, measure, type Counts } from './certgroups.js';
import { NativeError } from './errors.js';
import { BRIDGE_CBOR_ITEMS, BRIDGE_ITEM_GAS, GAS_RESERVE, MAX_PATH_STEPS, MAX_RSMT_SIBLINGS, TX_GAS_BUDGET } from './limits.js';

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

export interface Gate {
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
  /** The gated sum including the fixed reserve. */
  total: number;
}

/** Price a complete bounded envelope against `budget`; above it is `ErrGasBudget` (BudgetExceeded). */
export function computeGate(cfg: Uint8Array, envelopeBytes: number, kernelRequest: number, e: Envelope, budget: number = TX_GAS_BUDGET): Gate {
  const cfgBytes = cfg.length;
  // J: the item occurrences of the Cfg, the policy body, every anchor UC (counted by the batch scan) and every anchor IR opening,
  // each once, against the one shared budget. A malformed object is its own shape failure; crossing the budget is ErrTooManyItems.
  let spent = 0;
  const take = (b: Uint8Array, malformed: Parameters<typeof fail>[0]): void => {
    try {
      spent += countItems(b, BRIDGE_CBOR_ITEMS - spent);
    } catch (err) {
      if (err instanceof NativeError && err.reason === 'ErrTooManyItems') throw err;
      fail(malformed);
    }
  };
  take(cfg, 'ErrShape');
  take(e.policyBody, 'ErrShape');
  for (const a of e.anchors) take(a.inputRecord, 'ErrShape');
  const grouping = measure(e.anchors, spent);
  const j = spent + grouping.items;
  let rsmt = 0;
  let steps = grouping.p;
  for (const p of e.leafProofs) {
    const l = leafPathGas(p);
    rsmt += l.gas;
    steps += l.steps;
  }
  if (steps > MAX_PATH_STEPS) fail('ErrTooManyPaths');
  const g: Gate = {
    intrinsic: intrinsicGas(cfgBytes, envelopeBytes),
    b2: b2Gas(kernelRequest, e.leafProofs.length),
    batch: batchGas(grouping),
    items: itemGas(j),
    rsmt,
    steps,
    j,
    grouping,
    total: 0,
  };
  g.total = g.intrinsic + g.b2 + g.batch + g.items + g.rsmt + GAS_RESERVE;
  if (g.total > budget) fail('ErrGasBudget');
  return g;
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
 * The burn-time best-case projection: the gate of the redemption envelope a token with `leaves` leaves (the burn included) and a
 * `historyBytes` history would need if everything the burn cannot yet know turns out as small as it can: ONE anchor (a single
 * certificate may serve every leaf, so the best case is never one anchor per shard), the smallest certificate and empty paths.
 * The burn is refused, before any wallet burn is made, only when even this cannot pass the gas gate; whether the bundle that is
 * actually fetched passes is the gate's decision at redemption.
 */
export function projectedGate(cfgBytes: number, policyBytes: number, leaves: number, historyBytes: number): { gate: Gate; envelopeBytes: number } {
  const word = 32;
  // abi.encode(bytes policy, bytes history, Anchor[] anchors, LeafProof[] leaves), best-case sizes, one anchor.
  const bytesField = (n: number): number => word + pad32(n);
  const anchorBytes = 7 * word + bytesField(1) + bytesField(BEST_UC_BYTES) + bytesField(BEST_IR_BYTES);
  const leafBytes = 3 * word + word;
  const envelope = 4 * word + bytesField(policyBytes) + bytesField(historyBytes) +
    word + (word + anchorBytes) + word + leaves * (word + leafBytes);
  const grouping: Counts = { k: 1, c: 4 + 106 + 1 + BEST_UC_BYTES, e: 1, s: 1, q: BEST_SIGNATURES, a: 1, p: 0, items: BEST_UC_ITEMS };
  const j = fixedItems(1) + grouping.items;
  const g: Gate = {
    intrinsic: intrinsicGas(cfgBytes, envelope),
    b2: b2Gas(kernelRequestBytes(cfgBytes, historyBytes), leaves),
    batch: batchGas(grouping),
    items: itemGas(j),
    rsmt: leaves * rsmtGas(0),
    steps: 0,
    j,
    grouping,
    total: 0,
  };
  g.total = g.intrinsic + g.b2 + g.batch + g.items + g.rsmt + GAS_RESERVE;
  void BRIDGE_CBOR_ITEMS;
  return { gate: g, envelopeBytes: envelope };
}
