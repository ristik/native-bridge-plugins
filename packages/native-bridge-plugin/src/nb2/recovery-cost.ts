/** Cold admission is based on the complete signed EIP-1559 envelope and a pinned execution bound. */
import { eq } from '../bytes.js';
import { decodeConfig, domainOf, MAX_SEGMENT, type Params } from './config.js';
import { fail } from './errors.js';
import { rlpBytes, rlpList, rlpUintEnc } from './rlp.js';
import { burnIndex, verifySealReceipt } from './rules.js';
import { gapProofLen } from './segment.js';
import { decodeToken, lineageOf, MAX_TRANSFER_PAIR } from './token.js';
import type { RecoveryDeployment } from './recovery.js';
import type { TrustInput } from './trust.js';
import { verifyHeld } from './verify.js';

export interface RecoveryShape {
  entry: 'run' | 'advanceGaps' | 'redeemRecovered';
  calldataBytes: number;
  operations: number;
  pages: number;
  gaps: number;
  receiptBytes: number;
  openingBytes: number;
}

/** Authenticated release calibration. The execution bound includes forwarding and memory, excluding transaction intrinsic and the seal reserve. */
export interface RecoveryCalibration {
  pins: Uint8Array;
  runtimeHash: Uint8Array;
  vaultRuntimeHash?: Uint8Array;
  executionBound(shape: Readonly<RecoveryShape>): bigint | null;
}

/** Effective minima over the authenticated deployment, node/relay, chain and payer. Empty access lists, zero value. */
export interface RecoveryLimits {
  signedBytes: number;
  calldataBytes: number;
  gas: bigint;
  chainId: bigint;
  maxNonce: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  balance: bigint;
  feeBudget: bigint;
}

export interface RecoveryQuote {
  shape: RecoveryShape;
  gas: bigint;
  signedBytes: number;
  fee: bigint;
}

const TX_BYTES = 524_288;
const CALLDATA_BYTES = 393_216;
const RECEIPT_BYTES = 65_536;
const SPARSE = 8_224;
const SEAL_RESERVE = 500_000n;
const GAS_LIMIT = 24_000_000n;
const U64_MAX = (1n << 64n) - 1n;
const U256_MAX = (1n << 256n) - 1n;

export function quoteRecovery(shape: RecoveryShape, calibration: RecoveryCalibration, limits: RecoveryLimits): RecoveryQuote | null {
  const { calldataBytes: n } = shape;
  if (!Number.isSafeInteger(n) || !Number.isSafeInteger(limits.calldataBytes) || !Number.isSafeInteger(limits.signedBytes)
    || n < 68 || n > Math.min(CALLDATA_BYTES, limits.calldataBytes)) return null;
  const execution = calibration.executionBound(Object.freeze({ ...shape }));
  if (execution === null || execution <= 0n) return null;
  const gas = 21_000n + 16n * BigInt(n) + (6n * execution + 4n) / 5n
    + (shape.entry === 'redeemRecovered' ? SEAL_RESERVE : 0n);
  if (gas > GAS_LIMIT || gas > limits.gas || limits.chainId <= 0n || limits.chainId > U64_MAX || limits.maxNonce < 0n || limits.maxNonce > U64_MAX
    || limits.maxFeePerGas <= 0n || limits.maxFeePerGas > U256_MAX || limits.maxPriorityFeePerGas < 0n
    || limits.maxPriorityFeePerGas > limits.maxFeePerGas) return null;
  const signedBytes = 1 + rlpList([
    rlpUintEnc(limits.chainId), rlpUintEnc(limits.maxNonce), rlpUintEnc(limits.maxPriorityFeePerGas), rlpUintEnc(limits.maxFeePerGas),
    rlpUintEnc(gas), rlpBytes(new Uint8Array(20)), rlpUintEnc(0), rlpBytes(new Uint8Array(n)), rlpList([]),
    rlpUintEnc(1), rlpBytes(new Uint8Array(32)), rlpBytes(new Uint8Array(32)),
  ]).length;
  if (signedBytes > Math.min(TX_BYTES, limits.signedBytes)) return null;
  return { shape, gas, signedBytes, fee: gas * limits.maxFeePerGas };
}

type Span = { start: number; end: number; claims: number };
const calldataSize = (payload: number): number => 68 + 32 * Math.ceil(payload / 32);

function runShape(spans: readonly Span[], from: number, end: number, n: number, receiptBytes: number, openingBytes: number): RecoveryShape | null {
  if (end <= from || end - from > 16) return null;
  const first = from === 0 ? 0 : Math.floor(spans[from].start / 4096);
  const last = Math.floor((spans[end - 1].end - 1) / 4096);
  const pages = last - first + 1;
  if (pages > 32) return null;
  const depth = Math.ceil(Math.log2(Math.ceil(n / 4096)));
  const pageBytes = Math.min((last + 1) * 4096, n) - first * 4096 + pages * (8 + 32 * depth);
  const prefix = from === 0 ? 0 : 290 + 4 + receiptBytes;
  return {
    entry: 'run', operations: end - from, pages, gaps: 0, receiptBytes, openingBytes,
    calldataBytes: calldataSize(42 + 1 + prefix + 1 + pageBytes + 1 + end - from + openingBytes),
  };
}

const gapShape = (entry: 'advanceGaps' | 'redeemRecovered', gaps: number, width: number): RecoveryShape => ({
  entry, operations: 0, pages: 0, gaps, receiptBytes: RECEIPT_BYTES, openingBytes: 0,
  calldataBytes: calldataSize(42 + 1 + 4 + RECEIPT_BYTES + 2 + (gaps === 0 ? 0 : 32) + gaps * width),
});

export interface RecoveryBacklog {
  signedStart: bigint;
  observed: bigint;
  /** Upper bound on segments appended while the progress packets become certified. */
  duringProgress: bigint;
  /** An authenticated measurement of peak seals in the same window as elapsedMs. */
  peakSeals: bigint;
  elapsedMs: bigint;
  receiptP99Ms: bigint;
}

/** Price the hypothetical terminal pair at its decoder cap, including its prefix, page alignment and worst later witnesses. */
export async function preflightRecovery(gamma: Uint8Array, held: Uint8Array, trust: TrustInput, params: Params,
  deployment: RecoveryDeployment, calibration: RecoveryCalibration, limits: RecoveryLimits, backlog: RecoveryBacklog, startingSeal?: Uint8Array,
): Promise<{ run: RecoveryQuote[]; advance: { quote: RecoveryQuote; calls: bigint; tail: RecoveryQuote | null }; settle: RecoveryQuote; totalFee: bigint }> {
  const cfg = decodeConfig(gamma, params);
  if (!eq(deployment.pins, calibration.pins) || !eq(deployment.runtimeHash, calibration.runtimeHash) || deployment.vaultRuntimeHash?.length !== 32 || calibration.vaultRuntimeHash?.length !== 32
    || !eq(deployment.vaultRuntimeHash, calibration.vaultRuntimeHash) || cfg.chainId !== limits.chainId) {
    fail('CapacityPreflight', 'unqualified recovery deployment');
  }
  const evidence = Uint8Array.from(held);
  const token = decodeToken(evidence);
  const domain = domainOf(gamma);
  await verifyHeld(cfg, domain, trust, token);
  const seal = startingSeal === undefined ? null : await verifySealReceipt(cfg, domain, trust, startingSeal);
  if (burnIndex(cfg, domain, seal).a !== backlog.signedStart) fail('CapacityPreflight', 'unauthenticated signed start');
  const view = new DataView(evidence.buffer);
  const spans: Span[] = [];
  let pos = 14;
  const skip = (): void => { pos += 4 + view.getUint32(pos); };
  for (const [index, level] of lineageOf(token).entries()) {
    const start = pos;
    skip(); skip(); skip();
    pos += 8;
    spans.push({ start, end: pos, claims: index === 0 ? 2 : 1 });
    for (const _ of level.transfers) {
      const start = pos;
      skip();
      spans.push({ start, end: pos, claims: 1 });
    }
  }
  const n = pos + MAX_TRANSFER_PAIR + 4;
  spans.push({ start: pos, end: n, claims: 1 });
  const run: RecoveryQuote[] = [];
  const quoted = (from: number, end: number): RecoveryQuote | null => {
    const opening = spans.slice(from, end).reduce((sum, op) => sum + SPARSE + op.claims * (34 + SPARSE), 0);
    const shape = runShape(spans, from, end, n, from === 0 ? 0 : RECEIPT_BYTES, opening);
    return shape === null ? null : quoteRecovery(shape, calibration, limits);
  };
  // Every operation must fit alone when a cut has to be retried with a full predecessor.
  for (let i = 0; i < spans.length; i++) {
    if (quoted(i, i + 1) === null) fail('CapacityPreflight', 'indivisible run operation');
  }
  for (let from = 0; from < spans.length;) {
    let end = Math.min(from + 16, spans.length);
    let quote: RecoveryQuote | null;
    while ((quote = quoted(from, end)) === null) end--;
    run.push(quote);
    from = end;
  }
  if (backlog.signedStart < 0n || backlog.observed < backlog.signedStart || backlog.duringProgress < 0n
    || backlog.observed + backlog.duringProgress + 64n > MAX_SEGMENT || backlog.peakSeals < 0n
    || backlog.elapsedMs <= 0n || backlog.receiptP99Ms <= 0n) fail('CapacityPreflight', 'unqualified backlog');
  const need = backlog.observed - backlog.signedStart + backlog.duringProgress + 64n;
  const width = gapProofLen(cfg.K);
  let q = Math.min(1024, Number(need));
  let gap: RecoveryQuote | null = null;
  for (; q > 0; q--) {
    gap = quoteRecovery(gapShape('advanceGaps', q, width), calibration, limits);
    if (gap !== null) break;
  }
  if (gap === null || BigInt(q) * backlog.elapsedMs < 2n * backlog.peakSeals * backlog.receiptP99Ms) {
    fail('CapacityPreflight', 'insufficient certified catch-up rate');
  }
  const settle = quoteRecovery(gapShape('redeemRecovered', 0, width), calibration, limits);
  if (settle === null) fail('CapacityPreflight', 'indivisible settlement');
  const calls = need / BigInt(q);
  const remaining = Number(need % BigInt(q));
  const tail = remaining === 0 ? null : quoteRecovery(gapShape('advanceGaps', remaining, width), calibration, limits);
  if (remaining !== 0 && tail === null) fail('CapacityPreflight', 'unqualified gap remainder');
  const totalFee = run.reduce((sum, call) => sum + call.fee, 0n) + gap.fee * calls + (tail?.fee ?? 0n) + settle.fee;
  if (totalFee > limits.feeBudget || totalFee > limits.balance) fail('CapacityPreflight', 'insufficient recovery fee budget');
  return { run, advance: { quote: gap, calls, tail }, settle, totalFee };
}
