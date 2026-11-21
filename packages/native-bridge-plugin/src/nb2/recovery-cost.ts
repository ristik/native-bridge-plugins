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

export const validRecoveryDeployment = (d: RecoveryDeployment): boolean =>
  d.salt.length === 32 && d.recovery.length === 20 && d.runtimeHash.length === 32 && d.pins.length === 32
  && (d.vaultRuntimeHash === undefined || d.vaultRuntimeHash.length === 32);

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
  ranges: readonly RecoveryCalibrationRange[];
}

/** A qualified envelope for the same entry, operation count and gap count.
 * It covers the inclusive receipt interval and all smaller calldata, page and opening sizes for that class.
 */
export interface RecoveryCalibrationRange {
  minReceiptBytes: number;
  max: Readonly<RecoveryShape>;
  execution: bigint;
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
  maxTransactionFee?: bigint;
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

function validLimits(limits: RecoveryLimits): boolean {
  const payer = [limits.gas, limits.chainId, limits.maxNonce, limits.maxFeePerGas, limits.maxPriorityFeePerGas, limits.balance, limits.feeBudget];
  return Number.isSafeInteger(limits.calldataBytes) && Number.isSafeInteger(limits.signedBytes)
    && payer.every((value) => typeof value === 'bigint' && value >= 0n)
    && (limits.maxTransactionFee === undefined || (typeof limits.maxTransactionFee === 'bigint' && limits.maxTransactionFee >= 0n));
}

export function quoteRecovery(shape: RecoveryShape, calibration: RecoveryCalibration, limits: RecoveryLimits): RecoveryQuote | null {
  const snapshot = { ...limits };
  return validLimits(snapshot) ? quoteRange(shape, shape.receiptBytes, calibration, snapshot) : null;
}

function quoteRange(shape: RecoveryShape, minReceiptBytes: number, calibration: RecoveryCalibration, limits: RecoveryLimits): RecoveryQuote | null {
  const { calldataBytes: n } = shape;
  if (!Number.isSafeInteger(n) || n < 68 || n > Math.min(CALLDATA_BYTES, limits.calldataBytes)) return null;
  let execution: bigint | null = null;
  for (const range of calibration.ranges ?? []) {
    const { max } = range;
    if (max.entry === shape.entry && max.operations === shape.operations && max.gaps === shape.gaps
      && range.minReceiptBytes <= minReceiptBytes && max.receiptBytes >= shape.receiptBytes
      && max.calldataBytes >= n && max.pages >= shape.pages && max.openingBytes >= shape.openingBytes
      && range.execution > 0n && (execution === null || range.execution < execution)) execution = range.execution;
  }
  if (execution === null) return null;
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
  const fee = gas * limits.maxFeePerGas;
  if (limits.maxTransactionFee !== undefined && fee > limits.maxTransactionFee) return null;
  return { shape, gas, signedBytes, fee };
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

/** Quote the exact full advance and all terminal suffixes with the widest allowed predecessor receipt. */
export function quoteRecoveryGapBatch(K: bigint, batch: number, calibration: RecoveryCalibration, limits: RecoveryLimits):
  { advance: RecoveryQuote; settle: RecoveryQuote } | null {
  if (!Number.isSafeInteger(batch) || batch < 1 || batch > 1024 || !validLimits(limits)) return null;
  const width = gapProofLen(K);
  const advance = quoteRange(gapShape('advanceGaps', batch, width), 1, calibration, limits);
  if (advance === null) return null;
  const settle = quoteSettlementSuffixes(batch, width, calibration, limits);
  return settle === null ? null : { advance, settle };
}

function quoteSettlementSuffixes(batch: number, width: number, calibration: RecoveryCalibration, limits: RecoveryLimits): RecoveryQuote | null {
  let settle: RecoveryQuote | null = null;
  for (let count = 0; count < batch; count++) {
    const quote = quoteRange(gapShape('redeemRecovered', count, width), 1, calibration, limits);
    if (quote === null) return null;
    if (settle === null || quote.fee > settle.fee) settle = quote;
  }
  return settle;
}

export interface RecoveryBacklog {
  signedStart: bigint;
  observed: bigint;
  /** Upper bound on segments appended while the progress packets become certified. */
  duringProgress: bigint;
  /** Sustained peak count over elapsedMs, for the catch-up throughput check. */
  peakSeals: bigint;
  elapsedMs: bigint;
  receiptP99Ms: bigint;
  /** Qualified maximum arrivals, including bursts, in any receiptP99Ms window. */
  advancePeakSeals: bigint;
  /** Qualified time from sealing the final endpoint, including proof retrieval, through settlement inclusion. */
  finalInclusionMs: bigint;
  /** Qualified maximum arrivals, including bursts, in any finalInclusionMs window. */
  finalPeakSeals: bigint;
  /** Horizon for which the peak-rate and timing bounds are qualified after lineage progress. */
  qualifiedForMs: bigint;
}

/** Price the hypothetical terminal pair at its decoder cap, including its prefix, page alignment and worst later witnesses. */
export async function preflightRecovery(gamma: Uint8Array, held: Uint8Array, trust: TrustInput, params: Params,
  deployment: RecoveryDeployment, calibration: RecoveryCalibration, limits: RecoveryLimits, backlog: RecoveryBacklog, startingSeal?: Uint8Array,
): Promise<{ run: RecoveryQuote[]; advance: { quote: RecoveryQuote; calls: bigint }; settle: RecoveryQuote; settlementMaxGaps: number; totalFee: bigint }> {
  limits = { ...limits };
  if (!validLimits(limits)) fail('CapacityPreflight', 'invalid recovery payer limits');
  backlog = { ...backlog };
  const times = [backlog.elapsedMs, backlog.receiptP99Ms, backlog.finalInclusionMs, backlog.qualifiedForMs];
  const counts = [backlog.signedStart, backlog.observed, backlog.duringProgress, backlog.peakSeals, backlog.advancePeakSeals, backlog.finalPeakSeals];
  if (times.some((v) => typeof v !== 'bigint' || v <= 0n) || counts.some((v) => typeof v !== 'bigint' || v < 0n)) {
    fail('CapacityPreflight', 'unqualified backlog measurements');
  }
  const config = Uint8Array.from(gamma);
  const cfg = decodeConfig(config, params);
  if (!validRecoveryDeployment(deployment) || !eq(deployment.pins, calibration.pins) || !eq(deployment.runtimeHash, calibration.runtimeHash) || deployment.vaultRuntimeHash?.length !== 32 || calibration.vaultRuntimeHash?.length !== 32
    || !eq(deployment.vaultRuntimeHash, calibration.vaultRuntimeHash) || cfg.chainId !== limits.chainId) {
    fail('CapacityPreflight', 'unqualified recovery deployment');
  }
  const evidence = Uint8Array.from(held);
  const token = decodeToken(evidence);
  const domain = domainOf(config);
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
    return shape === null ? null : quoteRange(shape, from === 0 ? 0 : 1, calibration, limits);
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
  const target = backlog.observed + backlog.duringProgress + 64n;
  if (backlog.observed < backlog.signedStart || target > MAX_SEGMENT) fail('CapacityPreflight', 'unqualified backlog');
  const ceilDiv = (n: bigint, d: bigint): bigint => (n + d - 1n) / d;
  const perAdvance = backlog.advancePeakSeals;
  const finalGrowth = backlog.finalPeakSeals;
  // Proofs for future seals cannot be included. The vault admits the current or previous endpoint.
  if (finalGrowth > 1n) fail('CapacityPreflight', 'unqualified final inclusion window');
  const need = target - backlog.signedStart;
  const width = gapProofLen(cfg.K);
  const gap = (count: number) => quoteRange(gapShape('advanceGaps', count, width), 1, calibration, limits);
  if (gap(1) === null) fail('CapacityPreflight', 'indivisible gap operation');
  let q = Math.min(1024, Number(need));
  let advance: RecoveryQuote | null = null;
  for (; q > 0; q--) {
    advance = gap(q);
    if (advance !== null) break;
  }
  if (advance === null || BigInt(q) <= perAdvance || BigInt(q) * backlog.elapsedMs < 2n * backlog.peakSeals * backlog.receiptP99Ms) {
    fail('CapacityPreflight', 'insufficient certified catch-up rate');
  }
  // Full advances are needed only while at least q proved gaps remain. Reserve for the
  // growing archive by charging every advance against its guaranteed net progress.
  const calls = ceilDiv(need, BigInt(q) - perAdvance);
  if (target + calls * perAdvance + finalGrowth > MAX_SEGMENT
    || calls * backlog.receiptP99Ms + backlog.finalInclusionMs > backlog.qualifiedForMs) {
    fail('CapacityPreflight', 'unqualified catch-up horizon');
  }
  // Once fewer than q gaps remain, settle against the latest proved endpoint. Price
  // every possible terminal suffix: the release need not price it monotonically.
  const settle = quoteSettlementSuffixes(q, width, calibration, limits);
  if (settle === null) fail('CapacityPreflight', 'unqualified settlement suffix');
  const totalFee = run.reduce((sum, call) => sum + call.fee, 0n) + advance.fee * calls + settle.fee;
  if (totalFee > limits.feeBudget || totalFee > limits.balance) fail('CapacityPreflight', 'insufficient recovery fee budget');
  return { run, advance: { quote: advance, calls }, settle, settlementMaxGaps: q - 1, totalFee };
}
