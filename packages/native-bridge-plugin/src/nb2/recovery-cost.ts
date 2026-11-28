/** Cold admission is based on the complete signed EIP-1559 envelope and a pinned execution bound. */
import { eq } from '../bytes.js';
import { redeemCalldataLength } from './abi.js';
import { decodeConfig, domainOf, MAX_SEGMENT, type Config, type Params } from './config.js';
import { fail } from './errors.js';
import type { RedeemShape } from './gas.js';
import { rlpBytes, rlpList, rlpUintEnc } from './rlp.js';
import { burnIndex, verifySealReceipt } from './rules.js';
import { gapProofLen } from './segment.js';
import { decodeToken, lineageOf, MAX_TRANSFER_PAIR } from './token.js';
import type { RecoveryDeployment } from './recovery.js';
import type { TrustInput } from './trust.js';
import { verifyHeld } from './verify.js';

export const validRecoveryDeployment = (d: RecoveryDeployment, cfg?: Config): boolean =>
  d.salt.length === 32 && d.recovery.length === 20 && d.runtimeHash.length === 32 && d.pins.length === 32
  && (d.vaultRuntimeHash === undefined || d.vaultRuntimeHash.length === 32)
  && (!cfg?.erc20 || (eq(d.salt, cfg.erc20.generation) && eq(d.pins, cfg.erc20.pins)));

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
  /** Size the signed envelope at maximal nonce and bid widths for portable wallet plans. */
  worstCaseEnvelope?: boolean;
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
/** Wallet admission policy for the ERC20 release. The continuation wire still accepts 16 Resume operations. */
export const ERC20_RESUME_OPERATIONS = 8;
const U64_MAX = (1n << 64n) - 1n;
const U256_MAX = (1n << 256n) - 1n;

function validLimits(limits: RecoveryLimits): boolean {
  const payer = [limits.gas, limits.chainId, limits.maxNonce, limits.maxFeePerGas, limits.maxPriorityFeePerGas, limits.balance, limits.feeBudget];
  return Number.isSafeInteger(limits.calldataBytes) && Number.isSafeInteger(limits.signedBytes)
    && payer.every((value) => typeof value === 'bigint' && value >= 0n)
    && (limits.maxTransactionFee === undefined || (typeof limits.maxTransactionFee === 'bigint' && limits.maxTransactionFee >= 0n));
}

export function quoteRecovery(shape: RecoveryShape, calibration: RecoveryCalibration, limits: RecoveryLimits, erc20 = false): RecoveryQuote | null {
  const snapshot = { ...limits };
  return validLimits(snapshot) ? quoteRange(shape, shape.receiptBytes, calibration, snapshot, erc20) : null;
}

function quoteRange(shape: RecoveryShape, minReceiptBytes: number, calibration: RecoveryCalibration, limits: RecoveryLimits, erc20 = false): RecoveryQuote | null {
  const { calldataBytes: n } = shape;
  if (!Number.isSafeInteger(n) || n < 68 || n > Math.min(CALLDATA_BYTES, limits.calldataBytes)) return null;
  if (erc20 && shape.entry === 'run' && shape.receiptBytes > 0 && shape.operations > ERC20_RESUME_OPERATIONS) return null;
  if (![shape.operations, shape.pages, shape.gaps, shape.receiptBytes, shape.openingBytes].every((v) => Number.isSafeInteger(v) && v >= 0)
    || shape.operations > 16 || shape.pages > 32 || shape.gaps > 1024 || shape.receiptBytes > RECEIPT_BYTES) return null;
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
  const bid = quoteErc20Call(n, gas, limits);
  return bid && { shape, gas, ...bid };
}

/** Bound a zero-value Type 2 call with an empty access list and full-width signature. */
export function quoteErc20Call(n: number, gas: bigint, limits: RecoveryLimits): { signedBytes: number; fee: bigint } | null {
  if (!validLimits(limits) || !Number.isSafeInteger(n) || n < 68 || n > Math.min(CALLDATA_BYTES, limits.calldataBytes)
    || typeof gas !== 'bigint' || gas <= 0n) return null;
  if (gas > GAS_LIMIT || gas > limits.gas || limits.chainId <= 0n || limits.chainId > U64_MAX || limits.maxNonce < 0n || limits.maxNonce > U64_MAX
    || limits.maxFeePerGas <= 0n || limits.maxFeePerGas > U256_MAX || limits.maxPriorityFeePerGas < 0n
    || limits.maxPriorityFeePerGas > limits.maxFeePerGas) return null;
  const signedBytes = 1 + rlpList([
    rlpUintEnc(limits.chainId), rlpUintEnc(limits.worstCaseEnvelope ? U64_MAX : limits.maxNonce),
    rlpUintEnc(limits.worstCaseEnvelope ? U256_MAX : limits.maxPriorityFeePerGas),
    rlpUintEnc(limits.worstCaseEnvelope ? U256_MAX : limits.maxFeePerGas),
    rlpUintEnc(gas), rlpBytes(new Uint8Array(20)), rlpUintEnc(0), rlpBytes(new Uint8Array(n)), rlpList([]),
    rlpUintEnc(1), rlpBytes(new Uint8Array(32)), rlpBytes(new Uint8Array(32)),
  ]).length;
  if (signedBytes > Math.min(TX_BYTES, limits.signedBytes)) return null;
  const fee = gas * limits.maxFeePerGas;
  if (limits.maxTransactionFee !== undefined && fee > limits.maxTransactionFee) return null;
  return { signedBytes, fee };
}

export type RecoveryRunSpan = { start: number; end: number; claims: number };
const calldataSize = (payload: number): number => 68 + 32 * Math.ceil(payload / 32);

function runShape(spans: readonly RecoveryRunSpan[], from: number, end: number, n: number, receiptBytes: number, openingBytes: number): RecoveryShape | null {
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
  /** Qualified maximum arrivals, including bursts, before the next usable advance proof. */
  advancePeakSeals: bigint;
  /** Qualified time from sealing the final endpoint, including proof retrieval, through settlement inclusion. */
  finalInclusionMs: bigint;
  /** Qualified maximum arrivals, including bursts, in any finalInclusionMs window. */
  finalPeakSeals: bigint;
  /** Horizon for which the peak-rate and timing bounds are qualified after lineage progress. */
  qualifiedForMs: bigint;
}

/** Qualified upper time bounds from signing through inclusion, in milliseconds. */
export interface Erc20SigningBounds {
  feeWindowMs: bigint;
  /** Includes certification of the burn and all Run calls, restore and any delay before fallback. */
  progressWindowMs: bigint;
  /** Maximum number of sequential Run certificates covered by the progress and arrival bounds. */
  maxRunCalls: number;
  /** Worst time to inclusion and usable proof, over which advancePeakSeals is bounded. */
  advanceWindowMs: bigint;
  ordinary?: {
    gas: bigint;
    calldataBytes: number;
    /** Maximum mined ordinary attempts charged before falling back to recovery. */
    attemptsBeforeFallback: bigint;
    inclusionMs: bigint;
  };
}

function checkBacklogMeasurements(backlog: RecoveryBacklog): void {
  const times = [backlog.elapsedMs, backlog.receiptP99Ms, backlog.finalInclusionMs, backlog.qualifiedForMs];
  const counts = [backlog.signedStart, backlog.observed, backlog.duringProgress, backlog.peakSeals, backlog.advancePeakSeals, backlog.finalPeakSeals];
  if (times.some((v) => typeof v !== 'bigint' || v <= 0n) || counts.some((v) => typeof v !== 'bigint' || v < 0n)) {
    fail('CapacityPreflight', 'unqualified backlog measurements');
  }
}

function recoveryGapNeed(backlog: RecoveryBacklog): bigint {
  const target = (backlog.observed > backlog.signedStart ? backlog.observed : backlog.signedStart) + backlog.duringProgress + 64n;
  if (target > MAX_SEGMENT) fail('CapacityPreflight', 'unqualified backlog');
  if (backlog.finalPeakSeals > 1n) fail('CapacityPreflight', 'unqualified final inclusion window');
  return target - backlog.signedStart;
}

/** Reserve the greater route at the fee ceiling, plus each allowed pre-fallback charge. */
export function erc20SigningReserve(recoveryFee: bigint, runCalls: number, calls: bigint, backlog: RecoveryBacklog,
  limits: RecoveryLimits, bounds?: Erc20SigningBounds): { totalFee: bigint; priorAttempts: bigint } {
  checkBacklogMeasurements(backlog);
  if (!validLimits(limits) || limits.maxFeePerGas <= 0n || limits.maxFeePerGas > U256_MAX
    || limits.maxPriorityFeePerGas > limits.maxFeePerGas) fail('CapacityPreflight', 'invalid ERC20 fee limits');
  if (!bounds || [bounds.feeWindowMs, bounds.progressWindowMs, bounds.advanceWindowMs]
    .some((v) => typeof v !== 'bigint' || v <= 0n) || bounds.advanceWindowMs < backlog.receiptP99Ms) {
    fail('CapacityPreflight', 'unqualified ERC20 fee or inclusion windows');
  }
  if (!Number.isSafeInteger(bounds.maxRunCalls) || bounds.maxRunCalls < 1 || runCalls > bounds.maxRunCalls) {
    fail('CapacityPreflight', 'Run schedule exceeds the qualified progress window');
  }
  const continuationMs = calls * bounds.advanceWindowMs + backlog.finalInclusionMs;
  if (continuationMs > backlog.qualifiedForMs || bounds.progressWindowMs + continuationMs > bounds.feeWindowMs) {
    fail('CapacityPreflight', 'unqualified ERC20 signing horizon');
  }
  let totalFee = recoveryFee;
  let priorAttempts = 0n;
  if (bounds.ordinary) {
    const { gas, calldataBytes, attemptsBeforeFallback, inclusionMs } = bounds.ordinary;
    if (typeof attemptsBeforeFallback !== 'bigint' || attemptsBeforeFallback <= 0n || typeof inclusionMs !== 'bigint'
      || inclusionMs <= 0n || attemptsBeforeFallback * inclusionMs > bounds.progressWindowMs) {
      fail('CapacityPreflight', 'unqualified ordinary retry window');
    }
    const bid = quoteErc20Call(calldataBytes, gas, limits);
    if (bid === null) fail('CapacityPreflight', 'ordinary call is outside the ERC20 admission limits');
    priorAttempts = attemptsBeforeFallback;
    totalFee = (recoveryFee > bid.fee ? recoveryFee : bid.fee) + priorAttempts * bid.fee;
  }
  if (totalFee > limits.feeBudget) fail('CapacityPreflight', 'insufficient authorized fee budget');
  if (totalFee > limits.balance) fail('CapacityPreflight', 'insufficient free payer balance');
  return { totalFee, priorAttempts };
}

/** Verify that the chosen advance can reach a payable end under the qualified arrival windows. */
export function recoveryCatchUpCalls(batch: number, backlog: RecoveryBacklog): bigint {
  if (!Number.isSafeInteger(batch) || batch < 1 || batch > 1024) fail('CapacityPreflight', 'invalid recovery gap batch');
  checkBacklogMeasurements(backlog);
  const need = recoveryGapNeed(backlog);
  const q = BigInt(batch);
  const arriving = backlog.advancePeakSeals;
  if (q <= arriving || q * backlog.elapsedMs < 2n * backlog.peakSeals * backlog.receiptP99Ms) {
    fail('CapacityPreflight', 'insufficient certified catch-up rate');
  }
  const net = q - arriving;
  const calls = (need + net - 1n) / net;
  if (backlog.signedStart + need + calls * arriving + backlog.finalPeakSeals > MAX_SEGMENT ||
    calls * backlog.receiptP99Ms + backlog.finalInclusionMs > backlog.qualifiedForMs) {
    fail('CapacityPreflight', 'unqualified catch-up horizon');
  }
  return calls;
}

function prospectiveRunQuotes(evidence: Uint8Array, calibration: RecoveryCalibration, limits: RecoveryLimits,
  erc20: boolean, token = decodeToken(evidence)) {
  const view = new DataView(evidence.buffer, evidence.byteOffset, evidence.byteLength);
  const spans: RecoveryRunSpan[] = [];
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
  return { operations: spans.length, quoted: (from: number, end: number) => quoteRunCut(spans, from, end, n, calibration, limits, erc20) };
}

export function quoteRunCut(spans: readonly RecoveryRunSpan[], from: number, end: number, evidenceBytes: number,
  calibration: RecoveryCalibration, limits: RecoveryLimits, erc20: boolean): RecoveryQuote | null {
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(end) || from < 0 || end > spans.length || end <= from || end - from > 16) return null;
  const opening = spans.slice(from, end).reduce((sum, op) => sum + SPARSE + op.claims * (34 + SPARSE), 0);
  const shape = runShape(spans, from, end, evidenceBytes, from === 0 ? 0 : RECEIPT_BYTES, opening);
  return shape === null ? null : quoteRange(shape, from === 0 ? 0 : 1, calibration, limits, erc20);
}

/** Price each remaining scheduled run at the same bounds used at admission. */
export function checkRemainingRecoveryRuns(held: Uint8Array, cuts: readonly number[], confirmedCuts: number,
  calibration: RecoveryCalibration, limits: RecoveryLimits, erc20 = false): bigint {
  const { operations, quoted } = prospectiveRunQuotes(Uint8Array.from(held), calibration, limits, erc20);
  let fee = 0n;
  let from = 0;
  for (const [index, count] of cuts.entries()) {
    const end = from + count;
    if (!Number.isSafeInteger(count) || count < 1 || count > 16 || end > operations) {
      fail('CapacityPreflight', 'invalid portable run cut');
    }
    if (index >= confirmedCuts) {
      const quote = quoted(from, end);
      if (!quote) fail('CapacityPreflight', 'portable run cut is outside the release limits');
      fee += quote.fee;
    }
    from = end;
  }
  if (from !== operations) fail('CapacityPreflight', 'portable run cuts do not cover the lineage');
  return fee;
}

export function scheduleRecoveryRuns(operations: number, quote: (from: number, end: number) => RecoveryQuote | null): RecoveryQuote[] {
  const run: RecoveryQuote[] = [];
  // Check even operations that normally share a cut with their neighbours.
  for (let i = 0; i < operations; i++) {
    if (quote(i, i + 1) === null) fail('CapacityPreflight', 'indivisible run operation');
  }
  for (let from = 0; from < operations;) {
    let end = Math.min(from + 16, operations);
    let priced: RecoveryQuote | null;
    while ((priced = quote(from, end)) === null) end--;
    run.push(priced);
    from = end;
  }
  return run;
}

/** Price the hypothetical terminal pair at its decoder cap, including its prefix, page alignment and worst later witnesses. */
export async function preflightRecovery(gamma: Uint8Array, held: Uint8Array, trust: TrustInput, params: Params,
  deployment: RecoveryDeployment, calibration: RecoveryCalibration, limits: RecoveryLimits, backlog: RecoveryBacklog, startingSeal?: Uint8Array,
  bounds?: Erc20SigningBounds,
): Promise<{ run: RecoveryQuote[]; advance: { quote: RecoveryQuote; calls: bigint }; settle: RecoveryQuote; settlementMaxGaps: number; totalFee: bigint; priorAttempts: bigint }> {
  limits = { ...limits };
  if (!validLimits(limits)) fail('CapacityPreflight', 'invalid recovery payer limits');
  backlog = { ...backlog };
  checkBacklogMeasurements(backlog);
  const config = Uint8Array.from(gamma);
  const cfg = decodeConfig(config, params);
  if (!validRecoveryDeployment(deployment, cfg) || !eq(deployment.pins, calibration.pins) || !eq(deployment.runtimeHash, calibration.runtimeHash) || deployment.vaultRuntimeHash?.length !== 32 || calibration.vaultRuntimeHash?.length !== 32
    || !eq(deployment.vaultRuntimeHash, calibration.vaultRuntimeHash) || cfg.chainId !== limits.chainId) {
    fail('CapacityPreflight', 'unqualified recovery deployment');
  }
  const evidence = Uint8Array.from(held);
  const token = decodeToken(evidence);
  const domain = domainOf(config);
  await verifyHeld(cfg, domain, trust, token);
  const seal = startingSeal === undefined ? null : await verifySealReceipt(cfg, domain, trust, startingSeal);
  if (burnIndex(cfg, domain, seal).a !== backlog.signedStart) fail('CapacityPreflight', 'unauthenticated signed start');
  const { operations, quoted } = prospectiveRunQuotes(evidence, calibration, limits, cfg.erc20 !== undefined, token);
  const run = scheduleRecoveryRuns(operations, quoted);
  const need = recoveryGapNeed(backlog);
  const width = gapProofLen(cfg.K);
  const gap = (count: number) => quoteRange(gapShape('advanceGaps', count, width), 1, calibration, limits);
  if (gap(1) === null) fail('CapacityPreflight', 'indivisible gap operation');
  let q = Math.min(1024, Number(need));
  let advance: RecoveryQuote | null = null;
  for (; q > 0; q--) {
    advance = gap(q);
    if (advance !== null) break;
  }
  if (advance === null) fail('CapacityPreflight', 'insufficient certified catch-up rate');
  const calls = recoveryCatchUpCalls(q, backlog);
  // Once fewer than q gaps remain, settle against the latest proved endpoint. Price
  // every possible terminal suffix: the release need not price it monotonically.
  const settle = quoteSettlementSuffixes(q, width, calibration, limits);
  if (settle === null) fail('CapacityPreflight', 'unqualified settlement suffix');
  const recoveryFee = run.reduce((sum, call) => sum + call.fee, 0n) + advance.fee * calls + settle.fee;
  const { totalFee, priorAttempts } = cfg.erc20 ? erc20SigningReserve(recoveryFee, run.length, calls, backlog, limits, bounds)
    : { totalFee: recoveryFee, priorAttempts: 0n };
  if (totalFee > limits.feeBudget || totalFee > limits.balance) fail('CapacityPreflight', 'insufficient recovery fee budget');
  return { run, advance: { quote: advance, calls }, settle, settlementMaxGaps: q - 1, totalFee, priorAttempts };
}

export interface OrdinaryCalibrationRange { maxEvidenceBytes: number; maxOperations: number; maxGaps: bigint; execution: bigint }

export function quoteOrdinaryExecution(shape: RedeemShape, ranges: readonly OrdinaryCalibrationRange[], reserve: bigint): bigint | null {
  const operations = shape.lineage.reduce((sum, level) => sum + 1 + level.transfers.length, shape.pendingTransactions);
  let execution: bigint | undefined;
  for (const range of ranges) {
    if (shape.evidenceBytes <= range.maxEvidenceBytes && operations <= range.maxOperations && shape.proofs <= range.maxGaps &&
        range.execution > 0n && (execution === undefined || range.execution < execution)) execution = range.execution;
  }
  if (execution === undefined) return null;
  const history = shape.proofs === 0n ? 0 : 32 + Number(shape.proofs) * gapProofLen(shape.K);
  const n = redeemCalldataLength(shape.evidenceBytes, history);
  return 21_000n + 16n * BigInt(n) + (6n * execution + 4n) / 5n + (reserve > SEAL_RESERVE ? reserve : SEAL_RESERVE);
}
