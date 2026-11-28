import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  erc20SigningReserve, quoteErc20Call, quoteRecovery, quoteRunCut, recoveryCatchUpCalls, scheduleRecoveryRuns,
  type Erc20SigningBounds, type RecoveryBacklog, type RecoveryShape,
} from '../../src/nb2/recovery-cost.js';

const limits = { gas: 24_000_000n, chainId: 31337n, signedBytes: 524_288, calldataBytes: 393_216,
  maxNonce: 255n, maxFeePerGas: 10n, maxPriorityFeePerGas: 2n, balance: 10n ** 18n, feeBudget: 10n ** 18n,
  worstCaseEnvelope: true };

const shape: RecoveryShape = { entry: 'run', calldataBytes: 393_188, operations: 16, pages: 32,
  receiptBytes: 65_536, openingBytes: 393_188, gaps: 0 };
const calibration = { pins: new Uint8Array(32), runtimeHash: new Uint8Array(32),
  ranges: Array.from({ length: 16 }, (_, i) => ({ minReceiptBytes: 0, max: { ...shape, operations: i + 1 }, execution: 14_000_000n })) };

test('ERC20 builds a whole schedule with capped Resume cuts and refuses an indivisible operation', () => {
  const spans = Array.from({ length: 25 }, (_, i) => ({ start: i * 4096, end: (i + 1) * 4096, claims: 1 }));
  const quote = (from: number, end: number) => quoteRunCut(spans, from, end, spans.at(-1)!.end, calibration, limits, true);
  const schedule = scheduleRecoveryRuns(spans.length, quote);
  assert.deepEqual(schedule.map((q) => q.shape.operations), [16, 8, 1]);
  assert.deepEqual(schedule.map((q) => q.shape.receiptBytes), [0, 65_536, 65_536]);
  assert.ok(schedule.every((q) => q.gas <= limits.gas && q.signedBytes <= limits.signedBytes));
  assert.equal(quote(16, 25), null);
  assert.throws(() => scheduleRecoveryRuns(spans.length, (from, end) => from === 23 && end === 24 ? null : quote(from, end)), /indivisible run/);
  assert.ok(quoteRecovery({ ...shape, operations: 8 }, calibration, limits, true));
  assert.equal(quoteRecovery({ ...shape, operations: 9 }, calibration, limits, true), null);
  assert.equal(quoteRecovery({ ...shape, operations: 8, pages: 33 }, calibration, limits, true), null);
  assert.equal(quoteRecovery({ ...shape, operations: 8, receiptBytes: 65_537 }, calibration, limits, true), null);
  const max = quoteRecovery({ ...shape, operations: 8 }, calibration, limits, true)!;
  const exact = { ...limits, signedBytes: max.signedBytes, calldataBytes: max.shape.calldataBytes, gas: max.gas, maxTransactionFee: max.fee };
  assert.ok(quoteRecovery(max.shape, calibration, exact, true));
  assert.equal(quoteRecovery(max.shape, calibration, { ...exact, signedBytes: max.signedBytes - 1 }, true), null);
  assert.equal(quoteRecovery(max.shape, calibration, { ...exact, calldataBytes: max.shape.calldataBytes - 1 }, true), null);
  assert.equal(quoteRecovery(max.shape, calibration, { ...exact, gas: max.gas - 1n }, true), null);
  assert.equal(quoteRecovery(max.shape, calibration, { ...exact, maxTransactionFee: max.fee - 1n }, true), null);
  const over24M = { ...calibration, ranges: calibration.ranges.map((range) => ({ ...range, execution: 20_000_000n })) };
  assert.equal(quoteRecovery(max.shape, over24M, { ...limits, gas: 40_000_000n }, true), null);
});

test('ERC20 uses net progress and reserves the larger route plus bounded attempts at the fee ceiling', () => {
  const backlog: RecoveryBacklog = { signedStart: 10n, observed: 7n, duringProgress: 1n, peakSeals: 1n, elapsedMs: 1000n,
    receiptP99Ms: 1_000n, advancePeakSeals: 2n, finalInclusionMs: 25n, finalPeakSeals: 1n, qualifiedForMs: 20_025n };
  const bounds = { progressWindowMs: 10_000n, maxRunCalls: 2, advanceWindowMs: 2_000n, feeWindowMs: 30_025n,
    ordinary: { gas: 1_500_000n, calldataBytes: 120_004, attemptsBeforeFallback: 2n, inclusionMs: 2_000n } };
  const calls = recoveryCatchUpCalls(9, backlog);
  assert.equal(calls, 10n);
  const reserve = (funds = limits, windows: Erc20SigningBounds | undefined = bounds, recoveryFee = 12_000_000n) =>
    erc20SigningReserve(recoveryFee, 2, calls, backlog, funds, windows);
  const exact = { ...limits, balance: 45_000_000n, feeBudget: 45_000_000n };
  assert.deepEqual(reserve(exact), { totalFee: 45_000_000n, priorAttempts: 2n });
  assert.equal(reserve(limits, bounds, 40_000_000n).totalFee, 70_000_000n);
  assert.throws(() => reserve({ ...exact, balance: exact.balance - 1n }), /free payer balance/);
  assert.throws(() => reserve({ ...exact, feeBudget: exact.feeBudget - 1n }), /authorized fee budget/);
  assert.throws(() => reserve({ ...limits, maxFeePerGas: 0n }), /fee limits/);
  assert.throws(() => erc20SigningReserve(1n, 2, calls, backlog, limits), /fee or inclusion windows/);
  assert.throws(() => reserve(limits, { ...bounds, maxRunCalls: 1 }), /Run schedule exceeds/);
  assert.throws(() => reserve(limits, { ...bounds, advanceWindowMs: 999n }), /fee or inclusion windows/);
  assert.throws(() => reserve(limits, { ...bounds, feeWindowMs: 30_024n }), /signing horizon/);
  assert.throws(() => reserve(limits, { ...bounds, ordinary: { ...bounds.ordinary, attemptsBeforeFallback: 0n } }), /ordinary retry window/);
  assert.throws(() => reserve(limits, { ...bounds, ordinary: { ...bounds.ordinary, gas: 24_000_001n } }), /ordinary call is outside/);
  assert.throws(() => recoveryCatchUpCalls(2, backlog), /catch-up rate/);
  assert.throws(() => recoveryCatchUpCalls(9, { ...backlog, peakSeals: 5n }), /catch-up rate/);
  assert.throws(() => recoveryCatchUpCalls(9, { ...backlog, finalPeakSeals: 2n }), /final inclusion window/);
  assert.throws(() => recoveryCatchUpCalls(9, { ...backlog, qualifiedForMs: 10_024n }), /catch-up horizon/);
});

test('shared ERC20 payer ceilings select the same envelope and route as Rust', () => {
  const vector = JSON.parse(readFileSync(new URL('../../../../tests/erc20-admission/payer-limits.json', import.meta.url), 'utf8'));
  const payer = { ...limits, worstCaseEnvelope: false, chainId: BigInt(vector.chainId), maxNonce: BigInt(vector.maxNonce),
    maxFeePerGas: BigInt(vector.maxFeePerGas), maxPriorityFeePerGas: BigInt(vector.maxPriorityFeePerGas) };
  assert.equal(quoteErc20Call(vector.ordinary.calldataBytes, BigInt(vector.ordinary.gas), payer)?.signedBytes, vector.ordinary.signedBytes);
  for (const row of vector.cases) {
    const capped = { ...payer, signedBytes: row.signedBytes, gas: BigInt(row.gas) };
    const fits = (call: typeof vector.ordinary) => quoteErc20Call(call.calldataBytes, BigInt(call.gas), capped) !== null;
    const route = !fits(vector.recovery) ? 'refused' : fits(vector.ordinary) ? 'ordinary' : 'continuation';
    assert.equal(route, row.route);
  }
});
