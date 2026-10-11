import assert from 'node:assert/strict';
import { test } from 'node:test';
import { minimalGas } from './gassearch.js';

const needs = (m: bigint) => async (g: bigint): Promise<boolean> => g >= m;

test('finds the exact minimum for any threshold in range', async () => {
  for (const m of [1_001n, 1_002n, 1_500n, 1_999n, 2_000n, 3_136_986n % 2_000n + 1_001n]) {
    const r = await minimalGas(1_000n, 2_000n, needs(m));
    assert.equal(r.min, m);
    assert.ok(r.calls <= 14);
  }
});
test('M succeeds and M-1 fails (the property the gas row sends)', async () => {
  const m = 3_141_592n; const ok = needs(m);
  const r = await minimalGas(3_000_000n, 3_165_000n, ok);
  assert.equal(await ok(r.min), true);
  assert.equal(await ok(r.min - 1n), false);
});
test('a lower bound that succeeds, an upper bound that fails or an empty range is an error, not a result', async () => {
  await assert.rejects(minimalGas(1_000n, 2_000n, needs(500n)), /already succeeds/);
  await assert.rejects(minimalGas(1_000n, 2_000n, needs(2_500n)), /does not succeed/);
  await assert.rejects(minimalGas(2_000n, 2_000n, needs(1_500n)), /not below/);
});
test('the search stays logarithmic at the redemption scale', async () => {
  const r = await minimalGas(3_000_000n, 3_200_000n, needs(3_112_345n));
  assert.equal(r.min, 3_112_345n);
  assert.ok(r.calls <= 20);
});

import { gasOneHolds, type GasOneFacts } from './gassearch.js';
// the one B3 evidence run (14:31-14:47, rows-evidence.json): M-1 failed, status 0x0, 3,075,844 of 3,122,231 gas used, anchors in window, M searched with eth_call, high send status 0x1
// (the credits were not recorded in that run's evidence; the row now asserts them)
const run: GasOneFacts = { lowStatus: '0x0', lowAnchorsInWindowAtExecution: true, creditedLow: 0n, mSucceeds: true, mMinusOneFails: true, highStatus: '0x1', creditedHigh: 10n ** 18n, amount: 10n ** 18n };
test('gas-1 verdict: the recorded run holds, each missing condition fails it', () => {
  assert.equal(gasOneHolds(run), true);
  for (const bad of [{ lowStatus: '0x1' }, { lowAnchorsInWindowAtExecution: false }, { creditedLow: 1n }, { mSucceeds: false }, { mMinusOneFails: false }, { highStatus: '0x0' }, { creditedHigh: 0n }] as Partial<GasOneFacts>[]) {
    assert.equal(gasOneHolds({ ...run, ...bad }), false, JSON.stringify(bad, (_k, v) => (typeof v === 'bigint' ? String(v) : v)));
  }
});
