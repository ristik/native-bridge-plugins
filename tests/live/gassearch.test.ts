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
