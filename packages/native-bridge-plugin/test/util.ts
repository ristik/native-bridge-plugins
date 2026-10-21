import assert from 'node:assert/strict';

import { NativeError, type NativeReason } from '../src/errors.js';

/** Assert that `p` rejects with exactly the named sentinel (exact error identity). */
export async function rejects(p: Promise<unknown>, reason: NativeReason, msg?: string): Promise<void> {
  try {
    await p;
  } catch (e) {
    if (e instanceof NativeError) {
      assert.equal(e.reason, reason, msg);
      return;
    }
    assert.fail(`${msg ?? ''} expected ${reason}, got non-native error: ${String(e)}`);
  }
  assert.fail(`${msg ?? ''} expected ${reason}, but it resolved`);
}

/** Assert that a synchronous call throws exactly the named sentinel. */
export function throwsReason(f: () => unknown, reason: NativeReason, msg?: string): void {
  try {
    f();
  } catch (e) {
    if (e instanceof NativeError) {
      assert.equal(e.reason, reason, msg);
      return;
    }
    assert.fail(`${msg ?? ''} expected ${reason}, got ${String(e)}`);
  }
  assert.fail(`${msg ?? ''} expected ${reason}, but it returned`);
}

/** The largest history whose best-case envelope plus the burn margin fits the ingress bound (the burn preflight's only refusal). */
export async function envelopeEdge(cfgLen: number, policyLen: number, leaves: number): Promise<number> {
  const { projectedGate } = await import('../src/gas.js');
  const { BURN_HISTORY_BYTES } = await import('../src/proof.js');
  const { MAX_ENVELOPE_BYTES } = await import('../src/limits.js');
  const fits = (h: number): boolean => projectedGate(cfgLen, policyLen, leaves, h).envelopeBytes + BURN_HISTORY_BYTES <= MAX_ENVELOPE_BYTES;
  let lo = 0, hi = MAX_ENVELOPE_BYTES;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (fits(mid)) lo = mid; else hi = mid - 1;
  }
  return lo;
}
