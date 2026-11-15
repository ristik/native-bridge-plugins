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
