import test from 'node:test';
import assert from 'node:assert/strict';
// Removing Node globals before import catches accidental host dependencies in
// the facade's browser entry point. PR3 extends this to all verifier exports.
test('facade loads without Node process/Buffer', async () => {
  const saved = {process: globalThis.process, Buffer: globalThis.Buffer};
  try {
    globalThis.process = undefined;
    globalThis.Buffer = undefined;
    const p = await import('../../packages/native-bridge-plugin/lib/index.js');
    assert.equal(p.NATIVE_BRIDGE_PROTO_VERSION, 2);
    assert.equal(p.NATIVE_BRIDGE_FAMILY, 'unicity-native');
    assert.equal(p.SDK_VERSION, '3.0.1');
    assert.equal('verifyNativeToken' in p, false);
  } finally {
    Object.assign(globalThis, saved);
  }
});
