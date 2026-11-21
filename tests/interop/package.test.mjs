import test from 'node:test';
import assert from 'node:assert/strict';
// Removing Node globals before import catches accidental host dependencies in the package root (the shared bytes, errors and trust
// input of the native bridge v2 plug-in; the protocol 7 facade was removed, bft-core#1106).
test('the package root loads without Node process/Buffer and exports the trust input', async () => {
  const saved = {process: globalThis.process, Buffer: globalThis.Buffer};
  try {
    globalThis.process = undefined;
    globalThis.Buffer = undefined;
    const p = await import('../../packages/native-bridge-plugin/lib/index.js');
    for (const name of ['TrustInput', 'NativeError', 'withTrustRefresh', 'needsNewerEntry', 'concat', 'toHex']) {
      assert.equal(typeof p[name], 'function', name);
    }
    assert.equal(p.NATIVE_BRIDGE_PROTO_VERSION, undefined, 'no protocol 7 export remains');
  } finally {
    Object.assign(globalThis, saved);
  }
});

test('the nb2 entry is protocol 10', async () => {
  const p = await import('../../packages/native-bridge-plugin/lib/nb2/index.js');
  assert.equal(p.NATIVE_BRIDGE_PROTO_VERSION, 10);
  assert.equal(typeof p.NativeBridgeV2, 'function');
});
