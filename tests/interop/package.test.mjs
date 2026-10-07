import test from 'node:test';
import assert from 'node:assert/strict';
// Removing Node globals before import catches accidental host dependencies in
// the facade's browser entry point. PR3 extends this to all verifier exports.
test('facade and every verifier export load without Node process/Buffer', async () => {
  const saved = {process: globalThis.process, Buffer: globalThis.Buffer};
  try {
    globalThis.process = undefined;
    globalThis.Buffer = undefined;
    const p = await import('../../packages/native-bridge-plugin/lib/index.js');
    assert.equal(p.NATIVE_BRIDGE_PROTO_VERSION, 2);
    assert.equal(p.NATIVE_BRIDGE_FAMILY, 'unicity-native');
    assert.equal(p.SDK_VERSION, '3.0.1');
    for (const name of ['verifyNativeToken', 'NativeBridge', 'NativeLockJustificationVerifier', 'BridgedTokenIssuancePolicy',
      'NativeBridgeTokenVerifier', 'TrustInput', 'loadManifests', 'buildReturnProof', 'refreshToken', 'createNativeBridgePlugin',
      'bridgeTokenPlugin', 'mintBridgedToken', 'burnForReturn', 'recoverPendingBurns', 'claim', 'verifyUnlock']) {
      assert.equal(typeof p[name], 'function', name);
    }
  } finally {
    Object.assign(globalThis, saved);
  }
});
