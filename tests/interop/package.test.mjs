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

test('the JavaScript origin setter requires both limits as bigints', async () => {
  const { readFile } = await import('node:fs/promises');
  const p = await import('../../packages/native-bridge-plugin/lib/nb2/index.js');
  const vectors = new URL('../../protocol/vectors/nb2-continuation-v1.1/', import.meta.url);
  const gamma = await readFile(new URL('gamma.bin', vectors));
  const cfg = p.decodeConfig(gamma, p.PRODUCTION_PARAMS);
  const history = await p.TrustInput.fromBundle(await readFile(new URL('transcripts/root/utb.cbor', vectors)), cfg.rootGenesis);
  for (const value of [undefined, null, {}, { usableEpoch: 2n }, { rootRound: 10_000n },
    { usableEpoch: 2, rootRound: 10_000n }, { usableEpoch: 2n, rootRound: 10_000 }]) {
    assert.throws(() => history.withAuthenticatedOrigin(value), { reason: 'ErrTrustBase' });
  }
  let reads = 0;
  const origin = history.withAuthenticatedOrigin({
    get usableEpoch() { reads++; return 2n; },
    get rootRound() { reads++; return 10_000n; },
  }).origin;
  assert.equal(reads, 2);
  assert.deepEqual(origin, { usableEpoch: 2n, rootRound: 10_000n });
});

test('the authenticated genesis is isolated from the caller pin and returned IDs', async () => {
  const { readFile } = await import('node:fs/promises');
  const p = await import('../../packages/native-bridge-plugin/lib/nb2/index.js');
  const vectors = new URL('../../protocol/vectors/nb2-continuation-v1.1/', import.meta.url);
  const cfg = p.decodeConfig(await readFile(new URL('gamma.bin', vectors)), p.PRODUCTION_PARAMS);
  const bundle = await readFile(new URL('transcripts/root/utb.cbor', vectors));
  const callerPin = Buffer.from(cfg.rootGenesis);
  const otherGenesis = Uint8Array.from(cfg.rootGenesis);
  otherGenesis[0] ^= 0xff;
  const installing = p.TrustInput.fromBundle(bundle, callerPin);
  callerPin.set(otherGenesis);
  const history = await installing;
  callerPin.fill(0);
  history.id.set(otherGenesis);
  const trust = history.withAuthenticatedOrigin({ usableEpoch: 2n, rootRound: 10_000n });
  trust.id.set(otherGenesis);
  assert.deepEqual(trust.id, Uint8Array.from(cfg.rootGenesis));
  const { mint } = p.decodeToken(await readFile(new URL('transcripts/root/evidence.bin', vectors)));
  const { proof } = p.decodeReceiptBacking(mint.justification);
  await p.verifyEvmUc(trust, proof.uc, cfg);
  await assert.rejects(p.verifyEvmUc(trust, proof.uc, { ...cfg, rootGenesis: otherGenesis }), { reason: 'TrustInput' });
});
