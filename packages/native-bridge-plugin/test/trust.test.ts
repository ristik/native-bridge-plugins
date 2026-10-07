import assert from 'node:assert/strict';
import { test } from 'node:test';

import { checkFixedProfile, TrustInput } from '../src/trust.js';
import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { rejects, throwsReason } from './util.js';
import { buildToken, makeRoot, makeUc, makeWorld, sha, spec, text } from './world.js';

const ucOf = (r: ReturnType<typeof makeRoot>, signers: number, extra: Parameters<typeof makeUc>[1]['extra'] = undefined) =>
  makeUc(r, { partition: 1, conf: new Uint8Array(32).fill(1), epochIr: 1n, rootEpoch: 2n, round: 200n, timestamp: 1n, stateHash: new Uint8Array(32), blockHash: null, signers, extra });

test('embedded UC rule is the SDK count quorum', async () => {
  const r = makeRoot(2, 4, 10);
  await r.trust.verifyEmbeddedUc(await ucOf(r, 3));
  await rejects(r.trust.verifyEmbeddedUc(await ucOf(r, 2)), 'ErrQuorumNotMet');
});

test('embedded UC rejects false root and wrong network like the SDK', async () => {
  const r = makeRoot(2, 4, 10);
  const bad = await makeUc(r, { partition: 1, conf: new Uint8Array(32).fill(1), epochIr: 1n, rootEpoch: 2n, round: 200n, timestamp: 1n, stateHash: new Uint8Array(32), blockHash: null, signers: 4, sealHash: new Uint8Array(32).fill(7) });
  await rejects(r.trust.verifyEmbeddedUc(bad), 'ErrSealRoot');
  const net = await makeUc(r, { partition: 1, conf: new Uint8Array(32).fill(1), epochIr: 1n, rootEpoch: 2n, round: 200n, timestamp: 1n, stateHash: new Uint8Array(32), blockHash: null, signers: 4, network: 4 });
  await rejects(r.trust.verifyEmbeddedUc(net), 'ErrSealNetwork');
});

test('an unknown or wrong-key signer adds nothing', async () => {
  const r = makeRoot(2, 4, 10);
  const { signer } = await import('./world.js');
  const uc = await ucOf(r, 2, [['stranger', signer(250)], [r.signers[2][0], signer(251)]]);
  await rejects(r.trust.verifyEmbeddedUc(uc), 'ErrQuorumNotMet');
});

const doc = (stakes: number[], th: number, version = '1'): Uint8Array => {
  const nodes = stakes.map((s, i) => `{"nodeId":"n${i}","sigKey":"${Buffer.from(makeRoot(2, 1, 40 + i).signers[0][1].publicKey).toString('hex')}","stake":"${s}"}`);
  return text(`{"changeRecordHash":null,"epoch":"2","epochStartRound":"1","networkId":3,"previousEntryHash":null,"quorumThreshold":"${th}","rootNodes":[${nodes.join(',')}],"signatures":{},"stateHash":"","version":"${version}"}`);
};

const install = (d: Uint8Array): TrustInput => TrustInput.fromJson(d, sha(d));

test('non-unit or non-matching configurations are rejected at installation', () => {
  install(doc([1, 1, 1, 1], 3));
  install(doc([1], 1));
  install(doc([1, 1, 1, 1, 1, 1, 1], 5));
  throwsReason(() => install(doc([98, 1, 1], 3)), 'ErrUnsupportedTrustBase', 'heavy validator never flattened');
  throwsReason(() => install(doc([1, 1, 1, 1], 2)), 'ErrUnsupportedTrustBase');
  throwsReason(() => install(doc([1, 1, 1, 1], 4)), 'ErrUnsupportedTrustBase');
  assert.ok(checkFixedProfile);
  void RootTrustBase;
});

test('installed document must hash to the pin and parse', () => {
  const r = makeRoot(2, 4, 10);
  TrustInput.fromJson(r.doc, sha(r.doc));
  throwsReason(() => TrustInput.fromJson(r.doc, new Uint8Array(32)), 'ErrTrustBaseDigest');
  const spaced = Uint8Array.of(...r.doc, 10);
  throwsReason(() => TrustInput.fromJson(spaced, sha(r.doc)), 'ErrTrustBaseDigest');
  const garbage = text('{not json');
  throwsReason(() => TrustInput.fromJson(garbage, sha(garbage)), 'ErrTrustBase');
});

test('the SDK base round trips to the pinned document bytes (the id hashes B)', () => {
  const r = makeRoot(2, 4, 10);
  const b = new TextEncoder().encode(JSON.stringify(RootTrustBase.fromJSON(JSON.parse(new TextDecoder().decode(r.doc))).toJSON()));
  assert.deepEqual(b, r.doc, 'the test document is already in the SDK emitted order, so id = SHA256(B)');
  assert.deepEqual(r.trust.id, sha(b));
});

test('a foreign epoch inside a lock proof is rejected end to end', async () => {
  const w = makeWorld();
  const { lockParts } = await import('./world.js');
  const s = spec(1);
  const p = await lockParts(w, s);
  p.uc = await makeUc(w.evm, { ...p.ucSpec, rootEpoch: 9n });
  await rejects(w.bridge.verifyNativeToken((await buildToken(w, s, [], 1n, 2n, {}, p)).token, 'receipt'), 'ErrEpochMismatch');
});

test('DEFERRED: weighted acceptance, historical/current committees, rotation, seal parity', { skip: 'common SDK trust-base work (bft-core#421); unsupported in the current bridge profile' }, () => undefined);

test('the published SDK trust-base fixture installs, and its digest is the trustBaseId', async () => {
  const { readFileSync } = await import('node:fs');
  const file = new URL('../../../protocol/vectors/config/sdk-root-trust-base.json', import.meta.url);
  const bytes = new Uint8Array(readFileSync(file));
  assert.equal(bytes.length, 524);
  const pin = 'e5454ae4fe566b05dab8c1b15c88a05356b8816b1cd66a2b7adcce184af27fb5';
  const t = TrustInput.fromJson(bytes, Buffer.from(pin, 'hex'));
  assert.equal(Buffer.from(t.id).toString('hex'), pin);
  assert.equal(t.base.networkId.id, 3);
  assert.equal(t.base.epoch, 1n);
  assert.equal(t.base.epochStartRound, 0n);
  // The same bytes re-emitted by the SDK are the same bytes (id = SHA256(B)).
  const b = new TextEncoder().encode(JSON.stringify(t.base.toJSON()));
  assert.deepEqual(b, bytes);
});
