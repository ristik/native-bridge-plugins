import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { RootTrustBaseV2 } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseBundle } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseBundle.js';

import { certificateFailure, TrustInput } from '../src/trust.js';
import { rejects } from './util.js';
import { buildToken, makeRoot, makeUc, makeWorld, nextEpoch, spec, successorEntry, type Root } from './world.js';

const ucOf = (r: Root, signers: number, extra: Parameters<typeof makeUc>[1]['extra'] = undefined, rootEpoch = 2n, round = 200n) =>
  makeUc(r, { partition: 1, conf: new Uint8Array(32).fill(1), epochIr: 1n, rootEpoch, round, timestamp: 1_700_000_000n, stateHash: new Uint8Array(32), blockHash: new Uint8Array(32).fill(2), signers, extra });

test('embedded UC rule is the SDK weighted quorum (unit weights: three of four)', async () => {
  const r = await makeRoot(2, 4, 10);
  await r.trust.verifyEmbeddedUc(await ucOf(r, 3));
  await rejects(r.trust.verifyEmbeddedUc(await ucOf(r, 2)), 'ErrQuorumNotMet');
});

test('weighted committee: the threshold is floor(2W/3)+1 of the weights, not a member count', async () => {
  // weights 98, 1, 1 in member order: W = 100, threshold 67; the heavy member alone is a quorum, the two light ones are not
  const r = await makeRoot(2, 3, 50, [98, 1, 1]);
  await r.trust.verifyEmbeddedUc(await ucOf(r, 1));
  await rejects(r.trust.verifyEmbeddedUc(await ucOf(r, 0, r.signers.slice(1))), 'ErrQuorumNotMet');
});

test('embedded UC rejects false root and wrong network like the SDK', async () => {
  const r = await makeRoot(2, 4, 10);
  const spec4 = { partition: 1, conf: new Uint8Array(32).fill(1), epochIr: 1n, rootEpoch: 2n, round: 200n, timestamp: 1_700_000_000n, stateHash: new Uint8Array(32), blockHash: new Uint8Array(32).fill(2), signers: 4 };
  await rejects(r.trust.verifyEmbeddedUc(await makeUc(r, { ...spec4, sealHash: new Uint8Array(32).fill(7) })), 'ErrSealRoot');
  await rejects(r.trust.verifyEmbeddedUc(await makeUc(r, { ...spec4, network: 4 })), 'ErrSealNetwork');
});

test('an unknown or wrong-key signer counts zero: it neither fails an honest quorum nor makes up for a missing signer', async () => {
  const r = await makeRoot(2, 4, 10);
  const { signer } = await import('./world.js');
  await r.trust.verifyEmbeddedUc(await ucOf(r, 3, [['stranger', signer(250)]]));
  await rejects(r.trust.verifyEmbeddedUc(await ucOf(r, 2, [['stranger', signer(250)]])), 'ErrQuorumNotMet');
  // an EMPTY signer ID is refused by the native seal validation, even with a real signature behind it
  await rejects(r.trust.verifyEmbeddedUc(await ucOf(r, 3, [['', signer(250)]])), 'ErrCertStructure');
  await rejects(r.trust.verifyEmbeddedUc(await ucOf(r, 2, [[r.signers[2][0], signer(251)]])), 'ErrQuorumNotMet');
});

test('each seal is verified under its own epoch: newer is retryable, before the genesis or outside the interval is invalid', async () => {
  const r = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r, 1000n, 4, 30);
  // r holds epoch 2 only
  await rejects(r.trust.verifyEmbeddedUc(await ucOf(r3, 4, undefined, 3n, 1500n)), 'ErrNoEntryForEpoch');
  await rejects(r.trust.verifyEmbeddedUc(await ucOf(r, 4, undefined, 1n)), 'ErrSealEpoch');
  // r3 holds epochs 2 and 3: epoch 2 ends where epoch 3 starts
  await r3.trust.verifyEmbeddedUc(await ucOf(r3, 3, undefined, 3n, 1500n));
  await r3.trust.verifyEmbeddedUc(await ucOf(r, 3, undefined, 2n, 999n));
  await rejects(r3.trust.verifyEmbeddedUc(await ucOf(r, 4, undefined, 2n, 1000n)), 'ErrSealEpoch');
  await rejects(r3.trust.verifyEmbeddedUc(await ucOf(r3, 4, undefined, 3n, 999n)), 'ErrSealEpoch');
});

test("installation: the bundle's genesis must be the pin; a broken or incomplete bundle is refused", async () => {
  const r = await makeRoot(2, 4, 10);
  await rejects(TrustInput.fromBundle(r.bundle, new Uint8Array(32)), 'ErrTrustBaseDigest');
  await rejects(TrustInput.fromBundle(Uint8Array.of(...r.bundle, 0), r.pin), 'ErrTrustBase');
  const r3 = await nextEpoch(r, 1000n, 4, 30);
  // a successor witnessed by a committee other than its predecessor's: the chain does not authenticate
  const forged = await TrustBaseBundle.encode([r.entries[0], await successorEntry(r, 1000n, 4, 31, undefined, r3.signers)].map((e) => RootTrustBaseV2.decode(e)));
  await rejects(TrustInput.fromBundle(forged, r.pin), 'ErrTrustBase');
  assert.equal((await TrustInput.fromBundle(r3.bundle, r.pin)).history.tip?.epoch, 3n);
});

test('a foreign epoch inside a lock proof is retryable end to end', async () => {
  const w = await makeWorld();
  const { lockParts } = await import('./world.js');
  const s = spec(1);
  const p = await lockParts(w, s);
  p.uc = await makeUc(w.evm, { ...p.ucSpec, rootEpoch: 9n });
  await rejects(w.bridge.verifyNativeToken((await buildToken(w, s, [], 1_700_000_040n, 1_700_000_900n, {}, p)).token, 'receipt'), 'ErrNoEntryForEpoch');
});

test('the shared dev trust-base fixture (the same bytes as both SDKs) installs under its pin, epochs 1 to 4', async () => {
  const dir = new URL('../../../tests/interop/utb-dev/', import.meta.url);
  const bundle = new Uint8Array(readFileSync(new URL('bft-trustbase.dev.bundle.cbor', dir)));
  const pin = new Uint8Array(Buffer.from(readFileSync(new URL('bft-trustbase.dev.genesis.entryid', dir), 'utf8').trim(), 'hex'));
  const t = await TrustInput.fromBundle(bundle, pin);
  assert.deepEqual(t.id, pin);
  assert.equal(t.network.id, 3);
  assert.equal(t.history.entries[0].epoch, 1n);
  assert.equal(t.history.tip?.epoch, 4n);
  // epoch 2's committee is weighted (1, 2, 3, 4): W = 10, threshold 7
  assert.equal(t.history.entryForEpoch(2n)!.quorumThreshold, 7n);
});

test("the SDK's own trace names the missing epoch (retryable) and, for an epoch before the genesis, the final seal epoch failure", async () => {
  const { UnicityCertificateVerifier } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/verification/UnicityCertificateVerifier.js');
  const { UnicitySealQuorumSignaturesVerificationRule } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js');
  const { Secp256k1SignatureVerifier } = await import('@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Secp256k1SignatureVerifier.js');
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const held = await TrustInput.fromBundle(r2.bundle, r2.pin);
  const verifier = new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier(), undefined, { maxSignatures: 16 }));
  const trace = async (uc: Awaited<ReturnType<typeof ucOf>>) => verifier.verifyCertificate(held.history, uc, { partitionId: uc.unicityTreeCertificate.partitionIdentifier });
  assert.equal(certificateFailure(await trace(await ucOf(r3, 3, undefined, 3n, 1500n))), 'ErrNoEntryForEpoch');
  assert.equal(certificateFailure(await trace(await ucOf(r2, 3, undefined, 1n, 200n))), 'ErrSealEpoch');
});
