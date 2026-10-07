import assert from 'node:assert/strict';
import { test } from 'node:test';

import { InclusionCertificate } from '@unicitylabs/state-transition-sdk/lib/api/InclusionCertificate.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { DataHasherFactory } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasherFactory.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { NodeDataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/NodeDataHasher.js';
import { SparseMerkleTree } from '@unicitylabs/state-transition-sdk/lib/smt/radix/SparseMerkleTree.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';

import { checkAnchor, checkPolicy, decodeEnvelope, encodeEnvelope, parseInputRecord } from '../src/envelope.js';
import { buildReturnProof, refreshToken } from '../src/proof.js';
import { DeploymentRegistry } from '../src/deployment.js';
import { rejects, throwsReason } from './util.js';
import { AGG_PARTITION, buildToken, burnStep, makeUc, makeWorld, sha, spec, txStep, type World } from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;
const ret = (w: World) => buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);

test('return envelope round trips and passes policy and anchor checks', async () => {
  const w = makeWorld();
  const { envelope, encoded, verified } = await buildReturnProof(w.bridge, (await ret(w)).token);
  assert.deepEqual(decodeEnvelope(encoded), envelope);
  assert.equal(envelope.leafProofs.length, 3);
  checkPolicy(w.dep.cfg, envelope, 3);
  const ir = checkAnchor(envelope.anchors[0], verified.outcome.leaves.map((l) => l.referenceTime));
  assert.equal(ir.timestamp, UC_TS);
});

test('envelope framing is canonical', async () => {
  const w = makeWorld();
  const { envelope, encoded } = await buildReturnProof(w.bridge, (await ret(w)).token);
  throwsReason(() => decodeEnvelope(Uint8Array.of(...encoded, ...new Uint8Array(32))), 'ErrABIFraming', 'trailing word');
  throwsReason(() => decodeEnvelope(Uint8Array.of(...encoded, 0)), 'ErrABIFraming', 'unaligned');
  const dirty = encoded.slice();
  dirty[4 * 32 + 32 + envelope.policyBody.length] = 1;
  throwsReason(() => decodeEnvelope(dirty), 'ErrABIFraming', 'dirty padding');
  assert.deepEqual(encodeEnvelope(envelope), encoded);
});

test('policy check names each tuple mismatch', async () => {
  const w = makeWorld();
  const { envelope } = await buildReturnProof(w.bridge, (await ret(w)).token);
  const cfg = w.dep.cfg;
  const clone = () => structuredClone(envelope);
  const flipBody = clone();
  flipBody.policyBody[3] ^= 1;
  throwsReason(() => checkPolicy(cfg, flipBody, 3), 'ErrPolicyHash');
  const two = clone();
  two.anchors.push(two.anchors[0]);
  throwsReason(() => checkPolicy(cfg, two, 3), 'ErrPolicyAnchors');
  const shard = clone();
  shard.anchors[0].shard = Uint8Array.of(0x40);
  throwsReason(() => checkPolicy(cfg, shard, 3), 'ErrPolicyTuple');
  const part = clone();
  part.anchors[0].partition += 1;
  throwsReason(() => checkPolicy(cfg, part, 3), 'ErrPolicyTuple');
  throwsReason(() => checkPolicy(cfg, envelope, 2), 'ErrPolicyLeafCount');
  const idx = clone();
  idx.leafProofs[1].anchorIndex = 1;
  throwsReason(() => checkPolicy(cfg, idx, 3), 'ErrPolicyLeafIndex');
});

test('input record opening is bound to the anchor', async () => {
  const w = makeWorld();
  const { envelope, verified } = await buildReturnProof(w.bridge, (await ret(w)).token);
  const times = verified.outcome.leaves.map((l) => l.referenceTime);
  const a = structuredClone(envelope.anchors[0]);
  a.inputRecord[10] ^= 1;
  throwsReason(() => checkAnchor(a, times), 'ErrInputRecordMismatch', 'false opening');
  const b = structuredClone(envelope.anchors[0]);
  b.expectedStateRoot[0] ^= 1;
  throwsReason(() => checkAnchor(b, times), 'ErrInputRecordMismatch', 'state root');
  throwsReason(() => checkAnchor(envelope.anchors[0], [UC_TS + 1n]), 'ErrReferenceTimeFuture');
  checkAnchor(envelope.anchors[0], [UC_TS]);
  throwsReason(() => parseInputRecord(C.encodeTag(39002, C.encodeArray(C.encodeUnsignedInteger(1)))), 'ErrShape');
  throwsReason(() => parseInputRecord(new Uint8Array(1025)), 'ErrInputTooLarge');
});

async function freshProofs(w: World, out: Awaited<ReturnType<typeof ret>>, extra: number, ts: bigint): Promise<InclusionProof[]> {
  const old = [out.token.genesis, ...out.token.transactions].map((c) => c.inclusionProof);
  const leaves = out.leaves.map(([sid, v]) => [sid, v] as [Uint8Array, Uint8Array]);
  for (let i = 0; i < extra; i++) leaves.push([sha(Uint8Array.of(i, 9)), sha(Uint8Array.of(i, 10))]);
  const smt = new SparseMerkleTree(new DataHasherFactory(HashAlgorithm.SHA256, NodeDataHasher));
  for (const [k, v] of leaves) await smt.addLeaf(k, v);
  const root = await smt.calculateRoot();
  const uc = await makeUc(w.agg, { partition: AGG_PARTITION, conf: w.aggConf, epochIr: 1n, rootEpoch: 2n, round: 950n, timestamp: ts, stateHash: root.hash.data, blockHash: null, signers: 4 });
  return old.map((o, i) => new InclusionProof(o.certificationData, o.referenceTime, InclusionCertificate.create(root, leaves[i][0]), uc));
}

test('refresh to a later anchor preserves t and J and verifies', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const refreshed = await refreshToken(out.token, await freshProofs(w, out, 5, UC_TS + 5000n));
  assert.deepEqual(refreshed.genesis.justification, out.token.genesis.justification);
  assert.equal(refreshed.genesis.referenceTime, T0);
  const v = await w.bridge.verifyNativeToken(refreshed, 'return');
  assert.equal(v.outcome.leaves[1].referenceTime, T0 + 10n);
  const { envelope } = await buildReturnProof(w.bridge, refreshed);
  assert.equal(parseInputRecord(envelope.anchors[0].inputRecord).timestamp, UC_TS + 5000n);
});

test('refresh changing t or certification data is rejected', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const f1 = await freshProofs(w, out, 1, UC_TS + 10n);
  f1[1] = new InclusionProof(f1[1].certificationData, f1[1].referenceTime + 1n, f1[1].inclusionCertificate, f1[1].unicityCertificate);
  await rejects(refreshToken(out.token, f1), 'ErrRefreshMismatch');
  const f2 = await freshProofs(w, out, 1, UC_TS + 10n);
  f2[0] = new InclusionProof(f2[1].certificationData, f2[0].referenceTime, f2[0].inclusionCertificate, f2[0].unicityCertificate);
  await rejects(refreshToken(out.token, f2), 'ErrRefreshMismatch');
  await rejects(refreshToken(out.token, f2.slice(0, 2)), 'ErrRefreshMismatch');
});

test('proofs at different roots cannot be assembled into one return', async () => {
  const w = makeWorld();
  const a = await ret(w);
  const b = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS + 5n);
  const bytes = a.token.toCBOR();
  void bytes;
  const mixed = await Token.fromCBOR(
    C.encodeTag(39040, C.encodeArray(C.encodeUnsignedInteger(2), a.token.genesis.toCBOR(), C.encodeArray(...b.token.transactions.map((t) => t.toCBOR())))),
  );
  await rejects(buildReturnProof(w.bridge, mixed), 'ErrPolicyAnchors');
  void CborDeserializer;
});

async function aggErr(f: (o: { uc: Parameters<typeof makeUc>[1] }) => void): Promise<unknown> {
  const w = makeWorld();
  const out = await buildToken(w, spec(1), [], T0, UC_TS);
  const g = out.token.genesis;
  const uc = { partition: AGG_PARTITION, conf: w.aggConf, epochIr: 1n, rootEpoch: 2n, round: 900n, timestamp: UC_TS, stateHash: g.inclusionProof.unicityCertificate.inputRecord.hash, blockHash: null, signers: 4 } as Parameters<typeof makeUc>[1];
  const o = { uc };
  f(o);
  const proof = new InclusionProof(g.inclusionProof.certificationData, g.inclusionProof.referenceTime, g.inclusionProof.inclusionCertificate, await makeUc(w.agg, o.uc));
  const bytes = C.encodeTag(39040, C.encodeArray(C.encodeUnsignedInteger(2), C.encodeArray(CborDeserializer.decodeArray(g.toCBOR(), 2)[0], proof.toCBOR()), C.encodeArray()));
  return w.bridge.verifyNativeToken(await Token.fromCBOR(bytes), 'receipt');
}

test('aggregator certificates are checked against the pinned policy and the SDK quorum', async () => {
  await rejects(aggErr((o) => void (o.uc.partition = 9)), 'ErrNotAdmitted');
  await rejects(aggErr((o) => void (o.uc.conf = new Uint8Array(32).fill(9))), 'ErrNotAdmitted');
  await rejects(aggErr((o) => void (o.uc.signers = 2)), 'ErrQuorumNotMet');
  await rejects(aggErr((o) => void (o.uc.stateHash = new Uint8Array(32).fill(0x13))), 'ErrPathInvalid');
  await rejects(aggErr((o) => void (o.uc.rootEpoch = 3n)), 'ErrEpochMismatch');
});

test('deployment registry rejects duplicates', () => {
  const w = makeWorld();
  assert.throws(() => new DeploymentRegistry([w.dep, w.dep]), /ErrAmbiguousDeployment/);
});
