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

import { checkAnchors, checkPolicyBody, decodeEnvelope, encodeEnvelope, parseInputRecord, planAnchors } from '../src/envelope.js';
import { computeGate, kernelRequestBytes, scanAnchor } from '../src/gas.js';
import { MAX_ANCHORS, MAX_LEAVES, TX_GAS_BUDGET } from '../src/limits.js';
import { buildReturnProof, leafRoutes, preflightBurn, refreshToken } from '../src/proof.js';
import { cfgBytes, shardId, shardRow } from '../src/profile.js';
import { buildNativeReturnProof, createNativeBridgePlugin, MAX_PROOF_ATTEMPTS } from '../src/wallet.js';
import { DeploymentRegistry } from '../src/deployment.js';
import { rejects, throwsReason } from './util.js';
import { AGG_PARTITION, buildToken, burnStep, makeUc, makeWorld, sha, spec, txStep, type World } from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;
const ret = (w: World) => buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);

test('return envelope round trips and passes policy, anchor and gate checks', async () => {
  const w = makeWorld();
  const { envelope, encoded, verified, gate } = await buildReturnProof(w.bridge, (await ret(w)).token);
  assert.deepEqual(decodeEnvelope(encoded), envelope);
  assert.equal(envelope.leafProofs.length, 3);
  assert.equal(envelope.anchors.length, 1, 'byte-identical certificates are one anchor');
  const sids = verified.outcome.leaves.map((l) => l.sid);
  const pol = checkPolicyBody(w.dep.cfg, envelope);
  const plan = planAnchors(pol, envelope, sids);
  assert.deepEqual(plan.leafAnchor, [0, 0, 0]);
  const ir = checkAnchors(envelope, plan, verified.outcome.leaves.map((l) => l.referenceTime));
  assert.equal(ir[0].timestamp, UC_TS);
  assert.ok(gate.total <= TX_GAS_BUDGET);
  assert.deepEqual(computeGate(encoded.length, kernelRequestBytes(cfgBytes(w.dep.cfg).length, envelope.history.length), envelope, pol), gate);
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

test('policy and anchor-table checks name each mismatch', async () => {
  const w = makeWorld();
  const { envelope, verified } = await buildReturnProof(w.bridge, (await ret(w)).token);
  const cfg = w.dep.cfg;
  const sids = verified.outcome.leaves.map((l) => l.sid);
  const clone = () => structuredClone(envelope);
  const plan = (e: typeof envelope, ids = sids) => planAnchors(checkPolicyBody(cfg, e), e, ids);
  const flipBody = clone();
  flipBody.policyBody[3] ^= 1;
  throwsReason(() => checkPolicyBody(cfg, flipBody), 'ErrPolicyHash');
  const none = clone();
  none.anchors = [];
  throwsReason(() => checkPolicyBody(cfg, none), 'ErrPolicyAnchors');
  const dup = clone();
  dup.anchors.push(structuredClone(dup.anchors[0]));
  throwsReason(() => plan(dup), 'ErrPolicyAnchors', 'identical UC bytes are one anchor, never two');
  const shard = clone();
  shard.anchors[0].shard = Uint8Array.of(0x40);
  throwsReason(() => plan(shard), 'ErrPolicyTuple', 'a shard of another topology');
  const part = clone();
  part.anchors[0].partition += 1;
  throwsReason(() => plan(part), 'ErrPolicyTuple');
  const conf = clone();
  conf.anchors[0].shardConfHash[0] ^= 1;
  throwsReason(() => plan(conf), 'ErrPolicyTuple');
  throwsReason(() => plan(envelope, sids.slice(0, 2)), 'ErrPolicyLeafCount');
  const idx = clone();
  idx.leafProofs[1].anchorIndex = 1;
  throwsReason(() => plan(idx), 'ErrPolicyLeafIndex', 'an index beyond the table');
  const unused = clone();
  const spare = structuredClone(unused.anchors[0]);
  spare.uc = Uint8Array.of(...spare.uc, 0);
  unused.anchors.push(spare);
  throwsReason(() => plan(unused), 'ErrPolicyAnchors', 'an anchor no leaf uses');
});

test('input record opening is bound to the anchor', async () => {
  const w = makeWorld();
  const { envelope, verified } = await buildReturnProof(w.bridge, (await ret(w)).token);
  const times = verified.outcome.leaves.map((l) => l.referenceTime);
  const one = { leafAnchor: [0, 0, 0] };
  const a = structuredClone(envelope);
  a.anchors[0].inputRecord[10] ^= 1;
  throwsReason(() => checkAnchors(a, one, times), 'ErrInputRecordMismatch', 'false opening');
  const b = structuredClone(envelope);
  b.anchors[0].expectedStateRoot[0] ^= 1;
  throwsReason(() => checkAnchors(b, one, times), 'ErrInputRecordMismatch', 'state root');
  throwsReason(() => checkAnchors(envelope, one, [UC_TS + 1n, UC_TS, UC_TS]), 'ErrReferenceTimeFuture');
  checkAnchors(envelope, one, [UC_TS, UC_TS, UC_TS]);
  throwsReason(() => parseInputRecord(C.encodeTag(39002, C.encodeArray(C.encodeUnsignedInteger(1)))), 'ErrShape');
  throwsReason(() => parseInputRecord(new Uint8Array(513)), 'ErrInputTooLarge');
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

test('distinct certificates are distinct anchors, up to the profile bound', async () => {
  const w = makeWorld();
  // genesis certified in one round, the transfers in another: two UCs, two anchors, first-use order
  const a = await ret(w);
  const b = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS + 5n);
  const mixed = await Token.fromCBOR(
    C.encodeTag(39040, C.encodeArray(C.encodeUnsignedInteger(2), a.token.genesis.toCBOR(), C.encodeArray(...b.token.transactions.map((t) => t.toCBOR())))),
  );
  const two = await buildReturnProof(w.bridge, mixed);
  assert.equal(two.envelope.anchors.length, 2);
  assert.deepEqual(two.envelope.leafProofs.map((l) => l.anchorIndex), [0, 1, 1]);
  assert.notDeepEqual(two.envelope.anchors[0].uc, two.envelope.anchors[1].uc);
  // one certificate per leaf: three anchors are over the bound, refused, never truncated
  assert.equal(MAX_ANCHORS, 2);
  const three = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS, { ucRound: (i) => 900n + BigInt(i) });
  assert.equal(three.ucs.length, 3);
  await rejects(buildReturnProof(w.bridge, three.token), 'ErrPolicyAnchors');
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

// ---- the DN-B topology: one aggregator partition, depth 1, shards 40 and c0 ----------------------------

/** A return whose leaves occupy both shards of the depth-1 world (the owner key moves the state IDs). */
async function twoShardReturn(w: World) {
  for (let k = 2; k < 60; k++) {
    const out = await buildToken(w, spec(1), [txStep(k, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
    if (new Set(out.leaves.map(([sid]) => shardRow(w.policy, sid))).size === 2) return out;
  }
  throw new Error('no two-shard fixture');
}

test('depth 1: one anchor per distinct UC in first-use order, each leaf under its own shard', async () => {
  const w = makeWorld(20, 1);
  const out = await twoShardReturn(w);
  assert.equal(out.ucs.length, 2);
  const { envelope, encoded, verified, gate } = await buildReturnProof(w.bridge, out.token);
  assert.equal(envelope.anchors.length, 2);
  assert.deepEqual(envelope.anchors.map((a) => [...a.shard]), [[...shardIdOf(w, out, 0)], [...shardIdOf(w, out, 1)]]);
  const rows = verified.outcome.leaves.map((l) => shardRow(w.policy, l.sid));
  // anchor j is the j-th distinct shard in leaf order, and every leaf names the anchor of its own row
  const order = [...new Set(rows)];
  assert.deepEqual(envelope.leafProofs.map((l) => l.anchorIndex), rows.map((r) => order.indexOf(r)));
  const pol = checkPolicyBody(w.dep.cfg, envelope);
  const plan = planAnchors(pol, envelope, verified.outcome.leaves.map((l) => l.sid));
  checkAnchors(envelope, plan, verified.outcome.leaves.map((l) => l.referenceTime));
  // the shard-tree sibling of the depth-1 certificate is a path step of the gate
  assert.equal(scanAnchor(envelope.anchors[0], 1).steps, 1);
  assert.throws(() => scanAnchor(envelope.anchors[0], 0), { reason: 'ErrAnchorAuth' });
  assert.ok(gate.total <= TX_GAS_BUDGET);
  assert.deepEqual(decodeEnvelope(encoded), envelope);
  // routing: every leaf is served by the row of its own shard, and the anchors agree
  const routes = await leafRoutes(w.bridge, out.token);
  assert.deepEqual(routes.map((r) => r.row), rows);
  assert.deepEqual(routes.map((r) => r.sid), verified.outcome.leaves.map((l) => l.sid));
  routes.forEach((r, i) => assert.deepEqual(r.shard, envelope.anchors[envelope.leafProofs[i].anchorIndex].shard));
  // a leaf under the other shard's anchor is refused
  const swapped = structuredClone(envelope);
  swapped.leafProofs.forEach((l) => { l.anchorIndex = 1 - l.anchorIndex; });
  throwsReason(() => planAnchors(pol, swapped, verified.outcome.leaves.map((l) => l.sid)), 'ErrPolicyLeafIndex');
});

const shardIdOf = (w: World, out: Awaited<ReturnType<typeof twoShardReturn>>, j: number): Uint8Array => {
  const rows = out.leaves.map(([sid]) => shardRow(w.policy, sid));
  return shardId(w.policy, [...new Set(rows)][j]);
};

test('depth 1: a certificate of the other shard is not admitted for a leaf', async () => {
  const w = makeWorld(20, 1);
  const out = await twoShardReturn(w);
  // The leaves of row r are certified by a UC that names the other row's shard and configuration.
  const g = out.token.genesis;
  const row = shardRow(w.policy, out.leaves[0][0]);
  const other = 1 - row;
  const wrong = await makeUc(w.agg, {
    partition: AGG_PARTITION, conf: w.aggConfs[other], epochIr: 1n, rootEpoch: 2n, round: 900n, timestamp: UC_TS,
    stateHash: g.inclusionProof.unicityCertificate.inputRecord.hash, blockHash: null, signers: 4,
    shard: { bytes: shardId(w.policy, other), siblings: [sha(Uint8Array.of(1))] },
  });
  const proof = new InclusionProof(g.inclusionProof.certificationData, g.inclusionProof.referenceTime, g.inclusionProof.inclusionCertificate, wrong);
  const bytes = C.encodeTag(39040, C.encodeArray(C.encodeUnsignedInteger(2), C.encodeArray(CborDeserializer.decodeArray(g.toCBOR(), 2)[0], proof.toCBOR()), C.encodeArray()));
  await rejects(w.bridge.verifyNativeToken(await Token.fromCBOR(bytes), 'receipt'), 'ErrNotAdmitted');
});

// ---- the burn-time preflight and the bounded retry ----------------------------------------------------

test('burn-time preflight admits a redeemable history and refuses one leaf more than the profile bound', async () => {
  const w = makeWorld();
  const fits = await buildToken(w, spec(1), Array.from({ length: MAX_LEAVES - 2 }, (_, i) => txStep(i + 2, i + 1, T0 + BigInt(i + 1))), T0, UC_TS);
  const gate = await preflightBurn(w.bridge, fits.bytes);
  assert.ok(gate.total <= TX_GAS_BUDGET, String(gate.total));
  const tooLong = await buildToken(w, spec(1), Array.from({ length: MAX_LEAVES - 1 }, (_, i) => txStep(i + 2, i + 1, T0 + BigInt(i + 1))), T0, UC_TS);
  await rejects(preflightBurn(w.bridge, tooLong.bytes), 'ErrTooManyTx');
});

test('a racing (path, UC) pair is retried a bounded number of times, then retryable unavailability', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const good = (): Promise<InclusionProof[]> => freshProofs(w, out, 0, UC_TS);
  const racing = async (): Promise<InclusionProof[]> => {
    const ok = await freshProofs(w, out, 0, UC_TS);
    const alien = (await freshProofs(w, out, 3, UC_TS))[0].unicityCertificate; // another tree's certificate
    return ok.map((p) => new InclusionProof(p.certificationData, p.referenceTime, p.inclusionCertificate, alien));
  };
  let calls = 0;
  const flaky = async (): Promise<InclusionProof[]> => (++calls < MAX_PROOF_ATTEMPTS ? racing() : good());
  const built = await buildNativeReturnProof(plugin, out.bytes, flaky);
  assert.equal(calls, MAX_PROOF_ATTEMPTS);
  assert.ok(built.encoded.length > 0);
  calls = 0;
  const never = async (): Promise<InclusionProof[]> => (++calls, racing());
  await rejects(buildNativeReturnProof(plugin, out.bytes, never), 'ErrProofUnavailable');
  assert.equal(calls, MAX_PROOF_ATTEMPTS, 'no more than the bound, and no re-query to make certificates converge');
  // a bound or profile failure is not retried
  calls = 0;
  const three = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS, { ucRound: (i) => 900n + BigInt(i) });
  const overBound = async (): Promise<InclusionProof[]> => { ++calls; return [three.token.genesis, ...three.token.transactions].map((c) => c.inclusionProof); };
  await rejects(buildNativeReturnProof(plugin, three.bytes, overBound), 'ErrPolicyAnchors');
  assert.equal(calls, 1);
});
