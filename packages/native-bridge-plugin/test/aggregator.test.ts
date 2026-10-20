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
import { measure } from '../src/certgroups.js';
import { computeGate, kernelRequestBytes } from '../src/gas.js';
import { MAX_ANCHORS, MAX_LEAVES, TX_GAS_BUDGET } from '../src/limits.js';
import { BURN_HISTORY_BYTES, buildReturnProof, leafStateIds, preflightBurn, refreshToken } from '../src/proof.js';
import { projectToken } from '../src/history.js';
import { NativeError, RETRYABLE } from '../src/errors.js';
import { BEST_UC_BYTES } from '../src/gas.js';
import { MAX_SEMANTIC_BYTES } from '../src/limits.js';
import { cfgBytes } from '../src/profile.js';
import { toHex } from '../src/bytes.js';
import { buildNativeReturnProof, createNativeBridgePlugin, MAX_PROOF_ATTEMPTS, PAIR_RACE } from '../src/wallet.js';
import { DeploymentRegistry } from '../src/deployment.js';
import { rejects, throwsReason } from './util.js';
import { AGG_PARTITION, buildToken, burnStep, makeUc, makeWorld, rowOf, sha, shardOf, signer, spec, txStep, type World } from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;
const ret = (w: World) => buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);

test('return envelope round trips and passes policy, anchor and gate checks', async () => {
  const w = await makeWorld();
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
  assert.deepEqual(computeGate(cfgBytes(w.dep.cfg), encoded.length, kernelRequestBytes(cfgBytes(w.dep.cfg).length, envelope.history.length), envelope), gate);
  assert.equal(gate.grouping.k, 1);
  assert.equal(gate.j, 17 + 4 + 12 + gate.grouping.items, 'J: Cfg, policy, one IR opening and the UC occurrences');
  assert.equal(gate.items, 1000 * gate.j);
});

test('envelope framing is canonical', async () => {
  const w = await makeWorld();
  const { envelope, encoded } = await buildReturnProof(w.bridge, (await ret(w)).token);
  throwsReason(() => decodeEnvelope(Uint8Array.of(...encoded, ...new Uint8Array(32))), 'ErrABIFraming', 'trailing word');
  throwsReason(() => decodeEnvelope(Uint8Array.of(...encoded, 0)), 'ErrABIFraming', 'unaligned');
  const dirty = encoded.slice();
  dirty[4 * 32 + 32 + envelope.policyBody.length] = 1;
  throwsReason(() => decodeEnvelope(dirty), 'ErrABIFraming', 'dirty padding');
  assert.deepEqual(encodeEnvelope(envelope), encoded);
});

test('policy and anchor-table checks name each mismatch', async () => {
  const w = await makeWorld();
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
  const foreign = clone();
  foreign.anchors[0].shard = Uint8Array.of(sids[0][0] & 0x80 ? 0x40 : 0xc0);
  throwsReason(() => plan(foreign), 'ErrPolicyLeafIndex', 'a shard whose prefix the leaf does not carry');
  const noncanonical = clone();
  noncanonical.anchors[0].shard = Uint8Array.of(0x00);
  throwsReason(() => plan(noncanonical), 'ErrPolicyTuple', 'a noncanonical shard ID');
  const part = clone();
  part.anchors[0].partition += 1;
  throwsReason(() => plan(part), 'ErrPolicyTuple');
  const conf = clone();
  conf.anchors[0].shardConfHash[0] ^= 1;
  plan(conf); // the configuration hash is authenticated by the UC (B1), not pinned by the policy
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
  const w = await makeWorld();
  const { envelope, verified } = await buildReturnProof(w.bridge, (await ret(w)).token);
  const times = verified.outcome.leaves.map((l) => l.referenceTime);
  const one = { leafAnchor: [0, 0, 0] };
  const a = structuredClone(envelope);
  a.anchors[0].inputRecord[10] ^= 1;
  throwsReason(() => checkAnchors(a, one, times), 'ErrIROpening', 'false opening');
  const b = structuredClone(envelope);
  b.anchors[0].expectedStateRoot[0] ^= 1;
  throwsReason(() => checkAnchors(b, one, times), 'ErrIRState', 'state root');
  throwsReason(() => checkAnchors(envelope, one, [UC_TS + 1n, UC_TS, UC_TS]), 'ErrIRTime');
  checkAnchors(envelope, one, [UC_TS, UC_TS, UC_TS]);
  throwsReason(() => parseInputRecord(C.encodeTag(39002, C.encodeArray(C.encodeUnsignedInteger(1)))), 'ErrIRShape');
  throwsReason(() => parseInputRecord(new Uint8Array(513)), 'ErrIRShape');
  // the summary value is bounded by the native sublimit the chain enforces (256 bytes), so a received envelope cannot open what the chain refuses
  const ir = (summary: number): Uint8Array => C.encodeTag(39002, C.encodeArray(
    C.encodeUnsignedInteger(1), C.encodeUnsignedInteger(7), C.encodeUnsignedInteger(1), C.encodeNull(), C.encodeByteString(new Uint8Array(32)),
    C.encodeByteString(new Uint8Array(summary)), C.encodeUnsignedInteger(5), C.encodeNull(), C.encodeUnsignedInteger(0), C.encodeNull()));
  assert.equal(parseInputRecord(ir(256)).round, 7n);
  throwsReason(() => parseInputRecord(ir(257)), 'ErrIRShape');
});

test('an over-bound certificate is a budget refusal, any other shape failure is malformed', async () => {
  const w = await makeWorld();
  const out = await ret(w);
  const { envelope } = await buildReturnProof(w.bridge, out.token);
  const a = envelope.anchors[0];
  const sealed = async (signers: number): Promise<Uint8Array> => {
    const old = out.token.genesis.inclusionProof.unicityCertificate;
    const extra: [string, ReturnType<typeof signer>][] = Array.from({ length: signers - 4 }, (_, i) => [`extra${i}`, signer(100 + (i % 100))]);
    return (await makeUc(w.agg, { partition: AGG_PARTITION, conf: w.aggConf, epochIr: 1n, rootEpoch: 2n, round: BigInt(old.unicitySeal.rootChainRoundNumber), timestamp: UC_TS, stateHash: old.inputRecord.hash!, blockHash: null, signers: 4, extra })).toCBOR();
  };
  assert.equal(measure([{ ...a, uc: await sealed(16) }]).q, 16);
  const over = await sealed(17);
  assert.throws(() => measure([{ ...a, uc: over }]), { reason: 'ErrTooManyItems', family: 'budget' });
  assert.throws(() => measure([{ ...a, uc: a.uc.slice(0, 20) }]), { family: 'malformed' });
  // 33 unicity steps (the bound is 32), spliced into the certificate's empty step list
  const at = Buffer.from(a.uc).indexOf(Buffer.from([0xd9, 0x98, 0x5c, 0x83]));
  assert.ok(at > 0, 'the unicity tree certificate');
  const head = at + 4 + 1 + 1; // tag, array(3), version, partition (one byte each here)
  assert.equal(a.uc[head], 0x80, 'an empty step list');
  const steps = Uint8Array.from([...a.uc.slice(0, head), 0x98, 33, ...new Array<number>(33).fill(0xf6), ...a.uc.slice(head + 1)]);
  assert.throws(() => measure([{ ...a, uc: steps }]), { reason: 'ErrTooManyItems', family: 'budget' });
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
  const w = await makeWorld();
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
  const w = await makeWorld();
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
  const w = await makeWorld();
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
  // one certificate per leaf: up to MAX_ANCHORS distinct UCs are admitted when the gate passes
  assert.equal(MAX_ANCHORS, 16);
  const perLeaf = (n: number) => buildToken(w, spec(1), Array.from({ length: n }, (_, i) => (i === n - 1 ? burnStep(T0 + 20n) : txStep(i + 2, 7, T0 + 10n + BigInt(i)))), T0, UC_TS, { ucRound: (i) => 900n + BigInt(i) });
  for (const n of [1, 2]) {
    const out = await perLeaf(n);
    assert.equal(out.ucs.length, n + 1);
    const ok = await buildReturnProof(w.bridge, out.token);
    assert.equal(ok.envelope.anchors.length, n + 1);
    assert.ok(ok.gate.total <= TX_GAS_BUDGET);
  }
  // every leaf of a full 16-leaf history under its own certificate is MAX_ANCHORS anchors: admitted or priced out by the gate, never truncated
  const full = await perLeaf(MAX_LEAVES - 1);
  assert.equal(full.ucs.length, MAX_ANCHORS);
  const sixteen = await buildReturnProof(w.bridge, full.token).then((r) => r.envelope.anchors.length, (e: unknown) => (e as NativeError).reason);
  assert.ok(sixteen === MAX_ANCHORS || sixteen === 'ErrGasBudget', String(sixteen));
});

test('consolidation (evidence 1c): re-proving the same token under one certificate changes the seals, never the transactions, IDs, times or the nullifier', async () => {
  const w = await makeWorld();
  // before: the genesis is certified in one round, the transfers in another: two UCs, two seals
  const a = await ret(w);
  const b = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS + 5n);
  const before = await Token.fromCBOR(
    C.encodeTag(39040, C.encodeArray(C.encodeUnsignedInteger(2), a.token.genesis.toCBOR(), C.encodeArray(...b.token.transactions.map((t) => t.toCBOR())))),
  );
  // after: every leaf re-proved under ONE later certificate (the refresh keeps exact M/T/CD/t/J)
  const after = await refreshToken(before, await freshProofs(w, a, 0, UC_TS + 5000n));
  const vb = await w.bridge.verifyNativeToken(before, 'return');
  const va = await w.bridge.verifyNativeToken(after, 'return');
  // signed transaction bytes (the proofs aside), token and leaf IDs, reference-time inputs and the burn nullifier are unchanged
  const txs = (t: Token): string[] => [t.genesis, ...t.transactions].map((c) => toHex(CborDeserializer.decodeArray(c.toCBOR(), 2)[0]));
  assert.deepEqual(txs(after), txs(before), 'signed transaction bytes');
  assert.deepEqual(va.outcome.leaves.map((l) => l.sid), vb.outcome.leaves.map((l) => l.sid), 'leaf IDs');
  assert.deepEqual(va.outcome.leaves.map((l) => l.txHash), vb.outcome.leaves.map((l) => l.txHash), 'transaction hashes');
  assert.deepEqual(va.outcome.leaves.map((l) => l.referenceTime), vb.outcome.leaves.map((l) => l.referenceTime), 'reference times');
  assert.deepEqual(va.outcome.nullifier, vb.outcome.nullifier, 'burn nullifier');
  assert.equal(va.outcome.nonce, vb.outcome.nonce);
  // the batch grouping shrinks: fewer distinct seals, fewer signatures, never more epochs or claims
  const gb = (await buildReturnProof(w.bridge, before)).gate.grouping;
  const ga = (await buildReturnProof(w.bridge, after)).gate.grouping;
  assert.equal(gb.s, 2);
  assert.equal(ga.s, 1);
  assert.ok(ga.q < gb.q, `Q ${gb.q} -> ${ga.q}`);
  assert.ok(ga.e <= gb.e && ga.a < gb.a && ga.k < gb.k, `E ${gb.e}->${ga.e} A ${gb.a}->${ga.a} K ${gb.k}->${ga.k}`);
});

async function aggErr(f: (o: { uc: Parameters<typeof makeUc>[1] }) => void): Promise<unknown> {
  const w = await makeWorld();
  const out = await buildToken(w, spec(1), [], T0, UC_TS);
  const g = out.token.genesis;
  const uc = { partition: AGG_PARTITION, conf: w.aggConf, epochIr: 1n, rootEpoch: 2n, round: 900n, timestamp: UC_TS, stateHash: g.inclusionProof.unicityCertificate.inputRecord.hash, blockHash: null, signers: 4 } as Parameters<typeof makeUc>[1];
  const o = { uc };
  f(o);
  const proof = new InclusionProof(g.inclusionProof.certificationData, g.inclusionProof.referenceTime, g.inclusionProof.inclusionCertificate, await makeUc(w.agg, o.uc));
  const bytes = C.encodeTag(39040, C.encodeArray(C.encodeUnsignedInteger(2), C.encodeArray(CborDeserializer.decodeArray(g.toCBOR(), 2)[0], proof.toCBOR()), C.encodeArray()));
  return w.bridge.verifyNativeToken(await Token.fromCBOR(bytes), 'receipt');
}

test('aggregator certificates are checked against the pinned partition and the SDK quorum', async () => {
  await rejects(aggErr((o) => void (o.uc.partition = 9)), 'ErrNotAdmitted');
  await rejects(aggErr((o) => void (o.uc.signers = 2)), 'ErrQuorumNotMet');
  await rejects(aggErr((o) => void (o.uc.stateHash = new Uint8Array(32).fill(0x13))), 'ErrPathInvalid');
  // an epoch the history does not hold yet is retryable; one before its genesis is not
  await rejects(aggErr((o) => void (o.uc.rootEpoch = 3n)), 'ErrNoEntryForEpoch');
  await rejects(aggErr((o) => void (o.uc.rootEpoch = 1n)), 'ErrSealEpoch');
  // several faults: an epoch not held and a false seal root -- the epoch decides, as in the oracle
  await rejects(aggErr((o) => void ((o.uc.rootEpoch = 3n), (o.uc.sealHash = new Uint8Array(32).fill(1)))), 'ErrNoEntryForEpoch');
});

test('deployment registry rejects duplicates', async () => {
  const w = await makeWorld();
  assert.throws(() => new DeploymentRegistry([w.dep, w.dep]), /ErrAmbiguousDeployment/);
});

// ---- the DN-B topology: one aggregator partition, depth 1, shards 40 and c0 ----------------------------

/** A return whose leaves occupy both shards of the depth-1 world (the owner key moves the state IDs). */
async function twoShardReturn(w: World) {
  for (let k = 2; k < 60; k++) {
    const out = await buildToken(w, spec(1), [txStep(k, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
    if (new Set(out.leaves.map(([sid]) => rowOf(w, sid))).size === 2) return out;
  }
  throw new Error('no two-shard fixture');
}

test('depth 1: one anchor per distinct UC in first-use order, each leaf under its own shard', async () => {
  const w = await makeWorld(20, 1);
  const out = await twoShardReturn(w);
  assert.equal(out.ucs.length, 2);
  const { envelope, encoded, verified, gate } = await buildReturnProof(w.bridge, out.token);
  assert.equal(envelope.anchors.length, 2);
  assert.deepEqual(envelope.anchors.map((a) => [...a.shard]), [[...shardIdOf(w, out, 0)], [...shardIdOf(w, out, 1)]]);
  const rows = verified.outcome.leaves.map((l) => rowOf(w, l.sid));
  // anchor j is the j-th distinct shard in leaf order, and every leaf names the anchor of its own row
  const order = [...new Set(rows)];
  assert.deepEqual(envelope.leafProofs.map((l) => l.anchorIndex), rows.map((r) => order.indexOf(r)));
  const pol = checkPolicyBody(w.dep.cfg, envelope);
  const plan = planAnchors(pol, envelope, verified.outcome.leaves.map((l) => l.sid));
  checkAnchors(envelope, plan, verified.outcome.leaves.map((l) => l.referenceTime));
  // the depth of each anchor comes from its own shard ID, and its shard-tree sibling is a path step of the gate
  assert.equal(measure([envelope.anchors[0]]).p, 1);
  assert.throws(() => measure([{ ...envelope.anchors[0], shard: Uint8Array.of(0x80) }]), { reason: 'ErrShardMismatch' });
  assert.ok(gate.total <= TX_GAS_BUDGET);
  assert.deepEqual(decodeEnvelope(encoded), envelope);
  // routing: the state ID of every leaf is what the host asks its aggregator for; the anchors carry the shards the certificates name
  const sidsOf = await leafStateIds(out.token);
  assert.deepEqual(sidsOf, verified.outcome.leaves.map((l) => l.sid));
  // a leaf under the other shard's anchor is refused
  const swapped = structuredClone(envelope);
  swapped.leafProofs.forEach((l) => { l.anchorIndex = 1 - l.anchorIndex; });
  throwsReason(() => planAnchors(pol, swapped, verified.outcome.leaves.map((l) => l.sid)), 'ErrPolicyLeafIndex');
});

const shardIdOf = (w: World, out: Awaited<ReturnType<typeof twoShardReturn>>, j: number): Uint8Array => {
  const rows = out.leaves.map(([sid]) => rowOf(w, sid));
  return shardOf(w, [...new Set(rows)][j]);
};

test('depth 1: a certificate of the other shard does not cover the leaf', async () => {
  const w = await makeWorld(20, 1);
  const out = await twoShardReturn(w);
  // The leaves of row r are certified by a UC that names the other row's shard and configuration.
  const g = out.token.genesis;
  const row = rowOf(w, out.leaves[0][0]);
  const other = 1 - row;
  const wrong = await makeUc(w.agg, {
    partition: AGG_PARTITION, conf: w.aggConfs[other], epochIr: 1n, rootEpoch: 2n, round: 900n, timestamp: UC_TS,
    stateHash: g.inclusionProof.unicityCertificate.inputRecord.hash, blockHash: null, signers: 4,
    shard: { bytes: shardOf(w, other), siblings: [sha(Uint8Array.of(1))] },
  });
  const proof = new InclusionProof(g.inclusionProof.certificationData, g.inclusionProof.referenceTime, g.inclusionProof.inclusionCertificate, wrong);
  const bytes = C.encodeTag(39040, C.encodeArray(C.encodeUnsignedInteger(2), C.encodeArray(CborDeserializer.decodeArray(g.toCBOR(), 2)[0], proof.toCBOR()), C.encodeArray()));
  await rejects(w.bridge.verifyNativeToken(await Token.fromCBOR(bytes), 'receipt'), 'ErrShardMismatch');
});

// ---- the burn-time preflight and the bounded retry ----------------------------------------------------

test('burn-time preflight admits a redeemable history and refuses one leaf more than the profile bound', async () => {
  const w = await makeWorld();
  const fits = await buildToken(w, spec(1), Array.from({ length: MAX_LEAVES - 2 }, (_, i) => txStep(i + 2, i + 1, T0 + BigInt(i + 1))), T0, UC_TS);
  const gate = await preflightBurn(w.bridge, fits.bytes);
  assert.ok(gate.total <= TX_GAS_BUDGET, String(gate.total));
  const tooLong = await buildToken(w, spec(1), Array.from({ length: MAX_LEAVES - 1 }, (_, i) => txStep(i + 2, i + 1, T0 + BigInt(i + 1))), T0, UC_TS);
  await rejects(preflightBurn(w.bridge, tooLong.bytes), 'ErrTooManyTx');
});

test('preflightBurn on a held token: a history within BURN_HISTORY_BYTES of the bound is refused, one byte less passes', async () => {
  const w = await makeWorld();
  const held = (n: number) => buildToken(w, spec(1), [txStep(2, 7, T0 + 10n)], T0, UC_TS, { mintData: new Uint8Array(n).fill(7) });
  const edge = MAX_SEMANTIC_BYTES - BURN_HISTORY_BYTES;
  // the projection grows one byte per data byte once the byte-string header width is fixed
  const probe = 4096;
  const base = projectToken((await held(probe)).token).length;
  const n = probe + (edge - base);
  const fits = await held(n);
  assert.equal(projectToken(fits.token).length, edge, 'the held history is exactly at the margin');
  const gate = await preflightBurn(w.bridge, fits.bytes);
  assert.ok(gate.total <= TX_GAS_BUDGET);
  await rejects(preflightBurn(w.bridge, (await held(n + 1)).bytes), 'ErrInputTooLarge');
});

test('preflightBurn prices a held token exactly (pins the best-case constants and the known-history rule)', async () => {
  const w = await makeWorld();
  const held = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n)], T0, UC_TS);
  const gate = await preflightBurn(w.bridge, held.bytes);
  // best case: ONE 445-byte one-signature certificate (39 items, depth 0, no shard sibling), an empty input record (12 items), the known history only
  assert.deepEqual([gate.total, gate.batch, gate.items, gate.b2, gate.intrinsic, gate.rsmt], [1_725_886, 107_896, 72_000, 125_600, 407_112, 13_278]);
});

test('planAnchors itself refuses more than MAX_ANCHORS anchors with ErrTooManyPaths (not shadowed by checkPolicyBody)', async () => {
  const w = await makeWorld();
  const { envelope, verified } = await buildReturnProof(w.bridge, (await ret(w)).token);
  const pol = checkPolicyBody(w.dep.cfg, envelope);
  const over = structuredClone(envelope);
  while (over.anchors.length <= MAX_ANCHORS) over.anchors.push(structuredClone(over.anchors[0]));
  throwsReason(() => planAnchors(pol, over, verified.outcome.leaves.map((l) => l.sid)), 'ErrTooManyPaths');
});

test('a real burn leaf adds no more history than BURN_HISTORY_BYTES, and the best-case certificate is no larger than any real one', async () => {
  const w = await makeWorld();
  const held = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n)], T0, UC_TS);
  const burned = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
  const added = projectToken(burned.token).length - projectToken(held.token).length;
  assert.ok(added > 0 && added <= BURN_HISTORY_BYTES, `the burn leaf adds ${added} bytes, bound ${BURN_HISTORY_BYTES}`);
  for (const uc of burned.ucs) assert.ok(uc.toCBOR().length >= BEST_UC_BYTES, `a real certificate of ${uc.toCBOR().length} bytes is below the best case`);
});

test('the retryable unavailability is its own family, not an invalid token', () => {
  assert.equal(new NativeError('ErrProofUnavailable').family, 'unavailable');
  assert.deepEqual([...RETRYABLE], ['ErrProofUnavailable']);
  assert.equal(new NativeError('ErrPolicyAnchors').family, 'invalid');
  assert.equal(new NativeError('ErrTooManyPaths').family, 'budget');
});

test('a racing (path, UC) pair is retried a bounded number of times, then retryable unavailability', async () => {
  const w = await makeWorld();
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
  const gone = await buildNativeReturnProof(plugin, out.bytes, never).then(() => undefined, (e: unknown) => e);
  assert.ok(gone instanceof NativeError && gone.reason === 'ErrProofUnavailable' && /last: Err\w+/.test(gone.detail ?? ''), String((gone as NativeError).detail));
  // without a source nothing was refetched, so nothing raced: a held token that does not verify is reported as what it is, not as an outage
  const tampered = (await refreshToken(out.token, await racing())).toCBOR();
  const bad = await buildNativeReturnProof(plugin, tampered).then(() => undefined, (e: unknown) => e);
  assert.ok(bad instanceof NativeError && PAIR_RACE.includes(bad.reason), String(bad));
  assert.equal(calls, MAX_PROOF_ATTEMPTS, 'no more than the bound, and no re-query to make certificates converge');
  // a bound or profile failure is not retried: more leaves than the profile admits is refused before anything is fetched
  calls = 0;
  const long = await buildToken(w, spec(1), [...Array.from({ length: MAX_LEAVES }, (_, i) => txStep(i + 2, 7 + i, T0 + 10n + BigInt(2 * i))), burnStep(T0 + 40n)], T0, UC_TS);
  const overBound = async (): Promise<InclusionProof[]> => { ++calls; return [long.token.genesis, ...long.token.transactions].map((c) => c.inclusionProof); };
  await rejects(buildNativeReturnProof(plugin, long.bytes, overBound), 'ErrTooManyTx');
  assert.ok(calls <= 1);
});
