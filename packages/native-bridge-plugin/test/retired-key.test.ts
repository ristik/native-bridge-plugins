/**
 * Retired-key forged history (bft-core #438, from B5 #66): after two committee rotations, a token history whose anchor is sealed by a rotated-out committee
 * is refused, whether the retired keys claim their own (closed) epoch or the current one. The bridge holds the whole history (epochs 2 to 4), so every
 * refusal is the seal's, never a missing epoch; the control anchor of the current committee verifies and builds a return proof.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { InclusionCertificate } from '@unicitylabs/state-transition-sdk/lib/api/InclusionCertificate.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { DataHasherFactory } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasherFactory.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { NodeDataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/NodeDataHasher.js';
import { SparseMerkleTree } from '@unicitylabs/state-transition-sdk/lib/smt/radix/SparseMerkleTree.js';

import { buildReturnProof, refreshToken } from '../src/proof.js';
import { NativeBridge } from '../src/verifier.js';
import { rejects } from './util.js';
import { AGG_PARTITION, buildToken, burnStep, makeUc, makeWorld, nextEpoch, spec, txStep, type Root, type World } from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;

interface Rotated {
  w: World;
  /** epoch 2 (the genesis committee, ended at round 1000), epoch 3 (ended at round 2000), epoch 4 (current) */
  r2: Root;
  r3: Root;
  r4: Root;
  out: Awaited<ReturnType<typeof buildToken>>;
  /** a bridge that holds epochs 2 to 4 */
  held: NativeBridge;
}

async function rotated(): Promise<Rotated> {
  const w = await makeWorld();
  const out = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
  const r3 = await nextEpoch(w.agg, 1000n, 4, 30);
  const r4 = await nextEpoch(r3, 2000n, 4, 40);
  return { w, r2: w.agg, r3, r4, out, held: new NativeBridge(w.bridge.registry, r4.trust) };
}

/** Every leaf of the held token re-anchored under one certificate sealed by `by` claiming root epoch `epoch` at root round 2500. */
async function anchoredBy(x: Rotated, by: Root, epoch: bigint): Promise<InclusionProof[]> {
  const old = [x.out.token.genesis, ...x.out.token.transactions].map((c) => c.inclusionProof);
  const smt = new SparseMerkleTree(new DataHasherFactory(HashAlgorithm.SHA256, NodeDataHasher));
  for (const [k, v] of x.out.leaves) await smt.addLeaf(k, v);
  const root = await smt.calculateRoot();
  const uc = await makeUc(by, {
    partition: AGG_PARTITION, conf: x.w.aggConf, epochIr: 1n, rootEpoch: epoch, round: 2500n, timestamp: UC_TS + 5000n, stateHash: root.hash.data, blockHash: null, signers: 4,
  });
  return old.map((o, i) => new InclusionProof(o.certificationData, o.referenceTime, InclusionCertificate.create(root, x.out.leaves[i][0]), uc));
}

const forged = async (x: Rotated, by: Root, epoch: bigint) => refreshToken(x.out.token, await anchoredBy(x, by, epoch));

test('control: the current committee\'s anchor verifies and builds a return proof on the bridge holding epochs 2 to 4', async () => {
  const x = await rotated();
  const token = await forged(x, x.r4, 4n);
  await x.held.verifyNativeToken(token, 'return');
  const ret = await buildReturnProof(x.held, token);
  assert.equal(ret.envelope.anchors.length, 1);
});

test('the retired epoch-2 committee claiming its own epoch after its end is refused as the seal\'s epoch, on verify and on the return proof', async () => {
  const x = await rotated();
  const token = await forged(x, x.r2, 2n);
  await rejects(x.held.verifyNativeToken(token, 'return'), 'ErrSealEpoch');
  await rejects(buildReturnProof(x.held, token), 'ErrSealEpoch');
});

test('the retired epoch-2 committee claiming the current epoch is refused as no quorum of the current committee', async () => {
  const x = await rotated();
  const token = await forged(x, x.r2, 4n);
  await rejects(x.held.verifyNativeToken(token, 'return'), 'ErrQuorumNotMet');
  await rejects(buildReturnProof(x.held, token), 'ErrQuorumNotMet');
});

test('the epoch-3 committee, retired at round 2000, claiming its own epoch is refused like epoch 2\'s', async () => {
  const x = await rotated();
  await rejects(x.held.verifyNativeToken(await forged(x, x.r3, 3n), 'return'), 'ErrSealEpoch');
  await rejects(x.held.verifyNativeToken(await forged(x, x.r3, 4n), 'return'), 'ErrQuorumNotMet');
});
