import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { fromHex } from '../../src/bytes.js';
import { lineageOf } from '../../src/nb2/bridge.js';
import {
  batchGas, calibratedDeployment, cborCount, cborItems, createAddress, memoryGas, MeasuredGasModel, NATIVE_GAS_SCHEDULE, redeemFeatures, redeemGasTerms, REDEEM_GAS,
  type DeploymentCode, type RedeemShape,
} from '../../src/nb2/gas.js';
import { type LineageLevel } from '../../src/nb2/token.js';
import { decodeEvidence } from '../../src/nb2/verify.js';

const evidence = readFileSync(new URL('../../../../protocol/vectors/nb2-continuation-v1.1/transcripts/one-split/evidence.bin', import.meta.url));
const part = decodeEvidence(evidence);
const shape: RedeemShape = { evidenceBytes: evidence.length, lineage: lineageOf(part), pendingTransactions: 0, proofs: 0n, K: 64n };

test('flat evidence is priced by its bounded signed records', () => {
  const features = redeemFeatures(shape)!;
  assert.equal(features.tokens, 2);
  assert.equal(features.edges, 1);
  assert.equal(features.steps, lineageOf(part).reduce((n, level) => n + 1 + level.transfers.length, 0));
  const limit = (s: RedeemShape) => redeemGasTerms(s)!.limit;
  assert.ok(limit({ ...shape, proofs: 1n }) > limit(shape));
  assert.ok(limit({ ...shape, evidenceBytes: evidence.length + 1000 }) > limit(shape));

  const held = { ...part, transfers: part.transfers.slice(0, -1), transfersRaw: part.transfersRaw.slice(0, -1), proofs: part.proofs.slice(0, -1) };
  const pending = { ...shape, lineage: lineageOf(held), pendingTransactions: 1 };
  assert.ok(redeemFeatures(pending)!.siblings >= REDEEM_GAS.pendingSiblings);
  assert.ok(limit(pending) >= limit(shape));
});

test('the native schedules: CERT_BATCH_V2 balanced at 16 claims and 256 KiB, memory expansion', () => {
  const claim = { bytes: 1_000, signatures: 4, path: 2, epoch: 1n };
  // one claim: 61,100 + 16 (4 + 1,000) + 0 + 29,900 + 7,200 * 4 + 2,000 + 250 * 2
  assert.equal(batchGas([claim]).gas, 61_100n + 16n * 1_004n + 29_900n + 28_800n + 2_000n + 500n);
  // 17 claims are two calls of 9 and 8 (the verifier's balance), each with its own epoch load
  const b = batchGas(Array(17).fill(claim));
  assert.equal(b.calls, 2);
  const call = (k: bigint): bigint => 61_100n + 16n * (4n + 1_000n * k) + 500n * k * (k - 1n) + 29_900n + 7_200n * 4n * k + 2_000n * k + 500n * k;
  assert.equal(b.gas, call(9n) + call(8n));
  // the byte cap splits a call: ten 24.7 KiB claims fit 256 KiB, an eleventh does not
  const big = { bytes: 24_717, signatures: 16, path: 288, epoch: null };
  assert.equal(batchGas(Array(11).fill(big)).calls, 2);
  // an unknown epoch is a new epoch in its call
  assert.equal(batchGas([claim, { ...claim, epoch: null }]).gas - batchGas([claim, claim]).gas, 29_900n);
  assert.equal(memoryGas(0), 0n);
  assert.equal(memoryGas(1024), 3n * 1024n + 2048n);
  assert.equal(memoryGas(50_000), 150_000n + 4_882_812n);
});

test('CBOR items: heads, string payloads skipped; argument heads and nested items counted for the walks', () => {
  assert.equal(cborItems(Uint8Array.of(0x82, 0x01, 0x43, 0xaa, 0xbb, 0xcc)), 3);
  assert.equal(cborItems(Uint8Array.of(0xd9, 0x98, 0x58, 0x81, 0x59, 0x00, 0x02, 0x01, 0x02)), 3);
  // a long tag, a one-item array, a long byte string; an empty array is not nested (scan pushes no depth for it)
  assert.deepEqual(cborCount(Uint8Array.of(0xd9, 0x98, 0x58, 0x81, 0x59, 0x00, 0x02, 0x01, 0x02)), { items: 3, long: 2, nodes: 2 });
  assert.deepEqual(cborCount(Uint8Array.of(0x80, 0xa0, 0xc1, 0x00, 0x18, 0x20)), { items: 5, long: 1, nodes: 1 });
});

test('fail closed: no lineage, a UC that does not parse, more than one pending transaction', () => {
  const s = shape;
  assert.equal(redeemGasTerms({ ...s, lineage: [] }), null);
  assert.equal(redeemGasTerms({ ...s, pendingTransactions: 2 }), null);
  const t = s.lineage[s.lineage.length - 1];
  const bad: LineageLevel = { ...t, proofs: t.proofs.map((p, i) => (i === 0 ? { ...p, uc: p.uc.subarray(0, p.uc.length - 1) } : p)) };
  assert.equal(redeemGasTerms({ ...s, lineage: [...s.lineage.slice(0, -1), bad] }), null);
});

interface DeploymentJson { helperCode: string; [build: string]: string | { gamma: string; verifier: string; helper: string; K: number; B: number; Qmax: string; verifierCode: string; vaultCode: string } }
const DEP = JSON.parse(readFileSync(new URL('../../../../tests/nb2-gas/deployment.json', import.meta.url), 'utf8')) as DeploymentJson;
const deployment = (build: 'test' | 'production'): DeploymentCode => {
  const d = DEP[build] as Exclude<DeploymentJson[string], string>;
  return {
    gamma: fromHex(d.gamma.slice(2))!, verifier: fromHex(d.verifier.slice(2))!, K: BigInt(d.K), B: BigInt(d.B), Qmax: BigInt(d.Qmax), verifierCode: fromHex(d.verifierCode.slice(2))!,
    helperCode: fromHex(DEP.helperCode.slice(2))!, vaultCode: fromHex(d.vaultCode.slice(2))!, nativeGasSchedule: NATIVE_GAS_SCHEDULE,
  };
};
const flip = (b: Uint8Array, at: number): Uint8Array => {
  const c = Uint8Array.from(b);
  c[at] ^= 1;
  return c;
};

test('the default estimate applies to the calibrated deployment only: each runtime rebuilt from the artifact and the deployment\'s own values', () => {
  const m = new MeasuredGasModel();
  for (const build of ['test', 'production'] as const) {
    const d = deployment(build);
    // a genuine deployment (the runtimes of a live release, rebuilt from the artifacts and checked against its code hashes)
    assert.equal(calibratedDeployment(d), true, build);
    assert.equal(m.supportsDeployment(d), true);
    assert.equal(createAddress(d.verifier, 1n).length, 20);
    // the helper at the verifier's first CREATE address
    const h = DEP[build] as { helper: string };
    assert.equal(`0x${Buffer.from(createAddress(d.verifier, 1n)).toString('hex')}`, h.helper.toLowerCase());
    // one occurrence of an immutable changed alone (sol's and astra's case: the helper address at its last use; admitsTestSet at one
    // use; the helper code hash at one use)
    for (const at of [15_504 + 31, 325 + 31, 12_187 + 31, 368 + 31]) assert.equal(calibratedDeployment({ ...d, verifierCode: flip(d.verifierCode, at) }), false, `${build} verifier ${at}`);
    // every occurrence of the helper address changed together: another helper than the one at the verifier's CREATE address
    const moved = Uint8Array.from(d.verifierCode);
    for (const at of [325, 3_071, 8_473, 15_504]) moved[at + 31] ^= 1;
    assert.equal(calibratedDeployment({ ...d, verifierCode: moved }), false);
    // admitsTestSet consistent with (K, B), in every occurrence
    const flipped = Uint8Array.from(d.verifierCode);
    for (const at of [8_541, 12_187]) flipped[at + 31] ^= 1;
    assert.equal(calibratedDeployment({ ...d, verifierCode: flipped }), false);
    // another build: one code byte, another length
    assert.equal(calibratedDeployment({ ...d, verifierCode: flip(d.verifierCode, 1_000) }), false);
    assert.equal(calibratedDeployment({ ...d, verifierCode: d.verifierCode.subarray(1) }), false);
    // another helper
    assert.equal(calibratedDeployment({ ...d, helperCode: flip(d.helperCode, 100) }), false);
    // the vault: one occurrence of D, K or Γ's first word changed alone, a code byte, another Γ, another verifier, another Qmax
    for (const at of [103 + 31, 4_057 + 31, 641 + 31, 1_218 + 31]) assert.equal(calibratedDeployment({ ...d, vaultCode: flip(d.vaultCode, at) }), false, `${build} vault ${at}`);
    assert.equal(calibratedDeployment({ ...d, vaultCode: flip(d.vaultCode, 3_000) }), false);
    assert.equal(calibratedDeployment({ ...d, gamma: flip(d.gamma, d.gamma.length - 1) }), false);
    assert.equal(calibratedDeployment({ ...d, Qmax: d.Qmax + 1n }), false);
    // the native schedule: absent or another
    const { nativeGasSchedule: _drop, ...noSchedule } = d;
    assert.equal(calibratedDeployment(noSchedule), false);
    assert.equal(calibratedDeployment({ ...d, nativeGasSchedule: `${NATIVE_GAS_SCHEDULE} ` }), false);
  }
});
