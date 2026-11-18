/**
 * The redeem gas estimate (src/nb2/gas.ts, estimate-nb2-1179): the shared vectors (tests/nb2-gas/gas-vectors.json, real evidence of the bft-core#1179
 * measurement lane) reproduced exactly, as the Rust plug-in reproduces them (crates/native-bridge-sdk-ext/tests/nb2_gas.rs), and the bound's
 * structure: the native schedules, the pending burn at its bounds, the fail-closed inputs.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { fromHex } from '../../src/bytes.js';
import { lineageOf } from '../../src/nb2/bridge.js';
import {
  batchGas, calibratedDeployment, cborCount, cborItems, createAddress, memoryGas, MeasuredGasModel, NATIVE_GAS_SCHEDULE, priceFeatures, redeemFeatures, redeemGasTerms, REDEEM_GAS,
  type DeploymentCode, type RedeemFeatures, type RedeemShape,
} from '../../src/nb2/gas.js';
import { type Token } from '../../src/nb2/token.js';
import { decodeEvidence } from '../../src/nb2/verify.js';

const FILE = new URL('../../../../tests/nb2-gas/gas-vectors.json', import.meta.url);
interface Case { input: string; pendingTransactions: number; proofs: string; K: string; evidenceBytes: number; features: unknown; terms: unknown }
const file = JSON.parse(readFileSync(FILE, 'utf8')) as { model: string; vectors: { name: string; labGas?: string; evidence: string; cases: Case[] }[] };
const json = (v: unknown): unknown => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x)));

/** The part before its burn: the evidence's last transfer pair dropped (the preflight's token). */
const beforeBurn = (t: Token): Token => ({ ...t, transfers: t.transfers.slice(0, -1), proofs: t.proofs.slice(0, -1), transfersRaw: t.transfersRaw.slice(0, -1) });

const shapes = (v: { evidence: string; cases: Case[] }): [Case, RedeemShape][] => {
  const part = decodeEvidence(fromHex(v.evidence)!);
  return v.cases.map((c) => [c, {
    evidenceBytes: c.evidenceBytes, lineage: lineageOf(c.pendingTransactions === 1 ? beforeBurn(part) : part), pendingTransactions: c.pendingTransactions,
    proofs: BigInt(c.proofs), K: BigInt(c.K),
  }]);
};

test('the shared vectors: every feature and term, exactly (a null bound where the vector fails closed)', () => {
  assert.equal(file.model, new MeasuredGasModel().name);
  assert.ok(file.vectors.length >= 18);
  let nulls = 0;
  for (const v of file.vectors) {
    for (const [c, s] of shapes(v)) {
      assert.deepEqual(json(redeemFeatures(s)), c.features, `${v.name} ${c.input} P ${c.proofs}: features`);
      assert.deepEqual(json(redeemGasTerms(s)), c.terms, `${v.name} ${c.input} P ${c.proofs}: terms`);
      const want = c.terms === null ? null : BigInt((c.terms as { limit: string }).limit);
      assert.equal(new MeasuredGasModel().redeemGasLimit(s), want);
      if (want === null) nulls++;
    }
  }
  // the 17-signature seal and the non-text signature key, every case
  assert.equal(nulls, 2 * 5);
});

test('every vector measured in the lab: the estimate\'s execution, memory and SHA-256 terms at redemption cover the deployed verifier\'s gas', () => {
  let measured = 0;
  for (const v of file.vectors) {
    if (v.labGas === undefined) continue;
    measured++;
    const [, s] = shapes(v)[0];
    const t = redeemGasTerms(s)!;
    assert.ok(t.execution + t.memory + t.sha256 >= BigInt(v.labGas), `${v.name}: ${t.execution + t.memory + t.sha256} < ${v.labGas}`);
  }
  // the review's counterexamples above the splits among them
  assert.ok(measured >= 14);
  for (const n of ['split-above-2-levels-32-unicity-steps', 'split-above-3-levels-32-unicity-steps', 'split-above-5-levels-16-signatures-8-steps', 'split-above-7-levels-32-unicity-steps']) {
    assert.ok(file.vectors.some((v) => v.name === n && v.labGas !== undefined), n);
  }
});

test('every vector: the preflight is at or above the redemption at the same proofs, and so is each pending-dependent feature', () => {
  for (const v of file.vectors) {
    const all = shapes(v);
    for (const K of [4n, 64n]) {
      const red = all.find(([c]) => c.pendingTransactions === 0 && BigInt(c.K) === K && BigInt(c.proofs) === 17n);
      const pre = all.find(([c]) => c.pendingTransactions === 1 && BigInt(c.K) === K);
      if (!red || !pre) continue;
      const fr = redeemFeatures(red[1]);
      const fp = redeemFeatures(pre[1]);
      if (fr === null || fp === null) {
        assert.equal(fr, fp, `${v.name}: null in one input only`);
        continue;
      }
      assert.ok(redeemGasTerms({ ...pre[1], proofs: 17n })!.limit >= redeemGasTerms(red[1])!.limit, `${v.name} K ${K}`);
      for (const k of ['steps', 'txWords', 'siblings', 'ucBytes', 'ucSignatures', 'ucStc', 'ucUtc', 'ucSlow', 'probes', 'keyLookups'] as const) {
        assert.ok(fp[k] >= fr[k], `${v.name} K ${K}: ${k} ${fp[k]} < ${fr[k]}`);
      }
      for (const w of ['scan', 'skip'] as const) {
        for (const k of ['items', 'long', 'nodes'] as const) assert.ok(fp[w][k] >= fr[w][k], `${v.name} K ${K}: ${w}.${k}`);
      }
      assert.ok(fp.claims.length >= fr.claims.length);
    }
  }
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

test('the pending burn is counted at its bounds, and more of the token never costs less', () => {
  const v = file.vectors[0];
  const [, red] = shapes(v)[0];
  const [, pre] = shapes(v)[3];
  const f = redeemFeatures(pre)!;
  assert.ok(f.ucBytes >= REDEEM_GAS.pendingUcBytes && f.ucStc >= REDEEM_GAS.pendingStc && f.siblings >= REDEEM_GAS.pendingSiblings);
  assert.equal(f.claims[f.claims.length - 1].epoch, null);
  // the preflight's bound of the part before its burn is above the bound of the burned evidence at the same proofs
  assert.ok(redeemGasTerms(pre)!.limit > redeemGasTerms({ ...red, proofs: pre.proofs })!.limit);
  // monotone in the proofs, in the evidence bytes and in every counted feature
  const g = (s: RedeemShape): bigint => redeemGasTerms(s)!.limit;
  assert.ok(g({ ...red, proofs: 1n }) > g(red));
  assert.ok(g({ ...red, evidenceBytes: red.evidenceBytes + 1_000 }) > g(red));
  for (const w of file.vectors) {
    const [, r] = shapes(w)[0];
    const fr = redeemFeatures(r);
    if (fr === null) continue;
    const base = priceFeatures(fr, r.evidenceBytes, 0n, 4n).limit;
    for (const k of ['steps', 'siblings', 'ucBytes', 'ucIr', 'ucSignatures', 'ucStc', 'ucUtc', 'ucSlow', 'probes', 'decompressions', 'txWords', 'edges', 'allocSteps', 'jBytes',
      'rcptItems', 'rcptLong', 'rcptLists', 'rcptHeads', 'rcptLongHeads', 'rcptKids'] as const) {
      const more: RedeemFeatures = { ...fr, [k]: fr[k] + 1 };
      assert.ok(priceFeatures(more, r.evidenceBytes, 0n, 4n).limit > base, `${w.name}: ${k}`);
    }
    for (const wk of ['scan', 'skip'] as const) {
      for (const k of ['items', 'long'] as const) {
        const more: RedeemFeatures = { ...fr, [wk]: { ...fr[wk], [k]: fr[wk][k] + 1 } };
        assert.ok(priceFeatures(more, r.evidenceBytes, 0n, 4n).limit > base, `${w.name}: ${wk}.${k}`);
      }
    }
  }
});

test('fail closed: no lineage, a UC that does not parse, more than one pending transaction', () => {
  const v = file.vectors[0];
  const [, s] = shapes(v)[0];
  assert.equal(redeemGasTerms({ ...s, lineage: [] }), null);
  assert.equal(redeemGasTerms({ ...s, pendingTransactions: 2 }), null);
  const t = s.lineage[s.lineage.length - 1];
  const bad: Token = { ...t, proofs: t.proofs.map((p, i) => (i === 0 ? { ...p, uc: p.uc.subarray(0, p.uc.length - 1) } : p)) };
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
