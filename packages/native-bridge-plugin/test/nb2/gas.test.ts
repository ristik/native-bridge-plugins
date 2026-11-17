/**
 * The redeem gas bound (src/nb2/gas.ts, bound-nb2-1179): the shared vectors (tests/nb2-gas/gas-vectors.json, real evidence of the bft-core#1179
 * measurement lane) reproduced exactly, as the Rust plug-in reproduces them (crates/native-bridge-sdk-ext/tests/nb2_gas.rs), and the bound's
 * structure: the native schedules, the pending burn at its bounds, the fail-closed inputs.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { fromHex } from '../../src/bytes.js';
import { lineageOf } from '../../src/nb2/bridge.js';
import { batchGas, cborItems, memoryGas, MeasuredGasModel, priceFeatures, redeemFeatures, redeemGasTerms, REDEEM_GAS, type RedeemShape } from '../../src/nb2/gas.js';
import { type Token } from '../../src/nb2/token.js';
import { decodeEvidence } from '../../src/nb2/verify.js';

const FILE = new URL('../../../../tests/nb2-gas/gas-vectors.json', import.meta.url);
interface Case { input: string; pendingTransactions: number; proofs: string; K: string; evidenceBytes: number; features: unknown; terms: unknown }
const file = JSON.parse(readFileSync(FILE, 'utf8')) as { model: string; vectors: { name: string; evidence: string; cases: Case[] }[] };
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
  assert.ok(file.vectors.length >= 11);
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
      for (const k of ['steps', 'items', 'txWords', 'siblings', 'ucBytes', 'ucSignatures', 'ucStc', 'ucUtc', 'ucSlow', 'probes', 'keyLookups'] as const) {
        assert.ok(fp[k] >= fr[k], `${v.name} K ${K}: ${k} ${fp[k]} < ${fr[k]}`);
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

test('CBOR items: heads, string payloads skipped', () => {
  assert.equal(cborItems(Uint8Array.of(0x82, 0x01, 0x43, 0xaa, 0xbb, 0xcc)), 3);
  assert.equal(cborItems(Uint8Array.of(0xd9, 0x98, 0x58, 0x81, 0x59, 0x00, 0x02, 0x01, 0x02)), 3);
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
    for (const k of ['steps', 'parentSteps', 'items', 'siblings', 'ucBytes', 'ucIr', 'ucSignatures', 'ucStc', 'ucUtc', 'ucSlow', 'probes', 'decompressions', 'txWords', 'edges', 'allocSteps', 'jBytes'] as const) {
      const more = { ...fr, [k]: fr[k] + 1 };
      assert.ok(priceFeatures(more, r.evidenceBytes, 0n, 4n).limit > priceFeatures(fr, r.evidenceBytes, 0n, 4n).limit, `${w.name}: ${k}`);
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
