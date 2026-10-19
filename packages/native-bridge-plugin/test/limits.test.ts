import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { BURN_HISTORY_BYTES, checkBurnProjection } from '../src/proof.js';
import { throwsReason } from './util.js';
import { batchGas } from '../src/certgroups.js';
import { b2Gas, intrinsicGas, itemGas, kernelRequestBytes, projectedGate, rsmtGas } from '../src/gas.js';
import * as L from '../src/limits.js';

const PROFILE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'protocol', 'profile-v5.json');

test('the named bounds are the limits of profile-v5.json, the one source of the contract, oracle and plug-ins', () => {
  const lim = (JSON.parse(readFileSync(PROFILE, 'utf8')) as { limits: Record<string, number> }).limits;
  assert.equal(L.NATIVE_BRIDGE_PROTO_VERSION, 5);
  assert.equal(L.MAX_ANCHORS, lim.aggregatorAnchors);
  assert.equal(L.MAX_LEAVES, lim.leaves);
  assert.equal(L.MAX_TRANSFERS, lim.transfers);
  assert.equal(L.MAX_SEMANTIC_BYTES, lim.semanticBytes);
  assert.equal(L.MAX_ENVELOPE_BYTES, lim.envelopeBytes);
  assert.equal(L.MAX_ANCHOR_UC_BYTES, lim.anchorUcBytes);
  assert.equal(L.MAX_RSMT_SIBLINGS, lim.rsmtSiblingsPerLeaf);
  assert.equal(L.MAX_PATH_STEPS, lim.pathSteps);
  assert.equal(L.MAX_POLICY_BYTES, lim.policyBytes);
  assert.equal(L.MAX_UNICITY_STEPS, lim.unicityStepsPerUc);
  assert.equal(L.MAX_INPUT_RECORD_BYTES, lim.irBytes);
  assert.equal(L.TX_GAS_BUDGET, lim.txGasBudget);
  assert.equal(L.GAS_RESERVE, lim.gasReserve);
  assert.equal(L.MAX_JUSTIFICATION_BYTES, lim.justificationBytes);
  assert.equal(L.BRIDGE_CBOR_ITEMS, lim.bridgeCborItems);
  assert.equal(L.BRIDGE_ITEM_GAS, lim.bridgeItemGas);
  assert.equal(L.MAX_SHARD_DEPTH, lim.shardDepthMax);
  assert.equal(L.MAX_CBOR_ITEMS, lim.cborItems);
});

test('the shared gate prices its components exactly as the oracle and the contract do', () => {
  assert.equal(rsmtGas(L.MAX_RSMT_SIBLINGS), 28_810);
  // 21000 + 16*D_max + 80*B_env with D_max = 4 + 128 + pad32(B_cfg) + pad32(B_env)
  assert.equal(intrinsicGas(512, L.MAX_ENVELOPE_BYTES), 21_000 + 16 * (132 + 512 + 65_536) + 80 * 65_536);
  assert.equal(intrinsicGas(513, 100), 21_000 + 16 * (132 + 544 + 128) + 80 * 100, 'both lengths are padded to words');
  assert.equal(b2Gas(kernelRequestBytes(L.MAX_SEMANTIC_BYTES, L.MAX_SEMANTIC_BYTES), L.MAX_LEAVES), 908_560);
  assert.equal(itemGas(L.BRIDGE_CBOR_ITEMS), 4_096_000);
  // G_batch = 60000 + 16*C + 500*K*(K-1) + 1100 + 29900*E + 6000*Q + 2000*A + 250*P
  const n = { k: 3, c: 1000, e: 2, s: 2, q: 8, a: 3, p: 7, items: 0 };
  assert.equal(batchGas(n), 60_000 + 16_000 + 500 * 6 + 1_100 + 2 * 29_900 + 8 * 6_000 + 3 * 2_000 + 7 * 250);
  assert.ok(L.MAX_ANCHORS * (1 + L.MAX_UNICITY_STEPS) + L.MAX_LEAVES * L.MAX_RSMT_SIBLINGS <= L.MAX_PATH_STEPS, 'the cumulative step bound cannot bind');
});

test('the best-case projection fits at the bounds with ONE anchor', () => {
  const fit = projectedGate(300, 150, L.MAX_LEAVES, L.MAX_SEMANTIC_BYTES);
  assert.ok(fit.gate.total <= L.TX_GAS_BUDGET, String(fit.gate.total));
  assert.ok(fit.envelopeBytes <= L.MAX_ENVELOPE_BYTES, String(fit.envelopeBytes));
  assert.equal(fit.gate.grouping.k, 1, 'a single certificate may serve every leaf: the best case is never one anchor per shard');
});

test('the burn preflight refuses a history within BURN_HISTORY_BYTES of the bound and a best case the gate cannot pass', () => {
  const edge = L.MAX_SEMANTIC_BYTES - BURN_HISTORY_BYTES;
  assert.ok(checkBurnProjection(200, 300, L.MAX_LEAVES, edge).total <= L.TX_GAS_BUDGET, 'exactly at the margin passes');
  throwsReason(() => checkBurnProjection(200, 300, L.MAX_LEAVES, edge + 1), 'ErrInputTooLarge');
  assert.ok(checkBurnProjection(200, 300, 8, 500).total <= L.TX_GAS_BUDGET);
});
