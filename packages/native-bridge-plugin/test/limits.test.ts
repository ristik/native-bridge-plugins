import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { b2Gas, intrinsicGas, kernelRequestBytes, projectedGate, rsmtGas, ucGas } from '../src/gas.js';
import * as L from '../src/limits.js';

const PROFILE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'protocol', 'profile-v3.json');

test('the named bounds are the limits of profile-v3.json, the one source of the contract, oracle and plug-ins', () => {
  const lim = (JSON.parse(readFileSync(PROFILE, 'utf8')) as { limits: Record<string, number> }).limits;
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
});

test('the shared gate prices the worst admitted bundle exactly as the oracle and the contract do', () => {
  // The numbers of bft-core `TestWorstAdmittedBundleFitsBudget` and the contract's `BridgeBounds`.
  assert.equal(ucGas(1, L.MAX_ANCHOR_UC_BYTES, L.MAX_SIGNATURES, 1 + L.MAX_UNICITY_STEPS), 1_768_798);
  assert.equal(rsmtGas(L.MAX_RSMT_SIBLINGS), 28_810);
  assert.equal(intrinsicGas(L.MAX_ENVELOPE_BYTES), 1_069_576);
  assert.equal(b2Gas(kernelRequestBytes(L.MAX_SEMANTIC_BYTES, L.MAX_SEMANTIC_BYTES), L.MAX_LEAVES), 908_560);
  const worst = intrinsicGas(L.MAX_ENVELOPE_BYTES) + b2Gas(kernelRequestBytes(L.MAX_SEMANTIC_BYTES, L.MAX_SEMANTIC_BYTES), L.MAX_LEAVES) +
    L.MAX_ANCHORS * ucGas(1, L.MAX_ANCHOR_UC_BYTES, L.MAX_SIGNATURES, 1 + L.MAX_UNICITY_STEPS) + L.MAX_LEAVES * rsmtGas(L.MAX_RSMT_SIBLINGS) + L.GAS_RESERVE;
  assert.equal(worst, 6_976_692);
  assert.ok(worst <= L.TX_GAS_BUDGET);
  assert.ok(L.MAX_ANCHORS * (1 + L.MAX_UNICITY_STEPS) + L.MAX_LEAVES * L.MAX_RSMT_SIBLINGS <= L.MAX_PATH_STEPS, 'the cumulative step bound cannot bind');
});

test('a burn-time projection at the bounds fits, and one leaf more does not exist', () => {
  const fit = projectedGate(300, 150, 2, L.MAX_LEAVES, L.MAX_SEMANTIC_BYTES);
  assert.ok(fit.gate.total <= L.TX_GAS_BUDGET, String(fit.gate.total));
  assert.ok(fit.envelopeBytes <= L.MAX_ENVELOPE_BYTES, String(fit.envelopeBytes));
});
