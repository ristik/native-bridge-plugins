import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { fromHex, toHex } from '../src/bytes.js';
import { batchRequest, measure } from '../src/certgroups.js';
import { checkAnchors, checkPolicyBody, decodeEnvelope, planAnchors } from '../src/envelope.js';
import { computeGate, kernelRequestBytes } from '../src/gas.js';
import { decodeCfg } from '../src/profile.js';

/**
 * The token-level vectors of bft-core's b1ref/tokenvec through this projection (acceptance matrix 1b/1c/7e): bft-core's
 * `bridgeprofile/testdata/tokenvec-envelopes.json`, pinned in `tests/tokenvec/pin.json`. Each run is a real lock-backed return token
 * whose leaves are certified by the scenario's anchors (several epochs, a topology change, eight shards before and after
 * consolidation); Go's Compose accepted it and b1ref accepted its batch on the TokenWorld registry. From the kernel's leaves this
 * projection must plan the same anchor table, open every anchor within its leaves' times, and build the same CERT_BATCH_V2 request,
 * grouping and gate. Split semantics are not executed: the kernel refuses a split (bft-core TestTokenvecSplitIsUnsupportedByTheKernel),
 * so the split-* runs are multi-epoch and topology-change histories at the anchor level.
 */
const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'tests', 'tokenvec');

interface Run {
  scenario: string;
  op: number;
  cfg: string;
  envelope: string;
  request: string;
  grouping: { C: number; K: number; E: number; S: number; Q: number; A: number; P: number; Gas: number };
  gate: Record<string, number>;
  leaves: { sid: string; value: string; referenceTime: number }[];
}

function load(): Run[] {
  const pin = JSON.parse(readFileSync(path.join(DIR, 'pin.json'), 'utf8'));
  const raw = readFileSync(path.join(DIR, 'tokenvec-envelopes.json'));
  assert.equal(createHash('sha256').update(raw).digest('hex'), pin.sha256, 'the fixture is the pinned file');
  const f = JSON.parse(raw.toString('utf8'));
  assert.equal(f.format, 'bridgeprofile/tokenvec-envelopes-v1');
  return f.envelopes as Run[];
}

test('tokenvec: every token-level run is planned, opened, batched, grouped and gated as the Go projection did', () => {
  const runs = load();
  assert.deepEqual(runs.map((r) => r.scenario), [
    'split-three-epochs', 'split-across-topology-change', 'consolidated-eight-shards', 'unconsolidated-eight-seals',
    'paired/unconsolidated-eight-seals', 'paired/consolidated-eight-shards',
  ]);
  for (const r of runs) {
    const cfgRaw = fromHex(r.cfg)!;
    const cfg = decodeCfg(cfgRaw);
    const encoded = fromHex(r.envelope)!;
    const env = decodeEnvelope(encoded);
    const pol = checkPolicyBody(cfg, env);
    const plan = planAnchors(pol, env, r.leaves.map((l) => fromHex(l.sid)!));
    assert.deepEqual(plan.leafAnchor, r.leaves.map((_, i) => i), `${r.scenario}: leaf i is certified by anchor i`);
    checkAnchors(env, plan, r.leaves.map((l) => BigInt(l.referenceTime)));
    assert.equal(toHex(batchRequest(env.anchors)), r.request, `${r.scenario}: request`);
    const n = measure(env.anchors);
    assert.deepEqual([n.c, n.k, n.e, n.s, n.q, n.a, n.p], [r.grouping.C, r.grouping.K, r.grouping.E, r.grouping.S, r.grouping.Q, r.grouping.A, r.grouping.P], `${r.scenario}: grouping`);
    const g = computeGate(cfgRaw, encoded.length, kernelRequestBytes(cfgRaw.length, env.history.length), env);
    assert.deepEqual({ b2: g.b2, batch: g.batch, intrinsic: g.intrinsic, items: g.items, j: g.j, rsmt: g.rsmt, steps: g.steps, total: g.legacyTotal },
      { b2: r.gate.b2, batch: r.gate.batch, intrinsic: r.gate.intrinsic, items: r.gate.items, j: r.gate.j, rsmt: r.gate.rsmt, steps: r.gate.steps, total: r.gate.total },
      `${r.scenario}: gate`);
  }
});

test('tokenvec: consolidation changes the anchors and the price, never the token', () => {
  const runs = load();
  const [before, after] = ['paired/unconsolidated-eight-seals', 'paired/consolidated-eight-shards'].map((s) => runs.find((r) => r.scenario === s)!);
  const hb = decodeEnvelope(fromHex(before.envelope)!).history;
  const ha = decodeEnvelope(fromHex(after.envelope)!).history;
  assert.equal(toHex(hb), toHex(ha), 'the same token bytes');
  assert.deepEqual(before.leaves, after.leaves, 'the same state IDs, values and reference times');
  assert.notEqual(before.request, after.request);
  assert.deepEqual([before.grouping.E, before.grouping.S, before.grouping.A], [3, 8, 8]);
  assert.deepEqual([after.grouping.E, after.grouping.S, after.grouping.A], [1, 1, 8]);
  assert.ok(after.gate.total < before.gate.total);
});

test('tokenvec: a leaf moved past its anchor\'s time or out of its shard is refused by this projection too', () => {
  const r = load()[0];
  const cfg = decodeCfg(fromHex(r.cfg)!);
  const env = decodeEnvelope(fromHex(r.envelope)!);
  const pol = checkPolicyBody(cfg, env);
  const sids = r.leaves.map((l) => fromHex(l.sid)!);
  const plan = planAnchors(pol, env, sids);
  const late = r.leaves.map((l) => BigInt(l.referenceTime));
  late[1] += 2n; // one past its anchor's IR time (Go: reference time = IR time - 1)
  assert.throws(() => checkAnchors(env, plan, late), (e: Error & { reason?: string }) => e.reason === 'ErrIRTime');
  const swapped = [sids[1], sids[0], sids[2]];
  assert.throws(() => planAnchors(pol, env, swapped), (e: Error & { reason?: string }) => e.reason === 'ErrPolicyLeafIndex');
});
