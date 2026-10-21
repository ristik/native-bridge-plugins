import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { fromHex } from '../src/bytes.js';
import { checkPolicyBody, decodeEnvelope, planAnchors } from '../src/envelope.js';
import { composeGas, computeGate, kernelRequestBytes, projectedGate } from '../src/gas.js';
import { COMPOSE_OUTPUT_BYTES, COMPOSE_STATUS, composeInput, composeOutputStatus, composeStatusName } from '../src/compose.js';
import { NativeError } from '../src/errors.js';
import { cfgBytes, decodeCfg, decodePolicy } from '../src/profile.js';

/** The released protocol-4 corpus (`protocol/vectors`), replayed by an implementation independent of the Go oracle that generated it. */
const VECTORS = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'protocol', 'vectors');

interface Case {
  id: string;
  op: string;
  cfg?: string;
  input: string;
  aux?: Record<string, string>;
  expected: { status: 'ok' | 'error' | 'halt'; family?: string; reason?: string; output?: string; values?: Record<string, string> };
}

const load = (rel: string): any => JSON.parse(readFileSync(path.join(VECTORS, rel), 'utf8'));
const cfgOf = (name: string): ReturnType<typeof decodeCfg> => decodeCfg(fromHex(load('config/fixtures.json').fixtures[name].cfg)!);

function replay(c: Case, run: () => void): void {
  let got: { status: 'ok' | 'error'; family?: string; reason?: string } = { status: 'ok' };
  try {
    run();
  } catch (e) {
    if (!(e instanceof NativeError)) throw e;
    got = { status: 'error', family: e.family, reason: e.reason };
  }
  assert.deepEqual(got, c.expected.status === 'ok' ? { status: 'ok' } : { status: 'error', family: c.expected.family, reason: c.expected.reason }, c.id);
}

test('policy family: every partition-policy body decodes or is refused with the corpus verdict', () => {
  const cases = (load('policy/cases.json').cases as Case[]).filter((c) => c.op === 'policy-decode');
  assert.ok(cases.length >= 13);
  for (const c of cases) replay(c, () => void decodePolicy(fromHex(c.input)!));
});

test('policy family: every envelope is framed, its policy opened and its anchor table planned as the corpus says', () => {
  const cases = (load('policy/cases.json').cases as Case[]).filter((c) => c.op === 'envelope-policy');
  assert.ok(cases.length >= 49);
  for (const c of cases) {
    replay(c, () => {
      const cfg = cfgOf(c.cfg!);
      const env = decodeEnvelope(fromHex(c.input)!);
      const pol = checkPolicyBody(cfg, env);
      const sids = (c.aux?.sids ?? '').split(',').filter((x) => x !== '').map((x) => fromHex(x)!);
      planAnchors(pol, env, sids);
    });
  }
});

test('proof family: the gas estimate of every published envelope is the oracle\'s, component by component', () => {
  const cases = (load('proof/cases.json').cases as Case[]).filter((c) => c.op === 'gate');
  assert.ok(cases.length >= 14);
  for (const c of cases) {
    let values: Record<string, string> | undefined;
    replay(c, () => {
      const cfg = cfgOf(c.cfg!);
      const cfgRaw = cfgBytes(cfg);
      const env = decodeEnvelope(fromHex(c.input)!);
      checkPolicyBody(cfg, env);
      const encodedLen = c.input.length / 2;
      const g = computeGate(cfgRaw, encodedLen, kernelRequestBytes(cfgRaw.length, env.history.length), env);
      values = {
        b2: String(g.b2), batch: String(g.batch), intrinsic: String(g.intrinsic), items: String(g.items), j: String(g.j),
        rsmt: String(g.rsmt), steps: String(g.steps), total: String(g.legacyTotal),
      };
    });
    if (c.expected.status === 'ok') assert.deepEqual(values, c.expected.values, c.id);
  }
});

test('the burn-time projection with K anchors under one seal is a lower bound of every consolidated bundle of the corpus', () => {
  const cases = (load('proof/cases.json').cases as Case[]).filter((c) => c.op === 'gate' && /^gate-consolidated-m\d+-n\d+$/.test(c.id));
  assert.equal(cases.length, 8, 'm in {1,2,4,8} x committee {4,16}');
  for (const c of cases) {
    const cfg = cfgOf(c.cfg!);
    const env = decodeEnvelope(fromHex(c.input)!);
    const k = env.anchors.length;
    const leaves = env.leafProofs.length;
    const exact = BigInt(c.expected.values!.total);
    const best = projectedGate(cfgBytes(cfg).length, env.policyBody.length, leaves, env.history.length, k).gate.legacyTotal;
    const one = projectedGate(cfgBytes(cfg).length, env.policyBody.length, leaves, env.history.length).gate.legacyTotal;
    assert.ok(BigInt(best) <= exact, `${c.id}: projection ${best} above the bundle's gate ${exact}`);
    if (k > 1) assert.ok(best > one, `${c.id}: ${k} anchors project above one`);
    // more anchors than leaves cannot occur: the projection caps K at L
    assert.equal(projectedGate(cfgBytes(cfg).length, env.policyBody.length, leaves, env.history.length, leaves + 5).gate.legacyTotal,
      projectedGate(cfgBytes(cfg).length, env.policyBody.length, leaves, env.history.length, leaves).gate.legacyTotal);
  }
});

test('no gas ceiling (owner section 36): a bundle estimated above the former 7,000,000 is estimated, not refused', () => {
  const c = (load('proof/cases.json').cases as Case[]).find((x) => x.id === 'gate-compose-leaves-max-two-anchors')!;
  assert.equal(c.expected.status, 'ok');
  const cfgRaw = cfgBytes(cfgOf(c.cfg!));
  const env = decodeEnvelope(fromHex(c.input)!);
  const g = computeGate(cfgRaw, c.input.length / 2, kernelRequestBytes(cfgRaw.length, env.history.length), env);
  assert.equal(g.legacyTotal, 7_206_166);
  assert.ok(g.legacyTotal > 7_000_000);
});

test('compose status table: config/compose-status.json is the plug-ins\' append-only table, code 0 ok', () => {
  const table = load('config/compose-status.json') as unknown as { code: number; name: string }[];
  assert.deepEqual(table, ['ok', ...COMPOSE_STATUS].map((name, code) => ({ code, name })));
});

/** abi.encode(uint8 op, bytes cfg, bytes envelope) read back (the corpus input of a native-compose case). */
function readComposeInput(b: Uint8Array): { op: number; cfg: Uint8Array; envelope: Uint8Array } {
  const w = (o: number): number => Number(BigInt('0x' + Buffer.from(b.subarray(o, o + 32)).toString('hex')));
  const field = (off: number): Uint8Array => b.slice(off + 32, off + 32 + w(off));
  return { op: w(0), cfg: field(w(32)), envelope: field(w(64)) };
}

test('native-compose: every case\'s input, output status and, when it succeeds, its gas is the plug-ins\' BRIDGE_COMPOSE_V1 estimate', () => {
  const cases = (load('proof/cases.json').cases as Case[]).filter((c) => c.op === 'native-compose');
  const twins = (load('proof/cases.json').cases as Case[]).filter((c) => c.op === 'compose');
  assert.ok(cases.length >= twins.length + 4, String(cases.length));
  let priced = 0;
  for (const c of cases) {
    const input = fromHex(c.input)!;
    const v = c.expected.values ?? {};
    if (c.expected.status === 'halt') {
      assert.ok(['abi', 'out-of-gas'].includes(v.halt!), c.id);
      continue;
    }
    assert.equal(c.expected.status, 'ok', c.id);
    const { op, cfg, envelope } = readComposeInput(input);
    assert.deepEqual(composeInput(op, cfg, envelope), input, `${c.id}: the canonical three-field input`);
    const out = fromHex(c.expected.output!)!;
    assert.equal(out.length, COMPOSE_OUTPUT_BYTES, c.id);
    assert.equal(String(composeOutputStatus(out)), v.status, c.id);
    assert.equal(composeStatusName(Number(v.status)), v.status === '0' ? 'ok' : v.statusName, c.id); // the corpus names success ''
    if (v.status !== '0') {
      assert.ok(out.subarray(64).every((x) => x === 0), `${c.id}: a status zeroes every result field`);
      continue;
    }
    const env = decodeEnvelope(envelope);
    const g = computeGate(cfg, envelope.length, kernelRequestBytes(cfg.length, env.history.length), env);
    assert.equal(g.compose.b, input.length, `${c.id}: B`);
    assert.equal(String(composeGas(g.compose)), v.gas, `${c.id}: gas`);
    assert.equal(g.native, Number(v.gas));
    priced++;
  }
  assert.ok(priced >= 10, String(priced));
});
