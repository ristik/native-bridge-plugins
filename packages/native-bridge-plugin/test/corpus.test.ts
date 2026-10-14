import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { fromHex } from '../src/bytes.js';
import { checkPolicyBody, decodeEnvelope, planAnchors } from '../src/envelope.js';
import { computeGate, kernelRequestBytes } from '../src/gas.js';
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
  expected: { status: 'ok' | 'error'; family?: string; reason?: string; values?: Record<string, string> };
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

test('proof family: the gate of every published envelope is the oracle\'s, component by component, at its exact budget and one less', () => {
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
      const g = computeGate(cfgRaw, encodedLen, kernelRequestBytes(cfgRaw.length, env.history.length), env, c.aux?.budget === undefined ? 7_000_000 : Number(c.aux.budget));
      values = {
        b2: String(g.b2), batch: String(g.batch), intrinsic: String(g.intrinsic), items: String(g.items), j: String(g.j),
        rsmt: String(g.rsmt), steps: String(g.steps), total: String(g.total),
      };
    });
    if (c.expected.status === 'ok') assert.deepEqual(values, c.expected.values, c.id);
  }
});
