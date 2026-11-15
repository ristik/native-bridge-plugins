/** The v2 verifier, segment, journal and preflight modules have no network or filesystem capability; only the adapters do. */
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'src', 'nb2');
/** The network adapters: the gateway client and the SDK aggregator client. Nothing else may reach the network. */
const ADAPTERS = new Set(['rpc.ts', 'aggregator.ts', 'index.ts']);

test('nb2 sources outside the adapters contain no network or filesystem capability', () => {
  const banned = ['fetch(', 'XMLHttpRequest', 'WebSocket', 'node:http', 'node:https', 'node:net', 'node:dgram', 'node:fs', 'node:child_process', 'process.env', 'AggregatorClient', 'http://', 'https://'];
  const files = readdirSync(SRC).filter((f) => f.endsWith('.ts') && !ADAPTERS.has(f));
  assert.ok(files.length >= 15);
  for (const f of files) {
    const text = readFileSync(path.join(SRC, f), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const b of banned) assert.ok(!text.includes(b), `${f} mentions ${b}`);
    for (const a of ['./rpc.js', './aggregator.js']) if (f !== 'bridge.ts') assert.ok(!text.includes(`from '${a}'`), `${f} imports the adapter ${a}`);
  }
});
