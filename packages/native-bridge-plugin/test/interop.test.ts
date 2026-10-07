import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { fromHex } from '../src/bytes.js';
import { generate } from '../scripts/gen-fixtures.js';
import { makeWorld } from './world.js';

const FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'tests', 'interop', 'fixtures.json');

test('the committed fixtures are exactly what the TypeScript constructors generate', async () => {
  const committed = JSON.parse(readFileSync(FILE, 'utf8'));
  const fresh = JSON.parse(JSON.stringify(await generate()));
  assert.deepEqual(fresh, committed);
});

test('every fixture replays to its recorded verdict', async () => {
  const f = JSON.parse(readFileSync(FILE, 'utf8')) as { cases: { name: string; expect: 'receipt' | 'return'; result: string; token: string }[] };
  const w = makeWorld();
  for (const c of f.cases) {
    let got = 'ok';
    try {
      await w.bridge.verifyNativeTokenBytes(fromHex(c.token)!, c.expect);
    } catch (e) {
      got = (e as { reason?: string }).reason ?? String(e);
    }
    assert.equal(got, c.result, c.name);
  }
});
