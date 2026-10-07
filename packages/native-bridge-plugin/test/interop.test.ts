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

test('native Go PDR encoding and both hash preimages match independent construction', async () => {
  const f = JSON.parse(readFileSync(path.join(path.dirname(FILE), 'native-pdr.json'), 'utf8'));
  const { pdrBytes, pdrConfigHash } = await import('./world.js');
  const { configHashOfPdr } = await import('../src/lockproof.js');
  const { H } = await import('../src/profile.js');
  const { pdrElements } = await import('../src/scan.js');
  const { toHex } = await import('../src/bytes.js');
  const native = fromHex(f.native)!;
  assert.deepEqual(pdrBytes(5n, 0n), native);
  assert.equal(toHex(H(native)), f.fullHash);
  assert.equal(toHex(H(fromHex(f.neutralized)!)), f.configHash);
  assert.equal(toHex(pdrConfigHash()), f.configHash);
  assert.equal(toHex(configHashOfPdr(native)), f.configHash);
  assert.throws(() => pdrElements(native.subarray(3)), { reason: 'ErrShape' });
  const wrongTag = native.slice(); wrongTag[2] ^= 1;
  assert.throws(() => pdrElements(wrongTag), { reason: 'ErrTag' });
});
