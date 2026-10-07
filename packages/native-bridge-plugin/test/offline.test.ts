import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { test } from 'node:test';

import { buildToken, makeWorld, spec, txStep } from './world.js';

const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

test('verifier sources contain no network or filesystem capability', () => {
  const banned = ['fetch(', 'XMLHttpRequest', 'WebSocket', 'node:http', 'node:https', 'node:net', 'node:dgram', 'node:fs', 'node:child_process', 'process.env', 'http://', 'https://'];
  for (const f of readdirSync(SRC)) {
    const text = readFileSync(path.join(SRC, f), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const b of banned) assert.ok(!text.includes(b), `${f} mentions ${b}`);
  }
});

test('receipt verification succeeds with the network disabled', async (t) => {
  if (process.env.NBP_NO_NET_CHILD) {
    const w = makeWorld();
    const out = await buildToken(w, spec(1), [txStep(2, 7, 1_700_000_050n)], 1_700_000_040n, 1_700_000_900n);
    await w.bridge.verifyNativeTokenBytes(out.bytes, 'receipt');
    const net = await import('node:net');
    const denied = await new Promise<boolean>((resolve) => {
      const s = net.connect(9, '127.0.0.1');
      s.on('error', () => resolve(true));
      s.on('connect', () => { s.destroy(); resolve(false); });
    });
    assert.ok(denied, 'sandbox must deny networking');
    return;
  }
  let cmd: string[] | null = null;
  if (process.platform === 'darwin' && existsSync('/usr/bin/sandbox-exec')) {
    cmd = ['/usr/bin/sandbox-exec', '-p', '(version 1)(allow default)(deny network*)'];
  } else if (process.platform === 'linux' && spawnSync('unshare', ['-rn', 'true']).status === 0) {
    cmd = ['unshare', '-rn'];
  }
  if (!cmd) {
    t.skip('no network sandbox available on this platform; the source scan covers it');
    return;
  }
  const r = spawnSync(cmd[0], [...cmd.slice(1), process.execPath, '--import', 'tsx', '--test', '--test-name-pattern=network disabled', fileURLToPath(import.meta.url)], {
    env: { ...process.env, NBP_NO_NET_CHILD: '1' }, encoding: 'utf8',
  });
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
});
