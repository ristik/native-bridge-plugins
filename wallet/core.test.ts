/**
 * The reference wallet's core against the plug-in's offline simulator (packages/native-bridge-plugin/test/nb2/world.ts): the transfer
 * journal, the durable store under a power loss, the wallet lock and the installation check at init (the review of nbp#79).
 */
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { toHex } from '../packages/native-bridge-plugin/src/bytes.js';
import { type Aggregator } from '../packages/native-bridge-plugin/src/nb2/tokenops.js';
import { WORLD_GAS, key, setup } from '../packages/native-bridge-plugin/test/nb2/world.js';
import { Wallet, burn, connectionOf, io, lockWallet, mint, planDeposit, planReturn, sendDeposit, split, transfer, type WalletConfig } from './core.js';

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'nb2-wallet-'));
  dirs.push(d);
  return d;
};
const hex = (b: Uint8Array): string => `0x${toHex(b)}`;

/** An aggregator that counts submissions and can lose power right after one is certified. */
class Flaky implements Aggregator {
  public submitted = 0;
  public crashNext = false;
  public onSubmit: (request: Uint8Array) => void = () => undefined;
  public constructor(private readonly inner: Aggregator) {}
  public async certify(request: Uint8Array): Promise<Uint8Array> {
    this.submitted++;
    this.onSubmit(request);
    const p = await this.inner.certify(request);
    if (this.crashNext) {
      this.crashNext = false;
      throw new Error('power lost after certification');
    }
    return p;
  }
}

/** A simulated deployment, its published files, and a wallet directory on it with one minted 10-unit token `coin`. */
async function world(opts: { badCodeHash?: boolean } = {}) {
  const s = await setup();
  const pub = tmp();
  const pins = {
    gamma: hex(s.pins.gamma), build: 'test', vaultRuntimeCodeHash: opts.badCodeHash ? `0x${'11'.repeat(32)}` : hex(s.pins.vaultRuntimeCodeHash),
    maxEncodedTxBytes: 524288, userGasLimit: '60000000', gasReserve: '500000', returnReserveSegments: 64, deploymentBlock: 1, stateReadOnly: false,
  };
  writeFileSync(join(pub, 'nb2-release.json'), JSON.stringify({ pins, trust: { bundle: 'trust-base.bundle.cbor' } }));
  writeFileSync(join(pub, 'trust-base.bundle.cbor'), s.root.bundle);
  writeFileSync(join(pub, 'trust-base.genesis.entryid'), `${hex(s.root.pin)}\n`);
  const config: WalletConfig = connectionOf({ release: join(pub, 'nb2-release.json'), rpc: 'http://127.0.0.1:9/unused' });
  const agg = new Flaky(s.agg);
  const dir = join(tmp(), 'w');
  const secret = key('wallet secret');
  const openAt = (d = dir): Promise<Wallet> => new Wallet(d, secret, config).open({ check: false, lock: false, rpc: s.chain, aggregator: agg, gas: WORLD_GAS });
  return { ...s, config, agg, dir, secret, openAt };
}

async function withCoin() {
  const x = await world();
  const w = await x.openAt();
  x.chain.fund(w.signer.address, 10n ** 24n);
  await planDeposit(w, 'coin', 10n);
  await sendDeposit(w, 'coin');
  await mint(w, 'coin');
  return { ...x, w };
}

test('transfer: an invalid new name is refused before anything is submitted', async () => {
  const { w, agg } = await withCoin();
  const before = agg.submitted;
  for (const bad of ['coin 2', '', '../x', 'a/b']) await assert.rejects(transfer(w, 'coin', bad, 1), /a token name is/);
  assert.equal(agg.submitted, before, 'nothing reached the aggregator');
  assert.equal(w.entry('coin').spent, undefined);
  await transfer(w, 'coin', 'coin2', 1); // the token is still spendable
  assert.equal((await w.bridge.verifyToken(w.token('coin2'))).amount, 10n);
});

test('transfer: an existing name is refused before anything is submitted, and its token is untouched', async () => {
  const { w, agg } = await withCoin();
  await split(w, 'coin', 0, [{ label: 'a', amount: 4n }, { label: 'b', amount: 6n }]);
  const held = readFileSync(join(w.dir, 'tokens', 'b.cbor'));
  const before = agg.submitted;
  await assert.rejects(transfer(w, 'a', 'b', 1), /already has a token named b/);
  await assert.rejects(transfer(w, 'a', 'a', 1), /already has a token named a/);
  assert.equal(agg.submitted, before);
  assert.deepEqual(readFileSync(join(w.dir, 'tokens', 'b.cbor')), held);
  assert.equal(w.entry('a').spent, undefined);
  // a spent token cannot be spent again
  await assert.rejects(transfer(w, 'coin', 'c', 1), /coin is spent \(split into a, b\)/);
});

test('transfer: a crash after certification resumes from the journal with the same request', async () => {
  const x = await withCoin();
  x.agg.crashNext = true;
  await assert.rejects(transfer(x.w, 'coin', 'coin2', 1), /power lost/);
  assert.ok(existsSync(join(x.dir, 'tokens', 'coin2.pending.json')), 'the request was journaled before it was submitted');
  assert.match(x.w.entry('coin').spent ?? '', /transfer pending as coin2/);
  // a new process over the same directory: the same request is certified again (the fake aggregator refuses another one for this
  // state: "already spent by another transaction"), and the token is saved
  const again = await x.openAt();
  await assert.rejects(transfer(again, 'coin', 'other', 1), /coin is spent/);
  await assert.rejects(transfer(again, 'keep', 'coin2', 1), /a transfer of coin to coin2 is pending/);
  const t = await transfer(again, 'coin', 'coin2', 1);
  assert.equal((await again.bridge.verifyToken(t)).amount, 10n);
  assert.equal(again.entry('coin').spent, 'transferred as coin2');
  assert.ok(!existsSync(join(x.dir, 'tokens', 'coin2.pending.json')));
  assert.deepEqual(readFileSync(join(x.dir, 'tokens', 'coin2.cbor')), Buffer.from(t));
});

test('durability: a power loss right after the burn is certified rolls back to a journal that holds the exact burn request', async () => {
  const x = await withCoin();
  // what survives a power loss: each file's content as of its last durable write; every durable write fsyncs the file and the directory
  const disk = new Map<string, string | Uint8Array | null>();
  let fsyncs = 0;
  const real = { ...io };
  io.fsync = (fd) => { fsyncs++; real.fsync(fd); };
  io.durable = (file, data) => { disk.set(file, data); };
  try {
    const plan = await planReturn(x.w, 'coin');
    const id = toHex(plan.returnId);
    let seen: string | undefined;
    x.agg.onSubmit = (request) => {
      // when the aggregator first sees the burn request, it is already on disk as burn-requested, byte for byte
      const j = JSON.parse(String(disk.get(join(x.dir, 'journal.json'))));
      const rec = JSON.parse(j[Object.keys(j).find((k) => k.endsWith(`return/${id}`))!]);
      assert.equal(rec.status, 'burn-requested');
      assert.equal(rec.burnRequest, hex(request));
      seen = rec.burnRequest;
    };
    x.agg.crashNext = true;
    const f0 = fsyncs;
    await assert.rejects(burn(x.w, 'coin'), /power lost/);
    assert.ok(seen, 'the burn reached the aggregator');
    assert.ok(fsyncs - f0 >= 2, 'the journal write fsynced the file and its directory');
    // the power loss: every file back to its last durable content (nothing written after that survives)
    for (const [file, data] of disk) {
      if (data === null) rmSync(file, { force: true });
      else writeFileSync(file, data);
    }
    x.agg.onSubmit = () => undefined;
    const again = await x.openAt();
    const b = await burn(again, 'coin');
    assert.equal(b.plan, null, 'the burn resumed from its journaled request, no new plan');
    assert.ok(b.evidenceBytes > 0);
    assert.equal((await again.returnRecord('coin')).status, 'burned');
  } finally {
    Object.assign(io, real);
  }
});

test('the wallet lock: a live owner refuses, a dead one on this host is taken over, this process re-enters', async () => {
  const d = tmp();
  writeFileSync(join(d, 'lock'), JSON.stringify({ pid: process.ppid, host: hostname(), at: 'then' }));
  assert.throws(() => lockWallet(d), /in use by process/);
  writeFileSync(join(d, 'lock'), JSON.stringify({ pid: 2 ** 22 + 12345, host: hostname(), at: 'then' }));
  lockWallet(d);
  assert.equal(JSON.parse(readFileSync(join(d, 'lock'), 'utf8')).pid, process.pid);
  lockWallet(d); // re-entrant
  writeFileSync(join(d, 'lock'), JSON.stringify({ pid: 1, host: 'another-host', at: 'then' }));
  assert.throws(() => lockWallet(d), /delete .*lock/);
});

test('init: a refused installation check leaves no wallet; a passed one writes the secret (0600) and config.json', async () => {
  const bad = await world({ badCodeHash: true });
  await assert.rejects(Wallet.create(bad.dir, bad.config, () => bad.secret, { lock: false, rpc: bad.chain, aggregator: bad.agg }), /BadDeployment/);
  assert.ok(!existsSync(join(bad.dir, 'config.json')) && !existsSync(join(bad.dir, 'secret.hex')));
  const good = await world();
  const w = await Wallet.create(good.dir, good.config, () => good.secret, { lock: false, rpc: good.chain, aggregator: good.agg, gas: WORLD_GAS });
  assert.equal(statSync(join(good.dir, 'secret.hex')).mode & 0o777, 0o600);
  assert.ok(existsSync(join(good.dir, 'config.json')));
  assert.deepEqual(w.signer.address, Wallet.load(good.dir).signer.address);
  await assert.rejects(Wallet.create(good.dir, good.config, () => good.secret, { lock: false, rpc: good.chain, aggregator: good.agg, gas: WORLD_GAS }), /already a wallet/);
  assert.ok(!readdirSync(good.dir).some((f) => f.endsWith('.tmp')));
});

test('split: a crashed split reserves its part names until it is resumed', async () => {
  const x = await withCoin();
  x.agg.crashNext = true; // the parent's burn is certified, then the process dies
  await assert.rejects(split(x.w, 'coin', 0, [{ label: 'a', amount: 4n }, { label: 'b', amount: 6n }]), /power lost/);
  const again = await x.openAt();
  await assert.rejects(planDeposit(again, 'a', 1n), /a is reserved by the unfinished split of coin/);
  await assert.rejects(transfer(again, 'coin', 'b', 1), /b is reserved by the unfinished split of coin/);
  const [a, b] = await split(again, 'coin', 0, [{ label: 'a', amount: 4n }, { label: 'b', amount: 6n }]);
  assert.equal((await again.bridge.verifyToken(a)).amount, 4n);
  assert.equal((await again.bridge.verifyToken(b)).amount, 6n);
  assert.equal(again.entry('coin').spent, 'split into a, b');
  await planDeposit(again, 'c', 1n); // other names were never reserved
});

test('burn: the token is marked spent before its request is journaled, so a crash leaves nothing that can spend it twice', async () => {
  const x = await withCoin();
  await planReturn(x.w, 'coin');
  x.agg.crashNext = true;
  await assert.rejects(burn(x.w, 'coin'), /power lost/);
  const again = await x.openAt();
  assert.equal((await again.returnRecord('coin')).status, 'burn-requested');
  const before = x.agg.submitted;
  await assert.rejects(transfer(again, 'coin', 'x', 1), /coin is spent \(burn in progress\)/);
  assert.equal(x.agg.submitted, before, 'the transfer submitted nothing');
  const b = await burn(again, 'coin');
  assert.equal(b.plan, null);
  assert.equal(again.entry('coin').spent, 'burned for its return');
});
