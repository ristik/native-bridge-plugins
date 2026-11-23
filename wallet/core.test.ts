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
import { revertData } from '../packages/native-bridge-plugin/src/nb2/abi.js';
import { Nb2Error } from '../packages/native-bridge-plugin/src/nb2/errors.js';
import { RpcError } from '../packages/native-bridge-plugin/src/nb2/rpc.js';
import { MAX_TRANSFER_PAIR } from '../packages/native-bridge-plugin/src/nb2/token.js';
import { type Aggregator } from '../packages/native-bridge-plugin/src/nb2/tokenops.js';
import { SealAheadOfOrigin } from '../packages/native-bridge-plugin/src/nb2/trust.js';
import { framedProof, withSeal, withoutQuorum } from '../packages/native-bridge-plugin/test/nb2/certification-fixtures.js';
import { WORLD_GAS, key, setup } from '../packages/native-bridge-plugin/test/nb2/world.js';
import { REGISTRY_LAG_MS, RegistryLagExpired, Wallet, burn, connectionOf, io, lockWallet, mint, planDeposit, planReturn, redeem, sendDeposit, split, transfer, type WalletConfig } from './core.js';

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
  writeFileSync(join(pub, 'nb2-release.json'), JSON.stringify({ pins, trust: { bundle: 'trust-base.bundle.cbor', origin: { usableEpoch: '1', rootRound: '1000000' } } }));
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

test('transfer: a retained proof survives an origin lag and a CLI reopen', async (t) => {
  const x = await withCoin();
  const before = x.agg.submitted;
  const verify = x.w.bridge.verifyToken.bind(x.w.bridge);
  let verifications = 0;
  t.mock.method(x.w.bridge, 'verifyToken', async (token: Uint8Array) => {
    if (++verifications === 2) throw new SealAheadOfOrigin();
    return verify(token);
  });
  await assert.rejects(transfer(x.w, 'coin', 'coin2', 1), SealAheadOfOrigin);
  const pending = JSON.parse(readFileSync(join(x.dir, 'tokens', 'coin2.pending.json'), 'utf8'));
  assert.match(pending.proof, /^0x[0-9a-f]+$/);
  const again = await x.openAt();
  assert.equal((await again.bridge.verifyToken(await transfer(again, 'coin', 'coin2', 1))).amount, 10n);
  assert.equal(x.agg.submitted, before + 1);
});

test('transfer: explicit recovery preserves an ahead candidate until a healthy proof verifies', async (t) => {
  const x = await withCoin();
  const certify = x.agg.certify.bind(x.agg);
  let request: Uint8Array | undefined;
  let healthy = false;
  const before = x.agg.submitted;
  t.mock.method(x.agg, 'certify', async (cd: Uint8Array) => {
    if (request) assert.deepEqual(cd, request);
    request ??= cd.slice();
    const proof = await certify(cd);
    return healthy ? proof : withoutQuorum(proof, x.root, x.agg.submitted === before + 1);
  });
  const path = x.w.pendingFile('coin2');
  t.mock.method(x.w, 'refreshAuthority', async () => x.w.trust);
  await assert.rejects(transfer(x.w, 'coin', 'coin2', 1), SealAheadOfOrigin);
  const pending = readFileSync(path, 'utf8');
  const resumed = await x.openAt();
  t.mock.method(resumed, 'refreshAuthority', async () => resumed.trust);
  await assert.rejects(transfer(resumed, 'coin', 'coin2', 1), SealAheadOfOrigin);
  assert.equal(x.agg.submitted, before + 1);
  await assert.rejects(transfer(resumed, 'coin', 'coin2', 1, undefined, true), { rule: 'QuorumNotMet' });
  assert.equal(readFileSync(path, 'utf8'), pending);
  healthy = true;
  const token = await transfer(resumed, 'coin', 'coin2', 1, undefined, true);
  assert.equal((await resumed.bridge.verifyToken(token)).amount, 10n);
  assert.equal(x.agg.submitted, before + 3);
});

test('transfer: a rejected saved proof is replaced by a fixed ahead candidate across reopen', async (t) => {
  const x = await withCoin();
  const certify = x.agg.certify.bind(x.agg);
  const origin = x.w.trust.origin!;
  let calls = 0;
  let request: Uint8Array | undefined;
  let replacement: Uint8Array | undefined;
  t.mock.method(x.agg, 'certify', async (cd: Uint8Array) => {
    if (request) assert.deepEqual(cd, request);
    request ??= cd.slice();
    if (++calls === 1) return framedProof(cd, 512);
    replacement = await withSeal(await certify(cd), x.root, origin.rootRound + BigInt(calls) + 3n, x.root.signers.length);
    return replacement;
  });
  await assert.rejects(transfer(x.w, 'coin', 'coin2', 1), { rule: 'Length' });
  await assert.rejects(transfer(x.w, 'coin', 'coin2', 1), SealAheadOfOrigin);
  const path = x.w.pendingFile('coin2');
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).proof, hex(replacement!));
  const resumed = await x.openAt();
  t.mock.method(resumed, 'refreshAuthority', async () => resumed.trust);
  await assert.rejects(transfer(resumed, 'coin', 'coin2', 1), SealAheadOfOrigin);
  assert.equal(calls, 2);
  await resumed.persistAuthority(resumed.trust.withAuthenticatedOrigin({ ...origin, rootRound: origin.rootRound + 5n }));
  const caughtUp = await x.openAt();
  const token = await transfer(caughtUp, 'coin', 'coin2', 1);
  assert.equal((await caughtUp.bridge.verifyToken(token)).amount, 10n);
  assert.equal(calls, 2);
});

test('transfer: overflow leaves the pending file unchanged and the maximum pair fits', async (t) => {
  const x = await withCoin();
  const path = x.w.pendingFile('coin2');
  let overflow = true;
  let pending = '';
  let txBytes = 0;
  t.mock.method(x.agg, 'certify', async (cd: Uint8Array) => {
    pending = readFileSync(path, 'utf8');
    txBytes = Buffer.from(JSON.parse(pending).tx.slice(2), 'hex').length;
    return framedProof(cd, MAX_TRANSFER_PAIR - 1 - txBytes + Number(overflow));
  });
  await assert.rejects(transfer(x.w, 'coin', 'coin2', 1), { rule: 'InputTooLarge' });
  assert.equal(readFileSync(path, 'utf8'), pending);
  overflow = false;
  await assert.rejects(transfer(x.w, 'coin', 'coin2', 1), { rule: 'Length' });
  const proof = JSON.parse(readFileSync(path, 'utf8')).proof;
  assert.equal(1 + txBytes + Buffer.from(proof.slice(2), 'hex').length, MAX_TRANSFER_PAIR);
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

test('redeem waits out a possible seal import lag before sending once', async () => {
  const { w, chain } = await withCoin();
  await burn(w, 'coin');
  const rpc = chain.call.bind(chain);
  const refusal = hex(revertData('VerifierRefused', revertData('QuorumNotMet')));
  let firstEstimate = true;
  let sends = 0;
  chain.call = async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_sendRawTransaction') sends++;
    if (method === 'eth_estimateGas' && firstEstimate) {
      firstEstimate = false;
      throw new RpcError(200, 3, 'execution reverted', refusal);
    }
    return rpc<T>(method, params);
  };
  const notes: string[] = [];
  assert.equal((await redeem(w, 'coin', 0, 0, (note) => {
    assert.equal(sends, 0);
    notes.push(note);
  })).state, 'paid');
  assert.equal(notes.length, 1);
  assert.match(notes[0], /possible seal registry lag/);
  assert.equal(sends, 1);
});

test('redeem opens no retry at the registry wait deadline', async (t) => {
  const { w } = await withCoin();
  await burn(w, 'coin');
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 0 });
  t.mock.method(performance, 'now', () => Date.now());

  const refusal = new Nb2Error('VerifierRefused', undefined, undefined, new Nb2Error('QuorumNotMet'));
  const attempts: number[] = [];
  t.mock.method(w.bridge, 'submitRedeem', async () => {
    attempts.push(Date.now());
    throw refusal;
  });
  let onWait!: () => void;
  const waiting = new Promise<void>((resolve) => { onWait = resolve; });
  const result = assert.rejects(redeem(w, 'coin', 0, REGISTRY_LAG_MS + 1000, onWait),
    (e) => e instanceof RegistryLagExpired && e.refusal === refusal);
  await waiting;
  t.mock.timers.tick(REGISTRY_LAG_MS);
  await result;
  assert.deepEqual(attempts, [0]);
});
