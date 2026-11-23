import assert from 'node:assert/strict';
import { test } from 'node:test';
import { NativeBridgeV2, type ProofRecoveryOptions, type ReturnAdmission } from '../../src/nb2/bridge.js';
import { depositCalldata } from '../../src/nb2/abi.js';
import { firstOwnerOf } from '../../src/nb2/deposit.js';
import { Nb2Error } from '../../src/nb2/errors.js';
import { signTx } from '../../src/nb2/evm.js';
import { hex } from '../../src/nb2/journal.js';
import { MAX_MINT_PROOF } from '../../src/nb2/token.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { SealAheadOfOrigin } from '../../src/nb2/trust.js';
import { framedProof, successor, withSeal, withoutQuorum } from './certification-fixtures.js';
import { evmAccount, FakeAggregator, key, roundAtLeast, roundNow, setup } from './world.js';

function ahead(error: unknown): boolean {
  for (let cause = error; cause instanceof Nb2Error; cause = cause.inner) {
    if (cause instanceof SealAheadOfOrigin) return true;
  }
  return false;
}

async function laggingFeed() {
  const w = await setup();
  const opts = w.options('moving certification');
  const owner = localOwner(key('owner'));
  const payer = evmAccount(w.chain, 'payer');
  const boot = await NativeBridgeV2.open(opts);
  const { intent } = await boot.planDeposit(8n, owner.publicKey);
  await boot.submitDeposit(intent, payer);
  await boot.collectDepositProof(intent);

  let originRound = roundNow();
  const trust = () => w.root.trust.withAuthenticatedOrigin({ usableEpoch: 1n, rootRound: originRound });
  const agg = new FakeAggregator(w.root, true);
  const open = () => NativeBridgeV2.open({ ...opts, trust: trust(),
    aggregator: { certify: (request) => {
      // Even repeated requests get a new proof, always ahead of the feed.
      roundAtLeast(originRound + 19n);
      return agg.certify(request);
    } },
    refreshTrust: async () => { originRound += 5n; return trust(); },
  });
  return { open, agg, intent, owner, payer };
}

async function untilCovered<T>(run: () => Promise<T>): Promise<T> {
  for (let attempts = 0; attempts < 12; attempts++) {
    try { return await run(); } catch (error) { if (!ahead(error)) throw error; }
  }
  throw new Error('origin never caught a fixed proof');
}

test('Mint persists the exact proof and a reloaded wallet catches it instead of chasing newer proofs', async () => {
  const { open, agg, intent } = await laggingFeed();
  const first = await open();
  await assert.rejects(first.mint(intent), ahead);
  const pending = await first.journal.deposit(intent);
  assert.equal(pending?.status, 'proven');
  assert.ok(pending.mintProof, 'certified substate is durable');
  assert.equal(pending.token, undefined, 'only verified tokens are spendable');
  const resumed = await open();
  assert.deepEqual(await resumed.journal.deposit(intent), pending);
  const token = await untilCovered(() => resumed.mint(intent));
  assert.equal((await resumed.verifyToken(token)).amount, 8n);
  assert.deepEqual(await resumed.mint(intent), token);
  assert.equal(agg.calls, 1);
  assert.equal((await resumed.journal.deposit(intent))?.status, 'minted');
});

test('transfer, split burn and child mint, and return burn also keep their proofs across retries', async () => {
  const { open, agg, intent, owner, payer } = await laggingFeed();
  const bridge = await open();
  const root = await untilCovered(() => bridge.mint(intent));
  const recipient = localOwner(key('recipient'));
  await assert.rejects(bridge.transfer(root, owner, recipient.publicKey), ahead);
  const resumed = await open();
  const transferred = await untilCovered(() => resumed.transfer(root, owner, recipient.publicKey));
  assert.equal(agg.calls, 2);
  const children = await untilCovered(() => resumed.split(transferred, recipient, [{ ownerKey: recipient.publicKey, amount: 8n }]));
  assert.equal(agg.calls, 4);
  const plan = await resumed.planReturn(children[0], payer.address, payer.address);
  const { burned } = await untilCovered(() => resumed.burn(plan.returnId, recipient));
  assert.ok(burned.length > 0);
  assert.equal(agg.calls, 5);
});

test('Mint recovery replaces a future seal only with a verified proof of the same request', async () => {
  const w = await setup();
  const opts = w.options('mint recovery');
  const owner = localOwner(key('mint recovery owner'));
  let serveHealthy = false;
  let request: Uint8Array | undefined;
  let attempts = 0;
  const open = () => NativeBridgeV2.open({ ...opts, aggregator: { certify: async (cd) => {
    if (request) assert.deepEqual(cd, request);
    request ??= cd.slice();
    attempts++;
    const proof = await w.agg.certify(cd);
    return serveHealthy ? proof : withoutQuorum(proof, w.root, attempts === 1);
  } } });
  const first = await open();
  const { intent } = await first.planDeposit(8n, owner.publicKey);
  await first.submitDeposit(intent, evmAccount(w.chain, 'mint recovery payer'));
  await first.collectDepositProof(intent);
  await assert.rejects(first.mint(intent), ahead);
  const candidate = await first.journal.deposit(intent);
  const resumed = await open();
  await assert.rejects(resumed.mint(intent), ahead);
  assert.equal(attempts, 1);
  await assert.rejects(resumed.mint(intent, { recoverProof: true }), { rule: 'QuorumNotMet' });
  assert.deepEqual(await resumed.journal.deposit(intent), candidate);
  serveHealthy = true;
  assert.equal((await resumed.verifyToken(await resumed.mint(intent, { recoverProof: true }))).amount, 8n);
  assert.equal(attempts, 3);
});

test('after a structural refusal Mint retains the next valid but ahead proof across reload', async () => {
  const w = await setup();
  const opts = w.options('replacement catch-up');
  const boot = await NativeBridgeV2.open(opts);
  const { intent } = await boot.planDeposit(8n, localOwner(key('replacement owner')).publicKey);
  await boot.submitDeposit(intent, evmAccount(w.chain, 'replacement payer'));
  await boot.collectDepositProof(intent);
  let origin = roundNow();
  let calls = 0;
  let request: Uint8Array | undefined;
  let replacement: Uint8Array | undefined;
  const moving = new FakeAggregator(w.root, true);
  const open = () => NativeBridgeV2.open({ ...opts, trust: w.root.trust.withAuthenticatedOrigin({ usableEpoch: 1n, rootRound: origin }),
    aggregator: { certify: async (cd) => {
      if (request) assert.deepEqual(cd, request);
      request ??= cd.slice();
      if (++calls === 1) return framedProof(cd, 512);
      roundAtLeast(origin + 4n);
      replacement = await moving.certify(cd);
      return replacement;
    } },
  });
  const first = await open();
  await assert.rejects(first.mint(intent), { rule: 'Length' });
  assert.ok((await first.journal.deposit(intent))?.mintProof);
  await assert.rejects(first.mint(intent), ahead);
  const resumed = await open();
  const pending = await resumed.journal.deposit(intent);
  assert.equal(pending?.mintProof, hex(replacement!));
  assert.equal(pending?.status, 'proven');
  assert.equal(pending?.token, undefined);
  await assert.rejects(resumed.mint(intent), ahead);
  assert.equal(calls, 2);
  origin = roundNow();
  const caughtUp = await open();
  assert.equal((await caughtUp.verifyToken(await caughtUp.mint(intent))).amount, 8n);
  assert.equal(calls, 2);
});

test('Mint retains a replacement missing a UTB epoch, refreshes, and resumes it after reload', async () => {
  const w = await setup();
  const opts = w.options('replacement missing epoch');
  const boot = await NativeBridgeV2.open(opts);
  const { intent } = await boot.planDeposit(8n, localOwner(key('missing epoch owner')).publicKey);
  await boot.submitDeposit(intent, evmAccount(w.chain, 'missing epoch payer'));
  await boot.collectDepositProof(intent);
  const start = roundNow() + 1n;
  const next = await successor(w.root, start);
  const origin = { ...w.root.trust.origin!, usableEpoch: 2n };
  let calls = 0;
  let refreshes = 0;
  let available = false;
  let request: Uint8Array | undefined;
  let pendingProof: string | undefined;
  const open = (trust = w.root.trust.withAuthenticatedOrigin(origin)) => NativeBridgeV2.open({ ...opts, trust,
    aggregator: { certify: async (cd) => {
      if (request) assert.deepEqual(cd, request);
      request ??= cd.slice();
      if (++calls === 1) return framedProof(cd, 512);
      const proof = await withSeal(await w.agg.certify(cd), next, start + 1n, next.signers.length, 2n);
      pendingProof = hex(proof);
      return proof;
    } },
    refreshTrust: async () => {
      refreshes++;
      const record = await boot.journal.deposit(intent);
      assert.ok(pendingProof);
      assert.equal(record?.mintProof, pendingProof);
      assert.equal(record?.status, 'proven');
      assert.equal(record?.token, undefined);
      return available ? next.trust.withAuthenticatedOrigin(origin) : undefined;
    },
  });
  const first = await open(w.root.trust);
  await assert.rejects(first.mint(intent), { rule: 'Length' });
  const waiting = await open();
  await assert.rejects(waiting.mint(intent), (error: unknown) =>
    error instanceof Nb2Error && error.rule === 'NoEntryForEpoch' && error.inner?.rule === 'DepositUC');
  assert.equal(refreshes, 1);
  const resumed = await open();
  assert.equal((await resumed.journal.deposit(intent))?.mintProof, pendingProof);
  available = true;
  assert.equal((await resumed.verifyToken(await resumed.mint(intent))).amount, 8n);
  assert.equal(refreshes, 2);
  assert.equal(calls, 2);
});

for (const operation of ['extra mint', 'transfer', 'split burn', 'split child', 'return burn'] as const) {
  test(`${operation} can recover the exact request from an unusable future seal`, async () => {
    const w = await setup();
    const opts = w.options(`recover ${operation}`);
    const boot = await NativeBridgeV2.open(opts);
    const owner = localOwner(key(`owner ${operation}`));
    const recipient = localOwner(key(`recipient ${operation}`));
    const payer = evmAccount(w.chain, `payer ${operation}`);
    const deposit = await boot.planDeposit(8n, owner.publicKey);
    await boot.submitDeposit(deposit.intent, payer);
    await boot.collectDepositProof(deposit.intent);
    const source = await boot.mint(deposit.intent);
    if (operation === 'extra mint') {
      const extra = await signTx(payer, {
        chainId: w.cfg.chainId, nonce: BigInt(await w.chain.call<string>('eth_getTransactionCount', [hex(payer.address), 'pending'])),
        maxPriorityFeePerGas: 1n, maxFeePerGas: 15n, gas: 200_000n, to: w.cfg.vault, value: 8n,
        data: depositCalldata(firstOwnerOf(recipient.publicKey), deposit.rho),
      });
      await w.chain.call('eth_sendRawTransaction', [hex(extra.raw)]);
      await boot.recoverDeposits(1n);
    }
    const outputs = [{ ownerKey: recipient.publicKey, amount: 8n }];
    const plan = operation === 'return burn' ? await boot.planReturn(source, payer.address, payer.address) : undefined;
    const poisonAt = operation === 'split child' ? 2 : 1;
    let calls = 0;
    let request: Uint8Array | undefined;
    let hooks = 0;
    let admitCertification = true;
    const admission: ReturnAdmission = { beforeCertification: async (record) => {
      hooks++;
      assert.equal(record.status, 'burn-requested');
      assert.equal(record.burned, undefined);
      assert.equal(record.eta, undefined);
      if (request) assert.equal(record.burnRequest, hex(request));
      if (!admitCertification) throw new Error('certification admission refused');
    } };
    const open = () => NativeBridgeV2.open({ ...opts, aggregator: { certify: async (cd) => {
      const call = ++calls;
      if (call === poisonAt) request = cd.slice();
      if (call === poisonAt + 1) assert.deepEqual(cd, request);
      const good = await w.agg.certify(cd);
      return call === poisonAt ? withoutQuorum(good, w.root, true) : good;
    } } });
    const run = async (bridge: NativeBridgeV2, recovery?: ProofRecoveryOptions) => {
      if (operation === 'extra mint') return bridge.mintExtraDeposit(deposit.intent, 2n, recovery);
      if (operation === 'transfer') return bridge.transfer(source, owner, recipient.publicKey, recovery);
      if (plan) {
        const result = await bridge.burn(plan.returnId, recovery ? undefined : owner, admission, payer.address, recovery);
        assert.equal(result.verdict.amount, 8n);
        assert.deepEqual(result.verdict.recipient, payer.address);
        assert.equal(result.verdict.minSegment, plan.a);
        return result.burned;
      }
      return (await bridge.split(source, owner, outputs, undefined, recovery))[0];
    };
    await assert.rejects(run(await open()), ahead);
    const resumed = await open();
    await assert.rejects(run(resumed), ahead);
    assert.equal(calls, poisonAt);
    if (plan) {
      const saved = await resumed.journal.ret(hex(plan.returnId));
      admitCertification = false;
      await assert.rejects(run(resumed, { recoverProof: true }), /certification admission refused/);
      assert.equal(calls, poisonAt);
      assert.deepEqual(await resumed.journal.ret(hex(plan.returnId)), saved);
      admitCertification = true;
    }
    const verified = await run(resumed, { recoverProof: true });
    if (plan) {
      assert.equal(hooks, 3);
      assert.equal((await resumed.journal.ret(hex(plan.returnId)))?.status, 'burned');
    } else {
      assert.deepEqual((await resumed.verifyToken(verified)).owner, recipient.publicKey);
    }
    assert.equal(calls, poisonAt + (operation === 'split burn' ? 2 : 1));
  });
}

test('Mint checks its proof bound before journaling and allows the exact maximum frame', async () => {
  const w = await setup();
  let size = MAX_MINT_PROOF + 1;
  const bridge = await NativeBridgeV2.open({ ...w.options('mint bound'), aggregator: { certify: async (cd) => framedProof(cd, size) } });
  const { intent } = await bridge.planDeposit(8n, localOwner(key('mint bound owner')).publicKey);
  await bridge.submitDeposit(intent, evmAccount(w.chain, 'mint bound payer'));
  await bridge.collectDepositProof(intent);
  const pending = await bridge.journal.deposit(intent);
  await assert.rejects(bridge.mint(intent), { rule: 'InputTooLarge' });
  assert.deepEqual(await bridge.journal.deposit(intent), pending);
  size--;
  await assert.rejects(bridge.mint(intent), { rule: 'Length' });
  assert.equal(Buffer.from((await bridge.journal.deposit(intent))!.mintProof!.slice(2), 'hex').length, MAX_MINT_PROOF);
});
