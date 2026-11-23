import assert from 'node:assert/strict';
import { test } from 'node:test';
import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { Nb2Error } from '../../src/nb2/errors.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { SealAheadOfOrigin } from '../../src/nb2/trust.js';
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
