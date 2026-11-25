import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeReceiptBacking } from '../../src/nb2/deposit.js';
import { decodeUc } from '../../src/nb2/trust.js';
import { fromHex } from '../../src/bytes.js';
import { IMPORTED_TIP_PROFILE_HASH, NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { successor } from './certification-fixtures.js';
import { evmAccount, key, roundNow, setup } from './world.js';

test('freshness requires a successful coalesced UTB sync and never credits a replay', async () => {
  const w = await setup();
  const opts = w.options('freshness');
  await assert.rejects(NativeBridgeV2.open({ ...opts, unsafeTestTrust: false }), { reason: 'BadDeployment' });
  const first = await NativeBridgeV2.open(opts);
  const { intent } = await first.planDeposit(8n, localOwner(key('fresh owner')).publicKey);
  await first.submitDeposit(intent, evmAccount(w.chain, 'fresh payer'));
  await first.collectDepositProof(intent);
  const token = await first.mint(intent);
  const next = await successor(w.root, roundNow() + 1n);
  let clock = 10;
  let attempts = 0;
  let available = false;
  let offered = next.trust;
  const open = () => NativeBridgeV2.open({ ...opts, trustFreshnessMs: 10, trustClock: () => clock,
    refreshTrust: async () => {
      attempts++;
      // Failed/partial updates must not credit a sync.
      if (!available) throw new Error('UTB source unavailable');
      return offered;
    },
  });
  const wallet = await open();
  const syncKey = wallet.journal.prefix + 'trust-sync';
  await assert.rejects(wallet.verifyToken(token), /UTB source unavailable/);
  assert.equal(await wallet.journal.store.get(syncKey), null);
  available = true;
  await Promise.all([wallet.verifyToken(token), wallet.verifyToken(token)]);
  assert.equal(attempts, 2);
  const record = (await wallet.journal.store.get(syncKey))!;
  assert.equal(JSON.parse(record).tipEpoch, '2');
  clock += 9;
  await wallet.verifyToken(token);
  assert.equal(attempts, 2);
  clock++;
  offered = w.root.trust;
  await assert.rejects(wallet.verifyToken(token), { reason: 'TrustInput' });
  assert.equal(await wallet.journal.store.get(syncKey), record);
  const reopenedBehind = await open();
  await assert.rejects(reopenedBehind.verifyToken(token), { reason: 'TrustInput' });
  const conflicting = await successor(w.root, roundNow() + 2n);
  offered = conflicting.trust;
  await assert.rejects(reopenedBehind.verifyToken(token), { reason: 'TrustInput' });
  assert.equal(await wallet.journal.store.get(syncKey), record);
  offered = next.trust;
  available = false;
  await assert.rejects(wallet.verifyToken(token), /UTB source unavailable/);
  const restarted = await open();
  await assert.rejects(restarted.mint(intent), /UTB source unavailable/);
  assert.equal(await wallet.journal.store.get(syncKey), record);
  clock = 1;
  available = true;
  await assert.rejects(wallet.verifyToken(token), { reason: 'TrustInput' });
  await wallet.verifyToken(token);
});

test('a frozen predecessor receipt needs an in-term witness for historical Mint verification', async () => {
  const w = await setup();
  const opts = w.options('frozen handoff fixture');
  const predecessor = await NativeBridgeV2.open(opts);
  const { intent } = await predecessor.planDeposit(8n, localOwner(key('frozen owner')).publicKey);
  await predecessor.submitDeposit(intent, evmAccount(w.chain, 'frozen payer'));
  const { reason } = await predecessor.collectDepositProof(intent);
  const receiptRound = decodeUc(decodeReceiptBacking(reason).proof.uc).unicitySeal.rootChainRoundNumber;
  const token = await predecessor.mint(intent);
  assert.equal((await predecessor.verifyToken(token)).amount, 8n);

  const closesAtReceipt = await successor(w.root, receiptRound);
  const afterDelayedSuffix = await NativeBridgeV2.open({ ...opts, trust: closesAtReceipt.trust });
  await assert.rejects(afterDelayedSuffix.verifyToken(token), { rule: 'DepositUC' });

  const closesAfterMint = await successor(w.root, roundNow() + 1n);
  const afterDurableWitness = await NativeBridgeV2.open({ ...opts, trust: closesAfterMint.trust });
  assert.equal((await afterDurableWitness.verifyToken(token)).amount, 8n);
});

test('default policy syncs and refuses publication after either a slow sync or slow verification', async () => {
  const w = await setup(fromHex(IMPORTED_TIP_PROFILE_HASH)!);
  const { unsafeTestTrust: _, ...opts } = w.options('default policy');
  const unsynced = await NativeBridgeV2.open(opts);
  await assert.rejects(unsynced.verifyWithTrust(async () => true), { reason: 'TrustInput' });
  const defaultOpen = await NativeBridgeV2.open({ ...opts, refreshTrust: async () => w.root.trust });
  assert.equal(await defaultOpen.verifyWithTrust(async () => true), true);
  let clock = 100;
  let slow = true;
  const bounded = await NativeBridgeV2.open({ ...opts, trustFreshnessMs: 10, trustClock: () => clock,
    refreshTrust: async () => {
      if (slow) clock += 11;
      return w.root.trust;
    },
  });
  await assert.rejects(bounded.verifyWithTrust(async () => true), { reason: 'TrustSyncRequired', retryable: true });
  slow = false;
  await assert.rejects(bounded.verifyWithTrust(async () => { clock += 11; return true; }), { reason: 'TrustSyncRequired' });
  assert.equal(await bounded.verifyWithTrust(async () => true), true);
});

test('a partial sync suspends publication within the old freshness window', async () => {
  const w = await setup();
  const next = await successor(w.root, roundNow() + 1n);
  let complete = true;
  let trusted = w.root.trust;
  const wallet = await NativeBridgeV2.open({ ...w.options('partial sync'), trustFreshnessMs: 10, trustClock: () => 1,
    refreshTrust: async () => {
      if (!complete) {
        trusted = next.trust; // the adapter saved the verified prefix before the next page failed
        throw new Error('UTB page failed after verified prefix');
      }
      return trusted;
    },
  });
  const readTip = () => wallet.verifyWithTrust(async (trust) => trust.history.tip!.epoch);
  assert.equal(await readTip(), 1n);
  const key = wallet.journal.prefix + 'trust-sync';
  const saved = await wallet.journal.store.get(key);
  complete = false;
  await assert.rejects(wallet.verifyWithTrust(async () => {
    void wallet.syncTrust().catch(() => undefined);
    return true;
  }), /UTB page failed/);
  await assert.rejects(readTip(), /UTB page failed/);
  assert.equal(await wallet.journal.store.get(key), saved);
  complete = true;
  assert.equal(await readTip(), 2n);
});
