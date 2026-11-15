/** The persistence rules: secret before value, crash and resume at each step, recovery from seed plus high-water mark. */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { WalletError } from '../../src/nb2/errors.js';
import { JOURNAL_FORMAT, MemoryJournalStore, type DepositRecord } from '../../src/nb2/journal.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { HE } from '../../src/nb2/crypto.js';
import { evmAccount, key, setup } from './world.js';

const reason = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof WalletError ? e.reason : String(e);
  }
};

test('secret before value: no deposit without a persisted, backed-up plan', async () => {
  const { chain, options } = await setup();
  const payer = evmAccount(chain, 'p');
  const owner = localOwner(key('o')).publicKey;
  // no backup and no explicit opt-out: refused at construction
  assert.equal(await reason(NativeBridgeV2.open({ ...options('w'), backup: undefined })), 'BadInput');
  // a plan whose journal entry is gone (another store) is refused before anything is signed
  const w = await NativeBridgeV2.open(options('w'));
  const plan = await w.planDeposit(5n, owner);
  const other = await NativeBridgeV2.open(options('w'));
  assert.equal(await reason(other.submitDeposit(plan, payer)), 'JournalNotPersisted');
  // a plan not backed up is refused while requireBackup holds
  let backups = 0;
  const failing = await NativeBridgeV2.open({ ...options('x'), backup: async () => { backups++; throw new Error('backup offline'); } });
  await assert.rejects(failing.planDeposit(5n, owner));
  assert.equal(backups, 1);
  const rec = (await failing.journal.deposit(0n))!;
  assert.equal(rec.backedUp, false);
  assert.equal(await reason(failing.submitDeposit(0n, payer)), 'JournalNotPersisted');
  assert.equal(chain.vault.state().deposits, 0n);
  // the journal record is the documented version 1 shape
  const r: DepositRecord = (await w.journal.deposit(plan.intent))!;
  assert.equal(r.format, JOURNAL_FORMAT);
  assert.deepEqual(Object.keys(r).sort(), ['amount', 'backedUp', 'domain', 'firstOwner', 'format', 'intent', 'keyScheme', 'kind', 'ownerKey', 'plannedBlock', 'rho', 'sends', 'status', 'version']);
});

test('crash between send and receipt: the retry reconciles and never deposits twice', async () => {
  const { chain, options } = await setup();
  const payer = evmAccount(chain, 'p');
  const store = new MemoryJournalStore();
  const w = await NativeBridgeV2.open(options('w', store));
  const plan = await w.planDeposit(7n, localOwner(key('o')).publicKey);
  chain.autoMine = false;
  assert.equal(await reason(w.submitDeposit(plan, payer)), 'Unconfirmed');
  // "restart": a fresh instance over the same journal, while the transaction is still in the pool
  const again = await NativeBridgeV2.open(options('w', store));
  assert.equal(await reason(again.submitDeposit(plan.intent, payer)), 'Unconfirmed');
  await chain.flush();
  chain.autoMine = true;
  const d = await again.submitDeposit(plan.intent, payer);
  assert.equal(d.depositNumber, 1n);
  assert.equal(chain.vault.state().deposits, 1n);
  assert.equal((await again.journal.deposit(plan.intent))!.sends.length, 1);
  await again.collectDepositProof(plan.intent);
  assert.equal((await again.verifyToken(await again.mint(plan.intent))).amount, 7n);
});

test('crash between burn request and certification, and between burn and redeem', async () => {
  const { chain, agg, options } = await setup();
  const payer = evmAccount(chain, 'p');
  const store = new MemoryJournalStore();
  const owner = localOwner(key('o'));
  const w = await NativeBridgeV2.open(options('w', store));
  const plan = await w.planDeposit(9n, owner.publicKey);
  await w.submitDeposit(plan, payer);
  await w.collectDepositProof(plan.intent);
  const t = await w.mint(plan.intent);
  const rp = await w.planReturn(t, HE(key('r')).slice(12), payer.address);
  // the aggregator is down at the burn: the request is journaled, nothing else
  const certify = agg.certify.bind(agg);
  agg.certify = async () => { throw new Error('aggregator unreachable'); };
  await assert.rejects(w.burn(rp.returnId, owner));
  const rec = (await w.journal.ret(rp.record.returnId))!;
  assert.equal(rec.status, 'burn-requested');
  agg.certify = certify;
  // a restart resumes the same request: the same burn, never a second one
  const w2 = await NativeBridgeV2.open(options('w', store));
  const b = await w2.burn(rp.returnId, owner);
  assert.equal((await w2.journal.ret(rp.record.returnId))!.burnRequest, rec.burnRequest);
  // between burn and redeem: another restart redeems from the journal alone
  const w3 = await NativeBridgeV2.open(options('w', store));
  assert.equal((await w3.submitRedeem(rp.returnId, payer)).state, 'paid');
  assert.equal(chain.balanceOf(HE(key('r')).slice(12)), 9n);
  assert.equal(b.verdict.amount, 9n);
});

test('recovery from the seed and the intent high-water mark', async () => {
  const { chain, options } = await setup();
  const payer = evmAccount(chain, 'p');
  const owner = localOwner(key('o')).publicKey;
  const lost = await NativeBridgeV2.open(options('seed'));
  for (const v of [3n, 4n, 5n]) await lost.planDeposit(v, owner); // intents 0..2; only 0 and 2 are sent
  await lost.submitDeposit(0n, payer);
  await lost.submitDeposit(2n, payer);
  // a new device: the same seed (k_w) and the backed-up mark, an empty journal
  const restored = await NativeBridgeV2.open(options('seed', new MemoryJournalStore()));
  assert.deepEqual(await restored.recoverDeposits(3n), [0n, 2n]);
  await restored.collectDepositProof(2n);
  assert.equal((await restored.verifyToken(await restored.mint(2n))).amount, 5n);
  // the counter continues past the mark: intent 1 is never reused
  assert.equal((await restored.planDeposit(1n, owner)).intent, 3n);
});
