/** Two fixes found by the Rust port (bft-core#1104): a lost journal compare-and-swap in verifiedPaid propagates, and a rewrite of the intents record keeps its unknown fields. */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { WalletError } from '../../src/nb2/errors.js';
import { MemoryJournalStore } from '../../src/nb2/journal.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { evmAccount, key, setup } from './world.js';

/** A store whose compare-and-swap of a paid return record loses while `lose` is set. */
class LosingStore extends MemoryJournalStore {
  public lose = false;
  public override putIf(k: string, expected: string | null, value: string): Promise<boolean> {
    if (this.lose && k.includes('/return/') && value.includes('"status":"paid"')) return Promise.resolve(false);
    return super.putIf(k, expected, value);
  }
}

const reason = async (p: Promise<unknown>): Promise<string> => {
  try {
    return `ok:${(await p as { state?: string }).state}`;
  } catch (e) {
    return e instanceof WalletError ? e.reason : String(e);
  }
};

test('a lost compare-and-swap while journaling Paid propagates: never not-paid or pending', async () => {
  const { chain, options } = await setup();
  const payer = evmAccount(chain, 'p');
  const owner = localOwner(key('o'));
  const store = new LosingStore();
  const w = await NativeBridgeV2.open(options('w', store));
  const p = await w.planDeposit(4n, owner.publicKey);
  await w.submitDeposit(p, payer);
  await w.collectDepositProof(p.intent);
  const rp = await w.planReturn(await w.mint(p.intent), HE(key('r')).slice(12), payer.address);
  await w.burn(rp.returnId, owner);
  store.lose = true;
  assert.equal(await reason(w.submitRedeem(rp.returnId, payer)), 'JournalConflict');
  assert.equal(chain.balanceOf(HE(key('r')).slice(12)), 4n); // it was paid on chain
  assert.equal(await reason(w.reconcile(rp.returnId)), 'JournalConflict');
  store.lose = false;
  const fresh = await NativeBridgeV2.open(options('w', store));
  assert.equal(await reason(fresh.reconcile(rp.returnId)), 'ok:paid');
});

test('planDeposit and recoverDeposits keep the unknown fields of the intents record', async () => {
  const { options } = await setup();
  const store = new MemoryJournalStore();
  const w = await NativeBridgeV2.open(options('w', store));
  await w.planDeposit(1n, localOwner(key('o')).publicKey);
  const k = [...store.map.keys()].find((x) => x.endsWith('/intents'))!;
  store.map.set(k, JSON.stringify({ ...JSON.parse(store.map.get(k)!), futureField: { x: 1 } }));
  const w2 = await NativeBridgeV2.open(options('w', store));
  await w2.planDeposit(1n, localOwner(key('o')).publicKey);
  assert.deepEqual(JSON.parse(store.map.get(k)!).futureField, { x: 1 });
  assert.equal(JSON.parse(store.map.get(k)!).next, '2');
  await w2.recoverDeposits(5n);
  assert.deepEqual(JSON.parse(store.map.get(k)!).futureField, { x: 1 });
  assert.equal(JSON.parse(store.map.get(k)!).next, '5');
});
