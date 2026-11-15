/**
 * The cross-language journal round trip (bft-core#1104): stage A plans and half-finishes deposits, a split and two returns;
 * stage B continues them from the journal alone. Each plug-in writes a snapshot after stage A (`tests/nb2-journal/`), and each
 * continues the other's: the Rust plug-in runs the same two stages (`crates/native-bridge-sdk-ext/tests/nb2_journal_interop.rs`).
 *
 *   npx tsx scripts/gen-nb2-journal-fixture.ts     # rewrites tests/nb2-journal/ts-written.json
 */
import assert from 'node:assert/strict';

import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { MemoryJournalStore, unhex } from '../../src/nb2/journal.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { restore, snapshot, worldOf } from './snapshot.js';
import { FakeAggregator, FakeChain, evmAccount, key, makeConfig, makeRoot } from './world.js';

export const WALLET = 'interop wallet';
const rcp = (s: string): Uint8Array => HE(key(s)).slice(12);

/** Stage A in a fresh world; the snapshot after it. */
export async function stageA(): Promise<unknown> {
  const root = await makeRoot();
  const chain = await FakeChain.create(root, makeConfig(root));
  const agg = new FakeAggregator(root);
  const world = worldOf(root, chain, agg);
  const store = new MemoryJournalStore();
  const w = await NativeBridgeV2.open(world.options(WALLET, store));
  const payer = evmAccount(chain, 'interop');
  const alice = localOwner(key('interop alice'));
  const bob = localOwner(key('interop bob'));
  const p = await w.planDeposit(100n, alice.publicKey);
  await w.submitDeposit(p, payer);
  await w.collectDepositProof(p.intent);
  const t100 = await w.mint(p.intent);
  const [t60, t40] = await w.split(t100, alice, [{ ownerKey: bob.publicKey, amount: 60n }, { ownerKey: bob.publicKey, amount: 40n }]);
  const r60 = await w.planReturn(t60, rcp('interop r1'), payer.address);
  await w.burn(r60.returnId, bob);
  await w.planReturn(t40, rcp('interop r2'), payer.address);
  const p7 = await w.planDeposit(7n, alice.publicKey);
  await w.submitDeposit(p7, payer);
  await w.collectDepositProof(p7.intent);
  await w.planDeposit(5n, alice.publicKey);
  return snapshot(root, chain, agg, store);
}

/** Stage B over a snapshot written by either plug-in. */
export async function stageB(snap: unknown): Promise<void> {
  const world = await restore(snap);
  const w = await NativeBridgeV2.open(world.options(WALLET, world.journal));
  const payer = evmAccount(world.chain, 'interop');
  const alice = localOwner(key('interop alice'));
  const bob = localOwner(key('interop bob'));
  assert.deepEqual((await w.journal.deposits()).map((d) => d.status), ['minted', 'proven', 'planned']);
  const rets = await w.journal.returns();
  const r60 = rets.find((r) => r.amount === '60')!;
  const r40 = rets.find((r) => r.amount === '40')!;
  assert.equal(r60.status, 'burned');
  assert.equal(r40.status, 'planned');
  // the proven deposit mints; the planned one is sent, proven and minted
  const t7 = await w.mint(1n);
  assert.equal((await w.verifyToken(t7)).amount, 7n);
  assert.deepEqual((await w.verifyToken(t7)).owner, alice.publicKey);
  await w.submitDeposit(2n, payer);
  await w.collectDepositProof(2n);
  assert.equal((await w.verifyToken(await w.mint(2n))).amount, 5n);
  // the planned return burns and both redeem
  await w.burn(unhex(r40.returnId), bob);
  assert.equal((await w.submitRedeem(unhex(r60.returnId), payer)).state, 'paid');
  assert.equal((await w.submitRedeem(unhex(r40.returnId), payer)).state, 'paid');
  assert.equal(world.chain.balanceOf(rcp('interop r1')), 60n);
  assert.equal(world.chain.balanceOf(rcp('interop r2')), 40n);
  assert.equal(world.chain.vault.state().outstanding, 12n);
  // the intent counter continues past the other plug-in's mark
  assert.equal((await w.planDeposit(1n, alice.publicKey)).intent, 3n);
  assert.equal((await w.status()).filter((x) => x.endsWith(': paid')).length, 2);
}
