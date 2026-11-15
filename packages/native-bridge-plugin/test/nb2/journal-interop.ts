/**
 * The cross-language journal round trip (bft-core#1104): stage A plans and half-finishes deposits, a split and two returns;
 * stage B continues them from the journal alone. Each plug-in writes a snapshot after stage A (`tests/nb2-journal/`), and each
 * continues the other's: the Rust plug-in runs the same two stages (`crates/native-bridge-sdk-ext/tests/nb2_journal_interop.rs`).
 *
 *   npx tsx scripts/gen-nb2-journal-fixture.ts     # rewrites tests/nb2-journal/ts-written.json
 */
import assert from 'node:assert/strict';

import { toHex } from '../../src/bytes.js';
import { depositCalldata } from '../../src/nb2/abi.js';
import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { firstOwnerOf } from '../../src/nb2/deposit.js';
import { WalletError } from '../../src/nb2/errors.js';
import { signTx } from '../../src/nb2/evm.js';
import { HE } from '../../src/nb2/crypto.js';
import { MemoryJournalStore, unhex } from '../../src/nb2/journal.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { restore, snapshot, worldOf } from './snapshot.js';
import { FakeAggregator, FakeChain, VAULT, evmAccount, key, makeConfig, makeRoot } from './world.js';

const h = (b: Uint8Array): string => `0x${toHex(b)}`;

export const WALLET = 'interop wallet';
const rcp = (s: string): Uint8Array => HE(key(s)).slice(12);

/**
 * Stage A in a fresh world; the snapshot after it. Every intermediate state the journal can hold is left for stage B: minted,
 * proven, deposited (with a second deposit of its rho in `seenDeposits`), submitted with a replaced send (`nonceUsedAt`), planned; a
 * split with one child minted; returns burned, planned, burn-requested and submitted (in the pool); and unknown fields in two records.
 */
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
  const minted = async (v: bigint): Promise<Uint8Array> => {
    const p = await w.planDeposit(v, alice.publicKey);
    await w.submitDeposit(p, payer);
    await w.collectDepositProof(p.intent);
    return w.mint(p.intent);
  };
  const certify = agg.certify.bind(agg);
  // intent 0: 100, split 60 + 40; the 60 burned, the 40 planned
  const [t60, t40] = await w.split(await minted(100n), alice, [{ ownerKey: bob.publicKey, amount: 60n }, { ownerKey: bob.publicKey, amount: 40n }]);
  const r60 = await w.planReturn(t60, rcp('interop r1'), payer.address);
  await w.burn(r60.returnId, bob);
  await w.planReturn(t40, rcp('interop r2'), payer.address);
  // intent 1: proven
  const p7 = await w.planDeposit(7n, alice.publicKey);
  await w.submitDeposit(p7, payer);
  await w.collectDepositProof(p7.intent);
  // intent 2: 30, split into 10 + 20, interrupted after the burn and the first child
  const t30 = await minted(30n);
  let left = 2;
  agg.certify = async (r) => {
    if (left-- <= 0) throw new Error('aggregator unreachable');
    return certify(r);
  };
  await assert.rejects(w.split(t30, alice, [{ ownerKey: bob.publicKey, amount: 10n }, { ownerKey: bob.publicKey, amount: 20n }]));
  agg.certify = certify;
  // intent 3: 9, its return burn-requested (the aggregator down at the burn)
  const r9 = await w.planReturn(await minted(9n), rcp('interop r9'), payer.address);
  agg.certify = async () => { throw new Error('aggregator unreachable'); };
  await assert.rejects(w.burn(r9.returnId, alice));
  agg.certify = certify;
  // intent 4: 3, deposited; a second deposit of its rho (to bob) is in seenDeposits
  const p3 = await w.planDeposit(3n, alice.publicKey);
  await w.submitDeposit(p3, payer);
  const nonce = async (tag: string): Promise<bigint> => BigInt(await chain.call<string>('eth_getTransactionCount', [h(payer.address), tag]));
  const tx = async (n: bigint, to: Uint8Array, value: bigint, data: Uint8Array) =>
    signTx(payer, { chainId: 31337n, nonce: n, maxPriorityFeePerGas: 1n, maxFeePerGas: 15n, gas: 200_000n, to, value, data });
  const extra = await tx(await nonce('pending'), VAULT, 3n, depositCalldata(firstOwnerOf(bob.publicKey), p3.rho));
  await chain.call('eth_sendRawTransaction', [h(extra.raw)]);
  await w.recoverDeposits(5n);
  // intent 5: 6, submitted, its send replaced by another transaction of the same nonce (nonceUsedAt journaled)
  const p6 = await w.planDeposit(6n, alice.publicKey);
  chain.autoMine = false;
  await assert.rejects(w.submitDeposit(p6, payer), (e) => e instanceof WalletError && e.reason === 'Unconfirmed');
  chain.dropPool();
  const other = await tx(await nonce('latest'), rcp('interop z'), 1n, new Uint8Array());
  await chain.call('eth_sendRawTransaction', [h(other.raw)]);
  await chain.flush();
  chain.autoMine = true;
  await assert.rejects(w.submitDeposit(p6.intent, payer), (e) => e instanceof WalletError && e.reason === 'Unconfirmed');
  // intent 6: 8, its redeem submitted and still in the pool
  const r8 = await w.planReturn(await minted(8n), rcp('interop r8'), payer.address);
  await w.burn(r8.returnId, alice);
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(r8.returnId, payer)).state, 'pending');
  // intent 7: planned
  await w.planDeposit(5n, alice.publicKey);
  // unknown fields in the intents record and in the planned return
  for (const [k, v] of store.map) {
    if (k.endsWith('/intents') || (k.includes('/return/') && v.includes('"amount":"40"'))) store.map.set(k, JSON.stringify({ ...JSON.parse(v), futureField: { from: 'stage A' } }));
  }
  return snapshot(root, chain, agg, store);
}

/** Stage B over a snapshot written by either plug-in. */
export async function stageB(snap: unknown): Promise<void> {
  const world = await restore(snap);
  const w = await NativeBridgeV2.open(world.options(WALLET, world.journal));
  const payer = evmAccount(world.chain, 'interop');
  const alice = localOwner(key('interop alice'));
  const bob = localOwner(key('interop bob'));
  assert.deepEqual((await w.journal.deposits()).map((d) => d.status), ['minted', 'proven', 'minted', 'minted', 'deposited', 'submitted', 'minted', 'planned']);
  const rets = await w.journal.returns();
  const by = (a: string) => rets.find((r) => r.amount === a)!;
  const [r60, r40, r9, r8] = ['60', '40', '9', '8'].map(by);
  assert.deepEqual([r60.status, r40.status, r9.status, r8.status], ['burned', 'planned', 'burn-requested', 'submitted']);
  // the submitted redeem lands and reconciles
  await world.chain.flush();
  assert.equal((await w.reconcile(unhex(r8.returnId))).state, 'paid');
  // proven mints; planned is sent, proven and minted
  const v7 = await w.verifyToken(await w.mint(1n));
  assert.equal(v7.amount, 7n);
  assert.deepEqual(v7.owner, alice.publicKey);
  await w.submitDeposit(7n, payer);
  await w.collectDepositProof(7n);
  assert.equal((await w.verifyToken(await w.mint(7n))).amount, 5n);
  // the replaced send is dead after depth on a certified block: one new send
  for (let k = 0; k < 6; k++) await world.chain.mine([]);
  await w.submitDeposit(5n, payer);
  await w.collectDepositProof(5n);
  assert.equal((await w.verifyToken(await w.mint(5n))).amount, 6n);
  // both deposits of intent 4's rho mint, each to its own first owner
  await w.collectDepositProof(4n);
  assert.equal((await w.verifyToken(await w.mint(4n))).amount, 3n);
  const seen = (await w.journal.deposit(4n))!.seenDeposits!;
  assert.equal(seen.length, 2);
  assert.deepEqual((await w.verifyToken(await w.mintExtraDeposit(4n, BigInt(seen[1].depositNumber)))).owner, bob.publicKey);
  // the interrupted split resumes from its record
  const rec = [...world.journal.map].filter(([k]) => k.includes('/split/')).map(([, v]) => JSON.parse(v)).find((v) => v.status === 'burned');
  assert.equal(rec.outputs.filter((o: { token: unknown }) => o.token !== null).length, 1);
  const kids = await w.split(unhex(rec.source), alice, [], unhex(rec.splitId));
  assert.deepEqual(await Promise.all(kids.map(async (t) => (await w.verifyToken(t)).amount)), [10n, 20n]);
  // the burn-requested return finishes its burn; every return redeems
  await w.burn(unhex(r9.returnId), alice);
  await w.burn(unhex(r40.returnId), bob);
  for (const r of [r9, r60, r40]) assert.equal((await w.submitRedeem(unhex(r.returnId), payer)).state, 'paid');
  assert.deepEqual(['interop r1', 'interop r2', 'interop r9', 'interop r8'].map((s) => world.chain.balanceOf(rcp(s))), [60n, 40n, 9n, 8n]);
  assert.equal(world.chain.vault.state().outstanding, 171n - 117n);
  // unknown fields survive the rewrites; the intent counter continues past the other plug-in's mark
  assert.equal((await w.planDeposit(1n, alice.publicKey)).intent, 8n);
  for (const [k, v] of world.journal.map) {
    if (k.endsWith('/intents') || (k.includes('/return/') && v.includes('"amount":"40"'))) assert.deepEqual(JSON.parse(v).futureField, { from: 'stage A' }, k);
  }
  assert.equal((await w.status()).filter((x) => x.endsWith(': paid')).length, 4);
}
