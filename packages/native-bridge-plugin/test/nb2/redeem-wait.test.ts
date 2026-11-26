/**
 * A mined payout whose block is not certified yet (its child, which carries the certificate, is still to come) is a normal wait. It stays
 * `pending` however often it is polled and becomes `paid` once the child is served: it is never escalated to `needs-archive` by a count of
 * reads. Only a node's own answer that the evidence is gone (EvidencePruned) means an archive is needed, and only while that answer holds.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { toHex } from '../../src/bytes.js';
import { MemoryJournalStore } from '../../src/nb2/journal.js';
import { CERTIFICATION_DEPTH, RpcError, type JsonRpc } from '../../src/nb2/rpc.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { evmAccount, key, setup } from './world.js';

async function burned(seed: string) {
  const world = await setup();
  const { chain, options } = world;
  const payer = evmAccount(chain, `${seed} payer`);
  const owner = localOwner(key(`${seed} owner`));
  const store = new MemoryJournalStore();
  const w = await NativeBridgeV2.open(options(seed, store));
  const p = await w.planDeposit(4n, owner.publicKey);
  await w.submitDeposit(p, payer);
  await w.collectDepositProof(p.intent);
  const rp = await w.planReturn(await w.mint(p.intent), HE(key(`${seed} r`)).slice(12), payer.address);
  await w.burn(rp.returnId, owner);
  return { ...world, w, store, payer, returnId: rp.returnId };
}

test('a payout in a block not certified yet stays pending through many polls, then is paid', async () => {
  const { chain, w, payer, returnId } = await burned('wait');
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'pending');
  await chain.mineUncertified();
  for (let i = 0; i < 8; i++) assert.equal((await w.reconcile(returnId)).state, 'pending', `poll ${i}`);
  await chain.mine([]); // the child arrives with the certificate
  assert.equal((await w.reconcile(returnId)).state, 'paid');
});

test('a node that answers "pruned" gives needs-archive with what is missing; the same record recovers once a reader serves it', async () => {
  const { chain, options, store, payer, returnId, w } = await burned('pruned');
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'pending');
  await chain.flush();
  // a gateway whose node no longer holds the payment block (its header lookup answers null)
  let pruning = true;
  const rpc: JsonRpc = { call: (m, p) => (pruning && m === 'eth_getBlockByHash' ? Promise.resolve(null as never) : chain.call(m, p)) };
  const pruned = await NativeBridgeV2.open({ ...options('pruned', store), rpc });
  const r = await pruned.reconcile(returnId);
  assert.equal(r.state, 'needs-archive');
  assert.match(r.state === 'needs-archive' ? r.missing ?? '' : '', /payment block header/);
  pruning = false;
  assert.equal((await pruned.reconcile(returnId)).state, 'paid');
});

test('a record left at the old read cap by an earlier build recovers on the next read', async () => {
  const { chain, store, payer, returnId, w } = await burned('stuck');
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'pending');
  await chain.mineUncertified();
  await w.reconcile(returnId);
  const k = [...store.map.keys()].find((x) => x.includes('/return/'))!;
  const rec = JSON.parse(store.map.get(k)!);
  assert.ok(rec.paidProof, 'a pending proof read is remembered');
  rec.paidProof.reads = 3; // what 14974d0c left in the owner's tab: "needs-archive"
  rec.sends.at(-1).failureProofReads = 3;
  store.map.set(k, JSON.stringify(rec));
  assert.equal((await w.reconcile(returnId)).state, 'pending');
  await chain.mine([]);
  assert.equal((await w.reconcile(returnId)).state, 'paid');
});

test('a rate-limited proof read is thrown as transport, never counted', async () => {
  const { chain, options, store, payer, returnId, w } = await burned('busy');
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'pending');
  await chain.flush();
  let busy = true;
  const rpc: JsonRpc = { call: (m, p) => (busy && m === 'unicity_getSealCompanionV1' ? Promise.reject(new RpcError(429, 0, 'rate limit')) : chain.call(m, p)) };
  const limited = await NativeBridgeV2.open({ ...options('busy', store), rpc });
  for (let i = 0; i < 4; i++) await assert.rejects(limited.reconcile(returnId), (e) => e instanceof RpcError && e.retryable);
  busy = false;
  assert.equal((await limited.reconcile(returnId)).state, 'paid');
});

test('a reverted redeem in a block not certified yet stays pending, then is a certified failure', async () => {
  const { chain, w, payer, returnId } = await burned('revert');
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'pending');
  chain.faults.recipients.set(toHex(HE(key('revert r')).slice(12)), 'reverts'); // the payout reverts when it is mined
  await chain.mineUncertified();
  for (let i = 0; i < 6; i++) assert.equal((await w.reconcile(returnId)).state, 'pending', `poll ${i}`);
  await chain.mine([]);
  assert.equal((await w.reconcile(returnId)).state, 'not-paid');
});

test('a child the reader\'s head has long passed but does not serve is its answer: needs-archive naming the child', async () => {
  const { chain, options, store, payer, returnId, w } = await burned('gap');
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'pending');
  await chain.flush();
  const paidAt = BigInt(chain.blocks.length - 2);
  const child = `0x${(paidAt + 1n).toString(16)}`;
  const rpc: JsonRpc = { call: (m, p) => (m === 'eth_getBlockByNumber' && p[0] === child ? Promise.resolve(null as never) : chain.call(m, p)) };
  const holey = await NativeBridgeV2.open({ ...options('gap', store), rpc });
  assert.equal((await holey.reconcile(returnId)).state, 'pending'); // near the head: not out yet
  for (let i = 0n; i < CERTIFICATION_DEPTH; i++) await chain.mine([]);
  const r = await holey.reconcile(returnId);
  assert.equal(r.state, 'needs-archive');
  assert.match(r.state === 'needs-archive' ? r.missing ?? '' : '', /child/);
  assert.equal((await w.reconcile(returnId)).state, 'paid');
});
