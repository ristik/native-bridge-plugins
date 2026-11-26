/**
 * Review P2-1 of #94: a payout receipt that was seen but not certified, and then vanishes from every reader (its block rolled back by a
 * repeat certificate and the transaction not mined again) or turns out to be in a block that is not canonical, must not stay pending
 * forever. By each reader's own head, CERTIFICATION_DEPTH blocks past where it was seen: this wallet's own send is offered again (the
 * identical signed bytes, which cannot compete), and another party's payment is reported as `vanished` (nothing is signed).
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { toHex } from '../../src/bytes.js';
import { decodeSignedTx } from '../../src/nb2/evm.js';
import { MemoryJournalStore, type ReturnRecord } from '../../src/nb2/journal.js';
import { CERTIFICATION_DEPTH, type JsonRpc } from '../../src/nb2/rpc.js';
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
  return { ...world, w, store, payer, returnId: rp.returnId, seed };
}

type Mode = 'vanished' | 'non-canonical';

/**
 * A gateway over the fake chain that, once `rollback` is set, behaves as if the block holding `tx` was replaced: the receipt is gone (or
 * served in a block that is not canonical), its logs are gone, its sender's nonce is unused again, its call simulates as before it was
 * mined, and a broadcast is recorded unexecuted.
 */
function rolledBack(chain: Awaited<ReturnType<typeof setup>>['chain'], mode: Mode) {
  const state = { rollback: false, tx: '', nonce: 0n as bigint | undefined, data: '', sent: [] as string[] };
  const rpc: JsonRpc = {
    call: async <T>(method: string, params: unknown[]): Promise<T> => {
      if (!state.rollback) return chain.call<T>(method, params);
      if (method === 'eth_getTransactionReceipt' && params[0] === state.tx) {
        if (mode === 'vanished') return null as T;
        const r = await chain.call<Record<string, unknown>>(method, params);
        return { ...r, blockHash: `0x${'ab'.repeat(32)}` } as T;
      }
      if (method === 'eth_getLogs') return (await chain.call<{ transactionHash: string }[]>(method, params)).filter((l) => l.transactionHash !== state.tx) as T;
      // the replaced block's payout never happened: the same call simulates as it did before it was mined
      if (method === 'eth_call' && (params[0] as { data?: string }).data === state.data) return '0x' as T;
      if (method === 'eth_getTransactionCount' && params[1] === 'latest' && state.nonce !== undefined) return `0x${state.nonce!.toString(16)}` as T;
      if (method === 'eth_sendRawTransaction') {
        state.sent.push(params[0] as string);
        return `0x${toHex(HE(Buffer.from((params[0] as string).slice(2), 'hex')))}` as T;
      }
      return chain.call<T>(method, params);
    },
  };
  return { rpc, state };
}

async function record(store: MemoryJournalStore): Promise<[string, ReturnRecord]> {
  const k = [...store.map.keys()].find((x) => x.includes('/return/'))!;
  return [k, JSON.parse(store.map.get(k)!)];
}

for (const mode of ['vanished', 'non-canonical'] as const) {
  test(`own send whose seen receipt is ${mode} 20 blocks later: the identical bytes are offered again, then it is paid`, async () => {
    const { chain, options, store, payer, returnId, seed, w } = await burned(`own ${mode}`);
    chain.autoMine = false;
    assert.equal((await w.submitRedeem(returnId, payer)).state, 'pending');
    await chain.mineUncertified();
    const { rpc, state } = rolledBack(chain, mode);
    const v = await NativeBridgeV2.open({ ...options(seed, store), rpc });
    assert.equal((await v.reconcile(returnId)).state, 'pending');
    const [, seen] = await record(store);
    assert.ok(seen.paidProof?.block, 'the block the receipt was seen in is remembered');
    const signed = seen.sends[0];
    state.tx = signed.hash;
    state.data = `0x${toHex(decodeSignedTx(Buffer.from(signed.raw.slice(2), 'hex')).request.data)}`;
    state.nonce = BigInt(signed.nonce);
    state.rollback = true;
    for (let i = 0; i < 5; i++) await chain.mine([]);
    assert.equal((await v.reconcile(returnId)).state, mode === 'vanished' ? 'pending' : 'needs-archive');
    assert.deepEqual(state.sent, [], 'near the head nothing is offered again');
    for (let i = 5n; i < 20n; i++) await chain.mine([]);
    assert.ok(BigInt(chain.blocks.length) > BigInt(seen.paidProof!.block!) + CERTIFICATION_DEPTH);
    for (let i = 0; i < 3; i++) assert.equal((await v.reconcile(returnId)).state, 'pending');
    assert.ok(state.sent.length >= 1);
    assert.ok(state.sent.every((raw) => raw === signed.raw), 'only the identical signed transaction');
    const [, after] = await record(store);
    assert.equal(after.paidProof, undefined);
    assert.equal(after.sends.length, 1, 'nothing new was signed');
    assert.equal((await v.submitRedeem(returnId, payer)).state, 'pending');
    assert.equal((await record(store))[1].sends.length, 1, 'submitRedeem signs nothing new either');
    state.rollback = false; // the transaction lands again
    assert.equal((await v.reconcile(returnId)).state, 'paid');
  });
}

test('another party\'s payment that vanished 20 blocks later is reported as vanished, signs nothing, and is paid if it lands again', async () => {
  const { chain, options, store, payer, returnId, seed, w } = await burned('peer');
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'pending');
  await chain.mineUncertified();
  const { rpc, state } = rolledBack(chain, 'vanished');
  const v = await NativeBridgeV2.open({ ...options(seed, store), rpc });
  assert.equal((await v.reconcile(returnId)).state, 'pending');
  // the holder knows the payment only as a remembered claim (a peer's send, restored without its bytes)
  const [k, rec] = await record(store);
  state.tx = rec.sends[0].hash;
  state.data = `0x${toHex(decodeSignedTx(Buffer.from(rec.sends[0].raw.slice(2), 'hex')).request.data)}`;
  state.nonce = BigInt(rec.sends[0].nonce);
  store.map.set(k, JSON.stringify({ ...rec, sends: [] }));
  state.rollback = true;
  for (let i = 0; i < 5; i++) await chain.mine([]);
  assert.equal((await v.reconcile(returnId)).state, 'pending');
  for (let i = 5; i < 20; i++) await chain.mine([]);
  const r = await v.reconcile(returnId);
  assert.equal(r.state, 'vanished');
  assert.equal(toHex((r as { txHash: Uint8Array }).txHash), state.tx.slice(2));
  assert.equal((await v.submitRedeem(returnId, payer)).state, 'vanished');
  assert.deepEqual(state.sent, []);
  assert.deepEqual((await record(store))[1].sends, []);
  state.rollback = false;
  assert.equal((await v.reconcile(returnId)).state, 'paid');
});

test('a reverted send whose failed receipt vanished 20 blocks later is offered again with the identical bytes', async () => {
  const { chain, options, store, payer, returnId, seed, w } = await burned('failed');
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'pending');
  chain.faults.recipients.set(toHex(HE(key('failed r')).slice(12)), 'reverts');
  await chain.mineUncertified();
  const { rpc, state } = rolledBack(chain, 'vanished');
  const v = await NativeBridgeV2.open({ ...options(seed, store), rpc });
  assert.equal((await v.reconcile(returnId)).state, 'pending');
  const [, seen] = await record(store);
  assert.equal(seen.sends[0].failureProofReads, 1);
  assert.ok(seen.sends[0].failureBlock);
  state.tx = seen.sends[0].hash;
  state.data = `0x${toHex(decodeSignedTx(Buffer.from(seen.sends[0].raw.slice(2), 'hex')).request.data)}`;
  state.nonce = BigInt(seen.sends[0].nonce);
  state.rollback = true;
  for (let i = 0; i < 5; i++) await chain.mine([]);
  assert.equal((await v.reconcile(returnId)).state, 'pending');
  assert.deepEqual(state.sent, []);
  for (let i = 5; i < 20; i++) await chain.mine([]);
  assert.equal((await v.reconcile(returnId)).state, 'pending');
  assert.deepEqual(state.sent, [seen.sends[0].raw]);
  const [, after] = await record(store);
  assert.equal(after.sends.length, 1);
  assert.equal(after.sends[0].failureProofReads, undefined);
  assert.equal(after.sends[0].failureBlock, undefined);
});

test('a reader without the receipt of an own send whose nonce is used stays pending past the depth: nothing is offered or signed', async () => {
  const { chain, options, store, payer, returnId, seed, w } = await burned('used');
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'pending');
  await chain.mineUncertified();
  const { rpc, state } = rolledBack(chain, 'vanished');
  const v = await NativeBridgeV2.open({ ...options(seed, store), rpc });
  assert.equal((await v.reconcile(returnId)).state, 'pending');
  const [, rec] = await record(store);
  state.tx = rec.sends[0].hash;
  state.nonce = undefined; // the account's nonce stays used: the transaction is mined, this reader lacks its receipt
  state.rollback = true;
  for (let i = 0; i < 20; i++) await chain.mine([]);
  for (let i = 0; i < 3; i++) assert.equal((await v.reconcile(returnId)).state, 'pending');
  assert.deepEqual(state.sent, []);
  assert.equal((await record(store))[1].sends.length, 1);
  state.rollback = false;
  assert.equal((await v.reconcile(returnId)).state, 'paid');
});
