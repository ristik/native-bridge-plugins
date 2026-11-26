/**
 * A reader whose eth_blockNumber lies (0xffffffff) must not make the wallet page eth_getLogs through the claimed range (about 429,000
 * windows of LOG_BLOCK_RANGE): every height-driven loop runs to EvmReader.saneHead(), the highest block the reader actually serves.
 * The lie costs O(log) header reads and O(1) extra log windows.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { MemoryJournalStore } from '../../src/nb2/journal.js';
import { EvmReader, type JsonRpc } from '../../src/nb2/rpc.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { evmAccount, key, setup } from './world.js';

const counting = (inner: JsonRpc, head?: string) => {
  const calls = new Map<string, number>();
  const rpc: JsonRpc = {
    call: <T>(method: string, params: unknown[]): Promise<T> => {
      calls.set(method, (calls.get(method) ?? 0) + 1);
      if (head && method === 'eth_blockNumber') return Promise.resolve(head as T);
      return inner.call<T>(method, params);
    },
  };
  return { rpc, calls };
};

test('saneHead: an honest head costs one header read; a lying 0xffffffff head is bounded to the served head in O(log) reads', async () => {
  const { chain } = await setup();
  for (let i = 0; i < 40; i++) await chain.mine([]);
  const real = BigInt(chain.blocks.length - 1);
  const honest = counting(chain);
  assert.equal(await new EvmReader(honest.rpc).saneHead(), real);
  assert.equal(honest.calls.get('eth_getBlockByNumber'), 1);
  const lying = counting(chain, '0xffffffff');
  const reader = new EvmReader(lying.rpc);
  assert.equal(await reader.saneHead(), real);
  assert.ok((lying.calls.get('eth_getBlockByNumber') ?? 0) <= 34, `${lying.calls.get('eth_getBlockByNumber')} header reads`);
  // later reads start from the confirmed head
  await chain.mine([]);
  lying.calls.clear();
  assert.equal(await reader.saneHead(), real + 1n);
  assert.ok((lying.calls.get('eth_getBlockByNumber') ?? 0) <= 34);
});

test('a reconcile through a reader whose head lies costs O(1) extra eth_getLogs windows, and still finds the payout', async () => {
  const world = await setup();
  const { chain, options } = world;
  const payer = evmAccount(chain, 'sane payer');
  const owner = localOwner(key('sane owner'));
  const store = new MemoryJournalStore();
  const w = await NativeBridgeV2.open(options('sane', store));
  const p = await w.planDeposit(4n, owner.publicKey);
  await w.submitDeposit(p, payer);
  await w.collectDepositProof(p.intent);
  const rp = await w.planReturn(await w.mint(p.intent), HE(key('sane r')).slice(12), payer.address);
  await w.burn(rp.returnId, owner);
  chain.autoMine = false;
  assert.equal((await w.submitRedeem(rp.returnId, payer)).state, 'pending');
  await chain.mineUncertified();
  const honest = counting(chain);
  const a = await NativeBridgeV2.open({ ...options('sane', store), rpc: honest.rpc });
  assert.equal((await a.reconcile(rp.returnId)).state, 'pending');
  const lying = counting(chain, '0xffffffff');
  const b = await NativeBridgeV2.open({ ...options('sane', store), rpc: lying.rpc });
  const started = Date.now();
  assert.equal((await b.reconcile(rp.returnId)).state, 'pending');
  const windows = { honest: honest.calls.get('eth_getLogs') ?? 0, lying: lying.calls.get('eth_getLogs') ?? 0 };
  assert.ok(windows.lying <= windows.honest + 2, `eth_getLogs: ${windows.lying} with the lie, ${windows.honest} without`);
  assert.ok(Date.now() - started < 5_000, 'no scan of the claimed range');
  await chain.mine([]);
  assert.equal((await b.reconcile(rp.returnId)).state, 'paid');
});
