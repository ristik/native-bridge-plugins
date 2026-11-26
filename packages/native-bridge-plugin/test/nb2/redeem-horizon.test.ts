/**
 * Owner decision on review P3-C of #95: a claim of another party's payment that no reader holds canonically is dropped once every reader's
 * own head is VANISHED_CLAIM_HORIZON (64) blocks past where this return first saw such a claim, and the wallet proceeds with its own payout.
 * A provider that invents Paid can delay a redemption, never stop it. The vault's AlreadyPaid refuses a true double payment.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { decodeRevert, TOPIC } from '../../src/nb2/index.js';
import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { VANISHED_CLAIM_HORIZON } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { toHex } from '../../src/bytes.js';
import { MemoryJournalStore, type ReturnRecord } from '../../src/nb2/journal.js';
import { CERTIFICATION_DEPTH, EvmReader, RpcError, revertDataOf, type JsonRpc } from '../../src/nb2/rpc.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { evmAccount, key, setup } from './world.js';

const h = (b: Uint8Array) => `0x${toHex(b)}`;

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
  const recipient = HE(key(`${seed} r`)).slice(12);
  const rp = await w.planReturn(await w.mint(p.intent), recipient, payer.address);
  await w.burn(rp.returnId, owner);
  return { ...world, w, store, payer, recipient, returnId: rp.returnId };
}

async function record(store: MemoryJournalStore): Promise<ReturnRecord> {
  const k = [...store.map.keys()].find((x) => x.includes('/return/'))!;
  return JSON.parse(store.map.get(k)!);
}

test('an invented peer Paid from one reader, then honest readers: vanished, then dropped after the horizon and the own payout is made; '
  + 'the vault refuses the double payment with AlreadyPaid', async () => {
  const { chain, cfg, options, store, payer, recipient, returnId, w } = await burned('horizon');
  const rec = await record(store);
  // the liar indexes an invented Paid(eta, recipient, amount) at a transaction no chain holds, naming its current head as the block
  const fake = h(HE(new TextEncoder().encode('an invented payment')));
  const liar: JsonRpc = {
    call: async <T>(method: string, params: unknown[]): Promise<T> => {
      if (method === 'eth_getLogs' && (params[0] as { topics: string[] }).topics[0] === h(TOPIC.Paid)) {
        const at = `0x${(chain.blocks.length - 1).toString(16)}`;
        return [{
          address: h(cfg.vault), topics: [h(TOPIC.Paid), rec.eta, `0x${'00'.repeat(12)}${toHex(recipient)}`],
          data: `0x${BigInt(rec.amount).toString(16).padStart(64, '0')}`, blockNumber: at, blockHash: `0x${'cd'.repeat(32)}`,
          transactionHash: fake, logIndex: '0x0',
        }] as T;
      }
      return chain.call<T>(method, params);
    },
  };
  const lied = await NativeBridgeV2.open({ ...options('horizon', store), rpc: liar });
  assert.equal((await lied.reconcile(returnId)).state, 'pending');
  assert.equal((await lied.submitRedeem(returnId, payer)).state, 'pending', 'an unproven claim signs nothing');
  const seen = await record(store);
  assert.equal(seen.paidProof?.txHash, fake);
  assert.ok(seen.peerClaimSince !== undefined, 'the horizon starts at the first unproven peer claim');
  assert.deepEqual(seen.sends, []);
  // honest readers from now on: the remembered claim is not on any chain
  for (let i = 0n; i < CERTIFICATION_DEPTH + 4n; i++) await chain.mine([]);
  assert.equal((await w.reconcile(returnId)).state, 'vanished');
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'vanished');
  assert.deepEqual((await record(store)).sends, []);
  const before = new MemoryJournalStore();
  for (const [k, v] of store.map) before.map.set(k, v); // a second device holding the same return, still unpaid
  while (BigInt(chain.blocks.length - 1) < BigInt(seen.peerClaimSince!) + VANISHED_CLAIM_HORIZON) await chain.mine([]);
  assert.equal((await w.reconcile(returnId)).state, 'not-paid', 'past the horizon the invented claim is dropped');
  assert.equal((await record(store)).paidProof, undefined);
  const paid = await w.submitRedeem(returnId, payer);
  assert.equal(paid.state, 'paid');
  assert.equal(chain.balanceOf(recipient), 4n);
  // the liar again after the payout: the certified Paid stands
  assert.equal((await lied.reconcile(returnId)).state, 'paid');

  // a true double payment: the other device, whose reader hides the payout, signs and sends a second redeem of the same eta
  const payout = (await record(store)).paid!.txHash;
  const other = evmAccount(chain, 'horizon other payer');
  let estimates = 0;
  const hiding: JsonRpc = {
    call: async <T>(method: string, params: unknown[]): Promise<T> => {
      if (method === 'eth_getTransactionReceipt' && params[0] === payout) return null as T;
      if (method === 'eth_getLogs') return (await chain.call<{ transactionHash: string }[]>(method, params)).filter((l) => l.transactionHash !== payout) as T;
      if (method === 'eth_estimateGas' && ++estimates === 1) return '0x1d4c0' as T; // let it sign: the vault decides
      if (method === 'eth_call' && typeof params[1] === 'object') return '0x' as T;
      return chain.call<T>(method, params);
    },
  };
  const device = await NativeBridgeV2.open({ ...options('horizon', before), rpc: hiding });
  await device.submitRedeem(returnId, other).catch(() => undefined);
  const second = (await record(before)).sends.at(-1);
  assert.ok(second, 'the second device did sign a redeem');
  const receipt = await chain.call<{ status: string } | null>('eth_getTransactionReceipt', [second.hash]);
  assert.equal(receipt?.status, '0x0', 'the vault refused the second payout');
  assert.equal(chain.balanceOf(recipient), 4n, 'paid once');
  assert.equal(chain.vault.events.filter((e) => e.name === 'Paid').length, 1);
  const { request } = (await import('../../src/nb2/evm.js')).decodeSignedTx(Buffer.from(second.raw.slice(2), 'hex'));
  const refusal = await chain.call('eth_estimateGas', [{ from: h(other.address), to: h(request.to), data: h(request.data), value: '0x0' }])
    .then(() => null, (e: unknown) => e);
  assert.ok(refusal instanceof RpcError);
  assert.equal(decodeRevert(revertDataOf(refusal)!)?.rule, 'AlreadyPaid');
});

test('a reader that keeps inventing a new peer Paid every read, alongside an honest one, delays only until the horizon', async () => {
  const { chain, cfg, options, store, payer, recipient, returnId } = await burned('rotating');
  const rec = await record(store);
  let n = 0;
  const liar: JsonRpc = {
    call: async <T>(method: string, params: unknown[]): Promise<T> => {
      if (method === 'eth_getLogs' && (params[0] as { topics: string[] }).topics[0] === h(TOPIC.Paid)) {
        return [{
          address: h(cfg.vault), topics: [h(TOPIC.Paid), rec.eta, `0x${'00'.repeat(12)}${toHex(recipient)}`],
          data: `0x${BigInt(rec.amount).toString(16).padStart(64, '0')}`, blockNumber: `0x${(chain.blocks.length - 1).toString(16)}`,
          blockHash: `0x${'cd'.repeat(32)}`, transactionHash: h(HE(new TextEncoder().encode(`invented ${n++}`))), logIndex: '0x0',
        }] as T;
      }
      return chain.call<T>(method, params);
    },
  };
  const w = await NativeBridgeV2.open(options('rotating', store));
  const readers = [w.evm, new EvmReader(liar)];
  assert.equal((await w.reconcile(returnId, readers)).state, 'pending');
  const since = BigInt((await record(store)).peerClaimSince!);
  for (let i = 0; i < 3; i++) {
    for (let k = 0; k < 20; k++) await chain.mine([]);
    if (BigInt(chain.blocks.length - 1) < since + VANISHED_CLAIM_HORIZON) assert.notEqual((await w.reconcile(returnId, readers)).state, 'not-paid');
  }
  while (BigInt(chain.blocks.length - 1) < since + VANISHED_CLAIM_HORIZON) await chain.mine([]);
  assert.equal((await w.submitRedeem(returnId, payer, { archives: readers })).state, 'paid');
  assert.equal(chain.balanceOf(recipient), 4n);
});

test('a lying head of 0xffffffff with an invented peer Paid, then honest readers: the own payout after 64 honest blocks', async () => {
  const { chain, cfg, options, store, payer, recipient, returnId } = await burned('high head');
  const rec = await record(store);
  const liar: JsonRpc = {
    call: async <T>(method: string, params: unknown[]): Promise<T> => {
      if (method === 'eth_blockNumber') return '0xffffffff' as T;
      if (method === 'eth_getLogs' && (params[0] as { topics: string[] }).topics[0] === h(TOPIC.Paid)) {
        return [{
          address: h(cfg.vault), topics: [h(TOPIC.Paid), rec.eta, `0x${'00'.repeat(12)}${toHex(recipient)}`],
          data: `0x${BigInt(rec.amount).toString(16).padStart(64, '0')}`, blockNumber: `0x${(chain.blocks.length - 1).toString(16)}`,
          blockHash: `0x${'cd'.repeat(32)}`, transactionHash: `0x${'ee'.repeat(32)}`, logIndex: '0x0',
        }] as T;
      }
      return chain.call<T>(method, params);
    },
  };
  const lied = await NativeBridgeV2.open({ ...options('high head', store), rpc: liar });
  assert.notEqual((await lied.reconcile(returnId)).state, 'not-paid');
  assert.equal((await record(store)).peerClaimSince, String(0xffffffff), 'the only reader claimed a far head');
  const w = await NativeBridgeV2.open(options('high head', store));
  const honestStart = BigInt(chain.blocks.length - 1);
  assert.equal((await w.reconcile(returnId)).state, 'pending', 'honestly, the claim is fresh');
  assert.equal(BigInt((await record(store)).peerClaimSince!), honestStart, 'an honest head lowers it, never raises it');
  for (let i = 0n; i < VANISHED_CLAIM_HORIZON - 1n; i++) await chain.mine([]);
  assert.equal((await w.reconcile(returnId)).state, 'vanished', 'one block short of the horizon');
  await chain.mine([]);
  assert.equal((await w.submitRedeem(returnId, payer)).state, 'paid');
  assert.equal(chain.balanceOf(recipient), 4n);
});
