/**
 * The reference scenario of #1103 through the plug-in API only, against the offline simulator (the vault model behind a fake gateway
 * and a fake aggregator): deposit 100, mint, transfer, split 60 + 40, split 40 into 15 + 25, transfer again, return 60, 15 and 25 each
 * with its own index while a second wallet's returns rotate segments. Exactly 100 is paid; replays are refused before and after
 * eviction; a witness made stale by two rotations is rebuilt; an ambiguous broadcast resolves by its receipt; a fresh instance over
 * the same journal finishes a return.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { decodeRevert } from '../../src/nb2/abi.js';
import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { MemoryJournalStore, unhex } from '../../src/nb2/journal.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { EvmReader } from '../../src/nb2/rpc.js';
import { buildHistory, checkSegmentLog, type Segment } from '../../src/nb2/segment.js';
import { FakeChain, evmAccount, key, setup, VAULT } from './world.js';

test('reference scenario: 100 -> 60 + 40 -> 60 + 15 + 25, all returned', async () => {
  const { chain, options } = await setup();
  const store = new MemoryJournalStore();
  const w = await NativeBridgeV2.open(options('alice wallet', store));
  const other = await NativeBridgeV2.open(options('dave wallet'));
  const payer = evmAccount(chain, 'alice');
  const davePayer = evmAccount(chain, 'dave');
  const alice = localOwner(key('alice'));
  const bob = localOwner(key('bob'));
  const carol = localOwner(key('carol'));
  const dave = localOwner(key('dave'));
  const [r1, r2, r3, rd] = ['r1', 'r2', 'r3', 'rd'].map((s) => HE(key(s)).slice(12));

  // a second wallet's small deposits and returns rotate segments (K = 4)
  const rotate = async (segments: number): Promise<void> => {
    for (let k = 0; k < 4 * segments; k++) {
      const p = await other.planDeposit(1n, dave.publicKey);
      await other.submitDeposit(p, davePayer);
      await other.collectDepositProof(p.intent);
      const t = await other.mint(p.intent);
      const plan = await other.planReturn(t, rd, davePayer.address);
      await other.burn(plan.returnId, dave);
      assert.equal((await other.submitRedeem(plan.returnId, davePayer)).state, 'paid');
    }
  };

  // deposit 100, mint
  const plan = await w.planDeposit(100n, alice.publicKey);
  const dep = await w.submitDeposit(plan, payer);
  assert.equal(dep.depositNumber, 1n);
  await w.collectDepositProof(plan.intent);
  const t100 = await w.mint(plan.intent);
  assert.equal((await w.verifyToken(t100)).amount, 100n);

  // transfer, split 60 + 40, split 40 into 15 + 25, transfer again
  const tb = await w.transfer(t100, alice, bob.publicKey);
  const [t60, t40] = await w.split(tb, bob, [{ ownerKey: bob.publicKey, amount: 60n }, { ownerKey: bob.publicKey, amount: 40n }]);
  const [t15, t25] = await w.split(t40, bob, [{ ownerKey: carol.publicKey, amount: 15n }, { ownerKey: bob.publicKey, amount: 25n }]);
  const t60c = await w.transfer(t60, bob, carol.publicKey);
  assert.deepEqual((await w.verifyToken(t15)).owner, carol.publicKey);

  await rotate(1);
  // return 60: burned at its index, redeemed after two rotations with historical gap proofs
  const p60 = await w.planReturn(t60c, r1, payer.address);
  assert.equal(p60.a, 1n);
  assert.ok(p60.marginSegments > 0n);
  await w.burn(p60.returnId, carol);
  await rotate(2);
  const rtx60 = await w.buildRedeem(p60.returnId);
  assert.equal(rtx60.P, 2n);
  assert.equal((await w.submitRedeem(p60.returnId, payer)).state, 'paid');

  // a replay of the paid part is refused while it is in the recent buffers
  const evm = new EvmReader(chain);
  const replay = await evm.estimateGas({ from: payer.address, to: VAULT, data: rtx60.calldata });
  assert.ok('revert' in replay);
  assert.equal(decodeRevert((replay as { revert: Uint8Array }).revert)?.rule, 'AlreadyPaid');

  // return 15 through an ambiguous broadcast: the receipt of the locally computed hash decides
  const p15 = await w.planReturn(t15, r2, payer.address);
  await w.burn(p15.returnId, carol);
  chain.faults.ambiguousSends = 1;
  assert.equal((await w.submitRedeem(p15.returnId, payer)).state, 'paid');

  // return 25 with a witness made stale by two rotations, finished by a fresh instance over the same journal
  const p25 = await w.planReturn(t25, r3, payer.address);
  await w.burn(p25.returnId, bob);
  const stale = await w.buildRedeem(p25.returnId);
  await rotate(2);
  const now = await evm.estimateGas({ from: payer.address, to: VAULT, data: stale.calldata });
  assert.equal(decodeRevert((now as { revert: Uint8Array }).revert)?.rule, 'StaleEndpoint');
  const cold = await NativeBridgeV2.open(options('alice wallet', store));
  assert.equal((await cold.submitRedeem(p25.returnId, payer)).state, 'paid');

  // exactly 100 paid; nothing left outstanding (the second wallet's returns net to zero)
  assert.equal(chain.balanceOf(r1) + chain.balanceOf(r2) + chain.balanceOf(r3), 100n);
  assert.deepEqual([chain.balanceOf(r1), chain.balanceOf(r2), chain.balanceOf(r3)], [60n, 15n, 25n]);
  assert.equal(chain.vault.state().outstanding, 0n);

  // after eviction (two more rotations) the replay's recent check is gone, and its history shows it paid
  await rotate(2);
  const again = await evm.estimateGas({ from: payer.address, to: VAULT, data: rtx60.calldata });
  assert.equal(decodeRevert((again as { revert: Uint8Array }).revert)?.rule, 'StaleEndpoint');
  assert.equal((await w.reconcile(p60.returnId)).state, 'paid');
  const rec = (await w.journal.ret(p60.record.returnId))!;
  const st = await evm.vaultState(VAULT);
  const segs: Segment[] = [];
  let before = unhex(rec.startHead);
  for (const l of await evm.segmentLogs(VAULT, BigInt(rec.fromBlock), BigInt(rec.a), st.segment)) {
    const sg = checkSegmentLog(w.domain, 4n, BigInt(`0x${Buffer.from(l.topics[1]).toString('hex')}`), before, l.data);
    segs.push(sg);
    before = sg.after;
  }
  assert.notEqual(buildHistory(segs, unhex(rec.eta!), BigInt(rec.a), st.segment, unhex(rec.startHead)).paid, null);
  assert.deepEqual(await w.status().then((s) => s.filter((x) => x.includes('paid')).length), 3);
});
