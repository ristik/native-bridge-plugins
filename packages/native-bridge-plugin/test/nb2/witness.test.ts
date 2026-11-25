/**
 * The witness builder against served logs: zero, one and several segments, one rollover between build and submit tolerated, a missing
 * or substituted log reported as missing evidence (never as absence); and the error classification of every vault error from the
 * recorded revert data of the shared vectors.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { fromHex, toHex } from '../../src/bytes.js';
import { classifyRedeemError, decodeRevert, revertData } from '../../src/nb2/abi.js';
import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { decodeSignedTx } from '../../src/nb2/evm.js';
import { Nb2Error, WalletError } from '../../src/nb2/errors.js';
import { MemoryJournalStore } from '../../src/nb2/journal.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { evmAccount, key, setup, VAULT } from './world.js';
import { EvmReader, RpcError } from '../../src/nb2/rpc.js';

async function world() {
  const s = await setup();
  const payer = evmAccount(s.chain, 'p');
  const owner = localOwner(key('o'));
  const store = new MemoryJournalStore();
  const w = await NativeBridgeV2.open(s.options('w', store));
  const token = async (v: bigint, actor = payer): Promise<Uint8Array> => {
    const p = await w.planDeposit(v, owner.publicKey);
    await w.submitDeposit(p, actor);
    await w.collectDepositProof(p.intent);
    return w.mint(p.intent);
  };
  const pay = async (n: number, actor = payer): Promise<void> => {
    for (let k = 0; k < n; k++) {
      const rp = await w.planReturn(await token(1n, actor), HE(key('x')).slice(12), actor.address);
      await w.burn(rp.returnId, owner);
      assert.equal((await w.submitRedeem(rp.returnId, actor)).state, 'paid');
    }
  };
  const burned = async (): Promise<Uint8Array> => {
    const rp = await w.planReturn(await token(2n), HE(key('y')).slice(12), payer.address);
    await w.burn(rp.returnId, owner);
    return rp.returnId;
  };
  return { ...s, w, payer, pay, burned, store };
}

test('history of zero, one and several segments; one rollover in flight is tolerated', async () => {
  const { w, payer, pay, burned, chain } = await world();
  const id = await burned();
  assert.equal((await w.buildRedeem(id)).P, 0n);
  await pay(4);
  assert.equal((await w.buildRedeem(id)).P, 1n);
  await pay(8);
  const built = await w.buildRedeem(id);
  assert.equal(built.P, 3n);
  // one more seal between build and submit: the old witness ends at c - 1, still accepted
  await pay(4);
  const sim = await new EvmReader(chain).estimateGas({ from: payer.address, to: VAULT, data: built.calldata });
  assert.ok('gas' in sim);
  assert.equal((await w.submitRedeem(id, payer)).state, 'paid');
});

test('a missing or substituted segment log is missing evidence, never absence', async () => {
  const { w, pay, burned, chain } = await world();
  const id = await burned();
  await pay(8);
  chain.faults.hideSegments.add(1n);
  await assert.rejects(w.buildRedeem(id), (e) => e instanceof WalletError && e.reason === 'EvidenceMissing');
  chain.faults.hideSegments.clear();
  // a provider that serves segment 1's log in place of segment 0's: the chain link refuses it
  const real = chain.call.bind(chain);
  chain.call = async <T>(m: string, p: any[]): Promise<T> => {
    const r = await real<any>(m, p);
    if (m !== 'eth_getLogs' || !Array.isArray(r)) return r as T;
    const seals = r.filter((l: any) => l.topics.length === 2 && l.topics[0] === p[0].topics[0]);
    if (seals.length >= 2) [seals[0].data, seals[1].data] = [seals[1].data, seals[0].data];
    return r as T;
  };
  await assert.rejects(w.buildRedeem(id), (e) => e instanceof Nb2Error && e.rule === 'SegmentLog');
});

test('a deployed quorum refusal is retryable and the same certified burn pays after import', async () => {
  const { w, payer, burned, chain } = await world();
  const id = await burned();
  const rpc = chain.call.bind(chain);
  let refusal = revertData('VerifierRefused', revertData('QuorumNotMet'));
  let sends = 0;
  chain.call = async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_sendRawTransaction') sends++;
    if (method === 'eth_estimateGas' && refusal.length !== 0) {
      throw new RpcError(200, 3, 'execution reverted', `0x${Buffer.from(refusal).toString('hex')}`);
    }
    return rpc<T>(method, params);
  };

  assert.equal(classifyRedeemError(decodeRevert(refusal)), 'retry-later');
  await assert.rejects(w.buildRedeem(id), (e) => e instanceof Nb2Error &&
    e.rule === 'VerifierRefused' && e.inner?.rule === 'QuorumNotMet' && e.retryable);
  await assert.rejects(w.submitRedeem(id, payer), (e) => e instanceof Nb2Error && e.retryable);
  assert.equal(sends, 0);

  refusal = revertData('VerifierRefused', revertData('SealRoot'));
  await assert.rejects(w.buildRedeem(id), (e) => e instanceof Nb2Error &&
    e.rule === 'VerifierRefused' && e.inner?.rule === 'SealRoot' && !e.retryable);
  assert.equal(new Nb2Error('QuorumNotMet').retryable, false, 'offline quorum failure is final');
  assert.equal(sends, 0);

  refusal = new Uint8Array();
  assert.equal((await w.submitRedeem(id, payer)).state, 'paid');
  assert.equal(sends, 1);
});

test('a never-broadcast return rebuilds after two rollovers during finalized import lag', async () => {
  const { w, payer, burned, chain, pay } = await world();
  const id = await burned();
  const original = await w.buildRedeem(id);
  chain.importedTipEpoch = 0n;
  const sends = () => chain.calls.filter((call) => call === 'eth_sendRawTransaction').length;
  const firstSendCount = sends();
  await assert.rejects(w.submitRedeem(id, payer), { reason: 'ImportLag', retryable: true });
  const pending = await w.journal.ret('0x' + toHex(id));
  assert.equal(pending?.status, 'burned');
  assert.equal(pending?.sends.length, 0);
  assert.equal(pending?.executionPayer, undefined);
  assert.equal(sends(), firstSendCount);
  chain.importedTipEpoch = 1n;
  await pay(8);
  const rebuilt = await w.buildRedeem(id);
  assert.equal(rebuilt.endpoint, original.endpoint + 2n);
  assert.notDeepEqual(rebuilt.calldata, original.calldata);
  const beforeResume = sends();
  assert.equal((await w.submitRedeem(id, payer)).state, 'paid');
  const paid = await w.journal.ret('0x' + toHex(id));
  assert.equal(paid?.burned, pending?.burned);
  assert.equal(paid?.sends.length, 1);
  assert.equal(sends(), beforeResume + 1);
});

test('an expired payout after a lost send rebuilds at the same nonce and certifies Paid after restart', async () => {
  const { w, payer, burned, chain, pay, options, store } = await world();
  const id = await burned();
  const keyOf = '0x' + toHex(id);
  const call = chain.call.bind(chain);
  chain.call = async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_sendRawTransaction') throw new Error('transport before delivery');
    return call<T>(method, params);
  };
  await assert.rejects(w.submitRedeem(id, payer), /transport before delivery/);
  const pending = (await w.journal.ret(keyOf))!;
  assert.equal(pending.sends.length, 1);
  chain.call = call;
  await pay(8, evmAccount(chain, 'independent payer'));
  const reopened = await NativeBridgeV2.open(options('w', store));
  assert.equal((await reopened.submitRedeem(id, payer)).state, 'paid');
  const paid = (await reopened.journal.ret(keyOf))!;
  assert.ok(paid.paid?.receipt);
  assert.equal(paid.burned, pending.burned);
  assert.equal(paid.sends.length, 2);
  assert.deepEqual(paid.sends[0], pending.sends[0]);
  const [old, replacement] = paid.sends.map(({ raw }) => decodeSignedTx(fromHex(raw.slice(2))!));
  assert.equal(replacement.request.nonce, old.request.nonce);
  assert.deepEqual(replacement.from, old.from);
  assert.notDeepEqual(replacement.request.data, old.request.data);
  assert.equal(await call('eth_getTransactionReceipt', [paid.sends[0].hash]), null);
  assert.equal(chain.vault.events.filter((e) => e.name === 'Paid').length, 9);
});

test('a final refusal after a mined revert preserves the decoded inner rule', async () => {
  const { w, payer, burned, chain } = await world();
  const id = await burned();
  const inner = revertData('SealRoot');
  const refusal = revertData('VerifierRefused', inner);
  chain.faults.recipients.set(toHex(HE(key('y')).slice(12)), 'reverts');
  const rpc = chain.call.bind(chain);
  let estimates = 0;
  const hashes: string[] = [];
  chain.call = async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_estimateGas') {
      if (++estimates === 1) return '0x1d4c0' as T;
      throw new RpcError(200, 3, 'execution reverted', `0x${toHex(refusal)}`);
    }
    if (method === 'eth_call' && typeof params[1] === 'object') return '0x' as T;
    const result = await rpc<T>(method, params);
    if (method === 'eth_sendRawTransaction') hashes.push(result as string);
    return result;
  };
  await assert.rejects(w.submitRedeem(id, payer), (e) => e instanceof Nb2Error &&
    e.rule === 'VerifierRefused' && e.inner?.rule === 'SealRoot' &&
    e.args?.[0] === `0x${toHex(inner)}` && !e.retryable);
  assert.equal(estimates, 2);
  assert.equal(hashes.length, 1);
  assert.equal((await rpc<{ status: string }>('eth_getTransactionReceipt', hashes)).status, '0x0');
});

test('every vault error classifies from its recorded revert data', () => {
  const F = JSON.parse(readFileSync(new URL('../../../../protocol/vectors/nb2/nb2-vectors.json', import.meta.url), 'utf8'));
  const want: Record<string, string> = {
    AlreadyPaid: 'reconcile', StaleEndpoint: 'rebuild-history', FutureIndex: 'wait', BadGapProof: 'repair-proof', ChainMismatch: 'repair-proof',
    BadHistoryLength: 'repair-proof', PayoutFailed: 'retry-later', Reentrancy: 'retry-later', VerifierRefused: 'stop', VerifierBadReturn: 'stop',
    DomainMismatch: 'stop', AssetMismatch: 'stop', ClaimMismatch: 'stop', BadRecipient: 'stop', ZeroAmount: 'stop', LiabilityUnderflow: 'stop',
    SegmentCounterExhausted: 'stop', ZeroValue: 'stop', BadFirstOwner: 'stop', LiabilityCap: 'stop', DepositCounterExhausted: 'stop',
  };
  const seen = new Set<string>();
  for (const v of F.vault) {
    for (const st of v.steps) {
      if (!st.expect.error) continue;
      const d = decodeRevert(Uint8Array.from(Buffer.from(st.expect.revert.slice(2), 'hex')));
      assert.equal(d?.rule, st.expect.error, v.id);
      assert.equal(classifyRedeemError(d), want[st.expect.error], `${v.id} ${st.expect.error}`);
      seen.add(st.expect.error);
    }
  }
  assert.ok(seen.size >= 18, `classified ${[...seen]}`);
});
