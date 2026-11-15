/**
 * The witness builder against served logs: zero, one and several segments, one rollover between build and submit tolerated, a missing
 * or substituted log reported as missing evidence (never as absence); and the error classification of every vault error from the
 * recorded revert data of the shared vectors.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { classifyRedeemError, decodeRevert } from '../../src/nb2/abi.js';
import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { Nb2Error, WalletError } from '../../src/nb2/errors.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { evmAccount, key, setup, VAULT } from './world.js';
import { EvmReader } from '../../src/nb2/rpc.js';

async function world() {
  const s = await setup();
  const payer = evmAccount(s.chain, 'p');
  const owner = localOwner(key('o'));
  const w = await NativeBridgeV2.open(s.options('w'));
  const token = async (v: bigint): Promise<Uint8Array> => {
    const p = await w.planDeposit(v, owner.publicKey);
    await w.submitDeposit(p, payer);
    await w.collectDepositProof(p.intent);
    return w.mint(p.intent);
  };
  const pay = async (n: number): Promise<void> => {
    for (let k = 0; k < n; k++) {
      const rp = await w.planReturn(await token(1n), HE(key('x')).slice(12), payer.address);
      await w.burn(rp.returnId, owner);
      assert.equal((await w.submitRedeem(rp.returnId, payer)).state, 'paid');
    }
  };
  const burned = async (): Promise<Uint8Array> => {
    const rp = await w.planReturn(await token(2n), HE(key('y')).slice(12), payer.address);
    await w.burn(rp.returnId, owner);
    return rp.returnId;
  };
  return { ...s, w, payer, pay, burned };
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
