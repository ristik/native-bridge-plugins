/** The custody fixes of the nbp#76 review: send races, signer checks, serialization, recovery, verified Paid, the burn's last checks. */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { toHex } from '../../src/bytes.js';
import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { Nb2Error, WalletError } from '../../src/nb2/errors.js';
import { LocalKeySigner, signTx, type EvmSigner } from '../../src/nb2/evm.js';
import { MemoryJournalStore } from '../../src/nb2/journal.js';
import { localOwner, type OwnerSigner } from '../../src/nb2/tokenops.js';
import { TOPIC, firstOwnerOf } from '../../src/nb2/deposit.js';
import { depositCalldata } from '../../src/nb2/abi.js';
import { FakeChain, evmAccount, key, makeConfig, setup, VAULT } from './world.js';
import { encodeConfig } from '../../src/nb2/config.js';

const reason = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof WalletError ? e.reason : e instanceof Nb2Error ? e.rule : String(e);
  }
};
const h = (b: Uint8Array): string => `0x${toHex(b)}`;

/** A switch that makes the chain's next `n` receipt reads miss (a load-balanced backend behind the head). */
function receiptLag(chain: FakeChain): (n: number) => void {
  const real = chain.call.bind(chain);
  let left = 0;
  chain.call = async <T>(m: string, p: any[]): Promise<T> => {
    if (m === 'eth_getTransactionReceipt' && left > 0) {
      left--;
      return null as T;
    }
    return real<T>(m, p);
  };
  return (n) => { left = n; };
}

async function deposited(seed = 'w') {
  const s = await setup();
  const payer = evmAccount(s.chain, 'p');
  const owner = localOwner(key('o'));
  const store = new MemoryJournalStore();
  const w = await NativeBridgeV2.open(s.options(seed, store));
  return { ...s, payer, owner, store, w };
}

test('send race: a send mined between reads, behind a lagging backend, is never doubled', async () => {
  const { chain, payer, owner, w } = await deposited();
  const plan = await w.planDeposit(5n, owner.publicKey);
  chain.autoMine = false;
  assert.equal(await reason(w.submitDeposit(plan, payer)), 'Unconfirmed');
  await chain.flush(); // mined now; the nonce moved past it
  chain.autoMine = true;
  // every receipt read misses: the mined nonce alone must not make the send look dead
  const lag = receiptLag(chain);
  lag(1000);
  assert.equal(await reason(w.submitDeposit(plan.intent, payer)), 'Unconfirmed');
  assert.equal(await reason(w.submitDeposit(plan.intent, payer)), 'Unconfirmed');
  assert.equal(chain.vault.state().deposits, 1n);
  // the backend catches up: the success receipt is the answer, whenever it is seen
  lag(0);
  assert.equal((await w.submitDeposit(plan.intent, payer)).depositNumber, 1n);
  assert.equal(chain.vault.state().deposits, 1n);
});

test('send race windows: lagging receipt, then caught up; a replaced send is dead only after depth', async () => {
  const s = await setup();
  const payer = evmAccount(s.chain, 'p');
  const owner = localOwner(key('o'));
  const store = new MemoryJournalStore();
  const real = s.chain.call.bind(s.chain);
  let lag = 0;
  let companionDown = false;
  s.chain.call = async <T>(m: string, p: any[]): Promise<T> => {
    if (m === 'unicity_getSealCompanionV1' && companionDown) return { status: 'unknown' } as T;
    if (m === 'eth_getTransactionReceipt' && lag > 0) {
      lag--;
      return null as T;
    }
    return real<T>(m, p);
  };
  const w = await NativeBridgeV2.open({ ...s.options('w', store), deadAfterBlocks: 3n });
  // window 1: the send is mined between the broadcast's receipt read and the next call's reads
  const p1 = await w.planDeposit(5n, owner.publicKey);
  s.chain.autoMine = false;
  assert.equal(await reason(w.submitDeposit(p1, payer)), 'Unconfirmed');
  await s.chain.flush();
  s.chain.autoMine = true;
  lag = 1; // the first receipt read misses, the nonce read (taken first) already shows it mined
  assert.equal(await reason(w.submitDeposit(p1.intent, payer)), 'Unconfirmed');
  assert.equal((await w.submitDeposit(p1.intent, payer)).depositNumber, 1n);
  assert.equal(s.chain.vault.state().deposits, 1n);
  // window 2: a send replaced by another transaction of the same nonce is dead, but only after the head advanced deadAfterBlocks
  const p2 = await w.planDeposit(6n, owner.publicKey);
  s.chain.autoMine = false;
  assert.equal(await reason(w.submitDeposit(p2, payer)), 'Unconfirmed');
  s.chain.dropPool();
  const nonce = BigInt(await real<string>('eth_getTransactionCount', [h(payer.address), 'latest']));
  const other = await signTx(payer, { chainId: 31337n, nonce, maxPriorityFeePerGas: 1n, maxFeePerGas: 15n, gas: 21_000n, to: HE(key('z')).slice(12), value: 1n, data: new Uint8Array() });
  await real('eth_sendRawTransaction', [h(other.raw)]);
  await s.chain.flush();
  s.chain.autoMine = true;
  assert.equal(await reason(w.submitDeposit(p2.intent, payer)), 'Unconfirmed'); // first seen used: pending
  assert.equal(await reason(w.submitDeposit(p2.intent, payer)), 'Unconfirmed'); // not deep enough yet
  for (let k = 0; k < 3; k++) await s.chain.mine([]);
  // deep enough, but the block at nonceUsedAt has no certificate served: still not dead
  companionDown = true;
  assert.equal(await reason(w.submitDeposit(p2.intent, payer)), 'Unconfirmed');
  companionDown = false;
  assert.equal((await w.submitDeposit(p2.intent, payer)).depositNumber, 2n); // certified and deep: dead, one new send
  assert.equal(s.chain.vault.state().deposits, 2n);
});

test('an external signer must return exactly the requested transaction from its own address', async () => {
  const { chain, owner, w } = await deposited();
  const honest = evmAccount(chain, 'x');
  const lying: EvmSigner = { address: honest.address, signTransaction: (t) => honest.signTransaction({ ...t, value: t.value + 1n }) };
  const impostor: EvmSigner = { address: HE(key('i')).slice(12), signTransaction: (t) => honest.signTransaction(t) };
  const plan = await w.planDeposit(5n, owner.publicKey);
  assert.match(await reason(w.submitDeposit(plan, lying)), /another transaction/);
  assert.match(await reason(w.submitDeposit(plan, impostor)), /not from the signer/);
  assert.equal(chain.vault.state().deposits, 0n);
  assert.equal((await w.journal.deposit(plan.intent))!.sends.length, 0);
});

test('serialization: concurrent plans never share an intent; a second writer loses the compare-and-swap', async () => {
  const { chain, payer, owner, store, w, options } = await deposited();
  const plans = await Promise.all(Array.from({ length: 6 }, () => w.planDeposit(1n, owner.publicKey)));
  assert.deepEqual(plans.map((p) => p.intent).sort(), [0n, 1n, 2n, 3n, 4n, 5n]);
  // two instances on one store race one burn: one wins, the other is refused before certifying anything else
  await w.submitDeposit(plans[0], payer);
  await w.collectDepositProof(0n);
  const t = await w.mint(0n);
  const rp = await w.planReturn(t, HE(key('r')).slice(12), payer.address);
  const w2 = await NativeBridgeV2.open(options('w', store));
  await w2.journal.ret(rp.record.returnId); // both have read the planned record
  await w.journal.ret(rp.record.returnId);
  const outs = await Promise.allSettled([w.burn(rp.returnId, owner), w2.burn(rp.returnId, owner)]);
  const ok = outs.filter((o) => o.status === 'fulfilled');
  assert.ok(ok.length >= 1);
  for (const o of outs) if (o.status === 'rejected') assert.equal((o.reason as WalletError).reason, 'JournalConflict');
  const final = (await w2.journal.ret(rp.record.returnId))!;
  assert.equal(final.status, 'burned');
  for (const o of ok) assert.equal(h((o as PromiseFulfilledResult<{ eta: Uint8Array }>).value.eta), final.eta);
  void chain;
});

test('recovery: a stale planned record is upgraded, the pre-send scan finds a deposit, every deposit number is kept', async () => {
  const { chain, payer, owner, store, w, options } = await deposited();
  const plan = await w.planDeposit(5n, owner.publicKey);
  const copy = new MemoryJournalStore();
  for (const [k, v] of store.map) copy.map.set(k, v); // a second device restored before the send
  // both devices send the same intent before either sees the other's deposit (a faulty wallet reusing r)
  chain.autoMine = false;
  assert.equal(await reason(w.submitDeposit(plan, payer)), 'Unconfirmed');
  const b = await NativeBridgeV2.open(options('w', copy));
  const payer2 = evmAccount(chain, 'p2');
  assert.equal(await reason(b.submitDeposit(plan.intent, payer2)), 'Unconfirmed');
  await chain.flush();
  chain.autoMine = true;
  assert.equal(chain.vault.state().deposits, 2n);
  assert.equal((await w.submitDeposit(plan.intent, payer)).depositNumber, 1n);
  // the record's own deposit is merged with a rho scan: both numbers are journaled at once
  assert.deepEqual((await w.journal.deposit(plan.intent))!.seenDeposits!.map((x) => x.depositNumber), ['1', '2']);
  // device b's own deposit is number 2: its mint tags that entry, not entry 0
  assert.equal((await b.submitDeposit(plan.intent, payer2)).depositNumber, 2n);
  await b.collectDepositProof(plan.intent);
  await b.mint(plan.intent);
  const bs = (await b.journal.deposit(plan.intent))!.seenDeposits!;
  assert.deepEqual(bs.map((x) => x.token !== undefined), [false, true]);
  // a third device with the stale planned record: the pre-send scan adopts the deposits, and sends nothing
  const third = new MemoryJournalStore();
  for (const [k, v] of copy.map) if (!k.includes('/deposit/')) third.map.set(k, v);
  third.map.set([...copy.map.keys()].find((k) => k.includes('/deposit/'))!, store.map.get([...store.map.keys()].find((k) => k.includes('/deposit/'))!)!.replace(/"status":"submitted"/, '"status":"planned"').replace(/"sends":\[[^\]]*\]/, '"sends":[]'));
  const c = await NativeBridgeV2.open(options('w', third));
  await c.submitDeposit(plan.intent, payer);
  assert.equal(chain.vault.state().deposits, 2n);
  // recovery journals both deposit numbers; the second mints as its own root token
  await w.recoverDeposits(1n);
  const rec = (await w.journal.deposit(plan.intent))!;
  assert.deepEqual(rec.seenDeposits!.map((x) => x.depositNumber), ['1', '2']);
  await w.collectDepositProof(plan.intent);
  await w.mint(plan.intent);
  const extra = await w.mintExtraDeposit(plan.intent, 2n);
  assert.equal((await w.verifyToken(extra)).amount, 5n);
  // a deposit of the same rho to another first owner: its entry keeps that owner and its mint goes to it
  const other = localOwner(key('other owner'));
  const raw = await signTx(payer, {
    chainId: 31337n, nonce: BigInt(await chain.call<string>('eth_getTransactionCount', [h(payer.address), 'pending'])), maxPriorityFeePerGas: 1n, maxFeePerGas: 15n,
    gas: 200_000n, to: VAULT, value: 3n, data: depositCalldata(firstOwnerOf(other.publicKey), plan.rho),
  });
  await chain.call('eth_sendRawTransaction', [h(raw.raw)]);
  await w.recoverDeposits(1n);
  const third3 = (await w.journal.deposit(plan.intent))!.seenDeposits!.find((x) => x.depositNumber === '3')!;
  assert.equal(third3.firstOwner, h(firstOwnerOf(other.publicKey)));
  const t3 = await w.mintExtraDeposit(plan.intent, 3n);
  assert.deepEqual((await w.verifyToken(t3)).owner, other.publicKey);
});

test('Paid counts only from the vault and only with a certified receipt: a lying provider cannot stop a redemption', async () => {
  const { chain, payer, owner, w } = await deposited();
  const plan = await w.planDeposit(4n, owner.publicKey);
  await w.submitDeposit(plan, payer);
  await w.collectDepositProof(plan.intent);
  const rp = await w.planReturn(await w.mint(plan.intent), HE(key('r')).slice(12), payer.address);
  const { eta } = await w.burn(rp.returnId, owner);
  // the provider invents Paid(eta) logs: one from another address, one from the vault in a transaction that never paid
  const real = chain.call.bind(chain);
  const fake = (address: Uint8Array) => ({
    address: h(address), topics: [h(TOPIC.Paid), h(eta), h(new Uint8Array(32))], data: h(new Uint8Array(32)), blockNumber: '0x2', blockHash: h(chain.blocks[2].hash),
    transactionHash: h(HE(key('fake'))), logIndex: '0x0', removed: false,
  });
  chain.call = async <T>(m: string, p: any[]): Promise<T> => {
    const out = await real<any>(m, p);
    if (m === 'eth_getLogs' && p[0].topics?.[0] === h(TOPIC.Paid)) return [fake(HE(key('other')).slice(12)), fake(VAULT), ...out] as T;
    return out as T;
  };
  assert.equal((await w.reconcile(rp.returnId)).state, 'not-paid');
  assert.equal((await w.submitRedeem(rp.returnId, payer)).state, 'paid');
  assert.equal(chain.balanceOf(HE(key('r')).slice(12)), 4n);
});

test('the burn re-runs the preflight and checks the owner signature before anything irreversible is journaled', async () => {
  const { chain, payer, owner, w } = await deposited();
  const plan = await w.planDeposit(4n, owner.publicKey);
  await w.submitDeposit(plan, payer);
  await w.collectDepositProof(plan.intent);
  const t = await w.mint(plan.intent);
  const poorPayer = evmAccount(chain, 'poor');
  const rp = await w.planReturn(t, HE(key('r')).slice(12), poorPayer.address);
  chain.balances.set(toHex(poorPayer.address), 0n); // the payer was drained after planning
  assert.equal(await reason(w.burn(rp.returnId, owner)), 'InsufficientFunds');
  assert.equal((await w.journal.ret(rp.record.returnId))!.status, 'planned');
  chain.fund(poorPayer.address, 10n ** 24n);
  // an owner key whose signer returns recovery ID 2: refused (UnlockRecovery) before the burn request is journaled
  const odd: OwnerSigner = { publicKey: owner.publicKey, signUnlock: async (m) => { const s = await owner.signUnlock(m); s[64] = 2; return s; } };
  assert.equal(await reason(w.burn(rp.returnId, odd)), 'UnlockRecovery');
  assert.equal((await w.journal.ret(rp.record.returnId))!.status, 'planned');
  assert.equal((await w.burn(rp.returnId, owner)).verdict.amount, 4n);
});

test('options: the measured gas model is the default; k_w is not in the options; an old seal warns', async () => {
  const s = await setup();
  const o = s.options('w');
  const prodGamma = encodeConfig(makeConfig(s.root, 64n, 16n));
  // a production build opens with the measured model by default: no opt-in
  assert.equal((await NativeBridgeV2.open({ ...o, pins: { ...o.pins, gamma: prodGamma, build: 'production' } }, false)).gas.name, 'measured-nb2-05');
  const w = await NativeBridgeV2.open({ ...o, maxSealAgeBlocks: 0n });
  assert.equal((w as unknown as { opts: Record<string, unknown> }).opts.bridgeKey, undefined);
  // a seal exists after four payments; with a zero age bound the plan carries the freshness warning
  const payer = evmAccount(s.chain, 'p');
  const owner = localOwner(key('o'));
  for (let k = 0; k < 4; k++) {
    const p = await w.planDeposit(1n, owner.publicKey);
    await w.submitDeposit(p, payer);
    await w.collectDepositProof(p.intent);
    const rp = await w.planReturn(await w.mint(p.intent), HE(key('r')).slice(12), payer.address);
    await w.burn(rp.returnId, owner);
    await w.submitRedeem(rp.returnId, payer);
  }
  const p = await w.planDeposit(1n, owner.publicKey);
  await w.submitDeposit(p, payer);
  await w.collectDepositProof(p.intent);
  await s.chain.mine([]);
  const plan = await w.planReturn(await w.mint(p.intent), HE(key('r')).slice(12), payer.address);
  assert.equal(plan.a, 1n);
  assert.ok(plan.warnings.some((x) => x.includes('blocks old')));
  void LocalKeySigner;
});

test('a Deposited event with another deployment\'s domain D is not this deposit (the record stays submitted)', async () => {
  const { chain, payer, owner, w } = await deposited();
  const real = chain.call.bind(chain);
  chain.call = async <T>(m: string, p: any[]): Promise<T> => {
    const r = await real<T>(m, p);
    if (m !== 'eth_getTransactionReceipt' || r === null) return r;
    const rc = r as unknown as { logs: { topics: string[]; data: string }[] };
    // the same rho and amount, under another D (a vault of another configuration at the same address)
    for (const l of rc.logs) if (l.topics[0].toLowerCase() === h(TOPIC.Deposited)) l.data = `0x${'5a'.repeat(32)}${l.data.slice(66)}`;
    return r;
  };
  const plan = await w.planDeposit(7n, owner.publicKey);
  assert.equal(await reason(w.submitDeposit(plan, payer)), 'ProviderFault');
  assert.equal((await w.journal.deposit(plan.intent))!.status, 'submitted');
});
