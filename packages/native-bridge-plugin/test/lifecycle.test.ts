import assert from 'node:assert/strict';
import { test } from 'node:test';

import { InclusionCertificate } from '@unicitylabs/state-transition-sdk/lib/api/InclusionCertificate.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { DataHasherFactory } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasherFactory.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { NodeDataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/NodeDataHasher.js';
import { SparseMerkleTree } from '@unicitylabs/state-transition-sdk/lib/smt/radix/SparseMerkleTree.js';

import { eq } from '../src/bytes.js';
import { NativeError } from '../src/errors.js';
import { RedemptionUnconfirmed, type ChainReader, type RedeemPolicy, type RedeemTransport } from '../src/readiness.js';
import { ClaimUnconfirmed, abandonAttempt, claimCredited, redeemBurned, type ClaimPolicy, type ClaimTransport } from '../src/lifecycle.js';
import { MemoryRedemptionJournal, NativeBridgePayments, createNativeBridgePlugin, uintOf, type NativeWalletBackend, type RedemptionEntry } from '../src/wallet.js';
import { AGG_PARTITION, VAULT, buildToken, burnStep, makeUc, makeWorld, recipient20, sha, spec, txStep, type World } from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;
const rev = { manifestRevision: 'm', profileRevision: 'p' };
const noWait = { sleep: () => Promise.resolve() };
const fast = { maxAttempts: 3, maxOriginWaitMs: 1_000, pollMs: 1, ...noWait };
const rp = (over: Partial<RedeemPolicy> = {}): RedeemPolicy => ({ ...fast, maxSends: 3, receiptTimeoutMs: 10, now: (() => { let n = 0; return () => (n += 4); })(), ...over });
const cp = (over: Partial<ClaimPolicy> = {}): ClaimPolicy => ({ receiptTimeoutMs: 10, pollMs: 1, now: (() => { let n = 0; return () => (n += 4); })(), ...noWait, ...over });
const chain: ChainReader = { origin: () => Promise.resolve(952n) };

async function setup() {
  const w = makeWorld();
  const out = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
  const plugin = createNativeBridgePlugin(w.bridge, rev);
  const v = await plugin.bridge.verifyNativeToken(out.token, 'return');
  const journal = new MemoryRedemptionJournal();
  const payments = new NativeBridgePayments(plugin, {} as NativeWalletBackend, journal);
  const entry: RedemptionEntry = { burnId: 'b1', tokenId: 't1', burnedToken: out.bytes, nullifier: v.outcome.nullifier, nonce: v.outcome.nonce, amount: uintOf(v.outcome.amount), releaseTo: v.outcome.releaseTo, status: 'burned', redeemTxs: [] };
  await journal.put(entry);
  const source = async (): Promise<InclusionProof[]> => {
    const old = [out.token.genesis, ...out.token.transactions].map((c) => c.inclusionProof);
    const smt = new SparseMerkleTree(new DataHasherFactory(HashAlgorithm.SHA256, NodeDataHasher));
    for (const [k, val] of out.leaves) await smt.addLeaf(k, val);
    const root = await smt.calculateRoot();
    const uc = await makeUc(w.agg, { partition: AGG_PARTITION, conf: w.aggConf, epochIr: 1n, rootEpoch: 2n, round: 950n, timestamp: UC_TS, stateHash: root.hash.data, blockHash: null, signers: 4 });
    return old.map((o, i) => new InclusionProof(o.certificationData, o.referenceTime, InclusionCertificate.create(root, out.leaves[i][0]), uc));
  };
  return { w, out, plugin, payments, journal, entry, source };
}

/** A fake vault with the real vault's shape: spent state keyed by lock nonce (value: the nullifier), credit per recipient, pull-payment claim. */
class FakeVault implements RedeemTransport, ClaimTransport {
  public spent = new Map<bigint, Uint8Array>();
  public credit = new Map<string, bigint>();
  public paid = 0n;
  public sentRedeems: string[] = [];
  public sentClaims: { amount: bigint; to: string }[] = [];
  public receipts = new Map<string, 'success' | 'reverted' | undefined>();
  public onSend?: () => Promise<void>;
  /** what the next redeem/claim send does: 'ok' executes and mines it, 'lost' executes it but the RPC call throws, 'pending' sends without mining, 'revert' mines a revert */
  public next: 'ok' | 'lost' | 'pending' | 'revert' = 'ok';
  public constructor(private readonly s: Awaited<ReturnType<typeof setup>>) {}
  private readonly key = (a: Uint8Array): string => Buffer.from(a).toString('hex');
  public async send(arg: Uint8Array | { to: Uint8Array; data: Uint8Array }): Promise<string> {
    await this.onSend?.();
    const hash = `0x${(this.sentRedeems.length + this.sentClaims.length + 1).toString(16)}`;
    const isClaim = !(arg instanceof Uint8Array);
    if (isClaim) {
      assert.ok(eq(arg.to, VAULT), 'claims go to the vault');
      const amount = uintOf(arg.data.slice(4, 36));
      this.sentClaims.push({ amount, to: this.key(arg.data.slice(4 + 44)) });
      if (this.next === 'ok' || this.next === 'lost') {
        const k = this.key(this.s.entry.releaseTo);
        this.credit.set(k, (this.credit.get(k) ?? 0n) - amount);
        this.paid += amount;
        this.receipts.set(hash, 'success');
      } else this.receipts.set(hash, this.next === 'revert' ? 'reverted' : undefined);
    } else {
      this.sentRedeems.push(hash);
      if (this.next === 'ok' || this.next === 'lost') {
        this.spent.set(this.s.entry.nonce, this.s.entry.nullifier);
        const k = this.key(this.s.entry.releaseTo);
        this.credit.set(k, (this.credit.get(k) ?? 0n) + this.s.entry.amount);
        this.receipts.set(hash, 'success');
      } else this.receipts.set(hash, this.next === 'revert' ? 'reverted' : undefined);
    }
    if (this.next === 'lost') throw new Error('timeout');
    return hash;
  }
  public receipt(h: string): Promise<'success' | 'reverted' | undefined> { return Promise.resolve(this.receipts.get(h)); }
  /** The real vault answers `spentNullifier(nonce)` with a ZERO WORD for a nonce that was not redeemed. */
  public spentNullifier(nonce: bigint): Promise<Uint8Array | undefined> { return Promise.resolve(this.spent.get(nonce) ?? new Uint8Array(32)); }
  public claimable(r: Uint8Array): Promise<bigint> { return Promise.resolve(this.credit.get(this.key(r)) ?? 0n); }
}

test('the whole wallet path: burned -> submitted -> redeemed -> claimable -> claim -> settled, each state journalled', async () => {
  const s = await setup();
  const vault = new FakeVault(s);
  const seen: string[] = [];
  vault.onSend = async () => void seen.push(`during send: ${(await s.journal.get('b1'))!.status}`);
  assert.equal((await s.journal.get('b1'))!.status, 'burned');
  const r = await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp());
  assert.equal(r.status, 'redeemed');
  assert.deepEqual(seen, ['during send: submitted'], 'the journal says submitted BEFORE the transaction leaves');
  let e = (await s.journal.get('b1'))!;
  assert.equal(e.status, 'redeemed');
  assert.deepEqual(e.redeemTxs, ['0x1']);
  assert.equal(await vault.claimable(e.releaseTo), e.amount, 'the vault credited the recipient');
  // claim to a payee account: the journal settles only on the receipt AND the balance falling
  const payee = new Uint8Array(20).fill(0xbe);
  const c = await claimCredited(s.payments, 'b1', payee, VAULT, vault, cp());
  assert.equal(c.amount, e.amount);
  assert.equal(c.claimableBefore, e.amount);
  assert.equal(c.claimableAfter, 0n);
  e = (await s.journal.get('b1'))!;
  assert.equal(e.status, 'settled');
  assert.equal(e.claimTx, c.txHash);
  assert.equal(vault.paid, e.amount);
  assert.deepEqual(vault.sentClaims, [{ amount: e.amount, to: Buffer.from(payee).toString('hex') }]);
  // a settled burn is neither redeemed nor claimed again
  assert.equal((await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp())).status, 'already-redeemed');
  assert.equal(vault.sentRedeems.length, 1);
  await assert.rejects(claimCredited(s.payments, 'b1', payee, VAULT, vault, cp()), /already settled/);
});

test('an unconfirmed redeem stays submitted with its hash; the next call checks the receipt and never resends', async () => {
  const s = await setup();
  const vault = new FakeVault(s);
  vault.next = 'pending';
  const err = await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp()).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof RedemptionUnconfirmed && err.txHash === '0x1');
  let e = (await s.journal.get('b1'))!;
  assert.equal(e.status, 'submitted');
  assert.deepEqual(e.redeemTxs, ['0x1']);
  // restart: the hash is in the journal, the transaction is mined meanwhile
  vault.receipts.set('0x1', 'success');
  vault.spent.set(e.nonce, e.nullifier);
  vault.credit.set(Buffer.from(e.releaseTo).toString('hex'), e.amount);
  const r = await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp());
  assert.equal(r.status, 'redeemed');
  assert.equal(vault.sentRedeems.length, 1, 'nothing was sent again');
  assert.equal((await s.journal.get('b1'))!.status, 'redeemed');
  // a send that threw without a hash but was executed: the vault state settles it with no proof fetch
  const t = await setup();
  const lost = new FakeVault(t);
  lost.next = 'lost';
  const e2 = await redeemBurned(t.plugin, t.payments, 'b1', t.source, chain, lost, rp()).then((x) => x, (x: unknown) => x);
  assert.equal((e2 as { status: string }).status, 'redeemed');
});

test('the claim: a reverted or unconfirmed claim does not settle; its hash is journalled and checked before any resend', async () => {
  const s = await setup();
  const vault = new FakeVault(s);
  await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp());
  const payee = new Uint8Array(20).fill(0xbe);
  vault.next = 'revert';
  await assert.rejects(claimCredited(s.payments, 'b1', payee, VAULT, vault, cp()), /reverted/);
  assert.equal((await s.journal.get('b1'))!.status, 'redeemed');
  vault.next = 'pending';
  const err = await claimCredited(s.payments, 'b1', payee, VAULT, vault, cp()).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof ClaimUnconfirmed && err instanceof NativeError);
  const e = (await s.journal.get('b1'))!;
  assert.equal(e.status, 'redeemed');
  assert.equal(e.claimTx, (err as ClaimUnconfirmed).txHash);
  const sentBefore = vault.sentClaims.length;
  // mined later: the journalled hash decides, nothing is sent again
  vault.receipts.set(e.claimTx!, 'success');
  vault.credit.set(Buffer.from(e.releaseTo).toString('hex'), 0n);
  const done = await claimCredited(s.payments, 'b1', payee, VAULT, vault, cp());
  assert.equal(done.txHash, e.claimTx);
  assert.equal(vault.sentClaims.length, sentBefore);
  assert.equal((await s.journal.get('b1'))!.status, 'settled');
});

test('the claim refuses a burn that is not redeemed, an empty balance, a balance that did not fall, and a bad destination', async () => {
  const s = await setup();
  const vault = new FakeVault(s);
  const payee = new Uint8Array(20).fill(0xbe);
  await assert.rejects(claimCredited(s.payments, 'b1', payee, VAULT, vault, cp()), /burned: redeem it before claiming/);
  await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp());
  await assert.rejects(claimCredited(s.payments, 'b1', new Uint8Array(20), VAULT, vault, cp()), /ErrLockInput/);
  await assert.rejects(claimCredited(s.payments, 'b1', VAULT, VAULT, vault, cp()), /ErrLockInput/);
  assert.equal(vault.sentClaims.length, 0, 'a bad destination costs no gas');
  // someone else already claimed the credit
  vault.credit.set(Buffer.from(s.entry.releaseTo).toString('hex'), 0n);
  await assert.rejects(claimCredited(s.payments, 'b1', payee, VAULT, vault, cp()), /below the redeemed amount/);
  // a claim that is mined but does not lower the balance is not settlement
  vault.credit.set(Buffer.from(s.entry.releaseTo).toString('hex'), s.entry.amount);
  const inert = new FakeVault(s);
  inert.credit = vault.credit;
  inert.send = async (): Promise<string> => { inert.receipts.set('0x9', 'success'); return '0x9'; };
  await assert.rejects(claimCredited(s.payments, 'b1', payee, VAULT, inert, cp()), /not down by the claimed/);
  assert.equal((await s.journal.get('b1'))!.status, 'redeemed', 'unverified: not settled');
});
test('a pending hash with no receipt does not hide a redemption the vault already shows (a dropped transaction, a third party\'s redeem)', async () => {
  const s = await setup();
  const vault = new FakeVault(s);
  vault.next = 'pending';
  await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp()).then(() => undefined, () => undefined);
  const stuck = (await s.journal.get('b1'))!;
  assert.equal(stuck.status, 'submitted');
  assert.deepEqual(stuck.redeemTxs, ['0x1']);
  // our transaction is dropped and never gets a receipt; someone else redeems the same nonce
  vault.spent.set(stuck.nonce, stuck.nullifier);
  vault.credit.set(Buffer.from(stuck.releaseTo).toString('hex'), stuck.amount);
  let fetches = 0;
  const r = await redeemBurned(s.plugin, s.payments, 'b1', async () => { fetches++; throw new Error('proof service down'); }, chain, vault, rp());
  assert.equal(r.status, 'already-redeemed');
  assert.equal(fetches, 0);
  assert.equal(vault.sentRedeems.length, 1);
  assert.equal((await s.journal.get('b1'))!.status, 'redeemed', 'the entry can now be claimed');
  vault.next = 'ok';
  const c = await claimCredited(s.payments, 'b1', new Uint8Array(20).fill(0xbe), VAULT, vault, cp());
  assert.equal(c.amount, stuck.amount);
  assert.equal((await s.journal.get('b1'))!.status, 'settled');
});

test('the vault\'s real answer for an unredeemed nonce, a zero word, is "not redeemed"; a missing answer is the same', async () => {
  const s = await setup();
  const vault = new FakeVault(s);
  assert.deepEqual(await vault.spentNullifier(s.entry.nonce), new Uint8Array(32));
  assert.equal((await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp())).status, 'redeemed');
  assert.equal(vault.sentRedeems.length, 1, 'a zero word did not read as another burn\'s nullifier');
  const t = await setup();
  const v2 = new FakeVault(t);
  v2.spentNullifier = () => Promise.resolve(undefined);
  assert.equal((await redeemBurned(t.plugin, t.payments, 'b1', t.source, chain, v2, rp())).status, 'redeemed');
});

test('a claim attempt without a recorded hash is never repeated automatically; the host abandons it explicitly', async () => {
  const s = await setup();
  const vault = new FakeVault(s);
  await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp());
  const payee = new Uint8Array(20).fill(0xbe);
  const realSend = vault.send.bind(vault);
  vault.send = (): Promise<string> => Promise.reject(new Error('crash between the send and the journalled hash'));
  await assert.rejects(claimCredited(s.payments, 'b1', payee, VAULT, vault, cp()), /crash between/);
  const e = (await s.journal.get('b1'))!;
  assert.equal(e.claimStarted, true);
  assert.equal(e.claimTx, undefined);
  vault.send = realSend;
  await assert.rejects(claimCredited(s.payments, 'b1', payee, VAULT, vault, cp()), /was started and its hash was not recorded/);
  assert.equal(vault.sentClaims.length, 0, 'no second claim was sent');
  await abandonAttempt(s.payments, 'b1', { claim: true });
  assert.equal((await claimCredited(s.payments, 'b1', payee, VAULT, vault, cp())).amount, e.amount);
  assert.equal((await s.journal.get('b1'))!.status, 'settled');
  // a settled burn cannot be abandoned, and a resumed claim says it has no balance before
  await assert.rejects(abandonAttempt(s.payments, 'b1', { claim: true }), /already settled/);
});

test('a redeem transaction the host knows is dead can be abandoned, and the entry then sends again', async () => {
  const s = await setup();
  const vault = new FakeVault(s);
  vault.next = 'pending';
  await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp()).then(() => undefined, () => undefined);
  await assert.rejects(abandonAttempt(s.payments, 'b1', { redeemTx: '0xnope' }), /no redeem transaction/);
  await abandonAttempt(s.payments, 'b1', { redeemTx: '0x1' });
  assert.deepEqual((await s.journal.get('b1'))!.redeemTxs, []);
  vault.next = 'ok';
  assert.equal((await redeemBurned(s.plugin, s.payments, 'b1', s.source, chain, vault, rp())).status, 'redeemed');
  assert.equal(vault.sentRedeems.length, 2);
});

void recipient20; void sha; void burnStep; void txStep; void ({} as World);
