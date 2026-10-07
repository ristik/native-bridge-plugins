import assert from 'node:assert/strict';
import { test } from 'node:test';

import { keccak_256 } from '@noble/hashes/sha3.js';
import type { BridgePayments, MintRequest, WalletBurnResult, WalletPendingBurn } from '@unicitylabs/bridge-core';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { toHex } from '../src/bytes.js';
import { encodeJustification } from '../src/lockproof.js';
import { H, deriveSalt, returnReason } from '../src/profile.js';
import { BridgedTokenIssuancePolicy, NativeBridgeTokenVerifier } from '../src/verifier.js';
import {
  NativeBridgePayments, MemoryRedemptionJournal, VerdictCache, burnForReturn, buildNativeReturnProof, claim, claimCalldata, createNativeBridgePlugin,
  mintBridgedToken, recoverPendingBurns, type NativeWalletBackend,
} from '../src/wallet.js';
import { rejects } from './util.js';
import {
  CHAIN_ID, VAULT, ZERO20, buildToken, burnStep, encodeParts, lockParts, makeWorld, ownerPredicate, recipient20, signer, spec, txStep,
} from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;

class Backend implements NativeWalletBackend {
  public tokens = new Map<string, Uint8Array>();
  public calls: string[] = [];
  public burned: Uint8Array | null = null;
  public pending: WalletPendingBurn[] = [];
  public acked: string[] = [];
  public burnSuccess = true;

  public constructor(private readonly owner: ReturnType<typeof signer>) {}

  public tokenBytes(id: string): Promise<Uint8Array | null> {
    return Promise.resolve(this.tokens.get(id) ?? null);
  }
  public recipientPredicate(): Promise<Uint8Array> {
    return Promise.resolve(ownerPredicate(this.owner).toCBOR());
  }
  public mintCustom(): Promise<{ success: boolean }> {
    this.calls.push('mint');
    return Promise.resolve({ success: true });
  }
  public burn(): Promise<WalletBurnResult> {
    this.calls.push('burn');
    return Promise.resolve({ success: this.burnSuccess, burnId: 'b1', tokenId: 't1', burnedToken: this.burned ?? undefined });
  }
  public tokenJustification(): Promise<Uint8Array | null> {
    return Promise.resolve(null);
  }
  public pendingBurns(): Promise<readonly WalletPendingBurn[]> {
    return Promise.resolve(this.pending);
  }
  public acknowledgeBurn(id: string): Promise<void> {
    this.calls.push('ack');
    this.acked.push(id);
    return Promise.resolve();
  }
}

const rev = { manifestRevision: 'm1', profileRevision: 'p2' };

test('receive and export gate on full-history verification', async () => {
  const w = makeWorld();
  const plugin = createNativeBridgePlugin(w.bridge, rev);
  const be = new Backend(signer(1));
  const pay = new NativeBridgePayments(plugin, be);
  const out = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n)], T0, UC_TS);
  await pay.receive(out.bytes);
  const bad = out.bytes.slice();
  bad[70] ^= 1;
  await assert.rejects(pay.receive(bad));
  be.tokens.set('t1', out.bytes);
  assert.deepEqual(await pay.export('t1'), out.bytes);
  await rejects(pay.export('missing'), 'ErrMissingBacking');
});

test('validation cache is bound to token bytes, trust digest and revisions', async () => {
  const w = makeWorld();
  const a = createNativeBridgePlugin(w.bridge, rev);
  let count = 0;
  const orig = a.verifyNativeToken;
  const counting = { ...a, verifyNativeToken: (b: Uint8Array, e?: 'receipt' | 'return') => { count++; return orig(b, e); } };
  const out = await buildToken(w, spec(1), [], T0, UC_TS);
  const cache = new VerdictCache(counting);
  await cache.verify(out.bytes, 'receipt');
  await cache.verify(out.bytes, 'receipt');
  assert.equal(count, 1, 'second call is a hit');
  const other = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n)], T0, UC_TS);
  await cache.verify(other.bytes, 'receipt');
  assert.equal(count, 2, 'different bytes miss');
  const newRev = new VerdictCache({ ...counting, revision: { manifestRevision: 'm2', profileRevision: 'p2' } });
  await newRev.verify(out.bytes, 'receipt');
  assert.equal(count, 3, 'another manifest revision misses');
  await cache.verify(out.bytes, 'return').then(() => assert.fail('a receipt is not a return'), () => undefined);
  assert.equal(count, 4, 'the expectation is part of the key');
});

test('burn is gated before the wallet acts and the burned blob is rechecked', async () => {
  const w = makeWorld();
  const plugin = createNativeBridgePlugin(w.bridge, rev);
  const be = new Backend(signer(2));
  const pay = new NativeBridgePayments(plugin, be);
  const held = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n)], T0, UC_TS);
  const burned = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
  // A token that does not verify never reaches the wallet burn.
  const broken = held.bytes.slice();
  broken[70] ^= 1;
  be.tokens.set('t1', broken);
  await assert.rejects(pay.burn({ tokenId: 't1', reasonBytes: new Uint8Array() }));
  assert.deepEqual(be.calls, []);
  // A wallet success flag with a blob that does not verify as a return is refused.
  be.tokens.set('t1', held.bytes);
  be.burned = held.bytes;
  await rejects(pay.burn({ tokenId: 't1', reasonBytes: new Uint8Array() }), 'ErrNotBurn');
  be.burned = burned.bytes;
  const r = await pay.burn({ tokenId: 't1', reasonBytes: new Uint8Array() });
  assert.equal(r.success, true);
});

test('burnForReturn journals the verified blob before the burn is acknowledged', async () => {
  const w = makeWorld();
  const plugin = createNativeBridgePlugin(w.bridge, rev);
  const be = new Backend(signer(2));
  const journal = new MemoryRedemptionJournal();
  const pay = new NativeBridgePayments(plugin, be, journal);
  const held = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n)], T0, UC_TS);
  const burned = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
  be.tokens.set('t1', held.bytes);
  be.burned = burned.bytes;
  const order: string[] = [];
  const res = await burnForReturn(plugin, pay, {
    tokenId: 't1',
    reasonBytes: new Uint8Array(),
    persist: async () => void order.push(`persist:${(await journal.get('b1'))?.status}`),
  });
  assert.deepEqual(order, ['persist:burned']);
  assert.deepEqual(be.calls, ['burn', 'ack']);
  assert.deepEqual(res.burnedToken, burned.bytes);
  const e = (await journal.get('b1'))!;
  assert.deepEqual([...e.releaseTo], [...recipient20()]);
  assert.equal(e.status, 'burned');
});

test('burnForReturn does not acknowledge when the journal write fails', async () => {
  const w = makeWorld();
  const plugin = createNativeBridgePlugin(w.bridge, rev);
  const be = new Backend(signer(2));
  const pay = new NativeBridgePayments(plugin, be);
  const held = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n)], T0, UC_TS);
  be.tokens.set('t1', held.bytes);
  be.burned = (await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS)).bytes;
  await assert.rejects(burnForReturn(plugin, pay, { tokenId: 't1', reasonBytes: new Uint8Array(), persist: () => Promise.reject(new Error('disk full')) }));
  assert.deepEqual(be.calls, ['burn'], 'no acknowledgement without a durable handoff');
});

test('recoverPendingBurns re-journals a settled burn after interruption', async () => {
  const w = makeWorld();
  const plugin = createNativeBridgePlugin(w.bridge, rev);
  const be = new Backend(signer(2));
  const journal = new MemoryRedemptionJournal();
  const pay = new NativeBridgePayments(plugin, be, journal);
  const burned = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
  be.pending = [{ burnId: 'b9', tokenId: 't9', reasonBytes: new Uint8Array(), burnedToken: burned.bytes, settled: true }];
  const rec = await recoverPendingBurns(plugin, pay);
  assert.equal(rec.length, 1);
  assert.equal((await journal.get('b9'))?.status, 'burned');
  assert.deepEqual(be.acked, ['b9']);
  // A pending burn whose blob is not a native return is not recovered.
  be.pending = [{ burnId: 'b10', tokenId: 't', reasonBytes: new Uint8Array(), burnedToken: new Uint8Array([1, 2, 3]), settled: true }];
  assert.equal((await recoverPendingBurns(plugin, pay)).length, 0);
});

test('mint pre-check verifies the certified EVM lock before submission', async () => {
  const w = makeWorld();
  const plugin = createNativeBridgePlugin(w.bridge, rev);
  const s = spec(1);
  const be = new Backend(s.owner);
  const pay = new NativeBridgePayments(plugin, be);
  const good = await lockParts(w, s);
  const mk = (parts: typeof good): MintRequest => ({
    coinIdHex: toHex(w.dep.cfg.aid), amount: 1000n,
    mintData: (new Uint8Array(0)), tokenType: w.dep.cfg.ty, salt: deriveSalt(w.dep.cfgHash, s.nonce),
    genesisReason: encodeJustification(CHAIN_ID, VAULT, ZERO20, s.nonce, encodeParts(parts)), mintJustificationVerifiers: [],
  });
  const { valueEnvelope } = await import('../src/profile.js');
  const req = (parts: typeof good): MintRequest => ({ ...mk(parts), mintData: valueEnvelope(w.dep.cfg.aid, s.amount) });
  await mintBridgedToken(pay, req(good));
  assert.deepEqual(be.calls, ['mint']);
  const bad = await lockParts(w, { ...s, evm: { ...s.evm, stored: new Uint8Array(32).fill(3) } });
  await rejects(mintBridgedToken(pay, req(bad)), 'ErrLockDigest');
  assert.deepEqual(be.calls, ['mint'], 'the wallet is never reached with an unproven lock');
  const wrongSalt = { ...req(good), salt: new Uint8Array(32).fill(1) };
  await rejects(mintBridgedToken(pay, wrongSalt), 'ErrMintSalt');
});

test('return proof assembly with an optional untrusted transport', async () => {
  const w = makeWorld();
  const plugin = createNativeBridgePlugin(w.bridge, rev);
  const burned = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
  const { encoded, nullifier } = await buildNativeReturnProof(plugin, burned.bytes);
  assert.ok(encoded.length > 0 && nullifier.length === 32);
  let called = 0;
  await buildNativeReturnProof(plugin, burned.bytes, (t) => {
    called++;
    return Promise.resolve([t.genesis, ...t.transactions].map((c) => c.inclusionProof));
  });
  assert.equal(called, 1);
});

test('SDK seam: NativeBridgeTokenVerifier composes SDK and strict verification', async () => {
  const w = makeWorld();
  const out = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n)], T0, UC_TS);
  const ctx = w.bridge.context();
  const v = new NativeBridgeTokenVerifier(w.bridge);
  assert.equal((await v.verify(out.token, ctx)).status, VerificationStatus.OK);
  // A caller context with another base is outside the fixed profile.
  const other = makeWorld();
  const otherCtx = { ...ctx, trustBase: (await import('./world.js')).makeRoot(3, 4, 20).trust.base } as typeof ctx;
  void other;
  assert.equal((await v.verify(out.token, otherCtx)).status, VerificationStatus.FAIL);
  assert.equal(v.lastError, 'ErrTrustBase');
  // A bad lock fails with the exact native reason.
  const bad = await buildToken(w, { ...spec(1), evm: { ...spec(1).evm, stored: new Uint8Array(32).fill(5) } }, [], T0, UC_TS);
  assert.equal((await v.verify(bad.token, ctx)).status, VerificationStatus.FAIL);
  assert.equal(v.lastError, 'ErrLockDigest');
});

test('SDK context registers the justification verifier and one issuance policy per type', async () => {
  const w = makeWorld();
  const out = await buildToken(w, spec(1), [], T0, UC_TS);
  // Through the SDK's own token verification with only this bridge's registrations.
  const r = await out.token.verify(w.bridge.context());
  assert.equal(r.status, VerificationStatus.OK);
  const policy = new BridgedTokenIssuancePolicy(w.bridge, w.dep.cfg.ty);
  assert.deepEqual(policy.coinIds, [toHex(w.dep.cfg.aid)]);
  assert.equal((await policy.verify(out.token.genesis)).status, VerificationStatus.OK);
  const bare = await buildToken(w, spec(1), [], T0, UC_TS, { mintData: new Uint8Array([1]) });
  assert.equal((await policy.verify(bare.token.genesis)).status, VerificationStatus.FAIL);
  assert.equal(policy.lastError, 'ErrIssuanceData');
  const noReason = await buildToken(w, spec(1), [], T0, UC_TS, { mintJustification: null });
  await policy.verify(noReason.token.genesis);
  assert.equal(policy.lastError, 'ErrIssuanceReason');
  const split = await buildToken(w, spec(1), [], T0, UC_TS, { mintJustification: Uint8Array.of(0xd9, 0x98, 0xa7, 0x80) });
  await policy.verify(split.token.genesis);
  assert.equal(policy.lastError, 'ErrIssuanceReason');
});

test('claim calldata is the guarded pull payment selector and arguments', async () => {
  const data = claimCalldata(1000n, recipient20());
  assert.deepEqual(data.slice(0, 4), keccak_256(new TextEncoder().encode('claim(uint256,address)')).slice(0, 4));
  assert.equal(data.length, 4 + 64);
  assert.equal(data[4 + 30], 3);
  assert.deepEqual(data.slice(4 + 44), recipient20());
  let sent: { to: Uint8Array; data: Uint8Array } | null = null;
  await claim((tx) => { sent = tx; return Promise.resolve('0xhash'); }, VAULT, 1000n, recipient20());
  assert.deepEqual(sent!.to, VAULT);
  assert.throws(() => claimCalldata(0n, recipient20()));
  assert.throws(() => claimCalldata(1n, new Uint8Array(19)));
  void H; void returnReason; void ({} as BridgePayments);
});
