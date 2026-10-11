import assert from 'node:assert/strict';
import { test } from 'node:test';

import { InclusionCertificate } from '@unicitylabs/state-transition-sdk/lib/api/InclusionCertificate.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { DataHasherFactory } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasherFactory.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { NodeDataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/NodeDataHasher.js';
import { SparseMerkleTree } from '@unicitylabs/state-transition-sdk/lib/smt/radix/SparseMerkleTree.js';

import { NativeError } from '../src/errors.js';
import { anchorRounds, buildFreshReturnProof, classifyFreshness, redeemReturn, RedemptionUnconfirmed, type ChainReader, type RedeemPolicy, type RedeemTransport } from '../src/freshness.js';
import { createNativeBridgePlugin } from '../src/wallet.js';
import { rejects } from './util.js';
import { AGG_PARTITION, buildToken, burnStep, makeUc, makeWorld, sha, spec, txStep, type World } from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;
// the vault's stored nullifier for the token last built (the vault keys spent state by nonce and stores the nullifier)
let currentNullifier: Uint8Array = new Uint8Array(32);
const ret = async (w: World) => {
  const out = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
  currentNullifier = (await w.bridge.verifyNativeToken(out.token, 'return')).outcome.nullifier;
  return out;
};
// the held token's anchors are in root round 900; a refetch answers in `round`
async function proofsAt(w: World, out: Awaited<ReturnType<typeof ret>>, round: bigint, extra = 0): Promise<InclusionProof[]> {
  const old = [out.token.genesis, ...out.token.transactions].map((c) => c.inclusionProof);
  const smt = new SparseMerkleTree(new DataHasherFactory(HashAlgorithm.SHA256, NodeDataHasher));
  for (const [k, v] of out.leaves) await smt.addLeaf(k, v);
  for (let i = 0; i < extra; i++) await smt.addLeaf(sha(Uint8Array.of(i, 9)), sha(Uint8Array.of(i, 10)));
  const root = await smt.calculateRoot();
  const uc = await makeUc(w.agg, { partition: AGG_PARTITION, conf: w.aggConf, epochIr: 1n, rootEpoch: 2n, round, timestamp: UC_TS, stateHash: root.hash.data, blockHash: null, signers: 4 });
  return old.map((o, i) => new InclusionProof(o.certificationData, o.referenceTime, InclusionCertificate.create(root, out.leaves[i][0]), uc));
}
const noWait = { sleep: () => Promise.resolve() };
const chainAt = (origins: bigint[], wCert = 15n): ChainReader & { reads: number } => {
  const c = { reads: 0, origin: () => Promise.resolve(origins[Math.min(c.reads++, origins.length - 1)]), wCert: () => Promise.resolve(wCert) };
  return c;
};
const fast = { margin: 6n, maxAttempts: 3, maxOriginWaitMs: 1_000, pollMs: 1, ...noWait };

test('window classification: exact boundaries of max(r) <= O and O - min(r) <= W_cert - M', () => {
  const W = 15n;
  const M = 6n;
  assert.equal(classifyFreshness([100n], 100n, W, M), 'ok', 'r = O');
  assert.equal(classifyFreshness([100n], 109n, W, M), 'ok', 'age = W - M');
  assert.equal(classifyFreshness([100n], 110n, W, M), 'stale', 'age = W - M + 1');
  assert.equal(classifyFreshness([100n], 99n, W, M), 'future', 'r = O + 1');
  assert.equal(classifyFreshness([100n, 109n], 109n, W, M), 'ok', 'spread = W - M');
  assert.equal(classifyFreshness([100n, 110n], 110n, W, M), 'spread', 'spread = W - M + 1: no origin admits it');
  assert.equal(classifyFreshness([100n, 110n], 105n, W, M), 'spread', 'spread wins over future');
  assert.equal(classifyFreshness([100n, 105n], 104n, W, M), 'future');
  assert.equal(classifyFreshness([100n], 115n, W, 0n), 'ok', 'no margin: the raw window, inclusive');
  assert.equal(classifyFreshness([100n], 116n, W, 0n), 'stale');
  assert.throws(() => classifyFreshness([], 1n, W, M), TypeError);
  assert.throws(() => classifyFreshness([1n], 1n, W, W), RangeError);
});

test('an already-old token: every leaf is refetched and the fresh bundle passes the window', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  assert.deepEqual(anchorRounds(out.token), [900n]);
  let fetches = 0;
  const source = async (): Promise<InclusionProof[]> => (++fetches, proofsAt(w, out, 950n));
  const r = await buildFreshReturnProof(plugin, out.bytes, source, chainAt([952n]), fast);
  assert.equal(fetches, 1, 'the held proofs are never trusted for freshness: one fetch for every leaf');
  assert.deepEqual(r.rounds, [950n]);
  assert.equal(r.attempts, 1);
  assert.equal(r.nullifier.length, 32);
});

test('a stale answer is refetched for the same token, bounded, then unavailable with its cause', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  let fetches = 0;
  // the origin is far ahead of every answer the source gives: stale each time
  const stale = async (): Promise<InclusionProof[]> => (++fetches, proofsAt(w, out, 900n));
  const err = await buildFreshReturnProof(plugin, out.bytes, stale, chainAt([1000n]), fast).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof NativeError);
  assert.equal(err.reason, 'ErrProofUnavailable');
  assert.equal(err.family, 'unavailable');
  assert.match(err.detail ?? '', /^stale \(rounds 900, origin 1000, W_cert 15, margin 6\)/);
  assert.equal(fetches, fast.maxAttempts);
  // the second fetch is fresh: success on attempt 2
  fetches = 0;
  const catchUp = async (): Promise<InclusionProof[]> => proofsAt(w, out, ++fetches === 1 ? 900n : 995n);
  const r = await buildFreshReturnProof(plugin, out.bytes, catchUp, chainAt([1000n]), fast);
  assert.equal(r.attempts, 2);
});

test('a future anchor waits for the origin (bounded), rechecking the oldest after the wait', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const source = (): Promise<InclusionProof[]> => proofsAt(w, out, 950n);
  const lagging = chainAt([940n, 945n, 949n, 950n]);
  const r = await buildFreshReturnProof(plugin, out.bytes, source, lagging, fast);
  assert.equal(r.origin, 950n);
  assert.equal(lagging.reads, 4, 'polled until the origin imported the anchor');
  // never imported within the bound: unavailable, and no refetch can make the anchor older
  let now = 0;
  const clock = { now: () => (now += 400), sleep: () => Promise.resolve() };
  let fetches = 0;
  const counted = async (): Promise<InclusionProof[]> => (++fetches, source());
  const err = await buildFreshReturnProof(plugin, out.bytes, counted, chainAt([940n]), { ...fast, ...clock }).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof NativeError && err.reason === 'ErrProofUnavailable' && /^future /.test(err.detail ?? ''));
  assert.equal(fetches, 1);
  // the wait ends with the oldest anchor too old for the new origin: judged again, refetched, accepted
  let n = 0;
  const later = async (): Promise<InclusionProof[]> => proofsAt(w, out, ++n === 1 ? 950n : 958n);
  const r2 = await buildFreshReturnProof(plugin, out.bytes, later, chainAt([949n, 960n]), fast);
  assert.equal(r2.attempts, 2);
  assert.deepEqual(r2.rounds, [958n]);
});

test('a bound overflow is a budget refusal, never freshness, never retried', async () => {
  const w = makeWorld();
  const three = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), txStep(3, 8, T0 + 12n), txStep(4, 9, T0 + 14n), burnStep(T0 + 20n)], T0, UC_TS, { ucRound: (i) => 900n + BigInt(i) });
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  let fetches = 0;
  const source = async (): Promise<InclusionProof[]> => (++fetches, [three.token.genesis, ...three.token.transactions].map((c) => c.inclusionProof));
  await rejects(buildFreshReturnProof(plugin, three.bytes, source, chainAt([910n]), fast), 'ErrTooManyPaths');
  assert.equal(fetches, 1);
  // the refusal says how far over the ceiling the fetched bundle was
  const err = await buildFreshReturnProof(plugin, three.bytes, source, chainAt([910n]), fast).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof NativeError && err.family === 'budget' && err.detail === `${anchorRounds(three.token).length} distinct anchors fetched, ceiling 4; not retried`, String((err as NativeError).detail));
});

test('a bug or a bad policy in the pure classification is not reported as an unavailable origin and is not retried', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  let reads = 0;
  // the policy passes the up-front check (two reads of the margin) and is invalid by the time the bundle is classified
  const policy = { ...fast, get margin(): bigint { return ++reads <= 2 ? 6n : 99n; } };
  let fetches = 0;
  const err = await buildFreshReturnProof(plugin, out.bytes, async () => (++fetches, proofsAt(w, out, 950n)), chainAt([952n]), policy).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof RangeError, String(err));
  assert.equal(fetches, 1);
});

class Vault implements RedeemTransport {
  public sent: Uint8Array[] = [];
  public spent = false;
  public script: ('success' | 'reverted' | 'pending' | 'throw-then-success' | 'throw-spent')[];
  public constructor(script: Vault['script']) { this.script = script; }
  public send(data: Uint8Array): Promise<string> {
    this.sent.push(data);
    const step = this.script[this.sent.length - 1];
    if (step === 'throw-spent') { this.spent = true; return Promise.reject(new Error('timeout')); }
    if (step === 'throw-then-success') return Promise.reject(new Error('timeout'));
    if (step === 'success') this.spent = true;
    return Promise.resolve(`0x${this.sent.length}`);
  }
  public receipt(hash: string): Promise<'success' | 'reverted' | undefined> {
    const step = this.script[Number(hash.slice(2)) - 1];
    return Promise.resolve(step === 'success' ? 'success' : step === 'reverted' ? 'reverted' : undefined);
  }
  /** The nullifier the vault stored for the nonce (the token's own unless a test says another burn took it). */
  public stored: Uint8Array | undefined;
  public spentNullifier(): Promise<Uint8Array | undefined> { return Promise.resolve(this.spent ? (this.stored ?? currentNullifier) : undefined); }
}
const rp = (over: Partial<RedeemPolicy> = {}): RedeemPolicy => ({ ...fast, maxSends: 3, receiptTimeoutMs: 10, now: (() => { let n = 0; return () => (n += 4); })(), ...over });

test('redeem: a redemption the vault already credited is reported as such before any proof is fetched, whatever the proof service or the window say', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const done = new Vault([]);
  done.spent = true;
  let fetches = 0;
  const down = async (): Promise<InclusionProof[]> => { fetches++; throw new Error('proof service down'); };
  const deadChain: ChainReader = { wCert: () => Promise.resolve(15n), origin: () => Promise.reject(new Error('rpc down')) };
  const r = await redeemReturn(plugin, out.bytes, down, deadChain, done, rp());
  assert.equal(r.status, 'already-redeemed');
  assert.equal(fetches, 0);
  assert.equal(done.sent.length, 0);
  // a lock nonce the vault credited to a DIFFERENT burn is not this token's redemption
  const other = new Vault([]);
  other.spent = true;
  other.stored = new Uint8Array(32).fill(7);
  await rejects(redeemReturn(plugin, out.bytes, down, deadChain, other, rp()), 'ErrUnexpectedBurn');
  assert.equal(fetches, 0);
});

test('redeem: a revert refetches the same token and resends; a settled redemption is never sent again', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  let fetches = 0;
  const source = async (): Promise<InclusionProof[]> => (++fetches, proofsAt(w, out, 950n));
  const v = new Vault(['reverted', 'success']);
  const r = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), v, rp());
  assert.equal(r.status, 'redeemed');
  assert.equal(r.sends, 2);
  assert.equal(fetches, 2, 'each send is built from a fresh fetch of every leaf');
  // already spent on the vault: nothing is sent
  const done = new Vault([]);
  done.spent = true;
  const r2 = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), done, rp());
  assert.equal(r2.status, 'already-redeemed');
  assert.equal(done.sent.length, 0);
});

test('redeem: an RPC timeout is not a revert (the vault state decides), and an unknown send is not repeated', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const source = (): Promise<InclusionProof[]> => proofsAt(w, out, 950n);
  const accepted = new Vault(['throw-spent']);
  const r = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), accepted, rp());
  assert.equal(r.status, 'redeemed');
  assert.equal(accepted.sent.length, 1, 'the timed-out send had been accepted: not resent');
  const lost = new Vault(['throw-then-success']);
  const err = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), lost, rp()).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof NativeError && err.reason === 'ErrProofUnavailable' && /unconfirmed/.test(err.detail ?? ''));
  assert.equal(lost.sent.length, 1, 'an unknown outcome is never repeated while it may be pending');
  const pending = new Vault(['pending']);
  const err2 = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), pending, rp()).then(() => undefined, (e: unknown) => e);
  assert.ok(err2 instanceof NativeError && /unconfirmed/.test(err2.detail ?? ''));
  assert.equal(pending.sent.length, 1);
  const always = new Vault(['reverted', 'reverted', 'reverted']);
  const err3 = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), always, rp()).then(() => undefined, (e: unknown) => e);
  assert.ok(err3 instanceof NativeError && err3.reason === 'ErrProofUnavailable' && /reverted 3 times/.test(err3.detail ?? ''));
  assert.equal(always.sent.length, 3);
});

test('several certificates in different rounds: the OLDEST anchor decides, over every leaf', async () => {
  const W = 15n;
  const M = 6n;
  assert.equal(classifyFreshness([100n, 105n], 112n, W, M), 'stale', 'age of the oldest is 12 > 9 (the newest alone would pass)');
  assert.equal(classifyFreshness([105n, 100n], 112n, W, M), 'stale', 'the order of the anchors does not matter');
  assert.equal(classifyFreshness([100n, 105n], 109n, W, M), 'ok');
  assert.equal(classifyFreshness([100n, 105n], 104n, W, M), 'future', 'the newest decides future');
  const w = makeWorld();
  // the genesis leaf is certified in the NEWER round: reading only the genesis, or judging on the newest, would accept
  const two = await buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS, { ucRound: (i) => (i === 0 ? 905n : 900n) });
  assert.deepEqual(anchorRounds(two.token), [905n, 900n]);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const held = (): Promise<InclusionProof[]> => Promise.resolve([two.token.genesis, ...two.token.transactions].map((c) => c.inclusionProof));
  const err = await buildFreshReturnProof(plugin, two.bytes, held, chainAt([912n]), fast).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof NativeError && err.reason === 'ErrProofUnavailable' && /^stale \(rounds 905,900, origin 912/.test(err.detail ?? ''), String((err as NativeError)?.detail));
  const ok = await buildFreshReturnProof(plugin, two.bytes, held, chainAt([909n]), fast);
  assert.deepEqual(ok.rounds, [905n, 900n]);
  assert.equal(ok.origin, 909n);
});

test('a (path, UC) pair that raced a certificate is refetched, bounded, then unavailable with its cause', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const racing = async (): Promise<InclusionProof[]> => {
    const ok = await proofsAt(w, out, 950n);
    const alien = (await proofsAt(w, out, 950n, 3))[0].unicityCertificate; // another tree's certificate
    return ok.map((p) => new InclusionProof(p.certificationData, p.referenceTime, p.inclusionCertificate, alien));
  };
  let calls = 0;
  const flaky = async (): Promise<InclusionProof[]> => (++calls < 2 ? racing() : proofsAt(w, out, 950n));
  const r = await buildFreshReturnProof(plugin, out.bytes, flaky, chainAt([952n]), fast);
  assert.equal(r.attempts, 2);
  calls = 0;
  const never = async (): Promise<InclusionProof[]> => (++calls, racing());
  const err = await buildFreshReturnProof(plugin, out.bytes, never, chainAt([952n]), fast).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof NativeError && err.reason === 'ErrProofUnavailable' && /^pair-race/.test(err.detail ?? ''));
  assert.equal(calls, fast.maxAttempts);
});

test('temporary witness or origin unavailability is retried within the bound, then unavailable with its cause', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  let calls = 0;
  const down = async (): Promise<InclusionProof[]> => (++calls < 3 ? Promise.reject(new Error('ECONNRESET')) : proofsAt(w, out, 950n));
  const r = await buildFreshReturnProof(plugin, out.bytes, down, chainAt([952n]), fast);
  assert.equal(r.attempts, 3);
  calls = 0;
  const dead = async (): Promise<InclusionProof[]> => (++calls, Promise.reject(new Error('ECONNRESET')));
  const err = await buildFreshReturnProof(plugin, out.bytes, dead, chainAt([952n]), fast).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof NativeError && err.reason === 'ErrProofUnavailable' && err.family === 'unavailable' && /^witness unavailable \(ECONNRESET\)/.test(err.detail ?? ''));
  assert.equal(calls, fast.maxAttempts);
  // the chain reader failing is the same family
  let reads = 0;
  const flakyChain: ChainReader = { wCert: () => Promise.resolve(15n), origin: () => (++reads < 2 ? Promise.reject(new Error('rpc down')) : Promise.resolve(952n)) };
  assert.equal((await buildFreshReturnProof(plugin, out.bytes, () => proofsAt(w, out, 950n), flakyChain, fast)).attempts, 2);
  const deadChain: ChainReader = { wCert: () => Promise.resolve(15n), origin: () => Promise.reject(new Error('rpc down')) };
  const err2 = await buildFreshReturnProof(plugin, out.bytes, () => proofsAt(w, out, 950n), deadChain, fast).then(() => undefined, (e: unknown) => e);
  assert.ok(err2 instanceof NativeError && /^origin unavailable \(rpc down\)/.test(err2.detail ?? ''));
});

test('policy is checked before anything is fetched or sent', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  let fetched = 0;
  const source = (): Promise<InclusionProof[]> => (++fetched, proofsAt(w, out, 950n));
  await assert.rejects(buildFreshReturnProof(plugin, out.bytes, source, chainAt([952n]), { ...fast, margin: 15n }), RangeError);
  await assert.rejects(buildFreshReturnProof(plugin, out.bytes, source, chainAt([952n]), { ...fast, maxAttempts: 0 }), RangeError);
  const v = new Vault(['success']);
  await assert.rejects(redeemReturn(plugin, out.bytes, source, chainAt([952n]), v, rp({ maxSends: 0 })), RangeError);
  await assert.rejects(redeemReturn(plugin, out.bytes, source, chainAt([952n]), v, rp({ margin: 20n })), RangeError);
  assert.equal(fetched, 0);
  assert.equal(v.sent.length, 0);
});

test('redeem: a revert that follows a redemption by someone else ends the call without another fetch or send', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  let fetches = 0;
  const source = async (): Promise<InclusionProof[]> => (++fetches, proofsAt(w, out, 950n));
  const v = new Vault(['reverted']);
  const send = v.send.bind(v);
  v.send = (data) => { v.spent = true; return send(data); }; // our transaction reverts because another one landed first
  const r = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), v, rp({ maxSends: 1 }));
  assert.equal(r.status, 'already-redeemed');
  assert.equal(fetches, 1);
  assert.equal(v.sent.length, 1);
});

test('redeem: an unconfirmed send exposes its hash, and a pending hash is checked before any new send', async () => {
  const w = makeWorld();
  const out = await ret(w);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const source = (): Promise<InclusionProof[]> => proofsAt(w, out, 950n);
  const stuck = new Vault(['pending']);
  const err = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), stuck, rp()).then(() => undefined, (e: unknown) => e);
  assert.ok(err instanceof RedemptionUnconfirmed && err.reason === 'ErrProofUnavailable' && err.family === 'unavailable');
  assert.equal(err.txHash, '0x1');
  // still pending: nothing new is sent
  const again = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), stuck, rp(), [err.txHash!]).then(() => undefined, (e: unknown) => e);
  assert.ok(again instanceof RedemptionUnconfirmed && again.txHash === '0x1');
  assert.equal(stuck.sent.length, 1, 'no second transaction while the first may be pending');
  // it was mined successfully meanwhile: the call ends with that hash and sends nothing
  const mined = new Vault(['success']);
  mined.sent.push(new Uint8Array(0)); // the hash 0x1 is the earlier send
  mined.spent = true;
  const done = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), mined, rp(), ['0x1']);
  assert.equal(done.status, 'redeemed');
  assert.equal(done.status === 'redeemed' ? done.txHash : undefined, '0x1');
  assert.equal(mined.sent.length, 1);
  // it reverted: the pending hash is dropped and a fresh send follows
  const reverted = new Vault(['reverted', 'success']);
  reverted.sent.push(new Uint8Array(0));
  const resent = await redeemReturn(plugin, out.bytes, source, chainAt([952n]), reverted, rp(), ['0x1']);
  assert.equal(resent.status, 'redeemed');
  assert.equal(reverted.sent.length, 2);
});
