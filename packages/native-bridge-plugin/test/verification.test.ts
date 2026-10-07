import assert from 'node:assert/strict';
import { test } from 'node:test';

import { secp256k1 } from '@noble/curves/secp256k1.js';

import { decodeHistory, projectToken, prepareLock, verifyHistory } from '../src/history.js';
import { burnId, nullifier, returnReason, valueEnvelope } from '../src/profile.js';
import { rejects } from './util.js';
import {
  CHAIN_ID, VAULT, ZERO20, buildToken, burnStep, digestOf, encodeParts, lockParts, makeWorld, ownerPredicate, recipient20, signer,
  spec, text, txStep, type Tweaks, type World,
} from './world.js';
import { C } from './cbor.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;
const w0 = makeWorld();

const rec = (w: World, tw: Tweaks, s = spec(1), steps = [] as ReturnType<typeof txStep>[], expect: 'receipt' | 'return' = 'receipt') =>
  buildToken(w, s, steps, T0, UC_TS, tw).then((o) => w.bridge.verifyNativeToken(o.token, expect));

// ---- positive ----------------------------------------------------------------------------------

test('receipt with transfers exports leaves in order', async () => {
  const s = spec(1);
  const out = await buildToken(w0, s, [txStep(2, 7, T0 + 10n), txStep(3, 8, T0 + 20n)], T0, UC_TS);
  const v = await w0.bridge.verifyNativeToken(out.token, 'receipt');
  assert.equal(v.outcome.leaves.length, 3);
  assert.equal(v.outcome.leaves[1].referenceTime, T0 + 10n);
  v.outcome.leaves.forEach((l, i) => {
    assert.deepEqual(l.sid, out.leaves[i][0]);
    assert.deepEqual(l.value, out.leaves[i][1]);
  });
});

test('return with terminal burn commits the release and the nullifier', async () => {
  const out = await buildToken(w0, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);
  const v = await w0.bridge.verifyNativeToken(out.token, 'return');
  assert.deepEqual([...v.outcome.releaseTo], [...recipient20()]);
  const leaf = v.outcome.leaves[2];
  assert.deepEqual(v.outcome.nullifier, nullifier(v.outcome.cfg, burnId(leaf.sid, leaf.txHash)));
});

test('prague header with requestsHash verifies', async () => {
  const w = makeWorld(21);
  await w.bridge.verifyNativeToken((await buildToken(w, spec(1), [], T0, UC_TS)).token, 'receipt');
});

test('explicit deadlines bound the leaf time strictly', async () => {
  const s = spec(1);
  s.mintDeadline = T0 + 1n;
  await w0.bridge.verifyNativeToken((await buildToken(w0, s, [txStep(2, 7, T0 + 10n, T0 + 11n)], T0, UC_TS)).token, 'receipt');
});

// ---- deadlines and reference times -------------------------------------------------------------

test('deadline equal to or below the leaf time is expired; one above is fine', async () => {
  for (const e of [T0, T0 - 1n]) {
    const s = spec(1);
    s.mintDeadline = e;
    await rejects(w0.bridge.verifyNativeToken((await buildToken(w0, s, [], T0, UC_TS)).token, 'receipt'), 'ErrDeadlineExpired');
  }
  const s = spec(1);
  s.mintDeadline = T0 + 1n;
  await w0.bridge.verifyNativeToken((await buildToken(w0, s, [], T0, UC_TS)).token, 'receipt');
});

test('transfer deadline equal to the leaf time is expired', async () => {
  await rejects(rec(w0, {}, spec(1), [txStep(2, 7, T0 + 10n, T0 + 10n)]), 'ErrDeadlineExpired');
});

test('an old transaction never expires because the anchor is later', async () => {
  const s = spec(1);
  s.mintDeadline = T0 + 1n;
  await w0.bridge.verifyNativeToken((await buildToken(w0, s, [], T0, UC_TS + 10_000_000n)).token, 'receipt');
});

test('certification data deadline must equal the transaction deadline, including null', async () => {
  await rejects(rec(w0, { cdDeadline: [[0, T0 + 5n]] }), 'ErrCDMismatch', 'tx null, cd explicit');
  const s = spec(1);
  s.mintDeadline = T0 + 5n;
  await rejects(rec(w0, { cdDeadline: [[0, null]] }, s), 'ErrCDMismatch', 'tx explicit, cd null');
  await rejects(rec(w0, { cdDeadline: [[1, T0 + 99n]] }, spec(1), [txStep(2, 7, T0 + 10n)]), 'ErrCDMismatch', 'transfer');
});

test('leaf time after the anchor is rejected, equal is accepted', async () => {
  await rejects(w0.bridge.verifyNativeToken((await buildToken(w0, spec(1), [], UC_TS + 1n, UC_TS)).token, 'receipt'), 'ErrReferenceTimeFuture');
  await w0.bridge.verifyNativeToken((await buildToken(w0, spec(1), [], UC_TS, UC_TS)).token, 'receipt');
});

test('mutating only the proofs reference time breaks the path', async () => {
  await rejects(rec(w0, { proofTime: [[0, T0 + 1n]] }), 'ErrPathInvalid');
});

// ---- mint binding ------------------------------------------------------------------------------

test('mint binding rejections each name their guard', async () => {
  await rejects(rec(w0, { mintNetwork: 4 }), 'ErrUnknownDeployment');
  await rejects(rec(w0, { mintTy: new Uint8Array(32).fill(9) }), 'ErrMintType');
  await rejects(rec(w0, { mintSalt: new Uint8Array(32).fill(5) }), 'ErrMintSalt');
  await rejects(rec(w0, { mintData: null }), 'ErrMintData');
  await rejects(rec(w0, { mintJustification: null }), 'ErrMintJustif');
  await rejects(rec(w0, { mintData: valueEnvelope(w0.dep.cfg.aid, Uint8Array.of(3, 233)) }), 'ErrLockDigest');
});

test('value envelope variants are each rejected', async () => {
  const aid = w0.dep.cfg.aid;
  const entry = (id: Uint8Array, amt: Uint8Array): Uint8Array => C.encodeArray(C.encodeByteString(id), C.encodeByteString(amt));
  const env = (assets: Uint8Array[], memo: Uint8Array, v: number): Uint8Array => C.encodeTag(39050, C.encodeArray(C.encodeUnsignedInteger(v), C.encodeArray(...assets), memo));
  const nul = C.encodeNull();
  const foreign = new Uint8Array(32).fill(7);
  const cases: [string, Uint8Array][] = [
    ['bare dialect', C.encodeArray(C.encodeByteString(aid), C.encodeByteString(Uint8Array.of(3, 232)))],
    ['two assets', env([entry(aid, Uint8Array.of(3, 232)), entry(foreign, Uint8Array.of(1))], nul, 1)],
    ['no asset', env([], nul, 1)],
    ['foreign coin', env([entry(foreign, Uint8Array.of(3, 232))], nul, 1)],
    ['memo', env([entry(aid, Uint8Array.of(3, 232))], C.encodeByteString(text('m')), 1)],
    ['version', env([entry(aid, Uint8Array.of(3, 232))], nul, 2)],
    ['leading zero', env([entry(aid, Uint8Array.of(0, 3, 232))], nul, 1)],
    ['zero amount', env([entry(aid, new Uint8Array())], nul, 1)],
    ['33-byte amount', env([entry(aid, new Uint8Array(33).fill(1))], nul, 1)],
  ];
  for (const [name, bad] of cases) await rejects(rec(w0, { mintData: bad }), 'ErrMintData', name);
});

test('old and foreign justifications are rejected', async () => {
  const v1 = C.encodeTag(39049, C.encodeArray(C.encodeUnsignedInteger(1), C.encodeUnsignedInteger(CHAIN_ID), C.encodeByteString(VAULT), C.encodeByteString(ZERO20), C.encodeUnsignedInteger(1)));
  await rejects(rec(w0, { mintJustification: v1 }), 'ErrMintJustif', 'v1 pointer reason');
  const other = C.encodeTag(1330002, C.encodeArray(C.encodeUnsignedInteger(1)));
  await rejects(rec(w0, { mintJustification: other }), 'ErrMintJustif', 'foreign tag');
  const nullProof = C.encodeTag(39049, C.encodeArray(C.encodeUnsignedInteger(2), C.encodeUnsignedInteger(CHAIN_ID), C.encodeByteString(VAULT), C.encodeByteString(ZERO20), C.encodeUnsignedInteger(1), C.encodeNull()));
  await rejects(rec(w0, { mintJustification: nullProof }), 'ErrMintJustif', 'no embedded proof');
});

test('justification fields name the allow-listed deployment', async () => {
  const s = spec(1);
  const parts = await lockParts(w0, s);
  const { encodeJustification } = await import('../src/lockproof.js');
  const mk = (chain: bigint, vault: Uint8Array, zero: Uint8Array, n: bigint): Uint8Array => encodeJustification(chain, vault, zero, n, encodeParts(parts));
  await rejects(rec(w0, { mintJustification: mk(CHAIN_ID, new Uint8Array(20).fill(0xee), ZERO20, 1n) }), 'ErrUnknownDeployment');
  await rejects(rec(w0, { mintJustification: mk(CHAIN_ID, VAULT, new Uint8Array(20).fill(1), 1n) }), 'ErrMintJustif');
  await rejects(rec(w0, { mintJustification: mk(CHAIN_ID, VAULT, ZERO20, 0n) }), 'ErrMintJustif');
});

// ---- strict unlock -----------------------------------------------------------------------------

const unlockErr = (idx: number, f: (u: Uint8Array) => Uint8Array, reason: Parameters<typeof rejects>[1]): Promise<void> =>
  rejects(rec(w0, { unlock: [[idx, f]] }, spec(1), [txStep(2, 7, T0 + 10n)]), reason);

const N = secp256k1.Point.Fn.ORDER;
const toBig = (b: Uint8Array): bigint => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
const fromBig = (v: bigint): Uint8Array => Uint8Array.from({ length: 32 }, (_, i) => Number((v >> BigInt(8 * (31 - i))) & 0xffn));

test('strict unlock: length, scalars, recovery id and parity', async () => {
  await unlockErr(1, (u) => u.slice(0, 64), 'ErrUnlockLength');
  await unlockErr(1, (u) => Uint8Array.of(...u, 0), 'ErrUnlockLength');
  await unlockErr(1, (u) => Uint8Array.of(...new Uint8Array(32), ...u.slice(32)), 'ErrUnlockScalars');
  await unlockErr(1, (u) => Uint8Array.of(...u.slice(0, 32), ...fromBig(N - toBig(u.slice(32, 64))), u[64] ^ 1), 'ErrUnlockScalars');
  await unlockErr(1, (u) => Uint8Array.of(...u.slice(0, 64), 4), 'ErrUnlockRecovery');
  await unlockErr(1, (u) => Uint8Array.of(...u.slice(0, 64), u[64] ^ 1), 'ErrUnlockKey');
  await unlockErr(1, (u) => Uint8Array.of(...u.slice(0, 64), 2), 'ErrUnlockKey');
  await unlockErr(1, (u) => Uint8Array.of(...u.slice(0, 64), 3), 'ErrUnlockKey');
  await unlockErr(0, (u) => Uint8Array.of(...u.slice(0, 64), u[64] ^ 1), 'ErrUnlockKey');
});

test('a mint signed by a non-minter key is rejected', async () => {
  await rejects(rec(w0, { minterOverride: signer(77) }), 'ErrUnlockKey');
});

// ---- transfers and burns -----------------------------------------------------------------------

test('intermediate transfer data, early burn, wrong terminal shapes', async () => {
  await rejects(rec(w0, { transferData: [[1, Uint8Array.of(1, 2, 3)]] }, spec(1), [txStep(2, 7, T0 + 10n), txStep(3, 8, T0 + 20n)]), 'ErrTransferData');
  await rejects(rec(w0, {}, spec(1), [burnStep(T0 + 10n), txStep(3, 8, T0 + 20n)], 'return'), 'ErrBurnNotFinal');
  await rejects(rec(w0, {}, spec(1), [burnStep(T0 + 10n)], 'receipt'), 'ErrUnexpectedBurn');
  await rejects(rec(w0, {}, spec(1), [], 'return'), 'ErrNoTransfers');
  await rejects(rec(w0, {}, spec(1), [txStep(2, 7, T0 + 10n)], 'return'), 'ErrNotBurn');
});

const burnWith = (f: (w: World, amount: Uint8Array) => Uint8Array): Promise<unknown> =>
  buildToken(w0, spec(1), [{ kind: 'burnWith', reason: f(w0, spec(1).amount), t: T0 + 10n }], T0, UC_TS).then((o) => w0.bridge.verifyNativeToken(o.token, 'return'));

test('burn reason rules', async () => {
  const R = (w: World, recip: Uint8Array, amt: Uint8Array, vault = VAULT, chain = CHAIN_ID): Uint8Array =>
    returnReason(chain, vault, ZERO20, w.dep.cfg.ty, w.dep.cfg.aid, recip, amt);
  await rejects(burnWith((w, a) => R(w, ZERO20, a)), 'ErrReturnRecip', 'zero recipient');
  await rejects(burnWith((w, a) => R(w, VAULT, a)), 'ErrReturnRecip', 'vault recipient');
  await rejects(burnWith((w) => R(w, recipient20(), Uint8Array.of(3, 231))), 'ErrReturnAmount');
  await rejects(burnWith((w, a) => R(w, recipient20(), a, new Uint8Array(20).fill(0xee))), 'ErrReturnData', 'other vault');
  await rejects(burnWith((w, a) => R(w, recipient20(), a, VAULT, CHAIN_ID + 1n)), 'ErrReturnData', 'other chain');
  await rejects(burnWith((w, a) => Uint8Array.of(...R(w, recipient20(), a), 0)), 'ErrReturnData', 'trailing byte');
});

test('nullifier excludes time, paths and unlock representation', async () => {
  const a = await w0.bridge.verifyNativeToken((await buildToken(w0, spec(1), [burnStep(T0 + 10n)], T0, UC_TS)).token, 'return');
  const b = await w0.bridge.verifyNativeToken((await buildToken(w0, spec(1), [burnStep(T0 + 10n)], T0, UC_TS + 50n)).token, 'return');
  assert.deepEqual(a.outcome.nullifier, b.outcome.nullifier);
});

test('transfer count budget: 64 verify, 65 is a budget failure', async () => {
  const steps = (n: number): ReturnType<typeof txStep>[] => Array.from({ length: n }, (_, i) => txStep(2 + (i % 2), i, T0 + 1n));
  await w0.bridge.verifyNativeToken((await buildToken(w0, spec(1), steps(64), T0, UC_TS)).token, 'receipt');
  await rejects(rec(w0, {}, spec(1), steps(65)), 'ErrTooManyTx');
});

// ---- compact history ---------------------------------------------------------------------------

test('compact history projection round trips and rejects malformed bytes', async () => {
  const out = await buildToken(w0, spec(1), [txStep(2, 7, T0 + 10n), txStep(3, 8, T0 + 20n)], T0, UC_TS);
  const bytes = projectToken(out.token);
  const h = decodeHistory(bytes);
  assert.equal(h.transfers.length, 2);
  assert.equal(h.mintT, T0);
  assert.deepEqual(h.times, [T0 + 10n, T0 + 20n]);
  assert.equal((await verifyHistory(w0.dep, h, false)).leaves.length, 3);
  await rejects(verifyHistory(w0.dep, h, true), 'ErrNotBurn');
  assert.throws(() => decodeHistory(Uint8Array.of(...bytes, 0)));
  assert.throws(() => decodeHistory(bytes.slice(0, -1)));
});

test('prepareLock binds cfg, nonce, amount, id and recipient', () => {
  const s = spec(1);
  const { digest, tokenId, salt } = digestOf(w0, s);
  const o = prepareLock(w0.dep, 1n, s.amount, ownerPredicate(s.owner).toCBOR());
  assert.deepEqual(o.lockDigest, digest);
  assert.deepEqual(o.tokenId, tokenId);
  assert.deepEqual(o.salt, salt);
  for (const [n, a] of [[0n, s.amount], [1n, Uint8Array.of(0, 1)], [1n, new Uint8Array()]] as const) {
    assert.throws(() => prepareLock(w0.dep, n, a, ownerPredicate(s.owner).toCBOR()));
  }
});

// ---- the pure relation, with no SDK in the loop (what ureth and the B2 kernel run) -------------

const relation = async (w: World, out: Awaited<ReturnType<typeof buildToken>>) => verifyHistory(w.dep, decodeHistory(projectToken(out.token)), false);

test('relation alone enforces certification data deadline equality', async () => {
  const s = spec(1);
  await rejects(relation(w0, await buildToken(w0, s, [], T0, UC_TS, { cdDeadline: [[0, T0 + 5n]] })), 'ErrCDMismatch');
  const s2 = spec(1);
  s2.mintDeadline = T0 + 5n;
  await rejects(relation(w0, await buildToken(w0, s2, [], T0, UC_TS, { cdDeadline: [[0, null]] })), 'ErrCDMismatch');
});

test('relation alone enforces t strictly below the deadline', async () => {
  for (const [e, ok] of [[T0 - 1n, false], [T0, false], [T0 + 1n, true]] as const) {
    const s = spec(1);
    s.mintDeadline = e;
    const p = relation(w0, await buildToken(w0, s, [], T0, UC_TS));
    if (ok) await p;
    else await rejects(p, 'ErrDeadlineExpired', `e=${e}`);
  }
});
