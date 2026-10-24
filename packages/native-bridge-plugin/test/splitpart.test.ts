import assert from 'node:assert/strict';
import { test } from 'node:test';

import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { SplitMintJustification } from '@unicitylabs/state-transition-sdk/lib/payment/SplitMintJustification.js';
import { SplitTokenRequest } from '@unicitylabs/state-transition-sdk/lib/payment/SplitTokenRequest.js';
import { TokenSplit, type ISplit } from '@unicitylabs/state-transition-sdk/lib/payment/TokenSplit.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import type { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';

import { eq, toHex } from '../src/bytes.js';
import { projectToken } from '../src/history.js';
import { MAX_JUSTIFICATION_BYTES } from '../src/limits.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { Token as SdkToken } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { COMPOSE_OUTPUT_BYTES_V2, composeInput } from '../src/compose.js';
import { NativeError } from '../src/errors.js';
import { composeOfflineV2 } from '../src/lineage.js';
import { buildReturnProof, checkBurnProjection, preflightBurn } from '../src/proof.js';
import { cfgBytes, policyBytes, valueEnvelope } from '../src/profile.js';
import { preflightToken } from '../src/resources.js';
import { WalletValue, lineageProofs, splitChain } from '../src/splitpart.js';
import { DEFAULT_REDEEM, anchorRounds, redeemReturn, returnIdentity, type ChainReader, type RedeemTransport } from '../src/readiness.js';
import { createNativeBridgePlugin } from '../src/wallet.js';
import { BridgedTokenIssuancePolicy } from '../src/verifier.js';
import { AGG_PARTITION, NETWORK, assembleToken, buildToken, burnStep, makeWorld, signer, spec, txStep, type MintSpec, type TokenOut, type World } from './world.js';

const T0 = 1_700_000_000n;
const UC_TS = T0 + 10_000n;
const amt = (n: number): Uint8Array => {
  const out: number[] = [];
  for (let x = n; x > 0; x = Math.floor(x / 256)) out.unshift(x % 256);
  return Uint8Array.of(...out);
};

async function rejects(p: Promise<unknown>, reason: string): Promise<void> {
  await assert.rejects(p, (e: unknown) => e instanceof NativeError && e.reason === reason, reason);
}

/** One output of a split: who receives it, how much, with which salt. */
interface Out { owner: number; amount: number; salt: number }

/** The SDK's split of `held` into `outs` (manifest and allocation proofs; the burn is assembled by the world). */
function sdkSplit(w: World, held: Token, outs: Out[]): Promise<ISplit> {
  const requests = outs.map((o) =>
    SplitTokenRequest.create(SignaturePredicate.create(signer(o.owner).publicKey), WalletValue.of(w.dep.cfg.aid, amt(o.amount)), TokenSalt.fromBytes(new Uint8Array(32).fill(o.salt))));
  return TokenSplit.split(held, WalletValue.decode, requests);
}

/** Mint output `j` of `split` from the burned source and give it `steps`. */
async function mintChild(w: World, split: ISplit, j: number, out: Out, burned: Token, steps: Parameters<typeof assembleToken>[4], t: bigint): Promise<TokenOut> {
  const o = split.tokens[j];
  const mint = await MintTransaction.create(NetworkId.fromId(NETWORK), o.recipient, {
    data: await o.paymentData.encode(),
    justification: SplitMintJustification.create(burned, o.proofs).toCBOR(),
    salt: o.salt,
    tokenType: o.tokenType,
  });
  const s: MintSpec = { ...spec(out.owner), amount: amt(out.amount) };
  return assembleToken(w, s, mint, {}, steps, t, UC_TS);
}

/** Root variations: its spec, the certificate time of its leaves, and transfers before its split burn (the split burn's time follows them). */
interface RootOpts { root?: MintSpec; rootUcTs?: bigint; rootSteps?: Parameters<typeof assembleToken>[4]; rootPartition?: number; rootPartitionAt?: [number, number] }

/** Lock 1000 -> split 400 + 600 (the 400 to owner 2), and optionally split the 400 again into 150 + 250. */
async function lineage(w: World, childSteps: (s: MintSpec) => Parameters<typeof assembleToken>[4], depth: 1 | 2 = 1, o: RootOpts = {}) {
  const root = o.root ?? spec(1);
  const held = await buildToken(w, root, [], T0, UC_TS);
  const first: Out[] = [{ owner: 2, amount: 400, salt: 0x10 }, { owner: 3, amount: 600, salt: 0x20 }];
  const s1 = await sdkSplit(w, held.token, first);
  const pre = o.rootSteps ?? [];
  const burnT = T0 + 10n + BigInt(pre.length);
  const burned = await buildToken(w, root, [...pre, { kind: 'burnWith', reason: s1.burn.transaction.data!, t: burnT }], T0, o.rootUcTs ?? UC_TS, { ucPartition: o.rootPartition, ucPartitionAt: o.rootPartitionAt });
  if (depth === 1) {
    const child = await mintChild(w, s1, 0, first[0], burned.token, childSteps({ ...spec(2), amount: amt(400) }), T0 + 20n);
    const sibling = await mintChild(w, s1, 1, first[1], burned.token, [], T0 + 21n);
    return { root: burned, child, sibling };
  }
  const heldChild = await mintChild(w, s1, 0, first[0], burned.token, [], T0 + 20n);
  const second: Out[] = [{ owner: 4, amount: 150, salt: 0x30 }, { owner: 5, amount: 250, salt: 0x40 }];
  const s2 = await sdkSplit(w, heldChild.token, second);
  const burnedChild = await mintChild(w, s1, 0, first[0], burned.token, [{ kind: 'burnWith', reason: s2.burn.transaction.data!, t: T0 + 30n }], T0 + 20n);
  const child = await mintChild(w, s2, 0, second[0], burnedChild.token, childSteps({ ...spec(4), amount: amt(150) }), T0 + 40n);
  const sibling = await mintChild(w, s2, 1, second[1], burnedChild.token, [], T0 + 41n);
  return { root: burned, child, sibling };
}

test('a held split part verifies (receipt): the root\'s lock and identity, the part, and every leaf of the lineage admitted', async () => {
  const w = await makeWorld();
  const { root, child, sibling } = await lineage(w, () => [txStep(7, 9, T0 + 25n)]);
  const v = await w.bridge.verifyNativeToken(child.token, 'receipt');
  assert.equal(v.lineage?.depth, 1);
  assert.deepEqual(v.lineage?.partAmount, amt(400));
  assert.deepEqual(v.outcome.amount, amt(1000), 'the root amount: what the lock digest commits');
  assert.ok(eq(v.outcome.tokenId, root.token.id.bytes));
  assert.ok(eq(v.lineage!.partTokenId, child.token.id.bytes));
  assert.equal(v.outcome.leaves.length, 2 + 2, 'the root mint and its split burn, the part mint and its one transfer');
  assert.ok(v.outcome.nullifier.every((x) => x === 0), 'a held part has no return');
  // the sibling, with no transfer at all, is a held part too
  assert.equal((await w.bridge.verifyNativeToken(sibling.token, 'receipt')).lineage?.partAmount.length, 2);
  // splitChain is the ancestry, root first
  const chain = await splitChain(child.token);
  assert.deepEqual(chain.map((t) => toHex(t.id.bytes)), [toHex(root.token.id.bytes), toHex(child.token.id.bytes)]);
});

test('a returned split part builds the V2 envelope: the composition\'s offline steps accept it and price it as the gate does', async () => {
  const w = await makeWorld();
  const { child } = await lineage(w, () => [txStep(7, 9, T0 + 25n), burnStep(T0 + 26n)]);
  const built = await buildReturnProof(w.bridge, child.token);
  const lin = built.verified.lineage!;
  assert.equal(built.envelope.leafProofs.length, lin.leaves.length);
  assert.deepEqual(lin.partAmount, amt(400));
  const cfg = cfgBytes(w.dep.cfg);
  const offline = await composeOfflineV2(w.dep, cfg, built.encoded);
  assert.equal(built.gate.native, offline.gas, 'the gate is the V2 charge: the schedule over every leaf plus the walk');
  assert.ok(eq(offline.nullifier, lin.nullifier) && eq(offline.lockDigest, lin.lockDigest));
  assert.ok(composeInput(2, cfg, built.encoded).length > 0 && COMPOSE_OUTPUT_BYTES_V2 === 480);
});

test('a depth-2 part (a split of a split) verifies and returns; the token preflight bounds a split reason as a token', async () => {
  const w = await makeWorld();
  const { root, child } = await lineage(w, () => [burnStep(T0 + 45n)], 2);
  preflightToken(child.bytes);
  const built = await buildReturnProof(w.bridge, child.token);
  const lin = built.verified.lineage!;
  assert.equal(lin.depth, 2);
  assert.deepEqual(lin.partAmount, amt(150));
  assert.ok(eq(lin.tokenId, root.token.id.bytes));
  assert.deepEqual(lin.levels.map((l) => l.amount), [amt(1000), amt(400), amt(150)]);
  assert.equal(built.gate.native, (await composeOfflineV2(w.dep, cfgBytes(w.dep.cfg), built.encoded)).gas);
});

test('the burn-time estimate of a held part is verified first and prices the lineage and the walk', async () => {
  const w = await makeWorld();
  const { child } = await lineage(w, () => [txStep(7, 9, T0 + 25n)]);
  const gate = await preflightBurn(w.bridge, child.bytes);
  const plain = await preflightBurn(w.bridge, (await buildToken(w, spec(1), [txStep(7, 9, T0 + 25n)], T0, UC_TS)).bytes);
  assert.ok(gate.native > plain.native, 'more leaves and the walk');
});

test('the issuance policy admits a split output only as its root deployment\'s exact envelope', async () => {
  const w = await makeWorld();
  const { child } = await lineage(w, () => []);
  const policy = new BridgedTokenIssuancePolicy(w.bridge, w.dep.cfg.ty);
  policy.check(child.token.genesis);
  const g = child.token.genesis;
  const forged = Object.create(Object.getPrototypeOf(g), { ...Object.getOwnPropertyDescriptors(g), data: { value: valueEnvelope(new Uint8Array(32).fill(9), amt(400)) } });
  assert.throws(() => policy.check(forged), (e: unknown) => e instanceof NativeError && e.reason === 'ErrIssuanceData');
  const noRoot = Object.create(Object.getPrototypeOf(g), { ...Object.getOwnPropertyDescriptors(g), justification: { value: Uint8Array.of(0xd9, 0x98, 0x84, 0x80) } });
  assert.throws(() => policy.check(noRoot), (e: unknown) => e instanceof NativeError && e.reason === 'ErrIssuanceReason');
});

test('refusals: a part returned for its root amount, a sibling\'s reason on another mint, a part whose value is not its allocation', async () => {
  const w = await makeWorld();
  // the return reason of the part names the root's amount: ErrReturnAmount
  const root = spec(1);
  const held = await buildToken(w, root, [], T0, UC_TS);
  const outs: Out[] = [{ owner: 2, amount: 400, salt: 0x10 }, { owner: 3, amount: 600, salt: 0x20 }];
  const s1 = await sdkSplit(w, held.token, outs);
  const burned = await buildToken(w, root, [{ kind: 'burnWith', reason: s1.burn.transaction.data!, t: T0 + 10n }], T0, UC_TS);
  const o = s1.tokens[0];
  const mint = await MintTransaction.create(NetworkId.fromId(NETWORK), o.recipient, {
    data: await o.paymentData.encode(), justification: SplitMintJustification.create(burned.token, o.proofs).toCBOR(), salt: o.salt, tokenType: o.tokenType,
  });
  const asRoot = await assembleToken(w, { ...spec(2), amount: amt(1000) }, mint, {}, [burnStep(T0 + 26n)], T0 + 20n, UC_TS);
  await rejects(w.bridge.verifyNativeToken(asRoot.token, 'return'), 'ErrReturnAmount');
  // output 0's proofs on output 1's mint: the allocation does not verify
  const o1 = s1.tokens[1];
  const swapped = await MintTransaction.create(NetworkId.fromId(NETWORK), o1.recipient, {
    data: await o1.paymentData.encode(), justification: SplitMintJustification.create(burned.token, o.proofs).toCBOR(), salt: o1.salt, tokenType: o1.tokenType,
  });
  const wrongProof = await assembleToken(w, { ...spec(3), amount: amt(600) }, swapped, {}, [], T0 + 21n, UC_TS);
  await rejects(w.bridge.verifyNativeToken(wrongProof.token, 'receipt'), 'ErrSplitProof');
  // the part claims 500 with the proof of 400
  const inflated = await MintTransaction.create(NetworkId.fromId(NETWORK), o.recipient, {
    data: valueEnvelope(w.dep.cfg.aid, amt(500)), justification: SplitMintJustification.create(burned.token, o.proofs).toCBOR(), salt: o.salt, tokenType: o.tokenType,
  });
  const more = await assembleToken(w, { ...spec(2), amount: amt(500) }, inflated, {}, [], T0 + 20n, UC_TS);
  await rejects(w.bridge.verifyNativeToken(more.token, 'receipt'), 'ErrSplitProof');
});

test('the burn-time estimate adds exactly the walk\'s charge to the projection of the whole lineage', async () => {
  const w = await makeWorld();
  const { child } = await lineage(w, () => [txStep(7, 9, T0 + 25n)]);
  const held = await w.bridge.verifyNativeToken(child.token, 'receipt');
  const leaves = held.outcome.leaves.length + 1;
  const base = checkBurnProjection(cfgBytes(w.dep.cfg).length, policyBytes(w.dep.policy).length, leaves, projectToken(child.token).length, 1);
  const gate = await preflightBurn(w.bridge, child.bytes);
  assert.equal(gate.native - base.native, held.lineage!.splitGas);
  assert.equal(gate.total - base.total, held.lineage!.splitGas);
});

test('a held part is the receipt relation: a part ending in a burn is not held (ErrUnexpectedBurn)', async () => {
  const w = await makeWorld();
  const { child } = await lineage(w, () => [txStep(7, 9, T0 + 25n), burnStep(T0 + 26n)]);
  await rejects(w.bridge.verifyNativeToken(child.token, 'receipt'), 'ErrUnexpectedBurn');
  await w.bridge.verifyNativeToken(child.token, 'return');
});

test('every ancestor leaf is admitted like the part\'s: an ancestor certified in another partition, or after its time, is refused', async () => {
  const w = await makeWorld();
  // the root's leaves certified by a validly signed certificate of a partition the policy does not name: only the bridge admission refuses
  const { child } = await lineage(w, () => [], 1, { rootPartition: AGG_PARTITION + 1 });
  await rejects(w.bridge.verifyNativeToken(child.token, 'receipt'), 'ErrNotAdmitted');
  // exactly one out-of-policy leaf: only the root's transfer (leaf 1), or only its split burn (leaf 2), or only its mint (leaf 0), in another partition
  for (const leaf of [1, 2, 0]) {
    const one = await lineage(w, () => [], 1, { rootSteps: [txStep(7, 9, T0 + 5n)], rootPartitionAt: [leaf, AGG_PARTITION + 1] });
    await rejects(w.bridge.verifyNativeToken(one.child.token, 'receipt'), 'ErrNotAdmitted');
  }
  // control: the same lineage with every leaf in the policy's partition is admitted
  await w.bridge.verifyNativeToken((await lineage(w, () => [], 1, { rootSteps: [txStep(7, 9, T0 + 5n)] })).child.token, 'receipt');
  // the root's certificates are stamped before its split burn
  const late = await lineage(w, () => [], 1, { rootUcTs: T0 + 5n });
  await rejects(w.bridge.verifyNativeToken(late.child.token, 'receipt'), 'ErrReferenceTimeFuture');
});

test('the root\'s lock proof is the backing of every part: a root whose vault slot does not hold its digest refuses the part', async () => {
  const w = await makeWorld();
  const root = spec(1);
  root.evm.stored = new Uint8Array(32);
  const { child } = await lineage(w, () => [], 1, { root });
  await rejects(w.bridge.verifyNativeToken(child.token, 'receipt'), 'ErrLockStorage');
});

test('the SDK verification runs on a part: a part whose mint carries a valid certificate of another tree is refused', async () => {
  const w = await makeWorld();
  const { child, sibling } = await lineage(w, () => []);
  // the part's mint proof with the sibling's certificate: same partition, shard and time, another state root
  const swap = (tok: SdkToken, uc: Uint8Array): Uint8Array => {
    const outer = CborDeserializer.decodeArray(CborDeserializer.decodeTag(tok.toCBOR()).data, 3);
    const genesis = CborDeserializer.decodeArray(outer[1], 2);
    const p = CborDeserializer.decodeArray(CborDeserializer.decodeTag(genesis[1]).data, 5);
    const proof = C.encodeTag(39033n, C.encodeArray(p[0], p[1], p[2], p[3], uc));
    return C.encodeTag(39040n, C.encodeArray(outer[0], C.encodeArray(genesis[0], proof), outer[2]));
  };
  const bytes = swap(child.token, sibling.token.genesis.inclusionProof.unicityCertificate.toCBOR());
  await assert.rejects(w.bridge.verifyNativeTokenBytes(bytes, 'receipt'), (e: unknown) => e instanceof NativeError);
  const forged = await SdkToken.fromCBOR(bytes);
  // the relation and the admission alone accept it (the certificate is the deployment's own): only the SDK's path check refuses
  const r = await w.bridge.verifyNativeToken(forged, 'receipt').then(() => 'ok', (e: NativeError) => e.reason);
  assert.notEqual(r, 'ok');
  assert.ok(!['ErrReferenceTimeFuture', 'ErrNotAdmitted', 'ErrShardMismatch', 'ErrCDMismatch'].includes(r), r);
});

test('a split reason is bounded as a token, not as a 64 KiB lock reason: a part whose parent has a long history verifies', async () => {
  const w = await makeWorld();
  const pre = Array.from({ length: 90 }, (_, i) => txStep(i % 2 === 0 ? 8 : 1, 3 + (i % 5), T0 + 1n + BigInt(i)));
  const { child } = await lineage(w, () => [], 1, { rootSteps: pre });
  assert.ok(child.token.genesis.justification!.length > MAX_JUSTIFICATION_BYTES, String(child.token.genesis.justification!.length));
  preflightToken(child.bytes);
  await w.bridge.verifyNativeToken(child.token, 'receipt');
});

test('fresh witnesses go into the envelope only, one per lineage leaf for the same certified leaf', async () => {
  const w = await makeWorld();
  const { child } = await lineage(w, () => [burnStep(T0 + 26n)]);
  const proofs = lineageProofs(await splitChain(child.token));
  const same = await buildReturnProof(w.bridge, child.token, proofs);
  assert.deepEqual(same.encoded, (await buildReturnProof(w.bridge, child.token)).encoded);
  await rejects(buildReturnProof(w.bridge, child.token, proofs.slice(1)), 'ErrRefreshMismatch');
  const swapped = [proofs[1], proofs[0], ...proofs.slice(2)];
  await rejects(buildReturnProof(w.bridge, child.token, swapped), 'ErrRefreshMismatch');
  // the same certification data under another reference time is another leaf (v = H(txHash, t)): refused, whichever lineage leaf it replaces
  for (const i of [0, proofs.length - 1]) {
    const [version, cd, , path, uc] = CborDeserializer.decodeArray(CborDeserializer.decodeTag(proofs[i].toCBOR()).data, 5);
    const later = InclusionProof.fromCBOR(C.encodeTag(39033, C.encodeArray(version, cd, C.encodeUnsignedInteger(proofs[i].referenceTime + 1n), path, uc)));
    assert.deepEqual(later.certificationData.toCBOR(), proofs[i].certificationData.toCBOR());
    await rejects(buildReturnProof(w.bridge, child.token, proofs.map((p, k) => (k === i ? later : p))), 'ErrRefreshMismatch');
  }
});

test('readiness keys a split part by (root nonce, part ID): identity, the part\'s own spent word, a sibling\'s spent word does not block it', async () => {
  const w = await makeWorld();
  const { child, sibling } = await lineage(w, () => [txStep(7, 9, T0 + 25n), burnStep(T0 + 26n)]);
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const id = await returnIdentity(plugin, child.bytes);
  assert.ok(eq(id.partId, child.token.id.bytes), 'the part key is the redeemed token\'s ID, never the root\'s');
  assert.equal(id.partAmount, 400n, 'the part\'s amount, not the lock\'s 1000');
  const built = await buildReturnProof(w.bridge, child.token);
  assert.equal(id.nonce, built.verified.outcome.nonce, 'the root lock nonce');
  assert.ok(eq(id.nullifier, built.verified.lineage!.nullifier));
  // anchors: the whole lineage's distinct certificates, root first
  const lineageUcs = new Set(lineageProofs(await splitChain(child.token)).map((p) => toHex(p.unicityCertificate.toCBOR())));
  assert.equal((await anchorRounds(child.token)).length, lineageUcs.size);
  const spent = new Map<string, Uint8Array>();
  const key = (n: bigint, p: Uint8Array) => `${n}:${toHex(p)}`;
  let sends = 0;
  const transport: RedeemTransport = {
    send: () => { sends++; return Promise.resolve('0x01'); },
    receipt: () => Promise.resolve(undefined),
    spentPart: (n, p) => Promise.resolve(spent.get(key(n, p)) ?? new Uint8Array(32)),
  };
  const chain: ChainReader = { origin: () => Promise.resolve(1n << 60n) };
  const down = (): Promise<never> => Promise.reject(new NativeError('ErrProofUnavailable', 'proof service down (test)'));
  const policy = { ...DEFAULT_REDEEM, maxAttempts: 1, maxSends: 1, receiptTimeoutMs: 0, pollMs: 0 };
  // the sibling's part of the same lock redeemed by its own burn: this part still goes on to fetch its proofs (and fails there, not on the spent word)
  spent.set(key(id.nonce, sibling.token.id.bytes), new Uint8Array(32).fill(7));
  await rejects(redeemReturn(plugin, child.bytes, down, chain, transport, policy), 'ErrProofUnavailable');
  // its own part credited by its own burn: already redeemed, before any proof is fetched
  spent.set(key(id.nonce, id.partId), id.nullifier);
  assert.equal((await redeemReturn(plugin, child.bytes, down, chain, transport, policy)).status, 'already-redeemed');
  // its own part credited by a different burn: ErrUnexpectedBurn
  spent.set(key(id.nonce, id.partId), new Uint8Array(32).fill(9));
  await rejects(redeemReturn(plugin, child.bytes, down, chain, transport, policy), 'ErrUnexpectedBurn');
  assert.equal(sends, 0);
});

test('a depth-32 part (split 32 times) preflights, verifies and returns on the JS stack: no unclassified RangeError, the gate is the composition\'s', async () => {
  const w = await makeWorld();
  const root: MintSpec = { ...spec(1), amount: amt(1000) };
  const level = (a: number, d: number): Out[] => [{ owner: 2 + (d % 3), amount: a - 1, salt: d }, { owner: 9, amount: 1, salt: (d + 0x80) & 0xff }];
  let amount = 1000;
  let held = (await buildToken(w, root, [], T0, UC_TS)).token;
  let outs = level(amount, 1);
  let split = await sdkSplit(w, held, outs);
  let t = T0 + 10n;
  let burned = (await buildToken(w, root, [{ kind: 'burnWith', reason: split.burn.transaction.data!, t }], T0, UC_TS)).token;
  for (let d = 2; d <= 32; d++) {
    amount -= 1;
    t += 10n;
    held = (await mintChild(w, split, 0, outs[0], burned, [], t)).token;
    const next = level(amount, d);
    const nextSplit = await sdkSplit(w, held, next);
    burned = (await mintChild(w, split, 0, outs[0], burned, [{ kind: 'burnWith', reason: nextSplit.burn.transaction.data!, t: t + 5n }], t)).token;
    split = nextSplit;
    outs = next;
  }
  const last = await mintChild(w, split, 0, outs[0], burned, [burnStep(t + 20n)], t + 10n);
  preflightToken(last.bytes);
  const built = await buildReturnProof(w.bridge, last.token);
  const lin = built.verified.lineage!;
  assert.equal(lin.depth, 32);
  assert.deepEqual(lin.partAmount, amt(1000 - 32));
  assert.equal(built.gate.native, (await composeOfflineV2(w.dep, cfgBytes(w.dep.cfg), built.encoded)).gas);
});
