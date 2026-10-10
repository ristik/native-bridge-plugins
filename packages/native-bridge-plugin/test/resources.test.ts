import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CborDeserializer as D } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { CborMap } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborMap.js';
import { CborMapEntry } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborMapEntry.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { MAX_TRANSFERS } from '../src/limits.js';
import { arr, bs, u } from '../src/profile.js';
import { preflightToken, preflightUc } from '../src/resources.js';
import { rejects } from './util.js';
import { buildToken, makeWorld, spec, txStep } from './world.js';

const body = (b: Uint8Array) => D.decodeArray(D.decodeTag(b).data);
const tagged = (tag: number, kids: Uint8Array[]) => C.encodeTag(tag, arr(...kids));
function replaceUc(bytes: Uint8Array, uc: Uint8Array): Uint8Array {
  const token = body(bytes), cert = D.decodeArray(token[1]), proof = body(cert[1]);
  proof[4] = uc; cert[1] = tagged(39033, proof); token[1] = arr(...cert);
  return tagged(39040, token);
}
function sizedUc(base: Uint8Array, target: number): Uint8Array {
  const uc = body(base), st = body(uc[4]), ut = body(uc[5]), seal = body(uc[6]), ir = body(uc[1]);
  st[1] = bs(Uint8Array.from({ length: 33 }, (_, i) => i === 32 ? 128 : 0));
  st[2] = arr(...Array.from({ length: 256 }, () => bs(new Uint8Array(32))));
  ut[2] = arr(...Array.from({ length: 32 }, () => arr(u(1), bs(new Uint8Array(32)))));
  uc[4] = tagged(39003, st); uc[5] = tagged(39004, ut);
  for (let count = 1; count <= 64; count++) {
    seal[7] = C.encodeMap(new CborMap(Array.from({ length: count }, (_, i) => new CborMapEntry(C.encodeTextString(String(i).padStart(128, 'x')), bs(new Uint8Array(65))))));
    uc[6] = tagged(39005, seal);
    ir[5] = bs(new Uint8Array()); uc[1] = tagged(39002, ir);
    const gap = target - tagged(39001, uc).length;
    for (const summary of [gap, gap - 1, gap - 2]) {
      if (summary < 0 || summary > 256) continue;
      ir[5] = bs(new Uint8Array(summary)); uc[1] = tagged(39002, ir);
      const out = tagged(39001, uc); if (out.length === target) return out;
    }
  }
  throw new Error('cannot size UC');
}

test('ordinary UC byte limit is enforced before SDK decoding and on decoded tokens', async () => {
  const w = makeWorld(); const out = await buildToken(w, spec(1), [], 1n, 2n);
  const base = out.token.genesis.inclusionProof.unicityCertificate.toCBOR();
  const at = sizedUc(base, 16384), over = sizedUc(base, 16385);
  assert.equal(at.length, 16384); preflightUc(at); preflightToken(replaceUc(out.bytes, at));
  // Resource-valid boundary reaches the semantic shard check; its synthetic paths are not a proof.
  await rejects(w.bridge.verifyNativeTokenBytes(replaceUc(out.bytes, at), 'receipt'), 'ErrShardMismatch');
  for (const uc of [over, sizedUc(base, 17473)]) {
    const bytes = replaceUc(out.bytes, uc);
    await rejects(w.bridge.verifyNativeTokenBytes(bytes, 'receipt'), 'ErrProofTooLarge');
    await rejects(w.bridge.verifyNativeToken(await Token.fromCBOR(bytes), 'receipt'), 'ErrProofTooLarge');
  }
});

test('native UC sublimits apply equally to ordinary and standalone embedded UCs', async () => {
  const w = makeWorld(); const out = await buildToken(w, spec(1), [], 1n, 2n);
  const base = out.token.genesis.inclusionProof.unicityCertificate.toCBOR();
  const mutations: ((k: Uint8Array[]) => void)[] = [
    k => { const ir = body(k[1]); ir[5] = bs(new Uint8Array(257)); k[1] = tagged(39002, ir); },
    k => { const st = body(k[4]); st[1] = bs(new Uint8Array(34).fill(128)); k[4] = tagged(39003, st); },
    k => { const st = body(k[4]); st[2] = arr(...Array.from({length: 257}, () => bs(new Uint8Array(32)))); k[4] = tagged(39003, st); },
    k => { const ut = body(k[5]); ut[2] = arr(...Array.from({length: 33}, () => arr(u(1), bs(new Uint8Array(32))))); k[5] = tagged(39004, ut); },
    k => { const seal = body(k[6]); seal[7] = C.encodeMap(new CborMap([new CborMapEntry(C.encodeTextString('x'.repeat(129)), bs(new Uint8Array(65)))])); k[6] = tagged(39005, seal); },
    k => { const seal = body(k[6]); seal[7] = C.encodeMap(new CborMap(Array.from({length:65}, (_, i) => new CborMapEntry(C.encodeTextString(String(i)), bs(new Uint8Array(65)))))); k[6] = tagged(39005, seal); },
  ];
  for (const mutate of mutations) {
    const k = body(base); mutate(k); const uc = tagged(39001, k);
    assert.throws(() => preflightUc(uc), { reason: 'ErrProofTooLarge' });
    const bytes = replaceUc(out.bytes, uc);
    await rejects(w.bridge.verifyNativeTokenBytes(bytes, 'receipt'), 'ErrProofTooLarge');
    await rejects(w.bridge.verifyNativeToken(await Token.fromCBOR(bytes), 'receipt'), 'ErrProofTooLarge');
  }
});

test('UC tree paths and RSMT paths share the full-token cumulative budget', async () => {
  const w = makeWorld();
  // MAX_TRANSFERS transfers: MAX_LEAVES certificates of 32 unicity steps and 100 shard-tree siblings each.
  const out = await buildToken(w, spec(1), Array.from({length: MAX_TRANSFERS}, (_, i) => txStep(i + 2, i + 1, BigInt(i + 2))), 1n, 100n);
  const token = body(out.bytes);
  const certs = [token[1], ...D.decodeArray(token[2])].map(c => {
    const cert = D.decodeArray(c), proof = body(cert[1]), uc = body(proof[4]), ut = body(uc[5]), st = body(uc[4]);
    ut[2] = arr(...Array.from({length:32}, () => arr(u(1), bs(new Uint8Array(32)))));
    st[2] = arr(...Array.from({length:100}, () => bs(new Uint8Array(32))));
    uc[4] = tagged(39003, st);
    uc[5] = tagged(39004, ut); proof[4] = tagged(39001, uc); cert[1] = tagged(39033, proof); return arr(...cert);
  });
  token[1] = certs[0]; token[2] = arr(...certs.slice(1)); const bytes = tagged(39040, token);
  await rejects(w.bridge.verifyNativeTokenBytes(bytes, 'receipt'), 'ErrTooManyPaths');
  await rejects(w.bridge.verifyNativeToken(await Token.fromCBOR(bytes), 'receipt'), 'ErrTooManyPaths');
});

test('nested payloads share depth and item budgets with the outer token', async () => {
  const w = makeWorld(); const out = await buildToken(w, spec(1), [], 1n, 2n);
  const token = body(out.bytes), cert = D.decodeArray(token[1]), mint = body(cert[0]);
  // Each payload and the outer token is individually under the item limit.
  mint[5] = bs(arr(...Array.from({length:16400}, () => u(0))));
  mint[6] = bs(arr(...Array.from({length:16400}, () => u(0))));
  cert[0] = tagged(39041, mint); token[1] = arr(...cert);
  const many = tagged(39040, token);
  await rejects(w.bridge.verifyNativeTokenBytes(many, 'receipt'), 'ErrTooManyItems');
  await rejects(w.bridge.verifyNativeToken(await Token.fromCBOR(many), 'receipt'), 'ErrTooManyItems');
  let nested = u(0); for (let i = 0; i < 11; i++) nested = arr(nested);
  mint[5] = bs(nested); mint[6] = C.encodeNull(); cert[0] = tagged(39041, mint); token[1] = arr(...cert);
  const deep = tagged(39040, token);
  await rejects(w.bridge.verifyNativeTokenBytes(deep, 'receipt'), 'ErrTooDeep');
  await rejects(w.bridge.verifyNativeToken(await Token.fromCBOR(deep), 'receipt'), 'ErrTooDeep');
  nested = arr(); for (let i = 0; i < 10; i++) nested = arr(nested);
  mint[5] = bs(nested); cert[0] = tagged(39041, mint); token[1] = arr(...cert);
  const emptyDeep = tagged(39040, token);
  await rejects(w.bridge.verifyNativeTokenBytes(emptyDeep, 'receipt'), 'ErrTooDeep');
  await rejects(w.bridge.verifyNativeToken(await Token.fromCBOR(emptyDeep), 'receipt'), 'ErrTooDeep');
});


test('an otherwise valid receipt cannot hide an oversized ordinary UC in unknown signatures', async () => {
  const w = makeWorld(); const out = await buildToken(w, spec(1), [], 1n, 2n);
  const k = body(out.token.genesis.inclusionProof.unicityCertificate.toCBOR());
  const seal = body(k[6]);
  const entries = D.decodeMap(seal[7]).map(e => new CborMapEntry(e.key, e.value));
  entries.push(new CborMapEntry(C.encodeTextString('x'.repeat(17000)), bs(new Uint8Array(65))));
  seal[7] = C.encodeMap(new CborMap(entries)); k[6] = tagged(39005, seal);
  const bytes = replaceUc(out.bytes, tagged(39001, k));
  await rejects(w.bridge.verifyNativeTokenBytes(bytes, 'receipt'), 'ErrProofTooLarge');
  await rejects(w.bridge.verifyNativeToken(await Token.fromCBOR(bytes), 'receipt'), 'ErrProofTooLarge');
});


test('the cumulative path boundary includes the immutable embedded certificate', async () => {
  const w = makeWorld();
  const out = await buildToken(w, spec(1), Array.from({length: MAX_TRANSFERS}, (_, i) => txStep(i + 2, i + 1, BigInt(i + 2))), 1n, 100n);
  const make = (extra: number): Uint8Array => {
    const token = body(out.bytes);
    const certs = [token[1], ...D.decodeArray(token[2])].map(c => D.decodeArray(c));
    // Add 32 path steps inside the immutable J, without changing its length budget.
    const mint = body(certs[0][0]), j = body(D.decodeByteString(mint[5])), lp = D.decodeArray(j[5]);
    const embedded = body(D.decodeByteString(lp[4])), eut = body(embedded[5]);
    eut[2] = arr(...Array.from({length:32}, () => arr(u(1), bs(new Uint8Array(32)))));
    embedded[5] = tagged(39004, eut); lp[4] = bs(tagged(39001, embedded)); j[5] = arr(...lp);
    mint[5] = bs(tagged(39049, j)); certs[0][0] = tagged(39041, mint);
    const rsmt = certs.reduce((sum, c) => sum + (D.decodeByteString(body(c[1])[3]).length - 32) / 32, 0);
    let remaining = 2048 - 32 - rsmt + extra;
    for (const c of certs) {
      const proof = body(c[1]), uc = body(proof[4]), ut = body(uc[5]), st = body(uc[4]);
      const n = Math.min(288, remaining); remaining -= n;
      const steps = Math.min(32, n);
      ut[2] = arr(...Array.from({length:steps}, () => arr(u(1), bs(new Uint8Array(32)))));
      st[2] = arr(...Array.from({length:n - steps}, () => bs(new Uint8Array(32))));
      uc[4] = tagged(39003, st);
      uc[5] = tagged(39004, ut); proof[4] = tagged(39001, uc); c[1] = tagged(39033, proof);
    }
    assert.equal(remaining, 0);
    token[1] = arr(...certs[0]); token[2] = arr(...certs.slice(1).map(c => arr(...c)));
    return tagged(39040, token);
  };
  preflightToken(make(0));
  const over = make(1);
  await rejects(w.bridge.verifyNativeTokenBytes(over, 'receipt'), 'ErrTooManyPaths');
  await rejects(w.bridge.verifyNativeToken(await Token.fromCBOR(over), 'receipt'), 'ErrTooManyPaths');
});
