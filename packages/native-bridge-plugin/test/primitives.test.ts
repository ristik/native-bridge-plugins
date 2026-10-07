import assert from 'node:assert/strict';
import { test } from 'node:test';

import { eq } from '../src/bytes.js';
import { makeDeployment } from '../src/deployment.js';
import { decodeHeader } from '../src/header.js';
import { verifyProof } from '../src/mpt.js';
import { decodeCfg, cfgBytes, decodePolicy, deriveAsset, deriveType, identityDomain, keccak256, policyBytes, valueEnvelope } from '../src/profile.js';
import { decode, encodeBytes, encodeList, encodeU64, u64Of } from '../src/rlp.js';
import { throwsReason } from './util.js';
import { CHAIN_ID, EXEC_GENESIS, NETWORK, ROOT_GENESIS, headerRlp, makeWorld, sha, text, trie } from './world.js';

test('rlp rejects every non-canonical form', () => {
  const cases: [string, number[]][] = [
    ['one byte below 0x80 in long form', [0x81, 0x05]],
    ['long form for a short string', [0xb8, 0x01, 0xaa]],
    ['leading zero in length', [0xb9, 0x00, 0x40]],
    ['truncated body', [0x82, 0x01]],
    ['trailing bytes', [0x01, 0x02]],
    ['truncated list', [0xc2, 0x01]],
    ['empty input', []],
  ];
  for (const [name, b] of cases) throwsReason(() => decode(Uint8Array.from(b)), 'ErrRlpMalformed', name);
  decode(Uint8Array.of(0x80));
  decode(Uint8Array.of(0x7f));
  throwsReason(() => u64Of(decode(Uint8Array.of(0x82, 0, 1))), 'ErrRlpMalformed');
  let x: Uint8Array = Uint8Array.of(0xc0);
  for (let i = 0; i < 40; i++) x = encodeList([x]);
  throwsReason(() => decode(x), 'ErrRlpMalformed', 'depth');
  assert.deepEqual(encodeU64(0n), Uint8Array.of(0x80));
});

const small = () => {
  const entries: [Uint8Array, Uint8Array][] = Array.from({ length: 40 }, (_, i) => [sha(Uint8Array.of(i)), Uint8Array.from([i + 1, i + 1, i + 1])]);
  const target = entries[7][0];
  const { root, proof } = trie(entries, target);
  return { root, proof, target, value: entries[7][1] };
};

test('mpt accepts the exact path and nothing else', () => {
  const { root, proof, target, value } = small();
  assert.deepEqual(verifyProof(root, target, proof), value);
  throwsReason(() => verifyProof(root, target, [...proof, proof[0]]), 'ErrMptMalformed', 'extra');
  throwsReason(() => verifyProof(root, target, proof.slice(0, -1)), 'ErrMptMalformed', 'missing');
  throwsReason(() => verifyProof(root, target, []), 'ErrMptMalformed', 'empty');
  if (proof.length > 1) throwsReason(() => verifyProof(root, target, [proof[1], proof[0], ...proof.slice(2)]), 'ErrMptMalformed', 'reordered');
  const m = proof.map((n) => n.slice());
  m[0][5] ^= 1;
  throwsReason(() => verifyProof(root, target, m), 'ErrMptMalformed', 'mutated');
  assert.throws(() => verifyProof(root, sha(text('absent')), proof));
  assert.throws(() => verifyProof(new Uint8Array(32).fill(1), target, proof));
  throwsReason(() => verifyProof(root, Uint8Array.of(...target, 0), proof), 'ErrMptMalformed', 'unused suffix');
  throwsReason(() => verifyProof(root, target.slice(0, 31), proof), 'ErrMptMalformed', 'short key');
});

test('mpt embedded children and single-entry tries', () => {
  const entries: [Uint8Array, Uint8Array][] = [
    [new Uint8Array(32).fill(0x10), Uint8Array.of(1)], [new Uint8Array(32).fill(0x11), Uint8Array.of(2)], [new Uint8Array(32).fill(0x20), Uint8Array.of(3)],
  ];
  for (const [k, v] of entries) {
    const { root, proof } = trie(entries, k);
    assert.deepEqual(verifyProof(root, k, proof), v);
  }
  const one: [Uint8Array, Uint8Array][] = [[new Uint8Array(32).fill(0x33), new Uint8Array(40).fill(9)]];
  const { root, proof } = trie(one, one[0][0]);
  verifyProof(root, one[0][0], proof);
});

test('hex-prefix flags are validated', () => {
  for (const flagByte of [0x40, 0x21]) {
    const bad = encodeList([encodeBytes(Uint8Array.of(flagByte)), encodeBytes(new Uint8Array(40).fill(1))]);
    throwsReason(() => verifyProof(keccak256(bad), new Uint8Array(32), [bad]), 'ErrMptMalformed', `flag ${flagByte}`);
  }
});

test('identifier derivations follow the family domain string', () => {
  const d = `${NETWORK}:${'11'.repeat(32)}:${'22'.repeat(32)}:${CHAIN_ID}:${'0'.repeat(40)}`;
  assert.equal(identityDomain(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID), d);
  assert.deepEqual(deriveType(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID), sha(text(`unicity-bridge:unicity-native:${d}`)));
  assert.deepEqual(deriveAsset(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID), sha(text(`unicity-bridge-coin:unicity-native:${d}`)));
  assert.ok(!eq(deriveType(NETWORK + 1, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID), deriveType(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID)));
  assert.ok(!eq(deriveType(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID + 1n), deriveType(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID)));
  assert.ok(!eq(deriveType(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID), deriveAsset(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID)));
});

test('value envelope bytes are exact', () => {
  const aid = new Uint8Array(32).fill(0x5a);
  assert.deepEqual(valueEnvelope(aid, Uint8Array.of(3, 232)), Uint8Array.of(0xd9, 0x98, 0x8a, 0x83, 0x01, 0x81, 0x82, 0x58, 0x20, ...aid, 0x42, 0x03, 0xe8, 0xf6));
});

test('cfg and policy round trip; deployment construction rejects forged identity', () => {
  const w = makeWorld();
  assert.deepEqual(decodeCfg(cfgBytes(w.dep.cfg)), w.dep.cfg);
  throwsReason(() => decodeCfg(Uint8Array.of(...cfgBytes(w.dep.cfg), 0)), 'ErrTrailing');
  assert.deepEqual(decodePolicy(policyBytes(w.policy)), w.policy);
  throwsReason(() => decodePolicy(new Uint8Array(129)), 'ErrInputTooLarge');
  const hp = { fields: 20 as const };
  const bad = (f: (c: typeof w.dep.cfg) => void, policy = w.policy) => {
    const c = structuredClone(w.dep.cfg);
    f(c);
    return () => makeDeployment(c, new Uint8Array(32), new Uint8Array(32), hp, policy);
  };
  throwsReason(bad((c) => void (c.ty[0] ^= 1)), 'ErrCfgMismatch');
  throwsReason(bad((c) => void (c.aggregatorPolicyHash[0] ^= 1)), 'ErrPolicyHash');
  const p = { partition: 7, shardConf: w.aggConf };
  throwsReason(bad((c) => void (c.aggregatorPolicyHash = sha(policyBytes(p))), p), 'ErrPolicyPartition');
  throwsReason(() => makeDeployment(w.dep.cfg, new Uint8Array(32), new Uint8Array(32), { fields: 19 as never }, w.policy), 'ErrCfgMismatch');
});

test('header fields are each pinned', () => {
  const p = { fields: 20 as const };
  const good = headerRlp(new Uint8Array(32).fill(7), 5n, 20);
  assert.equal(decodeHeader(good, p).number, 5n);
  throwsReason(() => decodeHeader(good, { fields: 21 }), 'ErrHeaderProfile');
  const f = (decode(good) as unknown as { items: { raw: Uint8Array }[] }).items;
  const rebuild = (i: number, v: Uint8Array): Uint8Array => encodeList(f.map((x, j) => (j === i ? v : x.raw)));
  const cases: [string, number, Uint8Array][] = [
    ['uncle hash', 1, encodeBytes(new Uint8Array(32).fill(1))], ['difficulty', 7, encodeU64(1n)], ['base fee', 15, encodeU64(0n)],
    ['withdrawals root', 16, encodeBytes(new Uint8Array(32).fill(1))], ['blob gas used', 17, encodeU64(1n)],
    ['excess blob gas', 18, encodeU64(1n)], ['extra data', 12, encodeBytes(new Uint8Array(33))], ['state root width', 3, encodeBytes(new Uint8Array(31).fill(1))],
  ];
  for (const [name, i, v] of cases) throwsReason(() => decodeHeader(rebuild(i, v), p), 'ErrHeaderProfile', name);
});
