/** Synthetic SDK certificates, actual plug-in logic. No chain or running service is implied. */
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { InclusionCertificate } from '@unicitylabs/state-transition-sdk/lib/api/InclusionCertificate.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { DataHasherFactory } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasherFactory.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { NodeDataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/NodeDataHasher.js';
import { SparseMerkleTree } from '@unicitylabs/state-transition-sdk/lib/smt/radix/SparseMerkleTree.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { concat, toHex } from '../../packages/native-bridge-plugin/src/bytes.js';
import { projectToken, prepareLock, type Outcome } from '../../packages/native-bridge-plugin/src/history.js';
import { arr, bs, cfgBytes, H, u, word } from '../../packages/native-bridge-plugin/src/profile.js';
import { buildReturnProof, refreshToken } from '../../packages/native-bridge-plugin/src/proof.js';
import { AGG_PARTITION, buildToken, burnStep, makeUc, makeWorld, ownerPredicate, sha, spec, txStep } from '../../packages/native-bridge-plugin/test/world.js';

const w = makeWorld();
const s = spec(1);
const t = 1_700_000_040n;
const ts = 1_700_000_900n;
const pad = (b: Uint8Array) => concat(b, new Uint8Array((32 - b.length % 32) % 32));
const dynamic = (b: Uint8Array) => concat(word(BigInt(b.length)), pad(b));
function request(op: bigint, payload: Uint8Array): Uint8Array {
  const cfg = dynamic(cfgBytes(w.dep.cfg));
  return concat(word(op), word(96n), word(BigInt(96 + cfg.length)), cfg, dynamic(payload));
}
function result(o: Outcome): Uint8Array {
  const marker = new Uint8Array(32);
  marker.set(new TextEncoder().encode('UNICITY_TOKEN_SEMANTICS'));
  const amount = new Uint8Array(32);
  amount.set(o.amount, 32 - o.amount.length);
  const recipient = new Uint8Array(32);
  recipient.set(o.releaseTo, 12);
  return concat(marker, word(1n), word(96n), o.cfg, word(o.nonce), amount, o.tokenId, o.salt,
    o.firstPredicateHash, o.lockDigest, recipient, o.nullifier, word(320n), word(BigInt(o.leaves.length)),
    ...o.leaves.flatMap(l => [l.sid, l.txHash, word(l.referenceTime), l.value]));
}
const cases: unknown[] = [];
const paths: unknown[] = [];
function add(name: string, op: bigint, payload: Uint8Array, o: Outcome) {
  cases.push({ name, request: toHex(request(op, payload)), expected: toHex(result(o)) });
}
const prepared = prepareLock(w.dep, s.nonce, s.amount, ownerPredicate(s.owner).toCBOR());
add('prepare', 0n, arr(u(s.nonce), bs(s.amount), ownerPredicate(s.owner).toCBOR()), prepared);
let previous: { tx: Uint8Array; cd: Uint8Array; t: bigint }[] = [];
let burned: Awaited<ReturnType<typeof buildToken>> | undefined;
for (const [name, steps, expect] of [
  ['mint', [], 'receipt'],
  ['transfer', [txStep(2, 7, t + 10n)], 'receipt'],
  ['burn', [txStep(2, 7, t + 10n), burnStep(t + 20n)], 'return'],
] as const) {
  const out = await buildToken(w, s, [...steps], t, ts);
  const verified = await w.bridge.verifyNativeTokenBytes(out.bytes, expect);
  const committed = [out.token.genesis, ...out.token.transactions].map(c => ({
    tx: CborDeserializer.decodeArray(c.toCBOR(), 2)[0],
    cd: c.inclusionProof.certificationData.toCBOR(), t: c.inclusionProof.referenceTime,
  }));
  assert.deepEqual(committed.slice(0, previous.length), previous, 'flow must extend exactly the prior certified history');
  previous = committed;
  if (name === 'mint') assert.deepEqual({ ...verified.outcome, leaves: [] }, prepared);
  // Operation 1 is pure mint; receipt verification above covers the transfer.
  if (name !== 'transfer') add(name, expect === 'return' ? 2n : 1n, projectToken(out.token), verified.outcome);
  if (name === 'burn') burned = out;
  const certs = [out.token.genesis, ...out.token.transactions];
  verified.outcome.leaves.forEach((l, i) => paths.push({
    name: `${name}/${i}`, sid: toHex(l.sid), txHash: toHex(l.txHash), t: l.referenceTime.toString(),
    value: toHex(l.value), root: toHex(certs[i].inclusionProof.unicityCertificate.inputRecord.hash),
    certificate: toHex(certs[i].inclusionProof.inclusionCertificate.encode()),
    proof: toHex(certs[i].inclusionProof.toCBOR()),
  }));
}
assert.ok(burned);
const before = await buildReturnProof(w.bridge, burned.token);
const smt = new SparseMerkleTree(new DataHasherFactory(HashAlgorithm.SHA256, NodeDataHasher));
for (const [sid, value] of burned.leaves) await smt.addLeaf(sid, value);
await smt.addLeaf(sha(Uint8Array.of(9)), sha(Uint8Array.of(10)));
const root = await smt.calculateRoot();
const uc = await makeUc(w.agg, { partition: AGG_PARTITION, conf: w.aggConf, epochIr: 1n,
  rootEpoch: 2n, round: 950n, timestamp: ts + 5000n, stateHash: root.hash.data, blockHash: null, signers: 4 });
const old = [burned.token.genesis, ...burned.token.transactions].map(c => c.inclusionProof);
const fresh = old.map((p, i) => new InclusionProof(p.certificationData, p.referenceTime,
  InclusionCertificate.create(root, burned!.leaves[i][0]), uc));
const refreshed = await refreshToken(burned.token, fresh);
// Serialize/reload: this is token persistence, not chain restart evidence.
const reloaded = await Token.fromCBOR(refreshed.toCBOR());
const after = await buildReturnProof(w.bridge, reloaded);
assert.deepEqual(projectToken(reloaded), projectToken(burned.token));
assert.deepEqual(reloaded.genesis.justification, burned.token.genesis.justification);
assert.deepEqual(after.verified.outcome.nullifier, before.verified.outcome.nullifier);
assert.notDeepEqual(after.encoded, before.encoded);
add('same-base-refresh-reload', 2n, projectToken(reloaded), after.verified.outcome);
after.verified.outcome.leaves.forEach((l, i) => paths.push({
  name: `refresh/${i}`, sid: toHex(l.sid), txHash: toHex(l.txHash), t: l.referenceTime.toString(), value: toHex(l.value),
  root: toHex(root.hash.data), certificate: toHex(fresh[i].inclusionCertificate.encode()), proof: toHex(fresh[i].toCBOR()),
}));
// Isolated strict unlock mutation, re-constructed with otherwise consistent CD/hash/path.
const bad = await buildToken(w, s, [txStep(2, 7, t + 10n), burnStep(t + 20n)], t, ts,
  { unlock: [[1, x => Uint8Array.of(...x.slice(0, 64), x[64] ^ 1)]] });
const falseResult = new Uint8Array(448);
falseResult.set(new TextEncoder().encode('UNICITY_TOKEN_SEMANTICS'));
falseResult.set(word(96n), 64);
falseResult.set(word(320n), 384);
cases.push({ name: 'flipped-unlock-parity', request: toHex(request(2n, projectToken(bad.token))), expected: toHex(falseResult) });
writeFileSync(process.argv[2], JSON.stringify({ kind: 'synthetic-component-join', trustDocument: toHex(w.agg.doc),
  cfg: toHex(cfgBytes(w.dep.cfg)), cases, paths, tokenSha256: toHex(H(burned.bytes)), envelopeSha256: toHex(H(after.encoded)) }, null, 2) + '\n');
console.log(`constructed ${cases.length} B2 requests and ${paths.length} SDK3 leaf paths; refresh preserves J/M/T/CD/t/nullifier`);
