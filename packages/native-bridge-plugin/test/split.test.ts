import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { fromHex, toHex } from '../src/bytes.js';
import { makeDeployment } from '../src/deployment.js';
import { COMPOSE_OUTPUT_BYTES_V2, COMPOSE_STATUS_V2, composeInput, composeStatusNameV2, decodeComposeOutputV2 } from '../src/compose.js';
import { checkAnchors, checkPolicyBody, decodeEnvelope, planAnchors } from '../src/envelope.js';
import { computeGate, kernelRequestBytes } from '../src/gas.js';
import { NativeError } from '../src/errors.js';
import { decodePredicateBytes } from '../src/history.js';
import { composeOfflineV2, verifyLineageReturn, type LineageOutcome } from '../src/lineage.js';
import { decodeCfg, decodePolicy, H } from '../src/profile.js';
import { scanOne } from '../src/scan.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { arr, u } from '../src/profile.js';
import {
  beToBigint, decodeSplitJustification, decodeSumProofItem, splitManifestBytes, splitOutputCommitment, sumLeafHash, sumNodeHash, sumProofBytes, verifySumProof,
} from '../src/split.js';

/**
 * The protocol 6 split corpus (bft-core `bridgeprofile/testdata/split-corpus`, sealed under `protocol/vectors/split`),
 * replayed by an implementation independent of the Go oracle that generated it.
 */
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'protocol');
const load = (rel: string): any => JSON.parse(readFileSync(path.join(ROOT, rel), 'utf8'));

interface Case {
  id: string;
  op: string;
  input?: string;
  aux?: Record<string, string>;
  expected: { status: 'ok' | 'error' | 'halt'; family?: string; reason?: string; output?: string; values?: Record<string, string>; split?: any };
}
const cases = (family: string): Case[] => load(`vectors/split/${family}/cases.json`).cases as Case[];

/** The verdict of `run`: ok, or the profile failure it raised. */
async function verdict(run: () => unknown): Promise<{ status: 'ok' | 'error'; family?: string; reason?: string }> {
  try {
    await run();
    return { status: 'ok' };
  } catch (e) {
    if (!(e instanceof NativeError)) throw e;
    return { status: 'error', family: e.family, reason: e.reason };
  }
}
const want = (c: Case): { status: 'ok' | 'error'; family?: string; reason?: string } =>
  c.expected.status === 'ok' ? { status: 'ok' } : { status: 'error', family: c.expected.family, reason: c.expected.reason };

const devDeployment = () => {
  const f = load('vectors/config/fixtures.json');
  const fx = f.fixtures.dev;
  return makeDeployment(decodeCfg(fromHex(fx.cfg)!), fromHex(f.pins.dev.vaultCodeHash)!, new Uint8Array(32), { fields: 20 }, decodePolicy(fromHex(fx.policyBody)!));
};

test('split corpus: every file this suite reads is in the sealed manifest (SHA256SUMS under MANIFEST.sha256), unedited', () => {
  const sums = readFileSync(path.join(ROOT, 'vectors/SHA256SUMS'), 'utf8');
  const listed = [...sums.matchAll(/^([0-9a-f]{64})  (split\/\S+)$/gm)].map((m) => [m[2], m[1]]);
  assert.equal(listed.length, 6);
  for (const [file, digest] of listed) assert.equal(toHex(H(readFileSync(path.join(ROOT, 'vectors', file)))), digest, file);
  assert.equal(toHex(H(new TextEncoder().encode(sums))), readFileSync(path.join(ROOT, 'vectors/MANIFEST.sha256'), 'utf8').trim());
  assert.equal(load('vectors/split/config/fixtures.json').nativeBridgeProtoVersion, 6);
  for (const fam of ['sum-tree', 'lineage', 'native']) assert.equal(load(`vectors/split/${fam}/cases.json`).format, 'native-bridge-split-vectors/1', fam);
  // the split corpus uses the protocol 5 corpus's dev fixture
  assert.equal(toHex(H(fromHex(load('vectors/config/fixtures.json').fixtures.dev.cfg)!)), '67c007348bc786d6a4d31f1c55fa35ef5d42e37eec63a7b91e32594d190a907a');
});

test('sum-tree family: every allocation proof, manifest and output commitment is the oracle\'s', async () => {
  const all = cases('sum-tree');
  let trees = 0;
  let proofs = 0;
  let commitments = 0;
  for (const c of all) {
    const aux = c.aux ?? {};
    if (c.op === 'sum-tree') {
      // the builder is the SDK's; the plug-ins verify: every leaf's recorded proof reconstructs the root and the total
      if (c.expected.status !== 'ok') continue;
      const v = c.expected.values!;
      const root = fromHex(v.root)!;
      assert.equal(toHex(splitManifestBytes(root)), v.manifest, c.id);
      assert.equal(toHex(H(splitManifestBytes(root))), v.reasonHash, c.id);
      aux.leaves.split(';').forEach((leaf, i) => {
        const [key, data, amount] = leaf.split(':');
        const p = decodeSumProofItem(scanOne(fromHex(v[`proof.${i}`])!));
        assert.equal(toHex(sumProofBytes(p)), v[`proof.${i}`], `${c.id}: proof ${i} re-encodes exactly`);
        assert.equal(verifySumProof(p, fromHex(key)!, fromHex(data)!, BigInt(amount), root), BigInt(v.total), `${c.id}: proof ${i}`);
      });
      trees++;
    } else if (c.op === 'sum-proof') {
      let got: { status: 'ok' | 'error'; family?: string; reason?: string; values?: Record<string, string> } = { status: 'ok' };
      try {
        const p = decodeSumProofItem(scanOne(fromHex(c.input!)!));
        const sum = verifySumProof(p, fromHex(aux.key)!, fromHex(aux.data)!, BigInt(aux.amount), fromHex(aux.root)!);
        if (sum === null) throw new NativeError('ErrSplitProof');
        got = { status: 'ok', values: { steps: String(p.length), sum: String(sum) } };
      } catch (e) {
        if (!(e instanceof NativeError)) throw e;
        got = { status: 'error', family: e.family, reason: e.reason };
      }
      assert.deepEqual(got, c.expected.status === 'ok' ? { status: 'ok', values: c.expected.values } : want(c), c.id);
      proofs++;
    } else if (c.op === 'split-commitment') {
      const d = splitOutputCommitment(
        fromHex(aux.source)!, Number(aux.network), decodePredicateBytes(fromHex(aux.recipient)!), fromHex(aux.salt)!, fromHex(aux.childId)!,
        fromHex(aux.type)!, fromHex(aux.data)!,
      );
      assert.equal(toHex(d), c.expected.values!.commitment, c.id);
      commitments++;
    } else {
      assert.fail(`${c.id}: unknown op ${c.op}`);
    }
  }
  assert.ok(trees >= 5 && proofs >= 10 && commitments >= 5, `${trees} ${proofs} ${commitments}`);
});

/** The expected relation result of a lineage case in the plug-in's field names and encodings. */
function resultOf(r: LineageOutcome): Record<string, unknown> {
  return {
    cfg: toHex(r.cfg), nonce: String(r.nonce), amount: toHex(r.amount), tokenId: toHex(r.tokenId), salt: toHex(r.salt),
    firstPredicateHash: toHex(r.firstPredicateHash), lockDigest: toHex(r.lockDigest), releaseTo: toHex(r.releaseTo), nullifier: toHex(r.nullifier),
    partTokenId: toHex(r.partTokenId), partAmount: toHex(r.partAmount), depth: String(r.depth),
    levels: r.levels.map((l) => ({ tokenId: toHex(l.tokenId), amount: toHex(l.amount), leaves: l.leaves })),
    leaves: r.leaves.map((l) => ({ sid: toHex(l.sid), txHash: toHex(l.txHash), referenceTime: String(l.referenceTime), leafValue: toHex(l.value) })),
  };
}

/** The reasons only B1 decides (certificate signatures and quorum, RSMT membership): the plug-ins' composition steps all pass. */
const B1_ONLY = new Set(['ErrAnchorAuth', 'ErrLeafProof']);

test('lineage family: the relation, the anchor plan and the openings give every case the oracle\'s verdict and result', async () => {
  const dep = devDeployment();
  const all = cases('lineage');
  assert.ok(all.length >= 39, String(all.length));
  let ok = 0;
  for (const c of all) {
    let res: LineageOutcome | undefined;
    const got = await verdict(async () => {
      const env = decodeEnvelope(fromHex(c.input!)!);
      const pol = checkPolicyBody(dep.cfg, env);
      res = await verifyLineageReturn(dep, env.history);
      const plan = planAnchors(pol, env, res.leaves.map((l) => l.sid));
      checkAnchors(env, plan, res.leaves.map((l) => l.referenceTime));
    });
    if (c.expected.status === 'error' && B1_ONLY.has(c.expected.reason!)) {
      assert.deepEqual(got, { status: 'ok' }, `${c.id}: every step before B1 passes`);
      continue;
    }
    assert.deepEqual(got, want(c), c.id);
    if (c.expected.status !== 'ok') continue;
    const r = resultOf(res!);
    const s = c.expected.split;
    for (const k of ['cfg', 'nonce', 'tokenId', 'salt', 'firstPredicateHash', 'lockDigest', 'releaseTo', 'nullifier', 'partTokenId', 'depth']) {
      assert.equal(r[k], s[k], `${c.id}: ${k}`);
    }
    // amounts: the corpus writes minimal big-endian hex
    assert.equal(r.amount, s.amount, `${c.id}: amount`);
    assert.equal(r.partAmount, s.partAmount, `${c.id}: partAmount`);
    assert.deepEqual(r.levels, s.levels, `${c.id}: levels`);
    assert.deepEqual((r.leaves as any[]).map((l) => ({ ...l })), s.leaves.map((l: any) => ({ sid: l.sid, txHash: l.txHash, referenceTime: l.referenceTime, leafValue: l.leafValue })), `${c.id}: leaves in root-to-part order`);
    ok++;
  }
  assert.ok(ok >= 11, String(ok));
});

test('compose status table V2: config/compose-status-v2.json is the plug-ins\' append-only table, code 0 ok', () => {
  const table = load('vectors/split/config/compose-status-v2.json') as { code: number; name: string }[];
  assert.deepEqual(table, [{ code: 0, name: 'ok' }, ...COMPOSE_STATUS_V2.map((name, i) => ({ code: i + 1, name }))]);
});

/** abi.encode(uint8 op, bytes cfg, bytes envelope) read back. */
function readComposeInput(b: Uint8Array): { op: number; cfg: Uint8Array; envelope: Uint8Array } {
  const w = (o: number): number => Number(BigInt('0x' + toHex(b.subarray(o, o + 32))));
  const field = (off: number): Uint8Array => b.slice(off + 32, off + 32 + w(off));
  return { op: w(0), cfg: field(w(32)), envelope: field(w(64)) };
}

test('native family: every BRIDGE_COMPOSE_V2 output is the plug-ins\' relation result, and every successful call\'s gas their estimate', async () => {
  const dep = devDeployment();
  const all = cases('native');
  let priced = 0;
  let refused = 0;
  for (const c of all) {
    const input = fromHex(c.input!)!;
    if (c.expected.status === 'halt') {
      assert.ok(['abi', 'out-of-gas'].includes(c.expected.values!.halt), c.id);
      continue;
    }
    const v = c.expected.values!;
    const out = fromHex(c.expected.output!)!;
    assert.equal(out.length, COMPOSE_OUTPUT_BYTES_V2, c.id);
    const decoded = decodeComposeOutputV2(out);
    assert.ok(decoded, c.id);
    assert.equal(String(decoded.status), v.status, c.id);
    assert.equal(composeStatusNameV2(decoded.status), v.status === '0' ? 'ok' : v.statusName, c.id);
    const { op, cfg, envelope } = readComposeInput(input);
    assert.deepEqual(composeInput(op, cfg, envelope), input, `${c.id}: the canonical three-field input`);
    const env = decodeEnvelope(envelope);
    let res: LineageOutcome | undefined;
    const got = await verdict(async () => {
      res = await composeOfflineV2(dep, cfg, envelope);
    });
    if (v.status !== '0') {
      if (!B1_ONLY.has(v.statusName)) assert.deepEqual(got, { status: 'error', family: got.family, reason: v.statusName }, c.id);
      refused++;
      continue;
    }
    assert.deepEqual(got, { status: 'ok' }, c.id);
    const r = decoded.result!;
    assert.equal(toHex(r.lockDigest), toHex(res!.lockDigest), c.id);
    assert.equal(toHex(r.nullifier), toHex(res!.nullifier), c.id);
    assert.equal(toHex(r.partTokenId), toHex(res!.partTokenId), c.id);
    assert.equal(toHex(r.partAmount), toHex(res!.partAmount), c.id);
    assert.equal(toHex(r.amount), toHex(res!.amount), c.id);
    assert.equal(r.splitDepth, BigInt(res!.depth), c.id);
    assert.equal(r.leafCount, BigInt(res!.leaves.length), c.id);
    // the estimate: the protocol 5 schedule over the whole lineage plus the walk's split terms
    const g = computeGate(cfg, envelope.length, kernelRequestBytes(cfg.length, env.history.length), env);
    assert.equal(g.compose.b, input.length, `${c.id}: B`);
    assert.equal(String(g.native + res!.splitGas), v.gas, `${c.id}: gas`);
    priced++;
  }
  assert.ok(priced >= 10 && refused >= 10, `${priced} ${refused}`);
});

/**
 * Mutations whose status differs only in the anchor phase of protocol 5: the native composition scans the anchors and lets B1
 * authenticate them before it opens their input records; the plug-ins' offline steps open them first. No lineage status differs.
 */
/** case: [the oracle's status, the plug-ins' refusal]. */
const ANCHOR_ORDER: Record<string, [string, string]> = {
  'mutation-029': ['ErrPathBitmap', 'ErrIROpening'], 'mutation-198': ['ErrAnchorAuth', 'ErrShape'], 'mutation-240': ['ErrIRShape', 'ErrIROpening'],
  'mutation-269': ['ErrAnchorAuth', 'ErrIROpening'], 'mutation-297': ['ErrAnchorAuth', 'ErrIROpening'],
};

test('mutation family: 400 seeded patches of a depth-2 input give the oracle\'s status (and gas) wherever the plug-ins decide', async () => {
  const dep = devDeployment();
  const m = load('vectors/split/mutation/cases.json');
  assert.equal(m.format, 'native-bridge-split-mutations/1');
  const names = (load('vectors/split/config/compose-status-v2.json') as { code: number; name: string }[]).map((x) => x.name);
  const base = fromHex(m.base)!;
  const tally = { halt: 0, same: 0, priced: 0, b1: 0, anchorOrder: 0 };
  for (const c of m.cases as { id: string; patch: { o: number; x: number }[]; expected: { status: string; values: Record<string, string> } }[]) {
    if (c.expected.status === 'halt') {
      tally.halt++;
      continue;
    }
    const input = Uint8Array.from(base);
    for (const p of c.patch) input[p.o] ^= p.x;
    const name = names[Number(c.expected.values.status)];
    const { cfg, envelope } = readComposeInput(input);
    let res: (LineageOutcome & { gas: number }) | undefined;
    const got = await verdict(async () => {
      res = await composeOfflineV2(dep, cfg, envelope);
    });
    const gotName = got.status === 'ok' ? 'ok' : got.reason;
    if (c.id in ANCHOR_ORDER) {
      assert.equal(name, ANCHOR_ORDER[c.id][0], `${c.id}: the allow-list entry still applies`);
      assert.equal(gotName, ANCHOR_ORDER[c.id][1], `${c.id}: the plug-ins refuse it, for the listed reason`);
      tally.anchorOrder++;
    } else if (B1_ONLY.has(name) && gotName === 'ok') {
      tally.b1++;
    } else {
      assert.equal(gotName, name, `${c.id} ${JSON.stringify(c.patch)}`);
      if (name === 'ok') {
        assert.equal(String(res!.gas), c.expected.values.gas, `${c.id}: gas`);
        tally.priced++;
      } else tally.same++;
    }
  }
  assert.deepEqual(tally, { halt: 7, same: 372, priced: 10, b1: 6, anchorOrder: 5 });
});

test('a split justification carries exactly one allocation proof (one asset): none or two is ErrSplitProofCount', async () => {
  const token = C.encodeTag(39040n, arr()); // the count is refused before the token is decoded
  const proof = arr(arr(u(3), C.encodeByteString(new Uint8Array(32)), C.encodeByteString(Uint8Array.of(5))));
  for (const proofs of [arr(), arr(proof, proof)]) {
    assert.deepEqual(await verdict(() => decodeSplitJustification(C.encodeTag(39044n, arr(token, proofs)))), { status: 'error', family: 'invalid', reason: 'ErrSplitProofCount' });
  }
  assert.equal(decodeSplitJustification(C.encodeTag(39044n, arr(token, arr(proof)))).proof.length, 1);
});

test('verifySumProof refuses steps that are not strictly root-ward even when the caller built them and the root matches', () => {
  const key = new Uint8Array(32); // every key bit 0: the leaf is always the left child
  const data = new Uint8Array(32);
  const sib = { hash: new Uint8Array(32).fill(1), sum: 5n };
  const rootOf = (depths: number[]): Uint8Array => {
    let h = sumLeafHash(key, data, 2n)!;
    let sum = 2n;
    for (const d of depths) ({ hash: h, sum } = sumNodeHash(d, h, sum, sib.hash, sib.sum)!);
    return h;
  };
  assert.equal(verifySumProof([{ depth: 7, ...sib }, { depth: 3, ...sib }], key, data, 2n, rootOf([7, 3])), 12n);
  // the same steps leaf-ward, against the root they hash to: refused by the depth order alone
  assert.equal(verifySumProof([{ depth: 3, ...sib }, { depth: 7, ...sib }], key, data, 2n, rootOf([3, 7])), null);
  assert.equal(verifySumProof([{ depth: 3, ...sib }, { depth: 3, ...sib }], key, data, 2n, rootOf([3, 3])), null);
  for (const bad of [[{ depth: 3, ...sib }, { depth: 7, ...sib }], [{ depth: 3, ...sib }, { depth: 3, ...sib }]]) {
    assert.throws(() => decodeSumProofItem(scanOne(sumProofBytes(bad))), (e) => e instanceof NativeError && e.reason === 'ErrSplitProofShape');
  }
});
