import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { test } from 'node:test';
import { decodeConfig, domainOf, PRODUCTION_PARAMS } from '../../src/nb2/config.js';
import { TrustInput } from '../../src/nb2/trust.js';
import { decodeToken, encodeToken, encodeMint, encodeTransfer, encodeCertification, lineageOf, stateId, tokenIdOf, valueData } from '../../src/nb2/token.js';
import { decodeSplitJustification, decodeSumProof, encodeSplitJustification, encodeSumProof, parentLink, splitOutputCommitment, SumTree } from '../../src/nb2/split.js';
import { mintRequest } from '../../src/nb2/tokenops.js';
import { ascii, u16, u64 } from '../../src/nb2/cbor.js';
import { HE, HU } from '../../src/nb2/crypto.js';
import { verdictAbi, verifyHeld, verifyReturn, verifySplit } from '../../src/nb2/verify.js';

const vectors = new URL('../../../../protocol/vectors/nb2-continuation-v1.1/', import.meta.url);
const read = (name: string): Uint8Array => Uint8Array.from(readFileSync(new URL(name, vectors)));
const gamma = read('gamma.bin');
const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
const domain = domainOf(gamma);
const scenarios = ['root', 'transfers', 'one-split', 'depth-20', 'held-sibling-0', 'held-sibling-1', 'held-sibling-2', 'parent-over-32-pages', 'transfers-600'];

function pageRoot(evidence: Uint8Array): Uint8Array {
  const domainHash = (label: string, ...fields: Uint8Array[]): Uint8Array =>
    HE(HE(ascii(`UNICITY/NB2/CONT/1.1/${label}`)), ...fields);
  const count = Math.ceil(evidence.length / 4096);
  const size = 2 ** Math.ceil(Math.log2(count));
  let nodes = Array.from({ length: size }, (_, i) => {
    if (i >= count) return domainHash('PAD');
    const page = evidence.subarray(i * 4096, (i + 1) * 4096);
    return domainHash('PAGE', u64(evidence.length), u64(i), u16(page.length), page);
  });
  while (nodes.length > 1) {
    const level = nodes;
    nodes = Array.from({ length: level.length / 2 }, (_, i) => domainHash('PAGE_NODE', level[2 * i], level[2 * i + 1]));
  }
  return nodes[0];
}

test('independent protocol 10 derivations and signed child bytes', () => {
  assert.deepEqual(domain, read('domain.bin'));
  const link = parentLink(domain, ...([0x11, 0x22, 0x33, 0x44].map((n) => new Uint8Array(32).fill(n)) as [Uint8Array, Uint8Array, Uint8Array, Uint8Array]), 7n);
  assert.deepEqual(link, read('parent-link.bin'));
  const part = decodeToken(read('transcripts/one-split/evidence.bin'));
  const child = part.mint;
  const golden = { ...child, recipient: { type: 1n, params: Uint8Array.from(Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex')) },
    salt: new Uint8Array(32), deadline: null, justification: encodeSplitJustification(link) };
  golden.data = valueData(cfg.aid, 1n);
  assert.deepEqual(encodeMint(golden), read('child-mint.bin'));
  assert.deepEqual(HU(encodeMint(golden)), read('child-mint-hash.bin'));
});

for (const name of scenarios) {
  test(`T1 flat transcript ${name}`, async () => {
    const path = `transcripts/${name}/`;
    const evidence = read(path + 'evidence.bin');
    const trust = await TrustInput.fromBundle(read(path + 'utb.cbor'), cfg.rootGenesis);
    const expected = read(path + 'verdict.bin');
    const context = JSON.parse(new TextDecoder().decode(read(path + 'context.json'))) as { PageRoot: string };
    assert.equal(Buffer.from(pageRoot(evidence)).toString('hex'), context.PageRoot);
    const part = decodeToken(evidence);
    assert.deepEqual(encodeToken(part), evidence);
    for (const [i, level] of lineageOf(part).entries()) {
      assert.deepEqual(mintRequest(level.mint).tx, level.mintRaw);
      assert.deepEqual(mintRequest(level.mint).cd, encodeCertification(level.mintProof.cd));
      for (const p of [level.mintProof, ...level.proofs]) {
        const sdk = CertificationData.fromCBOR(encodeCertification(p.cd));
        assert.deepEqual((await StateId.fromCertificationData(sdk)).data, stateId(p.cd.source, p.cd.sourceHash));
      }
      assert.deepEqual(HU(level.mintRaw), level.mintProof.cd.txHash);
      if (i === 0) {
        assert.ok(level.mint.justification!.length <= 65_536);
        assert.ok(level.mintRaw.length <= 66_048);
      } else {
        assert.ok(level.mintRaw.length <= 246);
        assert.deepEqual(encodeSumProof(decodeSumProof(level.allocation)), level.allocation);
      }
      for (const [j, transfer] of level.transfers.entries()) {
        assert.deepEqual(encodeTransfer(transfer), level.transfersRaw[j]);
        assert.deepEqual(HU(level.transfersRaw[j]), level.proofs[j].cd.txHash);
      }
    }
    if (expected.length === 0) assert.ok((await verifyHeld(cfg, domain, trust, part)).amount > 0n);
    else assert.deepEqual(verdictAbi(await verifyReturn(gamma, evidence, trust, PRODUCTION_PARAMS)), expected);
  });
}

test('held siblings require their own allocation and a verified parent spend', async () => {
  const dir = 'transcripts/held-sibling-0/';
  const trust = await TrustInput.fromBundle(read(dir + 'utb.cbor'), cfg.rootGenesis);
  const part = decodeToken(read(dir + 'evidence.bin'));
  const sibling = decodeToken(read('transcripts/held-sibling-1/evidence.bin'));
  const parent = { ...part.ancestors[0], ancestors: [] };
  const split = await verifySplit(cfg, domain, trust, parent);
  const children = [part, sibling, decodeToken(read('transcripts/held-sibling-2/evidence.bin'))];
  const leaves = await Promise.all(children.map(async (child) => ({
    key: tokenIdOf(child.mint.salt, child.mint.network), data: splitOutputCommitment(split.id, child.mint),
    value: (await verifyHeld(cfg, domain, trust, child)).amount,
  })));
  const tree = SumTree.build(leaves);
  assert.deepEqual(tree.root, split.manifest);
  for (const [i, child] of children.entries()) {
    assert.deepEqual(encodeSumProof(tree.proof(leaves[i].key)!), child.allocation);
    assert.deepEqual(decodeSplitJustification(child.mint.justification!), split.link);
  }
  const wrongParent = decodeToken(read('transcripts/one-split/evidence.bin')).ancestors;
  await assert.rejects(verifyHeld(cfg, domain, trust, { ...part, ancestors: wrongParent }), { rule: 'SplitJustif' });
  assert.notDeepEqual(splitOutputCommitment(split.id, part.mint), splitOutputCommitment(split.id, { ...part.mint, deadline: 1n }));
  await assert.rejects(verifyHeld(cfg, domain, trust, { ...part, allocation: sibling.allocation }));
  await assert.rejects(verifyHeld(cfg, domain, trust, { ...part, ancestors: [] }));
  await assert.rejects(verifyHeld(cfg, domain, trust, { ...part, allocation: Uint8Array.of(0x80) }));
  for (const mint of [
    { ...part.mint, deadline: 12n },
    { ...part.mint, data: valueData(cfg.aid, 6n) },
    { ...part.mint, recipient: sibling.mint.recipient },
    { ...part.mint, justification: part.ancestors[0].mint.justification },
  ]) {
    await assert.rejects(verifyHeld(cfg, domain, trust, { ...part, mint, mintRaw: encodeMint(mint) }));
  }
  const proof = decodeSumProof(part.allocation);
  proof[0].sum++;
  await assert.rejects(verifyHeld(cfg, domain, trust, { ...part, allocation: encodeSumProof(proof) }));
});

test('framing and signed size bounds are checked independently', async () => {
  const { encodeReceiptBacking, decodeReceiptBacking } = await import('../../src/nb2/deposit.js');
  const { MAX_U64 } = await import('../../src/nb2/cbor.js');
  const root = decodeToken(read('transcripts/root/evidence.bin')).mint;
  const reason = decodeReceiptBacking(root.justification!);
  const nodes = Array.from({ length: 20 }, () => new Uint8Array(1024));
  const makeReason = (leaf: number) => encodeReceiptBacking({ ...reason, proof: { ...reason.proof, nodes: [...nodes, new Uint8Array(leaf)] } });
  const sample = 40_000;
  const leaf = sample + 65_536 - makeReason(sample).length;
  const capped = makeReason(leaf);
  assert.equal(capped.length, 65_536);
  assert.ok(mintRequest({ ...root, justification: capped }).tx.length <= 66_048);
  assert.throws(() => mintRequest({ ...root, justification: makeReason(leaf + 1) }));

  const child = decodeToken(read('transcripts/one-split/evidence.bin')).mint;
  const maxChild = mintRequest({ ...child, network: 65535, data: valueData(cfg.aid, (1n << 256n) - 1n), deadline: MAX_U64 }).tx;
  assert.ok(maxChild.length <= 246);
  const valid = read('transcripts/root/evidence.bin');
  assert.throws(() => decodeToken(valid.subarray(0, -1)));
  const version = valid.slice();
  version[5] = 0;
  assert.throws(() => decodeToken(version));
  const count = valid.slice();
  count.fill(255, 6, 14);
  assert.throws(() => decodeToken(count));
});

test('a refreshed external split proof preserves its children and return identity', async () => {
  const { UnicityCertificate } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js');
  const { UnicitySeal } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/UnicitySeal.js');
  const { NativeBridgeV2 } = await import('../../src/nb2/bridge.js');
  const { decodeUc } = await import('../../src/nb2/trust.js');
  const { localOwner } = await import('../../src/nb2/tokenops.js');
  const { setup, key, evmAccount } = await import('./world.js');
  const w = await setup();
  const bridge = await NativeBridgeV2.open(w.options('proof refresh'));
  const owner = localOwner(key('proof refresh owner'));
  const payer = evmAccount(w.chain, 'proof refresh payer');
  const intent = await bridge.planDeposit(3n, owner.publicKey);
  await bridge.submitDeposit(intent, payer);
  await bridge.collectDepositProof(intent.intent);
  const root = await bridge.mint(intent.intent);
  assert.equal(decodeToken(root).transfers.length, 0);
  const [child] = await bridge.split(root, owner, [{ ownerKey: owner.publicKey, amount: 3n }]);
  const held = decodeToken(child);
  assert.deepEqual(held.allocation, Uint8Array.of(0x80));
  assert.equal((await bridge.verifyToken(child)).amount, 3n);
  const plan = await bridge.planReturn(child, payer.address, payer.address);
  const { burned: original } = await bridge.burn(plan.returnId, owner);
  const burned = decodeToken(original);
  const parent = burned.ancestors[0];
  const proof = parent.proofs.at(-1)!;
  const uc = decodeUc(proof.uc);
  const oldSeal = uc.unicitySeal;
  const seal = await UnicitySeal.create(oldSeal.networkId, oldSeal.rootChainRoundNumber, oldSeal.epoch, oldSeal.timestamp,
    oldSeal.previousHash, oldSeal.hash, new Map(w.root.signers.slice(0, 3)));
  parent.proofs[parent.proofs.length - 1] = { ...proof, uc: new UnicityCertificate(uc.inputRecord, uc.technicalRecordHash,
    uc.shardConfigurationHash, uc.shardTreeCertificate, uc.unicityTreeCertificate, seal).toCBOR() };
  const refreshed = encodeToken(burned);
  assert.notDeepEqual(pageRoot(refreshed), pageRoot(original));
  const params = (await import('../../src/nb2/config.js')).TEST_PARAMS;
  const originalVerdict = await verifyReturn(w.chain.gamma, original, w.root.trust, params);
  assert.deepEqual(await verifyReturn(w.chain.gamma, refreshed, w.root.trust, params), originalVerdict);
  assert.deepEqual(decodeToken(refreshed).mintRaw, decodeToken(original).mintRaw);
});

test('a valid allocation root with the wrong total cannot authorize a child', async () => {
  const { NativeBridgeV2 } = await import('../../src/nb2/bridge.js');
  const { TEST_PARAMS } = await import('../../src/nb2/config.js');
  const { appendTransfer, certifyChecked, childMint, localOwner, mintRequest, splitPlan, tokenOfChild, transferRequest } = await import('../../src/nb2/tokenops.js');
  const { setup, key, evmAccount } = await import('./world.js');
  const w = await setup();
  const bridge = await NativeBridgeV2.open(w.options('split sum'));
  const owner = localOwner(key('split sum owner'));
  const payer = evmAccount(w.chain, 'split sum payer');
  const intent = await bridge.planDeposit(3n, owner.publicKey);
  await bridge.submitDeposit(intent, payer);
  await bridge.collectDepositProof(intent.intent);
  const root = await bridge.mint(intent.intent);
  const c = decodeConfig(w.chain.gamma, TEST_PARAMS);
  const d = domainOf(w.chain.gamma);
  const split = splitPlan(decodeToken(root), [{ ownerKey: owner.publicKey, amount: 2n, salt: key('child salt') }], c.ty, c.aid, key('split mask'));
  const burn = await transferRequest(root, owner, split.burn);
  const parent = appendTransfer(root, burn.tx, await certifyChecked(w.agg, burn.cd));
  const authenticated = await verifySplit(c, d, w.root.trust, decodeToken(parent));
  const child = childMint(authenticated.link, split.tree, split.children[0]);
  const req = mintRequest(child.mint);
  const token = tokenOfChild(parent, child.allocation, req.tx, await certifyChecked(w.agg, req.cd));
  await assert.rejects(bridge.verifyToken(token), { rule: 'SplitSum' });
});
