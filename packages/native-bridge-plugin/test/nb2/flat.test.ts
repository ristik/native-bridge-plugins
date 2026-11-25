import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { test } from 'node:test';
import { concat } from '../../src/bytes.js';
import { decodeConfig, domainOf, PRODUCTION_PARAMS } from '../../src/nb2/config.js';
import { TrustInput } from '../../src/nb2/trust.js';
import { decodeToken, encodeToken, encodeMint, encodeTransfer, encodeCertification, lineageOf, stateId, tokenIdOf, valueData } from '../../src/nb2/token.js';
import { decodeSplitJustification, decodeSumProof, encodeSplitJustification, encodeSumProof, parentLink, splitOutputCommitment, SumTree } from '../../src/nb2/split.js';
import { mintRequest } from '../../src/nb2/tokenops.js';
import { ascii, u16, u64, u256 } from '../../src/nb2/cbor.js';
import { HE, HU } from '../../src/nb2/crypto.js';
import { verdictAbi, verifyHeld, verifyReturn, verifySplit } from '../../src/nb2/verify.js';

const vectors = new URL('../../../../protocol/vectors/nb2-continuation-v1.1/', import.meta.url);
const read = (name: string): Uint8Array => Uint8Array.from(readFileSync(new URL(name, vectors)));
const gamma = read('gamma.bin');
const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
const domain = domainOf(gamma);
const scenarios = ['root', 'transfers', 'one-split', 'depth-20', 'held-sibling-0', 'held-sibling-1', 'held-sibling-2', 'parent-over-32-pages', 'transfers-600',
  'shared-claim', 'alternate-certificate', 'capped-root', 'combined-large-receipt-and-paths'];

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
    const trust = (await TrustInput.fromBundle(read(path + 'utb.cbor'), cfg.rootGenesis));
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
    if (expected.length === 0) {
      const held = await verifyHeld(cfg, domain, trust, part);
      assert.deepEqual(concat(held.owner.params, held.state, held.tokenId, u256(held.amount)), read(path + 'holding.bin'));
    } else {
      assert.deepEqual(verdictAbi(await verifyReturn(gamma, evidence, trust, PRODUCTION_PARAMS)), expected);
    }
  });
}

test('published alternate certificate preserves the shared claim return', () => {
  const original = 'transcripts/shared-claim/';
  const alternate = 'transcripts/alternate-certificate/';
  assert.notDeepEqual(pageRoot(read(original + 'evidence.bin')), pageRoot(read(alternate + 'evidence.bin')));
  assert.deepEqual(read(original + 'verdict.bin'), read(alternate + 'verdict.bin'));
});

test('published malformed lineages are refused', async () => {
  const trust = (await TrustInput.fromBundle(read('transcripts/root/utb.cbor'), cfg.rootGenesis));
  const cases = {
    'continuing-transfer-data': 'TransferData', 'expired-transfer': 'DeadlineExpired',
    'recursive-reason': 'InputTooLarge', 'repeated-mint-sid': 'RepeatedSID',
    'wrong-amount': 'SplitProof', 'wrong-deadline': 'SplitProof', 'wrong-link': 'SplitJustif',
    'wrong-root-amount': 'MintData', 'wrong-root-owner': 'MintOwner', 'wrong-root-secret': 'SecretOpening', 'wrong-sum': 'SplitSum',
  };
  for (const [name, rule] of Object.entries(cases)) {
    const path = `transcripts/refusals/${name}/`;
    assert.equal(new TextDecoder().decode(read(path + 'stage.txt')).trim(), 'BadStep');
    await assert.rejects(verifyReturn(gamma, read(path + 'evidence.bin'), trust, PRODUCTION_PARAMS), { rule }, name);
  }
});

test('held siblings require their own allocation and a verified parent spend', async () => {
  const dir = 'transcripts/held-sibling-0/';
  const trust = (await TrustInput.fromBundle(read(dir + 'utb.cbor'), cfg.rootGenesis));
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

test('the B1 seal signature ceiling applies to both certificate routes', async () => {
  const { decodeUc, ucCheck, verifyEvmUc } = await import('../../src/nb2/trust.js');
  const { makeRoot, makeConfig, makeUc } = await import('./world.js');
  const root = await makeRoot(17);
  const c = makeConfig(root);
  for (const partition of [c.evmPartition, c.aggregatorPartition]) {
    const check = async (n: number) => {
      const uc = await makeUc({ ...root, signers: root.signers.slice(0, n) }, partition, new Uint8Array(32).fill(1),
        new Uint8Array(32).fill(2), 1_700_000_000n);
      if (partition === c.evmPartition) await verifyEvmUc(root.trust, uc, c);
      else await ucCheck(root.trust, decodeUc(uc), partition, c.evmShard);
    };
    await check(16);
    await assert.rejects(check(17), { rule: partition === c.evmPartition ? 'DepositUC' : 'UnsupportedCertificateEncoding' });
  }
});

test('declared receipt and allocation counts refuse before visiting children', async () => {
  const { cArr, cBytes, cTag, cUint, head, MAJ_ARRAY } = await import('../../src/nb2/cbor.js');
  const { decodeDepositProof, decodeReceiptBacking } = await import('../../src/nb2/deposit.js');
  const { TAG } = await import('../../src/nb2/config.js');
  const receipt = (nodes: Uint8Array) => cArr(cUint(1), cBytes(new Uint8Array()), cBytes(new Uint8Array()), cUint(0), cUint(0), nodes);
  const reason = (proof: Uint8Array) => cTag(TAG.receiptBacking, cArr(cUint(1), cBytes(domain), cUint(1), cBytes(domain), proof));
  const nodes = Array.from({ length: 66 }, () => cBytes(Uint8Array.of(1)));
  for (const encoded of [head(MAJ_ARRAY, 66), cArr(...nodes)]) {
    assert.throws(() => decodeDepositProof(receipt(encoded)), { rule: 'InputTooLarge' });
    assert.throws(() => decodeReceiptBacking(reason(receipt(encoded))), { rule: 'InputTooLarge' });
  }
  assert.equal(decodeDepositProof(receipt(cArr(...nodes.slice(1)))).nodes.length, 65);
  assert.equal(decodeReceiptBacking(reason(receipt(cArr(...nodes.slice(1))))).proof.nodes.length, 65);
  assert.throws(() => decodeDepositProof(receipt(head(MAJ_ARRAY, 65))), { rule: 'Truncated' });
  const steps = Array.from({ length: 256 }, (_, i) => ({ depth: 255 - i, hash: domain, sum: 1n }));
  assert.equal(decodeSumProof(encodeSumProof(steps)).length, 256);
  assert.throws(() => decodeSumProof(head(MAJ_ARRAY, 256)), { rule: 'Truncated' });
  assert.throws(() => decodeSumProof(head(MAJ_ARRAY, 257)), { rule: 'SplitProofShape' });
  assert.throws(() => decodeSumProof(encodeSumProof([...steps, steps[0]])), { rule: 'SplitProofShape' });
});

test('split retries the exact request after an unusable parent proof and restart', async () => {
  const { NativeBridgeV2 } = await import('../../src/nb2/bridge.js');
  const { array, cArr, cTag, cUint, raw, scanNative, tagContent } = await import('../../src/nb2/cbor.js');
  const { TAG } = await import('../../src/nb2/config.js');
  const { localOwner } = await import('../../src/nb2/tokenops.js');
  const { setup, key, evmAccount } = await import('./world.js');
  const w = await setup();
  const opts = w.options('split retry');
  const bridge = await NativeBridgeV2.open(opts);
  const owner = localOwner(key('split retry owner'));
  const payer = evmAccount(w.chain, 'split retry payer');
  const plan = await bridge.planDeposit(3n, owner.publicKey);
  await bridge.submitDeposit(plan, payer);
  await bridge.collectDepositProof(plan.intent);
  const root = await bridge.mint(plan.intent);
  const splitId = key('retry split ID');
  const outputs = [{ ownerKey: owner.publicKey, amount: 3n }];
  let signatureCount = 0;
  const signer = { publicKey: owner.publicKey, signUnlock: async (digest: Uint8Array) => {
    signatureCount++;
    return owner.signUnlock(digest);
  } };
  let request: Uint8Array | undefined;
  const broken = await NativeBridgeV2.open({ ...opts, aggregator: { certify: async (cd) => {
    request = cd.slice();
    const proof = await w.agg.certify(cd);
    const items = array(tagContent(scanNative(proof), TAG.inclusion), 5);
    return cTag(TAG.inclusion, cArr(raw(proof, items[0]), raw(proof, items[1]), cUint(items[2].arg + 1n), raw(proof, items[3]), raw(proof, items[4])));
  } } });
  await assert.rejects(broken.split(root, signer, outputs, splitId), { rule: 'InclusionProof' });
  const pending = await bridge.journal.splitForUpdate(`0x${Buffer.from(splitId).toString('hex')}`);
  assert.equal(pending?.status, 'burn-requested');
  assert.equal(pending?.burned, undefined);

  let replayed: Uint8Array | undefined;
  const resumed = await NativeBridgeV2.open({ ...opts, aggregator: { certify: async (cd) => {
    replayed ??= cd.slice();
    return w.agg.certify(cd);
  } } });
  const [child] = await resumed.split(root, signer, outputs, splitId);
  assert.deepEqual(replayed, request);
  assert.equal(signatureCount, 1);
  assert.equal((await resumed.verifyToken(child)).amount, 3n);
});

test('transfer, split and return planning use the caller bytes captured at entry', async () => {
  const { NativeBridgeV2 } = await import('../../src/nb2/bridge.js');
  const { localOwner } = await import('../../src/nb2/tokenops.js');
  const { setup, key, evmAccount } = await import('./world.js');
  const w = await setup();
  const bridge = await NativeBridgeV2.open(w.options('snapshot'));
  const alice = localOwner(key('snapshot alice'));
  const bob = localOwner(key('snapshot bob'));
  const payer = evmAccount(w.chain, 'snapshot payer');
  const intent = await bridge.planDeposit(3n, alice.publicKey);
  await bridge.submitDeposit(intent, payer);
  await bridge.collectDepositProof(intent.intent);
  const root = await bridge.mint(intent.intent);

  const to = bob.publicKey.slice();
  const source = root.slice();
  const transferring = bridge.transfer(source, alice, to);
  source.fill(0);
  to.fill(0);
  const transferred = await transferring;
  assert.deepEqual((await bridge.verifyToken(transferred)).owner, bob.publicKey);

  const splitSource = transferred.slice();
  const output = { ownerKey: alice.publicKey.slice(), amount: 3n };
  const splitting = bridge.split(splitSource, bob, [output]);
  splitSource.fill(0);
  output.ownerKey.fill(0);
  output.amount = 1n;
  const [child] = await splitting;
  assert.deepEqual((await bridge.verifyToken(child)).owner, alice.publicKey);

  const returnSource = child.slice();
  const recipient = payer.address.slice();
  const planning = bridge.planReturn(returnSource, recipient, payer.address);
  returnSource.fill(0);
  recipient.fill(0);
  const returned = await planning;
  assert.deepEqual(returned.recipient, payer.address);
  assert.deepEqual(returned.returnId, HU(child));
  const { burned } = await bridge.burn(returned.returnId, alice);
  assert.equal(decodeToken(burned).ancestors.length, 1);
});

test('the held tip is open and a successor closes it exclusively on both certificate routes', async () => {
  const { makeRoot, makeUc, nextEpoch } = await import('../rootfixture.js');
  const { makeConfig } = await import('./world.js');
  const { ucCheck, verifyEvmUc } = await import('../../src/nb2/trust.js');
  const old = await makeRoot(1, 4, 10);
  const current = await nextEpoch(old, 100n, 4, 30);
  const c = makeConfig(old);
  const lagging = old.trust;
  const fresh = current.trust;
  for (const partition of [c.evmPartition, c.aggregatorPartition]) {
    for (const round of [99n, 100n]) {
      const uc = await makeUc(old, {
        partition, conf: new Uint8Array(32), rootEpoch: 1n, epochIr: 1n, round,
        timestamp: 1_700_000_000n, stateHash: new Uint8Array(32).fill(1), blockHash: new Uint8Array(32).fill(2), signers: 4,
      });
      const isEvm = partition === c.evmPartition;
      const check = (t: TrustInput) => isEvm ? verifyEvmUc(t, uc.toCBOR(), c) : ucCheck(t, uc, partition, c.evmShard);
      await check(lagging);
      if (round === 99n) await check(fresh);
      else await assert.rejects(check(fresh), { rule: isEvm ? 'DepositUC' : 'SealEpoch' });
    }
  }
});

test('standalone EVM and receipt verification require the configured genesis', async () => {
  const { decodeReceiptBacking, verifyReceiptLog } = await import('../../src/nb2/deposit.js');
  const { verifyEvmUc } = await import('../../src/nb2/trust.js');
  const evidence = decodeToken(read('transcripts/root/evidence.bin'));
  const { proof } = decodeReceiptBacking(evidence.mint.justification!);
  const trust = (await TrustInput.fromBundle(read('transcripts/root/utb.cbor'), cfg.rootGenesis));
  await verifyEvmUc(trust, proof.uc, cfg);
  await verifyReceiptLog(cfg, trust, proof);
  const otherGenesis = { ...cfg, rootGenesis: new Uint8Array(32) };
  await assert.rejects(verifyEvmUc(trust, proof.uc, otherGenesis), { reason: 'TrustInput' });
  await assert.rejects(verifyReceiptLog(otherGenesis, trust, proof), { reason: 'TrustInput' });
});

test('burn and redeem submission retain the same return ID through lock and signer waits', async () => {
  const { NativeBridgeV2 } = await import('../../src/nb2/bridge.js');
  const { localOwner } = await import('../../src/nb2/tokenops.js');
  const { unhex, hex } = await import('../../src/nb2/journal.js');
  const { setup, key, evmAccount } = await import('./world.js');
  const w = await setup();
  const bridge = await NativeBridgeV2.open(w.options('return ID'));
  const owner = localOwner(key('return ID owner'));
  const payer = evmAccount(w.chain, 'return ID payer');
  const mint = async () => {
    const intent = await bridge.planDeposit(3n, owner.publicKey);
    await bridge.submitDeposit(intent, payer);
    await bridge.collectDepositProof(intent.intent);
    return bridge.mint(intent.intent);
  };
  const a = await bridge.planReturn(await mint(), payer.address, payer.address);
  const b = await bridge.planReturn(await mint(), payer.address, payer.address);
  const id = a.returnId.slice();
  const burning = bridge.burn(id, owner);
  id.set(b.returnId);
  const first = await burning;
  assert.deepEqual(await bridge.burn(a.returnId, owner), first);
  assert.equal((await bridge.journal.retForUpdate(hex(b.returnId)))!.status, 'planned');

  await bridge.burn(b.returnId, owner);
  const sendingId = a.returnId.slice();
  const submitting = bridge.submitRedeem(sendingId, {
    address: payer.address,
    signTransaction: (tx) => {
      sendingId.set(b.returnId);
      return payer.signTransaction(tx);
    },
  });
  assert.equal((await submitting).state, 'paid');
  const firstRecord = (await bridge.journal.retForUpdate(hex(a.returnId)))!;
  assert.equal(firstRecord.sends.length, 1);
  assert.deepEqual(unhex(firstRecord.eta!), first.eta);
  assert.equal((await bridge.journal.retForUpdate(hex(b.returnId)))!.sends.length, 0);
});

test('wallet intervals agree with the shared B1 imported-tip cases', async () => {
  const { makeRoot, makeUc, nextEpoch } = await import('../rootfixture.js');
  const { makeConfig } = await import('./world.js');
  const { ucCheck, verifyEvmUc } = await import('../../src/nb2/trust.js');
  const fixture = JSON.parse(String(readFileSync(new URL('../../../../protocol/vectors/b1-wallet-tip.json', import.meta.url)))) as {
    cases: { id: string; tip: number; epoch: number; round: number; accept: boolean }[];
  };
  const roots = [await makeRoot(0, 4, 10)];
  for (let epoch = 1; epoch <= 8; epoch++) roots.push(await nextEpoch(roots[epoch - 1], BigInt(epoch * 1000), 4, 10 + epoch * 5));
  const c = makeConfig(roots[0]);
  for (const { id, tip, epoch, round, accept } of fixture.cases) {
    for (const partition of [c.evmPartition, c.aggregatorPartition]) {
      const uc = await makeUc(roots[epoch], { partition, conf: new Uint8Array(32), rootEpoch: BigInt(epoch), epochIr: 1n,
        round: BigInt(round), timestamp: 1_700_000_000n, stateHash: new Uint8Array(32).fill(1), blockHash: new Uint8Array(32).fill(2), signers: 3 });
      const trust = roots[tip].trust;
      const outcome = partition === c.evmPartition ? verifyEvmUc(trust, uc.toCBOR(), c) : ucCheck(trust, uc, partition, c.evmShard);
      if (accept) await outcome;
      else await assert.rejects(outcome, { rule: epoch > tip ? 'NoEntryForEpoch' : partition === c.evmPartition ? 'DepositUC' : 'SealEpoch' }, id);
    }
  }
});
