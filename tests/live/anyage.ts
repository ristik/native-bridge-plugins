/**
 * Any-age lane driver (bft-core briefs/anyage-final-lane-plan.md, steps L1a, L1b and L1c): one burned token whose ORIGINAL return proof
 * is saved once and later verified unchanged, first while its anchors' epoch is still the usable one and again after a root epoch
 * handoff has made that epoch historical, and then released exactly once. Three separate commands, never interleaved by the lane:
 *
 *   anyage.ts save    <lane-config.json> [<out-dir>]                          lock, mint, burn; save the exact proof bytes, hashes and the
 *                                                                              registry interval each anchor was made under
 *   anyage.ts verify  <lane-config.json> <saved.json> --epoch current|historical
 *                                                                              non-mutating eth_call of the saved bytes: the native
 *                                                                              CERT_BATCH_V2 verdict and the vault's whole redeem relation
 *   anyage.ts release <lane-config.json> <saved.json>                         the one vault redemption of the saved bytes, then the claim
 *
 * Nothing is refreshed: the saved envelope is the one the plug-in assembled from the proofs the aggregator returned when each transition
 * was certified, and every later command checks its sha256 before use. Protocol 4 (any-age registry, one CERT_BATCH_V2 call over the
 * anchor table): a certificate is accepted for any age while its epoch interval and the registry's usable origin admit it.
 */
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { SignaturePredicateUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicateUnlockScript.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { StateMask } from '@unicitylabs/state-transition-sdk/lib/transaction/StateMask.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';

import { batchRequest, measure } from '../../packages/native-bridge-plugin/src/certgroups.js';
import { DeploymentRegistry, makeDeployment } from '../../packages/native-bridge-plugin/src/deployment.js';
import { configHashOfPdr, encodeJustification } from '../../packages/native-bridge-plugin/src/lockproof.js';
import { buildReturnProof } from '../../packages/native-bridge-plugin/src/proof.js';
import {
  arr, bs, decodeCfg, decodePolicy, deriveSalt, deriveTokenId, H, keccak256, lockDigest, lockRecord, returnReason, shardCovers, shardDepth, u, valueEnvelope,
} from '../../packages/native-bridge-plugin/src/profile.js';
import { TrustInput } from '../../packages/native-bridge-plugin/src/trust.js';
import { NativeBridge } from '../../packages/native-bridge-plugin/src/verifier.js';
import { hex, LaneConfig, loadConfig, rpc, run, until, unhex } from './lib.js';

// ---- lane parameters -------------------------------------------------------------------------------------------------------------------
const DEPLOYER_KEY = process.env.DNB_DEPLOYER_KEY ?? '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const DNB_TOOL = process.env.DNB_TOOL ?? '/private/tmp/dnb-tool';
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const RECIPIENT_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const THIRD_PARTY_ADDR = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
const THIRD_PARTY_KEY = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a';
const PAYEE = '0x000000000000000000000000000000000000bEEF';
const REGISTRY = '0xff00000000000000000000000000000000000002';
const CERT_BATCH = '0x0000000000000000000000000000000000000100';

type Json = Record<string, unknown>;
const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const sha = (b: Uint8Array): string => hex(sha256(b));
const toJson = (v: unknown): string => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x), 2);
const word = (n: bigint): Uint8Array => unhex(n.toString(16).padStart(64, '0'));
/** ABI calldata of `redeem(bytes)` (selector 0x9945e3d3), encoded here: `cast calldata` is offline (no --rpc-url, so not c.cast) and a
 * large envelope would exceed the per-argument limit of a subprocess. */
const redeemCalldata = (envelope: Uint8Array): string => {
  const padded = new Uint8Array(Math.ceil(envelope.length / 32) * 32);
  padded.set(envelope);
  return `0x9945e3d3${hex(word(32n))}${hex(word(BigInt(envelope.length)))}${hex(padded)}`;
};

/** One lane configuration, with an optional aggregator per shard: protocol 4 names no shard table, so a leaf goes to the aggregator whose
 * shard prefix its state ID carries (`shardCovers`), and to `aggUrl` when no shard list is given. */
interface AnyAgeConfig extends LaneConfig {
  aggShards?: { shard: string; url: string }[];
}

function ctx(cfgPath: string) {
  const lane = loadConfig(cfgPath) as AnyAgeConfig;
  const eth = lane.ethUrls[0];
  const cast = (...a: string[]): string => {
    // ureth refuses an estimate or call while its bound build input belongs to another parent: retry.
    for (let i = 0; ; i++) {
      try {
        return run('cast', [...a, '--rpc-url', eth]);
      } catch (e) {
        if (i >= 8 || !String(e).includes('bound')) throw e;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500);
      }
    }
  };
  const shards = (lane.aggShards ?? []).map((s) => ({ shard: unhex(s.shard), client: new AggregatorClient(s.url) }));
  const fallback = new AggregatorClient(lane.aggUrl);
  // Several configured shards may cover one state ID (a parent and its child across a split): the deepest is the one serving it now. The route
  // is only where to ask: the anchor's shard, configuration and partition come from the UC the aggregator returns, and the verifier refuses
  // a UC whose shard does not cover the leaf.
  const aggOfData = (data: Uint8Array): AggregatorClient => shards.filter((s) => shardCovers(s.shard, data))
    .sort((x, y) => shardDepth(y.shard) - shardDepth(x.shard))[0]?.client ?? fallback;
  const aggOf = (sid: StateId): AggregatorClient => aggOfData(sid.data);
  return { lane, eth, cast, aggOf, aggOfData };
}
type Ctx = ReturnType<typeof ctx>;

/** The installed bridge: Cfg from the vault itself, trust, EVM PDR and policy from the lane's pinned documents. */
async function installedBridge(c: Ctx) {
  const cfg = decodeCfg(unhex(c.cast('call', c.lane.vault, 'cfgBytes()(bytes)')));
  const trustDoc = readFileSync(`${c.lane.dir}/trust-base.bundle.cbor`);
  const trust = await TrustInput.fromBundle(Uint8Array.from(trustDoc), Uint8Array.from(Buffer.from(readFileSync(`${c.lane.dir}/trust-base.genesis.entryid`, 'utf8').trim(), 'hex')));
  const pdr = Uint8Array.from(readFileSync(`${c.lane.dir}/evm-pdr.cbor`));
  const policy = decodePolicy(unhex(JSON.parse(readFileSync(`${c.lane.dir}/bridge-deployment.json`, 'utf8')).policyBody));
  const vaultCode = unhex(await rpc(c.eth, 'eth_getCode', [c.lane.vault, 'latest']));
  const dep = makeDeployment(cfg, keccak256(vaultCode), configHashOfPdr(pdr), { fields: 20 }, policy);
  return { cfg, dep, bridge: new NativeBridge(new DeploymentRegistry([dep]), trust) };
}

// ---- the registry (format 2), read at one block -------------------------------------------------------------------------------------------
const fixedSlot = (name: string): Uint8Array => keccak256(text(`unicity.seal-registry/${name}`));
const entrySlot = (e: bigint, f: bigint): Uint8Array => keccak256(fixedSlot('b1.entry'), word(e), word(f));

/** The usable origin, the import tip and the interval of each requested epoch, all at `block`. */
async function registryAt(c: Ctx, block: string, epochs: bigint[]): Promise<Json> {
  const at = async (slot: Uint8Array): Promise<bigint> => BigInt(await rpc(c.eth, 'eth_getStorageAt', [REGISTRY, `0x${hex(slot)}`, block]));
  const out: Json = {
    block, originReady: await at(fixedSlot('b1.originReady')), usableEpoch: await at(fixedSlot('origin.rootEpoch')),
    clockRound: await at(fixedSlot('clock.rootRound')), importedTip: await at(fixedSlot('b1.importedTipEpoch')), genesisEpoch: await at(fixedSlot('b1.genesisEpoch')),
  };
  const entries: Json = {};
  for (const e of [...new Set(epochs)]) {
    entries[e.toString()] = { present: await at(entrySlot(e, 0n)), start: await at(entrySlot(e, 4n)), end: await at(entrySlot(e, 5n)), hasEnd: await at(entrySlot(e, 6n)) };
  }
  out.entries = entries;
  return out;
}

/** Sign once, publish to every validator's pool, wait for the receipt. */
async function sendAll(c: Ctx, to: string, sig: string, args: string[], key: string, gas: string, value?: string) {
  const sender = run('cast', ['wallet', 'address', '--private-key', key]);
  const nonce = String(parseInt(await rpc(c.eth, 'eth_getTransactionCount', [sender, 'pending']), 16));
  const raw = c.cast('mktx', to, ...(sig ? [sig, ...args] : []), ...(value ? ['--value', value] : []), '--private-key', key, '--gas-limit', gas,
    '--nonce', nonce, '--chain', String(c.lane.chainId), '--legacy', '--gas-price', '2000000000');
  const txHash = `0x${hex(keccak256(unhex(raw)))}`;
  const accepted = await Promise.all(c.lane.ethUrls.map(async (url) => {
    try {
      await rpc(url, 'eth_sendRawTransaction', [raw]);
      return true;
    } catch (e) {
      return /already known|known transaction/.test(String(e));
    }
  }));
  assert.ok(accepted.some(Boolean), `no validator pool accepted ${txHash}`);
  return until(`receipt of ${txHash}`, 120_000, async () => (await rpc(c.eth, 'eth_getTransactionReceipt', [txHash])) ?? undefined) as Promise<{
    status: string; gasUsed: string; blockNumber: string; transactionHash: string;
  }>;
}

// ---- save ------------------------------------------------------------------------------------------------------------------------------
async function save(cfgPath: string, outDir?: string): Promise<void> {
  const c = ctx(cfgPath);
  const out = outDir ?? `${c.lane.dir}/anyage`;
  mkdirSync(out, { recursive: true });
  const { cfg, dep, bridge } = await installedBridge(c);
  for (const a of [RECIPIENT, THIRD_PARTY_ADDR]) await sendAll(c, a, '', [], DEPLOYER_KEY, '100000', '1000000000000000000');

  // lock, and its proof from the archived certificate of the lock block
  const owner = new SigningService(sha256(text('anyage-owner')));
  const p0 = EncodedPredicate.fromPredicate(SignaturePredicate.create(owner.publicKey)).toCBOR();
  const amountWei = 10n ** 18n;
  const amount = unhex(amountWei.toString(16).padStart(16, '0'));
  // With several aggregator shards the history must span them: the burn's StateId is fixed by the mint (its source state) and the mint's by the lock's nonce,
  // so a lock whose mint and burn fall to the same shard is abandoned (its funds stay in the vault, unredeemed) and the next lock is tried.
  const spans = (c.lane.aggShards?.length ?? 0) >= 2;
  const lockAndMint = async () => {
    const sent = JSON.parse(c.cast('send', c.lane.vault, 'lock(bytes)(uint256)', `0x${hex(p0)}`, '--value', amountWei.toString(), '--private-key', DEPLOYER_KEY,
      '--json', '--gas-limit', '2000000'));
    assert.equal(sent.status, '0x1', `lock reverted: ${JSON.stringify(sent)}`);
    const nonce = BigInt(sent.logs.find((l: { topics: string[] }) => l.topics.length === 3).topics[1]);
    const proofPath = `${out}/lockproof-${nonce}.cbor`;
    await until('the lock block to be certified and archived', 120_000, async () => {
      try {
        run(DNB_TOOL, ['lockproof', '--archive', c.lane.archive, '--block-hash', sent.blockHash, '--eth-url', c.eth, '--vault', c.lane.vault, '--nonce', nonce.toString(),
          '--full-shard-conf', `${c.lane.dir}/evm-full-shard-conf.json`, '--trust-bundle', `${c.lane.dir}/trust-base.bundle.cbor`, '--cfg', `0x${hex(dep.cfgHash)}`, '--out', proofPath]);
        return true;
      } catch {
        return false;
      }
    });
    const lockProof = Uint8Array.from(readFileSync(proofPath));
    const salt = deriveSalt(dep.cfgHash, nonce);
    const tokenId = deriveTokenId(salt, cfg.network);
    assert.equal(hex(unhex(c.cast('call', c.lane.vault, 'lockDigest(uint256)(bytes32)', nonce.toString()))),
      hex(lockDigest(dep.cfgHash, nonce, lockRecord(cfg.zeroAddress, cfg.ty, cfg.aid, amount, tokenId, sha256(p0)))), 'the vault stored the derived lock digest');

    // mint and burn, each certified by the live aggregator; the proofs are the ones returned at certification, never refreshed
    const mint = await MintTransaction.create(NetworkId.fromId(cfg.network), SignaturePredicate.create(owner.publicKey), {
      data: valueEnvelope(cfg.aid, amount), expiresAt: null, justification: encodeJustification(cfg.chainId, cfg.vault, cfg.zeroAddress, nonce, lockProof),
      salt: TokenSalt.fromBytes(salt), tokenType: new TokenType(cfg.ty),
    });
    const mcd = await CertificationData.fromMintTransaction(mint);
    const msid = await StateId.fromCertificationData(mcd);
    return { nonce, lockProof, tokenId, mint, mcd, msid };
  };
  let first = await lockAndMint();
  for (let attempt = 1; spans; attempt++) {
    const burnSid = H(arr(first.mint.recipient.toCBOR(), bs((await first.mint.calculateStateHash()).data)));
    if (c.aggOf(first.msid) !== c.aggOfData(burnSid)) break;
    assert.ok(attempt < 16, 'no lock gave a mint and a burn on different aggregator shards in 16 attempts');
    first = await lockAndMint();
  }
  const { nonce, lockProof, tokenId, mint, mcd, msid } = first;
  await c.aggOf(msid).submitCertificationRequest(mcd);
  const mproof = await until('the mint to be certified', 120_000, async () => (await c.aggOf(msid).getInclusionProof(msid)).inclusionProof ?? undefined);
  let tokenBytes = C.encodeTag(39040, arr(u(2), arr(mint.toCBOR(), mproof.toCBOR()), arr()));
  let token = await Token.fromCBOR(tokenBytes);
  const reason = returnReason(cfg.chainId, cfg.vault, cfg.zeroAddress, cfg.ty, cfg.aid, unhex(RECIPIENT), amount);
  const burn = await TransferTransaction.create(token, BurnPredicate.create(sha256(reason)), StateMask.generate(), { data: reason });
  const bcd = await CertificationData.fromTransaction(burn, await SignaturePredicateUnlockScript.create(burn, owner));
  const bsid = await StateId.fromCertificationData(bcd);
  if (spans) assert.notEqual(c.aggOf(bsid), c.aggOf(msid), 'the burn went to the shard of the mint: the steering did not hold');
  await c.aggOf(bsid).submitCertificationRequest(bcd);
  const bproof = await until('the burn to be certified', 120_000, async () => (await c.aggOf(bsid).getInclusionProof(bsid)).inclusionProof ?? undefined);
  const genesis = CborDeserializer.decodeArray(token.genesis.toCBOR(), 2);
  tokenBytes = C.encodeTag(39040, arr(u(2), arr(genesis[0], genesis[1]), arr(arr(burn.toCBOR(), bproof.toCBOR()))));
  token = await Token.fromCBOR(tokenBytes);

  // the return proof, assembled once and saved byte for byte, with the batch request the verifier will make from it
  const ret = await buildReturnProof(bridge, token);
  const request = batchRequest(ret.envelope.anchors);
  const counts = measure(ret.envelope.anchors);
  // Each anchor is labelled by the seal of the certificate it carries: its UC must be one of the token's certificates (byte for byte),
  // and every certificate with those bytes has one epoch and round. No fallback: a mislabelled anchor would mislabel the evidence.
  const certs = [token.genesis, ...token.transactions].map((t) => t.inclusionProof.unicityCertificate);
  const anchors = ret.envelope.anchors.map((a, i) => {
    const matching = certs.filter((uc) => hex(uc.toCBOR()) === hex(a.uc));
    assert.ok(matching.length > 0, `anchor ${i}: its UC is not one of the token's certificates`);
    const labels = new Set(matching.map((uc) => `${uc.unicitySeal.epoch}/${uc.unicitySeal.rootChainRoundNumber}`));
    assert.equal(labels.size, 1, `anchor ${i}: its certificate occurrences disagree on epoch/round`);
    return { epoch: matching[0].unicitySeal.epoch, round: matching[0].unicitySeal.rootChainRoundNumber, shard: hex(a.shard), ucSha256: sha(a.uc) };
  });
  if (spans) assert.equal(new Set(anchors.map((a) => a.shard)).size, c.lane.aggShards!.length, `the saved history must carry an anchor of each aggregator shard: ${anchors.map((a) => a.shard)}`);
  const head = await rpc(c.eth, 'eth_blockNumber', []);
  const saved = {
    lane: 'anyage', savedAtBlock: head, nonce, amountWei, recipient: RECIPIENT, nullifier: hex(ret.verified.outcome.nullifier),
    token: { file: 'token.cbor', sha256: sha(tokenBytes) }, envelope: { file: 'envelope.bin', sha256: sha(ret.encoded), bytes: ret.encoded.length },
    batchRequest: { file: 'batch-request.bin', sha256: sha(request), bytes: request.length }, grouping: counts, gate: ret.gate, anchors,
    registry: await registryAt(c, head, anchors.map((a) => a.epoch)),
  };
  writeFileSync(`${out}/token.cbor`, tokenBytes);
  writeFileSync(`${out}/envelope.bin`, ret.encoded);
  writeFileSync(`${out}/batch-request.bin`, request);
  writeFileSync(`${out}/saved.json`, toJson(saved));
  console.log(`SAVED ${out}/saved.json`, toJson({ nonce, anchors, envelopeSha256: saved.envelope.sha256 }));
}

/** The saved bytes, each checked against the sha256 recorded when it was saved. */
function loadSaved(savedPath: string) {
  const saved = JSON.parse(readFileSync(savedPath, 'utf8'));
  const dir = savedPath.replace(/\/[^/]*$/, '');
  const file = (f: { file: string; sha256: string }): Uint8Array => {
    const b = Uint8Array.from(readFileSync(`${dir}/${f.file}`));
    assert.equal(sha(b), f.sha256, `${f.file} changed since it was saved`);
    return b;
  };
  return { saved, dir, envelope: file(saved.envelope), request: file(saved.batchRequest) };
}

// ---- verify (eth_call only) ---------------------------------------------------------------------------------------------------------------
async function verify(cfgPath: string, savedPath: string, epoch: 'current' | 'historical'): Promise<void> {
  const c = ctx(cfgPath);
  const { saved, dir, envelope, request } = loadSaved(savedPath);
  const head = await rpc(c.eth, 'eth_blockNumber', []);
  const anchorEpochs = (saved.anchors as { epoch: string }[]).map((a) => BigInt(a.epoch));
  const reg = await registryAt(c, head, anchorEpochs);
  const usable = reg.usableEpoch as bigint;
  if (epoch === 'current') {
    assert.ok(anchorEpochs.every((e) => e === usable), `--epoch current: the anchors' epochs ${anchorEpochs} must be the usable epoch ${usable}`);
  } else {
    assert.ok(anchorEpochs.every((e) => e < usable), `--epoch historical: the anchors' epochs ${anchorEpochs} must be below the usable epoch ${usable}`);
    // the closed-interval acceptance itself: each anchor's epoch is closed and its round lies inside [start, end)
    const entries = reg.entries as Record<string, { start: bigint; end: bigint; hasEnd: bigint }>;
    for (const a of saved.anchors as { epoch: string; round: string }[]) {
      const e = entries[a.epoch];
      const r = BigInt(a.round);
      assert.ok(e.hasEnd === 1n && e.start <= r && r < e.end, `--epoch historical: anchor epoch ${a.epoch} must be closed with start <= ${r} < end (${e.start}, ${e.end}, hasEnd ${e.hasEnd})`);
    }
  }
  const ages = (saved.anchors as { round: string }[]).map((a) => (reg.clockRound as bigint) - BigInt(a.round));

  // the native batch verdict on the saved request: abi.encode(uint256 2, bool)
  const out = await rpc(c.eth, 'eth_call', [{ to: CERT_BATCH, data: `0x${hex(request)}` }, head]);
  const version = BigInt(`0x${out.slice(2, 66)}`);
  const valid = BigInt(`0x${out.slice(66, 130)}`) === 1n;
  const batchGas = BigInt(await rpc(c.eth, 'eth_estimateGas', [{ to: CERT_BATCH, data: `0x${hex(request)}` }, head]));
  assert.ok(version === 2n && valid, `the native CERT_BATCH_V2 verdict on the saved request must be (2, true): ${out}`);

  // the vault's whole redeem relation on the saved envelope, as the third-party submitter, without sending
  const redeemData = redeemCalldata(envelope);
  const redeemOut = await rpc(c.eth, 'eth_call', [{ from: THIRD_PARTY_ADDR, to: c.lane.vault, data: redeemData }, head]);
  const redeemGas = BigInt(await rpc(c.eth, 'eth_estimateGas', [{ from: THIRD_PARTY_ADDR, to: c.lane.vault, data: redeemData }, head]));
  // BridgeVault.redeem returns the redeemed lock's nonce (the credited amount is checked by release on the real transaction)
  assert.equal(BigInt(redeemOut), BigInt(saved.nonce), `the redeem eth_call must return the saved nonce: ${redeemOut}`);
  const result = { epoch, block: head, registry: reg, anchorAges: ages, batch: { returndata: out, valid, estimatedGas: batchGas }, redeem: { returndata: redeemOut, estimatedGas: redeemGas } };
  writeFileSync(`${dir}/verify-${epoch}.json`, toJson(result));
  console.log(`VERIFIED ${epoch}`, toJson({ block: head, usableEpoch: usable, anchorEpochs, anchorAges: ages, batchGas, redeemGas }));
}

// ---- release (the one redemption, then the claim) -----------------------------------------------------------------------------------------
async function release(cfgPath: string, savedPath: string): Promise<void> {
  const c = ctx(cfgPath);
  const { saved, dir, envelope } = loadSaved(savedPath);
  const amountWei = BigInt(saved.amountWei);
  const gas = String(Math.min(7_000_000, Number(saved.gate.total) + 200_000));
  const claimable = (): bigint => BigInt(c.cast('call', c.lane.vault, 'claimable(address)(uint256)', saved.recipient).split(' ')[0]);
  const creditBefore = claimable();
  const rc = await sendAll(c, c.lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(envelope)}`], THIRD_PARTY_KEY, gas);
  assert.equal(rc.status, '0x1', `redeem reverted: ${JSON.stringify(rc).slice(0, 400)}`);
  const credited = claimable() - creditBefore;
  const recorded = hex(unhex(c.cast('call', c.lane.vault, 'spentNullifier(uint256)(bytes32)', String(saved.nonce))));
  assert.equal(credited, amountWei, 'the recipient is credited with exactly the locked amount by this redemption');
  assert.equal(recorded, saved.nullifier, 'the vault recorded the saved nullifier');
  const claim = await sendAll(c, c.lane.vault, 'claim(uint256,address)', [amountWei.toString(), PAYEE], RECIPIENT_KEY, '500000');
  assert.equal(claim.status, '0x1', 'claim reverted');
  // the payee's balance just before and at the claim block, so no other block's transfer can enter the delta
  const claimBlock = BigInt(claim.blockNumber);
  const before = BigInt(await rpc(c.eth, 'eth_getBalance', [PAYEE, `0x${(claimBlock - 1n).toString(16)}`]));
  const after = BigInt(await rpc(c.eth, 'eth_getBalance', [PAYEE, claim.blockNumber]));
  assert.equal(after - before, amountWei, 'the payee received the locked amount');
  const result = {
    redeem: { tx: rc.transactionHash, block: rc.blockNumber, gasUsed: BigInt(rc.gasUsed), gasLimit: gas, registry: await registryAt(c, rc.blockNumber, (saved.anchors as { epoch: string }[]).map((a) => BigInt(a.epoch))) },
    nullifier: recorded, credited, claim: { tx: claim.transactionHash, gasUsed: BigInt(claim.gasUsed) }, balanceDelta: after - before,
  };
  writeFileSync(`${dir}/release.json`, toJson(result));
  console.log('RELEASED', toJson(result));
}

const [cmd, cfgPath, arg3, ...rest] = process.argv.slice(2);
switch (cmd) {
  case 'save':
    await save(cfgPath, arg3);
    break;
  case 'verify': {
    const i = rest.indexOf('--epoch');
    const epoch = rest[i + 1];
    if (i < 0 || (epoch !== 'current' && epoch !== 'historical')) throw new Error('verify needs --epoch current|historical');
    await verify(cfgPath, arg3, epoch);
    break;
  }
  case 'release':
    await release(cfgPath, arg3);
    break;
  default:
    throw new Error('usage: anyage.ts save <lane-config> [<out-dir>] | verify <lane-config> <saved.json> --epoch current|historical | release <lane-config> <saved.json>');
}
