/**
 * Any-age lane driver (bft-core briefs/anyage-final-lane-plan.md, steps L1a, L1b and L1c): one burned token whose ORIGINAL return proof
 * is saved once and later verified unchanged, first while its anchors' epoch is still the usable one and again after a root epoch
 * handoff has made that epoch historical, and then released exactly once. Three separate commands, never interleaved by the lane:
 *
 *   anyage.ts save    <lane-config.json> [<out-dir>]                          lock, mint, SAVE_TRANSFERS transfers (default 0), burn; save the exact proof bytes, hashes and the
 *                                                                              registry interval each anchor was made under
 *   anyage.ts verify  <lane-config.json> <saved.json> --epoch current|historical
 *                                                                              non-mutating eth_call of the saved bytes: the native
 *                                                                              CERT_BATCH_V2 verdict and the vault's whole redeem relation
 *   anyage.ts release <lane-config.json> <saved.json>                         the one vault redemption of the saved bytes, then the claim
 *   anyage.ts consolidated <lane-config.json> [<out-dir>]                     a second token burned over the shards, consolidated by the SDK (K = m anchors, m = 1 unsharded
 *                                                                              under one seal), redeemed once and claimed; the per-SID envelope of the same token is
 *                                                                              built and priced as the control (#526 step 4)
 *   anyage.ts long-history <lane-config.json> [<out-dir>]                     (B7 PR 3) a token transferred LONG_TRANSFERS times (default 320) through the
 *                                                                              live aggregators, burned and consolidated (K = m); redeemed first one gas below the least
 *                                                                              limit that succeeds (mined, reverts, the vault unchanged), then at the estimate, and claimed
 *   anyage.ts negatives <lane-config.json> <saved.json>                       (bft-core #438) after the saved token's release: a conflicting burn of its pre-burn state
 *                                                                              (another recipient) is not certified, the aggregator serves the first burn's proof for that
 *                                                                              state; and a fresh proof of the redeemed burn (consolidated now, under a newer seal) is refused
 *                                                                              by the vault as PartAlreadyRedeemed, with the saved nullifier. Writes negatives.json; sends nothing
 *                                                                              to the vault
 *
 * Nothing is refreshed: the saved envelope is the one the plug-in assembled from the proofs the aggregator returned when each transition
 * was certified, and every later command checks its sha256 before use. Protocol 4 (any-age registry, one CERT_BATCH_V2 call over the
 * anchor table): a certificate is accepted for any age while its epoch interval and the registry's usable origin admit it.
 */
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { ShardId } from '@unicitylabs/state-transition-sdk/lib/api/bft/ShardId.js';
import { ShardRouting } from '@unicitylabs/state-transition-sdk/lib/consolidation/ShardRouting.js';
import { TokenProofClient } from '@unicitylabs/state-transition-sdk/lib/consolidation/TokenProofClient.js';
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
import { assembleEnvelope, buildReturnProof, refreshToken } from '../../packages/native-bridge-plugin/src/proof.js';
import { projectToken } from '../../packages/native-bridge-plugin/src/history.js';
import { isSplitReason, lineageProofs, splitChain } from '../../packages/native-bridge-plugin/src/splitpart.js';
import { consolidatedProofs } from '../../packages/native-bridge-plugin/src/wallet.js';
import {
  arr, bs, decodeCfg, decodePolicy, deriveSalt, deriveTokenId, H, keccak256, lockDigest, lockRecord, returnReason, shardCovers, shardDepth, u, valueEnvelope,
} from '../../packages/native-bridge-plugin/src/profile.js';
import { TrustInput } from '../../packages/native-bridge-plugin/src/trust.js';
import { NativeBridge } from '../../packages/native-bridge-plugin/src/verifier.js';
import { minimalGas } from './gassearch.js';
import { hex, LaneConfig, loadConfig, rpc, run, signLegacyTx, sleep, until, unhex } from './lib.js';

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
/** BridgeVault's PartAlreadyRedeemed(uint256,bytes32) (protocol 6: spent state per (lock nonce, part token ID); `cast sig`, contracts pin) */
const PART_ALREADY_REDEEMED = '0xe8f8709e';
/** The owner keys a token passes through (the mint's first, then each transfer to the next, cyclically): `negatives` re-derives the holder. */
const ownerKey = (i: number): SigningService => new SigningService(sha256(text(i === 0 ? 'anyage-owner' : `anyage-owner-${i}`)));
const OWNERS = 4;

type Json = Record<string, unknown>;
const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const sha = (b: Uint8Array): string => hex(sha256(b));
const toJson = (v: unknown): string => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x), 2);
const word = (n: bigint): Uint8Array => unhex(n.toString(16).padStart(64, '0'));
/** A token amount: minimal big-endian, no leading zero byte (interop.md "Canonical primitives"). */
const amountBytes = (n: bigint): Uint8Array => unhex(n.toString(16).length % 2 ? `0${n.toString(16)}` : n.toString(16));
/** ABI calldata of `redeem(bytes)` (selector 0x9945e3d3), encoded here: `cast calldata` is offline (no --rpc-url, so not c.cast) and a
 * large envelope would exceed the per-argument limit of a subprocess. */
const redeemCalldata = (envelope: Uint8Array): string => {
  const padded = new Uint8Array(Math.ceil(envelope.length / 32) * 32);
  padded.set(envelope);
  return `0x9945e3d3${hex(word(32n))}${hex(word(BigInt(envelope.length)))}${hex(padded)}`;
};
/** BridgeVault.redeem's return data, abi.encode(uint256 nonce, bytes32 partId) (protocol 6); undefined for any other length. */
const redeemReturn = (out: string): { nonce: bigint; partId: string } | undefined =>
  out.length === 2 + 128 ? { nonce: BigInt(`0x${out.slice(2, 66)}`), partId: out.slice(66, 130) } : undefined;
/** An eth_call of the vault as the third-party submitter at BLOCK: its result, or its revert data (lib's rpc keeps only the message). */
async function callVault(eth: string, vault: string, data: string, block: string): Promise<{ result?: string; revert?: string; message?: string }> {
  const res = await fetch(eth, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ from: THIRD_PARTY_ADDR, to: vault, data }, block] }) });
  const body = (await res.json()) as { result?: string; error?: { message: string; data?: string } };
  return body.error ? { revert: body.error.data, message: body.error.message } : { result: body.result };
}

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

/** Sign once, publish to every validator's pool, wait for the receipt. Small calls only: the calldata is built by `cast calldata`; an envelope goes through sendData. */
async function sendAll(c: Ctx, to: string, sig: string, args: string[], key: string, gas: string, value?: string) {
  return sendData(c, to, sig ? run('cast', ['calldata', sig, ...args]) : '0x', key, gas, value);
}

/** sendAll for calldata of any size: signed in-process (signLegacyTx), never passed through a command line. */
async function sendData(c: Ctx, to: string, data: string, key: string, gas: string, value?: string) {
  const sender = run('cast', ['wallet', 'address', '--private-key', key]);
  const nonce = BigInt(await rpc(c.eth, 'eth_getTransactionCount', [sender, 'pending']));
  const { raw, hash: txHash } = signLegacyTx({ nonce, gasPrice: 2_000_000_000n, gas: BigInt(gas), to, value: BigInt(value ?? '0'), data: unhex(data), chainId: BigInt(c.lane.chainId) }, key);
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

// ---- the burned token (shared by save and consolidated) ----------------------------------------------------------------------------------
/** Lock, mint and burn one token on the live aggregator(s): the original proofs, as returned at certification, never refreshed. With several shards the history spans them.
 * `transfers` live signature transfers between the mint and the burn (the long-history step) cycle through a few owner keys, each one certified before the next. */
async function burnedToken(c: Ctx, out: string, transfers = 0) {
  const { cfg, dep, bridge } = await installedBridge(c);
  for (const a of [RECIPIENT, THIRD_PARTY_ADDR]) await sendAll(c, a, '', [], DEPLOYER_KEY, '100000', '1000000000000000000');

  // lock, and its proof from the archived certificate of the lock block
  const owner = ownerKey(0);
  const p0 = EncodedPredicate.fromPredicate(SignaturePredicate.create(owner.publicKey)).toCBOR();
  const amountWei = 10n ** 18n;
  const amount = amountBytes(amountWei);
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
  // Steer only a two-leaf token; a long history's state IDs span the shards on their own (asserted on its anchors).
  for (let attempt = 1; spans && transfers === 0; attempt++) {
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
  const genesisPair = CborDeserializer.decodeArray(token.genesis.toCBOR(), 2);
  const certified: Uint8Array[] = [];
  const owners = Array.from({ length: OWNERS }, (_, i) => ownerKey(i));
  let holder = owner;
  for (let i = 0; i < transfers; i++) {
    const next = owners[(i + 1) % owners.length];
    const tx = await TransferTransaction.create(token, SignaturePredicate.create(next.publicKey), StateMask.generate());
    const cd = await CertificationData.fromTransaction(tx, await SignaturePredicateUnlockScript.create(tx, holder));
    const sid = await StateId.fromCertificationData(cd);
    await c.aggOf(sid).submitCertificationRequest(cd);
    const proof = await until(`transfer ${i + 1}/${transfers} to be certified`, 120_000, async () => (await c.aggOf(sid).getInclusionProof(sid)).inclusionProof ?? undefined);
    certified.push(arr(tx.toCBOR(), proof.toCBOR()));
    tokenBytes = C.encodeTag(39040, arr(u(2), arr(genesisPair[0], genesisPair[1]), arr(...certified)));
    token = await Token.fromCBOR(tokenBytes);
    holder = next;
    if ((i + 1) % 32 === 0) console.log(`certified ${i + 1}/${transfers} transfers`);
  }
  const reason = returnReason(cfg.chainId, cfg.vault, cfg.zeroAddress, cfg.ty, cfg.aid, unhex(RECIPIENT), amount);
  const burn = await TransferTransaction.create(token, BurnPredicate.create(sha256(reason)), StateMask.generate(), { data: reason });
  const bcd = await CertificationData.fromTransaction(burn, await SignaturePredicateUnlockScript.create(burn, holder));
  const bsid = await StateId.fromCertificationData(bcd);
  if (spans && transfers === 0) assert.notEqual(c.aggOf(bsid), c.aggOf(msid), 'the burn went to the shard of the mint: the steering did not hold');
  await c.aggOf(bsid).submitCertificationRequest(bcd);
  const bproof = await until('the burn to be certified', 120_000, async () => (await c.aggOf(bsid).getInclusionProof(bsid)).inclusionProof ?? undefined);
  tokenBytes = C.encodeTag(39040, arr(u(2), arr(genesisPair[0], genesisPair[1]), arr(...certified, arr(burn.toCBOR(), bproof.toCBOR()))));
  token = await Token.fromCBOR(tokenBytes);

  return { cfg, dep, bridge, token, tokenBytes, nonce, amountWei, amount, spans };
}

// ---- save ---------------------------------------------------------------------------------------------------------------------------------
async function save(cfgPath: string, outDir?: string): Promise<void> {
  const c = ctx(cfgPath);
  const out = outDir ?? `${c.lane.dir}/anyage`;
  mkdirSync(out, { recursive: true });
  // SAVE_TRANSFERS live signature transfers between the mint and the burn (default none)
  const transfers = Number(process.env.SAVE_TRANSFERS ?? '0');
  assert.ok(Number.isInteger(transfers) && transfers >= 0, `SAVE_TRANSFERS must be a whole number: ${process.env.SAVE_TRANSFERS}`);
  const { bridge, token, tokenBytes, nonce, amountWei, spans } = await burnedToken(c, out, transfers);

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
    lane: 'anyage', savedAtBlock: head, transfers, nonce, amountWei, recipient: RECIPIENT, nullifier: hex(ret.verified.outcome.nullifier),
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
  // the native batch verdict on the saved request: abi.encode(uint256 2, bool). A fresh anchor is admitted only once the registry's usable
  // origin covers its round (round <= O), so wait for the verdict (bounded) and read everything else at that block.
  let out = '';
  const head = await until('the native CERT_BATCH_V2 verdict on the saved request is (2, true) (the usable origin covers every anchor)', 240_000, async () => {
    const block = await rpc(c.eth, 'eth_blockNumber', []);
    out = await rpc(c.eth, 'eth_call', [{ to: CERT_BATCH, data: `0x${hex(request)}` }, block]);
    return BigInt(`0x${out.slice(2, 66)}`) === 2n && BigInt(`0x${out.slice(66, 130)}`) === 1n ? block : undefined;
  }).catch((e: unknown) => {
    throw new Error(`${String(e)}; the last verdict: ${out}`);
  });
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

  const version = BigInt(`0x${out.slice(2, 66)}`);
  const valid = BigInt(`0x${out.slice(66, 130)}`) === 1n;
  const batchGas = BigInt(await rpc(c.eth, 'eth_estimateGas', [{ to: CERT_BATCH, data: `0x${hex(request)}` }, head]));
  assert.ok(version === 2n && valid, `the native CERT_BATCH_V2 verdict on the saved request must be (2, true): ${out}`);

  // the vault's whole redeem relation on the saved envelope, as the third-party submitter, without sending
  const redeemData = redeemCalldata(envelope);
  const redeemOut = await rpc(c.eth, 'eth_call', [{ from: THIRD_PARTY_ADDR, to: c.lane.vault, data: redeemData }, head]);
  const redeemGas = BigInt(await rpc(c.eth, 'eth_estimateGas', [{ from: THIRD_PARTY_ADDR, to: c.lane.vault, data: redeemData }, head]));
  // BridgeVault.redeem returns the redeemed lock's nonce and the part's token ID (the credited amount is checked by release on the real transaction)
  const partId = hex((await Token.fromCBOR(Uint8Array.from(readFileSync(`${dir}/${saved.token.file}`)))).id.bytes);
  assert.deepEqual(redeemReturn(redeemOut), { nonce: BigInt(saved.nonce), partId }, `the redeem eth_call must return the saved (nonce, partId): ${redeemOut}`);
  const result = { epoch, block: head, registry: reg, anchorAges: ages, batch: { returndata: out, valid, estimatedGas: batchGas }, redeem: { returndata: redeemOut, estimatedGas: redeemGas } };
  writeFileSync(`${dir}/verify-${epoch}.json`, toJson(result));
  console.log(`VERIFIED ${epoch}`, toJson({ block: head, usableEpoch: usable, anchorEpochs, anchorAges: ages, batchGas, redeemGas }));
}

// ---- release (the one redemption, then the claim) -----------------------------------------------------------------------------------------
/** The one vault redemption of an envelope by the third-party submitter, then the claim; every effect asserted. */
async function redeemAndClaim(c: Ctx, p: { envelope: Uint8Array; gateTotal: number; nonce: bigint | string; partId: string; nullifier: string; amountWei: bigint; recipient: string; epochs: bigint[]; gasLimit?: bigint }) {
  const gas = p.gasLimit?.toString() ?? String(Math.min(7_000_000, p.gateTotal + 200_000));
  const claimable = (): bigint => BigInt(c.cast('call', c.lane.vault, 'claimable(address)(uint256)', p.recipient).split(' ')[0]);
  const creditBefore = claimable();
  const rc = await sendData(c, c.lane.vault, redeemCalldata(p.envelope), THIRD_PARTY_KEY, gas);
  assert.equal(rc.status, '0x1', `redeem reverted: ${JSON.stringify(rc).slice(0, 400)}`);
  const credited = claimable() - creditBefore;
  const recorded = hex(unhex(c.cast('call', c.lane.vault, 'spentPart(uint256,bytes32)(bytes32)', String(p.nonce), `0x${p.partId}`)));
  assert.equal(credited, p.amountWei, 'the recipient is credited with exactly the locked amount by this redemption');
  assert.equal(recorded, p.nullifier, 'the vault recorded the saved nullifier');
  const claim = await sendAll(c, c.lane.vault, 'claim(uint256,address)', [p.amountWei.toString(), PAYEE], RECIPIENT_KEY, '500000');
  assert.equal(claim.status, '0x1', 'claim reverted');
  // the payee's balance just before and at the claim block, so no other block's transfer can enter the delta
  const claimBlock = BigInt(claim.blockNumber);
  const before = BigInt(await rpc(c.eth, 'eth_getBalance', [PAYEE, `0x${(claimBlock - 1n).toString(16)}`]));
  const after = BigInt(await rpc(c.eth, 'eth_getBalance', [PAYEE, claim.blockNumber]));
  assert.equal(after - before, p.amountWei, 'the payee received the locked amount');
  return {
    redeem: { tx: rc.transactionHash, block: rc.blockNumber, gasUsed: BigInt(rc.gasUsed), gasLimit: gas, registry: await registryAt(c, rc.blockNumber, p.epochs) },
    nullifier: recorded, credited, claim: { tx: claim.transactionHash, gasUsed: BigInt(claim.gasUsed) }, balanceDelta: after - before,
  };
}

async function release(cfgPath: string, savedPath: string): Promise<void> {
  const c = ctx(cfgPath);
  const { saved, dir, envelope } = loadSaved(savedPath);
  const result = await redeemAndClaim(c, {
    envelope, gateTotal: Number(saved.gate.total), nonce: saved.nonce, partId: hex((await Token.fromCBOR(Uint8Array.from(readFileSync(`${dir}/${saved.token.file}`)))).id.bytes),
    nullifier: saved.nullifier, amountWei: BigInt(saved.amountWei), recipient: saved.recipient,
    epochs: (saved.anchors as { epoch: string }[]).map((a) => BigInt(a.epoch)),
  });
  writeFileSync(`${dir}/release.json`, toJson(result));
  console.log('RELEASED', toJson(result));
}


type Labeller = (tk: Token, anchors: readonly { uc: Uint8Array; shard: Uint8Array }[]) => { epoch: bigint; round: bigint; shard: string; ucSha256: string }[];
/** Each anchor labelled by the token certificate it carries (byte for byte). */
const labelByCertificate: Labeller = (tk, anchors) => {
  const certs = [tk.genesis, ...tk.transactions].map((t) => t.inclusionProof.unicityCertificate);
  return anchors.map((a, i) => {
    const m = certs.filter((uc) => hex(uc.toCBOR()) === hex(a.uc));
    assert.ok(m.length > 0, `anchor ${i}: its UC is not one of the token's certificates`);
    return { epoch: m[0].unicitySeal.epoch, round: m[0].unicitySeal.rootChainRoundNumber, shard: hex(a.shard), ucSha256: sha(a.uc) };
  });
};

/** The consolidation of a burned token over the lane's shards (the SDK's two waves over the deployment's shard routing; one attempt per call, retried only when it is
 * unavailable AND retryable), its envelope (K = m anchors under one seal), and the block from which the vault accepts it (the master seal's round within the usable origin). */
async function consolidateAndAccept(c: Ctx, bridge: NativeBridge, token: Token, nonce: bigint, label: Labeller, refusal?: string) {
  // an unsharded aggregation layer (no aggShards: the testnet package's single aggregator) is one root-shard endpoint, the SDK's single routing
  const endpoints = c.lane.aggShards?.length
    ? c.lane.aggShards.map((sh) => ({ client: new AggregatorClient(sh.url), shard: ShardId.decode(unhex(sh.shard)) }))
    : [{ client: new AggregatorClient(c.lane.aggUrl), shard: ShardId.ROOT }];
  const routing = c.lane.aggShards?.length ? new ShardRouting({ endpoints, scheme: endpoints.map((e) => e.shard) }) : ShardRouting.single(endpoints[0].client);
  const proofClient = new TokenProofClient({ routing, verificationContext: await bridge.context() });
  let summary: Record<string, unknown> | undefined;
  const t0 = Date.now();
  let cons: Awaited<ReturnType<typeof consolidatedProofs>> | undefined;
  for (let attempt = 1; attempt <= 4; attempt++) {
    cons = await consolidatedProofs(token, {
      partitionShards: endpoints.length,
      consolidate: async (tk) => {
        const r = await proofClient.consolidate(tk, { timeoutMs: 60_000 });
        if (r.status === 'consolidated') summary = { ...r.summary, masterShard: r.summary.masterShard.toString() };
        return r;
      },
    });
    if (cons.proofs || !(cons.path.kind === 'per-sid' && cons.path.retryable)) break;
    console.log(`consolidation unavailable (${cons.path.kind === 'per-sid' ? cons.path.unavailable : '?'}), attempt ${attempt}`);
    await sleep(5000);
  }
  assert.ok(cons?.proofs, `the consolidation did not produce a consolidated token: ${toJson(cons?.path)}`);
  const consolidatedToken = await refreshToken(token, cons.proofs);
  const ret = await buildReturnProof(bridge, consolidatedToken);
  const conAnchors = label(consolidatedToken, ret.envelope.anchors);
  const conCounts = measure(ret.envelope.anchors);
  assert.equal(conAnchors.length, endpoints.length, `K = m: one anchor per participating shard, got ${conAnchors.length}`);
  assert.equal(new Set(conAnchors.map((a) => `${a.epoch}/${a.round}`)).size, 1, 'S = 1: every anchor is under the identical seal');
  assert.equal(conAnchors.length, new Set(conAnchors.map((a) => a.shard)).size, 'one anchor per shard');

  // the master seal must satisfy the registry (round <= the usable origin): wait for the redeem relation to accept the consolidated envelope, recording the rounds.
  // With REFUSAL (revert data), wait instead until the vault gets that far and refuses it so: until then a refusal for the seal's round is the registry's, not the verdict.
  const masterRound = BigInt(conAnchors[0].round);
  const regBefore = await registryAt(c, await rpc(c.eth, 'eth_blockNumber', []), [conAnchors[0].epoch]);
  let last: Awaited<ReturnType<typeof callVault>> | undefined;
  const accepted = await until(refusal ? `the vault to refuse the consolidated envelope with ${refusal.slice(0, 10)}` : 'the vault accepts the consolidated envelope (master round within the usable origin)', 240_000, async () => {
    const head = await rpc(c.eth, 'eth_blockNumber', []);
    last = await callVault(c.eth, c.lane.vault, redeemCalldata(ret.encoded), head);
    const done = refusal ? last.revert === refusal : last.result !== undefined && redeemReturn(last.result)?.nonce === nonce && redeemReturn(last.result)?.partId === hex(token.id.bytes);
    return done ? head : undefined;
  }).catch((e: unknown) => {
    throw new Error(`${String(e)}; the last eth_call: ${toJson(last)}`);
  });
  const regAt = await registryAt(c, accepted, [conAnchors[0].epoch]);
  return { endpoints, cons, summary, t0, consolidatedToken, ret, conAnchors, conCounts, masterRound, regBefore, regAt, accepted };
}

// ---- consolidated (#526 step 4: one token over several shards, redeemed through the SDK's consolidation) -----------------------------------------
async function consolidated(cfgPath: string, outDir?: string): Promise<void> {
  const c = ctx(cfgPath);
  const out = outDir ?? `${c.lane.dir}/anyage-consolidated`;
  mkdirSync(out, { recursive: true });
  const { bridge, token, tokenBytes, nonce, amountWei } = await burnedToken(c, out);

  // the labels of an envelope's anchors: each anchor's UC is one of the token's certificates (byte for byte)
  const label: Labeller = (tk, anchors) => {
    const certs = [tk.genesis, ...tk.transactions].map((t) => t.inclusionProof.unicityCertificate);
    return anchors.map((a, i) => {
      const m = certs.filter((uc) => hex(uc.toCBOR()) === hex(a.uc));
      assert.ok(m.length > 0, `anchor ${i}: its UC is not one of the token's certificates`);
      return { epoch: m[0].unicitySeal.epoch, round: m[0].unicitySeal.rootChainRoundNumber, shard: hex(a.shard), ucSha256: sha(a.uc) };
    });
  };
  const estimate = async (envelope: Uint8Array): Promise<{ gas?: bigint; error?: string }> => {
    const data = redeemCalldata(envelope);
    try {
      return { gas: BigInt(await rpc(c.eth, 'eth_estimateGas', [{ from: THIRD_PARTY_ADDR, to: c.lane.vault, data }, 'latest'])) };
    } catch (e) {
      return { error: String(e).slice(0, 300) };
    }
  };

  // the control: the per-SID envelope of the proofs as returned at certification (protocol 5, one anchor per distinct complete UC)
  const per = await buildReturnProof(bridge, token);
  const perAnchors = label(token, per.envelope.anchors);
  const perCounts = measure(per.envelope.anchors);

  const { endpoints, cons, summary, t0, consolidatedToken, ret, conAnchors, conCounts, masterRound, regBefore, regAt, accepted } =
    await consolidateAndAccept(c, bridge, token, nonce, label);
  assert.equal(hex(ret.verified.outcome.nullifier), hex(per.verified.outcome.nullifier), 'the consolidated and the per-SID envelope redeem the same lock (same nullifier)');
  const conEst = await estimate(ret.encoded);
  const perEst = await estimate(per.encoded);

  const result = await redeemAndClaim(c, {
    envelope: ret.encoded, gateTotal: Number(ret.gate.total), nonce, partId: hex(token.id.bytes), nullifier: hex(ret.verified.outcome.nullifier), amountWei, recipient: RECIPIENT,
    epochs: conAnchors.map((a) => BigInt(a.epoch)),
  });
  const record = {
    lane: 'anyage-consolidated', path: cons.path, shards: endpoints.length, nonce, amountWei, nullifier: hex(ret.verified.outcome.nullifier),
    token: { file: 'token.cbor', sha256: sha(tokenBytes) }, consolidatedToken: { file: 'consolidated-token.cbor' },
    consolidation: { summary, elapsedMs: Date.now() - t0 },
    consolidated: { K: conCounts.k, E: conCounts.e, S: conCounts.s, Q: conCounts.q, anchors: conAnchors, gate: ret.gate, envelopeBytes: ret.encoded.length, estimatedGas: conEst.gas, estimateError: conEst.error },
    perSid: { K: perCounts.k, E: perCounts.e, S: perCounts.s, Q: perCounts.q, anchors: perAnchors, gate: per.gate, envelopeBytes: per.encoded.length, estimatedGas: perEst.gas, estimateError: perEst.error },
    masterRound, usableOrigin: { atBuild: regBefore, atAcceptance: regAt, acceptedAtBlock: accepted },
    release: result,
  };
  writeFileSync(`${out}/token.cbor`, tokenBytes);
  writeFileSync(`${out}/consolidated-token.cbor`, consolidatedToken.toCBOR());
  writeFileSync(`${out}/envelope-consolidated.bin`, ret.encoded);
  writeFileSync(`${out}/envelope-per-sid.bin`, per.encoded);
  writeFileSync(`${out}/consolidated.json`, toJson(record));
  console.log('CONSOLIDATED', toJson({ K: conCounts.k, S: conCounts.s, masterRound, gasUsed: result.redeem.gasUsed, perSidK: perCounts.k, perSidS: perCounts.s }));
}

// ---- long-history (B7 PR 3: one token past the former bounds, redeemed underfunded and then funded) -------------------------------------------
/** EIP-7623 calldata floor of a transaction: 21000 + 10 * tokens, a zero byte one token and any other byte four. Below it a transaction is not admitted. */
const calldataFloor = (data: string): bigint => {
  const b = unhex(data);
  const zeros = b.filter((x) => x === 0).length;
  return 21_000n + 10n * BigInt(zeros + 4 * (b.length - zeros));
};

async function longHistory(cfgPath: string, outDir?: string): Promise<void> {
  const c = ctx(cfgPath);
  const out = outDir ?? `${c.lane.dir}/anyage-long-history`;
  mkdirSync(out, { recursive: true });
  const transfers = Number(process.env.LONG_TRANSFERS ?? '320');
  assert.ok(transfers > 64, `LONG_TRANSFERS must exceed the former 64-transfer bound: ${transfers}`);
  const { bridge, token, tokenBytes, nonce, amountWei } = await burnedToken(c, out, transfers);
  // consolidateAndAccept asserts K = m (one anchor per aggregator shard), so the history spans every shard; the per-SID control is not built (one
  // anchor per certification round would exceed the envelope bound)
  const { cons, summary, t0, consolidatedToken, ret, conAnchors, conCounts, masterRound, accepted } = await consolidateAndAccept(c, bridge, token, nonce, labelByCertificate);
  const leaves = ret.verified.outcome.leaves.length;
  assert.equal(leaves, transfers + 2, 'the leaves are the mint, every transfer and the burn');
  const data = redeemCalldata(ret.encoded);
  const from = THIRD_PARTY_ADDR;
  const estimatedGas = BigInt(await rpc(c.eth, 'eth_estimateGas', [{ from, to: c.lane.vault, data }, 'latest']));

  // the least limit at which the redemption succeeds, by bisection over eth_call at one block (eth_estimateGas stops within 1.5% of it)
  const head = await rpc(c.eth, 'eth_blockNumber', []);
  const succeeds = async (gas: bigint): Promise<boolean> => {
    try {
      const r = redeemReturn(await rpc(c.eth, 'eth_call', [{ from, to: c.lane.vault, data, gas: `0x${gas.toString(16)}` }, head]));
      return r?.nonce === nonce && r.partId === hex(token.id.bytes);
    } catch {
      return false;
    }
  };
  const floor = calldataFloor(data);
  const search = await minimalGas(21_000n, estimatedGas, succeeds);
  const underLimit = search.min - 1n;
  assert.ok(underLimit >= floor, `one below the least limit (${underLimit}) is under the calldata floor ${floor}: the underfunded redemption would not be admitted`);

  // the vault's view of this lock and its recipient, read at one block (the snapshots compare equal; their blocks are recorded beside them)
  const vault = async (block: string) => {
    const at = (sig: string, ...args: string[]): string => c.cast('call', c.lane.vault, sig, ...args, '--block', block).split(' ')[0];
    return {
      lockDigest: at('lockDigest(uint256)(bytes32)', nonce.toString()), spentPart: at('spentPart(uint256,bytes32)(bytes32)', nonce.toString(), `0x${hex(token.id.bytes)}`),
      redeemedAmount: at('redeemedAmount(uint256)(uint256)', nonce.toString()),
      claimable: at('claimable(address)(uint256)', RECIPIENT), balance: BigInt(await rpc(c.eth, 'eth_getBalance', [c.lane.vault, block])).toString(),
    };
  };
  const beforeBlock = await rpc(c.eth, 'eth_blockNumber', []);
  const vaultBefore = await vault(beforeBlock);
  const low = await sendData(c, c.lane.vault, data, THIRD_PARTY_KEY, underLimit.toString());
  const vaultAfter = await vault(low.blockNumber);
  assert.equal(low.status, '0x0', `the underfunded redemption must revert: ${JSON.stringify(low).slice(0, 300)}`);
  assert.deepEqual(vaultAfter, vaultBefore, 'the underfunded redemption changed the vault');

  // funded: the wallet's estimate, then the claim
  const release = await redeemAndClaim(c, {
    envelope: ret.encoded, gateTotal: Number(ret.gate.total), nonce, partId: hex(token.id.bytes), nullifier: hex(ret.verified.outcome.nullifier), amountWei, recipient: RECIPIENT,
    epochs: conAnchors.map((a) => BigInt(a.epoch)), gasLimit: estimatedGas,
  });
  const record = {
    lane: 'anyage-long-history', transfers, leaves, envelopeBytes: ret.encoded.length, historyBytes: ret.envelope.history.length,
    K: conCounts.k, S: conCounts.s, E: conCounts.e, Q: conCounts.q, estimatedGas, gate: ret.gate,
    minimalGas: { min: search.min, calls: search.calls, block: head, calldataFloor: floor },
    underfunded: { gasLimit: underLimit, status: low.status, gasUsed: BigInt(low.gasUsed), tx: low.transactionHash, vaultBefore, vaultAfter, beforeBlock, afterBlock: low.blockNumber },
    release, credited: release.credited, amountWei, nonce, nullifier: hex(ret.verified.outcome.nullifier),
    consolidation: { path: cons.path, summary, elapsedMs: Date.now() - t0, masterRound, acceptedAtBlock: accepted, anchors: conAnchors },
    token: { file: 'token.cbor', sha256: sha(tokenBytes) },
  };
  writeFileSync(`${out}/token.cbor`, tokenBytes);
  writeFileSync(`${out}/consolidated-token.cbor`, consolidatedToken.toCBOR());
  writeFileSync(`${out}/envelope-long-history.bin`, ret.encoded);
  writeFileSync(`${out}/long-history.json`, toJson(record));
  console.log('LONG-HISTORY', toJson({ transfers, leaves, envelopeBytes: ret.encoded.length, K: conCounts.k, estimatedGas, underLimit, lowStatus: low.status, gasUsed: release.redeem.gasUsed }));
}

// ---- negatives (bft-core #438: duplicate and replayed burns, live) -----------------------------------------------------------------------------
async function negatives(cfgPath: string, savedPath: string): Promise<void> {
  const c = ctx(cfgPath);
  const { saved, dir } = loadSaved(savedPath);
  const tokenBytes = Uint8Array.from(readFileSync(`${dir}/${saved.token.file}`));
  assert.equal(sha(tokenBytes), saved.token.sha256, 'token.cbor changed since it was saved');
  const nonce = BigInt(saved.nonce);
  const { cfg, bridge } = await installedBridge(c);
  const token = await Token.fromCBOR(tokenBytes);
  assert.equal(c.cast('call', c.lane.vault, 'spentPart(uint256,bytes32)(bytes32)', nonce.toString(), `0x${hex(token.id.bytes)}`).toLowerCase(), `0x${saved.nullifier}`.toLowerCase(),
    'run after the release: the vault has spent this token');
  const burn = token.transactions[token.transactions.length - 1];
  const amount = amountBytes(BigInt(saved.amountWei));

  // 1. a conflicting burn of the same pre-burn state, returning the token to another address: the state is spent, so the aggregator certifies
  // only the first burn. Whatever it answers to the submission, the proof it serves for that state ID is the first burn's.
  const [version, genesis, txs] = CborDeserializer.decodeArray(CborDeserializer.decodeTag(tokenBytes).data, 3);
  const preBurn = await Token.fromCBOR(C.encodeTag(39040, arr(version, genesis, arr(...CborDeserializer.decodeArray(txs).slice(0, -1)))));
  const holder = ownerKey(Number(saved.transfers) % OWNERS);
  const reason = returnReason(cfg.chainId, cfg.vault, cfg.zeroAddress, cfg.ty, cfg.aid, unhex(THIRD_PARTY_ADDR), amount);
  const conflicting = await TransferTransaction.create(preBurn, BurnPredicate.create(sha256(reason)), StateMask.generate(), { data: reason });
  const ccd = await CertificationData.fromTransaction(conflicting, await SignaturePredicateUnlockScript.create(conflicting, holder));
  const csid = await StateId.fromCertificationData(ccd);
  const firstProof = burn.inclusionProof;
  assert.equal(hex(csid.data), hex((await StateId.fromCertificationData(firstProof.certificationData)).data), 'the conflicting burn spends the same state as the first');
  assert.notEqual(hex(ccd.transactionHash.data), hex(firstProof.certificationData.transactionHash.data), 'the conflicting burn is another transaction');
  // the answer is recorded, not asserted: a server may accept it into its queue, refuse it, or fail the call
  const submitted = await c.aggOf(csid).submitCertificationRequest(ccd).then((r) => r.status, (e: unknown) => `error: ${String(e).slice(0, 200)}`);
  const served = await until('the proof the aggregator serves for the burned state', 120_000, async () => (await c.aggOf(csid).getInclusionProof(csid)).inclusionProof ?? undefined);
  assert.equal(hex(served.certificationData.transactionHash.data), hex(firstProof.certificationData.transactionHash.data),
    'the aggregator certifies only the first burn: the conflicting one is never certified');
  let conflictingRefused = '';
  try {
    await buildReturnProof(bridge, await Token.fromCBOR(C.encodeTag(39040, arr(version, genesis, arr(...CborDeserializer.decodeArray(txs).slice(0, -1), arr(conflicting.toCBOR(), served.toCBOR()))))));
  } catch (e) {
    conflictingRefused = String(e).slice(0, 300);
  }
  assert.ok(conflictingRefused, 'the plug-in refuses to build a return proof of the conflicting burn with the served proof');
  console.log(`CONFLICTING BURN submission ${submitted}; the first burn's proof is served; the plug-in refuses: ${conflictingRefused}`);

  // 2. a fresh proof of the redeemed burn: consolidated now, under a seal newer than every saved anchor. The vault refuses it on the nullifier
  // (PartAlreadyRedeemed of this nonce and token), not for its certificate, so a replay does not depend on the age of the proof.
  const refusal = PART_ALREADY_REDEEMED + hex(word(nonce)) + hex(token.id.bytes);
  const { ret, conAnchors, accepted } = await consolidateAndAccept(c, bridge, token, nonce, labelByCertificate, refusal);
  assert.equal(hex(ret.verified.outcome.nullifier), saved.nullifier, 'the fresh proof carries the redeemed burn\'s nullifier');
  const newest = (saved.anchors as { round: string }[]).reduce((m, a) => (BigInt(a.round) > m ? BigInt(a.round) : m), 0n);
  assert.ok(BigInt(conAnchors[0].round) > newest, `the fresh proof's seal (round ${conAnchors[0].round}) is newer than every saved anchor (${newest})`);
  assert.notEqual(sha(ret.encoded), saved.envelope.sha256, 'the fresh envelope is not the saved one');

  const record = {
    nonce, nullifier: saved.nullifier,
    conflictingBurn: { stateId: hex(csid.data), recipient: THIRD_PARTY_ADDR, submission: submitted, servedTransactionHash: hex(served.certificationData.transactionHash.data),
      conflictingTransactionHash: hex(ccd.transactionHash.data), pluginRefusal: conflictingRefused },
    freshReplay: { anchors: conAnchors, newestSavedRound: newest, envelopeSha256: sha(ret.encoded), envelopeBytes: ret.encoded.length, refusedAtBlock: accepted, revertData: refusal },
  };
  writeFileSync(`${dir}/negatives.json`, toJson(record));
  console.log('NEGATIVES', toJson({ conflictingSubmission: submitted, freshSeal: conAnchors[0], refusedAtBlock: accepted }));
}


// ---- split negatives (split plan PR5: a part of a split token, live) -----------------------------------------------------------------------
/** BridgeVault's BridgeRejected(uint256): the composition (BRIDGE_COMPOSE_V2) refused the redemption with a nonzero status. */
const BRIDGE_REJECTED = '0x2896c49d';
const STATUS_V2 = JSON.parse(readFileSync(new URL('../../protocol/vectors/split/config/compose-status-v2.json', import.meta.url), 'utf8')) as { code: number; name: string }[];

/** One byte string replaced by another of the same length, exactly once in `b`. */
function replaceOnce(b: Uint8Array, from: Uint8Array, to: Uint8Array, what: string): Uint8Array {
  assert.equal(from.length, to.length);
  const h = hex(b);
  const at = h.indexOf(hex(from));
  assert.ok(at >= 0 && at % 2 === 0 && h.indexOf(hex(from), at + 2) < 0, `${what}: the bytes occur exactly once in the envelope`);
  return unhex(h.slice(0, at) + hex(to) + h.slice(at + from.length * 2));
}

/**
 * The live negatives of a split part (bft-core rehearse_bridge.py `split`), on a tester wallet: PART is a burned, not yet redeemed part, PARENT a split
 * (manifest-burned) ancestor. Every refusal is the chain's own: an eth_call of the vault (BridgeRejected with the V2 status, or the vault's error).
 *  - the parent returned: its envelope (assembled, since the plug-in refuses to build it) is refused by the composition;
 *  - the part's envelope with its return recipient, or its amount in its mint, changed: refused (the certified transaction hashes no longer match);
 *  - an underfunded redemption runs out of gas: status 0, the vault unchanged;
 *  - the same envelope submitted twice at once by two submitters: one credit, the other reverts; the vault records the part's nullifier once.
 * The part ends redeemed by this command. Writes split-negatives.json next to the part.
 */
async function splitNegatives(cfgPath: string, wallet: string, partId: string, parentId: string): Promise<void> {
  const c = ctx(cfgPath);
  const { cfg, dep, bridge } = await installedBridge(c);
  const vault = c.lane.vault;
  const read = (id: string) => Uint8Array.from(readFileSync(`${wallet}/tokens/${id}/token.cbor`));
  const part = await Token.fromCBOR(read(partId));
  const parent = await Token.fromCBOR(read(parentId));
  const status = (revert: string | undefined): { revert: string; code: number; name: string } => {
    assert.ok(revert?.startsWith(BRIDGE_REJECTED), `refused by the composition (BridgeRejected): ${revert}`);
    const code = Number(BigInt(`0x${revert!.slice(10, 74)}`));
    assert.ok(code !== 0, 'a nonzero status');
    return { revert: revert!, code, name: STATUS_V2.find((s) => s.code === code)?.name ?? `status ${code}` };
  };
  const latest = async () => (await rpc(c.eth, 'eth_blockNumber', [])) as string;
  const out: Json = { part: partId, parent: parentId };

  // the part's own envelope, as certified (any age), once the registry's origin covers its anchors
  const built = await buildReturnProof(bridge, part);
  const lin = built.verified.lineage!;
  const nonce = built.verified.outcome.nonce;
  const data = redeemCalldata(built.encoded);
  await until('the vault accepts the part\'s envelope (eth_call)', 240_000, async () => ((await callVault(c.eth, vault, data, await latest())).result ? true : undefined));
  const partAmount = BigInt(`0x${hex(lin.partAmount)}`);
  const recipient = `0x${hex(built.verified.outcome.releaseTo)}`;
  out.partAmount = partAmount;
  out.depth = lin.depth;

  // 1. the parent returned: the plug-in refuses to build it; the chain refuses the envelope assembled anyway
  let pluginRefusal = '';
  try {
    await buildReturnProof(bridge, parent);
  } catch (e) {
    pluginRefusal = String(e).slice(0, 200);
  }
  assert.ok(pluginRefusal, 'the plug-in refuses to build a return of a split parent');
  const chain = isSplitReason(parent.genesis.justification) ? lineageProofs(await splitChain(parent)) : [parent.genesis, ...parent.transactions].map((x) => x.inclusionProof);
  const parentEnv = assembleEnvelope(dep, projectToken(parent), chain).encoded;
  out.parentReturn = { pluginRefusal, chain: status((await callVault(c.eth, vault, redeemCalldata(parentEnv), await latest())).revert) };

  // 2. the return recipient changed in the part's burn (R), and 3. the part's amount changed in its own mint's value
  const other = unhex('000000000000000000000000000000000000dead');
  out.changedRecipient = status((await callVault(c.eth, vault, redeemCalldata(replaceOnce(built.encoded, built.verified.outcome.releaseTo, other, 'the recipient')), await latest())).revert);
  const value = valueEnvelope(cfg.aid, lin.partAmount);
  const more = valueEnvelope(cfg.aid, amountBytes(partAmount + 1n));
  out.changedAmount = status((await callVault(c.eth, vault, redeemCalldata(replaceOnce(built.encoded, value, more, 'the part\'s value')), await latest())).revert);

  // the vault's view of this lock and part, at one block
  const view = async (block: string) => {
    const at = (sig: string, ...args: string[]): string => c.cast('call', vault, sig, ...args, '--block', block).split(' ')[0];
    return {
      spentPart: at('spentPart(uint256,bytes32)(bytes32)', nonce.toString(), `0x${hex(lin.partTokenId)}`), redeemedAmount: at('redeemedAmount(uint256)(uint256)', nonce.toString()),
      remaining: at('remaining(uint256)(uint256)', nonce.toString()), claimable: at('claimable(address)(uint256)', recipient),
      balance: BigInt(await rpc(c.eth, 'eth_getBalance', [vault, block])).toString(),
    };
  };

  // 4. out of gas: well under the estimate (above the calldata floor), status 0 and nothing changed
  for (const a of [THIRD_PARTY_ADDR]) if (BigInt(await rpc(c.eth, 'eth_getBalance', [a, 'latest'])) < 10n ** 17n) await sendAll(c, a, '', [], DEPLOYER_KEY, '100000', '1000000000000000000');
  const estimate = BigInt(await rpc(c.eth, 'eth_estimateGas', [{ from: THIRD_PARTY_ADDR, to: vault, data }, 'latest']));
  const low = (estimate * 2n) / 3n;
  assert.ok(low >= calldataFloor(data), 'the underfunded limit is above the calldata floor (the transaction is admitted)');
  const before = await view(await latest());
  const oog = await sendData(c, vault, data, THIRD_PARTY_KEY, low.toString());
  const afterOog = await view(oog.blockNumber);
  assert.equal(oog.status, '0x0', 'the underfunded redemption reverts');
  assert.deepEqual(afterOog, before, 'the underfunded redemption changed nothing in the vault');
  out.outOfGas = { status: oog.status, gasLimit: low, estimate, gasUsed: BigInt(oog.gasUsed), block: oog.blockNumber, vaultUnchanged: true };

  // 5. the same envelope from two submitters at once: both signed and published before either is mined
  const gas = (estimate * 3n) / 2n + 100_000n;
  const [a, b] = await Promise.all([sendData(c, vault, data, DEPLOYER_KEY, gas.toString()), sendData(c, vault, data, THIRD_PARTY_KEY, gas.toString())]);
  const ok = [a, b].filter((r) => r.status === '0x1');
  assert.equal(ok.length, 1, `exactly one of the two submissions redeems: ${a.status} ${b.status}`);
  const after = await view(await latest());
  const credited = BigInt(after.claimable) - BigInt(before.claimable);
  assert.equal(credited, partAmount, 'the recipient is credited the part\'s amount once');
  assert.equal(BigInt(before.remaining) - BigInt(after.remaining), partAmount, 'the lock\'s remaining falls by the part\'s amount once');
  assert.equal(after.spentPart.toLowerCase(), `0x${hex(lin.nullifier)}`, 'the vault records the part\'s nullifier');
  const refused = await callVault(c.eth, vault, data, await latest());
  assert.equal(refused.revert, `${PART_ALREADY_REDEEMED}${hex(word(nonce))}${hex(lin.partTokenId)}`, 'a third submission is refused as PartAlreadyRedeemed');
  out.duplicate = { statuses: [a.status, b.status], blocks: [a.blockNumber, b.blockNumber], credited, before, after, thirdRefusal: refused.revert };
  writeFileSync(`${wallet}/tokens/${partId}/split-negatives.json`, toJson(out));
  console.log('SPLIT NEGATIVES', toJson(out));
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
  case 'consolidated':
    await consolidated(cfgPath, arg3);
    break;
  case 'long-history':
    await longHistory(cfgPath, arg3);
    break;
  case 'negatives':
    await negatives(cfgPath, arg3);
    break;
  case 'split-negatives':
    await splitNegatives(cfgPath, arg3, rest[0], rest[1]);
    break;
  default:
    throw new Error('usage: anyage.ts save <lane-config> [<out-dir>] | verify <lane-config> <saved.json> --epoch current|historical | release <lane-config> <saved.json> | consolidated <lane-config> [<out-dir>] | long-history <lane-config> [<out-dir>] | negatives <lane-config> <saved.json> | split-negatives <lane-config> <tester-wallet> <part-id> <parent-id>');
}
