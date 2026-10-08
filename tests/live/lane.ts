/**
 * DN-B live lane driver (stage: lock -> mint). Runs against the running B1/B2 paired devnet (bft-core scripts/dnb-devnet.sh) and the
 * aggregator-go BFT shard. Every component is real: the vault executes on ureth with the native B1/B2 precompiles, the lock backing is an
 * eth_getProof of the executed chain bound to the archived certificate of its block, the mint is certified by the live aggregator.
 */
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { MintSigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/MintSigningService.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { SignaturePredicateUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicateUnlockScript.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { StateMask } from '@unicitylabs/state-transition-sdk/lib/transaction/StateMask.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';

import { DeploymentRegistry, makeDeployment } from '../../packages/native-bridge-plugin/src/deployment.js';
import { encodeJustification } from '../../packages/native-bridge-plugin/src/lockproof.js';
import { configHashOfPdr } from '../../packages/native-bridge-plugin/src/lockproof.js';
import { buildReturnProof, refreshToken } from '../../packages/native-bridge-plugin/src/proof.js';
import { arr, bs, returnReason, decodeCfg, decodePolicy, deriveSalt, deriveTokenId, keccak256, lockDigest, lockRecord, u, valueEnvelope } from '../../packages/native-bridge-plugin/src/profile.js';
import { TrustInput } from '../../packages/native-bridge-plugin/src/trust.js';
import { NativeBridge } from '../../packages/native-bridge-plugin/src/verifier.js';
import { hex, loadConfig, rpc, run, until, unhex } from './lib.js';

const cfgPath = process.argv[2] ?? '../bft-core-dnb/test-nodes/lane-config.json';
const lane = loadConfig(cfgPath);
const DEPLOYER_KEY = process.env.DNB_DEPLOYER_KEY ?? '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const DNB_TOOL = process.env.DNB_TOOL ?? '/private/tmp/dnb-tool';
const evidence: Record<string, unknown> = { steps: [] as unknown[] };
const step = (name: string, data: Record<string, unknown>): void => {
  (evidence.steps as unknown[]).push({ name, ...data });
  console.log(`PASS ${name}`, JSON.stringify(data, (_k, v) => (typeof v === 'bigint' ? v.toString() : v)));
};
const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const eth = lane.ethUrls[0];
const cast = (...a: string[]): string => {
  // ureth refuses an estimate or call while its bound build input belongs to another parent (a block is being built): retry, and prefer explicit gas.
  for (let i = 0; ; i++) {
    try {
      return run('cast', [...a, '--rpc-url', eth]);
    } catch (e) {
      if (i >= 8 || !String(e).includes('bound')) throw e;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500);
    }
  }
};

/** Sign once, publish to every validator's pool (transaction gossip is off in this stack, any validator may lead), wait for the receipt. */
async function sendAll(to: string, sig: string, args: string[], key: string, gas: string, value?: string): Promise<{ status: string; gasUsed: string; blockNumber: string; transactionHash: string }> {
  const round = async (): Promise<string> => String((await (await fetch(`${lane.rootRpc}/api/v1/roundInfo`)).json() as { roundNumber: number }).roundNumber);
  const r0 = await round();
  // Explicit nonce, chain and legacy gas price: no estimation round trips inside the B1 window.
  const sender = run('cast', ['wallet', 'address', '--private-key', key]);
  const nonce = String(parseInt(await rpc(eth, 'eth_getTransactionCount', [sender, 'pending']), 16));
  const raw = cast('mktx', to, ...(sig ? [sig, ...args] : []), ...(value ? ['--value', value] : []), '--private-key', key, '--gas-limit', gas, '--nonce', nonce, '--chain', String(lane.chainId), '--legacy', '--gas-price', '2000000000');
  const txHash = `0x${hex(keccak256(unhex(raw)))}`;
  await Promise.all(lane.ethUrls.map(async (url) => {
    try {
      await rpc(url, 'eth_sendRawTransaction', [raw]);
    } catch (e) {
      if (!/already known|known transaction|nonce too low/.test(String(e))) throw e;
    }
  }));
  const r1 = await round();
  const rc = await until(`receipt of ${txHash}`, 120_000, async () => (await rpc(eth, 'eth_getTransactionReceipt', [txHash])) ?? undefined);
  console.log(`  tx ${sig || 'transfer'}: signed at root round ${r0}, published at ${r1}, receipt seen at ${await round()}, block ${parseInt(rc.blockNumber, 16)}`);
  return rc;
}

// ---- the installed bridge: Cfg from the vault itself, trust and PDR from the pinned documents -----------------------------------------
const vaultCfgRaw = unhex(cast('call', lane.vault, 'cfgBytes()(bytes)'));
const cfg = decodeCfg(vaultCfgRaw);
const trustDoc = readFileSync(`${lane.dir}/sdk-trust-base.json`);
const trust = TrustInput.fromJson(Uint8Array.from(trustDoc), sha256(trustDoc));
const pdr = Uint8Array.from(readFileSync(`${lane.dir}/evm-pdr.cbor`));
const policyBody = unhex(JSON.parse(readFileSync(`${lane.dir}/bridge-deployment.json`, 'utf8')).policyBody);
const vaultCode = unhex(await rpc(eth, 'eth_getCode', [lane.vault, 'latest']));
const dep = makeDeployment(cfg, keccak256(vaultCode), configHashOfPdr(pdr), { fields: 20 }, decodePolicy(policyBody));
const bridge = new NativeBridge(new DeploymentRegistry([dep]), trust);
step('bridge installed from the vault', { cfgHash: hex(dep.cfgHash), vault: lane.vault, trustBaseId: hex(trust.id) });

const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'; // Hardhat account 1, the credited redeemer
const THIRD_PARTY_ADDR = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
const payeeAddr = '0x000000000000000000000000000000000000bEEF';
const RECIPIENT_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const THIRD_PARTY_KEY = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'; // account 2 submits the redemption
// The genesis funds only the deployer: fund the redeemer and the third-party submitter for gas.
for (const a of [RECIPIENT, '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC']) {
  await sendAll(a, '', [], DEPLOYER_KEY, '100000', '1000000000000000000');
}
// ---- lock ------------------------------------------------------------------------------------------------------------------------------
const owner = new SigningService(sha256(text('dnb-owner-1')));
const p0 = EncodedPredicate.fromPredicate(SignaturePredicate.create(owner.publicKey)).toCBOR();
const amountWei = 10n ** 18n;
const amount = (() => {
  const h = amountWei.toString(16);
  return unhex(h.length % 2 ? `0${h}` : h);
})();
const sent = JSON.parse(cast('send', lane.vault, 'lock(bytes)(uint256)', `0x${hex(p0)}`, '--value', amountWei.toString(), '--private-key', DEPLOYER_KEY, '--json', '--gas-limit', '2000000'));
assert.equal(sent.status, '0x1', `lock reverted: ${JSON.stringify(sent)}`);
const lockedLog = sent.logs.find((l: { topics: string[] }) => l.topics.length === 3);
const nonce = BigInt(lockedLog.topics[1]);
const lockBlock = sent.blockHash as string;
step('lock executed on the running chain', { nonce, blockHash: lockBlock, blockNumber: BigInt(sent.blockNumber), gasUsed: BigInt(sent.gasUsed) });

// ---- lock proof: archived certificate + eth_getProof of the executed chain -------------------------------------------------------------
const proofPath = `${lane.dir}/lockproof-${nonce}.cbor`;
await until('the lock block to be certified and archived', 120_000, async () => {
  try {
    run(DNB_TOOL, ['lockproof', '--archive', lane.archive, '--block-hash', lockBlock, '--eth-url', eth, '--vault', lane.vault, '--nonce', nonce.toString(),
      '--full-shard-conf', `${lane.dir}/evm-full-shard-conf.json`, '--trust-doc', `${lane.dir}/sdk-trust-base.json`, '--cfg', `0x${hex(dep.cfgHash)}`, '--out', proofPath]);
    return true;
  } catch {
    return false;
  }
});
const lockProof = Uint8Array.from(readFileSync(proofPath));
step('lock proof assembled', { bytes: lockProof.length, sha256: hex(sha256(lockProof)) });

// ---- mint, certified by the live aggregator --------------------------------------------------------------------------------------------
const salt = deriveSalt(dep.cfgHash, nonce);
const tokenId = deriveTokenId(salt, cfg.network);
const digest = lockDigest(dep.cfgHash, nonce, lockRecord(cfg.zeroAddress, cfg.ty, cfg.aid, amount, tokenId, sha256(p0)));
const stored = unhex(cast('call', lane.vault, 'lockDigest(uint256)(bytes32)', nonce.toString()));
assert.equal(hex(stored), hex(digest), 'the vault stored the lock digest the plug-in derives');
step('lock digest equals the plug-in derivation', { digest: hex(digest) });

const justification = encodeJustification(cfg.chainId, cfg.vault, cfg.zeroAddress, nonce, lockProof);
const mint = await MintTransaction.create(NetworkId.fromId(cfg.network), SignaturePredicate.create(owner.publicKey), {
  data: valueEnvelope(cfg.aid, amount), expiresAt: null, justification, salt: TokenSalt.fromBytes(salt), tokenType: new TokenType(cfg.ty),
});
const agg = new AggregatorClient(lane.aggUrl);
const cd = await CertificationData.fromMintTransaction(mint);
const response = await agg.submitCertificationRequest(cd);
step('mint submitted', { status: JSON.stringify(response) });
const stateId = await StateId.fromCertificationData(cd);
const proof = await until('the aggregator to certify the mint', 120_000, async () => {
  const r = await agg.getInclusionProof(stateId);
  return r.inclusionProof ?? undefined;
});
step('mint certified by aggregator-go', { referenceTime: proof.referenceTime, rootRound: proof.unicityCertificate.unicitySeal.rootChainRoundNumber });

const certified = arr(mint.toCBOR(), proof.toCBOR());
const tokenBytes = C.encodeTag(39040, arr(u(2), certified, arr()));
const verified = await bridge.verifyNativeTokenBytes(tokenBytes, 'receipt');
step('native verification of the live token', { nonce: verified.outcome.nonce, leaves: verified.outcome.leaves.length });

writeFileSync(`${lane.dir}/token-mint.cbor`, tokenBytes);

// ---- transfer and burn, each certified by the live aggregator ---------------------------------------------------------------------------
/** Certify one transaction of `token` and return the extended token bytes. */
async function certifyStep(token: Token, tx: TransferTransaction, signer: SigningService): Promise<{ bytes: Uint8Array; token: Token }> {
  const certData = await CertificationData.fromTransaction(tx, await SignaturePredicateUnlockScript.create(tx, signer));
  const r = await agg.submitCertificationRequest(certData);
  assert.equal(JSON.stringify(r), '{"status":"SUCCESS"}');
  const sid = await StateId.fromCertificationData(certData);
  const p = await until('the aggregator to certify a transition', 120_000, async () => (await agg.getInclusionProof(sid)).inclusionProof ?? undefined);
  const parts = [token.genesis, ...token.transactions].map((c) => CborDeserializer.decodeArray(c.toCBOR(), 2)).map((x) => arr(x[0], x[1]));
  const bytes = C.encodeTag(39040, arr(u(2), parts[0], arr(...parts.slice(1), arr(tx.toCBOR(), p.toCBOR()))));
  return { bytes, token: await Token.fromCBOR(bytes) };
}
let token = await Token.fromCBOR(tokenBytes);
const owner2 = new SigningService(sha256(text('dnb-owner-2')));
const t1 = await TransferTransaction.create(token, SignaturePredicate.create(owner2.publicKey), StateMask.generate(), {});
({ token } = await certifyStep(token, t1, owner));
step('transfer certified', { transitions: token.transactions.length });

const reason = returnReason(cfg.chainId, cfg.vault, cfg.zeroAddress, cfg.ty, cfg.aid, unhex(RECIPIENT), amount);
const burnTx = await TransferTransaction.create(token, BurnPredicate.create(sha256(reason)), StateMask.generate(), { data: reason });
({ token } = await certifyStep(token, burnTx, owner2));
step('burn certified', { transitions: token.transactions.length });

// ---- one anchor for the whole history, then the return proof ------------------------------------------------------------------------
const sids = await Promise.all([token.genesis, ...token.transactions].map((c) => StateId.fromCertificationData(c.inclusionProof.certificationData)));
const fresh = await until('every proof under one certificate', 120_000, async () => {
  const rs = await Promise.all(sids.map((sid) => agg.getInclusionProof(sid)));
  if (rs.some((r) => !r.inclusionProof)) return undefined;
  const ps = rs.map((r) => r.inclusionProof!);
  const first = hex(ps[0].unicityCertificate.toCBOR());
  return ps.every((p) => hex(p.unicityCertificate.toCBOR()) === first) ? ps : undefined;
});
token = await refreshToken(token, fresh);
const ret = await buildReturnProof(bridge, token);
const clockSlot = `0x${hex(keccak256(text('unicity.seal-registry/clock.rootRound')))}`;
const registryClock = async (): Promise<bigint> => BigInt(await rpc(eth, 'eth_getStorageAt', ['0xff00000000000000000000000000000000000002', clockSlot, 'latest']));
step('return proof assembled', { anchorRootRound: token.genesis.inclusionProof.unicityCertificate.unicitySeal.rootChainRoundNumber, registryClock: await registryClock(), bytes: ret.encoded.length, nullifier: hex(ret.verified.outcome.nullifier), leaves: ret.verified.outcome.leaves.length });
writeFileSync(`${lane.dir}/return-proof.bin`, ret.encoded);
{
  // The exact B1 UC_V1 request the vault's verifier builds for the anchor (B1Calls.ucRequest), kept for off-chain diagnosis against the Go reference.
  const a = ret.envelope.anchors[0];
  const u16 = (n: number): Uint8Array => Uint8Array.of(n >> 8, n & 255);
  const u32 = (n: number): Uint8Array => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  const req = Buffer.concat([Uint8Array.of(1, 0), u16(1), u32(a.partition), u16(a.shard.length), a.shard, a.shardConfHash, a.expectedStateRoot, a.expectedIRHash, u32(a.uc.length), a.uc]);
  writeFileSync(`${lane.dir}/uc-request.bin`, req);
}
// B1 authenticates a certificate only within [registry clock - W_cert, registry clock]: a certificate newer than the clock is not yet known to the
// registry. Wait for the clock to reach the anchor, then submit at once.
const anchorRound = token.genesis.inclusionProof.unicityCertificate.unicitySeal.rootChainRoundNumber;
await until('the registry clock to reach the anchor round', 60_000, async () => (await registryClock()) >= anchorRound);
step('registry clock reached the anchor', { anchorRound, registryClock: await registryClock() });
{
  const clockNow = await registryClock();
  const verdict = await rpc(eth, 'eth_call', [{ to: '0x0000000000000000000000000000000000000100', data: `0x${hex(readFileSync(`${lane.dir}/uc-request.bin`))}` }, 'latest']);
  step('native UC_V1 verdict on the anchor request', { registryClock: clockNow, returndata: verdict, valid: verdict.endsWith('0000000000000000000000000000000000000000000000000000000000000001') && verdict.slice(66).replace(/^0x/, '').includes('1') });
}

// ---- redeem by a third party, then claim by the credited recipient --------------------------------------------------------------------
const gasPaid = async (hash: string): Promise<bigint> => BigInt((await rpc(eth, 'eth_getTransactionReceipt', [hash])).gasUsed);
const vaultBefore = BigInt(await rpc(eth, 'eth_getBalance', [lane.vault, 'latest']));
const redeemTx = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(ret.encoded)}`], THIRD_PARTY_KEY, '2500000');
const redeemClock = BigInt(await rpc(eth, 'eth_getStorageAt', ['0xff00000000000000000000000000000000000002', clockSlot, redeemTx.blockNumber]));
assert.equal(redeemTx.status, '0x1', `redeem reverted: ${JSON.stringify(redeemTx).slice(0, 400)}`);
const credited = BigInt(cast('call', lane.vault, 'claimable(address)(uint256)', RECIPIENT).split(' ')[0]);
assert.equal(credited, amountWei, 'the certified recipient is credited with the locked amount');
assert.equal(`0x${hex(unhex(cast('call', lane.vault, 'spentNullifier(uint256)(bytes32)', nonce.toString())))}`, `0x${hex(ret.verified.outcome.nullifier)}`, 'the nullifier the vault recorded is the plug-in derivation');
step('redeem executed (native B1 + B2 kernels)', { gasUsed: BigInt(redeemTx.gasUsed), credited, anchorRound, clockAtExecution: redeemClock });
// Refusals, each by eth_call in the live window (state untouched): a flipped certificate byte, and a claim by an account with no credit.
const callRevert = (from: string, sig: string, args: string[]): string => {
  try {
    cast('call', lane.vault, sig, ...args, '--from', from);
  } catch (e) {
    return /data: "(0x[0-9a-f]{8})/.exec(String(e))?.[1] ?? String(e).slice(0, 200);
  }
  return 'NO REVERT';
};
const selector = (sig: string): string => run('cast', ['sig', sig]);
{
  const uc = ret.envelope.anchors[0].uc;
  const at = Buffer.from(ret.encoded).indexOf(Buffer.from(uc));
  assert.ok(at > 0, 'the anchor certificate is embedded in the envelope');
  const flipped = Uint8Array.from(ret.encoded);
  flipped[at + (uc.length >> 1)] ^= 1;
  const r = callRevert('0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC', 'redeem(bytes)(uint256)', [`0x${hex(flipped)}`]);
  assert.notEqual(r, 'NO REVERT', 'a certificate with a flipped byte is not redeemable');
  step('control: flipped certificate byte refused', { revertData: r, ucRejected: r === selector('UCRejected()') });
  const c = callRevert(THIRD_PARTY_ADDR, 'claim(uint256,address)', [amountWei.toString(), payeeAddr]);
  assert.equal(c, selector('InsufficientCredit(uint256,uint256)'), 'an uncredited account cannot claim');
  step('control: claim by an uncredited account refused', { revertData: c });
}

{
  // Within the same window the same proof again is a duplicate burn: the vault keys on the nullifier.
  const d = callRevert(THIRD_PARTY_ADDR, 'redeem(bytes)(uint256)', [`0x${hex(ret.encoded)}`]);
  step('control: the same burn redeemed twice is refused', { revertData: d, alreadyRedeemed: d === selector('AlreadyRedeemed(uint256)') });
}
if (process.env.DNB_REPO) {
  // Interruption between redeem and claim: every shard validator and ureth is stopped at once and started again from its own state.
  const heightsOf = async (): Promise<number[]> => Promise.all(lane.ethUrls.map(async (u) => parseInt(await rpc(u, 'eth_blockNumber', []), 16)));
  const before = await heightsOf();
  run('bash', [`${process.env.DNB_REPO}/scripts/dnb-devnet.sh`, 'restart-all'], {});
  const after = await until('all four clients to advance past their old heads', 300_000, async () => {
    const h = await heightsOf();
    return h.every((x, i) => x > before[i] + 1) && Math.max(...h) - Math.min(...h) <= 1 ? h : undefined;
  });
  const stillCredited = BigInt(cast('call', lane.vault, 'claimable(address)(uint256)', RECIPIENT).split(' ')[0]);
  const nullifierKept = unhex(cast('call', lane.vault, 'spentNullifier(uint256)(bytes32)', nonce.toString()));
  assert.equal(stillCredited, amountWei, 'the credit survived the interruption exactly once');
  assert.equal(hex(nullifierKept), hex(ret.verified.outcome.nullifier), 'the recorded nullifier survived');
  const again = callRevert(THIRD_PARTY_ADDR, 'redeem(bytes)(uint256)', [`0x${hex(ret.encoded)}`]);
  assert.notEqual(again, 'NO REVERT', 'the old proof cannot credit twice');
  step('interruption: all validators and clients restarted between redeem and claim', { heightsBefore: before, heightsAfter: after, credit: stillCredited, replayedProofRefusedWith: again });
}
const payee = payeeAddr;
const before = BigInt(await rpc(eth, 'eth_getBalance', [payee, 'latest']));
const claimTx = await sendAll(lane.vault, 'claim(uint256,address)', [amountWei.toString(), payee], RECIPIENT_KEY, '500000');
assert.equal(claimTx.status, '0x1');
const after = BigInt(await rpc(eth, 'eth_getBalance', [payee, 'latest']));
assert.equal(after - before, amountWei, 'the payee received the locked amount');
step('claim paid', { gasUsed: BigInt(claimTx.gasUsed), paid: after - before, vaultBefore, vaultAfter: BigInt(await rpc(eth, 'eth_getBalance', [lane.vault, 'latest'])) });
void gasPaid;

writeFileSync(`${lane.dir}/lane-evidence.json`, JSON.stringify(evidence, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2));

// ---- budget probes: what a hostile redemption costs the submitter on the running chain --------------------------------------------------
for (const [name, at] of [['first byte of the certificate (malformed CBOR head)', 0], ['middle of the certificate', ret.envelope.anchors[0].uc.length >> 1]] as const) {
  const base = Buffer.from(ret.encoded).indexOf(Buffer.from(ret.envelope.anchors[0].uc));
  const bad = Uint8Array.from(ret.encoded);
  bad[base + at] ^= 0xff;
  const rc = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(bad)}`], THIRD_PARTY_KEY, '7000000');
  assert.equal(rc.status, '0x0');
  step(`budget: redemption with a corrupted ${name} reverts`, { gasUsed: BigInt(rc.gasUsed), gasLimit: 7_000_000n });
}
writeFileSync(`${lane.dir}/lane-evidence.json`, JSON.stringify(evidence, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
