/**
 * DN-B two-shard acceptance rows (B3 design "DN-B two-shard acceptance rows"). Runs against the devnet started with
 * `DNB_AGG_SHARDS=2 scripts/dnb-devnet.sh all` (aggregator-go in bft-shard mode, shards 40 and c0), after `lane.ts` passed there.
 *
 *   npx tsx tests/live/rows.ts <lane-config.json>          # env: DNB_REPO (bft-core checkout, for restarts), AGG_BIN, DNB_TOOL
 *
 * Every row builds its own token from a fresh lock, so rows are independent. Anchor patterns are produced by choosing, per leaf, the
 * proof the aggregator returned when the leaf was certified (its own round) or a freshly fetched one (the shard's current round): the
 * driver only selects among proofs the aggregators really served, and the plug-in never re-queries to make them converge.
 * Evidence: <lane.dir>/rows-evidence.json. Not run yet (needs a unicity-reth binary); typechecked only.
 */
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import type { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { SignaturePredicateUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicateUnlockScript.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { StateMask } from '@unicitylabs/state-transition-sdk/lib/transaction/StateMask.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';

import { DeploymentRegistry, makeDeployment } from '../../packages/native-bridge-plugin/src/deployment.js';
import { encodeEnvelope } from '../../packages/native-bridge-plugin/src/envelope.js';
import { encodeJustification, configHashOfPdr } from '../../packages/native-bridge-plugin/src/lockproof.js';
import { projectToken } from '../../packages/native-bridge-plugin/src/history.js';
import { MAX_ANCHORS, MAX_LEAVES, TX_GAS_BUDGET } from '../../packages/native-bridge-plugin/src/limits.js';
import { buildReturnProof, leafRoutes, preflightBurn, refreshToken } from '../../packages/native-bridge-plugin/src/proof.js';
import { arr, bs, returnReason, decodeCfg, decodePolicy, shardId, shardRow, deriveSalt, deriveTokenId, keccak256, lockDigest, lockRecord, policyBytes, u, valueEnvelope, H } from '../../packages/native-bridge-plugin/src/profile.js';
import { TrustInput } from '../../packages/native-bridge-plugin/src/trust.js';
import { NativeBridge } from '../../packages/native-bridge-plugin/src/verifier.js';
import type { Anchor, Envelope } from '../../packages/native-bridge-plugin/src/envelope.js';
import { hex, loadConfig, rpc, run, until, unhex } from './lib.js';

const lane = loadConfig(process.argv[2] ?? '../bft-core-dnb/test-nodes/lane-config.json');
const DEPLOYER_KEY = process.env.DNB_DEPLOYER_KEY ?? '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const DNB_TOOL = process.env.DNB_TOOL ?? '/private/tmp/dnb-tool';
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const THIRD_PARTY_ADDR = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
const THIRD_PARTY_KEY = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a';
const RECIPIENT_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const REGISTRY = '0xff00000000000000000000000000000000000002';
const W_CERT = Number(process.env.DNB_W_CERT ?? 15);
const REDEEM_GAS = '7000000';
assert.ok(lane.aggUrls && lane.aggUrls.length === 2, 'rows.ts needs the two-shard lane (lane-config aggUrls from DNB_AGG_SHARDS=2)');

const evidence: { rows: Record<string, unknown>[] } = { rows: [] };
const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const json = (v: unknown): string => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x));
const record = (row: string, ok: boolean, data: Record<string, unknown>): void => {
  evidence.rows.push({ row, ok, ...data });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${row}`, json(data));
  writeFileSync(`${lane.dir}/rows-evidence.json`, JSON.stringify(evidence, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
  assert.ok(ok, row);
};
const eth = lane.ethUrls[0];
const cast = (...a: string[]): string => {
  for (let i = 0; ; i++) {
    try {
      return run('cast', [...a, '--rpc-url', eth]);
    } catch (e) {
      if (i >= 8 || !String(e).includes('bound')) throw e;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500);
    }
  }
};
interface Receipt { status: string; gasUsed: string; blockNumber: string; transactionHash: string }
async function sendAll(to: string, sig: string, args: string[], key: string, gas: string, value?: string): Promise<Receipt> {
  const sender = run('cast', ['wallet', 'address', '--private-key', key]);
  const nonce = String(parseInt(await rpc(eth, 'eth_getTransactionCount', [sender, 'pending']), 16));
  const raw = cast('mktx', to, ...(sig ? [sig, ...args] : []), ...(value ? ['--value', value] : []), '--private-key', key, '--gas-limit', gas, '--nonce', nonce, '--chain', String(lane.chainId), '--legacy', '--gas-price', '2000000000');
  const txHash = `0x${hex(keccak256(unhex(raw)))}`;
  const accepted = await Promise.all(lane.ethUrls.map(async (url) => {
    try { await rpc(url, 'eth_sendRawTransaction', [raw]); return true; } catch (e) { return /already known|known transaction/.test(String(e)); }
  }));
  assert.ok(accepted.some(Boolean), `no validator pool accepted ${txHash}`);
  return until(`receipt of ${txHash}`, 120_000, async () => (await rpc(eth, 'eth_getTransactionReceipt', [txHash])) ?? undefined);
}
const clockSlot = `0x${hex(keccak256(text('unicity.seal-registry/clock.rootRound')))}`;
const registryClock = async (): Promise<bigint> => BigInt(await rpc(eth, 'eth_getStorageAt', [REGISTRY, clockSlot, 'latest']));
const selector = (sig: string): string => run('cast', ['sig', sig]);
const callRevert = (from: string, data: Uint8Array): string => {
  try { cast('call', lane.vault, 'redeem(bytes)(uint256)', `0x${hex(data)}`, '--from', from); } catch (e) {
    return /data: "(0x[0-9a-f]{8})/.exec(String(e))?.[1] ?? String(e).slice(0, 200);
  }
  return 'NO REVERT';
};

// ---- the installed bridge ------------------------------------------------------------------------------------------------------------
const cfg = decodeCfg(unhex(cast('call', lane.vault, 'cfgBytes()(bytes)')));
const trustDoc = readFileSync(`${lane.dir}/sdk-trust-base.json`);
const pdr = Uint8Array.from(readFileSync(`${lane.dir}/evm-pdr.cbor`));
const policyBody = unhex(JSON.parse(readFileSync(`${lane.dir}/bridge-deployment.json`, 'utf8')).policyBody);
const dep = makeDeployment(cfg, keccak256(unhex(await rpc(eth, 'eth_getCode', [lane.vault, 'latest']))), configHashOfPdr(pdr), { fields: 20 }, decodePolicy(policyBody));
const bridge = new NativeBridge(new DeploymentRegistry([dep]), TrustInput.fromJson(Uint8Array.from(trustDoc), sha256(trustDoc)));
assert.equal(dep.policy.depth, 1, 'the two-shard rows need the depth-1 policy');
const aggs = lane.aggUrls!.map((url) => new AggregatorClient(url));
const rowOfSid = (sid: Uint8Array): number => shardRow(dep.policy, sid);
const aggOf = (sid: StateId): AggregatorClient => aggs[rowOfSid(sid.data)];
for (const a of [RECIPIENT, THIRD_PARTY_ADDR]) await sendAll(a, '', [], DEPLOYER_KEY, '100000', '1000000000000000000');

// ---- token construction with steered shards ------------------------------------------------------------------------------------------
const amountWei = 10n ** 18n;
const amount = (() => { const h = amountWei.toString(16); return unhex(h.length % 2 ? `0${h}` : h); })();
let ownerCounter = 0;
const newSigner = (): SigningService => new SigningService(sha256(text(`dnb-rows-owner-${Date.now()}-${ownerCounter++}`)));
const sidOfNext = async (tx: { recipient: EncodedPredicate; calculateStateHash(): Promise<{ data: Uint8Array }> }): Promise<Uint8Array> =>
  H(arr(tx.recipient.toCBOR(), bs((await tx.calculateStateHash()).data)));

interface Built { token: Token; owner: SigningService; row0: number; nonce: bigint }

/** Lock, certify the lock block, mint through the leaf's own shard. `leaf1` steers the first transfer's shard relative to the mint's. */
async function lockAndMint(leaf1: 'same' | 'other' | null): Promise<Built> {
  for (let attempt = 0; attempt < 16; attempt++) {
    const owner = newSigner();
    const p0 = EncodedPredicate.fromPredicate(SignaturePredicate.create(owner.publicKey)).toCBOR();
    const sent = JSON.parse(cast('send', lane.vault, 'lock(bytes)(uint256)', `0x${hex(p0)}`, '--value', amountWei.toString(), '--private-key', DEPLOYER_KEY, '--json', '--gas-limit', '2000000'));
    assert.equal(sent.status, '0x1', 'lock');
    const nonce = BigInt(sent.logs.find((l: { topics: string[] }) => l.topics.length === 3).topics[1]);
    const proofPath = `${lane.dir}/rows-lockproof-${nonce}.cbor`;
    await until('the lock block to be certified and archived', 120_000, async () => {
      try {
        run(DNB_TOOL, ['lockproof', '--archive', lane.archive, '--block-hash', sent.blockHash, '--eth-url', eth, '--vault', lane.vault, '--nonce', nonce.toString(),
          '--full-shard-conf', `${lane.dir}/evm-full-shard-conf.json`, '--trust-doc', `${lane.dir}/sdk-trust-base.json`, '--cfg', `0x${hex(dep.cfgHash)}`, '--out', proofPath]);
        return true;
      } catch { return false; }
    });
    const salt = deriveSalt(dep.cfgHash, nonce);
    const justification = encodeJustification(cfg.chainId, cfg.vault, cfg.zeroAddress, nonce, Uint8Array.from(readFileSync(proofPath)));
    const mint = await MintTransaction.create(NetworkId.fromId(cfg.network), SignaturePredicate.create(owner.publicKey), {
      data: valueEnvelope(cfg.aid, amount), expiresAt: null, justification, salt: TokenSalt.fromBytes(salt), tokenType: new TokenType(cfg.ty),
    });
    const sid1 = H(arr(mint.recipient.toCBOR(), bs((await mint.calculateStateHash()).data)));
    const cd = await CertificationData.fromMintTransaction(mint);
    const sid0 = await StateId.fromCertificationData(cd);
    const row0 = rowOfSid(sid0.data);
    const rel = rowOfSid(sid1) === row0 ? 'same' : 'other';
    if (leaf1 !== null && rel !== leaf1) continue; // the first transfer's shard is fixed by the lock: lock again
    await aggOf(sid0).submitCertificationRequest(cd);
    const proof = await until('the mint to be certified', 120_000, async () => (await aggOf(sid0).getInclusionProof(sid0)).inclusionProof ?? undefined);
    const tokenBytes = C.encodeTag(39040, arr(u(2), arr(mint.toCBOR(), proof.toCBOR()), arr()));
    return { token: await Token.fromCBOR(tokenBytes), owner, row0, nonce };
  }
  throw new Error('no lock gave the requested first-transfer shard');
}

const partsOf = (token: Token): Uint8Array[] => [token.genesis, ...token.transactions].map((c) => CborDeserializer.decodeArray(c.toCBOR(), 2)).map((x) => arr(x[0], x[1]));

/** One certified transition. `next` is the owner of the new state, or 'burn'. `rel` steers the NEXT leaf's shard relative to row0 (not for a burn). */
async function extend(b: Built, next: SigningService | 'burn', rel: 'same' | 'other' | null): Promise<Built> {
  const reason = returnReason(cfg.chainId, cfg.vault, cfg.zeroAddress, cfg.ty, cfg.aid, unhex(RECIPIENT), amount);
  let tx: TransferTransaction | undefined;
  for (let i = 0; i < 64 && !tx; i++) {
    const cand = next === 'burn'
      ? await TransferTransaction.create(b.token, BurnPredicate.create(sha256(reason)), StateMask.generate(), { data: reason })
      : await TransferTransaction.create(b.token, SignaturePredicate.create(next.publicKey), StateMask.generate(), {});
    if (next === 'burn' || rel === null || (rowOfSid(await sidOfNext(cand)) === b.row0) === (rel === 'same')) tx = cand;
  }
  assert.ok(tx, 'a mask steering the next leaf was found');
  const cd = await CertificationData.fromTransaction(tx, await SignaturePredicateUnlockScript.create(tx, b.owner));
  const sid = await StateId.fromCertificationData(cd);
  const r = await aggOf(sid).submitCertificationRequest(cd);
  assert.equal(json(r), '{"status":"SUCCESS"}');
  const p = await until('a transition to be certified', 120_000, async () => (await aggOf(sid).getInclusionProof(sid)).inclusionProof ?? undefined);
  const bytes = C.encodeTag(39040, arr(u(2), partsOf(b.token)[0], arr(...partsOf(b.token).slice(1), arr(tx.toCBOR(), p.toCBOR()))));
  return { ...b, token: await Token.fromCBOR(bytes), owner: next === 'burn' ? b.owner : next };
}

/** A token of `leaves` leaves (mint, leaves-2 transfers, burn). `rels[i]` steers leaf i+2 relative to the mint's shard (leaf 1: `leaf1`). */
async function buildToken(leaves: number, leaf1: 'same' | 'other' | null, rels: ('same' | 'other' | null)[] = []): Promise<Built> {
  let b = await lockAndMint(leaf1);
  for (let k = 0; k < leaves - 2; k++) b = await extend(b, newSigner(), rels[k] ?? null);
  return extend(b, 'burn', null);
}

/** The proofs a mix selects: per leaf the proof served when the leaf was certified, or the shard's current one. */
async function mix(token: Token, fresh: boolean[]): Promise<Token> {
  const all = [token.genesis, ...token.transactions];
  const sids = await Promise.all(all.map((c) => StateId.fromCertificationData(c.inclusionProof.certificationData)));
  const proofs: InclusionProof[] = await Promise.all(all.map(async (c, i) => {
    if (!fresh[i]) return c.inclusionProof;
    return until('a current proof', 60_000, async () => (await aggOf(sids[i]).getInclusionProof(sids[i])).inclusionProof ?? undefined);
  }));
  return refreshToken(token, proofs);
}

interface Outcome { receipt: Receipt; anchors: number; leaves: number; gasUsed: bigint; credited: bigint; calls: { uc: number; rsmt: number } | null; gate: number }

async function countCalls(txHash: string): Promise<{ uc: number; rsmt: number } | null> {
  try {
    const t = await rpc(eth, 'debug_traceTransaction', [txHash, { tracer: 'callTracer' }]);
    const n = { uc: 0, rsmt: 0 };
    const walk = (c: { to?: string; calls?: unknown[] }): void => {
      if (c.to?.toLowerCase() === '0x0000000000000000000000000000000000000100') n.uc++;
      if (c.to?.toLowerCase() === '0x0000000000000000000000000000000000000102') n.rsmt++;
      (c.calls ?? []).forEach((x) => walk(x as { to?: string; calls?: unknown[] }));
    };
    walk(t);
    return n;
  } catch { return null; }
}

const claimable = (): bigint => BigInt(cast('call', lane.vault, 'claimable(address)(uint256)', RECIPIENT).split(' ')[0]);
const anchorRoundOf = (token: Token): { min: bigint; max: bigint } => {
  const rs = [token.genesis, ...token.transactions].map((c) => c.inclusionProof.unicityCertificate.unicitySeal.rootChainRoundNumber);
  return { min: rs.reduce((a, b) => (a < b ? a : b)), max: rs.reduce((a, b) => (a > b ? a : b)) };
};
/** B1 authenticates a certificate only within [clock - W_cert, clock]: wait for the newest anchor, check the oldest is inside the window, submit at once. */
async function waitWindow(token: Token): Promise<{ min: bigint; max: bigint; clock: bigint }> {
  const r = anchorRoundOf(token);
  await until('the registry clock to reach the newest anchor', 60_000, async () => (await registryClock()) >= r.max);
  const clock = await registryClock();
  assert.ok(clock - r.min <= BigInt(W_CERT), `the oldest anchor (round ${r.min}) is outside the window at clock ${clock}: this row needs a faster run`);
  return { ...r, clock };
}

async function redeem(token: Token, gas = REDEEM_GAS, tamper?: (e: Uint8Array, env: Envelope) => Uint8Array): Promise<Outcome & { encoded: Uint8Array }> {
  const built = await buildReturnProof(bridge, token);
  await waitWindow(token);
  const before = claimable();
  const data = tamper ? tamper(built.encoded, built.envelope) : built.encoded;
  const receipt = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(data)}`], THIRD_PARTY_KEY, gas);
  return {
    receipt, anchors: built.envelope.anchors.length, leaves: built.envelope.leafProofs.length, gasUsed: BigInt(receipt.gasUsed),
    credited: claimable() - before, calls: await countCalls(receipt.transactionHash), gate: built.gate.total, encoded: built.encoded,
  };
}
const flipIn = (encoded: Uint8Array, uc: Uint8Array, at: number): Uint8Array => {
  const base = Buffer.from(encoded).indexOf(Buffer.from(uc));
  assert.ok(base > 0, 'the certificate is embedded in the envelope');
  const bad = Uint8Array.from(encoded);
  bad[base + at] ^= 0xff;
  return bad;
};
/** The envelope exactly as the plug-in would build it but without its bound checks, so the CHAIN's refusal of an over-bound bundle can be observed. */
async function uncheckedEnvelope(token: Token, anchorIndexOf: (uc: string) => number, ucs: Uint8Array[]): Promise<Uint8Array> {
  const all = [token.genesis, ...token.transactions];
  const routes = await leafRoutes(bridge, token);
  const anchors: Anchor[] = ucs.map((uc, j) => {
    const p = all.find((c) => hex(c.inclusionProof.unicityCertificate.toCBOR()) === hex(uc))!.inclusionProof;
    const r = routes[all.findIndex((c) => c.inclusionProof === p)].row;
    return { partition: dep.policy.partition, shard: shardId(dep.policy, r), shardConfHash: dep.policy.shardConfs[r], expectedStateRoot: p.unicityCertificate.inputRecord.hash,
      expectedIRHash: H(p.unicityCertificate.inputRecord.toCBOR()), uc, inputRecord: p.unicityCertificate.inputRecord.toCBOR() };
  });
  const leafProofs = all.map((c) => {
    const enc = c.inclusionProof.inclusionCertificate.encode();
    return { anchorIndex: anchorIndexOf(hex(c.inclusionProof.unicityCertificate.toCBOR())), bitmap: enc.slice(0, 32), siblings: Array.from({ length: (enc.length - 32) / 32 }, (_, i) => enc.slice(32 + 32 * i, 64 + 32 * i)) };
  });
  return encodeEnvelope({ policyBody: policyBytes(dep.policy), history: projectToken(token), anchors, leafProofs });
}
const distinctUcs = (token: Token): Uint8Array[] => {
  const seen: Uint8Array[] = [];
  for (const c of [token.genesis, ...token.transactions]) {
    const uc = c.inclusionProof.unicityCertificate.toCBOR();
    if (!seen.some((s) => hex(s) === hex(uc))) seen.push(uc);
  }
  return seen;
};

// =====================================================================================================================================
// Rows
// =====================================================================================================================================

/** Rows "1/2/3/4 anchors incl. several on one shard": the redemption succeeds, A calls to 0x0100 and L to 0x0102, the exact credit, gas inside 7M. */
async function acceptedRow(name: string, token: Token, wantAnchors: number): Promise<Outcome> {
  const o = await redeem(token);
  const ok = o.receipt.status === '0x1' && o.anchors === wantAnchors && o.credited === amountWei && o.gasUsed < BigInt(TX_GAS_BUDGET) &&
    (o.calls === null || (o.calls.uc === wantAnchors && o.calls.rsmt === o.leaves));
  record(name, ok, { anchors: o.anchors, leaves: o.leaves, gasUsed: o.gasUsed, gateTotal: o.gate, credited: o.credited, nativeCalls: o.calls, tx: o.receipt.transactionHash });
  return o;
}

// 1 anchor: every leaf in one shard, current proofs.
{
  const b = await buildToken(3, 'same', ['same']);
  const t = await mix(b.token, [true, true, true]);
  await acceptedRow('anchors=1 (one shard, one UC)', t, 1);
}
// 2 anchors: leaves of both shards, current proofs: one UC per shard.
{
  const b = await buildToken(3, 'same', ['other']);
  const t = await mix(b.token, [true, true, true]);
  await acceptedRow('anchors=2 (two shards, one UC each)', t, 2);
}
// several UCs on ONE shard: the mint's own round for leaf 0, a later round for the rest, all in one shard.
{
  const b = await buildToken(3, 'same', ['same']);
  const t = await mix(b.token, [false, true, true]);
  await acceptedRow('anchors=2 (two different-round UCs of ONE shard)', t, 2);
}
// 3 and 4 anchors: every leaf under the proof served when it was certified (its own round), mixed shards, several on one shard.
{
  const b = await buildToken(3, 'same', ['other']);
  await acceptedRow('anchors=3 (own-round proofs)', await mix(b.token, [false, false, false]), 3);
}
{
  const b = await buildToken(4, 'same', ['other', 'same']);
  await acceptedRow('anchors=4 (own-round proofs, several on one shard)', await mix(b.token, [false, false, false, false]), 4);
}
// 5th anchor refused: by the plug-in before submission, and by the chain for the same bundle assembled without the plug-in's bounds.
{
  const b = await buildToken(5, 'same', ['other', 'same', 'other']);
  const t = await mix(b.token, [false, false, false, false, false]);
  assert.equal(distinctUcs(t).length, MAX_ANCHORS + 1);
  let plugin = 'NO REFUSAL';
  try { await buildReturnProof(bridge, t); } catch (e) { plugin = (e as { reason?: string }).reason ?? String(e); }
  await waitWindow(t);
  const ucs = distinctUcs(t);
  const env = await uncheckedEnvelope(t, (uc) => ucs.findIndex((x) => hex(x) === uc), ucs);
  const before = claimable();
  const rc = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(env)}`], THIRD_PARTY_KEY, REDEEM_GAS);
  const revert = callRevert(THIRD_PARTY_ADDR, env);
  record('anchors=5 refused', plugin === 'ErrPolicyAnchors' && rc.status === '0x0' && revert === selector('BudgetExceeded()') && claimable() === before,
    { plugin, chain: revert, gasUsed: BigInt(rc.gasUsed), creditUnchanged: claimable() === before });
}
// 16 leaves (the bound) redeem; 17 leaves are refused by the burn-time preflight and by the chain.
{
  const b = await buildToken(MAX_LEAVES, 'same', Array.from({ length: MAX_LEAVES - 3 }, (_, i) => (i % 2 ? 'same' : 'other')));
  const t = await mix(b.token, Array(MAX_LEAVES).fill(true));
  const o = await acceptedRow(`leaves=${MAX_LEAVES} (the bound, worst real bundle)`, t, 2);
  record('worst admitted real bundle: gas against the gate', o.gasUsed <= BigInt(o.gate), { gasUsed: o.gasUsed, gate: o.gate, budget: TX_GAS_BUDGET, reserveLeft: BigInt(o.gate) - o.gasUsed });
}
{
  const b = await buildToken(MAX_LEAVES + 1, 'same', Array.from({ length: MAX_LEAVES - 2 }, (_, i) => (i % 2 ? 'same' : 'other')));
  let pre = 'NO REFUSAL';
  try { await preflightBurn(bridge, b.token.toCBOR()); } catch (e) { pre = (e as { reason?: string }).reason ?? String(e); }
  // the held receipt before its burn, for the preflight: drop the burn leaf
  const held = await Token.fromCBOR(C.encodeTag(39040, arr(u(2), partsOf(b.token)[0], arr(...partsOf(b.token).slice(1, -1)))));
  let pre2 = 'NO REFUSAL';
  try { await preflightBurn(bridge, held.toCBOR()); } catch (e) { pre2 = (e as { reason?: string }).reason ?? String(e); }
  const t = await mix(b.token, Array(MAX_LEAVES + 1).fill(true));
  await waitWindow(t);
  const ucs = distinctUcs(t);
  const env = await uncheckedEnvelope(t, (uc) => ucs.findIndex((x) => hex(x) === uc), ucs);
  const before = claimable();
  const rc = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(env)}`], THIRD_PARTY_KEY, REDEEM_GAS);
  record('leaves=17 refused', pre2 === 'ErrTooManyTx' && rc.status === '0x0' && callRevert(THIRD_PARTY_ADDR, env) === selector('BudgetExceeded()') && claimable() === before,
    { preflightOnHeldReceipt: pre2, preflightOnBurned: pre, chain: callRevert(THIRD_PARTY_ADDR, env), gasUsed: BigInt(rc.gasUsed) });
}
// Malformed FINAL anchor: the first anchor verifies, the last is corrupted (or truncated): the whole redemption reverts, inside 7M, nothing credited.
{
  const b = await buildToken(3, 'same', ['other']);
  const t = await mix(b.token, [true, true, true]);
  for (const [what, edit] of [['flipped byte', (uc: Uint8Array) => uc.length >> 1], ['malformed CBOR head', () => 0]] as const) {
    const before = claimable();
    const built = await buildReturnProof(bridge, t);
    const last = built.envelope.anchors[built.envelope.anchors.length - 1].uc;
    assert.ok(built.envelope.anchors.length === 2);
    await waitWindow(t);
    const bad = flipIn(built.encoded, last, edit(last));
    const rc = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(bad)}`], THIRD_PARTY_KEY, REDEEM_GAS);
    record(`malformed final anchor (${what})`, rc.status === '0x0' && BigInt(rc.gasUsed) < BigInt(TX_GAS_BUDGET) && claimable() === before,
      { gasUsed: BigInt(rc.gasUsed), revert: callRevert(THIRD_PARTY_ADDR, bad) });
  }
}
// gas and gas-1: the same two-anchor shape twice. Token A at a generous limit measures the gas used (U); token B is attempted with a limit one
// below U (must fail with nothing credited) and then with the limit the native 63/64 forwarding needs above U (must succeed). The exact
// minimum limit is not searched: the window allows a handful of attempts only.
{
  const a = await buildToken(3, 'same', ['other']);
  const oa = await acceptedRow('gas: reference redemption (two anchors)', await mix(a.token, [true, true, true]), 2);
  const U = oa.gasUsed;
  const b = await buildToken(3, 'same', ['other']);
  const t = await mix(b.token, [true, true, true]);
  const built = await buildReturnProof(bridge, t);
  await waitWindow(t);
  const before = claimable();
  const low = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(built.encoded)}`], THIRD_PARTY_KEY, String(U - 1n));
  const creditedLow = claimable() - before;
  const high = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(built.encoded)}`], THIRD_PARTY_KEY, String(U + U / 32n + 50_000n));
  record('gas-1 fails, gas+headroom succeeds', low.status === '0x0' && creditedLow === 0n && high.status === '0x1' && claimable() - before === amountWei,
    { referenceGasUsed: U, lowLimit: U - 1n, lowStatus: low.status, highLimit: U + U / 32n + 50_000n, highGasUsed: BigInt(high.gasUsed) });
}
// Restart and recovery of a pending redemption: burn certified and persisted, both aggregators restarted, proofs fetched again, redeem, then every
// validator restarted between redeem and claim, and the claim paid.
{
  assert.ok(process.env.DNB_REPO, 'the restart row needs DNB_REPO (the bft-core checkout with scripts/dnb-devnet.sh)');
  const sh = `${process.env.DNB_REPO}/scripts/dnb-devnet.sh`;
  const b = await buildToken(3, 'same', ['other']);
  const path = `${lane.dir}/rows-pending-burn.cbor`;
  writeFileSync(path, b.token.toCBOR());
  run('bash', [sh, 'restart-agg'], {});
  const urlsUp = await until('both aggregators to answer', 180_000, async () => (await Promise.all(lane.aggUrls!.map(async (url) => (await fetch(`${url}/health`)).ok))).every(Boolean) || undefined);
  const pending = await Token.fromCBOR(Uint8Array.from(readFileSync(path)));
  const t = await mix(pending, [true, true, true]);
  const o = await redeem(t);
  assert.equal(o.receipt.status, '0x1');
  const heights = async (): Promise<number[]> => Promise.all(lane.ethUrls.map(async (x) => parseInt(await rpc(x, 'eth_blockNumber', []), 16)));
  const h0 = await heights();
  run('bash', [sh, 'restart-all'], {});
  await until('all clients to answer', 300_000, async () => (await heights()).every((x, i) => x >= h0[i]) || undefined);
  const live = await sendAll(RECIPIENT, '', [], DEPLOYER_KEY, '100000', '1');
  assert.equal(live.status, '0x1');
  const stillCredited = claimable() >= amountWei;
  const payee = '0x000000000000000000000000000000000000bEEF';
  const pb = BigInt(await rpc(eth, 'eth_getBalance', [payee, 'latest']));
  const claim = await sendAll(lane.vault, 'claim(uint256,address)', [amountWei.toString(), payee], RECIPIENT_KEY, '500000');
  const pa = BigInt(await rpc(eth, 'eth_getBalance', [payee, 'latest']));
  record('restart: pending redemption recovered, redeem/claim state preserved', urlsUp === true && o.credited === amountWei && stillCredited && claim.status === '0x1' && pa - pb === amountWei,
    { redeemGas: o.gasUsed, creditedOnce: o.credited, paid: pa - pb });
}
console.log(`ROWS COMPLETE: ${evidence.rows.length} rows, evidence ${lane.dir}/rows-evidence.json`);
