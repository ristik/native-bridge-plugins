/**
 * DN-B two-shard acceptance rows (B3 design "DN-B two-shard acceptance rows"). Runs against the devnet started with
 * `DNB_AGG_SHARDS=2 scripts/dnb-devnet.sh all` (aggregator-go in bft-shard mode, shards 40 and c0), after `lane.ts` passed there.
 *
 *   npx tsx tests/live/rows.ts <lane-config.json>          # env: DNB_REPO (bft-core checkout, for restarts), AGG_BIN, DNB_TOOL
 *
 * Every row builds its own token from a fresh lock, so rows are independent. Anchor patterns are produced by choosing, per leaf, the
 * proof the aggregator returned when the leaf was certified (its own round) or a freshly fetched one (the shard's current round): the
 * driver only selects among proofs the aggregators really served, and the plug-in never re-queries to make them converge.
 * Evidence: <lane.dir>/rows-evidence.json. Wallet-path rows (issue #9) use the plug-in freshness contract; the `inWindow` token rebuilding is a test-shape helper only.
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
import { DEFAULT_REDEEM, redeemReturn, type ChainReader, type RedeemPolicy, type RedeemTransport } from '../../packages/native-bridge-plugin/src/freshness.js';
import { createNativeBridgePlugin, type ProofSource } from '../../packages/native-bridge-plugin/src/wallet.js';
import { gasOneHolds, minimalGas } from './gassearch.js';
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
const W_CERT = Number((JSON.parse(readFileSync(`${lane.dir}/b1-profile.json`, 'utf8')) as { wCert: number }).wCert); // the pinned B1 profile is the one source
// A redeem lands in the next EVM block (a few root rounds after it is published), so the oldest anchor must be this many rounds younger than W_CERT when it is sent.
const EXEC_MARGIN = Number(process.env.DNB_EXEC_MARGIN ?? 10); // run 5 measured 8-9 root rounds between a redeem's send and its execution block (origin 195 -> 203, 240 -> 249)
const REDEEM_GAS = '7000000';
assert.ok(lane.aggUrls && lane.aggUrls.length === 2, 'rows.ts needs the two-shard lane (lane-config aggUrls from DNB_AGG_SHARDS=2)');

// The attested ureth binary (sha256 and reported commit) checked by `dnb-devnet.sh up`; a lane without it is not evidence.
const attestation = JSON.parse(readFileSync(`${lane.dir}/ureth-attestation.json`, 'utf8')) as { sha256: string; commit: string };
assert.ok(/^[0-9a-f]{64}$/.test(attestation.sha256) && /^[0-9a-f]{40}$/.test(attestation.commit), 'ureth attestation is complete');
const evidence: { ureth: unknown; groups: string; rows: Record<string, unknown>[] } = { ureth: attestation, groups: process.env.ROWS_ONLY ?? 'all', rows: [] };
const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const json = (v: unknown): string => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x));
// ROWS_ONLY=anchors,refusals,bound,malformed,gas,wallet,restart runs just those groups (a resumed or focused run; the evidence run runs all)
const ONLY = process.env.ROWS_ONLY ? new Set(process.env.ROWS_ONLY.split(',')) : null;
const on = (g: string): boolean => ONLY === null || ONLY.has(g);
const failedRows: string[] = [];
// an unexpected error in one row group is a FAIL row for that group; the other groups still run
const groupFailed = (group: string, e: unknown): void => {
  failedRows.push(`${group}: ${(e as { reason?: string }).reason ?? String(e).slice(0, 160)}`);
  console.log(`FAIL group ${group}`, String(e).slice(0, 600));
  evidence.rows.push({ row: `group ${group}`, ok: false, error: String(e).slice(0, 600) });
  writeFileSync(`${lane.dir}/rows-evidence.json`, JSON.stringify(evidence, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
};
/** Shapes this devnet cannot produce by construction (not failures): the measurement is the result. */
const limitRows: Record<string, unknown>[] = [];
const recordLimit = (row: string, data: Record<string, unknown>): void => {
  limitRows.push({ row, ...data });
  console.log(`LIMIT ${row}`, json(data));
  writeFileSync(`${lane.dir}/rows-limits.json`, JSON.stringify(limitRows, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
};
const record = (row: string, ok: boolean, data: Record<string, unknown>): void => {
  evidence.rows.push({ row, ok, ...data });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${row}`, json(data));
  writeFileSync(`${lane.dir}/rows-evidence.json`, JSON.stringify(evidence, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
  if (!ok) failedRows.push(row);
};
// nothing escapes uncaught: an unexpected throw is a FAILED row and the run still ends with its final line and a non-zero exit
const diedOn = (e: unknown): void => {
  failedRows.push(`driver error: ${(e as { reason?: string }).reason ?? String(e).slice(0, 200)}`);
  console.log(`FAIL driver error`, String(e).slice(0, 600));
  console.log(`ROWS COMPLETE: ${evidence.rows.length} rows, ${failedRows.length} failed (${failedRows.join('; ')}), ${limitRows.length} measured limits, evidence ${lane.dir}/rows-evidence.json`);
  process.exit(1);
};
process.on('uncaughtException', diedOn);
process.on('unhandledRejection', diedOn);
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

/** `mix` without the plug-in's token preflight: the over-bound shapes (17 leaves) the plug-in itself refuses are assembled for the chain this way. */
async function mixRaw(token: Token): Promise<Token> {
  const all = [token.genesis, ...token.transactions];
  const proofs = await Promise.all(all.map(async (c) => {
    const sid = await StateId.fromCertificationData(c.inclusionProof.certificationData);
    return until('a current proof', 60_000, async () => (await aggOf(sid).getInclusionProof(sid)).inclusionProof ?? undefined);
  }));
  const certified = all.map((c, i) => arr(CborDeserializer.decodeArray(c.toCBOR(), 2)[0], proofs[i].toCBOR()));
  return Token.fromCBOR(C.encodeTag(39040, arr(u(2), certified[0], arr(...certified.slice(1)))));
}

interface Outcome { receipt: Receipt; anchors: number; leaves: number; gasUsed: bigint; credited: bigint; calls: { uc: number; rsmt: number } | null; gate: number; diag: Record<string, unknown> }

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
  if (clock - r.min > BigInt(W_CERT - EXEC_MARGIN)) console.log(`  warning: the oldest anchor (round ${r.min}) is older than W_cert - M at clock ${clock}; sending anyway, the diagnostics classify the outcome`);
  return { ...r, clock };
}


/**
 * TEST-SHAPE HELPER ONLY, not wallet recovery and not evidence that an old token can be redeemed: a wallet refreshes the SAME burned token
 * (issue #9). Rows with several own-round UCs need every anchor young enough to still be inside B1's window when the redeem executes. Build the token again
 * (a fresh lock and mint) until the oldest anchor is within W_cert - EXEC_MARGIN of the registry clock once the newest one has landed.
 */
async function inWindow(what: string, build: () => Promise<Token>, attempts = 2): Promise<{ token?: Token; spans: bigint[] }> {
  const spans: bigint[] = [];
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const t = await build();
    const r = anchorRoundOf(t);
    await until('the registry clock to reach the newest anchor', 60_000, async () => (await registryClock()) >= r.max);
    const clock = await registryClock();
    spans.push(clock - r.min);
    if (clock - r.min <= BigInt(W_CERT - EXEC_MARGIN)) return { token: t, spans };
    console.log(`  ${what}: attempt ${attempt} spans ${clock - r.min} rounds (limit ${W_CERT - EXEC_MARGIN})`);
  }
  return { spans };
}
/** An own-round shape that cannot fit the window on this devnet is a measured limit: certification of one leaf takes several root rounds, and a redeem executes 8-9 rounds after it is sent. */
const infeasible = (row: string, what: string, spans: bigint[]): void =>
  recordLimit(row, { shape: what, oldestAnchorAgeWhenNewestImported: spans, allowedAgeAtSend: W_CERT - EXEC_MARGIN, W_CERT, margin: EXEC_MARGIN, result: 'infeasible on this devnet by construction (measured), not a failure' });

/**
 * Why a redemption was or was not accepted, from the chain: every anchor's seal round r_a, the registry origin O at the transaction's own
 * execution block, W_cert, each anchor classified (stale: O - r > W_cert, future: r > O, in-window), the B1 verdict for each anchor's UC_V1
 * request evaluated at that block (state after the block, origin O), and the UC / RSMT calls the transaction really made with their outputs.
 */
async function diagnose(token: Token, built: { envelope: Envelope }, receipt: Receipt, sentClock: bigint): Promise<Record<string, unknown>> {
  const block = receipt.blockNumber;
  const O = BigInt(await rpc(eth, 'eth_getStorageAt', [REGISTRY, clockSlot, block]));
  const O1 = BigInt(await rpc(eth, 'eth_getStorageAt', [REGISTRY, clockSlot, `0x${(BigInt(block) - 1n).toString(16)}`]));
  const roundOfUc = new Map<string, bigint>();
  for (const c of [token.genesis, ...token.transactions]) roundOfUc.set(hex(c.inclusionProof.unicityCertificate.toCBOR()), c.inclusionProof.unicityCertificate.unicitySeal.rootChainRoundNumber);
  const u16 = (n: number): Uint8Array => Uint8Array.of(n >> 8, n & 255);
  const u32 = (n: number): Uint8Array => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  const anchors = [];
  for (const a of built.envelope.anchors) {
    const r = roundOfUc.get(hex(a.uc)) ?? -1n;
    const req = Buffer.concat([Uint8Array.of(1, 0), u16(1), u32(a.partition), u16(a.shard.length), a.shard, a.shardConfHash, a.expectedStateRoot, a.expectedIRHash, u32(a.uc.length), a.uc]);
    let verdict = 'n/a';
    try {
      const v = await rpc(eth, 'eth_call', [{ to: '0x0000000000000000000000000000000000000100', data: `0x${hex(req)}` }, block]);
      verdict = `${BigInt(`0x${v.slice(2, 66)}`)}/${BigInt(`0x${v.slice(66, 130)}`) === 1n ? 'valid' : 'invalid'}`;
    } catch (e) { verdict = `error ${String(e).slice(0, 120)}`; }
    anchors.push({ shard: hex(a.shard), r, class: r > O ? 'future' : O - r > BigInt(W_CERT) ? 'stale' : 'in-window', age: O - r, verdictAtBlock: verdict });
  }
  const ucCalls: Record<string, unknown>[] = [];
  try {
    const t = await rpc(eth, 'debug_traceTransaction', [receipt.transactionHash, { tracer: 'callTracer' }]);
    const walk = (c: { to?: string; output?: string; error?: string; revertReason?: string; gasUsed?: string; calls?: unknown[] }): void => {
      const to = c.to?.toLowerCase();
      if (to === '0x0000000000000000000000000000000000000100' || to === '0x0000000000000000000000000000000000000102') {
        ucCalls.push({ to: to.slice(-3), output: (c.output ?? '').slice(0, 140), error: c.error, revertReason: c.revertReason, gasUsed: c.gasUsed });
      }
      (c.calls ?? []).forEach((x) => walk(x as never));
    };
    walk(t);
  } catch (e) { ucCalls.push({ traceError: String(e).slice(0, 120) }); }
  return { W_CERT, M: EXEC_MARGIN, originAtSend: sentClock, originAtBlock: O, originBeforeBlock: O1, originAdvanceSinceSend: O - sentClock, block, anchors, nativeCalls: ucCalls };
}

async function redeem(token: Token, gas = REDEEM_GAS, tamper?: (e: Uint8Array, env: Envelope) => Uint8Array): Promise<Outcome & { encoded: Uint8Array }> {
  const built = await buildReturnProof(bridge, token);
  const win = await waitWindow(token);
  const before = claimable();
  const data = tamper ? tamper(built.encoded, built.envelope) : built.encoded;
  const receipt = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(data)}`], THIRD_PARTY_KEY, gas);
  return {
    receipt, anchors: built.envelope.anchors.length, leaves: built.envelope.leafProofs.length, gasUsed: BigInt(receipt.gasUsed),
    credited: claimable() - before, calls: await countCalls(receipt.transactionHash), gate: built.gate.total, encoded: built.encoded, diag: await diagnose(token, built, receipt, win.clock),
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
    o.calls !== null && o.calls.uc === wantAnchors && o.calls.rsmt === o.leaves; // an unavailable trace fails the row: the native call counts are part of its claim
  record(name, ok, { anchors: o.anchors, leaves: o.leaves, gasUsed: o.gasUsed, gateTotal: o.gate, credited: o.credited, nativeCalls: o.calls, tx: o.receipt.transactionHash, diag: o.diag });
  return o;
}

// 1 anchor: every leaf in one shard, current proofs.
if (on('anchors')) try {
  const b = await buildToken(3, 'same', ['same']);
  const t = await mix(b.token, [true, true, true]);
  await acceptedRow('anchors=1 (one shard, one UC)', t, 1);
} catch (e) { groupFailed('anchors', e); }
// 2 anchors: leaves of both shards, current proofs: one UC per shard.
if (on('anchors')) try {
  const b = await buildToken(3, 'same', ['other']);
  const t = await mix(b.token, [true, true, true]);
  await acceptedRow('anchors=2 (two shards, one UC each)', t, 2);
} catch (e) { groupFailed('anchors', e); }
// several UCs on ONE shard: the mint's own round for leaf 0, a later round for the rest, all in one shard.
if (on('anchors')) try {
  const w = await inWindow('anchors=2 one shard', async () => mix((await buildToken(3, 'same', ['same'])).token, [false, true, true]));
  if (w.token) await acceptedRow('anchors=2 (two different-round UCs of ONE shard)', w.token, 2);
  else infeasible('anchors=2 (two different-round UCs of ONE shard)', 'mint in its own round, later leaves in a later round, one shard', w.spans);
} catch (e) { groupFailed('anchors', e); }
// 3 and 4 anchors: every leaf under the proof served when it was certified (its own round), mixed shards, several on one shard.
if (on('anchors')) try {
  const w = await inWindow('anchors=3', async () => mix((await buildToken(3, 'same', ['other'])).token, [false, false, false]));
  if (w.token) await acceptedRow('anchors=3 (own-round proofs)', w.token, 3);
  else infeasible('anchors=3 (own-round proofs)', 'three leaves, each under the certificate of its own round', w.spans);
} catch (e) { groupFailed('anchors', e); }
if (on('anchors')) try {
  const w = await inWindow('anchors=4', async () => mix((await buildToken(4, 'same', ['other', 'same'])).token, [false, false, false, false]));
  if (w.token) await acceptedRow('anchors=4 (own-round proofs, several on one shard)', w.token, 4);
  else infeasible('anchors=4 (own-round proofs, several on one shard)', 'four leaves, each under the certificate of its own round', w.spans);
} catch (e) { groupFailed('anchors', e); }
// 5th anchor refused: by the plug-in before submission, and by the chain for the same bundle assembled without the plug-in's bounds.
if (on('refusals')) try {
  // the anchor count is refused before any certificate is judged, so the proofs need not be inside the window
  const t = await mix((await buildToken(5, 'same', ['other', 'same', 'other'])).token, [false, false, false, false, false]);
  assert.equal(distinctUcs(t).length, MAX_ANCHORS + 1);
  let plugin = 'NO REFUSAL';
  try { await buildReturnProof(bridge, t); } catch (e) { plugin = (e as { reason?: string }).reason ?? String(e); }
  const ucs = distinctUcs(t);
  const env = await uncheckedEnvelope(t, (uc) => ucs.findIndex((x) => hex(x) === uc), ucs);
  const before = claimable();
  const rc = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(env)}`], THIRD_PARTY_KEY, REDEEM_GAS);
  const revert = callRevert(THIRD_PARTY_ADDR, env);
  record('anchors=5 refused', plugin === 'ErrTooManyPaths' && rc.status === '0x0' && revert === selector('BudgetExceeded()') && claimable() === before,
    { plugin, chain: revert, gasUsed: BigInt(rc.gasUsed), creditUnchanged: claimable() === before });
} catch (e) { groupFailed('refusals', e); }
// 16 leaves (the bound) redeem; 17 leaves are refused by the burn-time preflight and by the chain.
if (on('bound')) try {
  const b = await buildToken(MAX_LEAVES, 'same', Array.from({ length: MAX_LEAVES - 3 }, (_, i) => (i % 2 ? 'same' : 'other')));
  const t = await mix(b.token, Array(MAX_LEAVES).fill(true));
  const o = await acceptedRow(`leaves=${MAX_LEAVES} (the bound, worst real bundle)`, t, 2);
  record('worst admitted real bundle: gas against the gate', o.gasUsed <= BigInt(o.gate), { gasUsed: o.gasUsed, gate: o.gate, budget: TX_GAS_BUDGET, reserveLeft: BigInt(o.gate) - o.gasUsed });
} catch (e) { groupFailed('bound', e); }
if (on('bound')) try {
  const b = await buildToken(MAX_LEAVES + 1, 'same', Array.from({ length: MAX_LEAVES - 2 }, (_, i) => (i % 2 ? 'same' : 'other')));
  let pre = 'NO REFUSAL';
  try { await preflightBurn(bridge, b.token.toCBOR()); } catch (e) { pre = (e as { reason?: string }).reason ?? String(e); }
  // the held receipt before its burn, for the preflight: drop the burn leaf
  const held = await Token.fromCBOR(C.encodeTag(39040, arr(u(2), partsOf(b.token)[0], arr(...partsOf(b.token).slice(1, -1)))));
  let pre2 = 'NO REFUSAL';
  try { await preflightBurn(bridge, held.toCBOR()); } catch (e) { pre2 = (e as { reason?: string }).reason ?? String(e); }
  const t = await mixRaw(b.token);
  await waitWindow(t);
  const ucs = distinctUcs(t);
  const env = await uncheckedEnvelope(t, (uc) => ucs.findIndex((x) => hex(x) === uc), ucs);
  const before = claimable();
  const rc = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(env)}`], THIRD_PARTY_KEY, REDEEM_GAS);
  record('leaves=17 refused', pre2 === 'ErrTooManyTx' && rc.status === '0x0' && callRevert(THIRD_PARTY_ADDR, env) === selector('BudgetExceeded()') && claimable() === before,
    { preflightOnHeldReceipt: pre2, preflightOnBurned: pre, chain: callRevert(THIRD_PARTY_ADDR, env), gasUsed: BigInt(rc.gasUsed) });
} catch (e) { groupFailed('bound', e); }
// Malformed FINAL anchor: the first anchor verifies, the last is corrupted (or truncated): the whole redemption reverts, inside 7M, nothing credited.
// Each case refetches the same token's proofs and is judged by WHY it reverted: its error selector, the native calls it made (the trace) and
// that every anchor was inside the window at the execution block (a stale first anchor also reverts, with the same UCRejected()).
const nativeCallsOf = async (txHash: string): Promise<{ to: string; valid: boolean | null; error?: string }[]> => {
  const out: { to: string; valid: boolean | null; error?: string }[] = [];
  const t = await rpc(eth, 'debug_traceTransaction', [txHash, { tracer: 'callTracer' }]);
  const walk = (c: { to?: string; output?: string; error?: string; calls?: unknown[] }): void => {
    if (c.to?.toLowerCase() === '0x0000000000000000000000000000000000000100') {
      const o = c.output ?? '';
      out.push({ to: '100', valid: o.length >= 130 ? BigInt(`0x${o.slice(66, 130)}`) === 1n : null, error: c.error });
    }
    (c.calls ?? []).forEach((x) => walk(x as never));
  };
  walk(t);
  return out;
};
if (on('malformed')) try {
  const b = await buildToken(3, 'same', ['other']);
  for (const [what, edit, want, nCalls] of [
    ['flipped byte', (uc: Uint8Array) => uc.length >> 1, 'UCRejected()', 2],
    ['malformed CBOR head', () => 0, 'UCScanRejected()', null],
  ] as const) {
    const t = await mix(b.token, [true, true, true]);
    const before = claimable();
    const built = await buildReturnProof(bridge, t);
    const last = built.envelope.anchors[built.envelope.anchors.length - 1].uc;
    assert.ok(built.envelope.anchors.length === 2);
    const win = await waitWindow(t);
    const bad = flipIn(built.encoded, last, edit(last));
    const rc = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(bad)}`], THIRD_PARTY_KEY, REDEEM_GAS);
    const revert = callRevert(THIRD_PARTY_ADDR, bad);
    const diag = await diagnose(t, built, rc, win.clock) as { anchors: { class: string }[] };
    const inWin = diag.anchors.every((x) => x.class === 'in-window');
    const calls = await nativeCallsOf(rc.transactionHash).catch(() => null);
    const callsOk = calls === null ? false : nCalls === null ? calls.every((c) => c.valid !== true) : calls.length === nCalls && calls[0].valid === true && calls[1].valid !== true;
    record(`malformed final anchor (${what})`, rc.status === '0x0' && BigInt(rc.gasUsed) < BigInt(TX_GAS_BUDGET) && claimable() === before && revert === selector(want) && inWin && callsOk,
      { gasUsed: BigInt(rc.gasUsed), expectedRevert: `${want} ${selector(want)}`, revert, anchorsInWindowAtExecution: inWin, uc100Calls: calls, diag });
  }
} catch (e) { groupFailed('malformed', e); }
// gas and gas-1 on ONE token. The least limit M that succeeds is found for the very envelope under test (bisection on eth_call, the 63/64
// forwarding rule included), a send with M-1 must run out of gas (consume its whole limit, anchors in the window at its execution
// block, nothing credited), and then the same token's refetched proofs are sent with M + headroom and must redeem. Envelope sizes are the same
// for the same token, so M from the first envelope bounds the second to within the headroom.
if (on('gas')) try {
  const a = await buildToken(3, 'same', ['other']);
  const oa = await acceptedRow('gas: reference redemption (two anchors)', await mix(a.token, [true, true, true]), 2);
  const b = await buildToken(3, 'same', ['other']);
  const prepare = async (): Promise<{ t: Token; built: Awaited<ReturnType<typeof buildReturnProof>> }> => {
    const t = await mix(b.token, [true, true, true]);
    const built = await buildReturnProof(bridge, t);
    return { t, built };
  };
  const p1 = await prepare();
  // estimateGas at 'latest' sees the registry clock of the last block, which lags the newest shard certificate (a "future" anchor: UCRejected()), so
  // the clock is overridden to what the sent transaction will see at its execution block: the newest anchor, or the origin plus the measured 8-9 rounds.
  const clockAtExecution = [anchorRoundOf(p1.t).max, (await registryClock()) + 9n].reduce((x, y) => (x > y ? x : y));
  const data = run('cast', ['calldata', 'redeem(bytes)', `0x${hex(p1.built.encoded)}`]);
  const pinned = await rpc(eth, 'eth_blockNumber', []);
  const overrides = { [REGISTRY]: { stateDiff: { [clockSlot]: `0x${clockAtExecution.toString(16).padStart(64, '0')}` } } };
  const N = BigInt(await rpc(eth, 'eth_estimateGas', [{ from: THIRD_PARTY_ADDR, to: lane.vault, data }, pinned, overrides]));
  // eth_estimateGas is NOT the minimum: reth stops its search under 1.5% of the upper bound and returns the upper bound, so N-1 would still succeed.
  // The minimum M is bisected with eth_call on the same calldata, the same clock override and the same pinned block (read-only, no window pressure).
  const callSucceeds = (gas: bigint): Promise<boolean> =>
    rpc(eth, 'eth_call', [{ from: THIRD_PARTY_ADDR, to: lane.vault, data, gas: `0x${gas.toString(16)}` }, pinned, overrides]).then(() => true, () => false);
  const { min: M, calls: searchCalls } = await minimalGas(oa.gasUsed * 9n / 10n, N, callSucceeds);
  const win1 = await waitWindow(p1.t);
  const before = claimable();
  const lowLimit = M - 1n;
  const low = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(p1.built.encoded)}`], THIRD_PARTY_KEY, String(lowLimit));
  const lowDiag = await diagnose(p1.t, p1.built, low, win1.clock) as { anchors: { class: string }[] };
  const lowInWindow = lowDiag.anchors.every((x) => x.class === 'in-window');
  const lowOutOfGas = BigInt(low.gasUsed) === lowLimit;
  const creditedLow = claimable() - before;
  const p2 = await prepare();
  await waitWindow(p2.t);
  const highLimit = M + M / 32n + 50_000n;
  const beforeHigh = claimable();
  const high = await sendAll(lane.vault, 'redeem(bytes)(uint256)', [`0x${hex(p2.built.encoded)}`], THIRD_PARTY_KEY, String(highLimit));
  const mSucceeds = await callSucceeds(M);
  const mMinusOneFails = !(await callSucceeds(M - 1n));
  const creditedHigh = claimable() - beforeHigh;
  // lowConsumedWholeLimit is recorded, not asserted: below M the starved frame is an inner native/RSMT call (63/64 forwarding), its caller reverts
  // and the outer frame's unused gas comes back, so a failing send uses less than its limit (run 11: 3,075,844 of 3,122,231).
  record('gas-1 fails for gas, gas+headroom succeeds (one token)', gasOneHolds({ lowStatus: low.status, lowAnchorsInWindowAtExecution: lowInWindow, creditedLow, mSucceeds, mMinusOneFails, highStatus: high.status, creditedHigh, amount: amountWei }),
    { referenceGasUsed: oa.gasUsed, estimateGas: N, minimumGasM: M, searchCalls, pinnedBlock: pinned, clockOverride: clockAtExecution, lowLimit, lowStatus: low.status, lowGasUsed: BigInt(low.gasUsed), lowConsumedWholeLimit: lowOutOfGas, lowAnchorsInWindowAtExecution: lowInWindow, lowDiag, mSucceedsAtPinnedBlock: mSucceeds, mMinusOneFailsAtPinnedBlock: mMinusOneFails, highLimit, highStatus: high.status, highGasUsed: BigInt(high.gasUsed) });
} catch (e) { groupFailed('gas', e); }
// =====================================================================================================================================
// Wallet-path rows (issue #9). These use the plug-ins' own host freshness contract (buildFreshReturnProof / redeemReturn) against the live chain and
// shards: the proofs are refetched for the SAME burned token and nothing is rebuilt. They are the wallet evidence; the `inWindow` token rebuilding
// above is a test-shape helper and is not. Each row records fetch latency, the seal-round spread, the origin lag at the first read, the origin
// polls, attempts, sends and the origin at each transaction's execution block.
// =====================================================================================================================================
const plugin = createNativeBridgePlugin(bridge, { manifestRevision: 'rows', profileRevision: 'v3' });
const wCertPinned = BigInt(W_CERT);
const roundsOfProofs = (ps: InclusionProof[]): bigint[] => [...new Map(ps.map((p) => [hex(p.unicityCertificate.toCBOR()), BigInt(p.unicityCertificate.unicitySeal.rootChainRoundNumber)])).values()];
const maxOf = (xs: bigint[]): bigint => xs.reduce((a, b) => (a > b ? a : b));
const minOf = (xs: bigint[]): bigint => xs.reduce((a, b) => (a < b ? a : b));
interface WalletMetrics { fetches: { ms: number; rounds: bigint[] }[]; origins: { at: number; origin: bigint }[]; sends: Record<string, unknown>[]; t0: number }
const newMetrics = (): WalletMetrics => ({ fetches: [], origins: [], sends: [], t0: Date.now() });
const liveChain = (m: WalletMetrics): ChainReader => ({
  origin: async () => { const o = await registryClock(); m.origins.push({ at: Date.now() - m.t0, origin: o }); return o; },
  wCert: () => Promise.resolve(wCertPinned),
});
/** Every leaf's current proof from its own shard. `between(i)` runs after leaf i is fetched (concurrent-write rows); without it all leaves are fetched concurrently. */
const liveSource = (m: WalletMetrics, between?: (i: number) => Promise<void>, distinct = false): ProofSource => async (held) => {
  const t = Date.now();
  const all = [held.genesis, ...held.transactions];
  const seen = new Map<number, Set<string>>();
  const one = async (c: (typeof all)[number]): Promise<InclusionProof> => {
    const sid = await StateId.fromCertificationData(c.inclusionProof.certificationData);
    const row = rowOfSid(sid.data);
    // `distinct` FORCES the shape instead of observing it: this leaf's proof is taken only when its shard has certified a round no earlier-fetched leaf of that shard carries (what continuous writes make happen)
    const p = await until('a current proof', 60_000, async () => {
      const r = (await aggOf(sid).getInclusionProof(sid)).inclusionProof ?? undefined;
      if (r && distinct && seen.get(row)?.has(hex(r.unicityCertificate.toCBOR()))) return undefined;
      return r;
    });
    if (!seen.has(row)) seen.set(row, new Set());
    seen.get(row)!.add(hex(p.unicityCertificate.toCBOR()));
    return p;
  };
  let proofs: InclusionProof[];
  if (between) {
    proofs = [];
    for (let i = 0; i < all.length; i++) { proofs.push(await one(all[i])); if (i < all.length - 1) await between(i); }
  } else proofs = await Promise.all(all.map(one));
  m.fetches.push({ ms: Date.now() - t, rounds: roundsOfProofs(proofs) });
  return proofs;
};
const liveTransport = (m: WalletMetrics, nonce: bigint, delayFirstSendMs = 0): RedeemTransport => {
  let n = 0;
  return {
    send: async (data) => {
      if (n++ === 0 && delayFirstSendMs) await new Promise((r) => setTimeout(r, delayFirstSendMs));
      const sender = run('cast', ['wallet', 'address', '--private-key', THIRD_PARTY_KEY]);
      const txNonce = String(parseInt(await rpc(eth, 'eth_getTransactionCount', [sender, 'pending']), 16));
      const raw = cast('mktx', lane.vault, 'redeem(bytes)(uint256)', `0x${hex(data)}`, '--private-key', THIRD_PARTY_KEY, '--gas-limit', REDEEM_GAS, '--nonce', txNonce, '--chain', String(lane.chainId), '--legacy', '--gas-price', '2000000000');
      const txHash = `0x${hex(keccak256(unhex(raw)))}`;
      const sentOrigin = await registryClock();
      const sendErrors: string[] = [];
      await Promise.all(lane.ethUrls.map((url) => rpc(url, 'eth_sendRawTransaction', [raw]).catch((e) => { sendErrors.push(String(e).slice(0, 160)); })));
      m.sends.push({ txHash, sentAtMs: Date.now() - m.t0, originAtSend: sentOrigin, roundsFetched: m.fetches.at(-1)?.rounds, ...(sendErrors.length ? { sendErrors } : {}) });
      return txHash;
    },
    receipt: async (h) => {
      const r = await rpc(eth, 'eth_getTransactionReceipt', [h]);
      if (!r) return undefined;
      const rec = m.sends.find((s) => s.txHash === h);
      if (rec && rec.blockNumber === undefined) {
        rec.blockNumber = r.blockNumber; rec.gasUsed = BigInt(r.gasUsed); rec.status = r.status; rec.sealedAtMs = Date.now() - m.t0;
        rec.originAtBlock = BigInt(await rpc(eth, 'eth_getStorageAt', [REGISTRY, clockSlot, r.blockNumber]));
      }
      return r.status === '0x1' ? 'success' : 'reverted';
    },
    redeemed: () => Promise.resolve(BigInt(`0x${hex(unhex(cast('call', lane.vault, 'spentNullifier(uint256)(bytes32)', nonce.toString())))}`) !== 0n),
  };
};
const walletPolicy = (over: Partial<RedeemPolicy> = {}): RedeemPolicy => ({ ...DEFAULT_REDEEM, margin: BigInt(EXEC_MARGIN), receiptTimeoutMs: 60_000, ...over });
async function walletRow(name: string, limitOk: boolean, body: (m: WalletMetrics) => Promise<{ ok: boolean; data: Record<string, unknown> }>): Promise<void> {
  if (!on('wallet')) return;
  const m = newMetrics();
  try {
    const { ok, data } = await body(m);
    const first = m.origins[0];
    record(name, ok, {
      ...data, fetchMs: m.fetches.map((f) => f.ms), anchorsPerFetch: m.fetches.map((f) => f.rounds.length), roundSpreadPerFetch: m.fetches.map((f) => maxOf(f.rounds) - minOf(f.rounds)),
      originPolls: m.origins.length, firstOriginRead: first?.origin, newestAnchorLagAtFirstRead: first && m.fetches[0] ? maxOf(m.fetches[0].rounds) - first.origin : undefined,
      totalMs: Date.now() - m.t0, sends: m.sends,
    });
  } catch (e) {
    const detail = (e as { detail?: string }).detail ?? '';
    if (limitOk && (e as { reason?: string }).reason === 'ErrProofUnavailable' && /^(spread|stale|future) /.test(detail)) {
      // only for the rows whose point is to measure whether a shape fits: the plug-in judged every fetch outside the window and said so, so the shape does not fit this devnet's round timing
      recordLimit(name, { cause: detail, fetches: m.fetches.map((f) => ({ ms: f.ms, rounds: f.rounds, spread: maxOf(f.rounds) - minOf(f.rounds) })), originReads: m.origins.map((o) => o.origin), sends: m.sends.length });
      return;
    }
    record(name, false, { error: String((e as { detail?: string }).detail ?? (e as Error).message ?? e).slice(0, 300), reason: (e as { reason?: string }).reason, sends: m.sends, fetchMs: m.fetches.map((f) => f.ms) });
  }
}
async function credit<T>(f: () => Promise<T>): Promise<{ result: T; credited: bigint }> { const before = claimable(); const result = await f(); return { result, credited: claimable() - before }; }

// already-old token -> refresh all leaves -> redeem
await walletRow('wallet: already-old token refreshed for the same burned token, then redeemed', false, async (m) => {
  const b = await buildToken(3, 'same', ['other']);
  const rounds = anchorRoundOf(b.token);
  await until('the held proofs to be older than the window', 120_000, async () => (await registryClock()) - rounds.min > wCertPinned);
  const heldAge = (await registryClock()) - rounds.min;
  const { result, credited } = await credit(() => redeemReturn(plugin, b.token.toCBOR(), liveSource(m), liveChain(m), liveTransport(m, b.nonce), walletPolicy()));
  return { ok: result.status === 'redeemed' && credited === amountWei && result.sends === 1, data: { heldAnchorAgeAtStart: heldAge, status: result.status, sendsUsed: result.sends, credited, reburned: false } };
});

// delayed sign/send: judged fresh, executed after the window, the same token is refetched and sent again
await walletRow('wallet: delayed send expires on chain, same-token retry succeeds', false, async (m) => {
  const b = await buildToken(3, 'same', ['other']);
  const { result, credited } = await credit(() => redeemReturn(plugin, b.token.toCBOR(), liveSource(m), liveChain(m), liveTransport(m, b.nonce, 22_000), walletPolicy()));
  const first = m.sends[0];
  return { ok: result.status === 'redeemed' && result.sends === 2 && first?.status === '0x0' && credited === amountWei, data: { status: result.status, sendsUsed: result.sends, firstSendStatus: first?.status, firstSendOriginAtBlock: first?.originAtBlock, credited, reburned: false } };
});

// future origin: the registry imports a shard certificate some rounds after the shard made it; the wallet path waits for it
await walletRow('wallet: freshly certified burn, origin wait, redeem', false, async (m) => {
  const b = await buildToken(3, 'same', ['other']);
  const { result, credited } = await credit(() => redeemReturn(plugin, b.token.toCBOR(), liveSource(m), liveChain(m), liveTransport(m, b.nonce), walletPolicy()));
  const first = m.origins[0];
  const newest = m.fetches[0] ? maxOf(m.fetches[0].rounds) : undefined;
  return { ok: result.status === 'redeemed' && credited === amountWei, data: { status: result.status, sendsUsed: result.sends, credited, observedFutureAnchor: first !== undefined && newest !== undefined && newest > first.origin } };
});

// concurrent writes: certifications land on the shards between the per-leaf fetches, so the fetched proofs carry A = 3 or 4 distinct certificates
async function noiseWrite(row: number, proofFile: string): Promise<void> {
  for (let i = 0; i < 64; i++) {
    const owner = newSigner();
    const mint = await MintTransaction.create(NetworkId.fromId(cfg.network), SignaturePredicate.create(owner.publicKey), {
      data: valueEnvelope(cfg.aid, amount), expiresAt: null, justification: encodeJustification(cfg.chainId, cfg.vault, cfg.zeroAddress, 1n, Uint8Array.from(readFileSync(proofFile))),
      salt: TokenSalt.fromBytes(sha256(text(`noise-${Date.now()}-${ownerCounter++}-${i}`))), tokenType: new TokenType(cfg.ty),
    });
    const cd = await CertificationData.fromMintTransaction(mint);
    const sid = await StateId.fromCertificationData(cd);
    if (rowOfSid(sid.data) !== row) continue;
    await aggs[row].submitCertificationRequest(cd);
    await until('a noise write to be certified', 60_000, async () => (await aggs[row].getInclusionProof(sid)).inclusionProof ?? undefined);
    return;
  }
  throw new Error('no noise write for the shard');
}
/** Continuous writes on both shards while a wallet fetches: shard rounds keep advancing, so successive leaves of one shard come under different certificates. */
function startNoise(proofFile: string): () => void {
  let stop = false;
  for (const row of [0, 1]) void (async () => { while (!stop) { try { await noiseWrite(row, proofFile); } catch { await new Promise((r) => setTimeout(r, 500)); } } })();
  return () => { stop = true; };
}
for (const [want, rels] of [[3, ['same']], [4, ['same', 'same']]] as const) {
  await walletRow(`wallet: concurrent shard writes, A=${want}`, true, async (m) => {
    const b = await buildToken(want, 'same', [...rels]);
    const proofFile = `${lane.dir}/rows-lockproof-${b.nonce}.cbor`;
    const policy = walletPolicy({ margin: BigInt(Math.max(EXEC_MARGIN - 2, 1)) });
    const stop = startNoise(proofFile);
    try {
      const { result, credited } = await credit(() => redeemReturn(plugin, b.token.toCBOR(), liveSource(m, undefined, true), liveChain(m), liveTransport(m, b.nonce), policy));
      const used = m.fetches.at(-1)?.rounds.length ?? 0;
      return { ok: result.status === 'redeemed' && credited === amountWei && used >= want, data: { want, status: result.status, sendsUsed: result.sends, anchorsInSentBundle: used, credited, margin: Number(policy.margin) } };
    } finally { stop(); }
  });
}

// Restart and recovery of a pending redemption: burn certified and persisted, both aggregators restarted, proofs fetched again, redeem, then every
// validator restarted between redeem and claim, and the claim paid.
if (on('restart')) try {
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
} catch (e) { groupFailed('restart', e); }
console.log(`ROWS COMPLETE: ${evidence.rows.length} rows, ${failedRows.length} failed${failedRows.length ? ` (${failedRows.join('; ')})` : ''}, ${limitRows.length} measured limits, evidence ${lane.dir}/rows-evidence.json`);
if (failedRows.length) process.exit(1);
