/**
 * Rotating-authority proof refresh (bft-core #438): a token whose return proof was taken under root epoch 2 is refreshed to an anchor of epoch 4 after two
 * committee rotations and redeemed. The bridge holds the epoch-2 history only; the SDK's own refresh loop (`verifyWithTrustBaseUpdate`: "no entry for
 * epoch" -> fetch -> append) is run against a trust-base source that serves real signed pages (tag 39015), and the redemption is then repeated on the
 * SAME bridge and history object: nothing is rebuilt.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { InclusionCertificate } from '@unicitylabs/state-transition-sdk/lib/api/InclusionCertificate.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { RootTrustBaseV2 } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseResponseStatus } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseResponse.js';
import { TrustBaseUpdateError } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseUpdateError.js';
import { CertificateVerificationResult } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/CertificateVerdict.js';
import type { ITrustBaseSource } from '@unicitylabs/state-transition-sdk/lib/api/ITrustBaseSource.js';
import { DataHasherFactory } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasherFactory.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { NodeDataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/NodeDataHasher.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { SparseMerkleTree } from '@unicitylabs/state-transition-sdk/lib/smt/radix/SparseMerkleTree.js';
import { TokenVerifier } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/default/TokenVerifier.js';
import { verifyWithTrustBaseUpdate } from '@unicitylabs/state-transition-sdk/lib/util/TrustBaseUtils.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { decodeEnvelope } from '../src/envelope.js';
import { buildReturnProof, refreshToken } from '../src/proof.js';
import { redeemReturn, type ChainReader, type RedeemPolicy, type RedeemTransport } from '../src/readiness.js';
import { createNativeBridgePlugin } from '../src/wallet.js';
import { rejects } from './util.js';
import { AGG_PARTITION, buildToken, burnStep, makeUc, makeWorld, nextEpoch, NETWORK, spec, successorEntry, txStep, type Root, type World } from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;

// ---- the world after two rotations ---------------------------------------------------------------------------------------------------------------------

interface Rotated {
  w: World;
  r3: Root;
  r4: Root;
  out: Awaited<ReturnType<typeof returnToken>>;
  nullifier: Uint8Array;
}

const returnToken = (w: World) => buildToken(w, spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)], T0, UC_TS);

/** The bridge holds epoch 2 only; the network has rotated twice (epoch 3 from round 1000, epoch 4 from round 2000), a full committee change each time. */
async function rotated(): Promise<Rotated> {
  const w = await makeWorld();
  const out = await returnToken(w);
  const nullifier = (await w.bridge.verifyNativeToken(out.token, 'return')).outcome.nullifier;
  const r3 = await nextEpoch(w.agg, 1000n, 4, 30);
  const r4 = await nextEpoch(r3, 2000n, 4, 40);
  return { w, r3, r4, out, nullifier };
}

/** The aggregator's answer for the held token's leaves, certified by the epoch-4 committee in root round 2500. */
async function proofsUnder4(x: Rotated): Promise<InclusionProof[]> {
  const old = [x.out.token.genesis, ...x.out.token.transactions].map((c) => c.inclusionProof);
  const smt = new SparseMerkleTree(new DataHasherFactory(HashAlgorithm.SHA256, NodeDataHasher));
  for (const [k, v] of x.out.leaves) await smt.addLeaf(k, v);
  const root = await smt.calculateRoot();
  const uc = await makeUc(x.r4, {
    partition: AGG_PARTITION, conf: x.w.aggConf, epochIr: 1n, rootEpoch: 4n, round: 2500n, timestamp: UC_TS + 5000n, stateHash: root.hash.data, blockHash: null, signers: 4,
  });
  return old.map((o, i) => new InclusionProof(o.certificationData, o.referenceTime, InclusionCertificate.create(root, x.out.leaves[i][0]), uc));
}

// ---- a trust-base source that serves real pages ----------------------------------------------------------------------------------------------------------

/**
 * The aggregator's `GET /api/v1/trustbases`: signed pages (tag 39015) of the entries after `from`, at most `cap` per page (a cursor continues), built from
 * the raw entries `all` of which only the first `available` exist yet. `requests` records every `from`.
 */
class PageSource implements ITrustBaseSource {
  public requests: bigint[] = [];
  public constructor(private readonly all: Uint8Array[], public available: number, public cap = 64) {}

  public async getTrustBaseEntries(from: bigint, maxEntries: number): Promise<Uint8Array> {
    this.requests.push(from);
    const have = this.all.slice(0, this.available);
    const tip = RootTrustBaseV2.fromCBOR(have[have.length - 1]);
    const first = RootTrustBaseV2.fromCBOR(have[0]).epoch;
    const page = (status: TrustBaseResponseStatus, entries: Uint8Array[], end: Uint8Array | null, next: bigint | null): Uint8Array =>
      C.encodeTag(39015n, C.encodeArray(
        C.encodeUnsignedInteger(1n), C.encodeUnsignedInteger(NETWORK), C.encodeUnsignedInteger(status), C.encodeUnsignedInteger(from), C.encodeUnsignedInteger(tip.epoch),
        C.encodeNullable(end, C.encodeByteString), C.encodeArray(...entries), C.encodeNullable(next, C.encodeUnsignedInteger),
      ));
    if (from > tip.epoch) return page(TrustBaseResponseStatus.NOT_YET_AVAILABLE, [], null, null);
    const slice = have.slice(Number(from - first), Number(from - first) + Math.min(maxEntries, this.cap));
    const last = RootTrustBaseV2.fromCBOR(slice[slice.length - 1]).epoch;
    return page(TrustBaseResponseStatus.OK, slice, await tip.entryId(), last < tip.epoch ? last + 1n : null);
  }
}

// ---- the redemption side -------------------------------------------------------------------------------------------------------------------------------

class Vault implements RedeemTransport {
  public sent: Uint8Array[] = [];
  public spent = false;
  public constructor(private readonly nullifier: Uint8Array) {}
  public send(data: Uint8Array): Promise<string> {
    this.sent.push(data);
    this.spent = true;
    return Promise.resolve(`0x${this.sent.length}`);
  }
  public receipt(): Promise<'success'> { return Promise.resolve('success'); }
  public spentNullifier(): Promise<Uint8Array | undefined> { return Promise.resolve(this.spent ? this.nullifier : undefined); }
}
const noWait = { sleep: () => Promise.resolve() };
const policy = (): RedeemPolicy => ({ maxAttempts: 3, maxOriginWaitMs: 1_000, pollMs: 1, ...noWait, maxSends: 2, receiptTimeoutMs: 10, now: (() => { let n = 0; return () => (n += 4); })() });
const chain: ChainReader = { origin: () => Promise.resolve(2600n) };

/** The wallet's refresh loop around the SDK's: verify the refreshed token as the SDK does, fetching and appending trust-base entries on "no entry for epoch". */
const verifyRefreshed = (x: Rotated, refreshed: Awaited<ReturnType<typeof refreshToken>>, source: ITrustBaseSource) =>
  verifyWithTrustBaseUpdate(async (tb) => {
    assert.equal(tb, x.w.bridge.trust.history, 'the loop works on the bridge\'s own history, not a copy');
    return new TokenVerifier().verify(refreshed, await x.w.bridge.context());
  }, x.w.bridge.trust.history, source, { attempts: 4, intervalMs: 1, timeoutMs: 20_000 });

test('a return proof of epoch 2, refreshed to an epoch-4 anchor after two rotations, is redeemed once the SDK loop has fetched and appended epochs 3 and 4', async () => {
  const x = await rotated();
  const { w } = x;
  const history = w.bridge.trust.history;
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const vault = new Vault(x.nullifier);
  const aggregator = () => proofsUnder4(x);
  assert.equal(history.tipEpoch, 2n);
  const epoch2 = history.bytes(2n)!;

  // 1. the bridge cannot yet verify the epoch-4 anchor: retryable, and the redemption sends nothing
  await rejects(redeemReturn(plugin, x.out.bytes, aggregator, chain, vault, policy()), 'ErrNoEntryForEpoch');
  assert.equal(vault.sent.length, 0);

  // 2. the SDK reports the same thing as a verification result naming the missing epoch
  const refreshed = await refreshToken(x.out.token, await aggregator());
  const stale = await new TokenVerifier().verify(refreshed, await w.bridge.context());
  assert.notEqual(stale.status, VerificationStatus.OK);
  const missing = CertificateVerificationResult.findMissingEpoch(stale)?.missing;
  assert.deepEqual([missing?.epoch, missing?.latest], [4n, 2n]);

  // 3. the loop: the source serves one entry per page, so epoch 3 and epoch 4 take two fetches, each from the epoch after the held tip
  const source = new PageSource(x.r4.entries, 3, 1);
  const result = await verifyRefreshed(x, refreshed, source);
  assert.equal(result.status, VerificationStatus.OK);
  assert.deepEqual(source.requests, [3n, 4n]);
  assert.equal(history.tipEpoch, 4n);
  assert.equal(w.bridge.trust.history, history, 'the same history object was appended to');
  assert.deepEqual(history.bytes(2n), epoch2, 'held entries are never replaced');
  assert.deepEqual(history.bytes(3n), x.r4.entries[1]);
  assert.deepEqual(history.bytes(4n), x.r4.entries[2]);

  // 4. the plug-in now verifies the refreshed token and the old, epoch-2 proof of the same token, and the redemption goes through with the epoch-4 proof
  await w.bridge.verifyNativeToken(refreshed, 'return');
  await w.bridge.verifyNativeToken(x.out.token, 'return');
  const done = await redeemReturn(plugin, x.out.bytes, aggregator, chain, vault, policy());
  assert.equal(done.status, 'redeemed');
  assert.equal(vault.sent.length, 1);
  const { encoded } = await buildReturnProof(w.bridge, refreshed);
  assert.deepEqual(vault.sent[0], encoded, 'what the vault received is the proof anchored in epoch 4');
  assert.equal(decodeEnvelope(vault.sent[0]).anchors.length, 1);
});

test('a source that serves a forged epoch 3 (a successor not witnessed by the epoch-2 committee) is refused, nothing is appended, and the honest source then succeeds', async () => {
  const x = await rotated();
  const { w } = x;
  const history = w.bridge.trust.history;
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const vault = new Vault(x.nullifier);
  const aggregator = () => proofsUnder4(x);
  const refreshed = await refreshToken(x.out.token, await aggregator());

  // the same epoch 3 with the same members, witnessed by the later committee instead of the epoch-2 one
  const forged = await successorEntry(w.agg, 1000n, 4, 30, undefined, x.r4.signers);
  assert.notDeepEqual(forged, x.r4.entries[1]);
  const liar = new PageSource([x.r4.entries[0], forged, x.r4.entries[2]], 2);
  await assert.rejects(verifyRefreshed(x, refreshed, liar), (e: unknown) => TrustBaseUpdateError.is(e) && e.reason === 'rejected');
  assert.equal(history.tipEpoch, 2n, 'a refused entry is not held');
  await rejects(redeemReturn(plugin, x.out.bytes, aggregator, chain, vault, policy()), 'ErrNoEntryForEpoch');
  assert.equal(vault.sent.length, 0);

  const honest = new PageSource(x.r4.entries, 3);
  assert.equal((await verifyRefreshed(x, refreshed, honest)).status, VerificationStatus.OK);
  assert.equal((await redeemReturn(plugin, x.out.bytes, aggregator, chain, vault, policy())).status, 'redeemed');
});

test('a source that has not caught up leaves the proof retryable; entries appended before stay held and the next attempt continues from them', async () => {
  const x = await rotated();
  const { w } = x;
  const history = w.bridge.trust.history;
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const vault = new Vault(x.nullifier);
  const aggregator = () => proofsUnder4(x);
  const refreshed = await refreshToken(x.out.token, await aggregator());

  // the source knows epoch 2 only: every fetch brings nothing, the loop gives up after its attempts and returns the missing-epoch result
  const source = new PageSource(x.r4.entries, 1);
  const waiting = await verifyRefreshed(x, refreshed, source);
  assert.notEqual(waiting.status, VerificationStatus.OK);
  assert.equal(CertificateVerificationResult.findMissingEpoch(waiting)?.missing?.epoch, 4n);
  assert.equal(source.requests.length, 4);
  assert.equal(history.tipEpoch, 2n);

  // it then has epoch 3: that is appended, epoch 4 is still missing
  source.available = 2;
  const partial = await verifyRefreshed(x, refreshed, source);
  assert.notEqual(partial.status, VerificationStatus.OK);
  assert.deepEqual([CertificateVerificationResult.findMissingEpoch(partial)?.missing?.epoch, history.tipEpoch], [4n, 3n]);
  await rejects(redeemReturn(plugin, x.out.bytes, aggregator, chain, vault, policy()), 'ErrNoEntryForEpoch');
  assert.equal(vault.sent.length, 0);

  // and then epoch 4: the loop starts from the held tip (a fetch from epoch 4) and the redemption goes through
  source.available = 3;
  source.requests = [];
  assert.equal((await verifyRefreshed(x, refreshed, source)).status, VerificationStatus.OK);
  assert.deepEqual(source.requests, [4n]);
  assert.equal((await redeemReturn(plugin, x.out.bytes, aggregator, chain, vault, policy())).status, 'redeemed');
  assert.equal(vault.sent.length, 1);
});

