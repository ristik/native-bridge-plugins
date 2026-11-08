import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { ITrustBaseSource } from '@unicitylabs/state-transition-sdk/lib/api/ITrustBaseSource.js';
import { RootTrustBaseV2 } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseResponse, TrustBaseResponseStatus } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseResponse.js';
import { TrustBaseUpdateError } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseUpdateError.js';
import { ConsolidationError } from '@unicitylabs/state-transition-sdk/lib/consolidation/ConsolidationError.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { NativeError } from '../src/errors.js';
import { TrustInput } from '../src/trust.js';
import { needsNewerEntry, withTrustRefresh, type TrustRefreshEvent } from '../src/trustrefresh.js';
import { rejects } from './util.js';
import { makeRoot, makeUc, NETWORK, nextEpoch, successorEntry, type Root } from './world.js';

const ucOf = (r: Root, signers: number, rootEpoch: bigint, round: bigint) =>
  makeUc(r, { partition: 1, conf: new Uint8Array(32).fill(1), epochIr: 1n, rootEpoch, round, timestamp: 1_700_000_000n, stateHash: new Uint8Array(32), blockHash: new Uint8Array(32).fill(2), signers });

// the SDK's response type has a private constructor; a test source builds its pages with it, and the SDK's strict decoder checks them
const Response = TrustBaseResponse as unknown as new (...a: unknown[]) => TrustBaseResponse;

/** An untrusted source serving `entries` (canonical bytes, ascending, the genesis first) as GetTrustBase pages; it records every request. */
function sourceOf(entries: Uint8Array[], network = NETWORK) {
  const requests: [bigint, number][] = [];
  const source: ITrustBaseSource = {
    async getTrustBaseEntries(fromEpoch: bigint, maxEntries: number) {
      requests.push([fromEpoch, maxEntries]);
      const decoded = entries.map((e) => RootTrustBaseV2.fromCBOR(e));
      const tip = decoded[decoded.length - 1];
      const at = decoded.findIndex((e) => e.epoch === fromEpoch);
      if (at < 0) return new Response(network, TrustBaseResponseStatus.NOT_YET_AVAILABLE, fromEpoch, tip.epoch, await tip.entryId(), [], null, []).toCBOR();
      const page = entries.slice(at, at + maxEntries);
      const last = decoded[at + page.length - 1];
      const next = last.epoch < tip.epoch ? last.epoch + 1n : null;
      return new Response(network, TrustBaseResponseStatus.OK, fromEpoch, tip.epoch, await tip.entryId(), page, next, []).toCBOR();
    },
  };
  return { source, requests };
}

test('a certificate of a newer epoch: the wallet fetches the missing contiguous entries one page at a time, appends and retries', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const r4 = await nextEpoch(r3, 2000n, 4, 50);
  const held = await TrustInput.fromBundle(r2.bundle, r2.pin);
  const genesisBytes = held.history.bytes(2n);
  const uc = await ucOf(r4, 3, 4n, 2500n);
  // fetch disabled (one attempt): the verification fails for the missing entry
  await rejects(withTrustRefresh(held, sourceOf(r4.entries).source, () => held.verifyEmbeddedUc(uc), { attempts: 1 }), 'ErrNoEntryForEpoch');
  const { source, requests } = sourceOf(r4.entries);
  const events: TrustRefreshEvent[] = [];
  const persisted: Uint8Array[] = [];
  await withTrustRefresh(held, source, () => held.verifyEmbeddedUc(uc), { maxEntries: 1, onFetch: (e) => events.push(e), persist: (b) => void persisted.push(b) });
  assert.deepEqual(requests, [[3n, 1], [4n, 1]], 'one-entry pages from the held tip + 1');
  assert.deepEqual(events.map((e) => [e.tipBefore, e.tipAfter, e.appended]), [[2n, 3n, 1], [3n, 4n, 1]]);
  assert.equal(held.history.tipEpoch, 4n);
  assert.deepEqual(held.history.bytes(2n), genesisBytes, 'the held genesis entry is untouched');
  for (const e of [3n, 4n]) assert.deepEqual(held.history.bytes(e), r4.entries[Number(e) - 2], `epoch ${e} is the source's entry`);
  // the persisted history is the held one: it reinstalls under the same pin, at the new tip
  assert.equal(persisted.length, 2);
  assert.equal((await TrustInput.fromBundle(persisted[1], r2.pin)).history.tipEpoch, 4n);
  // idempotent: the same verification again needs no fetch
  await withTrustRefresh(held, source, () => held.verifyEmbeddedUc(uc));
  assert.equal(requests.length, 2);
});

test('a successor that does not authenticate is refused: nothing is appended and the error is the SDK update error', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const held = await TrustInput.fromBundle(r2.bundle, r2.pin);
  // epoch 3 witnessed by its own committee instead of epoch 2's
  const forged = await successorEntry(r2, 1000n, 4, 30, undefined, r3.signers);
  const uc = await ucOf(r3, 3, 3n, 1500n);
  await assert.rejects(withTrustRefresh(held, sourceOf([r2.entries[0], forged]).source, () => held.verifyEmbeddedUc(uc), { persist: () => assert.fail('nothing to persist') }),
    (e: unknown) => TrustBaseUpdateError.is(e) && e.reason === 'rejected');
  assert.equal(held.history.tipEpoch, 2n);
});

test('a held epoch is never replaced: a source with another epoch-3 entry after the held one is refused', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const r4 = await nextEpoch(r3, 2000n, 4, 50);
  const other3 = await nextEpoch(r2, 1100n, 4, 70);
  const other4 = await nextEpoch(other3, 2000n, 4, 90);
  const held = await TrustInput.fromBundle(r3.bundle, r2.pin);
  const held3 = held.history.bytes(3n);
  // the other chain's epoch 4 links to the other epoch 3, not the held one
  const uc = await ucOf(r4, 3, 4n, 2500n);
  await assert.rejects(withTrustRefresh(held, sourceOf(other4.entries).source, () => held.verifyEmbeddedUc(uc)),
    (e: unknown) => TrustBaseUpdateError.is(e));
  assert.equal(held.history.tipEpoch, 3n);
  assert.deepEqual(held.history.bytes(3n), held3);
});

test('only a missing epoch is retried: another failure propagates without a fetch', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const held = await TrustInput.fromBundle(r3.bundle, r2.pin);
  const { source, requests } = sourceOf(r3.entries);
  await rejects(withTrustRefresh(held, source, async () => held.verifyEmbeddedUc(await ucOf(r3, 2, 3n, 1500n))), 'ErrQuorumNotMet');
  assert.equal(requests.length, 0);
});

test('a source without the epoch yet: the wallet pauses, and gives up with the retryable error when the attempts run out', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const held = await TrustInput.fromBundle(r2.bundle, r2.pin);
  const { source, requests } = sourceOf(r2.entries);
  const uc = await ucOf(r3, 3, 3n, 1500n);
  await rejects(withTrustRefresh(held, source, () => held.verifyEmbeddedUc(uc), { attempts: 3, intervalMs: 1 }), 'ErrNoEntryForEpoch');
  assert.deepEqual(requests, [[3n, 64], [3n, 64]]);
  assert.equal(held.history.tipEpoch, 2n);
});

test('the missing epoch is recognised from the plug-in and from an SDK consolidation integrity error, nothing else', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const held = await TrustInput.fromBundle(r2.bundle, r2.pin);
  let missing: unknown;
  try {
    await held.verifyEmbeddedUc(await ucOf(r3, 3, 3n, 1500n));
  } catch (e) {
    missing = e;
  }
  assert.ok(needsNewerEntry(missing));
  assert.equal(needsNewerEntry(new NativeError('ErrQuorumNotMet')), false);
  // the SDK's own trace of a missing epoch, as a consolidation integrity error carries it
  const { UnicityCertificateVerifier } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/verification/UnicityCertificateVerifier.js');
  const { UnicitySealQuorumSignaturesVerificationRule } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js');
  const { Secp256k1SignatureVerifier } = await import('@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Secp256k1SignatureVerifier.js');
  const uc = await ucOf(r3, 3, 3n, 1500n);
  const trace = await new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier()))
    .verifyCertificate(held.history, uc, { partitionId: uc.unicityTreeCertificate.partitionIdentifier });
  assert.notEqual(trace.status, VerificationStatus.OK);
  assert.ok(needsNewerEntry(new ConsolidationError('integrity', 'The token does not verify.', { cause: trace, outcome: 'invalid_input' })));
  const other = new VerificationResult('UnicitySealQuorumSignaturesVerificationRule', VerificationStatus.FAIL);
  assert.equal(needsNewerEntry(new ConsolidationError('integrity', 'The token does not verify.', { cause: other, outcome: 'invalid_input' })), false);
  assert.equal(needsNewerEntry(new ConsolidationError('timeout', 'late')), false);
  assert.equal(needsNewerEntry(new Error('ErrNoEntryForEpoch')), false);
});
