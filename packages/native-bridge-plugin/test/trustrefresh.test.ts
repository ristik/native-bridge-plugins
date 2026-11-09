import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { ITrustBaseRequest, ITrustBaseSource } from '@unicitylabs/state-transition-sdk/lib/api/ITrustBaseSource.js';
import { RootTrustBaseV2 } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseUpdateError } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseError.js';
import { TrustBaseStatus } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseRange.js';
import { encodeTrustBaseResponse } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseResponseWire.js';
import { ConsolidationError } from '@unicitylabs/state-transition-sdk/lib/consolidation/ConsolidationError.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { NativeError } from '../src/errors.js';
import { TrustInput } from '../src/trust.js';
import { needsNewerEntry, TrustPersistError, withTrustRefresh, type TrustRefreshEvent } from '../src/trustrefresh.js';
import { rejects } from './util.js';
import { makeRoot, makeUc, NETWORK, nextEpoch, successorEntry, type Root } from './world.js';

const ucOf = (r: Root, signers: number, rootEpoch: bigint, round: bigint) =>
  makeUc(r, { partition: 1, conf: new Uint8Array(32).fill(1), epochIr: 1n, rootEpoch, round, timestamp: 1_700_000_000n, stateHash: new Uint8Array(32), blockHash: new Uint8Array(32).fill(2), signers });

/** An untrusted source serving `entries` (canonical bytes, ascending, the genesis first) as GetTrustBase pages; it records every request. */
function sourceOf(entries: Uint8Array[], network = NETWORK) {
  const requests: [bigint, number][] = [];
  const source: ITrustBaseSource = {
    async getTrustBasePage(request: ITrustBaseRequest) {
      const fromEpoch = request.fromEpoch;
      const maxEntries = request.maxEntries;
      requests.push([fromEpoch, maxEntries]);
      const decoded = entries.map((e) => RootTrustBaseV2.decode(e));
      const tip = decoded[decoded.length - 1];
      const at = decoded.findIndex((e) => e.epoch === fromEpoch);
      if (at < 0) return encodeTrustBaseResponse({ effectiveEnd: tip.epoch, endEntryId: null, entries: [], fromEpoch, network, nextEpoch: null, status: BigInt(TrustBaseStatus.NOT_YET_AVAILABLE) });
      const page = entries.slice(at, at + maxEntries);
      const last = decoded[at + page.length - 1];
      const next = last.epoch < tip.epoch ? last.epoch + 1n : null;
      return encodeTrustBaseResponse({ effectiveEnd: tip.epoch, endEntryId: await tip.entryId(), entries: page, fromEpoch, network, nextEpoch: next, status: BigInt(TrustBaseStatus.OK) });
    },
  };
  return { source, requests };
}

test('a certificate of a newer epoch: the SDK update fetches the missing contiguous entries one page at a time in one pass, appends and the wallet retries', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const r4 = await nextEpoch(r3, 2000n, 4, 50);
  const held = await TrustInput.fromBundle(r2.bundle, r2.pin);
  const genesisBytes = held.history.entryForEpoch(2n)!.encode();
  const uc = await ucOf(r4, 3, 4n, 2500n);
  // fetch disabled (one attempt): the verification fails for the missing entry
  await rejects(withTrustRefresh(held, sourceOf(r4.entries).source, () => held.verifyEmbeddedUc(uc), { attempts: 1 }), 'ErrNoEntryForEpoch');
  const { source, requests } = sourceOf(r4.entries);
  const events: TrustRefreshEvent[] = [];
  const persisted: Uint8Array[] = [];
  await withTrustRefresh(held, source, () => held.verifyEmbeddedUc(uc), { maxEntries: 1, onFetch: (e) => events.push(e), persist: (b) => void persisted.push(b) });
  assert.deepEqual(requests, [[3n, 1], [4n, 1]], 'one-entry pages from the held tip + 1');
  // the SDK's update follows the cursor itself: one fetch event for the whole range
  assert.deepEqual(events.map((e) => [e.tipBefore, e.tipAfter, e.appended]), [[2n, 4n, 2]]);
  assert.equal(held.history.tip?.epoch, 4n);
  assert.deepEqual(held.history.entryForEpoch(2n)!.encode(), genesisBytes, 'the held genesis entry is untouched');
  for (const e of [3n, 4n]) assert.deepEqual(held.history.entryForEpoch(e)!.encode(), r4.entries[Number(e) - 2], `epoch ${e} is the source's entry`);
  // the persisted history is the held one: it reinstalls under the same pin, at the new tip
  assert.equal(persisted.length, 1);
  assert.equal((await TrustInput.fromBundle(persisted[0], r2.pin)).history.tip?.epoch, 4n);
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
    (e: unknown) => e instanceof TrustBaseUpdateError);
  assert.equal(held.history.tip?.epoch, 2n);
});

test('a held epoch is never replaced: a source with another epoch-3 entry after the held one is refused', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const r4 = await nextEpoch(r3, 2000n, 4, 50);
  const other3 = await nextEpoch(r2, 1100n, 4, 70);
  const other4 = await nextEpoch(other3, 2000n, 4, 90);
  const held = await TrustInput.fromBundle(r3.bundle, r2.pin);
  const held3 = held.history.entryForEpoch(3n)!.encode();
  // the other chain's epoch 4 links to the other epoch 3, not the held one
  const uc = await ucOf(r4, 3, 4n, 2500n);
  await assert.rejects(withTrustRefresh(held, sourceOf(other4.entries).source, () => held.verifyEmbeddedUc(uc)),
    (e: unknown) => e instanceof TrustBaseUpdateError);
  assert.equal(held.history.tip?.epoch, 3n);
  assert.deepEqual(held.history.entryForEpoch(3n)!.encode(), held3);
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
  assert.equal(held.history.tip?.epoch, 2n);
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

test('a refused page keeps its authenticated prefix durable: entry 3 accepted, entry 4 refused, the operation refused without a retry', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const r4 = await nextEpoch(r3, 2000n, 4, 50);
  // epoch 4 witnessed by its own committee instead of epoch 3's: structurally a page, refused at append
  const forged4 = await successorEntry(r3, 2000n, 4, 50, undefined, r4.signers);
  const held = await TrustInput.fromBundle(r2.bundle, r2.pin);
  const uc = await ucOf(r4, 3, 4n, 2500n);
  let verifications = 0;
  const persisted: Uint8Array[] = [];
  await assert.rejects(withTrustRefresh(held, sourceOf([...r3.entries, forged4]).source, () => { verifications++; return held.verifyEmbeddedUc(uc); },
    { persist: (b) => void persisted.push(b) }), (e: unknown) => e instanceof TrustBaseUpdateError);
  assert.equal(verifications, 1, 'the refusal is not retried');
  assert.equal(held.history.tip?.epoch, 3n, 'the authenticated prefix is held in memory');
  assert.equal(persisted.length, 1, 'and persisted once');
  // a fresh load of what was written, under the same pin: entry 3 is there, unchanged, and nothing past it
  const reloaded = await TrustInput.fromBundle(persisted[0], r2.pin);
  assert.equal(reloaded.history.tip?.epoch, 3n);
  assert.deepEqual(reloaded.history.entryForEpoch(3n)!.encode(), r3.entries[1]);
  assert.deepEqual(reloaded.history.entryForEpoch(2n)!.encode(), r2.entries[0]);
});

test('a failed write stops the operation: after a refused page with both errors, after a good fetch without a retry', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const r4 = await nextEpoch(r3, 2000n, 4, 50);
  const forged4 = await successorEntry(r3, 2000n, 4, 50, undefined, r4.signers);
  const uc4 = await ucOf(r4, 3, 4n, 2500n);
  const diskFull = () => { throw new Error('ENOSPC'); };
  const a = await TrustInput.fromBundle(r2.bundle, r2.pin);
  await assert.rejects(withTrustRefresh(a, sourceOf([...r3.entries, forged4]).source, () => a.verifyEmbeddedUc(uc4), { persist: diskFull }), (e: unknown) => {
    assert.ok(e instanceof TrustPersistError);
    const both = (e as Error).cause as AggregateError;
    assert.ok(both instanceof AggregateError && (both.errors[0] as Error).message === 'ENOSPC' && both.errors[1] instanceof TrustBaseUpdateError);
    return true;
  });
  const b = await TrustInput.fromBundle(r2.bundle, r2.pin);
  const uc3 = await ucOf(r3, 3, 3n, 1500n);
  let verifications = 0;
  await assert.rejects(withTrustRefresh(b, sourceOf(r3.entries).source, () => { verifications++; return b.verifyEmbeddedUc(uc3); }, { persist: diskFull }),
    (e: unknown) => e instanceof TrustPersistError && ((e as Error).cause as Error).message === 'ENOSPC');
  assert.equal(verifications, 1, 'the verification is not retried after a failed write');
});

test('the history is written before the report: a failing onFetch cannot prevent the write', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const held = await TrustInput.fromBundle(r2.bundle, r2.pin);
  const uc = await ucOf(r3, 3, 3n, 1500n);
  const persisted: Uint8Array[] = [];
  await assert.rejects(withTrustRefresh(held, sourceOf(r3.entries).source, () => held.verifyEmbeddedUc(uc),
    { persist: (b) => void persisted.push(b), onFetch: () => { throw new Error('report failed'); } }), /report failed/);
  assert.equal(persisted.length, 1);
  assert.equal((await TrustInput.fromBundle(persisted[0], r2.pin)).history.tip?.epoch, 3n);
});
