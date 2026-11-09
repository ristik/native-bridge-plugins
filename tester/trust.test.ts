import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import type { ITrustBaseRequest, ITrustBaseSource } from '@unicitylabs/state-transition-sdk/lib/api/ITrustBaseSource.js';
import { RootTrustBaseV2 } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseUpdateError } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseError.js';
import { TrustBaseStatus } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseRange.js';
import { encodeTrustBaseResponse } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseResponseWire.js';

import { TrustPersistError } from '../packages/native-bridge-plugin/src/trustrefresh.js';
import { makeRoot, NETWORK, nextEpoch, successorEntry, type Root } from '../packages/native-bridge-plugin/test/world.js';
import { loadHeldTrust, maxEntriesOf, persistTrustFile, refreshAll } from './trust.js';

/** An untrusted source serving `entries` as GetTrustBase pages. */
function sourceOf(entries: Uint8Array[]): ITrustBaseSource {
  return {
    async getTrustBasePage(request: ITrustBaseRequest) {
      const fromEpoch = request.fromEpoch;
      const maxEntries = request.maxEntries;
      const decoded = entries.map((e) => RootTrustBaseV2.decode(e));
      const tip = decoded[decoded.length - 1];
      const at = decoded.findIndex((e) => e.epoch === fromEpoch);
      if (at < 0) return encodeTrustBaseResponse({ effectiveEnd: tip.epoch, endEntryId: null, entries: [], fromEpoch, network: NETWORK, nextEpoch: null, status: BigInt(TrustBaseStatus.NOT_YET_AVAILABLE) });
      const page = entries.slice(at, at + maxEntries);
      const last = decoded[at + page.length - 1];
      return encodeTrustBaseResponse({ effectiveEnd: tip.epoch, endEntryId: await tip.entryId(), entries: page, fromEpoch, network: NETWORK, nextEpoch: last.epoch < tip.epoch ? last.epoch + 1n : null, status: BigInt(TrustBaseStatus.OK) });
    },
  };
}

/** A wallet directory with the operator's shipped bundle and pin. */
function wallet(shipped: Root) {
  const dir = mkdtempSync(join(tmpdir(), 'tester-trust-'));
  writeFileSync(join(dir, 'bundle.cbor'), shipped.bundle);
  writeFileSync(join(dir, 'pin'), `${Buffer.from(shipped.pin).toString('hex')}\n`);
  const load = () => loadHeldTrust(join(dir, 'bundle.cbor'), join(dir, 'pin'), join(dir, 'trust-history.cbor'));
  return { dir, history: join(dir, 'trust-history.cbor'), load, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test('held trust: the shipped bundle without a history; the durable history when it extends it; shipped entries it lacks are appended', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const r4 = await nextEpoch(r3, 2000n, 4, 50);
  const a = wallet(r3);
  try {
    assert.equal((await a.load()).history.tip?.epoch, 3n, 'no history: the shipped bundle');
    persistTrustFile(a.history, r4.bundle);
    assert.ok(!existsSync(`${a.history}.tmp`), 'the write leaves no temporary file');
    const held = await a.load();
    assert.equal(held.history.tip?.epoch, 4n, 'the history that extends the shipped one');
    assert.deepEqual(held.history.entryForEpoch(3n)!.encode(), r3.entries[1]);
    // a history shorter than the shipped bundle (an older wallet, a newer release): the shipped entry is appended, nothing replaced
    persistTrustFile(a.history, r2.bundle);
    assert.equal((await a.load()).history.tip?.epoch, 3n);
  } finally {
    a.done();
  }
});

test('held trust: a history that conflicts with the shipped bundle, or is of another pin, is refused', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const other3 = await nextEpoch(r2, 1100n, 4, 70);
  const a = wallet(r3);
  try {
    persistTrustFile(a.history, other3.bundle);
    await assert.rejects(a.load(), /does not extend the shipped trust bundle at epoch 3/);
    persistTrustFile(a.history, (await makeRoot(2, 4, 90)).bundle);
    await assert.rejects(a.load());
  } finally {
    a.done();
  }
});

test('trust --refresh: every page persisted; a refused page persists its authenticated prefix, then the refusal propagates; a failed write stops', async () => {
  const r2 = await makeRoot(2, 4, 10);
  const r3 = await nextEpoch(r2, 1000n, 4, 30);
  const r4 = await nextEpoch(r3, 2000n, 4, 50);
  const a = wallet(r2);
  try {
    assert.equal(await refreshAll(await a.load(), sourceOf(r4.entries), 1, (b) => persistTrustFile(a.history, b)), 2);
    assert.equal((await a.load()).history.tip?.epoch, 4n, 'a fresh load holds what was fetched');
  } finally {
    a.done();
  }
  const forged4 = await successorEntry(r3, 2000n, 4, 50, undefined, r4.signers);
  const b = wallet(r2);
  try {
    await assert.rejects(refreshAll(await b.load(), sourceOf([...r3.entries, forged4]), 64, (x) => persistTrustFile(b.history, x)),
      (e: unknown) => e instanceof TrustBaseUpdateError);
    const reloaded = await b.load();
    assert.equal(reloaded.history.tip?.epoch, 3n, 'the accepted epoch 3 survives the refusal of epoch 4 across a reload');
    assert.deepEqual(reloaded.history.entryForEpoch(3n)!.encode(), r3.entries[1]);
    const before = readFileSync(b.history);
    await assert.rejects(refreshAll(await b.load(), sourceOf(r4.entries), 64, () => { throw new Error('EROFS'); }),
      (e: unknown) => e instanceof TrustPersistError && ((e as Error).cause as Error).message === 'EROFS');
    assert.deepEqual(readFileSync(b.history), before, 'a failed write leaves the old history');
  } finally {
    b.done();
  }
});

test('BRIDGE_TRUST_MAX_ENTRIES is 1 to 64', () => {
  assert.equal(maxEntriesOf({}), 64);
  assert.equal(maxEntriesOf({ BRIDGE_TRUST_MAX_ENTRIES: '1' }), 1);
  for (const bad of ['0', '65', '2.5', 'x']) assert.throws(() => maxEntriesOf({ BRIDGE_TRUST_MAX_ENTRIES: bad }), /1 to 64/);
});
