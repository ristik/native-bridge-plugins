import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { SignaturePredicateUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicateUnlockScript.js';
import { CborDeserializer as D } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';

import { eq, toHex } from '../src/bytes.js';
import { NativeError } from '../src/errors.js';
import { buildReturnProof } from '../src/proof.js';
import { MemorySplitJournal, planSplit, runSplit, type SplitHost, type SplitOutput } from '../src/splitflow.js';
import { createNativeBridgePlugin } from '../src/wallet.js';
import { assembleToken, buildToken, burnStep, certifyRequest, makeWorld, ownerPredicate, signer, spec, txStep, type World } from './world.js';

const T0 = 1_700_000_000n;
const UC_TS = T0 + 10_000n;

const out = (owner: number, amount: bigint, salt: number): SplitOutput => ({ recipient: ownerPredicate(signer(owner)).toCBOR(), amount, salt: new Uint8Array(32).fill(salt) });

/** A host whose aggregator is the test world; `failAt` names a certification (by its label) that fails once, as a crash would. */
function host(w: World, holder: number, failAt?: string) {
  const journal = new MemorySplitJournal();
  const calls: { what: string; request: Uint8Array }[] = [];
  let t = T0 + 100n;
  let failed = false;
  const h: SplitHost = {
    journal,
    unlock: (tx) => SignaturePredicateUnlockScript.create(tx, signer(holder)),
    certify: async (request: CertificationData, what: string) => {
      calls.push({ what, request: request.toCBOR() });
      if (what === failAt && !failed) {
        failed = true;
        throw new Error('crash (test)');
      }
      return certifyRequest(w, request, t++, UC_TS);
    },
  };
  return { h, journal, calls };
}

async function setup() {
  const w = await makeWorld();
  const plugin = createNativeBridgePlugin(w.bridge, { manifestRevision: 'm', profileRevision: 'p' });
  const held = await buildToken(w, spec(1), [txStep(7, 9, T0 + 5n)], T0, UC_TS); // 1000, held by owner 7
  return { w, plugin, held };
}

test('a planned split burns the source once and mints every output; each output is a held part of the root lock', async () => {
  const { w, plugin, held } = await setup();
  const { record, estimates } = await planSplit(plugin, 's1', held.bytes, [out(2, 400n, 0x10), out(3, 600n, 0x20)]);
  assert.equal(estimates.length, 2);
  assert.ok(estimates.every((g) => g.native > 0 && g.total > g.native));
  const { h, journal, calls } = host(w, 7);
  await journal.put(record);
  const children = await runSplit(plugin, record, h);
  assert.deepEqual(calls.map((c) => c.what), ['the split burn', 'split output 1/2', 'split output 2/2']);
  const amounts = [];
  for (const c of children) {
    const v = await w.bridge.verifyNativeToken(await Token.fromCBOR(c), 'receipt');
    assert.equal(v.lineage?.depth, 1);
    amounts.push(toHex(v.lineage!.partAmount));
  }
  assert.deepEqual(amounts, ['0190', '0258']);
  const saved = (await journal.get('s1'))!;
  assert.ok(saved.burned && saved.burnRequest && saved.children.every((c) => c !== null));
  // the first output, burned for its return, builds the V2 envelope of a depth-1 part; the plan's estimate is a lower bound of its gate
  const [, genesis] = D.decodeArray(D.decodeTag(children[0]).data, 3);
  const mint = await MintTransaction.fromCBOR(D.decodeArray(genesis, 2)[0]);
  const returned = await assembleToken(w, { ...spec(2), amount: Uint8Array.of(0x01, 0x90) }, mint, {}, [burnStep(T0 + 200n)], T0 + 150n, UC_TS);
  const built = await buildReturnProof(w.bridge, returned.token);
  assert.equal(built.verified.lineage?.depth, 1);
  assert.ok(estimates[0].native <= built.gate.native, `estimate ${estimates[0].native} <= gate ${built.gate.native}`);
});

test('a crash after the burn request is journaled resumes with the identical request; a crash after the burn never burns again', async () => {
  const { w, plugin, held } = await setup();
  const { record } = await planSplit(plugin, 's2', held.bytes, [out(2, 400n, 0x10), out(3, 600n, 0x20)]);
  const first = host(w, 7, 'the split burn');
  await first.journal.put(record);
  await assert.rejects(runSplit(plugin, record, first.h), /crash/);
  const afterCrash = (await first.journal.get('s2'))!;
  assert.ok(afterCrash.burnRequest && afterCrash.burned === undefined, 'the request was journaled before its submission');
  const children = await runSplit(plugin, afterCrash, first.h);
  assert.equal(first.calls.filter((c) => c.what === 'the split burn').length, 2);
  assert.ok(eq(first.calls[0].request, first.calls[1].request), 'the resubmission is the same request, never a second burn');
  assert.equal(children.length, 2);

  const second = host(w, 7, 'split output 2/2');
  const { record: r2 } = await planSplit(plugin, 's3', held.bytes, [out(2, 400n, 0x11), out(3, 600n, 0x21)]);
  await second.journal.put(r2);
  await assert.rejects(runSplit(plugin, r2, second.h), /crash/);
  const mid = (await second.journal.get('s3'))!;
  assert.ok(mid.burned && mid.children[0] !== null && mid.children[1] === null);
  const done = await runSplit(plugin, mid, second.h);
  assert.equal(second.calls.filter((c) => c.what === 'the split burn').length, 1, 'the burned source is in the journal: no second burn request');
  assert.ok(eq(done[0], mid.children[0]!), 'a journaled output is kept, not minted again');
});

test('a resumed split refuses a journaled burn request that is not its plan\'s', async () => {
  const { w, plugin, held } = await setup();
  const { record: a } = await planSplit(plugin, 'a', held.bytes, [out(2, 400n, 0x10), out(3, 600n, 0x20)]);
  const { record: b } = await planSplit(plugin, 'b', held.bytes, [out(2, 500n, 0x10), out(3, 500n, 0x20)], a.burnStateMask);
  const x = host(w, 7, 'the split burn');
  await assert.rejects(runSplit(plugin, a, x.h), /crash/);
  const journaled = (await x.journal.get('a'))!;
  await assert.rejects(runSplit(plugin, { ...b, burnRequest: journaled.burnRequest }, x.h), (e: unknown) => e instanceof NativeError && e.reason === 'ErrBurnReason');
});

test('plan refusals: outputs that do not sum to the held amount, a single output, a zero amount, repeated salts', async () => {
  const { plugin, held } = await setup();
  const refuses = (outs: SplitOutput[], reason: string) =>
    assert.rejects(planSplit(plugin, 'x', held.bytes, outs), (e: unknown) => e instanceof NativeError && e.reason === reason, reason);
  await refuses([out(2, 400n, 0x10), out(3, 599n, 0x20)], 'ErrSplitSum');
  await refuses([out(2, 1000n, 0x10)], 'ErrSplitProofCount');
  await refuses([out(2, 0n, 0x10), out(3, 1000n, 0x20)], 'ErrSplitSum');
  await refuses([out(2, 400n, 0x10), out(3, 600n, 0x10)], 'ErrSplitProofShape');
});
