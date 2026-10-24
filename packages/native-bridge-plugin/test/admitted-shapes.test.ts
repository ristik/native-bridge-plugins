/**
 * Every admitted history has an exit (bft-core #438; `docs/admitted-shapes.md`): for each shape the receipt relation admits, the held token verifies as
 * a receipt, the same history with the wallet's terminal burn verifies as a return, and its return proof is built within the direct envelope bound and
 * the deployment's ordinary block capacity. The receipt relation is the return relation without the terminal burn (`verifyHistory`), so an admitted
 * history plus a well-formed burn is return-valid by construction; these tests show the resources of each shape fit as well.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { MAX_ENVELOPE_BYTES } from '../src/limits.js';
import { buildReturnProof } from '../src/proof.js';
import { buildToken, burnStep, makeWorld, spec, txStep, type Step, type Tweaks, type World } from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_100_000n;
/** The ordinary block capacity of the package's B1 profile (D3, recorded in bridge-release.json): the only gas bound (owner section 36). */
const BLOCK_GAS = 60_000_000;

/** The held token (receipt) and the same history burned (return): both verify, and the return proof fits. Returns the proof's measures. */
async function exits(w: World, transfers: Step[], tw: Tweaks = {}): Promise<{ anchors: number; envelopeBytes: number; gas: number }> {
  if (transfers.length > 0) {
    const held = await buildToken(w, spec(1), transfers, T0, UC_TS, tw);
    await w.bridge.verifyNativeToken(held.token, 'receipt');
  }
  const burned = await buildToken(w, spec(1), [...transfers, burnStep(T0 + 10n + BigInt(transfers.length) + 10n)], T0, UC_TS, tw);
  await w.bridge.verifyNativeToken(burned.token, 'return');
  const ret = await buildReturnProof(w.bridge, burned.token);
  assert.ok(ret.encoded.length <= MAX_ENVELOPE_BYTES, `envelope ${ret.encoded.length} B within the direct bound`);
  assert.ok(ret.gate.total <= BLOCK_GAS, `estimated gas ${ret.gate.total} within the block capacity`);
  return { anchors: ret.envelope.anchors.length, envelopeBytes: ret.encoded.length, gas: ret.gate.total };
}

const transfers = (n: number, f: (i: number) => Partial<{ mask: number; deadline: bigint | null }> = () => ({})): Step[] =>
  Array.from({ length: n }, (_, i) => {
    const o = f(i);
    return txStep((i % 200) + 2, o.mask ?? 7, T0 + 10n + BigInt(i), o.deadline ?? null);
  });

test('no transfer: the minted token burned straight away', async () => {
  await exits(await makeWorld(), []);
});

test('signature transfers with any state mask', async () => {
  const masks = [0x00, 0x01, 0x7f, 0x80, 0xff];
  await exits(await makeWorld(), transfers(masks.length, (i) => ({ mask: masks[i] })));
});

test('a transfer with a deadline, certified before it', async () => {
  await exits(await makeWorld(), transfers(2, (i) => ({ deadline: i === 0 ? T0 + 1000n : null })));
});

test('leaves certified in different rounds: one anchor per distinct certificate', async () => {
  const m = await exits(await makeWorld(), transfers(4), { ucRound: (i) => 900n + BigInt(i) });
  assert.equal(m.anchors, 6);
});

test('leaves in both shards of a depth-1 aggregation partition', async () => {
  const m = await exits(await makeWorld(20, 1), transfers(6));
  assert.ok(m.anchors >= 2, `anchors ${m.anchors}: the history spans both shards`);
});

test('a long history beyond the standalone kernel bound (64 transfers), every leaf under its own certificate', async () => {
  const m = await exits(await makeWorld(), transfers(100), { ucRound: (i) => 100n + BigInt(i) });
  assert.equal(m.anchors, 102);
});
