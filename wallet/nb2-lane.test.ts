import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { runLaneWorkload } from '../packages/native-bridge-plugin/scripts/nb2-lane-run.js';
import { NativeBridgeV2 } from '../packages/native-bridge-plugin/src/nb2/bridge.js';
import { TEST_PARAMS } from '../packages/native-bridge-plugin/src/nb2/config.js';
import { localOwner } from '../packages/native-bridge-plugin/src/nb2/tokenops.js';
import { evmAccount, key, setup } from '../packages/native-bridge-plugin/test/nb2/world.js';

test('lane rejects an occupied output before certifying and resumes both an interrupted split and return', async (t) => {
  const w = await setup();
  const bridge = await NativeBridgeV2.open(w.options('lane retry'));
  const owner = localOwner(key('lane owner'));
  const payer = evmAccount(w.chain, 'lane payer');
  const intent = await bridge.planDeposit(21n, owner.publicKey);
  await bridge.submitDeposit(intent, payer);
  await bridge.collectDepositProof(intent.intent);
  const root = await bridge.mint(intent.intent);
  const dir = mkdtempSync(join(tmpdir(), 'nb2-lane-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const opts = { gamma: w.chain.gamma, params: TEST_PARAMS, trust: w.root.trust, root, owner, recipient: payer.address, minIndex: 0n, history: 'depth-20' as const };
  const occupied = join(dir, 'occupied');
  writeFileSync(occupied, 'existing');
  const before = w.agg.calls;
  await assert.rejects(runLaneWorkload({ ...opts, output: occupied, aggregator: w.agg }), /output already exists/);
  assert.equal(w.agg.calls, before);
  assert.equal(readFileSync(occupied, 'utf8'), 'existing');

  const output = join(dir, 'evidence');
  const state = () => JSON.parse(readFileSync(join(output + '.journal', 'state.json'), 'utf8')) as { step: number; pending?: { cd: string } };
  let attempts = 0;
  let interruptedSplit: string | undefined;
  let interruptedReturn: string | undefined;
  const aggregator = { certify: async (cd: Uint8Array) => {
    assert.equal(statSync(output).size, 0);
    const request = Buffer.from(cd).toString('hex');
    assert.equal(state().pending?.cd, request);
    const proof = await w.agg.certify(cd);
    attempts++;
    if (attempts === 1) {
      interruptedSplit = request;
      throw new Error('disconnected after split certification');
    }
    if (attempts === 2) assert.equal(request, interruptedSplit);
    if (state().step === 40 && interruptedReturn === undefined) {
      interruptedReturn = request;
      throw new Error('disconnected after return certification');
    }
    if (state().step === 40) assert.equal(request, interruptedReturn);
    return proof;
  } };
  const run = () => runLaneWorkload({ ...opts, output, aggregator });
  await assert.rejects(run(), /after split certification/);
  assert.equal(state().step, 0);
  await assert.rejects(run(), /after return certification/);
  assert.equal(state().step, 40);
  const finished = await run();
  assert.equal(finished.levels.length, 21);
  assert.equal(finished.evidenceBytes, statSync(output).size);
  assert.ok(finished.evidenceBytes > 0);
  assert.equal(state().step, 41);
  assert.equal(state().pending, undefined);
  assert.deepEqual(await run(), finished);
  assert.equal(attempts, 43);
});
