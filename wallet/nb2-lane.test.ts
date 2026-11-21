import assert from 'node:assert/strict';
import { existsSync, fstatSync, mkdtempSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { runLaneWorkload } from '../packages/native-bridge-plugin/scripts/nb2-lane-run.js';
import { NativeBridgeV2 } from '../packages/native-bridge-plugin/src/nb2/bridge.js';
import { decodeConfig, TEST_PARAMS } from '../packages/native-bridge-plugin/src/nb2/config.js';
import { localOwner } from '../packages/native-bridge-plugin/src/nb2/tokenops.js';
import { decodeUc } from '../packages/native-bridge-plugin/src/nb2/trust.js';
import { verifyReturn } from '../packages/native-bridge-plugin/src/nb2/verify.js';
import { evmAccount, key, roundNow, setup } from '../packages/native-bridge-plugin/test/nb2/world.js';
import { io } from './core.js';

test('lane syncs the journal name and any recovered pending request before certification', async (t) => {
  const w = await setup();
  const bridge = await NativeBridgeV2.open(w.options('lane journal sync'));
  const owner = localOwner(key('lane journal owner'));
  const payer = evmAccount(w.chain, 'lane journal payer');
  const intent = await bridge.planDeposit(21n, owner.publicKey);
  await bridge.submitDeposit(intent, payer);
  await bridge.collectDepositProof(intent.intent);
  const root = await bridge.mint(intent.intent);

  const dir = mkdtempSync(join(tmpdir(), 'nb2-lane-sync-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const output = join(dir, 'evidence');
  const journal = output + '.journal';
  const file = join(journal, 'state.json');
  const pending = (): string | undefined => existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')).pending?.cd : undefined;
  const parent = statSync(dir, { bigint: true });
  const fsync = io.fsync;
  let failParent = true;
  let failPending = true;
  let parentSynced = false;
  let pendingSynced = false;
  let attempts = 0;
  let savedRequest: string | undefined;
  const aggregator = { certify: async (cd: Uint8Array): Promise<Uint8Array> => {
    attempts++;
    assert.ok(parentSynced);
    assert.ok(pendingSynced);
    assert.equal(Buffer.from(cd).toString('hex'), savedRequest);
    throw new Error('stopped at certification');
  } };
  const run = () => runLaneWorkload({
    gamma: w.chain.gamma, params: TEST_PARAMS, trust: w.root.trust,
    root, owner, aggregator, recipient: payer.address, output, history: 'depth-20',
  });
  io.fsync = (fd) => {
    const target = fstatSync(fd, { bigint: true });
    if (target.dev === parent.dev && target.ino === parent.ino) {
      assert.ok(statSync(journal).isDirectory());
      if (failParent) {
        failParent = false;
        throw new Error('journal parent sync failed');
      }
      fsync(fd);
      parentSynced = true;
      return;
    }
    if (target.isDirectory() && pending() !== undefined) {
      if (failPending) {
        failPending = false;
        throw new Error('pending journal sync failed');
      }
      fsync(fd);
      pendingSynced = true;
      return;
    }
    fsync(fd);
  };
  try {
    await assert.rejects(run(), /journal parent sync failed/);
    assert.equal(attempts, 0);
    await assert.rejects(run(), /pending journal sync failed/);
    assert.equal(attempts, 0);
    assert.ok(parentSynced);
    savedRequest = pending();
    assert.ok(savedRequest);
    parentSynced = false;
    await assert.rejects(run(), /stopped at certification/);
    assert.equal(attempts, 1);
  } finally {
    io.fsync = fsync;
  }
});

test('lane reloads authority for the starting seal and spends, resumes exact requests and preserves occupied output', async (t) => {
  const w = await setup();
  const bridge = await NativeBridgeV2.open(w.options('lane retry'));
  const owner = localOwner(key('lane owner'));
  const payer = evmAccount(w.chain, 'lane payer');
  const mint = async (amount: bigint) => {
    const intent = await bridge.planDeposit(amount, owner.publicKey);
    await bridge.submitDeposit(intent, payer);
    await bridge.collectDepositProof(intent.intent);
    return bridge.mint(intent.intent);
  };
  const { K } = decodeConfig(w.chain.gamma, TEST_PARAMS);
  for (let i = 0n; i < K; i++) {
    const plan = await bridge.planReturn(await mint(1n), payer.address, payer.address);
    await bridge.burn(plan.returnId, owner);
    assert.equal((await bridge.submitRedeem(plan.returnId, payer)).state, 'paid');
  }
  const start = await bridge.newestSealReceipt();
  assert.ok(start);
  const sealRound = decodeUc(start.receipt.proof.uc).unicitySeal.rootChainRoundNumber;
  const root = await mint(21n);
  const dir = mkdtempSync(join(tmpdir(), 'nb2-lane-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const checkpoint = () => w.root.trust.withAuthenticatedOrigin({ usableEpoch: 1n, rootRound: roundNow() });
  const initial = w.root.trust.withAuthenticatedOrigin({ usableEpoch: 1n, rootRound: sealRound - 1n });
  let reloads = 0;
  const opts = {
    gamma: w.chain.gamma, params: TEST_PARAMS, trust: initial, root, owner, recipient: payer.address, startingSeal: start.encoded, history: 'depth-20' as const,
    originPollMs: 0, refreshTrust: async () => { reloads++; return checkpoint(); },
  };
  const occupied = join(dir, 'occupied');
  writeFileSync(occupied, 'existing');
  const before = w.agg.calls;
  await assert.rejects(runLaneWorkload({ ...opts, output: occupied, aggregator: w.agg }), /output already exists/);
  assert.equal(reloads, 1, 'the starting receipt needs a refresh before checking or spending the root');
  assert.equal(w.agg.calls, before);
  assert.equal(readFileSync(occupied, 'utf8'), 'existing');

  const output = join(dir, 'evidence');
  const journal = output + '.journal';
  const state = () => JSON.parse(readFileSync(join(journal, 'state.json'), 'utf8')) as {
    step: number; token: string; pending?: { cd: string };
  };
  let attempts = 0;
  let interruptedSplit: string | undefined;
  let interruptedReturn: string | undefined;
  const aggregator = { certify: async (cd: Uint8Array) => {
    assert.ok(reloads > 1);
    assert.equal(statSync(join(journal, 'evidence')).size, 0);
    assert.equal(existsSync(output), false);
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
    if (state().step === 40) {
      assert.equal(request, interruptedReturn);
      writeFileSync(output, 'created during certification', { flag: 'wx' });
    }
    return proof;
  } };
  const run = () => runLaneWorkload({ ...opts, output, aggregator });
  await assert.rejects(run(), /after split certification/);
  assert.equal(state().step, 0);
  await assert.rejects(run(), /after return certification/);
  assert.equal(state().step, 40);
  await assert.rejects(run(), /output already exists/);
  assert.equal(state().step, 41);
  assert.equal(readFileSync(output, 'utf8'), 'created during certification');
  await assert.rejects(run(), /output already exists/);
  unlinkSync(output);
  writeFileSync(output, 'replacement');
  await assert.rejects(run(), /output already exists/);
  assert.equal(readFileSync(output, 'utf8'), 'replacement');
  assert.ok(reloads >= 41, 'the initial checkpoint predates all certified spends');
  unlinkSync(output);

  const completed = state();
  const fsync = io.fsync;
  let raced = false;
  io.fsync = (fd) => {
    fsync(fd);
    const file = fstatSync(fd);
    if (!raced && file.isFile() && file.size === Buffer.byteLength(completed.token, 'hex')) {
      writeFileSync(output, 'created during staging fsync', { flag: 'wx' });
      raced = true;
    }
  };
  try {
    await assert.rejects(run(), (error: Error) => {
      assert.equal(error.message, `lane output already exists: ${output}`);
      assert.equal((error.cause as NodeJS.ErrnoException).code, 'EEXIST');
      return true;
    });
  } finally {
    io.fsync = fsync;
  }
  assert.ok(raced);
  assert.equal(readFileSync(output, 'utf8'), 'created during staging fsync');
  assert.deepEqual(state(), completed);
  unlinkSync(output);
  const finished = await run();
  assert.equal(finished.levels.length, 21);
  assert.equal(finished.evidenceBytes, statSync(output).size);
  assert.ok(finished.evidenceBytes > 0);
  const verdict = await verifyReturn(opts.gamma, readFileSync(output), checkpoint(), opts.params);
  assert.equal(verdict.minSegment, start.receipt.segment.index + 1n);
  assert.equal(state().step, 41);
  assert.equal(state().pending, undefined);
  assert.deepEqual(await run(), finished);
  assert.equal(attempts, 43);
});
