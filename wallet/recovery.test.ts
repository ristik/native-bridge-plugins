import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, type TestContext } from 'node:test';
import { eq } from '../packages/native-bridge-plugin/src/bytes.js';
import {
  EvmReader, Nb2Error, RecoveryAuthority, RecoverySession, TEST_PARAMS, appendTransfer, buildHistory, decodeSignedTx,
  evidenceOf, recoveryGeneration, recoveryRpcSource, signTx, transferRequest, verifyReturn, verdictAbi,
  type GasModel, type JsonRpc, type ReturnRecord, type RecoveryEvent,
} from '../packages/native-bridge-plugin/src/nb2/index.js';
import { HE } from '../packages/native-bridge-plugin/src/nb2/crypto.js';
import { ascii } from '../packages/native-bridge-plugin/src/nb2/cbor.js';
import { signaturePredicate } from '../packages/native-bridge-plugin/src/nb2/token.js';
import { FakeChain, FakeAggregator, key, makeConfig, makeRoot } from '../packages/native-bridge-plugin/test/nb2/world.js';
import { Wallet, burn, connectionOf, hx, io, mint, planDeposit, planReturn, receive, sendDeposit, transfer, unhex } from './core.js';
import { publishReturnBackup, recoverStep, restoreReturn, type PayerPolicy } from './recovery.js';

const caps: PayerPolicy = { signedBytes: 524_288, calldataBytes: 524_288, gas: 24_000_000n, maxNonce: 10_000n,
  maxFeePerGas: 30n, maxPriorityFeePerGas: 2n, maxTransactionFee: 10n ** 9n, feeBudget: 10n ** 12n, archives: [] };
const gas: GasModel = { name: 'fixture without ordinary admission', depositGasLimit: () => 1_000_000n, redeemGasLimit: () => null };
const selector = (name: string) => hx(HE(ascii(name)).subarray(0, 4));

async function setup(t: TestContext, includeOrdinaryRange = false) {
  const dir = mkdtempSync(join(tmpdir(), 'nb2-recovery-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const root = await makeRoot(1);
  const code = ascii('simulated ordinary');
  const cfg = { ...makeConfig(root), verifierCodeHash: HE(code) };
  const chain = await FakeChain.create(root, cfg);
  const aggregator = new FakeAggregator(root);
  const recovery = Uint8Array.from(new Uint8Array(20).fill(7));
  const recoveryCode = ascii('simulated recovery');
  const deployment = { recovery, salt: key('salt'), pins: key('pins'), runtimeHash: HE(recoveryCode), vaultRuntimeHash: HE(chain.vaultCode) };
  const generation = recoveryGeneration(deployment.salt, chain.domain);
  const receiptHelper = new Uint8Array(20).fill(8);
  const lineageHelper = new Uint8Array(20).fill(9);
  const registry = unhex('0xff00000000000000000000000000000000000002');
  const word = (a: Uint8Array) => hx(Uint8Array.from([...new Uint8Array(12), ...a]));
  const views = new Map([
    [selector('RECOVERY()'), word(recovery)],
    [selector('RECOVERY_RUNTIME()'), hx(deployment.runtimeHash)],
    [selector('RECOVERY_PINS()'), hx(deployment.pins)],
    [selector('RECOVERY_GENERATION()'), hx(generation)],
  ]);
  const recoveryViews = new Map([[selector('RECEIPTS()'), word(receiptHelper)], [selector('LINEAGE()'), word(lineageHelper)]]);
  for (const [getter, address] of [['RECEIPTS_HASH()', receiptHelper], ['LINEAGE_HASH()', lineageHelper], ['REGISTRY_HASH()', registry]] as const) {
    const runtime = ascii(getter);
    chain.code.set(hx(address).slice(2), runtime);
    recoveryViews.set(selector(getter), hx(HE(runtime)));
  }
  const range = (entry: string, operations: number, gaps: number) => ({
    minReceiptBytes: entry === 'run' ? 0 : 1,
    max: { entry, operations, gaps, calldataBytes: 393216, pages: 32, receiptBytes: 65536, openingBytes: 393216 },
    execution: '1000000',
  });
  chain.code.set(hx(cfg.verifier).slice(2), code);
  chain.code.set(hx(recovery).slice(2), recoveryCode);
  const rpc: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_call') {
      const { to, data } = params[0] as { to: string; data: string };
      const result = to === hx(cfg.vault) ? views.get(data) : to === hx(recovery) ? recoveryViews.get(data) : undefined;
      if (result) return result as T;
    }
    return chain.call<T>(method, params);
  } };
  const manifest = join(dir, 'release.json');
  writeFileSync(manifest, JSON.stringify({
    pins: { gamma: hx(chain.gamma), build: 'test', vaultRuntimeCodeHash: hx(deployment.vaultRuntimeHash),
      maxEncodedTxBytes: 524288, userGasLimit: '24000000', gasReserve: '500000', returnReserveSegments: 64, deploymentBlock: 1,
      stateReadOnly: false },
    trust: { origin: { usableEpoch: '1', rootRound: '1000000' } },
    recovery: { salt: hx(deployment.salt), address: hx(recovery), runtimeHash: hx(deployment.runtimeHash), pins: hx(deployment.pins),
      ...(includeOrdinaryRange ? { ordinaryRanges: [{ maxEvidenceBytes: 100_000, maxOperations: 10, maxGaps: '64', execution: '1000000' }] } : {}),
      ranges: [
        ...Array.from({ length: 16 }, (_, i) => range('run', i + 1, 0)),
        ...Array.from({ length: 65 }, (_, i) => range('advanceGaps', 0, i + 1)),
        ...Array.from({ length: 65 }, (_, i) => range('redeemRecovered', 0, i)),
      ],
      backlog: { duringProgress: '0', peakSeals: '0', elapsedMs: '1000', receiptP99Ms: '1000',
        advancePeakSeals: '0', finalInclusionMs: '25', finalPeakSeals: '0', qualifiedForMs: '100000' },
    },
  }));
  writeFileSync(join(dir, 'trust-base.bundle.cbor'), root.bundle);
  writeFileSync(join(dir, 'trust-base.genesis.entryid'), hx(root.pin));
  const conn = connectionOf({ release: manifest, rpc: 'http://127.0.0.1:9' });
  const open = (name: string, override: JsonRpc = rpc, model: GasModel = gas) =>
    new Wallet(join(dir, name), key(name), conn).open({ lock: false, rpc: override, aggregator, gas: model });
  const w = await open('holder');
  chain.fund(w.signer.address, 10n ** 18n);
  await planDeposit(w, 'coin', 19n);
  await sendDeposit(w, 'coin');
  await mint(w, 'coin');
  return { w, open, root, cfg, chain, deployment, aggregator, dir, rpc, views };
}

test('refused preflight never certifies a spend, and receive verifies the full path and owner', async (t) => {
  const { w, open, aggregator, views } = await setup(t);
  const before = aggregator.calls;
  await assert.rejects(burn(w, 'coin', undefined, undefined, { ...caps, gas: 1n }), { rule: 'CapacityPreflight' });
  assert.equal(aggregator.calls, before);
  assert.equal(w.entry('coin').spent, undefined);
  const original = views.get(selector('RECOVERY_PINS()'))!;
  views.set(selector('RECOVERY_PINS()'), hx(key('different release')));
  await assert.rejects(burn(w, 'coin', undefined, undefined, caps), { reason: 'BadDeployment' });
  assert.equal(aggregator.calls, before);
  views.set(selector('RECOVERY_PINS()'), original);
  const other = await open('receiver');
  await assert.rejects(receive(other, 'coin', w.token('coin'), 0), /another owner/);
  const token = await transfer(w, 'coin', 'sent', 0, other.ownerPub(0));
  assert.match(await receive(other, 'coin', token, 0), /ordinary gap proofs.*minimum recovery packets/);
  assert.equal(other.entry('coin').amount, '19');
});

test('a qualified ordinary envelope takes precedence over the cold route', async (t) => {
  const { w } = await setup(t, true);
  const plan = await planReturn(w, 'coin', undefined, undefined, { ...caps, calldataBytes: 393_216 });
  assert.equal(plan.record.recovery, undefined);
  assert.equal(plan.a, 0n);
  assert.ok(plan.gasLimit > 1_700_000n && plan.gasLimit < caps.gas);
  assert.equal(w.entry('coin').spent, undefined);
});

test('a private backup made before submission restores the exact signed burn without the holder key', async (t) => {
  const { w, open, dir, aggregator } = await setup(t);
  const backup = join(dir, 'relayer-private.json');
  const old = io.durable;
  const before = aggregator.calls;
  io.durable = (file, data) => {
    old(file, data);
    if (file.includes('.nb2-backup-')) throw new Error('power lost while publishing holder-authorized backup');
  };
  try {
    await assert.rejects(burn(w, 'coin', undefined, undefined, caps, backup), /power lost/);
  } finally { io.durable = old; }
  assert.equal(aggregator.calls, before);
  const rec = await w.returnRecord('coin');
  assert.equal(rec.status, 'burn-requested');
  assert.ok(rec.burnTx && rec.burnRequest && rec.certificationLocator);
  assert.equal(existsSync(backup), false);
  const reopened = await open('holder');
  // Publish the pending authorization from disk without making another signed request.
  publishReturnBackup(reopened, rec, backup);
  assert.equal(statSync(backup).mode & 0o777, 0o600);
  const relay = await open('second-device');
  const copy = JSON.parse(readFileSync(backup, 'utf8'));
  const bad = join(dir, 'tampered.json');
  writeFileSync(bad, JSON.stringify({ ...copy, pending: { ...copy.pending, recipient: hx(relay.signer.address) } }));
  await assert.rejects(restoreReturn(relay, bad), { reason: 'BadInput' });
  assert.equal(aggregator.calls, before);
  const restored = await restoreReturn(relay, backup);
  assert.equal(restored.burnRequest, rec.burnRequest);
  assert.equal(restored.recipient, hx(w.signer.address));
  assert.notEqual(hx(relay.signer.address), restored.recipient);
  assert.ok(restored.eta);
  const result = await burn(reopened, 'coin', undefined, undefined, caps);
  assert.equal(hx(result.eta), restored.eta);
});

test('large lineage relays exact pending bytes across submission and checkpoint crashes, then reconciles competing Paid', { timeout: 420_000 }, async (t) => {
  const { w, open, chain, dir, deployment, aggregator, cfg, rpc } = await setup(t);
  let token = w.token('coin');
  const owner = w.owner(0);
  for (let i = 0; i < 304; i++) {
    const signed = await transferRequest(token, owner, {
      recipient: signaturePredicate(owner.publicKey), mask: key(`transfer-${i}`), data: null, deadline: null,
    });
    token = appendTransfer(token, signed.tx, await aggregator.certify(signed.cd));
  }
  w.keep('coin', token, 0, { amount: '19', intent: w.entry('coin').intent });
  const backup = join(dir, 'durable-backup.json');
  await burn(w, 'coin', undefined, undefined, caps, backup);
  let loseSubmission = true;
  let rawSendCount = 0;
  const relayRpc: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_sendRawTransaction') {
      rawSendCount++;
      const value = await rpc.call<T>(method, params);
      if (loseSubmission) {
        loseSubmission = false;
        throw new Error('power lost after network submission');
      }
      return value;
    }
    return rpc.call<T>(method, params);
  } };
  let relay = await open('relay', relayRpc);
  const rec = await restoreReturn(relay, backup);
  assert.ok(rec.burned && rec.recovery && rec.eta);
  assert.notEqual(hx(relay.signer.address), rec.recipient);
  chain.fund(relay.signer.address, 10n ** 18n);
  const evidence = evidenceOf(unhex(rec.burned));
  const session = await RecoverySession.create(chain.gamma, evidence,
    new RecoveryAuthority(relay.trust, async () => undefined), TEST_PARAMS, deployment);
  assert.equal(session.operationCount, 306);
  const verdict = await verifyReturn(chain.gamma, evidence, relay.trust, TEST_PARAMS);
  const file = join(relay.dir, `recovery-${rec.returnId.slice(2)}.json`);
  const journal = () => JSON.parse(readFileSync(file, 'utf8'));
  const expected: { hash: Uint8Array; event: RecoveryEvent; end: number }[] = [];
  const reader = new EvmReader(rpc);
  chain.coldCall = async (vault, to, data) => {
    const last = expected.at(-1);
    const seq = BigInt(expected.length);
    const previous = last ? await recoveryRpcSource(reader, last.hash)(deployment.recovery, last.event) : undefined;
    if (eq(to, deployment.recovery)) {
      const pending = journal().pending;
      const count = rec.recovery!.runCuts[expected.length];
      const packet = await session.run(last?.end ?? 0, count, relay.trust, previous ? { seq, receipt: previous } : undefined);
      assert.deepEqual(data, packet.calldata);
      const { hash } = decodeSignedTx(unhex(pending.raw));
      expected.push({ hash, event: packet.event, end: packet.end });
      return [{ address: deployment.recovery, topics: packet.event.topics, data: packet.event.data }];
    }
    if (eq(to, cfg.vault) && hx(data.subarray(0, 4)) === selector('redeemRecovered(bytes)')) {
      assert.ok(previous);
      const packet = await session.gaps('redeemRecovered', relay.trust, previous, { seq }, []);
      assert.deepEqual(data, packet.calldata);
      const history = buildHistory([], verdict.eta, verdict.minSegment, verdict.minSegment, unhex(rec.startHead));
      vault.redeem(verdict.eta, verdict.minSegment, history.history, { ret: verdictAbi(verdict) });
      return [];
    }
    return undefined;
  };
  await assert.rejects(recoverStep(relay, rec, caps), /power lost after network submission/);
  const signed = journal().pending;
  assert.equal(journal().cuts.length, 0);
  assert.equal(rawSendCount, 1);
  relay = await open('relay', relayRpc);
  const savedFsync = io.fsync;
  try {
    io.fsync = () => { throw new Error('power lost before the checkpoint rename'); };
    await assert.rejects(recoverStep(relay, rec, caps), /before the checkpoint rename/);
  } finally { io.fsync = savedFsync; }
  assert.deepEqual(journal().pending, signed);
  assert.equal(journal().cuts.length, 0);
  const savedDurable = io.durable;
  try {
    io.durable = (path) => { if (path === file) throw new Error('power lost after the checkpoint commit'); };
    await assert.rejects(recoverStep(relay, rec, caps), /after the checkpoint commit/);
  } finally { io.durable = savedDurable; }
  assert.equal(journal().cuts.length, 1);
  assert.equal(journal().pending, undefined);
  assert.equal(rawSendCount, 1, 'the same certified transaction was reconciled, never sent again');
  relay = await open('relay', relayRpc);
  while (journal().cuts.length < rec.recovery.runCuts.length) {
    assert.equal((await recoverStep(relay, rec, caps)).state, 'checkpoint');
  }
  assert.equal(expected.at(-1)!.end, 306);
  assert.equal(journal().cuts.at(-1).state, undefined);
  assert.ok(journal().cuts.at(-1).location.blockHash);

  const competing = await open('ordinary-payer');
  chain.fund(competing.signer.address, 10n ** 18n);
  const other: ReturnRecord = await restoreReturn(competing, backup);
  const ordinary = await competing.bridge.buildRedeem(unhex(other.returnId));
  const bid = await signTx(competing.signer, { chainId: cfg.chainId, nonce: 0n, maxFeePerGas: 23n, maxPriorityFeePerGas: 1n,
    gas: ordinary.gasLimit, to: cfg.vault, value: 0n, data: ordinary.calldata });
  chain.autoMine = false;
  assert.equal((await recoverStep(relay, rec, caps)).state, 'pending');
  const pending = unhex(journal().pending.raw);
  assert.notEqual(decodeSignedTx(pending).request.maxFeePerGas, bid.request.maxFeePerGas);
  const before = chain.balanceOf(w.signer.address);
  chain.dropPool();
  await chain.mine([bid.raw, pending]);
  await chain.mine([]);
  const paid = await recoverStep(relay, rec, caps);
  assert.equal(paid.state, 'paid');
  assert.equal(hx(paid.txHash), hx(bid.hash));
  assert.equal(chain.balanceOf(w.signer.address) - before, 19n);
  assert.equal(chain.vault.q, 0n);
  assert.equal(chain.vault.events.filter((event) => event.name === 'Paid').length, 1);
  const saved = (await relay.bridge.journal.ret(rec.returnId))!;
  assert.ok(saved.paid!.receipt);
  assert.equal(journal().pending, undefined);
  assert.equal(journal().settled.paidTx, hx(bid.hash));
});

test('a certified alternate archive carries a recovered payment through a pruned primary', async (t) => {
  const { createServer } = await import('node:http');
  const { w, open, chain, dir, deployment, cfg, rpc } = await setup(t);
  const backup = join(dir, 'alternate-private.json');
  await burn(w, 'coin', undefined, undefined, caps, backup);
  let preferred: string | undefined;
  let alternateReads = 0;
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    try {
      const result = await rpc.call(body.method, body.params);
      if (body.method === 'eth_getTransactionReceipt') alternateReads++;
      res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }));
    } catch (e) {
      res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -32000, message: String(e) } }));
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const alternate = { ...caps, archives: [`http://127.0.0.1:${(server.address() as { port: number }).port}`] };
  const primary: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_getTransactionReceipt' && preferred === params[0]) return null as T;
    return rpc.call<T>(method, params);
  } };
  const relay = await open('archive-relay', primary);
  chain.fund(relay.signer.address, 10n ** 18n);
  const rec = await restoreReturn(relay, backup);
  const E = evidenceOf(unhex(rec.burned!));
  const verdict = await verifyReturn(chain.gamma, E, relay.trust, TEST_PARAMS);
  const session = await RecoverySession.create(chain.gamma, E, new RecoveryAuthority(relay.trust, async () => undefined), TEST_PARAMS, deployment);
  const packet = await session.run(0, session.operationCount, relay.trust);
  let completeTx: Uint8Array | undefined;
  let failFirst = true;
  const reader = new EvmReader(rpc);
  chain.coldCall = async (vault, to, data) => {
    if (eq(to, deployment.recovery)) {
      assert.deepEqual(data, packet.calldata);
      if (failFirst) {
        failFirst = false;
        throw new Nb2Error('PayoutFailed');
      }
      const file = join(relay.dir, `recovery-${rec.returnId.slice(2)}.json`);
      const pending = JSON.parse(readFileSync(file, 'utf8')).pending;
      preferred = pending.txHash;
      completeTx = unhex(preferred!);
      return [{ address: deployment.recovery, topics: packet.event.topics, data: packet.event.data }];
    }
    if (eq(to, cfg.vault) && hx(data.subarray(0, 4)) === selector('redeemRecovered(bytes)')) {
      const proof = await recoveryRpcSource(reader, completeTx!)(deployment.recovery, packet.event);
      const settle = await session.gaps('redeemRecovered', relay.trust, proof, { seq: 1n }, []);
      assert.deepEqual(data, settle.calldata);
      const hist = buildHistory([], verdict.eta, verdict.minSegment, verdict.minSegment, unhex(rec.startHead));
      vault.redeem(verdict.eta, verdict.minSegment, hist.history, { ret: verdictAbi(verdict) });
      return [];
    }
    return undefined;
  };
  assert.equal((await recoverStep(relay, rec, alternate)).state, 'retry');
  assert.equal((await recoverStep(relay, rec, alternate)).state, 'checkpoint');
  assert.ok(alternateReads > 0);
  const portable = join(dir, 'certified-cut.private.json');
  publishReturnBackup(relay, rec, portable);
  const other = await open('archive-relay-device-two', primary);
  chain.fund(other.signer.address, 10n ** 18n);
  const restored = await restoreReturn(other, portable);
  const balance = chain.balanceOf(w.signer.address);
  assert.equal((await recoverStep(other, restored, alternate)).state, 'paid');
  assert.equal(chain.balanceOf(w.signer.address) - balance, 19n);
  assert.equal(chain.vault.q, 0n);
  assert.equal((await recoverStep(relay, rec, alternate)).state, 'paid');
  assert.equal(chain.balanceOf(w.signer.address) - balance, 19n);
});
