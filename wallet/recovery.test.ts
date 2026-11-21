import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, type TestContext } from 'node:test';
import type { ITrustBaseSource } from '@unicitylabs/state-transition-sdk/lib/api/ITrustBaseSource.js';
import { encodeTrustBaseResponse } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseResponseWire.js';
import { TrustBaseStatus } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseRange.js';
import { eq } from '../packages/native-bridge-plugin/src/bytes.js';
import {
  EvmReader, Nb2Error, SELECTOR, RecoveryAuthority, RecoverySession, RpcError, TEST_PARAMS, appendTransfer, buildHistory, decodeSignedTx,
  evidenceOf, recoveryGeneration, recoveryRpcSource, signTx, transferRequest, verifyReturn, verdictAbi,
  type Aggregator, type GasModel, type JsonRpc, type ReturnRecord, type RecoveryEvent,
} from '../packages/native-bridge-plugin/src/nb2/index.js';
import { HE } from '../packages/native-bridge-plugin/src/nb2/crypto.js';
import { ascii } from '../packages/native-bridge-plugin/src/nb2/cbor.js';
import { signaturePredicate } from '../packages/native-bridge-plugin/src/nb2/token.js';
import { FakeChain, FakeAggregator, key, makeConfig, makeRoot, roundNow, roundAtLeast } from '../packages/native-bridge-plugin/test/nb2/world.js';
import { nextEpoch } from '../packages/native-bridge-plugin/test/rootfixture.js';
import { Wallet, burn, connectionOf, hx, io, mint, planDeposit, planReturn, receive, resumePayout, sendDeposit, transfer, unhex } from './core.js';
import { ordinaryPayout, publishReturnBackup, qualifyExistingRecovery, recoverStep, restoreReturn, walletAdmission, type PayerPolicy } from './recovery.js';

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
  const open = (name: string, override: JsonRpc = rpc, opts: { aggregator?: Aggregator; trustSource?: ITrustBaseSource; origin?: string } = {}) =>
    new Wallet(join(dir, name), key(name), { ...conn, trustOrigin: opts.origin }).open({
      lock: false, rpc: override, aggregator: opts.aggregator ?? aggregator, gas, trustSource: opts.trustSource,
    });
  const w = await open('holder');
  chain.fund(w.signer.address, 10n ** 18n);
  await planDeposit(w, 'coin', 19n);
  await sendDeposit(w, 'coin');
  await mint(w, 'coin');
  return { w, open, root, cfg, chain, deployment, aggregator, dir, rpc, views, manifest };
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

test('ordinary release gas bound survives missing and smaller estimates with positive history', async (t) => {
  const { w, chain, cfg } = await setup(t, true);
  const background = await planDeposit(w, 'background', cfg.K);
  await sendDeposit(w, 'background');
  assert.equal(background.amount, cfg.K);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  assert.equal(rec.recovery, undefined);
  assert.equal(rec.a, '0');
  const marker = key('segment producer').slice(0, 20);
  chain.coldCall = async (vault, to) => {
    if (!eq(to, marker)) return undefined;
    for (let i = 0n; i < cfg.K; i++) {
      const eta = key(`background-eta-${i}`);
      vault.redeem(eta, 0n, new Uint8Array(), { ret: verdictAbi({
        domain: chain.domain, eta, minSegment: 0n, asset: cfg.asset, recipient: marker, amount: 1n,
      }) });
    }
    return [];
  };
  const submit = await signTx(w.signer, { chainId: cfg.chainId, nonce: await w.bridge.evm.nonce(w.signer.address),
    maxFeePerGas: 15n, maxPriorityFeePerGas: 1n, gas: 2_000_000n, to: marker, value: 0n, data: new Uint8Array() });
  await w.bridge.evm.sendRaw(submit.raw);
  assert.equal(chain.vault.c, 1n);
  const call = chain.call.bind(chain);
  let unsupported = false;
  chain.call = async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_estimateGas') {
      if (unsupported) throw new RpcError(200, -32601, 'no estimator');
      return '0x5208' as T;
    }
    return call<T>(method, params);
  };
  const opts = ordinaryPayout(w, rec, caps);
  const smallEstimate = await w.bridge.buildRedeem(unhex(rec.returnId), opts.envelope);
  assert.equal(smallEstimate.P, 1n);
  assert.equal(smallEstimate.gasLimit, 1_721_000n + 16n * BigInt(smallEstimate.calldata.length));
  unsupported = true;
  assert.equal((await resumePayout(w, rec, caps)).state, 'paid');
  const paid = (await w.bridge.journal.ret(rec.returnId))!;
  assert.equal(BigInt(paid.sends[0].gas), smallEstimate.gasLimit);
});

test('the signing gate rejects mismatched amounts, record IDs and source IDs on both routes', async (t) => {
  for (const ordinary of [false, true]) {
    const { w, aggregator } = await setup(t, ordinary);
    const plan = await planReturn(w, 'coin', undefined, undefined, caps);
    assert.equal(plan.record.recovery === undefined, ordinary);
    const keyOfRecord = `${w.bridge.journal.prefix}return/${plan.record.returnId.slice(2)}`;
    const store = w.bridge.journal.store;
    const before = (await store.get(keyOfRecord))!;
    const other = await transfer(w, 'coin', 'alternate', 0);
    const certifications = aggregator.calls;
    let signatures = 0;
    const owner = w.owner(0);
    const signer = { ...owner, signUnlock: (hash: Uint8Array) => { signatures++; return owner.signUnlock(hash); } };
    for (const patch of [{ amount: '20' }, { returnId: hx(key('different-record-id')) }, { source: hx(other) }]) {
      const corrupt = JSON.stringify({ ...JSON.parse(before), ...patch });
      assert.ok(await store.putIf(keyOfRecord, before, corrupt));
      await assert.rejects(w.bridge.burn(plan.returnId, signer, walletAdmission(w, caps)), { reason: 'BadInput' });
      assert.ok(await store.putIf(keyOfRecord, corrupt, before));
    }
    assert.equal(signatures, 0);
    assert.equal(aggregator.calls, certifications);
  }
});

test('ordinary signing re-prices the reserve against the newest bid inside the payer cap', async (t) => {
  const { w, chain, aggregator } = await setup(t, true);
  const p = await planReturn(w, 'coin', undefined, undefined, caps);
  const call = chain.call.bind(chain);
  let finalGate = false;
  chain.call = async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_getBlockByNumber' && params[0] === 'latest') {
      const block = await call<Record<string, string>>(method, params);
      return { ...block, baseFeePerGas: finalGate ? '0xa' : '0x7' } as T;
    }
    return call<T>(method, params);
  };
  const before = aggregator.calls;
  const policy = { ...caps, feeBudget: p.gasLimit * 21n - 1n };
  // The preview observed 15 wei. The final gate must use the newly observed 21 wei.
  assert.equal((await w.bridge.evm.fees()).baseFee, 7n);
  const admission = walletAdmission(w, policy);
  const check = admission.checkOrdinary!;
  await assert.rejects(w.bridge.burn(p.returnId, w.owner(0), {
    ...admission, recover: undefined, checkOrdinary: (...args) => {
      finalGate = true;
      return check(...args);
    },
  }), { rule: 'CapacityPreflight' });
  assert.equal(aggregator.calls, before);
  assert.equal((await w.returnRecord('coin')).status, 'planned');
  const exact = { ...policy, feeBudget: policy.feeBudget + 1n };
  await w.bridge.burn(p.returnId, w.owner(0), { ...walletAdmission(w, exact), recover: undefined });
  assert.equal(aggregator.calls, before + 1);
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
  const terminal = JSON.parse(readFileSync(join(reopened.dir, `recovery-${rec.returnId.slice(2)}.json`), 'utf8'));
  assert.equal(terminal.evidenceBytes, result.evidenceBytes);
  assert.equal(terminal.generation, rec.recovery!.generation);
  assert.match(terminal.session, /^0x[0-9a-f]{64}$/);
  assert.match(terminal.pageRoot, /^0x[0-9a-f]{64}$/);
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
    if (method === 'eth_getRawTransactionByBlockHashAndIndex') throw new RpcError(200, -32601, 'raw transactions pruned');
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
  const offline = { certify: async () => { throw new Error('certification service offline'); } };
  const other = await open('archive-relay-device-two', primary, { aggregator: offline });
  const broken = join(dir, 'bad-certified-cut.json');
  const doc = JSON.parse(readFileSync(portable, 'utf8'));
  const badSchedule = structuredClone(doc);
  badSchedule.pending.recovery.runCuts = [1, 1];
  writeFileSync(broken, JSON.stringify(badSchedule));
  await assert.rejects(restoreReturn(other, broken), /cut disagrees with the admitted schedule/);
  assert.equal(await other.bridge.journal.ret(rec.returnId), null);
  doc.checkpoint.cuts[0].location.logIndex = '99';
  writeFileSync(broken, JSON.stringify(doc));
  await assert.rejects(restoreReturn(other, broken), /locator/);
  assert.equal(await other.bridge.journal.ret(rec.returnId), null);
  writeFileSync(broken, JSON.stringify({ ...doc, terminal: hx(key('different terminal')) }));
  await assert.rejects(restoreReturn(other, broken));
  assert.equal(await other.bridge.journal.ret(rec.returnId), null);
  chain.fund(other.signer.address, 10n ** 18n);
  const restored = await restoreReturn(other, portable);
  const balance = chain.balanceOf(w.signer.address);
  assert.equal((await recoverStep(other, restored, alternate)).state, 'paid');
  assert.equal(chain.balanceOf(w.signer.address) - balance, 19n);
  assert.equal(chain.vault.q, 0n);
  assert.equal((await recoverStep(relay, rec, alternate)).state, 'paid');
  assert.equal(chain.balanceOf(w.signer.address) - balance, 19n);
});

test('portable replay refreshes for later certified cuts and reopening preserves the merged authority', async (t) => {
  const { w, open, rpc, root, chain, deployment, dir, manifest } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const oldRelease = readFileSync(manifest);
  const bundleFile = join(dir, 'trust-base.bundle.cbor');
  const originFile = join(dir, 'origin.json');
  const oldOrigin = { usableEpoch: '1', rootRound: '1000000' };
  const freshOrigin = { usableEpoch: '2', rootRound: '1000010' };
  writeFileSync(originFile, JSON.stringify(oldOrigin));
  const next = await nextEpoch({ ...root, entries: [root.trust.history.tip!.encode()] }, roundNow() + 1n, 1, 55);
  const offline = { certify: async () => { throw new Error('certifier is offline'); } };
  let requests = 0;
  const source: ITrustBaseSource = { getTrustBasePage: async (r) => {
    requests++;
    assert.equal(r.fromEpoch, 2n);
    return encodeTrustBaseResponse({ effectiveEnd: 2n, endEntryId: await next.trust.history.tip!.entryId(),
      entries: [next.entries[1]], fromEpoch: 2n, network: w.bridge.cfg.network, nextEpoch: null, status: BigInt(TrustBaseStatus.OK) });
  } };
  const relay = await open('epoch-relay', rpc, { aggregator: offline, trustSource: source, origin: originFile });
  const originallyHeld = readFileSync(join(relay.dir, 'recovery-authority.json'));

  // Accept the newer shipped bundle and origin, then restart against the original deployment files.
  writeFileSync(bundleFile, next.bundle);
  const changed = JSON.parse(oldRelease.toString());
  changed.trust.origin = freshOrigin;
  writeFileSync(manifest, JSON.stringify(changed));
  const advanced = await open('holder');
  assert.equal(advanced.trust.history.tip?.epoch, 2n);
  writeFileSync(bundleFile, root.bundle);
  writeFileSync(manifest, oldRelease);
  const author = await open('holder');
  assert.equal(author.trust.history.tip?.epoch, 2n);
  assert.equal(author.trust.origin?.usableEpoch, 2n);

  const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!), new RecoveryAuthority(author.trust, async () => undefined), TEST_PARAMS, deployment);
  const packet = await session.run(0, session.operationCount, author.trust);
  roundAtLeast(next.trust.history.tip!.epochStartRound);
  chain.certificateAuthority = { root: next, epoch: 2n };
  chain.coldCall = async (_vault, to) => eq(to, deployment.recovery)
    ? [{ address: deployment.recovery, topics: packet.event.topics, data: packet.event.data }] : undefined;
  assert.equal((await recoverStep(author, rec, caps)).state, 'checkpoint');

  const backup = join(dir, 'epoch-portable.json');
  publishReturnBackup(author, rec, backup);
  writeFileSync(originFile, JSON.stringify(freshOrigin));
  const restored = await restoreReturn(relay, backup);
  assert.equal(restored.eta, rec.eta);
  assert.equal(requests, 1, 'the later cut fetched the successor during restore');
  writeFileSync(originFile, JSON.stringify(oldOrigin));
  const restarted = await open('epoch-relay', rpc, { aggregator: offline, origin: originFile });
  assert.equal(restarted.trust.history.tip?.epoch, 2n);
  assert.equal(restarted.trust.origin?.rootRound, BigInt(freshOrigin.rootRound));

  // The local cut survives on its own as well, with an older authority copied alongside it.
  writeFileSync(join(relay.dir, 'recovery-authority.json'), originallyHeld);
  const local = await open('epoch-relay', rpc, { aggregator: offline, trustSource: source, origin: originFile });
  writeFileSync(originFile, JSON.stringify(freshOrigin));
  chain.fund(local.signer.address, 10n ** 18n);
  chain.autoMine = false;
  assert.equal((await recoverStep(local, restored, caps)).state, 'pending');
  assert.equal(requests, 2, 'local replay fetched and installed the successor before signing');
  assert.equal((await open('epoch-relay', rpc, { aggregator: offline })).trust.history.tip?.epoch, 2n);
});

test('the shared payer budget counts an outstanding cold send before an ordinary attempt', async (t) => {
  const { w, chain } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  chain.autoMine = false;
  assert.equal((await recoverStep(w, rec, caps)).state, 'pending');
  const file = join(w.dir, `recovery-${rec.returnId.slice(2)}.json`);
  const raw = JSON.parse(readFileSync(file, 'utf8')).pending.raw;
  const { request } = decodeSignedTx(unhex(raw));
  const coldFee = request.gas * request.maxFeePerGas;
  const ordinary = await w.bridge.buildRedeem(unhex(rec.returnId));
  const { baseFee, priority } = await w.bridge.evm.fees();
  const combined = coldFee + ordinary.gasLimit * (2n * baseFee + priority);
  await assert.rejects(resumePayout(w, rec, { ...caps, feeBudget: combined - 1n }, true), { rule: 'CapacityPreflight' });
  assert.equal((await w.bridge.journal.ret(rec.returnId))!.sends.length, 0);
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).pending.raw, raw);
  // Mine the ordinary attempt while the previous signed cold packet is still accounted for.
  chain.dropPool();
  chain.autoMine = true;
  assert.equal((await resumePayout(w, rec, { ...caps, feeBudget: combined }, true)).state, 'paid');
});

test('ordinary settlement refuses to re-sign a failed receipt until its exact transaction is certified', async (t) => {
  const { w, chain, cfg, rpc, open, deployment } = await setup(t, true);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  let sends = 0;
  chain.coldCall = async (_vault, to, data) => {
    if (sends === 1 && eq(to, cfg.vault) && eq(data.subarray(0, 4), SELECTOR.redeem)) {
      throw new Nb2Error('PayoutFailed');
    }
    return undefined;
  };
  const transport: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_estimateGas') return '0x1d4c0' as T;
    if (method === 'eth_sendRawTransaction' && ++sends === 1) {
      const raw = unhex(params[0] as string);
      await chain.mine([raw]); // no resulting-block certificate yet
      return hx(decodeSignedTx(raw).hash) as T;
    }
    return rpc.call<T>(method, params);
  } };
  const uncertain = await open('holder', transport);
  assert.equal((await resumePayout(uncertain, rec, caps)).state, 'pending');
  const pending = (await uncertain.bridge.journal.ret(rec.returnId))!.sends[0];
  assert.equal((await uncertain.bridge.evm.receipt(unhex(pending.hash)))!.status, '0x0');
  const restarted = await open('holder', transport);
  assert.equal((await resumePayout(restarted, rec, caps)).state, 'pending');
  assert.equal(sends, 1);
  assert.deepEqual((await restarted.bridge.journal.ret(rec.returnId))!.sends, [pending]);
  await chain.mine([]);
  const cold = await qualifyExistingRecovery(restarted, rec, caps);
  const session = await RecoverySession.create(chain.gamma, unhex(cold.burned!),
    new RecoveryAuthority(restarted.trust, async () => undefined), TEST_PARAMS, deployment);
  const packet = await session.run(0, cold.recovery!.runCuts[0], restarted.trust);
  const ordinaryTx = decodeSignedTx(unhex(pending.raw)).request;
  const combined = ordinaryTx.gas * ordinaryTx.maxFeePerGas +
    (1_221_000n + 16n * BigInt(packet.calldata.length)) * caps.maxFeePerGas;
  await assert.rejects(recoverStep(restarted, cold, { ...caps, feeBudget: combined - 1n }), { rule: 'CapacityPreflight' });
  assert.equal(sends, 1);
  assert.equal((await resumePayout(restarted, cold, caps, true)).state, 'paid');
  assert.equal(sends, 2);
});
