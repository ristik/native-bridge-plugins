import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, type TestContext } from 'node:test';
import type { ITrustBaseSource } from '@unicitylabs/state-transition-sdk/lib/api/ITrustBaseSource.js';
import { encodeTrustBaseResponse } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseResponseWire.js';
import { TrustBaseStatus } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseRange.js';
import { eq } from '../packages/native-bridge-plugin/src/bytes.js';
import {
  EvmReader, Nb2Error, SELECTOR, RecoveryAuthority, RecoverySession, RpcError, TEST_PARAMS, appendTransfer, buildHistory, decodeSignedTx,
  evidenceOf, quoteRecoveryGapBatch, recoveryGeneration, recoveryRpcSource, signTx, transferRequest, verifyReturn, verdictAbi,
  type Aggregator, type GasModel, type JsonRpc, type ReturnRecord, type RecoveryEvent,
} from '../packages/native-bridge-plugin/src/nb2/index.js';
import { HE } from '../packages/native-bridge-plugin/src/nb2/crypto.js';
import { ascii, u256 } from '../packages/native-bridge-plugin/src/nb2/cbor.js';
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
  const rpcOn = (view: FakeChain): JsonRpc => ({ call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_call') {
      const { to, data } = params[0] as { to: string; data: string };
      const result = to === hx(cfg.vault) ? views.get(data) : to === hx(recovery) ? recoveryViews.get(data) : undefined;
      if (result) return result as T;
    }
    return view.call<T>(method, params);
  } });
  const rpc = rpcOn(chain);
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
  const open = (name: string, override: JsonRpc = rpc, opts: { aggregator?: Aggregator; trustSource?: ITrustBaseSource; origin?: string; seed?: Uint8Array } = {}) =>
    new Wallet(join(dir, name), opts.seed ?? key(name), { ...conn, trustOrigin: opts.origin }).open({
      lock: false, rpc: override, aggregator: opts.aggregator ?? aggregator, gas, trustSource: opts.trustSource,
    });
  const w = await open('holder');
  chain.fund(w.signer.address, 10n ** 18n);
  await planDeposit(w, 'coin', 19n);
  await sendDeposit(w, 'coin');
  await mint(w, 'coin');
  return { w, open, root, cfg, chain, deployment, aggregator, dir, rpc, rpcOn, views, manifest };
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

test('the signing gate binds the source, amount, IDs and authorized recipient on both routes', async (t) => {
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
    const cases = [
      { patch: { amount: '20' } }, { patch: { returnId: hx(key('different-record-id')) } }, { patch: { source: hx(other) } },
      { patch: { recipient: hx(new Uint8Array(19)) } },
      { patch: { recipient: hx(new Uint8Array(20)) }, reason: 'RecipientRefused' },
      { patch: { recipient: hx(w.bridge.cfg.vault) }, reason: 'RecipientRefused' },
      { patch: { recipient: hx(key('different authorized address').slice(0, 20)) } },
    ];
    for (const { patch, reason = 'BadInput' } of cases) {
      const corrupt = JSON.stringify({ ...JSON.parse(before), ...patch });
      assert.ok(await store.putIf(keyOfRecord, before, corrupt));
      await assert.rejects(w.bridge.burn(plan.returnId, signer, walletAdmission(w, caps), plan.recipient), { reason });
      assert.ok(await store.putIf(keyOfRecord, corrupt, before));
    }
    assert.equal(signatures, 0);
    assert.equal(aggregator.calls, certifications);
  }
});

test('a reopened wallet refuses an altered planned recipient and keeps the original authorization', async (t) => {
  for (const ordinary of [true, false]) {
    const { w, open, aggregator } = await setup(t, ordinary);
    const address = key('original holder authorization').slice(0, 20);
    const plan = await planReturn(w, 'coin', address, undefined, caps);
    assert.equal(plan.record.recovery === undefined, ordinary);
    const path = `${w.bridge.journal.prefix}return/${plan.record.returnId.slice(2)}`;
    const store = w.bridge.journal.store;
    const original = (await store.get(path))!;
    const altered = JSON.stringify({ ...JSON.parse(original), recipient: hx(key('recipient substitution').slice(0, 20)) });
    assert.ok(await store.putIf(path, original, altered));
    const reopened = await open('holder');
    const certifications = aggregator.calls;
    await assert.rejects(burn(reopened, 'coin', undefined, undefined, caps), /saved holder authorization/);
    assert.equal(aggregator.calls, certifications);
    assert.equal(reopened.entry('coin').spent, undefined);
    assert.ok(await store.putIf(path, altered, original));
    await burn(reopened, 'coin', undefined, undefined, caps);
    assert.equal((await reopened.returnRecord('coin')).recipient, hx(address));
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
  const { w, open, chain, dir, deployment, cfg, rpc, manifest } = await setup(t);
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
  // The certified Complete remains usable even if its old run class is no longer priced.
  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  release.recovery.ranges = release.recovery.ranges.filter((r: { max: { entry: string } }) => r.max.entry !== 'run');
  writeFileSync(manifest, JSON.stringify(release));
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

test('restore checks full gap batches and every settlement suffix against the release envelope', async (t) => {
  const { w, dir, manifest, open, rpc } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const correct = join(dir, 'valid-gap-plan.json');
  publishReturnBackup(w, rec, correct);
  const backup = JSON.parse(readFileSync(correct, 'utf8'));
  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  const template = release.recovery.ranges.find((r: { max: { entry: string } }) => r.max.entry === 'advanceGaps');
  release.recovery.ranges.push(
    { ...template, max: { ...template.max, gaps: 66, receiptBytes: 65_535 } },
    { ...template, max: { ...template.max, gaps: 67, calldataBytes: 68 } },
    { ...template, max: { ...template.max, gaps: 68 }, execution: '25000000' },
    { ...template, max: { ...template.max, gaps: 69 } },
  );
  writeFileSync(manifest, JSON.stringify(release));
  const offline = { certify: async () => { throw new Error('expected a certified backup'); } };
  const relay = await open('portable-gap-plan', rpc, { aggregator: offline });
  const invalid = join(dir, 'invalid-gap-plan.json');
  // Check truncated receipt coverage, undersized calldata, excessive gas, a missing suffix and an absent advance class.
  for (const advanceGaps of [66, 67, 68, 69, 70]) {
    const doc = structuredClone(backup);
    doc.pending.recovery.advanceGaps = advanceGaps;
    writeFileSync(invalid, JSON.stringify(doc));
    await assert.rejects(restoreReturn(relay, invalid), { rule: 'CapacityPreflight' });
    assert.equal(await relay.bridge.journal.ret(rec.returnId), null);
  }
  assert.deepEqual((await restoreReturn(relay, correct)).recovery, rec.recovery);
});

test('admission and restore use the same maximum-width signed envelope at a tight byte cap', async (t) => {
  const { w, dir, manifest, open, deployment, cfg, rpc } = await setup(t);
  const doc = JSON.parse(readFileSync(manifest, 'utf8'));
  for (const entry of ['advanceGaps', 'redeemRecovered']) {
    const template = doc.recovery.ranges.find((range: { max: { entry: string } }) => range.max.entry === entry);
    for (let gaps = entry === 'advanceGaps' ? 66 : 65; gaps <= 1024; gaps++) {
      doc.recovery.ranges.push({ ...template, max: { ...template.max, gaps } });
    }
  }
  const calibration = {
    pins: deployment.pins, runtimeHash: deployment.runtimeHash, vaultRuntimeHash: deployment.vaultRuntimeHash,
    ranges: doc.recovery.ranges.map((range: { execution: string }) => ({ ...range, execution: BigInt(range.execution) })),
  };
  const limits = { ...caps, chainId: cfg.chainId, balance: 10n ** 18n };
  const narrow = quoteRecoveryGapBatch(cfg.K, 1024, calibration, limits)!;
  const wide = quoteRecoveryGapBatch(cfg.K, 1024, calibration, { ...limits, worstCaseEnvelope: true })!;
  assert.ok(narrow.advance.signedBytes < wide.advance.signedBytes);
  doc.pins.maxEncodedTxBytes = narrow.advance.signedBytes;
  writeFileSync(manifest, JSON.stringify(doc));
  // The wallet prices the observed backlog even when the latest certified start is zero.
  const backlog: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
    const result = await rpc.call<T>(method, params);
    if (method !== 'eth_call' || (params[0] as { data: string }).data !== hx(SELECTOR.state)) return result;
    const state = unhex(result as string);
    state.set(u256(960n), 32);
    return hx(state) as T;
  } };
  const holder = await open('holder', backlog);
  const { plan } = await burn(holder, 'coin', undefined, undefined, caps);
  assert.equal(plan!.record.recovery!.advanceGaps, 1023, 'the next smaller batch fits the portable envelope');
  const file = join(dir, 'width-boundary.json');
  const rec = await holder.returnRecord('coin');
  publishReturnBackup(holder, rec, file);
  assert.deepEqual((await restoreReturn(await open('width-relayer', backlog), file)).recovery, rec.recovery);
  assert.equal(w.pins.maxEncodedTxBytes, 524_288n);
});

test('restore refuses an unfunded remaining run class and a fully quoted zero-progress batch', async (t) => {
  const { w, dir, manifest, open } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const correct = join(dir, 'completable.json');
  publishReturnBackup(w, rec, correct);
  const backup = JSON.parse(readFileSync(correct, 'utf8'));
  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  release.recovery.ranges = release.recovery.ranges.filter((r: { max: { entry: string; operations: number } }) =>
    r.max.entry !== 'run' || r.max.operations !== 1);
  release.recovery.backlog.advancePeakSeals = '1';
  writeFileSync(manifest, JSON.stringify(release));
  const relay = await open('portable-completion');
  const invalid = join(dir, 'incomplete.json');
  const missingRun = structuredClone(backup);
  missingRun.pending.recovery.runCuts = [1, 1];
  writeFileSync(invalid, JSON.stringify(missingRun));
  await assert.rejects(restoreReturn(relay, invalid), { rule: 'CapacityPreflight', detail: 'portable run cut is outside the release limits' });
  assert.equal(await relay.bridge.journal.ret(rec.returnId), null);
  backup.pending.recovery.advanceGaps = 1;
  writeFileSync(invalid, JSON.stringify(backup));
  await assert.rejects(restoreReturn(relay, invalid), { rule: 'CapacityPreflight', detail: 'insufficient certified catch-up rate' });
  assert.equal(await relay.bridge.journal.ret(rec.returnId), null);
  assert.deepEqual((await restoreReturn(relay, correct)).recovery, rec.recovery);
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

test('an outstanding cold send uses one pinned nonce and balance snapshot before an ordinary attempt', async (t) => {
  const { w, chain, rpc, open } = await setup(t);
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
  chain.balances.set(hx(w.signer.address).slice(2), combined - 1n);
  const tags: unknown[] = [];
  let allowSend = false;
  const mixed: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_getTransactionCount' && params[1] === 'latest') {
      // The independent latest nonce comes from a node that already advanced past the cold attempt.
      return `0x${(request.nonce + 1n).toString(16)}` as T;
    }
    if (method === 'eth_getBalance' || (method === 'eth_getTransactionCount' && params[1] !== 'pending')) tags.push(params[1]);
    if (method === 'eth_sendRawTransaction' && !allowSend) throw new Error('signing from mismatched block states');
    return rpc.call<T>(method, params);
  } };
  const reopened = await open('holder', mixed);
  const block = `0x${(await w.bridge.evm.blockNumber()).toString(16)}`;
  await assert.rejects(resumePayout(reopened, rec, caps, true), { rule: 'CapacityPreflight' });
  assert.deepEqual(tags, [block, block]);
  assert.equal((await reopened.bridge.journal.ret(rec.returnId))!.sends.length, 0);
  chain.balances.set(hx(w.signer.address).slice(2), combined);
  chain.dropPool();
  chain.autoMine = true;
  allowSend = true;
  assert.equal((await resumePayout(reopened, rec, caps, true)).state, 'paid');
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
  // The balance already reflects the mined failure. Only the next attempt needs funds here.
  chain.balances.set(hx(restarted.signer.address).slice(2), ordinaryTx.gas * ordinaryTx.maxFeePerGas);
  assert.equal((await resumePayout(restarted, cold, caps, true)).state, 'paid');
  assert.equal(sends, 2);
});

test('ordinary restart refuses an unrelated certified failure hash in the send journal', async (t) => {
  const { w, chain, cfg, rpc, open } = await setup(t, true);
  const marker = key('unrelated certified failure').slice(0, 20);
  chain.coldCall = async (_vault, to, data) => {
    if (eq(to, marker) || (eq(to, cfg.vault) && eq(data.subarray(0, 4), SELECTOR.redeem))) {
      throw new Nb2Error('PayoutFailed');
    }
    return undefined;
  };
  const unrelated = await signTx(w.signer, { chainId: cfg.chainId, nonce: await w.bridge.evm.nonce(w.signer.address),
    maxFeePerGas: 15n, maxPriorityFeePerGas: 1n, gas: 1_000_000n, to: marker, value: 0n, data: new Uint8Array() });
  await w.bridge.evm.sendRaw(unrelated.raw);
  const failed = (await w.bridge.evm.receipt(unrelated.hash))!;
  await w.bridge.evm.verifyFailedReceipt(unrelated.hash, cfg, w.trust, failed);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  let sends = 0;
  const transport: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_estimateGas') return '0x1d4c0' as T;
    if (method === 'eth_sendRawTransaction') {
      sends++;
      const raw = unhex(params[0] as string);
      await chain.mine([raw]);
      return hx(decodeSignedTx(raw).hash) as T;
    }
    return rpc.call<T>(method, params);
  } };
  const first = await open('holder', transport);
  assert.equal((await resumePayout(first, rec, caps)).state, 'pending');
  const path = `${first.bridge.journal.prefix}return/${rec.returnId.slice(2)}`;
  const original = (await first.bridge.journal.store.get(path))!;
  const unrelatedFailure = JSON.parse(original);
  unrelatedFailure.sends[0].hash = hx(unrelated.hash);
  assert.ok(await first.bridge.journal.store.putIf(path, original, JSON.stringify(unrelatedFailure)));
  const restarted = await open('holder', transport);
  await assert.rejects(resumePayout(restarted, rec, caps), /hash does not match its signed transaction/);
  assert.equal(sends, 1);
});

test('restore qualifies and keeps the same checkpoint that will execute across both orderings', async (t) => {
  const { w, dir, manifest, open, rpc, chain, deployment } = await setup(t);
  const original = join(dir, 'original-return.json');
  await burn(w, 'coin', undefined, undefined, caps, original);
  const rec = await w.returnRecord('coin');
  const old = await open('older-local');
  const oldRec = await restoreReturn(old, original);
  chain.fund(old.signer.address, 10n ** 18n);
  const localFile = (wallet: Wallet) => join(wallet.dir, `recovery-${rec.returnId.slice(2)}.json`);
  const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const packet = await session.run(0, session.operationCount, w.trust);
  let refuseProgress = true;
  chain.coldCall = async (_vault, to) => {
    if (!eq(to, deployment.recovery)) return undefined;
    if (refuseProgress) throw new Nb2Error('PayoutFailed');
    return [{ address: deployment.recovery, topics: packet.event.topics, data: packet.event.data }];
  };
  assert.equal((await recoverStep(old, oldRec, caps)).state, 'retry');
  const oldAttempts = JSON.parse(readFileSync(localFile(old), 'utf8')).attempts;
  assert.equal(oldAttempts.length, 1);

  const withPending = await open('pending-local');
  const pendingRec = await restoreReturn(withPending, original);
  chain.fund(withPending.signer.address, 10n ** 18n);
  chain.autoMine = false;
  assert.equal((await recoverStep(withPending, pendingRec, caps)).state, 'pending');
  const pending = readFileSync(localFile(withPending), 'utf8');
  chain.dropPool();
  chain.autoMine = true;
  refuseProgress = false;
  assert.equal((await recoverStep(w, rec, caps)).state, 'checkpoint');
  const portable = join(dir, 'certified-complete.json');
  publishReturnBackup(w, rec, portable);
  await restoreReturn(withPending, original);
  assert.equal(readFileSync(localFile(withPending), 'utf8'), pending, 'a signing backup keeps the pending packet at its exact predecessor');

  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  release.recovery.ranges = release.recovery.ranges.filter((r: { max: { entry: string } }) => r.max.entry !== 'run');
  writeFileSync(manifest, JSON.stringify(release));
  // The local send receives certification while the relayer is down and still records it as pending.
  const raw = JSON.parse(pending).pending.raw;
  cpSync(withPending.dir, join(dir, 'pruned-local'), { recursive: true });
  await chain.mine([unhex(raw)]);
  await chain.mine([]);
  const receipt = (await w.bridge.evm.receipt(decodeSignedTx(unhex(raw)).hash))!;
  const prunedReader: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> =>
    method === 'eth_getBlockByHash' && params[0] === receipt.blockHash ? Promise.resolve(null as T) : rpc.call<T>(method, params) };
  const pruned = await open('pruned-local', prunedReader);
  await assert.rejects(restoreReturn(pruned, original), { rule: 'EvidencePruned' });
  assert.equal(readFileSync(localFile(pruned), 'utf8'), pending);
  const staleHint = join(dir, 'complete-stale-hint.json');
  const copy = JSON.parse(readFileSync(portable, 'utf8'));
  copy.checkpoint.cuts[0].location.txHash = hx(key('unrelated transaction hint'));
  writeFileSync(staleHint, JSON.stringify(copy));
  await restoreReturn(pruned, staleHint);
  const fromPortable = JSON.parse(readFileSync(localFile(pruned), 'utf8'));
  assert.equal(fromPortable.pending, undefined);
  assert.equal(fromPortable.cuts.length, 1);
  assert.deepEqual(fromPortable.attempts, [raw]);
  chain.fund(pruned.signer.address, 10n ** 18n);
  chain.autoMine = false;
  assert.equal((await recoverStep(pruned, (await pruned.bridge.journal.ret(rec.returnId))!, caps)).state, 'pending');
  assert.equal(JSON.parse(readFileSync(localFile(pruned), 'utf8')).pending.cut.kind, 'settle');
  chain.dropPool();
  chain.autoMine = true;

  const restartedPending = await open('pending-local', rpc);
  await restoreReturn(restartedPending, original);
  const reconciled = readFileSync(localFile(restartedPending), 'utf8');
  assert.equal(JSON.parse(reconciled).cuts.length, 1);
  assert.equal(JSON.parse(reconciled).pending, undefined);
  assert.deepEqual(JSON.parse(reconciled).attempts, [raw]);
  await restoreReturn(restartedPending, original);
  assert.equal(readFileSync(localFile(restartedPending), 'utf8'), reconciled);

  const ahead = await open('holder', rpc);
  const newest = readFileSync(localFile(ahead), 'utf8');
  await restoreReturn(ahead, original);
  assert.equal(readFileSync(localFile(ahead), 'utf8'), newest, 'the old file cannot roll back certified Complete');

  const behind = await open('older-local', rpc);
  const imported = await restoreReturn(behind, portable);
  const saved = readFileSync(localFile(behind), 'utf8');
  assert.equal(JSON.parse(saved).cuts.length, 1, 'the newer portable Complete becomes the execution checkpoint');
  assert.deepEqual(JSON.parse(saved).attempts, oldAttempts);
  await restoreReturn(behind, portable);
  assert.equal(readFileSync(localFile(behind), 'utf8'), saved, 'repeating the same import is a no-op');
  chain.autoMine = false;
  assert.equal((await recoverStep(behind, imported, caps)).state, 'pending');
  assert.equal(JSON.parse(readFileSync(localFile(behind), 'utf8')).pending.cut.kind, 'settle');
});

test('restore reconciles certified Paid before qualifying future packets', async (t) => {
  const { w, dir, manifest, open, rpc } = await setup(t);
  const original = join(dir, 'paid-from-signing-backup.json');
  await burn(w, 'coin', undefined, undefined, caps, original);
  const rec = await w.returnRecord('coin');
  const relayer = await open('paid-relayer');
  await restoreReturn(relayer, original);
  const signed = await open('signed-relayer');
  const pending = JSON.parse(readFileSync(original, 'utf8')).pending;
  assert.equal((await signed.bridge.importPendingReturn(pending)).status, 'burn-requested');
  const certified = join(dir, 'paid-from-certified-backup.json');
  publishReturnBackup(w, rec, certified);

  const paid = await resumePayout(w, rec, caps, true);
  assert.equal(paid.state, 'paid');
  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  release.recovery.ranges = [];
  release.recovery.backlog.qualifiedForMs = '1';
  writeFileSync(manifest, JSON.stringify(release));

  const offline = { certify: async () => { throw new Error('certifier offline after payout'); } };
  for (const [name, backup] of [
    ['signed-relayer', original], ['paid-relayer', original], ['fresh-paid', certified], ['fresh-signing-time', original],
  ]) {
    const device = await open(name, undefined, { aggregator: offline });
    const reconciled = await restoreReturn(device, backup, caps);
    assert.equal(reconciled.status, 'paid', name);
    assert.equal(reconciled.paid!.txHash, hx(paid.txHash!), name);
    assert.ok(reconciled.paid!.receipt, name);
    assert.equal((await resumePayout(device, reconciled, caps)).state, 'paid', name);
  }
  const noSearch: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_getLogs') throw new Error('archive disabled after payout');
    return rpc.call<T>(method, params);
  } };
  const reopened = await open('paid-relayer', noSearch);
  const reconciled = await restoreReturn(reopened, original);
  assert.equal((await resumePayout(reopened, reconciled, caps)).state, 'paid');
});

test('an ordinary relayer adopts a later portable Complete and keeps its own fee reservations', async (t) => {
  const { w, chain, deployment, cfg, dir, open, rpc } = await setup(t, true);
  const original = join(dir, 'ordinary-signing.json');
  await burn(w, 'coin', undefined, undefined, caps, original);
  const rec = await w.returnRecord('coin');
  assert.equal(rec.recovery, undefined);
  const transport: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_estimateGas') return '0x1d4c0' as T;
    if (method === 'eth_sendRawTransaction') {
      const raw = unhex(params[0] as string);
      await chain.mine([raw]);
      return hx(decodeSignedTx(raw).hash) as T;
    }
    return rpc.call<T>(method, params);
  } };
  const relay = await open('ordinary-relayer', transport);
  chain.fund(relay.signer.address, 10n ** 18n);
  const ordinary = await restoreReturn(relay, original);
  chain.coldCall = async (_vault, to, data) => {
    if (eq(to, cfg.vault) && eq(data.subarray(0, 4), SELECTOR.redeem)) throw new Nb2Error('PayoutFailed');
    return undefined;
  };
  assert.equal((await resumePayout(relay, ordinary, caps)).state, 'pending');
  await chain.mine([]);
  const sends = (await relay.bridge.journal.ret(rec.returnId))!.sends;
  assert.equal(sends.length, 1);

  const cold = await qualifyExistingRecovery(w, rec, caps);
  const session = await RecoverySession.create(chain.gamma, unhex(cold.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const packet = await session.run(0, session.operationCount, w.trust);
  chain.coldCall = async (_vault, to) => eq(to, deployment.recovery)
    ? [{ address: deployment.recovery, topics: packet.event.topics, data: packet.event.data }] : undefined;
  const complete = await recoverStep(w, cold, caps);
  assert.equal(complete.state, 'checkpoint');
  const portable = join(dir, 'ordinary-later-complete.json');
  publishReturnBackup(w, cold, portable);

  const restarted = await open('ordinary-relayer', rpc);
  const file = join(restarted.dir, `recovery-${rec.returnId.slice(2)}.json`);
  const savedDurable = io.durable;
  try {
    io.durable = (path) => { if (path === file) throw new Error('power lost after staging portable Complete'); };
    await assert.rejects(restoreReturn(restarted, portable), /power lost/);
  } finally { io.durable = savedDurable; }
  assert.equal((await restarted.bridge.journal.ret(rec.returnId))!.recovery, undefined);
  const reopened = await open('ordinary-relayer', rpc);
  const adopted = await restoreReturn(reopened, portable);
  assert.deepEqual(adopted.recovery, cold.recovery);
  assert.deepEqual(adopted.sends, sends);
  const journal = JSON.parse(readFileSync(file, 'utf8'));
  assert.equal(journal.cuts.length, 1);
  assert.equal(journal.attempts, undefined, 'the holder’s cold fees are outside the relayer’s ledger');
  const proof = unhex(journal.cuts[0].location.proof);
  const settlement = await session.gaps('redeemRecovered', reopened.trust, proof, { seq: 1n }, []);
  const { request } = decodeSignedTx(unhex(sends[0].raw));
  const cost = request.gas * request.maxFeePerGas + (1_721_000n + 16n * BigInt(settlement.calldata.length)) * caps.maxFeePerGas;
  assert.deepEqual((await restoreReturn(reopened, portable)).sends, sends);
  await assert.rejects(recoverStep(reopened, adopted, { ...caps, feeBudget: cost - 1n }), { rule: 'CapacityPreflight' });
  chain.autoMine = false;
  assert.equal((await recoverStep(reopened, adopted, { ...caps, feeBudget: cost })).state, 'pending');
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).pending.cut.kind, 'settle');
});

test('holder burn resume repairs a missing token-index return ID without another signature', async (t) => {
  const { w, open, dir } = await setup(t);
  const offline = { certify: async () => { throw new Error('certifier paused before submission'); } };
  const interrupted = await open('holder', undefined, { aggregator: offline });
  await assert.rejects(burn(interrupted, 'coin', undefined, undefined, caps), /certifier paused/);
  const signed = await interrupted.returnRecord('coin');
  assert.equal(signed.status, 'burn-requested');
  interrupted.update('coin', { returnId: undefined });
  const reopened = await open('holder');
  assert.equal(reopened.entry('coin').returnId, undefined);
  const owner = reopened.owner(0);
  reopened.owner = () => ({ ...owner, signUnlock: async () => { throw new Error('second signature'); } });
  assert.equal((await burn(reopened, 'coin', undefined, undefined, caps)).plan, null);
  assert.equal(reopened.entry('coin').returnId, signed.returnId);
  const certified = await reopened.returnRecord('coin');
  assert.equal(certified.burnRequest, signed.burnRequest);
  assert.equal(certified.status, 'burned');
  reopened.update('coin', { returnId: undefined });
  const certifiedOnly = await open('holder', undefined, { aggregator: offline });
  assert.equal((await burn(certifiedOnly, 'coin', undefined, undefined, caps)).plan, null);
  assert.equal(certifiedOnly.entry('coin').returnId, signed.returnId);
  assert.ok(existsSync(join(dir, 'holder', 'tokens.json')));
});


test('a holder reopens its burn after learning Paid before certification', async (t) => {
  const { chain, dir, open, aggregator } = await setup(t, true);
  const signed = join(dir, 'holder-signing-time.json');
  const offline = { certify: async () => { throw new Error('certifier offline'); } };
  const holder = await open('holder', undefined, { aggregator: offline });
  await assert.rejects(burn(holder, 'coin', undefined, undefined, caps, signed), /certifier offline/);
  const pending = await holder.returnRecord('coin');
  assert.equal(pending.status, 'burn-requested');
  for (const name of ['terminal-first', 'exact-request']) cpSync(holder.dir, join(dir, name), { recursive: true });

  const relayer = await open('receipt-relayer');
  const certified = await restoreReturn(relayer, signed);
  const terminal = join(dir, 'relayer-certified.json');
  publishReturnBackup(relayer, certified, terminal);
  const payer = await open('receipt-payer');
  chain.fund(payer.signer.address, 10n ** 18n);
  await restoreReturn(payer, terminal);
  const payout = await resumePayout(payer, certified, caps, true);
  assert.equal(payout.state, 'paid');

  const paid = await restoreReturn(holder, signed);
  assert.equal(paid.status, 'paid');
  assert.equal(paid.burned, undefined);
  assert.equal((await resumePayout(holder, paid, caps)).state, 'paid');
  await assert.rejects(burn(holder, 'coin'), /certifier offline/);
  assert.deepEqual(await holder.returnRecord('coin'), paid);
  const attached = await restoreReturn(holder, terminal);
  assert.equal(attached.burned, certified.burned);
  assert.deepEqual(attached.paid, paid.paid);
  assert.deepEqual(await restoreReturn(holder, terminal), attached);

  const terminalFirst = await open('terminal-first', undefined, { aggregator: offline, seed: key('holder') });
  const both = await restoreReturn(terminalFirst, terminal);
  assert.equal(both.status, 'paid');
  assert.equal(both.burned, certified.burned);
  for (const device of [holder, terminalFirst]) {
    const reopened = await burn(device, 'coin');
    assert.equal(hx(reopened.burned), certified.burned);
    assert.equal(device.entry('coin').note, 'paid');
  }

  const requestOnly = await open('exact-request', undefined, { seed: key('holder') });
  await restoreReturn(requestOnly, signed);
  const before = aggregator.calls;
  assert.equal(hx((await burn(requestOnly, 'coin')).burned), certified.burned);
  const recovered = await requestOnly.returnRecord('coin');
  assert.equal(recovered.burnRequest, pending.burnRequest);
  assert.equal(recovered.status, 'paid');
  assert.deepEqual(recovered.paid, paid.paid);
  await burn(requestOnly, 'coin');
  assert.equal(aggregator.calls, before + 1);
});

test('wallet-backup reconciliation matrix, in both holder and relayer orderings', { timeout: 420_000 }, async (t) => {
  for (const order of ['holder to relayer', 'relayer to holder'] as const) {
    await t.test(order, async (t) => {
      const { chain, cfg, deployment, dir, manifest, open, rpc, rpcOn } = await setup(t);
      const release = JSON.parse(readFileSync(manifest, 'utf8'));
      release.recovery.ranges = release.recovery.ranges.filter(({ max }: { max: { operations: number; gaps: number } }) =>
        max.operations <= 1 && max.gaps <= 1);
      writeFileSync(manifest, JSON.stringify(release));
      const offline = { certify: async () => { throw new Error('certifier offline'); } };
      const holder = await open('holder', rpc, { aggregator: offline });
      const plan = await planReturn(holder, 'coin', undefined, undefined, caps);
      assert.deepEqual(plan.record.recovery!.runCuts, [1, 1]);
      assert.equal(plan.record.recovery!.advanceGaps, 1);
      const id = hx(plan.returnId);
      const recoveryName = `recovery-${id.slice(2)}.json`;
      const journal = (w: Wallet) => {
        const file = join(w.dir, recoveryName);
        return existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : undefined;
      };
      const backup = (name: string) => join(dir, `matrix-${name}.json`);
      const snapshot = (name: string, w: Wallet) => cpSync(w.dir, join(dir, `snapshot-${name}`), { recursive: true });
      snapshot('planned', holder);
      await assert.rejects(burn(holder, 'coin', undefined, undefined, caps, backup('signed')), /certifier offline/);
      snapshot('signed', holder);

      const holderFirst = order === 'holder to relayer';
      const producer = await open(holderFirst ? 'holder' : 'matrix-relayer');
      chain.fund(producer.signer.address, 10n ** 18n);
      if (holderFirst) await burn(producer, 'coin');
      else await restoreReturn(producer, backup('signed'));
      const rec = (await producer.bridge.journal.ret(id))!;
      publishReturnBackup(producer, rec, backup('terminal'));
      snapshot('terminal', producer);

      // Interrupt an ordinary send after its signed bytes are durable.
      const interrupted: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
        if (method === 'eth_sendRawTransaction') throw new Error('interrupted before broadcast');
        return rpc.call<T>(method, params);
      } };
      const ordinary = await open('matrix-ordinary', interrupted);
      chain.fund(ordinary.signer.address, 10n ** 18n);
      await restoreReturn(ordinary, backup('terminal'));
      await assert.rejects(resumePayout(ordinary, rec, caps, true), /interrupted before broadcast/);
      assert.equal((await ordinary.bridge.journal.ret(id))!.status, 'submitted');
      snapshot('submitted', ordinary);

      const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!),
        new RecoveryAuthority(producer.trust, async () => undefined), TEST_PARAMS, deployment);
      const pruned = new Set<string>();
      const checkpoint = async (name: string, packet: Awaited<ReturnType<RecoverySession['run'] | RecoverySession['gaps']>>) => {
        const event = packet.event!;
        assert.equal(event.kind, name);
        chain.coldCall = async (_vault, to, data) => {
          if (!eq(to, deployment.recovery)) return undefined;
          assert.deepEqual(data, packet.calldata);
          return [{ address: deployment.recovery, topics: event.topics, data: event.data }];
        };
        chain.autoMine = false;
        assert.equal((await recoverStep(producer, rec, caps)).state, 'pending');
        snapshot(`pending-${name}`, producer);
        const pending = journal(producer).pending;
        chain.dropPool();
        await chain.mine([unhex(pending.raw)]);
        await chain.mine([]);
        chain.autoMine = true;
        assert.equal((await recoverStep(producer, rec, caps)).state, 'checkpoint');
        const certified = journal(producer).cuts.at(-1);
        pruned.add(certified.location.blockHash);
        publishReturnBackup(producer, rec, backup(name));
        snapshot(name, producer);
        return { seq: BigInt(certified.seq), receipt: unhex(certified.location.proof) };
      };
      const progress = await checkpoint('progress', await session.run(0, 1, producer.trust));
      const complete = await checkpoint('complete', await session.run(1, 1, producer.trust, progress));

      // Create one genuine certified vault segment after the burn's signed start.
      await planDeposit(producer, 'background', cfg.K);
      await sendDeposit(producer, 'background');
      const marker = key('matrix segment producer').slice(0, 20);
      chain.coldCall = async (vault, to) => {
        if (!eq(to, marker)) return undefined;
        for (let i = 0n; i < cfg.K; i++) {
          const eta = key(`matrix background-${i}`);
          vault.redeem(eta, 0n, new Uint8Array(), { ret: verdictAbi({
            domain: chain.domain, eta, minSegment: 0n, asset: cfg.asset, recipient: marker, amount: 1n,
          }) });
        }
        return [];
      };
      const markerTx = await signTx(producer.signer, { chainId: cfg.chainId, nonce: await producer.bridge.evm.nonce(producer.signer.address),
        maxFeePerGas: 15n, maxPriorityFeePerGas: 1n, gas: 2_000_000n, to: marker, value: 0n, data: new Uint8Array() });
      await producer.bridge.evm.sendRaw(markerTx.raw);
      const logs = await producer.bridge.evm.segmentLogs(cfg.vault, BigInt(rec.fromBlock), 0n, 1n);
      assert.equal(logs.length, 1);
      const seal = await producer.bridge.evm.receiptProof(markerTx.hash, cfg.vault, logs[0].topics[0], true, logs[0]);
      const gaps = await session.certifiedGaps(producer.trust, 0n, unhex(rec.startHead), [seal.encoded]);
      const advance = await session.gaps('advanceGaps', producer.trust, complete.receipt, { seq: complete.seq }, gaps, unhex(rec.startHead));
      const gap = await checkpoint('gap', advance);
      chain.autoMine = false;
      assert.equal((await recoverStep(producer, rec, caps)).state, 'pending');
      snapshot('pending-settle', producer);
      const settling = journal(producer).pending;
      chain.dropPool();
      chain.autoMine = true;

      const prunedReader = (transport: JsonRpc): JsonRpc => ({ call: <T>(method: string, params: unknown[]): Promise<T> => {
        if (method === 'eth_getBlockByHash' && pruned.has(String(params[0]))) return Promise.resolve(null as T);
        if (method === 'eth_sendRawTransaction') throw new Error('import must never broadcast an EVM transaction');
        return transport.call<T>(method, params);
      } });
      const evidence = ['none', 'signed', 'terminal', 'progress', 'complete', 'gap'] as const;
      // Each cell is the resulting cut count, or a safe refusal that must leave the journal intact.
      const unpaid = {
        absent:             [0, 0, 0, 1, 2, 3],
        planned:            [0, 0, 0, 1, 2, 3],
        signed:             [0, 0, 0, 1, 2, 3],
        terminal:           [0, 0, 0, 1, 2, 3],
        submitted:          [0, 0, 0, 1, 2, 3],
        progress:           [1, 1, 1, 1, 2, 3],
        complete:           [2, 2, 2, 2, 2, 3],
        gap:                [3, 3, 3, 3, 3, 3],
        'pending-progress': [0, 'pruned', 'pruned', 1, 2, 3],
        'pending-complete': [1, 'pruned', 'pruned', 'pruned', 2, 3],
        'pending-gap':      [2, 'pruned', 'pruned', 'pruned', 'pruned', 3],
        'pending-settle':   [3, 3, 3, 3, 3, 3],
      } as const;
      const rows = Object.keys(unpaid) as (keyof typeof unpaid)[];
      const localStatus: Partial<Record<keyof typeof unpaid, ReturnRecord['status']>> = {
        planned: 'planned', signed: 'burn-requested', submitted: 'submitted',
      };
      const clone = async (row: string, name: string, service?: Aggregator, transport = rpc) => {
        const from = join(dir, `snapshot-${row}`);
        if (existsSync(from)) cpSync(from, join(dir, name), { recursive: true });
        return open(name, prunedReader(transport), { aggregator: service, seed: key(holderFirst ? 'matrix-relayer' : 'holder') });
      };

      const bad = JSON.parse(readFileSync(backup('signed'), 'utf8'));
      bad.pending.amount = '20';
      writeFileSync(backup('conflict'), JSON.stringify(bad));
      const refuseConflict = async (device: Wallet, label: string) => {
        const before = await device.bridge.journal.ret(id);
        const local = journal(device);
        await assert.rejects(restoreReturn(device, backup('conflict')), { reason: 'BadInput' }, label);
        assert.deepEqual(await device.bridge.journal.ret(id), before, label);
        assert.deepEqual(journal(device), local, label);
      };
      for (const row of rows) {
        await refuseConflict(await clone(row, `conflict-${row}`, offline), row);
        for (const [i, proof] of evidence.entries()) {
          const label = `${row} × ${proof}`;
          const device = await clone(row, `unpaid-${row}-${proof}`, proof === 'signed' ? undefined : offline);
          const before = await device.bridge.journal.ret(id);
          const local = journal(device);
          const expected = unpaid[row][i];
          if (proof === 'none') {
            assert.equal(local?.cuts.length ?? 0, expected, label);
            assert.equal(before?.status, row === 'absent' ? undefined : localStatus[row] ?? 'burned', label);
          } else if (expected === 'pruned') {
            await assert.rejects(restoreReturn(device, backup(proof)), { rule: 'EvidencePruned' }, label);
            assert.deepEqual(journal(device), local, label);
            assert.deepEqual(await device.bridge.journal.ret(id), before, label);
          } else {
            const restored = await restoreReturn(device, backup(proof));
            assert.equal(restored.status, row === 'submitted' ? 'submitted' : 'burned', label);
            assert.equal(restored.burnRequest, rec.burnRequest, label);
            assert.equal(journal(device)?.cuts.length ?? 0, expected, label);
            assert.deepEqual(restored.sends, before?.sends ?? [], label);
            const expectedAttempts = local?.pending && row !== 'pending-settle'
              ? [...(local.attempts ?? []), local.pending.raw] : local?.attempts;
            assert.deepEqual(journal(device)?.attempts, expectedAttempts, label);
            assert.deepEqual(journal(device)?.pending, row === 'pending-settle' ? local.pending : undefined, label);
            const confirmed = journal(device);
            assert.deepEqual(await restoreReturn(device, backup(proof)), restored, label);
            assert.deepEqual(journal(device), confirmed, label);
          }
        }
      }

      // Branch the simulator at the common certified history to exercise both Paid routes in each ordering.
      const recovered = chain.fork();
      const recoveredRpc = rpcOn(recovered);
      const recoveryPayer = await clone('pending-settle', 'recovered-payer', offline, recoveredRpc);
      const verdict = await verifyReturn(chain.gamma, evidenceOf(unhex(rec.burned!)), producer.trust, TEST_PARAMS);
      const settle = await session.gaps('redeemRecovered', producer.trust, gap.receipt,
        { seq: gap.seq, cursor: { next: advance.next, head: advance.head! } }, []);
      recovered.coldCall = async (vault, to, data) => {
        if (!eq(to, cfg.vault) || hx(data.subarray(0, 4)) !== selector('redeemRecovered(bytes)')) return undefined;
        assert.deepEqual(data, settle.calldata);
        const history = new Uint8Array(32 + gaps[0].length);
        history.set(unhex(rec.startHead));
        history.set(gaps[0], 32);
        vault.redeem(verdict.eta, verdict.minSegment, history, { ret: verdictAbi(verdict) });
        return [];
      };
      await recovered.mine([unhex(settling.raw)]);
      await recovered.mine([]);
      assert.equal((await recoverStep(recoveryPayer, rec, caps)).state, 'paid');
      chain.coldCall = undefined;
      assert.equal((await resumePayout(producer, rec, caps, true)).state, 'paid');
      const payouts = [
        { route: 'ordinary', transport: rpc, payer: producer },
        { route: 'recovered', transport: recoveredRpc, payer: recoveryPayer },
      ];
      for (const { route, transport, payer } of payouts) {
        const paid = (await payer.bridge.journal.ret(id))!.paid;
        assert.ok(paid?.receipt);
        for (const proof of ['signed', 'terminal'] as const) {
          const name = `paid-${route}-${proof}`;
          const device = await clone('signed', name, offline, transport);
          await restoreReturn(device, backup(proof));
          await refuseConflict(device, name);
          snapshot(name, device);
        }
        for (const row of [...rows, `paid-${route}-signed`, `paid-${route}-terminal`]) {
          for (const proof of evidence) {
            const label = `${row} × ${route} Paid and ${proof}`;
            const device = await clone(row, `paid-${route}-${row}-${proof}`, offline, transport);
            const before = await device.bridge.journal.ret(id);
            const local = journal(device);
            if (proof === 'none' && !before?.burnRequest) {
              if (before) assert.equal((await device.bridge.reconcile(plan.returnId)).state, 'not-paid', label);
              assert.deepEqual(await device.bridge.journal.ret(id), before, label);
              continue;
            }
            // A durable signed request binds a discovered Paid even when no portable file was supplied.
            if (proof === 'none') {
              assert.equal((await device.bridge.reconcile(plan.returnId)).state, 'paid', label);
            } else {
              await restoreReturn(device, backup(proof));
            }
            const restored = (await device.bridge.journal.ret(id))!;
            assert.equal(restored.status, 'paid', label);
            assert.deepEqual(restored.paid, paid, label);
            assert.equal(Boolean(restored.burned), Boolean(before?.burned) || !['none', 'signed'].includes(proof), label);
            assert.deepEqual(restored.sends, before?.sends ?? [], label);
            assert.deepEqual(journal(device)?.cuts, local?.cuts, label);
            if (proof !== 'none' && local?.pending) {
              assert.equal(journal(device).pending, undefined, label);
              assert.equal(journal(device).settled.submitted.raw, local.pending.raw, label);
            }
          }
        }
      }
    });
  }
});
