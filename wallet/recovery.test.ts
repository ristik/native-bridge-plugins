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
  CERTIFICATION_DEPTH, EvmReader, GapTree, Journal, NativeBridgeV2, Nb2Error, SELECTOR, TOPIC, RecoveryAuthority, RecoverySession, RpcError, TEST_PARAMS, WalletError, appendTransfer, buildHistory, decodeSignedTx, domainOf,
  evidenceOf, firstOwnerOf, nextHead, quoteRecovery, quoteRecoveryGapBatch, quoteScheduledRecoveryFee, recoveryGeneration, recoveryRpcSource, signTx, transferRequest, verifyReturn, verdictAbi,
  type Aggregator, type GasModel, type JsonRpc, type ReturnRecord, type RecoveryCalibration, type RecoveryEvent,
} from '../packages/native-bridge-plugin/src/nb2/index.js';
import { HE } from '../packages/native-bridge-plugin/src/nb2/crypto.js';
import { ascii, u256 } from '../packages/native-bridge-plugin/src/nb2/cbor.js';
import { LIMITS, encodeReceiptBacking } from '../packages/native-bridge-plugin/src/nb2/deposit.js';
import { segmentSealedData } from '../packages/native-bridge-plugin/src/nb2/segment.js';
import { signaturePredicate } from '../packages/native-bridge-plugin/src/nb2/token.js';
import { FakeChain, FakeAggregator, key, makeConfig, makeRoot, roundNow, roundAtLeast } from '../packages/native-bridge-plugin/test/nb2/world.js';
import { nextEpoch } from '../packages/native-bridge-plugin/test/rootfixture.js';
import { Wallet, burn, connectionOf, readRetrying, retry, transportRetry, hx, io, mint, planDeposit, planReturn, receive, redeem, resumePayout, sendDeposit, transfer, unhex } from './core.js';
import { importReturn, checkLocalErc20Returns, ordinaryPayout, publishReturnBackup, reconcileReturn, qualifyExistingRecovery, recoverStep, restoreReturn, walletAdmission, type PayerPolicy } from './recovery.js';

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
      // The coldCall hook scripts mined events and late reverts. Keep finalized
      // simulation from changing that script or consuming an injected failure.
      if (view.coldCall && typeof params[1] === 'object' &&
        (to === hx(recovery) || (to === hx(cfg.vault) &&
          [hx(SELECTOR.redeem), selector('redeemRecovered(bytes)')].includes(data.slice(0, 10))))) {
        return '0x' as T;
      }
    }
    return view.call<T>(method, params);
  } });
  const rpc = rpcOn(chain);
  const manifest = join(dir, 'release.json');
  writeFileSync(manifest, JSON.stringify({
    pins: { gamma: hx(chain.gamma), build: 'test', vaultRuntimeCodeHash: hx(deployment.vaultRuntimeHash),
      maxEncodedTxBytes: 524288, userGasLimit: '24000000', gasReserve: '500000', returnReserveSegments: 64, deploymentBlock: 1,
      stateReadOnly: false },
    trust: {},
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
  const open = (name: string, override: JsonRpc = rpc, opts: { aggregator?: Aggregator; trustSource?: ITrustBaseSource; seed?: Uint8Array } = {}) =>
    new Wallet(join(dir, name), opts.seed ?? key(name), conn).open({
      lock: false, rpc: override, aggregator: opts.aggregator ?? aggregator, gas, trustSource: opts.trustSource,
    });
  const w = await open('holder');
  chain.fund(w.signer.address, 10n ** 18n);
  await planDeposit(w, 'coin', 19n);
  await sendDeposit(w, 'coin');
  await mint(w, 'coin');
  return { w, open, root, cfg, chain, deployment, aggregator, dir, rpc, rpcOn, views, manifest };
}

async function sealTestSegments(chain: FakeChain, payer: Wallet, count: number, oversizedIndex?: bigint) {
  const cfg = payer.bridge.cfg;
  const owner = firstOwnerOf(payer.owner(0).publicKey);
  const marker = new Uint8Array(20).fill(0x62);
  const previous = chain.coldCall;
  chain.fund(payer.signer.address, 10n ** 18n);
  chain.coldCall = async (vault, to, data) => {
    if (!eq(to, marker)) return previous?.(vault, to, data);
    const index = vault.c;
    for (let i = 0n; i < cfg.K; i++) {
      const id = HE(u256(index * cfg.K + i + 1n));
      vault.deposit(1n, owner, id);
      vault.redeem(id, index, new Uint8Array(), { ret: verdictAbi({
        domain: chain.domain, eta: id, minSegment: index, asset: cfg.asset, recipient: payer.signer.address, amount: 1n,
      }) });
    }
    return index === oversizedIndex ? [{ address: marker, topics: [], data: new Uint8Array(LIMITS.receiptLeafNodeBytes) }] : [];
  };
  try {
    for (let i = 0; i < count; i++) {
      const nonce = await payer.bridge.evm.nonce(payer.signer.address);
      const tx = await signTx(payer.signer, { chainId: cfg.chainId, nonce, maxFeePerGas: 15n,
        maxPriorityFeePerGas: 1n, gas: 1_000_000n, to: marker, value: 0n, data: new Uint8Array() });
      await payer.bridge.evm.sendRaw(tx.raw);
    }
  } finally {
    chain.coldCall = previous;
  }
}

test('a deposit with an oversized certified receipt cannot mint offline', async (t) => {
  const { w, chain, cfg, aggregator } = await setup(t);
  const plan = await planDeposit(w, 'wide-deposit', 1n);
  const padding = { address: new Uint8Array(20).fill(0x61), topics: [], data: new Uint8Array(LIMITS.receiptLeafNodeBytes) };
  chain.coldCall = async (vault, to, data) => {
    if (!eq(to, cfg.vault) || !eq(data, plan.calldata)) return undefined;
    vault.deposit(plan.amount, plan.firstOwner, plan.rho);
    return [padding];
  };
  const { txHash, depositNumber } = await sendDeposit(w, 'wide-deposit');
  const receipt = await w.bridge.evm.mintReceiptProof(txHash, cfg.vault, false, TOPIC.Deposited, [TOPIC.Deposited, u256(depositNumber)]);
  assert.ok(receipt.proof.nodes.at(-1)!.length > LIMITS.receiptLeafNodeBytes);
  assert.ok(receipt.encoded.length < LIMITS.justificationBytes);
  const calls = aggregator.calls;
  await assert.rejects(mint(w, 'wide-deposit'), { rule: 'InputTooLarge', message: /deposit receipt exceeds the offline proof limits/ });
  const pending = (await w.bridge.journal.deposit(plan.intent))!;
  assert.equal(pending.status, 'deposited');
  assert.equal(pending.reason, undefined);
  assert.equal(aggregator.calls, calls);
  // Emulate a journal written before the framing check was applied during collection.
  await w.bridge.journal.putDeposit({ ...pending, status: 'proven', receiptProof: hx(receipt.encoded),
    reason: hx(encodeReceiptBacking({ d: chain.domain, n: depositNumber, r: key('old cached secret'), proof: receipt.proof })) });
  const diagnostic = { rule: 'InputTooLarge', message: /deposit receipt exceeds the offline proof limits/ };
  await assert.rejects(w.bridge.collectDepositProof(plan.intent), diagnostic);
  await assert.rejects(w.bridge.mint(plan.intent), diagnostic);
  assert.equal((await w.bridge.journal.deposit(plan.intent))?.status, 'proven');
  assert.equal(aggregator.calls, calls);
});

for (const oversizedIndex of [0, 2]) test(`continuation authenticates the whole archived suffix and settles with oversized seal ${oversizedIndex}`, async (t) => {
  const { w, open, chain, cfg, deployment } = await setup(t);
  const release = w.release.recovery as { ranges: { max: { entry: string; gaps: number } }[] };
  release.ranges = release.ranges.filter(({ max }) => max.entry === 'run' || max.gaps <= 2);
  const { eta } = await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const evidence = evidenceOf(unhex(rec.burned!));
  const session = await RecoverySession.create(chain.gamma, evidence, new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const verdict = await verifyReturn(chain.gamma, evidence, w.trust, TEST_PARAMS);
  const complete = await session.run(0, session.operationCount, w.trust);
  chain.coldCall = async (_vault, to, data) => {
    if (!eq(to, deployment.recovery)) return;
    assert.deepEqual(data, complete.calldata);
    return [{ address: to, topics: complete.event.topics, data: complete.event.data }];
  };
  const checkpoint = await recoverStep(w, rec, caps);
  assert.equal(checkpoint.state, 'checkpoint');
  assert.ok('txHash' in checkpoint);
  const completion = await recoveryRpcSource(w.bridge.evm, checkpoint.txHash)(deployment.recovery, complete.event);

  await sealTestSegments(chain, await open('shared-seal-producer'), 3, BigInt(oversizedIndex));
  assert.equal(chain.vault.c, 3n);
  const before = unhex(rec.startHead);
  const seals = await w.bridge.evm.segmentLogs(cfg.vault, BigInt(rec.fromBlock), 0n, 3n);
  const oversized = await w.bridge.evm.receiptProof(seals[oversizedIndex].transactionHash, cfg.vault, TOPIC.SegmentSealed, true, seals[oversizedIndex]);
  assert.ok(oversized.proof.nodes.at(-1)!.length > LIMITS.receiptLeafNodeBytes);
  assert.ok(oversized.encoded.length < LIMITS.justificationBytes);
  await assert.rejects(session.certifiedGaps(w.trust, BigInt(oversizedIndex), before, [oversized.encoded]),
    (e: unknown) => e instanceof Nb2Error && e.rule === 'SealReceipt' && e.innermost === 'InputTooLarge');

  const segments = chain.vault.events.flatMap((e) => e.name === 'SegmentSealed'
    ? [{ index: e.segment, before: e.before, after: e.after, z: e.ids, root: GapTree.build(e.ids)!.root }] : []);
  if (oversizedIndex === 0) {
    const fetchLogs = w.bridge.evm.segmentLogs.bind(w.bridge.evm);
    const counterfeitIds = [1n, 2n, 3n, 4n].map(u256);
    const tail = segments[2];
    const wrongData = segmentSealedData(tail.before, nextHead(chain.domain, tail.index, tail.before, GapTree.build(counterfeitIds)!.root), counterfeitIds);
    const sign = t.mock.method(w.signer, 'signTransaction', async () => { throw new Error('signer reached'); });
    const send = t.mock.method(w.bridge.evm, 'sendRaw', async () => { throw new Error('sender reached'); });
    const payerBefore = chain.balanceOf(w.signer.address);
    for (const [change, error] of [
      [(rows: typeof seals) => rows.map((l) => eq(l.topics[1], u256(2)) ? { ...l, data: wrongData } : l), /do not fold to the certified vault head/],
      [(rows: typeof seals) => rows.map((l) => eq(l.topics[1], u256(2)) ? { ...l, data: l.data.slice(0, -32) } : l), /SegmentLog: length/],
      [(rows: typeof seals) => rows.filter((l) => !eq(l.topics[1], u256(2))), /archived segment range is incomplete/],
    ] as const) {
      w.bridge.evm.segmentLogs = async (...args) => change(await fetchLogs(...args));
      await assert.rejects(recoverStep(w, rec, caps), error);
      assert.equal(sign.mock.callCount(), 0);
      assert.equal(send.mock.callCount(), 0);
      assert.equal(chain.balanceOf(w.signer.address), payerBefore);
    }
    sign.mock.restore();
    send.mock.restore();
    w.bridge.evm.segmentLogs = fetchLogs;
  } else {
    const sign = t.mock.method(w.signer, 'signTransaction', async () => { throw new Error('signer reached'); });
    const send = t.mock.method(w.bridge.evm, 'sendRaw', async () => { throw new Error('sender reached'); });
    chain.faults.hideSegments.add(2n);
    await assert.rejects(recoverStep(w, rec, caps), /no SegmentSealed log of segment 2/);
    chain.faults.hideSegments.clear();
    const call = w.bridge.evm.rpc.call.bind(w.bridge.evm.rpc);
    const corrupt = t.mock.method(w.bridge.evm.rpc, 'call', async (method: string, params: unknown[]) => {
      const answer = await call(method, params);
      if (method !== 'eth_getProof') return answer;
      const proof = answer as { accountProof: string[] };
      return { ...proof, accountProof: ['0xc0'] };
    });
    await assert.rejects(recoverStep(w, rec, caps), /vault state proof does not verify/);
    corrupt.mock.restore();
    const state = await w.bridge.evm.vaultState(cfg.vault);
    const ahead = t.mock.method(w.bridge.evm, 'vaultState', async () => ({ ...state, segment: state.segment + 1n }));
    await assert.rejects(recoverStep(w, rec, caps), { reason: 'CompanionUnknown' });
    ahead.mock.restore();
    assert.equal(sign.mock.callCount(), 0);
    assert.equal(send.mock.callCount(), 0);
    sign.mock.restore();
    send.mock.restore();
  }

  const paths = segments.map((e) => GapTree.build(e.z)!.prove(eta)!);
  const advance = await session.gaps('advanceGaps', w.trust, completion, { seq: 1n }, paths.slice(0, 2), before);
  assert.ok(advance.event && advance.head);
  const gapEvent = advance.event;
  chain.coldCall = async (_vault, to, data) => {
    if (!eq(to, deployment.recovery)) return;
    assert.deepEqual(data, advance.calldata);
    return [{ address: to, topics: gapEvent.topics, data: gapEvent.data }];
  };
  const advanced = await recoverStep(w, rec, caps);
  assert.equal(advanced.state, 'checkpoint');
  assert.ok('txHash' in advanced);
  const gapReceipt = await recoveryRpcSource(w.bridge.evm, advanced.txHash)(deployment.recovery, gapEvent);
  const endpoint = oversizedIndex === 2 ? 2n : 3n;
  const settle = await session.gaps('redeemRecovered', w.trust, gapReceipt,
    { seq: 2n, cursor: { next: 2n, head: advance.head } }, paths.slice(2, Number(endpoint)));
  chain.coldCall = async (vault, to, data) => {
    if (!eq(to, cfg.vault) || hx(data.subarray(0, 4)) !== selector('redeemRecovered(bytes)')) return;
    assert.deepEqual(data, settle.calldata);
    const history = buildHistory(segments, eta, 0n, endpoint, before);
    vault.redeem(eta, 0n, history.history, { ret: verdictAbi(verdict) });
    return [];
  };
  assert.equal((await recoverStep(w, rec, caps)).state, 'paid');
  assert.equal(chain.vault.events.filter((e) => e.name === 'Paid' && eq(e.eta, eta)).length, 1);
  assert.equal(chain.vault.q, 0n);
});

test('Run uses the certified endpoint when the unsigned vault read omits an oversized seal', async (t) => {
  const { w, open, chain, cfg } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  await sealTestSegments(chain, await open('run-seal-producer'), 1, 0n);
  chain.faults.hideSegments.add(0n);
  const state = await w.bridge.evm.vaultState(cfg.vault);
  t.mock.method(w.bridge.evm, 'vaultState', async () => ({ ...state, segment: 0n }));
  const sign = t.mock.method(w.signer, 'signTransaction');
  const send = t.mock.method(w.bridge.evm, 'sendRaw');
  await assert.rejects(recoverStep(w, rec, caps), /no SegmentSealed log of segment 0/);
  assert.equal(sign.mock.callCount(), 0);
  assert.equal(send.mock.callCount(), 0);
});

for (const badFirst of [true, false]) test(`terminal previous-buffer settlement tolerates a malformed ${badFirst ? 'first' : 'second'} reader`, async (t) => {
  const { w, open, chain, cfg, deployment, rpc } = await setup(t);
  const faulty: JsonRpc = { async call<T>(method: string, params: unknown[]): Promise<T> {
    const answer = await rpc.call<T>(method, params);
    if (method !== 'eth_getLogs') return answer;
    return (answer as { topics: string[]; data: string }[]).map((row) =>
      row.topics[0] === hx(TOPIC.SegmentSealed) && row.topics[1] === hx(u256(1)) ? { ...row, data: row.data.slice(0, -64) } : row) as T;
  } };
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const session = await RecoverySession.create(chain.gamma, evidenceOf(unhex(rec.burned!)), new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const complete = await session.run(0, session.operationCount, w.trust);
  chain.coldCall = async (_vault, to) => eq(to, deployment.recovery)
    ? [{ address: to, topics: complete.event.topics, data: complete.event.data }] : undefined;
  const step = await recoverStep(w, rec, caps);
  assert.equal(step.state, 'checkpoint');
  assert.ok('txHash' in step);
  // Reopen the same journal for the faulty primary order.
  const relay = badFirst ? await open('holder', faulty) : w;
  await sealTestSegments(chain, await open('previous-buffer-producer'), 2, 1n);
  const [first] = chain.vault.events.filter((e) => e.name === 'SegmentSealed');
  const gap = GapTree.build(first.ids)!.prove(session.redemptionId)!;
  const proof = await recoveryRpcSource(w.bridge.evm, step.txHash)(deployment.recovery, complete.event);
  const settle = await session.gaps('redeemRecovered', w.trust, proof, { seq: 1n }, [gap], unhex(rec.startHead));
  const verdict = await verifyReturn(chain.gamma, evidenceOf(unhex(rec.burned!)), w.trust, TEST_PARAMS);
  chain.coldCall = async (vault, to, data) => {
    if (!eq(to, cfg.vault) || hx(data.subarray(0, 4)) !== selector('redeemRecovered(bytes)')) return;
    assert.deepEqual(data, settle.calldata);
    const history = buildHistory([{ index: first.segment, z: first.ids, before: first.before, after: first.after, root: GapTree.build(first.ids)!.root }],
      session.redemptionId, 0n, 1n, unhex(rec.startHead));
    vault.redeem(session.redemptionId, 0n, history.history, { ret: verdictAbi(verdict) });
    return [];
  };
  const alternate = badFirst ? rpc : faulty;
  const fetch = globalThis.fetch;
  t.mock.method(globalThis, 'fetch', async (url: string, opts: RequestInit) => {
    if (url !== 'http://archive.invalid') return fetch(url, opts);
    const body = JSON.parse(String(opts.body));
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: await alternate.call(body.method, body.params) }));
  });
  assert.equal((await recoverStep(relay, rec, { ...caps, archives: ['http://archive.invalid'] })).state, 'paid');
  assert.equal(chain.vault.events.filter((e) => e.name === 'Paid' && eq(e.eta, session.redemptionId)).length, 1);
});

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

test('Run replay consumes signed arrivals and preserves the other return’s payer reserve', async (t) => {
  const { w, open, chain, deployment, cfg } = await setup(t);
  const raw = w.release.recovery as { ranges: { max: { entry: string; operations: number; gaps: number } }[]; backlog: Record<string, string> };
  raw.ranges = raw.ranges.filter(({ max }) => max.entry === 'run' ? max.operations === 1 : max.gaps <= 3);
  Object.assign(raw.backlog, { duringProgress: '2', advancePeakSeals: '1', qualifiedForMs: '33025' });
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  assert.deepEqual(rec.recovery!.runCuts, [1, 1]);
  assert.equal(rec.recovery!.advanceGaps, 3);
  assert.equal(rec.recovery!.progressEnd, '2');
  assert.equal(rec.recovery!.calls, '36'); // two Runs, 33 Advances and settlement
  const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  let packet = await session.run(0, 1, w.trust);
  chain.coldCall = async (_vault, to, data) => {
    if (!eq(to, deployment.recovery)) return;
    assert.deepEqual(data, packet.calldata);
    return [{ address: to, topics: packet.event.topics, data: packet.event.data }];
  };
  // Use UCT receipt fixtures with the current ERC20 payer journal.
  w.bridge.cfg.erc20 = { token: new Uint8Array(20).fill(1), generation: deployment.salt, pins: deployment.pins };
  rec.erc20PayerState = 1;
  delete rec.payer;
  rec.recovery!.envelope = { gas: String(caps.gas), signedBytes: caps.signedBytes, calldataBytes: caps.calldataBytes,
    maxNonce: String(caps.maxNonce), maxFeePerGas: String(caps.maxFeePerGas), maxPriorityFeePerGas: String(caps.maxPriorityFeePerGas) };
  await w.bridge.journal.putReturn(rec);
  await w.bridge.journal.registerPayerChain(cfg.chainId);
  assert.equal((await recoverStep(w, rec, caps)).state, 'checkpoint');
  const path = join(w.dir, `recovery-${rec.returnId.slice(2)}.json`);
  const { cuts, attempts } = JSON.parse(readFileSync(path, 'utf8'));
  packet = await session.run(1, 1, w.trust, { seq: 1n, receipt: unhex(cuts[0].location.proof) });

  await checkLocalErc20Returns(w);
  const signed = decodeSignedTx(unhex(attempts[0])).request;
  assert.deepEqual(await w.bridge.journal.payerFees(rec, cfg.chainId, w.signer.address, signed.nonce + 1n),
    { prior: signed.gas * signed.maxFeePerGas, atNonce: 0n });
  const progress = await w.bridge.journal.store.list(`nb2/payer-progress/v2/${cfg.chainId}/`);
  assert.equal(progress.length, 1);
  const checkpoint = JSON.parse((await w.bridge.journal.store.get(progress[0]))!);
  assert.equal(checkpoint.completed, '1');
  assert.ok(BigInt(checkpoint.continuationGas) * caps.maxFeePerGas < BigInt(rec.recovery!.totalFee));
  const other = { ...rec, returnId: hx(key('other payout reserve')), status: 'burned' as const,
    executionPayer: undefined };
  const store = w.bridge.journal;
  await store.putReturn(other);
  chain.fund(w.signer.address, BigInt(other.recovery!.totalFee) - chain.balanceOf(w.signer.address));
  const state = w.bridge.evm.vaultState.bind(w.bridge.evm);
  let segment = 2n;
  w.bridge.evm.vaultState = async (vault) => ({ ...await state(vault), segment });
  await assert.rejects(recoverStep(w, rec, caps), /packet exceeds the remaining payer limits/);
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).cuts.length, 1);
  await store.retForUpdate(other.returnId);
  await store.putReturn({ ...other, status: 'paid' });
  chain.fund(w.signer.address, 10n ** 18n);
  segment = 3n;
  await assert.rejects(recoverStep(w, rec, caps), /observed arrivals exceed the admitted Run endpoint/);
  w.bridge.evm.vaultState = state;
  // The admitted two arrivals now need real, certified archived segments.
  await sealTestSegments(chain, await open('run-replay-seal-producer'), 2);
  assert.equal((await recoverStep(w, rec, caps)).state, 'checkpoint');
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).cuts.length, 2);

  const current = (await store.ret(rec.returnId))!;
  const saved = JSON.parse(readFileSync(path, 'utf8'));
  const [earlier, latest] = (saved.attempts as string[]).map((raw) => decodeSignedTx(unhex(raw)).request);
  assert.ok(earlier.nonce < latest.nonce);
  const scope = `${cfg.chainId}/${current.executionPayer!.slice(2)}/${current.domain.slice(2)}/${current.returnId.slice(2)}`;
  const feePrefix = `nb2/payer-fees/v1/${scope}/`;
  const journalPath = join(w.dir, 'journal.json');
  const complete = readFileSync(journalPath, 'utf8');
  const refused = /unsupported pre-release ERC20 record: start a fresh wallet/;
  const signer = t.mock.method(w.signer, 'signTransaction', async () => { throw new Error('signer reached'); });
  const ordinary = { ...latest, nonce: latest.nonce + 1n };
  for (const earlierFee of [undefined, String(earlier.gas * earlier.maxFeePerGas - 1n)]) {
    const damaged = JSON.parse(complete);
    if (earlierFee === undefined) delete damaged[feePrefix + earlier.nonce];
    else damaged[feePrefix + earlier.nonce] = earlierFee;
    writeFileSync(journalPath, JSON.stringify(damaged));
    const shared = await store.payerFeeMaxima(current, cfg.chainId, w.signer.address);
    assert.equal(shared.get(latest.nonce), latest.gas * latest.maxFeePerGas);
    assert.ok((shared.get(earlier.nonce) ?? 0n) < earlier.gas * earlier.maxFeePerGas);
    await assert.rejects(checkLocalErc20Returns(w), refused);
    await assert.rejects(w.bridge['reserveOrdinaryPayer'](current, w.signer.address, ordinary, ordinaryPayout(w, current, caps)), refused);
    await assert.rejects(recoverStep(w, current, caps), refused);
    assert.equal(signer.mock.callCount(), 0);
    assert.equal(await store.store.get(feePrefix + earlier.nonce), earlierFee ?? null);
  }
  writeFileSync(journalPath, complete);
});

test('a Run with only its first fee authorized leaves the payer free for another return', async (t) => {
  const { w, chain, deployment, cfg } = await setup(t);
  await planDeposit(w, 'second', 21n);
  await sendDeposit(w, 'second');
  await mint(w, 'second');
  await burn(w, 'coin', undefined, undefined, caps);
  await burn(w, 'second', undefined, undefined, caps);
  const first = await w.returnRecord('coin');
  const second = await w.returnRecord('second');
  const coldCalls = BigInt(first.recovery!.calls);
  first.recovery!.calls = String(coldCalls + 2n);
  first.recovery!.ordinary = { gas: '500000', calldataBytes: 393216, maxFeePerGas: String(caps.maxFeePerGas), attemptsBeforeFallback: '2' };
  second.recovery!.envelope = { gas: String(caps.gas), signedBytes: caps.signedBytes, calldataBytes: caps.calldataBytes,
    maxNonce: String(caps.maxNonce), maxFeePerGas: String(caps.maxFeePerGas), maxPriorityFeePerGas: String(caps.maxPriorityFeePerGas) };
  first.erc20PayerState = 1;
  second.erc20PayerState = 1;
  delete first.payer;
  delete second.payer;
  await w.bridge.journal.putReturn(first);
  await w.bridge.journal.putReturn(second);
  const session = await RecoverySession.create(chain.gamma, unhex(first.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const run = await session.run(0, first.recovery!.runCuts[0], w.trust);
  const firstFee = (1_221_000n + 16n * BigInt(run.calldata.length)) * caps.maxFeePerGas;
  assert.ok(firstFee < BigInt(first.recovery!.totalFee));
  const secondSession = await RecoverySession.create(chain.gamma, unhex(second.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const secondRun = await secondSession.run(0, second.recovery!.runCuts[0], w.trust);
  chain.coldCall = async (_vault, to) => eq(to, deployment.recovery)
    ? [{ address: to, topics: secondRun.event.topics, data: secondRun.event.data }] : undefined;
  w.bridge.cfg.erc20 = { token: new Uint8Array(20).fill(1), generation: deployment.salt, pins: deployment.pins };
  await w.bridge.journal.registerPayerChain(cfg.chainId);
  const signer = w.signer.signTransaction.bind(w.signer);
  let signed = 0;
  w.signer.signTransaction = (request) => { signed++; return signer(request); };
  await assert.rejects(recoverStep(w, first, { ...caps, feeBudget: firstFee }), /recovery payer balance or nonce changed before signing/);
  const nonce = await w.bridge.evm.nonce(w.signer.address);
  await assert.rejects(recoverStep(w, first, { ...caps, maxNonce: nonce + coldCalls - 1n }), /remaining continuation schedule exceeds the payer nonce horizon/);
  assert.equal(signed, 0);
  assert.equal((await recoverStep(w, second, caps)).state, 'checkpoint');
  assert.equal(signed, 1);
  await assert.rejects(recoverStep(w, first, caps), /outstanding ERC20 return/);
});

test('a contested ordinary handoff reserves the old fee and the entire fallback if the old call wins', async (t) => {
  const { w, cfg, chain, deployment } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const plan = rec.recovery!;
  const payer = w.signer.address;
  const nonce = await w.bridge.evm.nonce(payer);
  const old = await signTx(w.signer, { chainId: cfg.chainId, nonce, gas: 100_000n, maxFeePerGas: caps.maxFeePerGas,
    maxPriorityFeePerGas: 1n, to: cfg.vault, value: 0n, data: (await w.bridge.buildRedeem(unhex(rec.returnId))).calldata });
  const oldFee = old.request.gas * old.request.maxFeePerGas;
  rec.erc20PayerState = 1;
  delete rec.payer;
  plan.ordinary = { gas: '40000', calldataBytes: 393216, maxFeePerGas: String(caps.maxFeePerGas), attemptsBeforeFallback: '1' };
  const coldCalls = BigInt(plan.calls);
  plan.calls = String(coldCalls + 1n);
  const other = { ...rec, returnId: hx(key('other return at handoff')), sends: [],
    recovery: { ...plan, ordinary: undefined, calls: String(coldCalls) } };
  const journal = w.bridge.journal;
  await journal.putReturn(rec);
  await journal.putReturn(other);
  await journal.registerPayerChain(cfg.chainId);
  await journal.preparePayerSigning(rec, cfg.chainId, payer);
  await journal.retainPayerSend(rec, old.raw);
  rec.sends.push({ raw: hx(old.raw), hash: hx(old.hash), nonce: String(nonce), gas: String(old.request.gas), at: '0' });
  await journal.putReturn(rec);
  w.bridge.cfg.erc20 = { token: new Uint8Array(20).fill(1), generation: deployment.salt, pins: deployment.pins };
  t.mock.method(w.bridge, 'expiredOrdinaryNonce', async () => nonce);
  const eipLimits = { ...caps, chainId: cfg.chainId, balance: 0n };
  const ranges = (w.release.recovery as { ranges: (Omit<RecoveryCalibration['ranges'][number], 'execution'> & { execution: string })[] }).ranges;
  const calibration = { ...deployment, ranges: ranges.map((range) => ({ ...range, execution: BigInt(range.execution) })) };
  const fallback = quoteScheduledRecoveryFee(unhex(rec.source), cfg.K, {
    cuts: plan.runCuts, completedRuns: 0, batch: plan.advanceGaps, advances: coldCalls - BigInt(plan.runCuts.length) - 1n,
  }, calibration, eipLimits);
  const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const run = await session.run(0, plan.runCuts[0], w.trust);
  const firstRunFee = quoteRecovery(run.shape, calibration, eipLimits, true)!.fee;
  const allowance = BigInt(plan.ordinary.gas) * caps.maxFeePerGas;
  assert.ok(allowance < oldFee && oldFee < firstRunFee && firstRunFee < fallback);
  const larger = await signTx(w.signer, { ...old.request, gas: 150_000n });
  const largestFee = larger.request.gas * larger.request.maxFeePerGas;
  assert.ok(oldFee < largestFee && largestFee < firstRunFee);
  await journal.retainPayerSend(rec, larger.raw);
  const sign = t.mock.method(w.signer, 'signTransaction', async () => { throw new Error('payer signer reached'); });
  await assert.rejects(recoverStep(w, rec, { ...caps, feeBudget: fallback + allowance }), /recovery payer balance or nonce changed/);
  await assert.rejects(recoverStep(w, rec, { ...caps, feeBudget: fallback + oldFee }), /recovery payer balance or nonce changed/);
  await assert.rejects(recoverStep(w, rec, { ...caps, feeBudget: fallback + largestFee - 1n }), /recovery payer balance or nonce changed/);
  assert.equal(sign.mock.callCount(), 0);
  assert.deepEqual(await journal.store.list('nb2/payer/v1/'), []);
  await assert.rejects(recoverStep(w, rec, { ...caps, feeBudget: fallback + largestFee }), /payer signer reached/);
  assert.equal(sign.mock.callCount(), 1);
});

test('wallet startup refuses pre-release ERC20 pending and Paid records while UCT still resends', async (t) => {
  const { w, open, chain, cfg, deployment, rpc } = await setup(t, true);
  await burn(w, 'coin', undefined, undefined, caps);
  const id = (await w.returnRecord('coin')).returnId;
  const sidecar = join(w.dir, `recovery-${id.slice(2)}.json`);
  assert.equal(existsSync(sidecar), false);
  const send = t.mock.method(w.bridge.evm, 'sendRaw', async () => { throw new Error('old SDK send lost'); });
  await assert.rejects(w.bridge.submitRedeem(unhex(id), w.signer), /old SDK send lost/);
  assert.equal(send.mock.callCount(), 1);
  const record = (await w.bridge.journal.ret(id))!;
  assert.equal(record.recovery, undefined);
  assert.equal(record.erc20PayerState, undefined);
  assert.equal(record.executionPayer, hx(w.signer.address));
  const [ordinary] = record.sends;
  const sendNonce = decodeSignedTx(unhex(ordinary.raw)).request.nonce;
  const scope = `${cfg.chainId}/${record.executionPayer!.slice(2)}/${record.domain.slice(2)}/${id.slice(2)}`;
  await w.bridge.journal.registerPayerChain(cfg.chainId);
  const watermark = `nb2/payer-sends/v1/${scope}`;
  assert.ok(await w.bridge.journal.store.putIf(watermark, null, String(sendNonce - 1n)));
  const storePath = join(w.dir, 'journal.json');
  const before = readFileSync(storePath, 'utf8');
  let erc20 = true;
  const openSdk = NativeBridgeV2.open.bind(NativeBridgeV2);
  t.mock.method(NativeBridgeV2, 'open', async (...args: Parameters<typeof openSdk>) => {
    const bridge = await openSdk(...args);
    if (erc20) bridge.cfg.erc20 = { token: new Uint8Array(20).fill(1), generation: deployment.salt, pins: deployment.pins };
    return bridge;
  });
  const offered: string[] = [];
  const recordingRpc: JsonRpc = { call: async <T>(method: string, args: unknown[]): Promise<T> => {
    if (method === 'eth_sendRawTransaction') offered.push(args[0] as string);
    return rpc.call<T>(method, args);
  } };
  const refused = /unsupported pre-release ERC20 record: start a fresh wallet/;
  for (let i = 0; i < 2; i++) {
    await assert.rejects(open('holder', recordingRpc), refused);
    assert.deepEqual(offered, []);
    assert.equal(readFileSync(storePath, 'utf8'), before);
    assert.equal(existsSync(sidecar), false);
  }

  erc20 = false;
  const native = await open('holder', recordingRpc);
  const first = await reconcileReturn(native, record);
  assert.deepEqual(offered, [ordinary.raw]);
  await chain.mine([]);
  const paid = first.result.state === 'paid' ? first : await reconcileReturn(native, record);
  assert.equal(paid.result.state, 'paid');
  assert.equal((await native.bridge.evm.nonce(w.signer.address, 'finalized')), sendNonce + 1n);
  const after = readFileSync(storePath, 'utf8');
  erc20 = true;
  await assert.rejects(open('holder', recordingRpc), refused);
  assert.equal(readFileSync(storePath, 'utf8'), after);
});

test('wallet startup refuses ERC20 mode for an unregistered foreign pending return', async (t) => {
  const { w, open, cfg, deployment } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const record = await w.returnRecord('coin');
  record.erc20PayerState = 1;
  delete record.payer;
  await w.bridge.journal.putReturn(record);
  await w.bridge.journal.registerPayerChain(cfg.chainId);
  const openSdk = NativeBridgeV2.open.bind(NativeBridgeV2);
  t.mock.method(NativeBridgeV2, 'open', async (...args: Parameters<typeof openSdk>) => {
    const bridge = await openSdk(...args);
    bridge.cfg.erc20 = { token: new Uint8Array(20).fill(1), generation: deployment.salt, pins: deployment.pins };
    return bridge;
  });
  await open('holder');

  const { Assets } = JSON.parse(readFileSync(new URL('../protocol/vectors/erc20-nb2/vectors.json', import.meta.url), 'utf8'));
  const { Gamma, Held } = Assets[0] as { Gamma: string; Held: string };
  const foreign = new Journal(w.bridge.journal.store, domainOf(unhex('0x' + Gamma.replace(/^0x/, ''))));
  const tx = await signTx(w.signer, { chainId: cfg.chainId, nonce: 7n, gas: 100_000n, maxFeePerGas: 10n,
    maxPriorityFeePerGas: 1n, to: cfg.vault, value: 0n, data: new Uint8Array() });
  await foreign.putReturn({ ...record, ...foreign.base(), returnId: hx(key('foreign ERC20 pending')), status: 'submitted',
    source: `0x${Held.replace(/^0x/, '')}`, erc20PayerState: undefined, recovery: undefined, executionPayer: hx(w.signer.address),
    sends: [{ raw: hx(tx.raw), hash: hx(tx.hash), nonce: '7', gas: '100000', at: '0' }] });
  const file = join(w.dir, 'journal.json');
  const before = readFileSync(file, 'utf8');
  await assert.rejects(open('holder'), /unsupported pre-release ERC20 record: start a fresh wallet/);
  assert.equal(readFileSync(file, 'utf8'), before);
});

test('a peer payout keeps the wallet packet reserved after it drops out of the mempool', async (t) => {
  const { w, open, chain, deployment, cfg } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const packet = await session.run(0, session.operationCount, w.trust);
  chain.coldCall = async (_vault, to) => eq(to, deployment.recovery)
    ? [{ address: to, topics: packet.event.topics, data: packet.event.data }] : undefined;
  const peer = await open('peer settling first');
  chain.fund(peer.signer.address, 10n ** 18n);
  const ordinary = await w.bridge.buildRedeem(unhex(rec.returnId));
  const other = await signTx(peer.signer, { chainId: cfg.chainId, nonce: 0n, gas: ordinary.gasLimit,
    maxFeePerGas: 23n, maxPriorityFeePerGas: 1n, to: cfg.vault, value: 0n, data: ordinary.calldata });
  const journal = w.bridge.journal;
  const erc20 = { token: new Uint8Array(20).fill(1), generation: deployment.salt, pins: deployment.pins };
  rec.erc20PayerState = 1;
  delete rec.payer;
  await journal.putReturn(rec);
  await journal.registerPayerChain(cfg.chainId);
  w.bridge.cfg.erc20 = erc20;
  await journal.checkReturnPayer(cfg.chainId, w.signer.address, rec.returnId, true);
  assert.equal((await recoverStep(w, rec, caps)).state, 'checkpoint');
  chain.autoMine = false;
  assert.equal((await recoverStep(w, rec, caps)).state, 'pending');
  const file = join(w.dir, 'recovery-' + rec.returnId.slice(2) + '.json');
  const pending = unhex(JSON.parse(readFileSync(file, 'utf8')).pending.raw);
  chain.dropPool();
  const signed = decodeSignedTx(pending).request;
  const payerPath = `${cfg.chainId}/${hx(w.signer.address).slice(2)}/${rec.domain.slice(2)}/${rec.returnId.slice(2)}`;
  const index = `nb2/payer-fees/v1/${payerPath}/${signed.nonce}`;
  const journalFile = join(w.dir, 'journal.json');
  const complete = readFileSync(journalFile, 'utf8');
  const incomplete = JSON.parse(complete);
  delete incomplete[index];
  writeFileSync(journalFile, JSON.stringify(incomplete));
  const refused = /unsupported pre-release ERC20 record: start a fresh wallet/;
  const broadcast = t.mock.method(w.bridge.evm, 'sendRaw', async () => { throw new Error('unexpected RPC send'); });
  await assert.rejects(checkLocalErc20Returns(w), refused);
  await assert.rejects(recoverStep(w, rec, caps), refused);
  assert.equal(broadcast.mock.callCount(), 0);
  assert.equal(await journal.store.get(index), null);
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).pending.raw, hx(pending));
  broadcast.mock.restore();
  writeFileSync(journalFile, complete);
  await checkLocalErc20Returns(w);
  w.bridge.cfg.erc20 = undefined;

  await chain.mine([other.raw]);
  await chain.mine([]);
  const paid = await recoverStep(w, rec, caps);
  assert.equal(paid.state, 'paid');
  assert.equal(hx(paid.txHash), hx(other.hash));
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).settled.submitted.raw, hx(pending));
  const next = { ...rec, returnId: hx(key('new return after peer payout')), status: 'planned' as const };
  w.bridge.cfg.erc20 = erc20;
  await checkLocalErc20Returns(w);
  const nonce = decodeSignedTx(pending).request.nonce;
  assert.equal(await w.bridge.evm.nonce(w.signer.address, 'pending'), nonce);
  await assert.rejects(w.bridge.checkErc20Payer(next, w.signer.address), /signed nonce awaiting finalization/);
  await chain.mine([pending]);
  await chain.mine([]);
  assert.equal((await w.bridge.checkErc20Payer(next, w.signer.address)).finalizedNonce, nonce + 1n);
});

test('a peer payout cannot release the payer while the recovery signer is outstanding or ambiguous', async (t) => {
  const { w, open, chain, deployment, cfg } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const peer = await open('peer pays while the signer is waiting');
  chain.fund(peer.signer.address, 10n ** 18n);
  const ordinary = await w.bridge.buildRedeem(unhex(rec.returnId));
  const payment = await signTx(peer.signer, { chainId: cfg.chainId, nonce: 0n, gas: ordinary.gasLimit,
    maxFeePerGas: 23n, maxPriorityFeePerGas: 1n, to: cfg.vault, value: 0n, data: ordinary.calldata });
  // Use receipt fixtures for proof verification and the ERC20 guard for local execution.
  const erc20 = { token: new Uint8Array(20).fill(1), generation: deployment.salt, pins: deployment.pins };
  rec.erc20PayerState = 1;
  delete rec.payer;
  await w.bridge.journal.putReturn(rec);
  await w.bridge.journal.registerPayerChain(cfg.chainId);
  w.bridge.cfg.erc20 = erc20;
  await w.bridge.checkErc20Payer(rec, w.signer.address, true);
  let enter!: () => void;
  let release!: () => void;
  const entered = new Promise<void>((resolve) => { enter = resolve; });
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  const localSign = w.signer.signTransaction.bind(w.signer);
  const next = { ...rec, returnId: hx(key('next burn after the signer race')), status: 'planned' as const };
  let raw!: Uint8Array;
  w.signer.signTransaction = async (request) => {
    raw = await localSign(request);
    enter();
    await waiting;
    throw new Error('recovery signer disconnected');
  };
  const attempting = assert.rejects(recoverStep(w, rec, caps), /recovery signer disconnected/);
  await Promise.race([entered, attempting.then(() => assert.fail('recovery did not enter the signer'))]);
  try {
    await chain.mine([payment.raw]);
    await chain.mine([]);
    w.bridge.cfg.erc20 = undefined;
    const { result: paid } = await reconcileReturn(w, rec, caps);
    assert.equal(paid.state, 'paid');
    assert.equal(hx(paid.txHash), hx(payment.hash));
    w.bridge.cfg.erc20 = erc20;
    await assert.rejects(w.bridge.checkErc20Payer(next, w.signer.address, true), /signing nonce awaiting finalization/);
  } finally {
    release();
  }
  await attempting;
  await assert.rejects(w.bridge.checkErc20Payer(next, w.signer.address, true), /signing nonce awaiting finalization/);
  await chain.mine([raw]);
  await chain.mine([]);
  const nonce = decodeSignedTx(raw).request.nonce;
  assert.equal((await w.bridge.checkErc20Payer(next, w.signer.address, true)).finalizedNonce, nonce + 1n);
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

test('ordinary wallet admission budgets the higher signed fee at the replacement nonce once', async (t) => {
  const { w, cfg } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const nonce = await w.bridge.evm.nonce(w.signer.address);
  const request = { chainId: cfg.chainId, nonce, gas: 100_000n, maxFeePerGas: 15n, maxPriorityFeePerGas: 1n,
    to: cfg.vault, value: 0n, data: new Uint8Array(68) };
  const older = await signTx(w.signer, { ...request, maxFeePerGas: 30n });
  const prior = [{ raw: hx(older.raw), hash: hx(older.hash), nonce: String(nonce), gas: String(request.gas), at: '0' }];
  const oldFee = older.request.gas * older.request.maxFeePerGas;
  const policy = { ...caps, maxFeePerGas: 20n, feeBudget: oldFee };
  await assert.rejects(ordinaryPayout(w, rec, { ...policy, feeBudget: oldFee - 1n }).admit!(request, prior), /remaining payer limits/);
  await ordinaryPayout(w, rec, policy).admit!(request, prior);
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
  await publishReturnBackup(reopened, rec, backup);
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
  chain.fund(relay.signer.address, 10n ** 18n);
  const rec = await restoreReturn(relay, backup, caps);
  assert.ok(rec.burned && rec.recovery && rec.eta);
  assert.notEqual(hx(relay.signer.address), rec.recipient);
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
  await publishReturnBackup(relay, rec, portable);
  const offline = { certify: async () => { throw new Error('certification service offline'); } };
  // The certified Complete remains usable even if its old run class is no longer priced.
  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  release.recovery.ranges = release.recovery.ranges.filter((r: { max: { entry: string } }) => r.max.entry !== 'run');
  writeFileSync(manifest, JSON.stringify(release));
  const other = await open('archive-relay-device-two', primary, { aggregator: offline });
  const broken = join(dir, 'bad-certified-cut.json');
  const doc = JSON.parse(readFileSync(portable, 'utf8'));
  assert.equal(doc.pending.recovery, undefined);
  doc.complete.location.logIndex = '99';
  writeFileSync(broken, JSON.stringify(doc));
  await assert.rejects(restoreReturn(other, broken), /locator/);
  assert.equal(await other.bridge.journal.ret(rec.returnId), null);
  writeFileSync(broken, JSON.stringify({ ...doc, terminal: hx(key('different terminal')) }));
  await assert.rejects(restoreReturn(other, broken));
  assert.equal(await other.bridge.journal.ret(rec.returnId), null);
  chain.fund(other.signer.address, 10n ** 18n);
  const restored = await restoreReturn(other, portable);
  const settlementJournal = join(other.dir, `recovery-${restored.returnId.slice(2)}.json`);
  const balance = chain.balanceOf(w.signer.address);
  chain.importedTipEpoch = 0n;
  await assert.rejects(recoverStep(other, restored, alternate), { reason: 'ImportLag', retryable: true });
  assert.equal(JSON.parse(readFileSync(settlementJournal, 'utf8')).pending, undefined);
  assert.equal(chain.balanceOf(w.signer.address), balance);
  chain.importedTipEpoch = 1n;
  assert.equal((await recoverStep(other, restored, alternate)).state, 'paid');
  assert.equal(chain.balanceOf(w.signer.address) - balance, 19n);
  assert.equal(chain.vault.q, 0n);
  assert.equal((await recoverStep(relay, rec, alternate)).state, 'paid');
  assert.equal(chain.balanceOf(w.signer.address) - balance, 19n);
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
  await publishReturnBackup(holder, rec, file);
  const relay = await open('width-relayer', backlog);
  assert.equal((await restoreReturn(relay, file)).recovery, undefined);
  assert.equal((await restoreReturn(holder, file, caps)).recovery!.advanceGaps, 1023);
  assert.equal(w.pins.maxEncodedTxBytes, 524_288n);
});

test('restore qualifies the receiving payer without using a legacy unsigned schedule', async (t) => {
  const { w, chain, dir, manifest, open } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const file = join(dir, 'legacy-peer-plan.json');
  await publishReturnBackup(w, rec, file);
  const backup = JSON.parse(readFileSync(file, 'utf8'));
  backup.pending.recovery = { ...rec.recovery, runCuts: [2], advanceGaps: 1 };
  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  release.recovery.ranges = release.recovery.ranges.filter(({ max }: { max: { operations: number } }) => max.operations <= 1);
  writeFileSync(manifest, JSON.stringify(release));
  const relay = await open('local-qualification');
  chain.fund(relay.signer.address, 10n ** 18n);
  const adopted = await importReturn(relay, backup, caps);
  assert.deepEqual(adopted.recovery!.runCuts, [1, 1]);
  assert.equal(adopted.recovery!.advanceGaps, rec.recovery!.advanceGaps);
});

test('portable replay refreshes for later certified cuts and reopening preserves the merged authority', async (t) => {
  const { w, open, rpc, root, chain, deployment, dir, manifest } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const oldRelease = readFileSync(manifest);
  const bundleFile = join(dir, 'trust-base.bundle.cbor');
  const next = await nextEpoch({ ...root, entries: [root.trust.history.tip!.encode()] }, roundNow() + 1n, 1, 55);
  const offline = { certify: async () => { throw new Error('certifier is offline'); } };
  let requests = 0;
  const source: ITrustBaseSource = { getTrustBasePage: async (r) => {
    requests++;
    assert.equal(r.fromEpoch, 2n);
    return encodeTrustBaseResponse({ effectiveEnd: 2n, endEntryId: await next.trust.history.tip!.entryId(),
      entries: [next.entries[1]], fromEpoch: 2n, network: w.bridge.cfg.network, nextEpoch: null, status: BigInt(TrustBaseStatus.OK) });
  } };
  const relay = await open('epoch-relay', rpc, { aggregator: offline, trustSource: source });
  const originallyHeld = readFileSync(join(relay.dir, 'recovery-authority.json'));

  // Accept the newer shipped bundle, then restart against the original deployment files.
  writeFileSync(bundleFile, next.bundle);
  const changed = JSON.parse(oldRelease.toString());
  writeFileSync(manifest, JSON.stringify(changed));
  const advanced = await open('holder');
  assert.equal(advanced.trust.history.tip?.epoch, 2n);
  writeFileSync(bundleFile, root.bundle);
  writeFileSync(manifest, oldRelease);
  const author = await open('holder');
  assert.equal(author.trust.history.tip?.epoch, 2n);

  const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!), new RecoveryAuthority(author.trust, async () => undefined), TEST_PARAMS, deployment);
  const packet = await session.run(0, session.operationCount, author.trust);
  roundAtLeast(next.trust.history.tip!.epochStartRound);
  chain.certificateAuthority = { root: next, epoch: 2n };
  chain.coldCall = async (_vault, to) => eq(to, deployment.recovery)
    ? [{ address: deployment.recovery, topics: packet.event.topics, data: packet.event.data }] : undefined;
  assert.equal((await recoverStep(author, rec, caps)).state, 'checkpoint');

  const backup = join(dir, 'epoch-portable.json');
  await publishReturnBackup(author, rec, backup);
  const restored = await restoreReturn(relay, backup);
  assert.equal(restored.eta, rec.eta);
  assert.equal(requests, 1, 'the later cut fetched the successor during restore');
  const restarted = await open('epoch-relay', rpc, { aggregator: offline });
  assert.equal(restarted.trust.history.tip?.epoch, 2n);

  // The local cut survives on its own as well, with an older authority copied alongside it.
  writeFileSync(join(relay.dir, 'recovery-authority.json'), originallyHeld);
  const local = await open('epoch-relay', rpc, { aggregator: offline, trustSource: source });
  chain.fund(local.signer.address, 10n ** 18n);
  chain.autoMine = false;
  assert.equal((await recoverStep(local, restored, caps)).state, 'pending');
  assert.equal(requests, 2, 'local replay fetched and installed the successor before signing');
  assert.equal((await open('epoch-relay', rpc, { aggregator: offline })).trust.history.tip?.epoch, 2n);
});

test('an ordinary send lost at the gap limit hands its nonce to continuation and pays once', async (t) => {
  const { w, open, chain, deployment, cfg, rpc, manifest, dir } = await setup(t, true);
  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  for (const entry of ['advanceGaps', 'redeemRecovered']) {
    const last = release.recovery.ranges.filter((range: { max: { entry: string } }) => range.max.entry === entry).at(-1);
    for (const gaps of [65, 66]) release.recovery.ranges.push({ ...last, max: { ...last.max, gaps } });
  }
  writeFileSync(manifest, JSON.stringify(release));
  const { eta } = await burn(w, 'coin', undefined, undefined, caps);
  const [rec] = await w.bridge.journal.returns();
  const evidence = evidenceOf(unhex(rec.burned!));
  const verdict = await verifyReturn(chain.gamma, evidence, w.trust, TEST_PARAMS);
  const other = await open('gap-producer');
  chain.fund(other.signer.address, 10n ** 18n);
  const owner = firstOwnerOf(w.owner(0).publicKey);
  const roll = async (count: number) => {
    chain.coldCall = async (vault, to, data) => {
      if (!eq(to, deployment.recovery) || data.length !== 0) return undefined;
      const segment = vault.c;
      for (let j = 0n; j < cfg.K; j++) {
        const id = HE(u256(segment * cfg.K + j + 1n));
        vault.deposit(1n, owner, id);
        vault.redeem(id, segment, new Uint8Array(), { ret: verdictAbi({
          ...verdict, eta: id, minSegment: segment, amount: 1n, recipient: other.signer.address,
        }) });
      }
      return [];
    };
    for (let i = 0; i < count; i++) {
      const tx = await signTx(other.signer, { chainId: cfg.chainId, nonce: chain.vault.c, maxFeePerGas: 15n,
        maxPriorityFeePerGas: 1n, gas: 1_000_000n, to: deployment.recovery, value: 0n, data: new Uint8Array() });
      await rpc.call('eth_sendRawTransaction', [hx(tx.raw)]);
    }
    chain.coldCall = undefined;
  };
  await roll(63);
  let drop = true;
  let pooled = false;
  const interrupted: JsonRpc = { async call<T>(method: string, params: unknown[]): Promise<T> {
    if (method === 'eth_sendRawTransaction' && drop) {
      drop = false;
      throw new Error('ordinary transport failed before delivery');
    }
    if (method === 'eth_getTransactionCount' && params[1] === 'pending' && pooled) {
      return ('0x' + (BigInt(await rpc.call<string>(method, params)) + 1n).toString(16)) as T;
    }
    if (method === 'eth_call' && (params[0] as { data: string }).data.startsWith(hx(SELECTOR.redeem))) {
      return chain.call<T>(method, params);
    }
    return rpc.call<T>(method, params);
  } };
  let payer = await open('holder', interrupted);
  await assert.rejects(resumePayout(payer, rec, caps, true), /ordinary transport failed before delivery/);
  const original = (await payer.bridge.journal.ret(rec.returnId))!.sends[0];
  await roll(2);
  payer = await open('holder', interrupted);
  await assert.rejects(resumePayout(payer, rec, caps, true), { rule: 'CapacityExceeded' });
  assert.equal(await payer.bridge.evm.nonce(payer.signer.address), BigInt(original.nonce));
  pooled = true;
  await assert.rejects(resumePayout(payer, rec, caps, false, true), { reason: 'NotPending' });
  pooled = false;
  const journal = () => JSON.parse(readFileSync(join(payer.dir, `recovery-${rec.returnId.slice(2)}.json`), 'utf8'));
  const session = await RecoverySession.create(chain.gamma, evidence, new RecoveryAuthority(payer.trust, async () => undefined), TEST_PARAMS, deployment);
  const complete = await session.run(0, session.operationCount, payer.trust);
  const segments = chain.vault.events.flatMap((event) => event.name === 'SegmentSealed' ?
    [{ index: event.segment, before: event.before, after: event.after, z: event.ids, root: GapTree.build(event.ids)!.root }] : []);
  let completion: Uint8Array | undefined;
  chain.coldCall = async (vault, to, data) => {
    if (eq(to, deployment.recovery)) {
      assert.deepEqual(data, complete.calldata);
      const pending = journal().pending;
      assert.equal(pending.nonce, original.nonce);
      completion = unhex(pending.txHash);
      return [{ address: to, topics: complete.event.topics, data: complete.event.data }];
    }
    if (eq(to, cfg.vault) && hx(data.subarray(0, 4)) === selector('redeemRecovered(bytes)')) {
      assert.ok(completion);
      const proof = await recoveryRpcSource(new EvmReader(rpc), completion)(deployment.recovery, complete.event);
      const gaps = journal().pending.cut.gaps.map((gap: string) => unhex(gap));
      const settlement = await session.gaps('redeemRecovered', payer.trust, proof, { seq: 1n }, gaps, unhex(rec.startHead));
      assert.deepEqual(data, settlement.calldata);
      const history = buildHistory(segments, eta, verdict.minSegment, vault.c, unhex(rec.startHead));
      vault.redeem(eta, verdict.minSegment, history.history, { ret: verdictAbi(verdict) });
      return [];
    }
    return undefined;
  };
  assert.equal((await resumePayout(payer, rec, caps, false, true)).state, 'checkpoint');
  assert.equal(journal().ordinaryHandoff, original.hash);
  payer = await open('holder', interrupted);
  const holder = payer;
  const saved = (await holder.bridge.journal.ret(rec.returnId))!;
  const backup = join(dir, 'resolved-complete.json');
  await publishReturnBackup(holder, saved, backup);
  assert.equal(JSON.parse(readFileSync(backup, 'utf8')).handoff, undefined);
  assert.deepEqual((await holder.bridge.journal.ret(rec.returnId))?.sends, [original]);

  payer = await open('fresh relayer', interrupted);
  chain.fund(payer.signer.address, 10n ** 18n);
  const restored = await restoreReturn(payer, backup, caps);
  assert.equal((await resumePayout(payer, restored, caps)).state, 'paid');
  const paid = (await payer.bridge.journal.ret(rec.returnId))!;
  assert.ok(paid.paid?.receipt);
  assert.equal(paid.burned, rec.burned);
  assert.equal(await rpc.call('eth_getTransactionReceipt', [original.hash]), null);
  assert.equal(chain.vault.events.filter((e) => e.name === 'Paid' && eq(e.eta, eta)).length, 1);
});

test('route switching refuses unresolved signed sends in either direction after pool eviction', async (t) => {
  for (const active of ['recovery', 'ordinary'] as const) {
    await t.test(active, async (t) => {
      const { w, chain, rpc, open } = await setup(t, active === 'ordinary');
      await burn(w, 'coin', undefined, undefined, caps);
      const rec = await w.returnRecord('coin');
      const sends: Uint8Array[] = [];
      const transport: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
        if (method === 'eth_sendRawTransaction') {
          sends.push(unhex(params[0] as string));
          // Leave the exact request durable before any inclusion.
          throw new Error('interrupted submission');
        }
        return rpc.call<T>(method, params);
      } };
      const initial = await open('holder', transport);
      await assert.rejects(resumePayout(initial, rec, caps, active === 'ordinary'), /interrupted submission/);
      chain.dropPool();
      const restarted = await open('holder', transport);
      const hash = decodeSignedTx(sends[0]).hash;
      if (active === 'ordinary') {
        await assert.rejects(qualifyExistingRecovery(restarted, rec, caps), /route blocked by ordinary transaction/);
        assert.equal((await restarted.returnRecord('coin')).recovery, undefined);
        assert.deepEqual(await recoverStep(restarted, rec, caps), { state: 'route-blocked', route: active, txHash: hash });
      } else {
        assert.deepEqual(await resumePayout(restarted, rec, caps, true), { state: 'route-blocked', route: active, txHash: hash });
        assert.equal((await restarted.returnRecord('coin')).sends.length, 0);
      }
      const otherPayer = await open('holder', transport, { seed: key('different active payer') });
      assert.deepEqual(await resumePayout(otherPayer, rec, caps, active === 'ordinary'),
        { state: 'route-blocked', route: active, txHash: hash, payer: restarted.signer.address });
      assert.equal(sends.length, 1, 'a blocked switch neither signs nor reoffers a send');
    });
  }
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
  assert.deepEqual((await restarted.bridge.journal.ret(rec.returnId))!.sends, [{ ...pending, failureProofReads: 2 }]);
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
  await publishReturnBackup(w, rec, portable);
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
  const pruned = await open('pruned-local', prunedReader, { seed: key('pending-local') });
  await assert.rejects(restoreReturn(pruned, original), { rule: 'EvidencePruned' });
  assert.equal(readFileSync(localFile(pruned), 'utf8'), pending);
  const staleHint = join(dir, 'complete-stale-hint.json');
  const copy = JSON.parse(readFileSync(portable, 'utf8'));
  copy.complete.location.txHash = hx(key('unrelated transaction hint'));
  writeFileSync(staleHint, JSON.stringify(copy));
  await restoreReturn(pruned, staleHint);
  const fromPortable = JSON.parse(readFileSync(localFile(pruned), 'utf8'));
  assert.equal(fromPortable.pending, undefined);
  assert.ok(fromPortable.complete);
  assert.equal(fromPortable.cuts.length, 0);
  assert.deepEqual(fromPortable.superseded, [raw]);
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
  assert.ok(JSON.parse(saved).complete, 'the portable Complete becomes the execution checkpoint');
  assert.deepEqual(JSON.parse(saved).attempts, oldAttempts);
  await restoreReturn(behind, portable);
  assert.equal(readFileSync(localFile(behind), 'utf8'), saved, 'repeating the same import is a no-op');
  chain.autoMine = false;
  assert.equal((await recoverStep(behind, imported, caps)).state, 'pending');
  assert.equal(JSON.parse(readFileSync(localFile(behind), 'utf8')).pending.cut.kind, 'settle');
});

test('portable Complete restart checks archived history before rebroadcasting the lower nonce', async (t) => {
  const { w, dir, open, chain, deployment } = await setup(t);
  const original = join(dir, 'before-run.json');
  await burn(w, 'coin', undefined, undefined, caps, original);
  const rec = await w.returnRecord('coin');
  const relay = await open('unmined-run');
  const relayed = await restoreReturn(relay, original);
  chain.fund(relay.signer.address, 10n ** 18n);
  const session = await RecoverySession.create(chain.gamma, evidenceOf(unhex(rec.burned!)), new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const complete = await session.run(0, session.operationCount, w.trust);
  chain.coldCall = async (_vault, to) => eq(to, deployment.recovery)
    ? [{ address: to, topics: complete.event.topics, data: complete.event.data }] : undefined;
  chain.autoMine = false;
  assert.equal((await recoverStep(relay, relayed, caps)).state, 'pending');
  const journal = join(relay.dir, `recovery-${rec.returnId.slice(2)}.json`);
  const raw = JSON.parse(readFileSync(journal, 'utf8')).pending.raw;
  chain.dropPool();
  chain.autoMine = true;
  assert.equal((await recoverStep(w, rec, caps)).state, 'checkpoint');
  const portable = join(dir, 'external-complete.json');
  await publishReturnBackup(w, rec, portable);
  await restoreReturn(relay, portable);
  const saved = JSON.parse(readFileSync(journal, 'utf8'));
  assert.ok(saved.complete);
  assert.deepEqual(saved.superseded, [raw]);
  await sealTestSegments(chain, await open('restart-seal-producer'), 1);
  chain.faults.hideSegments.add(0n);
  const restarted = await open('unmined-run');
  const send = t.mock.method(restarted.bridge.evm, 'sendRaw');
  const payerBefore = chain.balanceOf(restarted.signer.address);
  await assert.rejects(recoverStep(restarted, relayed, caps), /no SegmentSealed log of segment 0/);
  assert.equal(send.mock.callCount(), 0);
  assert.equal(chain.balanceOf(restarted.signer.address), payerBefore);
  assert.deepEqual(JSON.parse(readFileSync(journal, 'utf8')).superseded, [raw]);
  chain.faults.hideSegments.clear();
  chain.autoMine = false;
  assert.equal((await recoverStep(restarted, relayed, caps)).state, 'pending');
  assert.equal(send.mock.callCount(), 1);
  assert.deepEqual(send.mock.calls[0].arguments[0], unhex(raw), 'replay preserves the exact transaction and nonce');
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
  await publishReturnBackup(w, rec, certified);

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
  ordinary.erc20PayerState = 1;
  await relay.bridge.journal.putReturn(ordinary);
  await relay.bridge.journal.registerPayerChain(cfg.chainId);
  await relay.bridge.journal.preparePayerSigning(ordinary, cfg.chainId, relay.signer.address);
  chain.coldCall = async (_vault, to, data) => {
    if (eq(to, cfg.vault) && eq(data.subarray(0, 4), SELECTOR.redeem)) throw new Nb2Error('PayoutFailed');
    return undefined;
  };
  assert.equal((await resumePayout(relay, ordinary, caps)).state, 'pending');
  await chain.mine([]);
  const sends = (await relay.bridge.journal.ret(rec.returnId))!.sends;
  assert.equal(sends.length, 1);
  await relay.bridge.journal.retainPayerSend(ordinary, unhex(sends[0].raw));

  const cold = await qualifyExistingRecovery(w, rec, caps);
  const session = await RecoverySession.create(chain.gamma, unhex(cold.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const packet = await session.run(0, session.operationCount, w.trust);
  chain.coldCall = async (_vault, to) => eq(to, deployment.recovery)
    ? [{ address: deployment.recovery, topics: packet.event.topics, data: packet.event.data }] : undefined;
  const complete = await recoverStep(w, cold, caps);
  assert.equal(complete.state, 'checkpoint');
  const portable = join(dir, 'ordinary-later-complete.json');
  await publishReturnBackup(w, cold, portable);

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
  assert.equal(adopted.recovery, undefined, 'a restore without policy retains only certified evidence');
  assert.deepEqual(adopted.sends.map(({ raw }) => raw), sends.map(({ raw }) => raw));
  const journal = JSON.parse(readFileSync(file, 'utf8'));
  assert.ok(journal.complete);
  assert.equal(journal.cuts.length, 0);
  assert.equal(journal.attempts, undefined, 'the holder’s cold fees are outside the relayer’s ledger');
  const proof = unhex(journal.complete.location.proof);
  const settlement = await session.gaps('redeemRecovered', reopened.trust, proof, { seq: 1n }, []);
  const { request } = decodeSignedTx(unhex(sends[0].raw));
  const cost = request.gas * request.maxFeePerGas + (1_721_000n + 16n * BigInt(settlement.calldata.length)) * caps.maxFeePerGas;
  assert.deepEqual((await restoreReturn(reopened, portable)).sends, adopted.sends);
  const localPlan = await qualifyExistingRecovery(reopened, adopted, caps);
  assert.equal(localPlan.recovery, undefined);
  // An imported Complete can only use funds left after the payer's outstanding ERC20 return.
  const journalStore = reopened.bridge.journal;
  reopened.bridge.cfg.erc20 = { token: new Uint8Array(20).fill(1), generation: deployment.salt, pins: deployment.pins };
  const pledged = { ...localPlan, returnId: hx(key('pledged payer balance')), status: 'burned' as const,
    payer: hx(reopened.signer.address), burnRequest: undefined, executionPayer: undefined, sends: [], recovery: { ...cold.recovery!, totalFee: String(cost) } };
  await journalStore.putReturn(pledged);
  await checkLocalErc20Returns(reopened);

  await reopened.bridge.checkErc20Payer(pledged, reopened.signer.address, true);
  chain.fund(reopened.signer.address, cost - chain.balanceOf(reopened.signer.address));
  await assert.rejects(recoverStep(reopened, localPlan, caps), /payer already has an outstanding ERC20 return/);
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).pending, undefined);
  await journalStore.retForUpdate(pledged.returnId);
  await journalStore.putReturn({ ...pledged, status: 'paid', paid: { txHash: hx(key('pledged return paid')), blockNumber: '1' } });
  reopened.bridge.cfg.erc20 = undefined;
  chain.fund(reopened.signer.address, 10n ** 18n);
  await assert.rejects(recoverStep(reopened, localPlan, { ...caps, feeBudget: cost - 1n }), { rule: 'CapacityPreflight' });
  chain.autoMine = false;
  assert.equal((await recoverStep(reopened, localPlan, { ...caps, feeBudget: cost })).state, 'pending');
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
  await publishReturnBackup(relayer, certified, terminal);
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
      else await restoreReturn(producer, backup('signed'), caps);
      const rec = (await producer.bridge.journal.ret(id))!;
      await publishReturnBackup(producer, rec, backup('terminal'));
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
        await publishReturnBackup(producer, rec, backup(name));
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
      const evidence = ['none', 'signed', 'terminal', 'progress', 'complete'] as const;
      // Each cell is the local cut count. An imported Complete lives separately.
      const unpaid = {
        absent:             [0, 0, 0, 'blocked', 0],
        planned:            [0, 0, 0, 'blocked', 0],
        signed:             [0, 0, 0, 'blocked', 0],
        terminal:           [0, 0, 0, 0, 0],
        submitted:          [0, 0, 0, 0, 'blocked'],
        progress:           [1, 1, 1, 1, 0],
        complete:           [2, 2, 2, 2, 2],
        gap:                [3, 3, 3, 3, 3],
        'pending-progress': [0, 'pruned', 'pruned', 'pruned', 0],
        'pending-complete': [1, 'pruned', 'pruned', 'pruned', 0],
        'pending-gap':      [2, 'pruned', 'pruned', 'pruned', 2],
        'pending-settle':   [3, 3, 3, 3, 3],
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
            if (before) assert.notEqual((await reconcileReturn(device, before, caps, undefined, false)).result.state, 'paid', label);
            assert.equal(journal(device)?.cuts.length ?? 0, expected, label);
            assert.equal(before?.status, row === 'absent' ? undefined : localStatus[row] ?? 'burned', label);
          } else if (expected === 'blocked') {
            await assert.rejects(restoreReturn(device, backup(proof)), /active payer handoff is blocked|route blocked by ordinary/);
            assert.deepEqual(journal(device), local, label);
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
            assert.deepEqual(journal(device)?.attempts, local?.attempts, label);
            const imported = proof === 'complete' && ['absent', 'planned', 'signed', 'terminal', 'progress', 'pending-progress', 'pending-complete'].includes(row);
            assert.equal(Boolean(journal(device)?.complete), imported, label);
            assert.deepEqual(journal(device)?.superseded, local?.pending && imported ? [local.pending.raw] : undefined, label);
            assert.deepEqual(journal(device)?.pending, imported ? undefined : local?.pending, label);
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
      cpSync(join(dir, 'snapshot-gap'), join(dir, 'ordinary-payer'), { recursive: true });
      const ordinaryPayer = await open('ordinary-payer', rpc, { seed: key(holderFirst ? 'holder' : 'matrix-relayer') });
      assert.equal((await resumePayout(ordinaryPayer, rec, caps, true)).state, 'paid');
      const payouts = [
        { route: 'ordinary', transport: rpc, payer: ordinaryPayer },
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
              if (before) assert.equal((await reconcileReturn(device, before, caps)).result.state, 'not-paid', label);
              assert.deepEqual(await device.bridge.journal.ret(id), before, label);
              continue;
            }
            // A durable signed request binds a discovered Paid even when no portable file was supplied.
            if (proof === 'none') {
              assert.equal((await reconcileReturn(device, before!, caps)).result.state, 'paid', label);
            } else {
              await restoreReturn(device, backup(proof));
            }
            const restored = (await device.bridge.journal.ret(id))!;
            assert.equal(restored.status, 'paid', label);
            assert.deepEqual(restored.paid, paid, label);
            assert.equal(Boolean(restored.burned), Boolean(before?.burned) || !['none', 'signed'].includes(proof), label);
            assert.deepEqual(restored.sends, before?.sends ?? [], label);
            assert.deepEqual(journal(device)?.cuts, local?.cuts, label);
            if (local?.pending) {
              assert.equal(journal(device).pending, undefined, label);
              assert.equal(journal(device).settled.submitted.raw, local.pending.raw, label);
            }
          }
        }
      }
    });
  }
});

test('local Complete wins over peer Progress and peer Complete installs no unsigned suffix', async (t) => {
  const { w, chain, dir, open, rpc, deployment, manifest } = await setup(t);
  const signed = join(dir, 'original-signed.json');
  await burn(w, 'coin', undefined, undefined, caps, signed);
  const original = await w.returnRecord('coin');
  assert.deepEqual(original.recovery!.runCuts, [2]);
  const session = await RecoverySession.create(chain.gamma, unhex(original.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const whole = await session.run(0, 2, w.trust);
  const prefix = await session.run(0, 1, w.trust);
  const events = new Map([[hx(whole.calldata), whole.event], [hx(prefix.calldata), prefix.event]]);
  chain.coldCall = async (_vault, to, data) => {
    if (!eq(to, deployment.recovery)) return undefined;
    const event = events.get(hx(data));
    assert.ok(event);
    return [{ address: to, topics: event.topics, data: event.data }];
  };
  const saved = (device: Wallet) => join(device.dir, `recovery-${original.returnId.slice(2)}.json`);
  const journal = (device: Wallet) => JSON.parse(readFileSync(saved(device), 'utf8'));
  chain.autoMine = false;
  assert.equal((await recoverStep(w, original, caps)).state, 'pending');
  const raw = journal(w).pending.raw;
  chain.dropPool();
  await chain.mine([unhex(raw)]);
  await chain.mine([]);
  chain.autoMine = true;

  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  release.recovery.ranges = release.recovery.ranges.filter(({ max }: { max: { operations: number } }) => max.operations <= 1);
  writeFileSync(manifest, JSON.stringify(release));
  const peer = await open('prefix-peer');
  chain.fund(peer.signer.address, 10n ** 18n);
  const split = await restoreReturn(peer, signed, caps);
  assert.deepEqual(split.recovery!.runCuts, [1, 1]);
  assert.equal((await recoverStep(peer, split, caps)).state, 'checkpoint');
  const replacement = await open('prefix-peer', rpc, { seed: key('replacement payer after certified Progress') });
  chain.fund(replacement.signer.address, 10n ** 18n);
  const heldProgress = readFileSync(saved(peer), 'utf8');
  const refusal = await resumePayout(replacement, split, caps);
  assert.equal(refusal.state, 'route-blocked');
  assert.deepEqual(refusal.payer, peer.signer.address);
  assert.equal(readFileSync(saved(peer), 'utf8'), heldProgress);
  const file = join(dir, 'peer-incomplete.json');
  await publishReturnBackup(peer, split, file);
  const incomplete = JSON.parse(readFileSync(file, 'utf8'));
  assert.equal(incomplete.handoff, 'active');
  assert.equal(incomplete.complete, undefined);
  assert.equal(incomplete.pending.recovery, undefined);
  const legacy = { ...incomplete, checkpoint: { ...journal(peer), attempts: undefined } };
  const fresh = await open('fresh-incomplete');
  await assert.rejects(importReturn(fresh, legacy, caps), /active payer handoff is blocked/);

  const local = await open('holder', rpc);
  const localRec = await importReturn(local, legacy, caps);
  assert.deepEqual(localRec.recovery!.runCuts, [2]);
  assert.equal(journal(local).cuts.length, 1);
  assert.equal(journal(local).cuts[0].state, undefined);
  assert.equal(journal(local).pending, undefined);
  assert.deepEqual(journal(local).attempts, [raw]);

  const first = journal(peer).cuts[0];
  const tail = await session.run(1, 1, peer.trust, { seq: 1n, receipt: unhex(first.location.proof) });
  events.set(hx(tail.calldata), tail.event);
  assert.equal((await recoverStep(peer, split, caps)).state, 'checkpoint');
  const terminal = join(dir, 'peer-complete.json');
  await publishReturnBackup(peer, split, terminal);
  const offered = JSON.parse(readFileSync(terminal, 'utf8'));
  assert.equal(offered.handoff, undefined);
  assert.equal(offered.pending.recovery, undefined);
  offered.pending.recovery = { ...split.recovery, runCuts: [16], advanceGaps: 1 };
  const stale = await open('complete-obsolete-plan');
  chain.fund(stale.signer.address, 10n ** 18n);
  const staged = await restoreReturn(stale, signed, caps);
  assert.ok(staged.recovery!.advanceGaps > 1);
  release.recovery.ranges = release.recovery.ranges.filter(({ max }: { max: { entry: string; gaps: number } }) =>
    max.entry === 'advanceGaps' && max.gaps === 1 || max.entry === 'redeemRecovered' && max.gaps === 0);
  writeFileSync(manifest, JSON.stringify(release));
  const recipient = await open('complete-recipient');
  const adopted = await importReturn(recipient, offered, caps);
  assert.equal(adopted.recovery, undefined, 'an unfunded recipient journals Complete before settlement qualification');
  assert.equal(journal(recipient).cuts.length, 0);
  assert.equal(journal(recipient).complete.seq, '2');
  const oldReceiver = await open('complete-obsolete-plan');
  assert.equal((await importReturn(oldReceiver, offered, caps)).recovery, undefined, 'the obsolete plan was removed');
  assert.equal((await restoreReturn(oldReceiver, signed, caps)).recovery, undefined, 'an older backup cannot restart the lineage');
  chain.fund(recipient.signer.address, 10n ** 18n);
  chain.autoMine = false;
  assert.equal((await resumePayout(recipient, adopted, caps)).state, 'pending');
  assert.equal(journal(recipient).pending.cut.kind, 'settle');
  chain.dropPool(); // Exercise the second receiver's independent quote without a visible competing settlement.
  assert.equal((await resumePayout(oldReceiver, staged, caps)).state, 'pending');
  assert.equal(journal(oldReceiver).pending.cut.kind, 'settle');
  chain.dropPool();
  chain.autoMine = true;
  const before = readFileSync(saved(local), 'utf8');
  await importReturn(local, offered, caps);
  assert.equal(readFileSync(saved(local), 'utf8'), before, 'local Complete also wins over an equivalent terminal');
});

test('Paid proof matrix closes every wallet entry point with a lagging log index', async (t) => {
  const { w, chain, cfg, dir, open, rpc, deployment, manifest } = await setup(t);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const initial = join(dir, 'paid-proof-terminal.json');
  await publishReturnBackup(w, rec, initial);
  const id = rec.returnId;
  const file = (device: Wallet) => join(device.dir, `recovery-${id.slice(2)}.json`);
  const journal = (device: Wallet) => JSON.parse(readFileSync(file(device), 'utf8'));
  const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const complete = await session.run(0, 2, w.trust);
  const verdict = await verifyReturn(chain.gamma, evidenceOf(unhex(rec.burned!)), w.trust, TEST_PARAMS);
  chain.coldCall = async (vault, to) => {
    if (eq(to, deployment.recovery)) return [{ address: to, topics: complete.event.topics, data: complete.event.data }];
    if (eq(to, cfg.vault)) {
      vault.redeem(verdict.eta, 0n, new Uint8Array(), { ret: verdictAbi(verdict) });
      return [];
    }
    return undefined;
  };
  assert.equal((await recoverStep(w, rec, caps)).state, 'checkpoint');
  chain.autoMine = false;
  assert.equal((await recoverStep(w, rec, caps)).state, 'pending');
  const exact = journal(w).pending;
  const names = ['redeem', 'redeem-recover', 'resume', 'import', 'restore'];
  for (const name of names) cpSync(w.dir, join(dir, `entry-${name}`), { recursive: true });
  chain.dropPool();
  await chain.mine([unhex(exact.raw)]);
  await chain.mine([]);
  const lagging: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_getLogs') return Promise.resolve([] as T);
    if (method === 'eth_sendRawTransaction') throw new Error('Paid must close before signing or broadcasting');
    return rpc.call<T>(method, params);
  } };
  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  release.recovery.ranges = [];
  writeFileSync(manifest, JSON.stringify(release));
  const offline = { certify: async () => { throw new Error('Paid must not require certification'); } };

  for (const name of names) {
    const device = await open(`entry-${name}`, lagging, { aggregator: offline, seed: key('holder') });
    switch (name) {
      case 'redeem': assert.equal((await redeem(device, 'coin', 0, 0, undefined, undefined, caps)).state, 'paid'); break;
      case 'redeem-recover': assert.equal((await resumePayout(device, rec, caps, false, true)).state, 'paid'); break;
      case 'resume': assert.equal((await resumePayout(device, rec, caps)).state, 'paid'); break;
      case 'import': assert.equal((await importReturn(device, JSON.parse(readFileSync(initial, 'utf8')), caps)).status, 'paid'); break;
      case 'restore': assert.equal((await restoreReturn(device, initial, caps)).status, 'paid'); break;
    }
    const paid = await device.returnRecord('coin');
    assert.equal(paid.paid!.txHash, exact.txHash, name);
    assert.ok(paid.paid!.receipt, name);
    assert.equal(journal(device).pending, undefined, name);
    assert.equal(journal(device).settled.submitted.raw, exact.raw, name);
    if (name === 'restore') {
      const portable = join(dir, 'portable-paid.json');
      await publishReturnBackup(device, paid, portable);
      const unavailable: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
        if (/eth_getLogs|eth_getTransactionReceipt|eth_getBlockByHash/.test(method)) throw new Error('no archive');
        return lagging.call<T>(method, params);
      } };
      const other = await open('offline-paid', unavailable, { aggregator: offline });
      assert.deepEqual((await restoreReturn(other, portable, caps)).paid, paid.paid);
      const wrong = JSON.parse(readFileSync(portable, 'utf8'));
      wrong.paid.receipt = JSON.parse(readFileSync(initial, 'utf8')).terminal;
      await assert.rejects(importReturn(await open('bad-portable-paid', unavailable), wrong, caps));
    }
  }
});

test('cold and ordinary sends stay pending on an incomplete failure proof, report needs-archive on a pruned answer, and recover with a complete reader', async (t) => {
  for (const route of ['cold', 'ordinary'] as const) {
    await t.test(route, async (t) => {
      const { w, chain, cfg, deployment, dir, open, rpc } = await setup(t, route === 'ordinary');
      await burn(w, 'coin', undefined, undefined, caps);
      const rec = await w.returnRecord('coin');
      const destination = route === 'cold' ? deployment.recovery : cfg.vault;
      chain.coldCall = async (_vault, to) => {
        if (eq(to, destination)) throw new Nb2Error('PayoutFailed');
        return undefined;
      };
      const sentRaws: string[] = [];
      const archive: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
        if (method === 'eth_estimateGas') return '0x1d4c0' as T;
        if (method === 'eth_sendRawTransaction') {
          const raw = unhex(params[0] as string);
          sentRaws.push(params[0] as string);
          await chain.mine([raw]);
          return hx(decodeSignedTx(raw).hash) as T;
        }
        return rpc.call<T>(method, params);
      } };
      const first = await open('holder', archive);
      const run = (device: Wallet) => route === 'cold' ? recoverStep(device, rec, caps) :
        reconcileReturn(device, rec, caps).then(({ result }) => result);
      const submitted = await resumePayout(first, rec, caps, route === 'ordinary');
      assert.equal(submitted.state, 'pending', route);
      const activeBackup = join(dir, 'active-return.json');
      await publishReturnBackup(first, await first.returnRecord('coin'), activeBackup);
      const exported = JSON.parse(readFileSync(activeBackup, 'utf8'));
      await chain.mine([]);
      cpSync(first.dir, join(dir, 'missing-raw'), { recursive: true });
      let rawReads = 0;
      const incomplete: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
        if (method === 'eth_getRawTransactionByBlockHashAndIndex') { rawReads++; return Promise.resolve('0x01' as T); }
        if (method === 'eth_sendRawTransaction') throw new Error('do not replace an unproved failure');
        return archive.call<T>(method, params);
      } };
      // a corrupt raw transaction is no pruned answer: the failure stays pending (no blind resend), however often it is read
      for (let i = 0; i < 4; i++) {
        const restart = await open('holder', incomplete);
        if (route === 'ordinary') {
          if (i === 1) await importReturn(restart, exported, caps);
          else await restoreReturn(restart, activeBackup, caps);
          assert.equal((await restart.returnRecord('coin')).sends.at(-1)!.failureProofReads, Math.min(i + 2, 3));
          assert.equal((await run(restart)).state, 'pending');
        } else {
          const outcome = await run(restart);
          assert.equal(outcome.state, 'pending');
        }
      }
      assert.ok(rawReads >= 3);
      const lagging: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> =>
        method === 'eth_getTransactionReceipt' ? Promise.resolve(null as T) : incomplete.call<T>(method, params) };
      assert.equal((await run(await open('holder', lagging))).state, 'pending', 'a reader that lost the failure metadata proves nothing');
      {
        // the failed receipt's block is rolled back (review P2-1): 20 blocks on, the send is gone and its nonce unused, so the identical
        // signed bytes are offered again; nothing new is signed
        const failedRaw = sentRaws.at(-1)!;
        const failed = decodeSignedTx(unhex(failedRaw));
        cpSync(first.dir, join(dir, 'rolled-back'), { recursive: true });
        const offered: string[] = [];
        const rolled: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
          if (method === 'eth_getTransactionReceipt' && params[0] === hx(failed.hash)) return null as T;
          if (method === 'eth_getTransactionCount' && params[1] === 'latest' && params[0] === hx(failed.from)) return `0x${failed.request.nonce.toString(16)}` as T;
          if (method === 'eth_call' && (params[0] as { data?: string }).data === hx(failed.request.data)) return '0x' as T;
          if (method === 'eth_sendRawTransaction') { offered.push(params[0] as string); return hx(HE(unhex(params[0] as string))) as T; }
          return incomplete.call<T>(method, params);
        } };
        const early = await open('rolled-back', rolled, { seed: key('holder') });
        assert.equal((await run(early)).state, 'pending');
        assert.deepEqual(offered, [], 'near the head nothing is offered again');
        for (let i = 0; i < 20; i++) await chain.mine([]);
        const late = await open('rolled-back', rolled, { seed: key('holder') });
        assert.equal((await run(late)).state, 'pending');
        assert.ok(offered.length >= 1 && offered.every((raw) => raw === failedRaw), 'only the identical signed bytes');
        if (route === 'ordinary') assert.equal((await late.returnRecord('coin')).sends.length, (await first.returnRecord('coin')).sends.length);
      }
      const missing: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> =>
        method === 'eth_getRawTransactionByBlockHashAndIndex' ? Promise.resolve(null as T) : incomplete.call<T>(method, params) };
      const pruned = await open('missing-raw', missing, { seed: key('holder') });
      const archived = await run(pruned);
      assert.equal(archived.state, 'needs-archive');
      assert.match(archived.state === 'needs-archive' ? archived.missing ?? '' : '', /raw transaction/);
      if (route === 'ordinary') await assert.rejects(restoreReturn(pruned, activeBackup, caps), /needs archive.*raw transaction/);
      const restored = await open('holder', archive);
      if (route === 'ordinary') assert.ok((await restoreReturn(restored, activeBackup, caps)).sends.at(-1)!.failed);
      else assert.equal((await run(restored)).state, 'retry');
      const failureExport = join(dir, 'verified-failure.json');
      await publishReturnBackup(restored, await restored.returnRecord('coin'), failureExport);
      const failed = JSON.parse(readFileSync(failureExport, 'utf8'));
      assert.equal(failed.handoff, 'active');
      assert.equal(failed.activePayer, hx(restored.signer.address));
      await assert.rejects(restoreReturn(await open('premature-handoff'), failureExport), /active payer handoff is blocked.*with payer 0x/);
      if (route === 'ordinary') {
        const last = (await restored.returnRecord('coin')).sends.at(-1)!;
        assert.equal(last.failed!.txHash, hx(decodeSignedTx(unhex(last.raw)).hash));
        assert.equal(last.failureProofReads, undefined);
        assert.equal((await run(await open('holder', missing))).state, 'not-paid', 'verified failure survives an archive downgrade');
      }
    });
  }
});

test('peer ordinary Paid crosses reader capabilities and preempts cold admission', async (t) => {
  const { createServer } = await import('node:http');
  const { w, chain, dir, open, rpc, manifest } = await setup(t, true);
  await burn(w, 'coin', undefined, undefined, caps);
  const ordinary = await w.returnRecord('coin');
  const backup = join(dir, 'paid-by-ordinary-peer.json');
  await publishReturnBackup(w, ordinary, backup);
  assert.equal(ordinary.recovery, undefined);
  const peer = await open('ordinary-peer');
  chain.fund(peer.signer.address, 10n ** 18n);
  const peerRec = await restoreReturn(peer, backup);
  const paid = await resumePayout(peer, peerRec, caps, true);
  assert.equal(paid.state, 'paid');
  const release = JSON.parse(readFileSync(manifest, 'utf8'));
  release.recovery.ranges = [];
  writeFileSync(manifest, JSON.stringify(release));

  let proofs = 0;
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk);
    const { id, method, params } = JSON.parse(Buffer.concat(chunks).toString());
    try {
      const result = method === 'eth_getLogs' ? [] : await rpc.call(method, params);
      if (method === 'eth_getTransactionReceipt' && params[0] === hx(paid.txHash)) proofs++;
      res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
    } catch (e) {
      res.end(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message: String(e) } }));
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const archive = { ...caps, archives: [`http://127.0.0.1:${(server.address() as { port: number }).port}`] };
  const discoveryOnly: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_getTransactionReceipt') throw new Error('no receipt archive');
    if (method === 'eth_sendRawTransaction') throw new Error('certified peer payment takes priority');
    return rpc.call<T>(method, params);
  } };
  const holder = await open('holder', discoveryOnly);
  // a reader that indexes the peer's Paid but serves no receipt proves nothing: pending, never escalated by a count of reads
  for (let i = 0; i < 4; i++) {
    const reopened = await open('holder', discoveryOnly);
    assert.deepEqual((await reconcileReturn(reopened, ordinary, caps, undefined, false)).result,
      { state: 'pending', txHash: paid.txHash });
  }
  const result = await resumePayout(holder, ordinary, archive, false, true);
  assert.equal(result.state, 'paid');
  assert.ok(proofs > 0, 'the reader with the proof need not index the event');
  const held = await holder.returnRecord('coin');
  assert.equal(held.recovery, undefined);
  assert.deepEqual(held.paid, (await peer.bridge.journal.ret(ordinary.returnId))!.paid);
});

async function partialProofReader(t: TestContext, read: (method: string, params: unknown[]) => Promise<unknown>) {
  const { createServer } = await import('node:http');
  let requests = 0;
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk);
    const { id, method, params } = JSON.parse(Buffer.concat(chunks).toString());
    requests++;
    try {
      res.end(JSON.stringify({ jsonrpc: '2.0', id, result: await read(method, params) }));
    } catch (error) {
      res.end(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message: String(error) } }));
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  return { policy: { ...caps, archives: [`http://127.0.0.1:${(server.address() as { port: number }).port}`] }, requests: () => requests };
}

test('the wallet\'s own cold-route settle packet whose seen Paid block is replaced is offered again as the same bytes, never vanished', async (t) => {
  const { w, chain, cfg, deployment, open, rpc } = await setup(t, false);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const complete = await session.run(0, 2, w.trust);
  const verdict = await verifyReturn(chain.gamma, evidenceOf(unhex(rec.burned!)), w.trust, TEST_PARAMS);
  chain.coldCall = async (vault, to) => {
    if (eq(to, deployment.recovery)) return [{ address: to, topics: complete.event.topics, data: complete.event.data }];
    if (!eq(to, cfg.vault)) return undefined;
    vault.redeem(verdict.eta, 0n, new Uint8Array(), { ret: verdictAbi(verdict) });
    return [];
  };
  assert.equal((await recoverStep(w, rec, caps)).state, 'checkpoint');
  let raw!: Uint8Array;
  const interrupted: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_sendRawTransaction') {
      raw = unhex(params[0] as string);
      throw new Error('offline after signing payout');
    }
    return rpc.call<T>(method, params);
  } };
  await assert.rejects(resumePayout(await open('holder', interrupted), rec, caps, false), /offline after signing payout/);
  const settle = decodeSignedTx(raw);
  await chain.mineUncertified(); // nothing pooled: the packet was never broadcast
  await chain.mine([raw]); // the settle packet pays, in a block not certified yet
  const state = { rollback: false, offered: [] as string[] };
  const rolled: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (!state.rollback) {
      if (method === 'eth_sendRawTransaction') throw new Error('nothing is sent before the rollback');
      return rpc.call<T>(method, params);
    }
    if (method === 'eth_getTransactionReceipt' && params[0] === hx(settle.hash)) return null as T;
    if (method === 'eth_getLogs') return (await rpc.call<{ transactionHash: string }[]>(method, params)).filter((l) => l.transactionHash !== hx(settle.hash)) as T;
    if (method === 'eth_getTransactionCount' && params[1] === 'latest' && params[0] === hx(settle.from)) return `0x${settle.request.nonce.toString(16)}` as T;
    if (method === 'eth_call' && (params[0] as { data?: string }).data === hx(settle.request.data)) return '0x' as T;
    if (method === 'eth_estimateGas') return '0x1d4c0' as T;
    if (method === 'eth_sendRawTransaction') { state.offered.push(params[0] as string); return hx(settle.hash) as T; }
    return rpc.call<T>(method, params);
  } };
  const holder = await open('holder', rolled);
  assert.deepEqual(await resumePayout(holder, rec, caps, false), { state: 'pending', txHash: settle.hash });
  const seen = await holder.returnRecord('coin');
  assert.equal(seen.paidProof?.txHash, hx(settle.hash));
  assert.ok(seen.paidProof?.block, 'the block the packet paid in is remembered');
  state.rollback = true;
  for (let i = 0; i < 5; i++) await chain.mine([]);
  assert.equal((await resumePayout(await open('holder', rolled), rec, caps, false)).state, 'pending');
  assert.deepEqual(state.offered, [], 'near the head nothing is offered again');
  for (let i = 5; i < 20; i++) await chain.mine([]);
  const late = await resumePayout(await open('holder', rolled), rec, caps, false);
  assert.notEqual(late.state, 'vanished', 'the wallet\'s own packet is never another party\'s payment');
  assert.equal(late.state, 'pending');
  assert.ok(state.offered.length >= 1 && state.offered.every((sent) => sent === hx(raw)), 'only the identical settle bytes');
  assert.equal((await holder.returnRecord('coin')).paidProof, undefined);
  state.rollback = false; // it lands again (the original block is still the fake chain's)
  assert.equal((await resumePayout(await open('holder', rolled), rec, caps, false)).state, 'paid');
});

test('a mined Paid proof component is needs-archive only on the node\'s own answer, and works with split readers', async (t) => {
  for (const route of ['ordinary', 'recovery'] as const) {
    await t.test(route, async (t) => {
      const { w, chain, dir, cfg, deployment, open, rpc } = await setup(t, route === 'ordinary');
      await burn(w, 'coin', undefined, undefined, caps);
      const rec = await w.returnRecord('coin');
      if (route === 'recovery') {
        const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!),
          new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
        const complete = await session.run(0, 2, w.trust);
        const verdict = await verifyReturn(chain.gamma, evidenceOf(unhex(rec.burned!)), w.trust, TEST_PARAMS);
        chain.coldCall = async (vault, to) => {
          if (eq(to, deployment.recovery)) return [{ address: to, topics: complete.event.topics, data: complete.event.data }];
          if (!eq(to, cfg.vault)) return undefined;
          vault.redeem(verdict.eta, 0n, new Uint8Array(), { ret: verdictAbi(verdict) });
          return [];
        };
        assert.equal((await recoverStep(w, rec, caps)).state, 'checkpoint');
      }
      const backup = join(dir, 'before-payout.json');
      await publishReturnBackup(w, rec, backup);
      let raw!: Uint8Array;
      const interrupted: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
        if (method === 'eth_sendRawTransaction') {
          raw = unhex(params[0] as string);
          throw new Error('offline after signing payout');
        }
        return rpc.call<T>(method, params);
      } };
      await assert.rejects(resumePayout(await open('holder', interrupted), rec, caps, route === 'ordinary'), /offline after signing payout/);
      const tx = decodeSignedTx(raw).hash;
      await chain.mine([raw]);
      await chain.mine([]);
      const receipt = (await w.bridge.evm.receipt(tx))!;
      const childNumber = `0x${(BigInt(receipt.blockNumber) + 1n).toString(16)}`;
      const child = await rpc.call<{ hash: string }>('eth_getBlockByNumber', [childNumber, false]);
      // hard: a pruned answer (needs-archive at once); deep: a missing child or companion, pending until the head is
      // CERTIFICATION_DEPTH past it; neither: a missing receipt proves nothing (pending)
      const kinds = [
        { name: 'transaction receipt', method: 'eth_getTransactionReceipt', arg: hx(tx), hard: false, deep: false },
        { name: 'block header', method: 'eth_getBlockByHash', arg: receipt.blockHash, hard: true, deep: false },
        { name: 'child header', method: 'eth_getBlockByNumber', arg: childNumber, hard: false, deep: true },
        { name: 'seal companion', method: 'unicity_getSealCompanionV1', arg: child.hash, hard: false, deep: true },
        { name: 'block receipts', method: 'eth_getBlockReceipts', arg: receipt.blockHash, hard: true, deep: false },
      ];
      let settled = false;
      for (const kind of kinds) {
        await t.test(kind.name, async (t) => {
          const name = kind.method;
          cpSync(w.dir, join(dir, name), { recursive: true });
          const matches = (method: string, params: unknown[]) => method === kind.method && params[0] === kind.arg;
          const absent: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
            if (matches(method, params)) {
              if (kind.method === 'eth_getBlockReceipts') return Promise.reject(new RpcError(413, 0, 'answer too large'));
              if (kind.method === 'eth_getBlockByHash') return Promise.reject(new RpcError(200, -32000, 'unknown block'));
              return Promise.resolve(null as T);
            }
            if (method === 'eth_sendRawTransaction') throw new Error('must reconcile before sending');
            return rpc.call<T>(method, params);
          } };
          const reopened = () => open(name, absent, { seed: key('holder') });
          const strip = (r: unknown) => { const { missing: _m, ...rest } = r as { missing?: string }; return rest; };
          for (let i = 0; i < 4; i++) {
            const rejoined = await reopened();
            const expected = kind.hard || kind.deep && settled ? 'needs-archive' : 'pending';
            assert.deepEqual(strip(await resumePayout(rejoined, rec, caps, route === 'ordinary')), { state: expected, txHash: tx });
            assert.equal((await rejoined.returnRecord('coin')).paidProof?.reads, Math.min(i + 1, 3));
          }
          if (kind.deep && !settled) {
            for (let i = 0n; i < CERTIFICATION_DEPTH; i++) await chain.mine([]);
            settled = true;
            assert.equal((await resumePayout(await reopened(), rec, caps, route === 'ordinary')).state, 'needs-archive');
          }
          if (kind.hard || kind.deep) await assert.rejects(restoreReturn(await reopened(), backup), /needs archive/);
          let componentReads = 0;
          const partial = await partialProofReader(t, async (method, params) => {
            if (!matches(method, params)) return null;
            componentReads++;
            return rpc.call(method, params);
          });
          const holder = await reopened();
          assert.equal((await resumePayout(holder, rec, partial.policy, route === 'ordinary')).state, 'paid');
          assert.ok(componentReads > 0);
          assert.equal((await holder.returnRecord('coin')).paid!.txHash, hx(tx));
          assert.equal((await holder.returnRecord('coin')).paidProof, undefined);
        });
      }
    });
  }
});

test('exact failed sends can combine a retained header with a body-only or raw-only reader', async (t) => {
  const { w, cfg, chain, dir, open, rpc } = await setup(t, true);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  chain.coldCall = async (_vault, to) => {
    if (eq(to, cfg.vault)) throw new Nb2Error('PayoutFailed');
    return undefined;
  };
  let signed!: Uint8Array;
  const interrupted: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_estimateGas') return Promise.resolve('0x1d4c0' as T);
    if (method === 'eth_sendRawTransaction') {
      signed = unhex(params[0] as string);
      throw new Error('offline after signing');
    }
    return rpc.call<T>(method, params);
  } };
  await assert.rejects(resumePayout(await open('holder', interrupted), rec, caps, true), /offline after signing/);
  const hash = decodeSignedTx(signed).hash;
  await chain.mine([signed]);
  await chain.mine([]);
  const receipt = (await w.bridge.evm.receipt(hash))!;
  for (const method of ['eth_getBlockByHash', 'eth_getRawTransactionByBlockHashAndIndex']) {
    await t.test(method, async (t) => {
      cpSync(w.dir, join(dir, method), { recursive: true });
      const matches = (query: string, params: unknown[]) => query === method && params[0] === receipt.blockHash;
      const primary: JsonRpc = { call: async <T>(query: string, params: unknown[]): Promise<T> => {
        if (!matches(query, params)) return rpc.call<T>(query, params);
        if (method !== 'eth_getBlockByHash') return null as T;
        const { transactions: _body, ...header } = await rpc.call<Record<string, unknown>>(query, params);
        return header as T;
      } };
      const holder = await open(method, primary, { seed: key('holder') });
      const archived = (await reconcileReturn(holder, rec, caps)).result;
      assert.deepEqual({ state: archived.state, txHash: 'txHash' in archived ? archived.txHash : undefined }, { state: 'needs-archive', txHash: hash });
      assert.ok(archived.state === 'needs-archive' && archived.missing, 'names the missing component');
      const partial = await partialProofReader(t, async (query, params) => {
        if (!matches(query, params)) return null;
        const value = await rpc.call(query, params);
        return method === 'eth_getBlockByHash' ? { transactions: (value as { transactions: string[] }).transactions } : value;
      });
      assert.equal((await reconcileReturn(holder, rec, partial.policy)).result.state, 'not-paid');
      assert.ok((await holder.returnRecord('coin')).sends.at(-1)!.failed);
      assert.ok(partial.requests() > 0);
    });
  }
});

async function pendingPeerSettlement(t: TestContext) {
  const world = await setup(t);
  const { w, chain, dir, cfg, deployment, open } = world;
  const signing = join(dir, 'one-payer-signing.json');
  await burn(w, 'coin', undefined, undefined, caps, signing);
  const rec = await w.returnRecord('coin');
  const relay = await open('settlement-peer');
  chain.fund(relay.signer.address, 10n ** 18n);
  const remote = await restoreReturn(relay, signing, caps);
  const session = await RecoverySession.create(chain.gamma, unhex(rec.burned!),
    new RecoveryAuthority(w.trust, async () => undefined), TEST_PARAMS, deployment);
  const packet = await session.run(0, 2, w.trust);
  const verdict = await verifyReturn(chain.gamma, evidenceOf(unhex(rec.burned!)), w.trust, TEST_PARAMS);
  chain.coldCall = async (vault, to, data) => {
    if (eq(to, deployment.recovery)) return [{ address: to, topics: packet.event.topics, data: packet.event.data }];
    if (eq(to, cfg.vault) && hx(data.subarray(0, 4)) === selector('redeemRecovered(bytes)')) {
      vault.redeem(verdict.eta, 0n, new Uint8Array(), { ret: verdictAbi(verdict) });
      return [];
    }
    return undefined;
  };
  assert.equal((await recoverStep(relay, remote, caps)).state, 'checkpoint');
  chain.autoMine = false;
  const other = await recoverStep(relay, remote, caps);
  assert.equal(other.state, 'pending');
  return { ...world, relay, remote, other };
}

test('a visible peer settlement stops both routes before signing, and hidden concurrent sends pay once', async (t) => {
  const { w, chain, dir, open, rpc, relay, remote, other } = await pendingPeerSettlement(t);
  const active = join(dir, 'peer-active.json');
  await publishReturnBackup(relay, remote, active);
  const held = await restoreReturn(w, active);
  const saved = () => JSON.parse(readFileSync(join(w.dir, `recovery-${held.returnId.slice(2)}.json`), 'utf8'));
  assert.ok(saved().complete);
  assert.equal(saved().pending, undefined);
  for (const ordinary of [false, true]) {
    assert.deepEqual(await resumePayout(w, held, caps, ordinary), { state: 'pending', txHash: other.txHash });
    assert.equal(saved().pending, undefined);
    assert.equal((await w.returnRecord('coin')).executionPayer, undefined);
    assert.deepEqual((await w.returnRecord('coin')).sends, []);
  }

  // Another gateway can keep its mempool private. This check cannot coordinate the two payers.
  const hidden: JsonRpc = { call: async <T>(method: string, params: unknown[]) => {
    if (method === 'eth_getBlockByNumber' && params[0] === 'pending') return null as T;
    const result = await rpc.call<T>(method, params);
    if (method === 'eth_sendRawTransaction') await chain.flush();
    return result;
  } };
  const holder = await open('holder', hidden);
  assert.equal((await resumePayout(holder, held, caps, true)).state, 'paid');
  const ordinary = (await holder.returnRecord('coin')).sends.at(-1)!;
  const duplicate = decodeSignedTx(unhex(ordinary.raw));
  assert.notDeepEqual(duplicate.hash, other.txHash);
  assert.deepEqual(duplicate.from, holder.signer.address);
  assert.equal(BigInt((await holder.bridge.evm.receipt(duplicate.hash))!.status), 0n);
  assert.equal(chain.vault.events.filter((event) => event.name === 'Paid').length, 1);
  const reconciled = (await reconcileReturn(holder, held, caps)).result;
  assert.equal(reconciled.state, 'paid');
  assert.deepEqual(reconciled.txHash, other.txHash);
});

test('a certified exact failure retires a stale remembered Paid hint on reconcile and restore', async (t) => {
  const { w, chain, cfg, dir, open, rpc, rpcOn } = await setup(t, true);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const original = join(dir, 'before-fork-payment.json');
  await publishReturnBackup(w, rec, original);
  let raw!: Uint8Array;
  const interrupted: JsonRpc = { call: <T>(method: string, params: unknown[]) => {
    if (method === 'eth_sendRawTransaction') {
      raw = unhex(params[0] as string);
      throw new Error('after journal before send');
    }
    return rpc.call<T>(method, params);
  } };
  await assert.rejects(resumePayout(await open('holder', interrupted), rec, caps, true), /after journal before send/);
  const tx = decodeSignedTx(raw).hash;
  const successful = chain.fork();
  await successful.mine([raw]); // Receipt and log appear, but no child has certified them.
  const speculative = await open('holder', rpcOn(successful));
  assert.deepEqual((await reconcileReturn(speculative, rec, caps, undefined, false)).result, { state: 'pending', txHash: tx });
  assert.equal((await speculative.returnRecord('coin')).paidProof?.reads, 1);
  cpSync(w.dir, join(dir, 'restore-failed-branch'), { recursive: true });

  chain.coldCall = async (_vault, to) => {
    if (eq(to, cfg.vault)) throw new Nb2Error('PayoutFailed');
    return undefined;
  };
  await chain.mine([raw]);
  await chain.mine([]);
  const failed = await open('holder', rpc);
  assert.equal((await reconcileReturn(failed, rec, caps, undefined, false)).result.state, 'not-paid');
  assert.equal((await failed.returnRecord('coin')).paidProof, undefined);
  assert.equal((await failed.returnRecord('coin')).sends.at(-1)!.failed?.txHash, hx(tx));
  const restored = await open('restore-failed-branch', rpc, { seed: key('holder') });
  const recovered = await restoreReturn(restored, original);
  assert.equal(recovered.paidProof, undefined);
  assert.equal(recovered.sends.at(-1)!.failed?.txHash, hx(tx));
  assert.equal((await reconcileReturn(restored, recovered, caps)).result.state, 'not-paid');
});

test('Paid tries every eligible child header with every available companion source', async (t) => {
  const { w, chain, dir, open, rpc } = await setup(t, true);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  const backup = join(dir, 'child-branch.json');
  await publishReturnBackup(w, rec, backup);
  const relay = await open('child-branch-payer');
  chain.fund(relay.signer.address, 10n ** 18n);
  await restoreReturn(relay, backup);
  const paid = await resumePayout(relay, rec, caps, true);
  assert.equal(paid.state, 'paid');
  const childNumber = `0x${(paid.blockNumber + 1n).toString(16)}`;
  const child = await rpc.call<{ hash: string }>('eth_getBlockByNumber', [childNumber, false]);
  const asked = new Set<string>();
  const partial = await partialProofReader(t, async (method, params) => {
    if (method === 'eth_getBlockByNumber' && params[0] === childNumber) return child;
    if (method !== 'unicity_getSealCompanionV1') return null;
    asked.add(String(params[0]));
    if (params[0] === child.hash) return rpc.call(method, params);
    return { status: 'unknown' };
  });
  // The primary's child has the correct parent but a different hash and no companion.
  const primary: JsonRpc = { call: async <T>(method: string, params: unknown[]) => {
    if (method === 'eth_getBlockByNumber' && params[0] === childNumber) return { ...child, extraData: '0x99' } as T;
    if (method === 'unicity_getSealCompanionV1') return { status: 'unknown' } as T;
    return rpc.call<T>(method, params);
  } };
  const holder = await open('holder', primary);
  assert.equal((await restoreReturn(holder, backup, partial.policy)).status, 'paid');
  assert.ok(asked.has(child.hash));
  assert.equal(asked.size, 2, 'the archive saw both child candidates');
});

test('all pending settlement candidates are checked for certified Paid regardless of order', async (t) => {
  const { w, chain, dir, open, rpc, other } = await pendingPeerSettlement(t);
  const pooled = await rpc.call<{ transactions: { hash: string; input: string; to: string }[] }>('eth_getBlockByNumber', ['pending', true]);
  const winner = pooled.transactions[0];
  assert.equal(winner.hash, hx(other.txHash));
  const unresolved = { ...winner, hash: hx(key('unresolved settlement')) };
  await chain.flush();
  const archive = await partialProofReader(t, async (method, params) => method === 'eth_getLogs' ? [] : rpc.call(method, params));
  for (const transactions of [[unresolved, winner], [winner, unresolved]]) {
    const name = `candidate-${transactions[0].hash.slice(2)}`;
    cpSync(w.dir, join(dir, name), { recursive: true });
    const primary: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
      if (method === 'eth_getBlockByNumber' && params[0] === 'pending') return Promise.resolve({ transactions } as T);
      if (method === 'eth_getLogs') return Promise.resolve([] as T);
      if (method === 'eth_getTransactionReceipt') return Promise.resolve(null as T);
      if (method === 'eth_sendRawTransaction') throw new Error('must reconcile certified Paid before signing');
      return rpc.call<T>(method, params);
    } };
    const holder = await open(name, primary, { seed: key('holder') });
    const result = await redeem(holder, 'coin', 0, 0, undefined, undefined, archive.policy);
    assert.equal(result.state, 'paid');
    assert.deepEqual(result.txHash, other.txHash);
    assert.deepEqual((await holder.returnRecord('coin')).sends, []);
  }
});

test('ordinary redeem polls the peer hash while pending and after it leaves the pending block', async (t) => {
  const { w, chain, open, rpc, other } = await pendingPeerSettlement(t);
  const pending = await redeem(w, 'coin', 1, 0, undefined, undefined, caps);
  assert.deepEqual(pending, { state: 'pending', txHash: other.txHash });

  let pendingReads = 0;
  const transport: JsonRpc = { call: async <T>(method: string, params: unknown[]) => {
    if (method === 'eth_getLogs') return [] as T;
    if (method === 'eth_getBlockByNumber' && params[0] === 'pending' && ++pendingReads === 2) await chain.flush();
    if (method === 'eth_sendRawTransaction') throw new Error('polling must not sign a new settlement');
    return rpc.call<T>(method, params);
  } };
  const holder = await open('holder', transport);
  const paid = await redeem(holder, 'coin', 1, 0, undefined, undefined, caps);
  assert.equal(paid.state, 'paid');
  assert.deepEqual(paid.txHash, other.txHash);
  assert.deepEqual((await holder.returnRecord('coin')).sends, []);
});

test('unrelated pending transactions do not consume the vault scan limit', async (t) => {
  const { open, rpc, other } = await pendingPeerSettlement(t);
  const transport: JsonRpc = { call: async <T>(method: string, params: unknown[]) => {
    if (method === 'eth_getBlockByNumber' && params[0] === 'pending') {
      const pending = await rpc.call<{ transactions: object[] }>(method, params);
      const unrelated = { to: hx(key('unrelated destination').slice(0, 20)), input: '0x', hash: hx(key('unrelated tx')) };
      return { transactions: [...Array(1024).fill(unrelated), ...pending.transactions] } as T;
    }
    if (method === 'eth_sendRawTransaction') throw new Error('the vault call is visible after unrelated traffic');
    return rpc.call<T>(method, params);
  } };
  const holder = await open('holder', transport);
  assert.deepEqual(await redeem(holder, 'coin', 0, 0, undefined, undefined, caps), { state: 'pending', txHash: other.txHash });
  assert.deepEqual((await holder.returnRecord('coin')).sends, []);
});

test('ordinary redeem recognizes pending recovery with the pinned emitter and no payer policy', async (t) => {
  const { open, rpc, other } = await pendingPeerSettlement(t);
  const holder = await open('holder', { call: <T>(method: string, params: unknown[]) => {
    if (method === 'eth_sendRawTransaction') throw new Error('the visible recovery call must defer signing');
    return rpc.call<T>(method, params);
  } });
  assert.deepEqual(await redeem(holder, 'coin', 0), { state: 'pending', txHash: other.txHash });
  assert.deepEqual((await holder.returnRecord('coin')).sends, []);
});

test('ordinary submission preserves another SDK instance’s durable send at the same payer nonce', async (t) => {
  const { w, open, rpc } = await setup(t, true);
  await burn(w, 'coin', undefined, undefined, caps);
  const { returnId } = await w.returnRecord('coin');
  const id = unhex(returnId);
  let durable!: string;
  const second = await open('holder', { call: <T>(method: string, params: unknown[]) => {
    if (method === 'eth_maxPriorityFeePerGas') return Promise.resolve('0x2' as T);
    if (method === 'eth_sendRawTransaction') {
      durable = params[0] as string;
      throw new Error('second SDK stopped before broadcast');
    }
    return rpc.call<T>(method, params);
  } });
  let competed = false;
  const first = await open('holder', { call: async <T>(method: string, params: unknown[]) => {
    if (method === 'eth_getBlockByNumber' && params[0] === 'pending' && !competed) {
      competed = true;
      await assert.rejects(second.bridge.submitRedeem(id, second.signer), /second SDK stopped before broadcast/);
      assert.equal((await second.returnRecord('coin')).sends[0].raw, durable);
    }
    if (method === 'eth_sendRawTransaction') throw new Error('conflicting send must not broadcast');
    return rpc.call<T>(method, params);
  } });
  await assert.rejects(first.bridge.submitRedeem(id, first.signer, { admit: async (request) => {
    const competing = decodeSignedTx(unhex(durable));
    assert.deepEqual(competing.from, first.signer.address);
    assert.equal(competing.request.nonce, request.nonce);
    assert.notEqual(competing.request.maxPriorityFeePerGas, request.maxPriorityFeePerGas);
  } }), (err: unknown) => err instanceof WalletError && err.reason === 'JournalConflict');
  assert.deepEqual((await first.returnRecord('coin')).sends.map((send) => send.raw), [durable]);
});

test('ordinary and recovery resume prefer a certified pending candidate over a saved payment hint', async (t) => {
  const { w, chain, cfg, rpc, rpcOn, open, dir, other } = await pendingPeerSettlement(t);
  const rec = await w.returnRecord('coin');
  assert.ok(rec.recovery);
  const pool = await rpc.call<{ transactions: { hash: string; input: string; to: string }[] }>('eth_getBlockByNumber', ['pending', true]);
  assert.equal(pool.transactions[0].hash, hx(other.txHash));
  const fork = chain.fork();
  fork.coldCall = chain.coldCall;
  const hint = await signTx(w.signer, { chainId: cfg.chainId, nonce: await w.bridge.evm.nonce(w.signer.address),
    maxFeePerGas: 23n, maxPriorityFeePerGas: 1n, gas: 2_000_000n, to: cfg.vault, value: 0n, data: unhex(pool.transactions[0].input) });
  await fork.mine([hint.raw]); // The payment receipt exists but has no certifying child.
  const speculative = await open('holder', rpcOn(fork));
  assert.deepEqual((await reconcileReturn(speculative, rec, caps, undefined, false)).result, { state: 'pending', txHash: hint.hash });
  assert.equal((await speculative.returnRecord('coin')).paidProof?.txHash, hx(hint.hash));
  await chain.flush();
  const certified: JsonRpc = { call: <T>(method: string, params: unknown[]) => {
    if (method === 'eth_getLogs') return Promise.resolve([] as T);
    if (method === 'eth_getBlockByNumber' && params[0] === 'pending') return Promise.resolve(pool as T);
    if (method === 'eth_sendRawTransaction') throw new Error('certified Paid must close the return before a send');
    return rpc.call<T>(method, params);
  } };
  for (const ordinary of [true, false]) {
    if (!ordinary) {
      // a receipt whose block has no certifying child yet is a wait, however often it is read (the demo's needs-archive of 2026-11-26)
      await reconcileReturn(speculative, rec, caps, undefined, false);
      assert.equal((await reconcileReturn(speculative, rec, caps, undefined, false)).result.state, 'pending');
    }
    const name = ordinary ? 'ordinary-hint' : 'recovery-hint';
    cpSync(w.dir, join(dir, name), { recursive: true });
    const resumed = await open(name, certified, { seed: key('holder') });
    const result = await resumePayout(resumed, rec, caps, ordinary);
    assert.equal(result.state, 'paid');
    assert.deepEqual(result.txHash, other.txHash);
    const row = await resumed.returnRecord('coin');
    assert.equal(row.paidProof, undefined);
    assert.deepEqual(row.sends, []);
  }
});

test('ordinary redeem refuses a planned return with NotPending before looking for settlements', async (t) => {
  const { w, open, rpc } = await setup(t, true);
  await planReturn(w, 'coin', undefined, undefined, caps);
  let pendingReads = 0;
  const holder = await open('holder', { call: <T>(method: string, params: unknown[]) => {
    if (method === 'eth_getBlockByNumber' && params[0] === 'pending') pendingReads++;
    if (method === 'eth_sendRawTransaction') throw new Error('a planned return must not broadcast');
    return rpc.call<T>(method, params);
  } });
  await assert.rejects(redeem(holder, 'coin', 0), (err: unknown) => err instanceof WalletError && err.reason === 'NotPending');
  assert.equal(pendingReads, 0);
  assert.equal((await holder.returnRecord('coin')).status, 'planned');
});

test('a 429 on the priority fee surfaces as a retryable RPC error, never as a preflight verdict', async (t) => {
  const { open, rpc } = await setup(t, true);
  const fail = { on: false };
  const limited: JsonRpc = { call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (fail.on && method === 'eth_maxPriorityFeePerGas') throw new RpcError(429, 0, 'rate limited');
    return rpc.call<T>(method, params);
  } };
  const w = await open('holder', limited);
  fail.on = true;
  await assert.rejects(planReturn(w, 'coin', undefined, undefined, caps), (e: unknown) =>
    e instanceof RpcError && e.status === 429 && e.retryable && !(e instanceof Nb2Error));
  assert.equal(w.entry('coin').spent, undefined);
  fail.on = false;
  assert.equal((await planReturn(w, 'coin', undefined, undefined, caps)).record.recovery, undefined);
});

test('a missing payer policy is PolicyRequired, distinct from exceeded limits', async (t) => {
  const { w } = await setup(t, true);
  await assert.rejects(planReturn(w, 'coin', undefined, undefined, undefined), (e: unknown) =>
    e instanceof WalletError && e.reason === 'PolicyRequired' && /payer limits are required/.test(e.message));
  await assert.rejects(burn(w, 'coin', undefined, undefined, { ...caps, gas: 1n }), { rule: 'CapacityPreflight' });
});

test('readRetrying waits out 429/503 on reads and never repeats a send', async () => {
  const calls: string[] = [];
  let busy = 2;
  const inner: JsonRpc = { call: async <T>(method: string): Promise<T> => {
    calls.push(method);
    if (method === 'eth_estimateGas' && busy-- > 0) throw new RpcError(429, 0, 'rate limit');
    if (method === 'eth_getTransactionReceipt' && calls.filter((m) => m === method).length === 1) throw new RpcError(503, 0, 'RPC unavailable');
    if (method === 'eth_sendRawTransaction') throw new RpcError(503, 0, 'No transaction acknowledgement');
    if (method === 'eth_call') throw new RpcError(200, 3, 'execution reverted');
    return '0x1' as T;
  } };
  const sleeps: number[] = [];
  const rpc = readRetrying(inner, undefined, { sleep: async (ms) => { sleeps.push(ms); }, random: () => 0 });
  assert.equal(await rpc.call('eth_estimateGas', [{}]), '0x1');
  assert.equal(await rpc.call('eth_getTransactionReceipt', ['0x00']), '0x1');
  await assert.rejects(rpc.call('eth_sendRawTransaction', ['0x00']), (e: unknown) => e instanceof RpcError && e.status === 503);
  await assert.rejects(rpc.call('eth_call', [{}, 'latest']), (e: unknown) => e instanceof RpcError && e.code === 3);
  assert.deepEqual(calls, ['eth_estimateGas', 'eth_estimateGas', 'eth_estimateGas', 'eth_getTransactionReceipt', 'eth_getTransactionReceipt',
    'eth_sendRawTransaction', 'eth_call'], 'reads repeat until answered; a send and a refusal are tried once');
  assert.equal(sleeps.length, 3);
});

test('a recovery archive reader rate-limited (HTTP 429) on the payout receipt is waited out, not thrown', async (t) => {
  const { createServer } = await import('node:http');
  const { w, chain, open, rpc } = await setup(t, true);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  let raw!: Uint8Array;
  const interrupted: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_sendRawTransaction') {
      raw = unhex(params[0] as string);
      throw new Error('offline after signing payout');
    }
    return rpc.call<T>(method, params);
  } };
  await assert.rejects(resumePayout(await open('holder', interrupted), rec, caps, true), /offline after signing payout/);
  await chain.mine([raw]);
  await chain.mine([]);
  // the gateway's per-client limit: the archive's first receipt reads answer HTTP 429, more often than the transport retries itself
  let limited = 4;
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk);
    const { id, method, params } = JSON.parse(Buffer.concat(chunks).toString());
    if (method === 'eth_getTransactionReceipt' && limited-- > 0) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '0' }).end(JSON.stringify({ error: 'rate limit' }));
      return;
    }
    try {
      res.end(JSON.stringify({ jsonrpc: '2.0', id, result: await rpc.call(method, params) }));
    } catch (e) {
      res.end(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message: String(e) } }));
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const archive = { ...caps, archives: [`http://127.0.0.1:${(server.address() as { port: number }).port}`] };
  // the primary has no receipts: only the archive can prove the payout
  const primary: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> =>
    method === 'eth_getTransactionReceipt' ? Promise.reject(new Error('no receipts here')) : rpc.call<T>(method, params) };
  const holder = await open('holder', primary);
  const { result } = await reconcileReturn(holder, rec, archive);
  assert.equal(result.state, 'paid');
  assert.ok(limited < 0, 'the archive was rate-limited and then answered');
});

test('a 429 burst on the mined Paid proof read propagates and never counts toward needs-archive', async (t) => {
  const { w, chain, open, rpc } = await setup(t, true);
  await burn(w, 'coin', undefined, undefined, caps);
  const rec = await w.returnRecord('coin');
  let raw!: Uint8Array;
  const interrupted: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_sendRawTransaction') {
      raw = unhex(params[0] as string);
      throw new Error('offline after signing payout');
    }
    return rpc.call<T>(method, params);
  } };
  await assert.rejects(resumePayout(await open('holder', interrupted), rec, caps, true), /offline after signing payout/);
  const tx = decodeSignedTx(raw).hash;
  await chain.mine([raw]);
  await chain.mine([]);
  const receipt = (await w.bridge.evm.receipt(tx))!;
  let limited = true;
  const burst: JsonRpc = { call: <T>(method: string, params: unknown[]): Promise<T> => {
    if (limited && method === 'eth_getBlockByHash' && params[0] === receipt.blockHash) return Promise.reject(new RpcError(429, 0, 'rate limit'));
    return rpc.call<T>(method, params);
  } };
  const holder = await open('holder', burst);
  for (let i = 0; i < 4; i++) {
    await assert.rejects(resumePayout(holder, rec, caps, true), (e: unknown) => e instanceof RpcError && e.retryable);
  }
  limited = false;
  const result = await resumePayout(holder, rec, caps, true);
  assert.notEqual(result.state, 'needs-archive');
});

test('transportRetry waits out a burst with backoff, fails fast on other errors, and gives up after its budget', async () => {
  const sleeps: number[] = [];
  const opts = { sleep: async (ms: number) => { sleeps.push(ms); }, random: () => 0 };
  let n = 0;
  assert.equal(await transportRetry(async () => {
    if (n++ < 3) throw new RpcError(429, 0, 'rate limit');
    return 'ok';
  }, undefined, opts), 'ok');
  assert.deepEqual(sleeps, [1000, 2000, 4000]);

  let calls = 0;
  await assert.rejects(transportRetry(async () => { calls++; throw new RpcError(200, -32000, 'execution reverted'); }, undefined, opts), RpcError);
  await assert.rejects(transportRetry(async () => { calls++; throw new Nb2Error('CapacityPreflight', 'x'); }, undefined, opts), Nb2Error);
  assert.equal(calls, 2);

  sleeps.length = 0;
  calls = 0;
  await assert.rejects(transportRetry(async () => { calls++; throw new RpcError(503, 0, 'busy'); }, undefined, { ...opts, random: () => 1 }),
    (e: unknown) => e instanceof RpcError && e.retryable);
  assert.ok(sleeps.reduce((a, b) => a + b, 0) <= 100_000 && sleeps.length >= 5 && calls === sleeps.length + 1);
});

test('retry waits out a transport burst without spending its not-yet tries, and a polled burst is retried', async () => {
  let n = 0;
  const out = await retry(async () => {
    n++;
    if (n === 1) throw new RpcError(0, 0, 'fetch failed');
    return 'done';
  }, undefined, 0, 1);
  assert.equal(out, 'done');
});
