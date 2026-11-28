import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { test } from 'node:test';
import { gunzipSync } from 'node:zlib';
import type { RecoveryCalibrationRange, RecoveryBacklog } from '../../src/nb2/recovery-cost.js';
import { concat, fromHex } from '../../src/bytes.js';
import { decodeConfig, decodeDepositProof, verifyReceiptLog, Nb2Error, PRODUCTION_PARAMS, RecoveryAuthority, RecoverySession, TrustInput, WalletError } from '../../src/nb2/index.js';

const fixtures = new URL('../../../../protocol/vectors/nb2-continuation-v1.1/', import.meta.url);
const read = (file: string) => readFile(new URL(file, fixtures));
function calibrationRanges(maxAdvance = 1024): RecoveryCalibrationRange[] {
  const range = (entry: RecoveryCalibrationRange['max']['entry'], operations: number, gaps: number): RecoveryCalibrationRange => ({
    minReceiptBytes: entry === 'run' ? 0 : 1,
    max: { entry, operations, gaps, receiptBytes: 65_536, calldataBytes: 393_216, pages: 32, openingBytes: 393_216 },
    execution: 1_000_000n + BigInt(operations) * 500_000n + BigInt(gaps) * 7000n,
  });
  return [
    ...Array.from({ length: 16 }, (_, i) => range('run', i + 1, 0)),
    ...Array.from({ length: maxAdvance }, (_, i) => range('advanceGaps', 0, i + 1)),
    ...Array.from({ length: 1024 }, (_, i) => range('redeemRecovered', 0, i)),
  ];
}

function trace(bytes: Buffer): Buffer[][] {
  const out: Buffer[][] = [];
  for (let p = 0; p < bytes.length;) {
    out.push(Array.from({ length: 6 }, () => {
      const size = bytes.readUInt32BE(p);
      p += 4;
      const field = bytes.subarray(p, p + size);
      p += size;
      return field;
    }));
  }
  return out;
}

function opCount(calldata: Buffer): number {
  const raw = calldata.subarray(68);
  const n = Number(raw.readBigUInt64BE(2));
  const depth = Math.ceil(Math.log2(Math.ceil(n / 4096)));
  const p = raw[42] === 0 ? 43 : 337 + raw.readUInt32BE(333);
  let i = p + 1;
  for (let j = 0; j < raw[p]; j++) {
    const index = Number(raw.readBigUInt64BE(i));
    i += 8 + Math.min(4096, n - index * 4096) + 32 * depth;
  }
  return raw[i];
}

for (const name of ['root', 'transfers', 'one-split', 'depth-20', 'shared-claim', 'alternate-certificate', 'transfers-600', 'capped-root', 'parent-over-32-pages', 'combined-large-receipt-and-paths']) {
  test(`recovery reproduces the prescribed ${name} packets and authenticated events`, async () => {
    const base = 'transcripts/' + name + '/';
    const [gamma, salt, pins, evidence, bundle, context, packed] = await Promise.all([
      read('gamma.bin'), read('generation-salt.bin'), read('pins.bin'), read(base + 'evidence.bin'), read(base + 'utb.cbor'),
      read(base + 'context.json'), read(base + 'trace.bin.gz'),
    ]);
    const c = JSON.parse(context.toString());
    const trust = (await TrustInput.fromBundle(bundle, decodeConfig(gamma, PRODUCTION_PARAMS).rootGenesis));
    const session = await RecoverySession.create(gamma, evidence, new RecoveryAuthority(trust, async () => {}), PRODUCTION_PARAMS, {
      salt, pins, recovery: fromHex(c.RecoveryAddress)!, runtimeHash: fromHex(c.RecoveryRuntimeHash)!,
    });
    assert.deepEqual(Buffer.from(session.id), Buffer.from(c.Session, 'hex'));
    assert.deepEqual(Buffer.from(session.pageRoot), Buffer.from(c.PageRoot, 'hex'));
    if (name === 'root') {
      const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
      const calibration = { pins, runtimeHash: fromHex(c.RecoveryRuntimeHash)!, ranges: calibrationRanges(0) };
      const limits = { signedBytes: 524_288, calldataBytes: 393_216, gas: 24_000_000n, chainId: cfg.chainId, maxNonce: 255n,
        maxFeePerGas: 10n, maxPriorityFeePerGas: 1n, balance: 10n ** 18n, feeBudget: 10n ** 18n };
      const whole = await session.run(0, 2, trust);
      const one = await session.run(0, 1, trust);
      assert.ok(whole.calldata.length > one.calldata.length);
      const planned = await session.runBounded(0, trust, calibration, { ...limits, calldataBytes: whole.calldata.length - 1 });
      assert.equal(planned.packet.end, 1);
      assert.deepEqual(planned.packet.calldata, one.calldata);
      await assert.rejects(session.runBounded(0, trust, calibration, { ...limits, calldataBytes: one.calldata.length - 1 }), { rule: 'CapacityPreflight' });
    }
    let from = 0;
    let prior: { seq: bigint; receipt: Uint8Array } | undefined;
    for (const [calldata, , state, topics, data, receipt] of trace(gunzipSync(packed))) {
      const expectedReceiptLength = prior?.receipt.length ?? 0;
      const input = prior && { ...prior };
      const building = session.run(from, opCount(calldata), trust, input);
      if (input) input.receipt = new Uint8Array();
      const result = await building;
      assert.equal(result.shape.receiptBytes, expectedReceiptLength);
      assert.deepEqual(Buffer.from(result.calldata), calldata);
      assert.deepEqual(Buffer.from(result.state ?? []), state);
      assert.deepEqual(Buffer.from(concat(...result.event.topics)), topics);
      assert.deepEqual(Buffer.from(result.event.data), data);
      await session.verifyEvent(trust, receipt, result.event);
      if (name === 'root') {
        const trimmed = await session.trimReceipt(trust, receipt, result.event);
        assert.ok(trimmed.encoded.length <= receipt.length);
        await session.verifyEvent(trust, trimmed.encoded, result.event);
      }
      from = result.end;
      prior = { seq: (prior?.seq ?? 0n) + 1n, receipt };
    }
    assert.equal(from, session.operationCount);
  });
}

test('recovery replays the production-verifier T1 supplement and rejects its invalid lineages', async () => {
  const root = new URL('../nb2-continuation-v1.1-supplement/', fixtures);
  const load = (file: string) => readFile(new URL(file, root));
  const gamma = await load('gamma.bin');
  const deployed = JSON.parse(String(await load('deployment.json')));
  const deployment = {
    salt: await load('generation-salt.bin'), pins: fromHex(deployed.Pins)!,
    recovery: fromHex(deployed.RecoveryAddress)!, runtimeHash: fromHex(deployed.RecoveryRuntimeHash)!,
  };
  const trust = (await TrustInput.fromBundle(await load('b1-rollover/utb.cbor'), decodeConfig(gamma, PRODUCTION_PARAMS).rootGenesis));
  const session = await RecoverySession.create(gamma, await load('b1-rollover/evidence.bin'), new RecoveryAuthority(trust, async () => {}), PRODUCTION_PARAMS, deployment);
  let from = 0;
  let prior: { seq: bigint; receipt: Uint8Array } | undefined;
  for (const [calldata, , state, topics, data, receipt] of trace(gunzipSync(await load('b1-rollover/trace.bin.gz')))) {
    const result = await session.run(from, opCount(calldata), trust, prior);
    assert.deepEqual(Buffer.from(result.calldata), calldata);
    assert.deepEqual(Buffer.from(result.state ?? []), state);
    assert.deepEqual(Buffer.from(concat(...result.event.topics)), topics);
    assert.deepEqual(Buffer.from(result.event.data), data);
    await session.verifyEvent(trust, receipt, result.event);
    from = result.end;
    prior = { seq: (prior?.seq ?? 0n) + 1n, receipt };
  }
  assert.equal(from, session.operationCount);
  for (const name of ['b1-rollover-refusals', 'cross-cut-conflict']) {
    const evidence = await load(name + '/evidence.bin');
    await assert.rejects(RecoverySession.create(gamma, evidence, new RecoveryAuthority(trust, async () => {}), PRODUCTION_PARAMS, deployment));
  }
});

test('cold recovery reproduces gap and settlement calls and switches proof sources', async () => {
  const gamma = await read('gamma.bin');
  const base = 'transcripts/root/';
  const context = JSON.parse(String(await read(base + 'context.json')));
  const recovery = fromHex(context.RecoveryAddress)!;
  const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
  const trust = (await TrustInput.fromBundle(await read(base + 'utb.cbor'), cfg.rootGenesis));
  const session = await RecoverySession.create(gamma, await read(base + 'evidence.bin'), new RecoveryAuthority(trust, async () => {}), PRODUCTION_PARAMS, {
    recovery, salt: await read('generation-salt.bin'), pins: await read('pins.bin'), runtimeHash: fromHex(context.RecoveryRuntimeHash)!,
  });
  for (const name of await readdir(new URL('transcripts/cold/', fixtures))) {
    const dir = 'transcripts/cold/' + name + '/';
    const calldata = await read(dir + 'calldata.bin');
    const body = calldata.subarray(68, 68 + Number(calldata.readBigUInt64BE(60)));
    const kind = body[42];
    const end = 47 + body.readUInt32BE(43);
    const receipt = body.subarray(47, end);
    const count = body.readUInt16BE(end);
    const gapStart = end + 2 + (kind === 1 && count > 0 ? 32 : 0);
    const width = count === 0 ? 0 : (body.length - gapStart) / count;
    const gaps = Array.from({ length: count }, (_, i) => body.subarray(gapStart + i * width, gapStart + (i + 1) * width));
    const log = await verifyReceiptLog(cfg, trust, decodeDepositProof(receipt), recovery);
    const data = Buffer.from(log.data);
    const prior = { seq: data.readBigUInt64BE(24), cursor: kind === 2 ? { next: data.readBigUInt64BE(248), head: data.subarray(256) } : undefined };
    const entry = name.startsWith('advance') ? 'advanceGaps' : 'redeemRecovered';
    const building = session.gaps(entry, trust, receipt, prior, gaps, gapStart === end + 2 ? undefined : body.subarray(end + 2, gapStart));
    if (kind === 2) prior.cursor = undefined;
    const packet = await building;
    assert.deepEqual(Buffer.from(packet.calldata), calldata, name);
    if (packet.event) {
      const outcome = JSON.parse(String(await read(dir + 'outcome.json')));
      assert.deepEqual(Buffer.from(packet.event.data), Buffer.from(outcome.Data, 'hex'));
      const pruned = async () => { throw new Nb2Error('EvidencePruned'); };
      const unknown = async () => { throw new WalletError('CompanionUnknown'); };
      await assert.rejects(session.acquire(trust, packet.event, [pruned]), { rule: 'EvidencePruned' });
      await assert.rejects(session.acquire(trust, packet.event, [pruned, unknown]), { reason: 'CompanionUnknown' });
      const acquired = await session.acquire(trust, packet.event, [pruned, async () => fromHex(outcome.Receipt)!]);
      assert.deepEqual(Buffer.from(acquired.receipt.encoded), Buffer.from(outcome.Receipt, 'hex'));
    }
  }
});

test('cold admission prices the terminal bound, reserve, signed envelope and refused neighbours', async () => {
  const { preflightRecovery, quoteRecovery } = await import('../../src/nb2/recovery-cost.js');
  const gamma = await read('gamma.bin');
  const base = 'transcripts/held-sibling-0/';
  const context = JSON.parse(String(await read(base + 'context.json')));
  const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
  const trust = (await TrustInput.fromBundle(await read(base + 'utb.cbor'), cfg.rootGenesis));
  const held = await read(base + 'evidence.bin');
  const deployment = {
    recovery: fromHex(context.RecoveryAddress)!, salt: await read('generation-salt.bin'),
    pins: await read('pins.bin'), runtimeHash: fromHex(context.RecoveryRuntimeHash)!, vaultRuntimeHash: new Uint8Array(32).fill(1),
  };
  const calibration = {
    pins: deployment.pins, runtimeHash: deployment.runtimeHash, vaultRuntimeHash: deployment.vaultRuntimeHash,
    ranges: calibrationRanges(),
  };
  const limits = {
    signedBytes: 524_288, calldataBytes: 393_216, gas: 24_000_000n, chainId: cfg.chainId, maxNonce: 255n,
    maxFeePerGas: 10n, maxPriorityFeePerGas: 1n, balance: 10n ** 18n, feeBudget: 10n ** 18n,
  };
  const backlog = { signedStart: 0n, observed: 2n, duringProgress: 3n, peakSeals: 1n, elapsedMs: 1000n, receiptP99Ms: 1000n, advancePeakSeals: 1n, finalInclusionMs: 25n, finalPeakSeals: 1n, qualifiedForMs: 200_000n };
  const call = (changes: Partial<typeof limits> = {}, progress: Partial<typeof backlog> = {}) =>
    preflightRecovery(gamma, held, trust, PRODUCTION_PARAMS, deployment, calibration, { ...limits, ...changes }, { ...backlog, ...progress });
  const plan = await call();
  assert.equal(plan.run.reduce((total, q) => total + q.shape.operations, 0), 4);
  assert.equal(plan.advance.quote.shape.gaps, 69);
  assert.equal(plan.advance.calls, 2n);
  assert.ok(plan.settle.signedBytes > plan.settle.shape.calldataBytes);
  assert.equal((await call({ feeBudget: plan.totalFee })).totalFee, plan.totalFee);
  await assert.rejects(call({ feeBudget: plan.totalFee - 1n }), { rule: 'CapacityPreflight' });
  await assert.rejects(call({}, { signedStart: 1n }), { rule: 'CapacityPreflight' });
  await assert.rejects(call({}, { peakSeals: 35n }), { rule: 'CapacityPreflight' });
  const max64 = { ...calibration, ranges: calibrationRanges(64) };
  const growing = { ...backlog, observed: 1024n, duringProgress: 0n, peakSeals: 32n, advancePeakSeals: 32n };
  const growingQuote = (changes = growing, budget = limits.feeBudget, model = max64) =>
    preflightRecovery(gamma, held, trust, PRODUCTION_PARAMS, deployment, model, { ...limits, feeBudget: budget }, changes);
  const extended = await growingQuote();
  assert.equal(extended.advance.calls, 34n);
  assert.equal(extended.settlementMaxGaps, 63);
  assert.equal(extended.settle.shape.gaps, 63);
  const originalSettlement = quoteRecovery({ ...extended.settle.shape, gaps: 0, calldataBytes: 65_668 }, max64, limits)!;
  const originalBudget = extended.run.reduce((sum, step) => sum + step.fee, 17n * extended.advance.quote.fee + originalSettlement.fee);
  await assert.rejects(growingQuote(growing, originalBudget), /insufficient recovery fee budget/);
  assert.equal((await growingQuote({ ...growing, qualifiedForMs: 34_025n })).advance.calls, 34n);
  await assert.rejects(growingQuote({ ...growing, qualifiedForMs: 34_024n }), /unqualified catch-up horizon/);
  const { qualifiedForMs: _, ...missingHorizon } = growing;
  await assert.rejects(growingQuote(missingHorizon as RecoveryBacklog), /unqualified backlog measurements/);
  await assert.rejects(growingQuote({ ...growing, finalPeakSeals: 2n }), /unqualified final inclusion window/);
  await assert.rejects(growingQuote({ ...growing, advancePeakSeals: 64n }), /insufficient certified catch-up rate/);
  const actual = { ...extended.advance.quote.shape, receiptBytes: 2073, calldataBytes: 20_000 };
  const narrow = { ...max64, ranges: max64.ranges.map((range) => range.max.entry === 'advanceGaps'
    ? { ...range, minReceiptBytes: 65_536 } : range) };
  assert.ok(quoteRecovery(extended.advance.quote.shape, narrow, limits));
  assert.equal(quoteRecovery(actual, narrow, limits), null);
  await assert.rejects(growingQuote(growing, limits.feeBudget, narrow), /indivisible gap operation/);
  assert.ok(quoteRecovery(actual, max64, limits)!.fee <= extended.advance.quote.fee);
  await assert.rejects(growingQuote({ ...growing, observed: (1n << 48n) - 66n }), /unqualified catch-up horizon/);
  await assert.rejects(growingQuote({ ...growing, observed: 0n, peakSeals: 0n, advancePeakSeals: 0n }, limits.feeBudget, {
    ...max64, ranges: max64.ranges.filter(({ max }) => max.entry !== 'advanceGaps' || max.gaps !== 1),
  }), /indivisible gap operation/);
  await assert.rejects(growingQuote(growing, limits.feeBudget, {
    ...max64, ranges: max64.ranges.filter(({ max }) => max.entry !== 'redeemRecovered' || max.gaps !== 1),
  }), /unqualified settlement suffix/);
  const quote = plan.settle;
  assert.ok(quoteRecovery(quote.shape, calibration, { ...limits, signedBytes: quote.signedBytes, gas: quote.gas }));
  assert.equal(quoteRecovery(quote.shape, calibration, { ...limits, gas: quote.gas - 1n }), null);
  assert.equal(quoteRecovery(quote.shape, calibration, { ...limits, maxTransactionFee: quote.fee - 1n }), null);
  assert.equal(quoteRecovery(quote.shape, calibration, { ...limits, signedBytes: quote.signedBytes - 1 }), null);
});

test('recovery RPC proves the parent with the canonical child companion and its technical record', async () => {
  const { EvmReader } = await import('../../src/nb2/rpc.js');
  const { toHex } = await import('../../src/bytes.js');
  const { setup } = await import('./world.js');
  const { chain } = await setup();
  const block = chain.blocks[0];
  const child = chain.blocks[1];
  const requested: unknown[][] = [];
  let wrongChild = false;
  let badRecord = false;
  const reader = new EvmReader({ call: async <T>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'eth_getBlockByNumber' && wrongChild) {
      return chain.call<T>(method, ['0x0', false]);
    }
    if (method === 'unicity_getSealCompanionV1') {
      requested.push(params);
      const result = await chain.call<{ companion: { witnesses: string[] } }>(method, params);
      if (badRecord) result.companion.witnesses[1] = '0x80';
      return result as T;
    }
    return chain.call<T>(method, params);
  } });
  assert.deepEqual(await reader.certificateOf(block.header, block.hash, true), block.uc);
  assert.deepEqual(requested, [['0x' + toHex(child.hash)]]);
  wrongChild = true;
  await assert.rejects(reader.certificateOf(block.header, block.hash, true), { reason: 'ProviderFault' });
  assert.equal(requested.length, 1);
  wrongChild = false;
  badRecord = true;
  await assert.rejects(reader.certificateOf(block.header, block.hash, true));
});

test('successor authority is persisted and prevents authority rollback across sessions', async () => {
  const { TrustBaseBundle } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseBundle.js');
  const base = 'transcripts/root/';
  const gamma = await read('gamma.bin');
  const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
  const evidence = await read(base + 'evidence.bin');
  const c = JSON.parse(String(await read(base + 'context.json')));
  const deployment = { salt: await read('generation-salt.bin'), pins: await read('pins.bin'),
    recovery: fromHex(c.RecoveryAddress)!, runtimeHash: fromHex(c.RecoveryRuntimeHash)! };
  const full = await TrustInput.fromBundle(await read(base + 'utb.cbor'), cfg.rootGenesis);
  const short = await TrustInput.fromBundle(await TrustBaseBundle.encode(full.history.entries.slice(0, 1)), cfg.rootGenesis);
  const previous = short;
  const current = full;
  let persisted = { bundle: await previous.history.toBundle() };
  let failStore = false;
  const guard = new RecoveryAuthority(previous, async (input) => {
    if (failStore) throw new Error('write failed');
    persisted = { bundle: await input.history.toBundle() };
  });
  const creating = RecoverySession.create(gamma, evidence, guard, PRODUCTION_PARAMS, deployment);
  gamma.fill(0); // Buffer input can be changed while verification is awaiting historical authority.
  const session = await creating;
  const { event } = await session.run(0, 2, previous);
  const [record] = trace(gunzipSync(await read(base + 'trace.bin.gz')));
  const proof = record[5];
  failStore = true;
  await assert.rejects(session.acquire(current, event, [async () => proof]), { reason: 'TrustInput' });
  failStore = false;
  await session.acquire(current, event, [async () => proof]);
  assert.deepEqual(persisted.bundle, await current.history.toBundle());
  for (const stale of [short]) {
    await assert.rejects(session.acquire(stale, event, [async () => proof]), { reason: 'TrustInput' });
  }
  const restored = (await TrustInput.fromBundle(persisted.bundle, current.id));
  const reopened = await RecoverySession.create(await read('gamma.bin'), evidence,
    new RecoveryAuthority(restored, async () => {}), PRODUCTION_PARAMS, deployment);
  await assert.rejects(reopened.run(0, 2, short), { reason: 'TrustInput' });
  await assert.rejects(reopened.verifyEvent(current, proof, { ...event, topics: [event.topics[0], new Uint8Array(32)] }), { reason: 'ProviderFault' });
  await reopened.verifyEvent(current, proof, event);
});

test('recovery RPC selects the later exact event by receipt-local index', async () => {
  const { EvmReader, recoveryRpcSource } = await import('../../src/nb2/rpc.js');
  const { toHex } = await import('../../src/bytes.js');
  const { setup } = await import('./world.js');
  const { chain } = await setup();
  const reader = new EvmReader(chain);
  const emitter = new Uint8Array(20).fill(1);
  const event = { kind: 'progress' as const, topics: [new Uint8Array(32).fill(2), new Uint8Array(32).fill(3)], data: Uint8Array.of(4) };
  const hex = (bytes: Uint8Array): string => '0x' + toHex(bytes);
  const block = chain.blocks[0];
  const hash = hex(block.hash);
  reader.receipt = async () => ({
    status: '0x1', cumulativeGasUsed: '0x1', logsBloom: '', blockHash: hash, blockNumber: '0x0', transactionIndex: '0x0', transactionHash: hash,
    logs: [
      { address: hex(emitter), topics: event.topics.map(hex), data: '0x05', logIndex: '0x17' },
      { address: hex(emitter), topics: event.topics.map(hex), data: '0x04', logIndex: '0x18' },
    ],
  });
  reader.headerByHash = async () => ({ header: block.header, raw: Uint8Array.of(0) });
  reader.certificateOf = async () => Uint8Array.of(1);
  reader.receiptPath = async () => [Uint8Array.of(2)];
  const proof = decodeDepositProof(await recoveryRpcSource(reader, block.hash)(emitter, event));
  assert.equal(proof.logIndex, 1n);
});

test('authority snapshots isolate in-place history appends before a durable save', async () => {
  const { TrustBaseBundle } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseBundle.js');
  const cfg = decodeConfig(await read('gamma.bin'), PRODUCTION_PARAMS);
  const full = await TrustInput.fromBundle(await read('transcripts/root/utb.cbor'), cfg.rootGenesis);
  const [genesis, successor] = full.history.entries;
  const input = (await TrustInput.fromBundle(await TrustBaseBundle.encode([genesis]), cfg.rootGenesis));
  let saving = false;
  const guard = new RecoveryAuthority(input, async () => {
    saving = true;
    assert.equal((await guard.checkpoint).history.tip?.epoch, genesis.epoch);
    throw new Error('write failed');
  });
  await input.history.append(successor);
  assert.equal((await guard.checkpoint).history.tip?.epoch, genesis.epoch);
  const external = await guard.checkpoint;
  await external.history.append(successor);
  assert.equal((await guard.checkpoint).history.tip?.epoch, genesis.epoch);
  await assert.rejects(guard.accept(external, cfg), { reason: 'TrustInput' });
  assert.ok(saving);
  assert.equal(guard.revision, 0);
  assert.equal((await guard.checkpoint).history.tip?.epoch, genesis.epoch);
});

test('recovery authority accepts an authenticated append beyond the initial load limit', { timeout: 180_000 }, async () => {
  const { RootTrustBaseV2 } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/RootTrustBaseV2.js');
  const { TRUST_BASE_BUNDLE_LIMITS } = await import('@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/ReleasePin.js');
  const { makeRoot, successorEntry } = await import('../rootfixture.js');
  const root = await makeRoot(1, 1, 31);
  const max = TRUST_BASE_BUNDLE_LIMITS.maxEntries;
  const cfg = { ...decodeConfig(await read('gamma.bin'), PRODUCTION_PARAMS), rootGenesis: root.pin };
  const trust = root.trust;
  const append = async (epoch: number): Promise<void> => {
    const raw = await successorEntry(root, BigInt(epoch), 1, 31);
    await trust.history.append(RootTrustBaseV2.decode(raw));
    root.entries.push(raw);
  };
  for (let epoch = 2; epoch <= max; epoch++) await append(epoch);
  let savedTip: bigint | undefined;
  const guard = new RecoveryAuthority(trust, async (candidate) => { savedTip = candidate.history.tip?.epoch; });
  await append(max + 1);
  const extended = trust;
  const overLimit = await extended.history.toBundle();
  await assert.rejects(TrustInput.fromBundle(overLimit, root.pin), { reason: 'ErrTrustBase' });
  await guard.accept(extended, cfg);
  assert.equal(savedTip, BigInt(max + 1));
  const readback = await guard.checkpoint;
  assert.equal(readback.history.entries.length, max + 1);
  assert.deepEqual(await readback.history.tip!.entryId(), await extended.history.tip!.entryId());
});
