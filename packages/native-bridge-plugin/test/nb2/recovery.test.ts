import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { test } from 'node:test';
import { gunzipSync } from 'node:zlib';
import { concat, fromHex } from '../../src/bytes.js';
import { decodeConfig, decodeDepositProof, verifyReceiptLog, Nb2Error, PRODUCTION_PARAMS, RecoverySession, TrustInput, WalletError } from '../../src/nb2/index.js';

const fixtures = new URL('../../../../protocol/vectors/nb2-continuation-v1.1/', import.meta.url);
const read = (file: string) => readFile(new URL(file, fixtures));
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
    const trust = (await TrustInput.fromBundle(bundle, decodeConfig(gamma, PRODUCTION_PARAMS).rootGenesis))
      .withAuthenticatedOrigin({ usableEpoch: 2n, rootRound: 10_000n });
    const session = await RecoverySession.create(gamma, evidence, trust, PRODUCTION_PARAMS, {
      salt, pins, recovery: fromHex(c.RecoveryAddress)!, runtimeHash: fromHex(c.RecoveryRuntimeHash)!,
    });
    assert.deepEqual(Buffer.from(session.id), Buffer.from(c.Session, 'hex'));
    assert.deepEqual(Buffer.from(session.pageRoot), Buffer.from(c.PageRoot, 'hex'));
    if (name === 'root') {
      const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
      const calibration = { pins, runtimeHash: fromHex(c.RecoveryRuntimeHash)!, executionBound: () => 1_000_000n };
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
      const result = await session.run(from, opCount(calldata), trust, prior);
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
  const trust = (await TrustInput.fromBundle(await load('b1-rollover/utb.cbor'), decodeConfig(gamma, PRODUCTION_PARAMS).rootGenesis))
    .withAuthenticatedOrigin({ usableEpoch: 2n, rootRound: 10_000n });
  const session = await RecoverySession.create(gamma, await load('b1-rollover/evidence.bin'), trust, PRODUCTION_PARAMS, deployment);
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
    await assert.rejects(RecoverySession.create(gamma, evidence, trust, PRODUCTION_PARAMS, deployment));
  }
});

test('cold recovery reproduces gap and settlement calls and switches proof sources', async () => {
  const gamma = await read('gamma.bin');
  const base = 'transcripts/root/';
  const context = JSON.parse(String(await read(base + 'context.json')));
  const recovery = fromHex(context.RecoveryAddress)!;
  const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
  const trust = (await TrustInput.fromBundle(await read(base + 'utb.cbor'), cfg.rootGenesis))
    .withAuthenticatedOrigin({ usableEpoch: 2n, rootRound: 10_000n });
  const session = await RecoverySession.create(gamma, await read(base + 'evidence.bin'), trust, PRODUCTION_PARAMS, {
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
    const packet = await session.gaps(entry, trust, receipt, prior, gaps, gapStart === end + 2 ? undefined : body.subarray(end + 2, gapStart));
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
  const trust = (await TrustInput.fromBundle(await read(base + 'utb.cbor'), cfg.rootGenesis))
    .withAuthenticatedOrigin({ usableEpoch: 2n, rootRound: 10_000n });
  const held = await read(base + 'evidence.bin');
  const deployment = {
    recovery: fromHex(context.RecoveryAddress)!, salt: await read('generation-salt.bin'),
    pins: await read('pins.bin'), runtimeHash: fromHex(context.RecoveryRuntimeHash)!, vaultRuntimeHash: new Uint8Array(32).fill(1),
  };
  const calibration = {
    pins: deployment.pins, runtimeHash: deployment.runtimeHash, vaultRuntimeHash: deployment.vaultRuntimeHash,
    executionBound: ({ operations, gaps }: { operations: number; gaps: number }) => 1_000_000n + BigInt(operations) * 500_000n + BigInt(gaps) * 7000n,
  };
  const limits = {
    signedBytes: 524_288, calldataBytes: 393_216, gas: 24_000_000n, chainId: cfg.chainId, maxNonce: 255n,
    maxFeePerGas: 10n, maxPriorityFeePerGas: 1n, balance: 10n ** 18n, feeBudget: 10n ** 18n,
  };
  const backlog = { signedStart: 0n, observed: 2n, duringProgress: 3n, peakSeals: 1n, elapsedMs: 1000n, receiptP99Ms: 1000n };
  const call = (changes: Partial<typeof limits> = {}, progress: Partial<typeof backlog> = {}) =>
    preflightRecovery(gamma, held, trust, PRODUCTION_PARAMS, deployment, calibration, { ...limits, ...changes }, { ...backlog, ...progress });
  const plan = await call();
  assert.equal(plan.run.reduce((total, q) => total + q.shape.operations, 0), 4);
  assert.equal(plan.advance.quote.shape.gaps, 69);
  assert.equal(plan.advance.calls, 1n);
  assert.ok(plan.settle.signedBytes > plan.settle.shape.calldataBytes);
  assert.equal((await call({ feeBudget: plan.totalFee })).totalFee, plan.totalFee);
  await assert.rejects(call({ feeBudget: plan.totalFee - 1n }), { rule: 'CapacityPreflight' });
  await assert.rejects(call({}, { signedStart: 1n }), { rule: 'CapacityPreflight' });
  await assert.rejects(call({}, { peakSeals: 35n }), { rule: 'CapacityPreflight' });
  const quote = plan.settle;
  assert.ok(quoteRecovery(quote.shape, calibration, { ...limits, signedBytes: quote.signedBytes, gas: quote.gas }));
  assert.equal(quoteRecovery(quote.shape, calibration, { ...limits, gas: quote.gas - 1n }), null);
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
  await assert.rejects(reader.certificateOf(block.header, block.hash, true), { reason: 'CompanionUnknown' });
  wrongChild = false;
  badRecord = true;
  await assert.rejects(reader.certificateOf(block.header, block.hash, true));
});
