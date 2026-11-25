import test from 'node:test';
import assert from 'node:assert/strict';
// Removing Node globals before import catches accidental host dependencies in the package root (the shared bytes, errors and trust
// input of the native bridge v2 plug-in; the protocol 7 facade was removed, bft-core#1106).
test('the package root loads without Node process/Buffer and exports the trust input', async () => {
  const saved = {process: globalThis.process, Buffer: globalThis.Buffer};
  try {
    globalThis.process = undefined;
    globalThis.Buffer = undefined;
    const p = await import('../../packages/native-bridge-plugin/lib/index.js');
    for (const name of ['TrustInput', 'NativeError', 'withTrustRefresh', 'needsNewerEntry', 'concat', 'toHex']) {
      assert.equal(typeof p[name], 'function', name);
    }
    assert.equal(p.NATIVE_BRIDGE_PROTO_VERSION, undefined, 'no protocol 7 export remains');
  } finally {
    Object.assign(globalThis, saved);
  }
});

test('the nb2 entry is protocol 10', async () => {
  const p = await import('../../packages/native-bridge-plugin/lib/nb2/index.js');
  assert.equal(p.NATIVE_BRIDGE_PROTO_VERSION, 10);
  assert.equal(typeof p.NativeBridgeV2, 'function');
});

test('the authenticated genesis is isolated from the caller pin and returned IDs', async () => {
  const { readFile } = await import('node:fs/promises');
  const p = await import('../../packages/native-bridge-plugin/lib/nb2/index.js');
  const vectors = new URL('../../protocol/vectors/nb2-continuation-v1.1/', import.meta.url);
  const cfg = p.decodeConfig(await readFile(new URL('gamma.bin', vectors)), p.PRODUCTION_PARAMS);
  const bundle = await readFile(new URL('transcripts/root/utb.cbor', vectors));
  const callerPin = Buffer.from(cfg.rootGenesis);
  const otherGenesis = Uint8Array.from(cfg.rootGenesis);
  otherGenesis[0] ^= 0xff;
  const installing = p.TrustInput.fromBundle(bundle, callerPin);
  callerPin.set(otherGenesis);
  const history = await installing;
  callerPin.fill(0);
  history.id.set(otherGenesis);
  const trust = history;
  trust.id.set(otherGenesis);
  assert.deepEqual(trust.id, Uint8Array.from(cfg.rootGenesis));
  const { mint } = p.decodeToken(await readFile(new URL('transcripts/root/evidence.bin', vectors)));
  const { proof } = p.decodeReceiptBacking(mint.justification);
  await p.verifyEvmUc(trust, proof.uc, cfg);
  await assert.rejects(p.verifyEvmUc(trust, proof.uc, { ...cfg, rootGenesis: otherGenesis }), { reason: 'TrustInput' });
});

test('JavaScript cold admission requires an explicit positive bigint qualification horizon', async () => {
  const p = await import('../../packages/native-bridge-plugin/lib/nb2/index.js');
  const backlog = {
    signedStart: 0n, observed: 1024n, duringProgress: 0n, peakSeals: 32n, elapsedMs: 1000n,
    receiptP99Ms: 1000n, advancePeakSeals: 32n, finalInclusionMs: 25n, finalPeakSeals: 1n,
  };
  const limits = { signedBytes: 1, calldataBytes: 1, gas: 1n, chainId: 1n, maxNonce: 0n,
    maxFeePerGas: 1n, maxPriorityFeePerGas: 0n, balance: 1n, feeBudget: 1n };
  const check = (input) => p.preflightRecovery(new Uint8Array(), new Uint8Array(), undefined, p.PRODUCTION_PARAMS,
    undefined, undefined, limits, input);
  for (const input of [backlog, { ...backlog, qualifiedForMs: 34_025 }, { ...backlog, qualifiedForMs: 0n }]) {
    await assert.rejects(check(input), { rule: 'CapacityPreflight', detail: 'unqualified backlog measurements' });
  }
});

test('JavaScript cold admission requires all payer limits and accepts exact funding limits', async () => {
  const { readFile } = await import('node:fs/promises');
  const p = await import('../../packages/native-bridge-plugin/lib/nb2/index.js');
  const vectors = new URL('../../protocol/vectors/nb2-continuation-v1.1/', import.meta.url);
  const read = (file) => readFile(new URL(file, vectors));
  const [gamma, salt, pins, held, bundle, context] = await Promise.all([
    read('gamma.bin'), read('generation-salt.bin'), read('pins.bin'), read('transcripts/held-sibling-0/evidence.bin'),
    read('transcripts/held-sibling-0/utb.cbor'), read('transcripts/held-sibling-0/context.json'),
  ]);
  const cfg = p.decodeConfig(gamma, p.PRODUCTION_PARAMS);
  const c = JSON.parse(context);
  const trust = (await p.TrustInput.fromBundle(bundle, cfg.rootGenesis));
  const vaultRuntimeHash = new Uint8Array(32).fill(1);
  const runtimeHash = Buffer.from(c.RecoveryRuntimeHash, 'hex');
  const deployment = { salt, pins, runtimeHash, vaultRuntimeHash, recovery: Buffer.from(c.RecoveryAddress, 'hex') };
  const range = (entry, operations, gaps) => ({
    minReceiptBytes: entry === 'run' ? 0 : 1,
    max: { entry, operations, gaps, calldataBytes: 393_216, pages: 32, receiptBytes: 65_536, openingBytes: 393_216 },
    execution: 1_000_000n,
  });
  const calibration = { pins, runtimeHash, vaultRuntimeHash, ranges: [
    ...Array.from({ length: 4 }, (_, i) => range('run', i + 1, 0)),
    range('advanceGaps', 0, 1),
    range('redeemRecovered', 0, 0),
  ] };
  const limits = { signedBytes: 524_288, calldataBytes: 393_216, gas: 24_000_000n, chainId: cfg.chainId,
    maxNonce: 255n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n, balance: 10n ** 18n, feeBudget: 10n ** 18n };
  const backlog = { signedStart: 0n, observed: 0n, duringProgress: 0n, peakSeals: 0n, elapsedMs: 1000n,
    receiptP99Ms: 1000n, advancePeakSeals: 0n, finalInclusionMs: 25n, finalPeakSeals: 0n, qualifiedForMs: 100_000n };
  const check = (input) => p.preflightRecovery(gamma, held, trust, p.PRODUCTION_PARAMS, deployment, calibration, input, backlog);
  const plan = await check(limits);
  const exact = { ...limits, balance: plan.totalFee, feeBudget: plan.totalFee };
  const { shape, gas } = plan.advance.quote;
  assert.equal(p.quoteRecovery(shape, calibration, { ...limits, gas }).gas, gas);
  assert.equal(p.quoteRecovery(shape, calibration, { ...limits, gas: gas - 1n }), null);
  assert.equal((await check(exact)).totalFee, plan.totalFee);
  for (const field of ['gas', 'chainId', 'maxNonce', 'maxFeePerGas', 'maxPriorityFeePerGas', 'balance', 'feeBudget']) {
    const omitted = { ...exact };
    delete omitted[field];
    await assert.rejects(check(omitted), { rule: 'CapacityPreflight', detail: 'invalid recovery payer limits' }, field);
    await assert.rejects(check({ ...exact, [field]: Number(exact[field]) }), { rule: 'CapacityPreflight', detail: 'invalid recovery payer limits' }, field);
  }
});
