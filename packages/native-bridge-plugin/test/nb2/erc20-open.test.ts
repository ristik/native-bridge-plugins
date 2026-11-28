import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { gunzipSync } from 'node:zlib';
import { toHex } from '../../src/bytes.js';
import { addressWord, decodeBytesReturn } from '../../src/nb2/abi.js';
import { ERC20_PROFILE_HASH, IMPORTED_TIP_PROFILE_HASH, NativeBridgeV2, type RedeemOptions, type ReturnAdmission } from '../../src/nb2/bridge.js';
import { ascii, u256 } from '../../src/nb2/cbor.js';
import { decodeConfig, PRODUCTION_PARAMS } from '../../src/nb2/config.js';
import { HE } from '../../src/nb2/crypto.js';
import { decodeReceiptBacking, depositedData, TOPIC } from '../../src/nb2/deposit.js';
import { LocalKeySigner, decodeSignedTx, signTx } from '../../src/nb2/evm.js';
import { Journal, MemoryJournalStore, continuationReserve, payerNonceLimit } from '../../src/nb2/journal.js';
import { WalletError } from '../../src/nb2/errors.js';
import { quoteErc20Call, quoteRecoveryGapBatch, quoteScheduledRecoveryFee, quoteScheduledRecoveryRuns,
  type RecoveryCalibrationRange, type RecoveryShape } from '../../src/nb2/recovery-cost.js';
import { RpcError, type JsonRpc } from '../../src/nb2/rpc.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { decodeUc } from '../../src/nb2/trust.js';
import { nextEpoch } from '../rootfixture.js';
import { successor } from './certification-fixtures.js';
import { FakeAggregator, evmAccount, key, roundNow, setup } from './world.js';

const hex = (b: Uint8Array) => `0x${toHex(b)}`;
const bytes = (h: string) => Uint8Array.from(Buffer.from(h.slice(2), 'hex'));
const selector = (s: string) => hex(HE(ascii(s)).subarray(0, 4));
type RpcLog = { address: string; topics: string[]; data: string };

/** Runtime code, config calls and the two activation logs captured from an Anvil deployment. */
const deployment = JSON.parse(gunzipSync(readFileSync(new URL(
  '../../../../protocol/vectors/erc20-nb2/sdk-deployment.json.gz', import.meta.url,
))).toString('utf8')) as {
  factory: string; generation: string; genesis: { hash: string }; code: Record<string, string>;
  vaultInitcodeHash: string; recoveryInitcodeHash: string;
  assets: { vault: string; token: string; recovery: string; config: string }[];
  activation: { logs: RpcLog[] };
};

async function world() {
  const w = await setup(bytes(`0x${IMPORTED_TIP_PROFILE_HASH}`));
  const a = deployment.assets[1];
  const gamma = decodeBytesReturn(bytes(a.config));
  const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
  assert.equal(toHex(cfg.semanticProfileHash), ERC20_PROFILE_HASH);
  assert.equal(hex(cfg.rootGenesis), hex(w.root.pin));
  assert.equal(hex(cfg.erc20!.token), a.token.toLowerCase());
  const payer = evmAccount(w.chain, 'ERC20 fixture payer');
  const factory = deployment.factory.toLowerCase();
  const call = async (logs: RpcLog[]) => {
    w.chain.coldCall = async () => logs.map((l) => ({
      address: bytes(l.address), topics: l.topics.map(bytes), data: bytes(l.data),
    }));
    const nonce = await w.chain.call<string>('eth_getTransactionCount', [hex(payer.address), 'pending']);
    const tx = await signTx(payer, { chainId: cfg.chainId, nonce: BigInt(nonce), to: bytes(factory), data: new Uint8Array(),
      value: 0n, gas: 150_000n, maxFeePerGas: 20n, maxPriorityFeePerGas: 1n });
    const number = BigInt(w.chain.blocks.length);
    await w.chain.mine([tx.raw]);
    await w.chain.mine([]);
    w.chain.coldCall = undefined;
    return { tx: tx.hash, number };
  };
  const tip = await successor(w.root, roundNow() + 1n);
  w.chain.certificateAuthority = { root: tip, epoch: 2n };
  const activation = await call(deployment.activation.logs);
  const activationRound = decodeUc(w.chain.blocks[Number(activation.number)].uc!).unicitySeal.rootChainRoundNumber;
  const agg = new FakeAggregator(tip, false, 2n);

  let preview: 'exact' | 'blocked' = 'exact';
  let badDependency = -1;
  let finalNonce = 0n;
  let pendingNonce: bigint | undefined;
  const dependencies = [new Uint8Array(20).fill(0x76), new Uint8Array(20).fill(0x77), bytes('0xff00000000000000000000000000000000000002')];
  const dependencyCode = dependencies.map((_, i) => Uint8Array.of(0x60, i));
  let probes = 0;
  const rpc: JsonRpc = {
    async call<T>(method: string, params: unknown[]): Promise<T> {
      if (method === 'eth_getCode' && typeof params[0] === 'string') {
        const helper = dependencies.findIndex((address) => hex(address) === params[0]);
        if (helper !== -1) return (helper === badDependency ? '0x600f' : hex(dependencyCode[helper])) as T;
        const runtime = deployment.code[params[0].toLowerCase()];
        if (runtime) return runtime as T;
      }
      if (method === 'eth_getTransactionCount' && params[1] === 'finalized') return ('0x' + finalNonce.toString(16)) as T;
      if (method === 'eth_getTransactionCount' && params[1] === 'pending' && pendingNonce !== undefined) return ('0x' + pendingNonce.toString(16)) as T;
      if (method === 'eth_getBlockByNumber' && params[0] === '0x0') return deployment.genesis as T;
      if (method === 'eth_call') {
        const { to, data, gas } = params[0] as { to: string; data: string; gas?: string };
        if (to === a.recovery.toLowerCase()) {
          if (data === selector('RECEIPTS()')) return hex(addressWord(dependencies[0])) as T;
          if (data === selector('LINEAGE()')) return hex(addressWord(dependencies[1])) as T;
          const helper = ['RECEIPTS_HASH()', 'LINEAGE_HASH()', 'REGISTRY_HASH()'].findIndex((getter) => data === selector(getter));
          if (helper !== -1) return hex(HE(dependencyCode[helper])) as T;
        }
        if (to === factory) {
          if (data === selector('config(address)') + toHex(addressWord(cfg.erc20!.token))) return a.config as T;
          if (data === selector('VAULT_INITCODE_HASH()')) return deployment.vaultInitcodeHash as T;
          if (data === selector('RECOVERY_INITCODE_HASH()')) return deployment.recoveryInitcodeHash as T;
          if (data === selector('GENERATION()')) return deployment.generation as T;
          if (data === selector('PINS()')) return hex(cfg.erc20!.pins) as T;
        }
        if (to === a.vault.toLowerCase()) {
          if (data === selector('config()')) return a.config as T;
          if (data === selector('state()')) return hex(new Uint8Array(192)) as T;
          if (data.startsWith(selector('previewPayout(address,uint256)'))) {
            assert.equal(gas, '0x55730');
            probes++;
            const result = selector(preview === 'exact' ? 'PayoutPreviewPassed()' : 'TokenCallFailed()');
            throw new RpcError(200, 3, 'execution reverted', result);
          }
        }
      }
      return w.chain.call<T>(method, params);
    },
  };
  const options = () => {
    const opts = w.options('ERC20 deployment fixture');
    return { ...opts, unsafeTestTrust: false, rpc, aggregator: agg, refreshTrust: async () => tip.trust, pins: { ...opts.pins,
      gamma, build: 'production' as const, deploymentBlock: activation.number,
      vaultRuntimeCodeHash: HE(bytes(deployment.code[a.vault.toLowerCase()])),
      erc20: { factory: bytes(factory), factoryRuntimeHash: HE(bytes(deployment.code[factory])),
        vaultInitcodeHash: bytes(deployment.vaultInitcodeHash), recoveryInitcodeHash: bytes(deployment.recoveryInitcodeHash),
        activationTx: activation.tx, fundingQualified: true },
    } };
  };
  return { agg, a, cfg, call, payer, tip, activationRound, options, blockRecipient: () => { preview = 'blocked'; }, probes: () => probes,
    setBadDependency: (value: number) => { badDependency = value; }, finalized: (nonce: bigint) => { finalNonce = nonce; },
    pending: (nonce?: bigint) => { pendingNonce = nonce; } };
}

test('normal ERC20 open authenticates the second deployed activation and refreshes genesis-only trust', async () => {
  const x = await world();
  const opts = x.options();
  assert.equal(opts.trust.history.tip?.epoch, 1n);
  let refreshed = 0;
  const bridge = await NativeBridgeV2.open({ ...opts, refreshTrust: async () => { refreshed++; return x.tip.trust; } });
  assert.equal(refreshed, 1);
  assert.equal(hex(bridge.cfg.vault), x.a.vault.toLowerCase());
  assert.equal(await bridge.verifyWithTrust(async (trust) => trust.history.tip?.epoch), 2n);

  const closed = await nextEpoch(x.tip, x.activationRound, 4, 56);
  await assert.rejects(NativeBridgeV2.open({ ...x.options(), refreshTrust: async () => closed.trust }), { rule: 'DepositUC' });
});

async function heldPair(store = new MemoryJournalStore()) {
  const x = await world();
  const bridge = await NativeBridgeV2.open({ ...x.options(), journal: store });
  const owner = localOwner(key('ERC20 batch owner'));
  const first = await bridge.planDeposit(10n, owner.publicKey, 10n);
  const second = await bridge.planDeposit(20n, owner.publicKey, 20n);
  await x.call([first, second].map((plan, i) => ({
    address: x.a.vault.toLowerCase(), topics: [hex(TOPIC.ERC20Deposited), hex(u256(i + 1)), hex(addressWord(x.cfg.erc20!.token))],
    data: hex(depositedData(bridge.domain, plan.amount, plan.rho, plan.firstOwner)),
  })));
  assert.equal((await bridge.submitDeposit(second, x.payer)).depositNumber, 2n);
  const collected = await bridge.collectDepositProof(second.intent);
  assert.equal(decodeReceiptBacking(collected.reason).proof.logIndex, 1n);
  const held = await bridge.mint(second.intent);
  assert.equal((await bridge.verifyToken(held)).amount, 20n);

  await bridge.submitDeposit(first, x.payer);
  await bridge.collectDepositProof(first.intent);
  const firstHeld = await bridge.mint(first.intent);
  return { x, bridge, owner, held, firstHeld, store };
}

function admissionFor(x: Awaited<ReturnType<typeof world>>): NonNullable<ReturnAdmission['erc20Recovery']> {
  const graph = {
    salt: x.cfg.erc20!.generation, pins: x.cfg.erc20!.pins, recovery: bytes(x.a.recovery),
    runtimeHash: HE(bytes(deployment.code[x.a.recovery.toLowerCase()])),
    vaultRuntimeHash: x.options().pins.vaultRuntimeCodeHash,
  };
  const ranges: RecoveryCalibrationRange[] = [];
  const range = (entry: RecoveryShape['entry'], operations: number, gaps: number) => ranges.push({
    minReceiptBytes: entry === 'run' ? 0 : 1, execution: 1_000_000n,
    max: { entry, operations, gaps, receiptBytes: 65_536, calldataBytes: 393_216, pages: 32, openingBytes: 393_216 },
  });
  for (let operations = 1; operations <= 16; operations++) range('run', operations, 0);
  for (let gaps = 0; gaps <= 128; gaps++) {
    if (gaps !== 0) range('advanceGaps', 0, gaps);
    range('redeemRecovered', 0, gaps);
  }
  return { deployment: graph, calibration: { ...graph, ranges },
    limits: { signedBytes: 524_288, calldataBytes: 393_216, gas: 24_000_000n, maxNonce: 255n,
      maxFeePerGas: 30n, maxPriorityFeePerGas: 2n, balance: 10n ** 20n, feeBudget: 10n ** 20n },
    backlog: { duringProgress: 3n, peakSeals: 1n, elapsedMs: 1000n, receiptP99Ms: 1000n,
      advancePeakSeals: 1n, finalInclusionMs: 25n, finalPeakSeals: 1n, qualifiedForMs: 200_000n },
    signingBounds: { feeWindowMs: 400_000n, progressWindowMs: 100_000n, maxRunCalls: 2, advanceWindowMs: 2000n },
    ordinaryAttempts: { attemptsBeforeFallback: 1n, inclusionMs: 1000n },
    ordinaryRanges: [{ maxEvidenceBytes: 100_000, maxOperations: 16, maxGaps: 64n, execution: 4_000_000n }],
  };
}

const recipient = bytes('0x' + 'ab'.repeat(20));

test('the second deposit in one certified receipt mints and the bridge prices the ERC20 burn before calling the signer', async () => {
  const { x, bridge, owner, held } = await heldPair();
  const input = admissionFor(x);
  const admission = { erc20Recovery: input };
  await assert.rejects(bridge.planReturn(held, recipient, x.payer.address, { admission: {
    erc20Recovery: { ...input, limits: { ...input.limits, feeBudget: 16_000_000n } },
  } }), /insufficient authorized fee budget/);
  const planned = await bridge.planReturn(held, recipient, x.payer.address, { admission });
  assert.ok(planned.record.recovery?.ordinary);
  const capped = await bridge.planReturn(held, recipient, x.payer.address, { admission: {
    erc20Recovery: { ...input, limits: { ...input.limits, gas: 4_000_000n } },
  } });
  assert.equal(capped.gasLimit, 0n);
  assert.equal(capped.record.recovery?.ordinary, undefined);
  assert.equal(planned.record.recovery.progressEnd, '3');
  let signatures = 0;
  const signer = { ...owner, signUnlock: (hash: Uint8Array) => { signatures++; return owner.signUnlock(hash); } };
  let called = false;
  await assert.rejects(bridge.burn(planned.returnId, signer, {
    recover: async () => {
      called = true;
      return { ...planned.record.recovery!, runCuts: [], calls: '0', totalFee: '0' };
    },
  }), /bounded ERC20 continuation quote/);
  assert.equal(called, false);
  await assert.rejects(bridge.burn(planned.returnId, signer, { erc20Recovery: {
    ...input, calibration: { ...input.calibration, ranges: input.calibration.ranges.filter((r) => r.max.entry !== 'run') },
  } }), /indivisible run operation/);
  const singletonRuns = input.calibration.ranges.filter((r) => r.max.entry !== 'run' || r.max.operations === 1);
  await assert.rejects(bridge.burn(planned.returnId, signer, { erc20Recovery: {
    ...input, calibration: { ...input.calibration, ranges: singletonRuns }, signingBounds: { ...input.signingBounds!, maxRunCalls: 1 },
  } }), /Run schedule exceeds the qualified progress window/);
  for (let helper = 0; helper < 3; helper++) {
    x.setBadDependency(helper);
    await assert.rejects(bridge.burn(planned.returnId, signer, admission), /pinned hash/);
    assert.equal(signatures, 0);
  }
  x.setBadDependency(-1);
  const before = x.agg.calls;
  x.blockRecipient();
  await assert.rejects(bridge.burn(planned.returnId, signer, admission), { reason: 'RecipientRefused' });
  assert.equal(signatures, 0);
  assert.equal((await bridge.journal.ret(hex(planned.returnId)))?.status, 'planned');
  assert.equal(x.agg.calls, before);
});

test('separate ERC20 SDK instances sharing a store reserve the payer before either signer can commit', async () => {
  class RacingStore extends MemoryJournalStore {
    private attempts = 0;
    private release!: () => void;
    private readonly bothReady = new Promise<void>((resolve) => { this.release = resolve; });
    override async putIf(key: string, expected: string | null, value: string): Promise<boolean> {
      if (key.startsWith('nb2/payer/v1/') && expected === null) {
        if (++this.attempts === 2) this.release();
        await this.bothReady;
      }
      return super.putIf(key, expected, value);
    }
  }
  const store = new RacingStore();
  const { x, bridge, owner, firstHeld, held } = await heldPair(store);
  const peer = await NativeBridgeV2.open({ ...x.options(), journal: store });
  const erc20Recovery = admissionFor(x);
  const admission = { erc20Recovery };
  const a = await bridge.planReturn(firstHeld, recipient, x.payer.address, { admission });
  const b = await peer.planReturn(held, recipient, x.payer.address, { admission });
  const calls = BigInt(a.record.recovery!.calls);
  assert.equal(BigInt(b.record.recovery!.calls), calls);
  erc20Recovery.limits.maxNonce = (await bridge.evm.nonce(x.payer.address)) + calls - 1n;
  let signed = 0;
  const signer = { ...owner, signUnlock: (hash: Uint8Array) => { signed++; return owner.signUnlock(hash); } };
  const outcomes = await Promise.allSettled([bridge.burn(a.returnId, signer, admission), peer.burn(b.returnId, signer, admission)]);
  assert.equal(signed, 1);
  assert.equal(outcomes.filter((value) => value.status === 'fulfilled').length, 1);
  const refused = outcomes.find((value) => value.status === 'rejected')!;
  assert.match(String(refused.reason), /payer already has an outstanding ERC20 return/);
  const loser = outcomes[0].status === 'rejected' ? a : b;
  const winner = loser === a ? b : a;
  await assert.rejects(bridge.burn(loser.returnId, signer, admission), /payer already has an outstanding ERC20 return/);
  assert.equal(signed, 1);
  const paid = (await bridge.journal.retForUpdate(hex(winner.returnId)))!;
  await bridge.journal.putReturn({ ...paid, status: 'paid', paid: { txHash: hex(key('paid')), blockNumber: '1' } });
  erc20Recovery.limits.maxNonce--;
  await assert.rejects(bridge.burn(loser.returnId, signer, admission), /declared nonce horizon/);
  assert.equal(signed, 1);
  erc20Recovery.limits.maxNonce++;
  await bridge.burn(loser.returnId, signer, admission);
  assert.equal(signed, 2);
});

test('peer Paid keeps the payer unavailable while a local recovery nonce can still be included', async () => {
  const { x, bridge, owner, firstHeld, held } = await heldPair();
  const admission = { erc20Recovery: admissionFor(x) };
  const first = await bridge.planReturn(firstHeld, recipient, x.payer.address, { admission });
  await bridge.burn(first.returnId, owner, admission);
  const raw = await signTx(x.payer, { chainId: x.cfg.chainId, nonce: 7n, gas: 2_000_000n,
    maxFeePerGas: 10n, maxPriorityFeePerGas: 1n, to: bytes(x.a.recovery), value: 0n, data: new Uint8Array() });
  const paid = (await bridge.journal.retForUpdate(hex(first.returnId)))!;
  await bridge.journal.retainPayerSend(paid, raw.raw);
  await bridge.journal.putReturn({ ...paid, status: 'paid', paid: { txHash: hex(key('peer-paid')), blockNumber: '190' } });
  x.finalized(7n);
  await assert.rejects(bridge.planReturn(held, recipient, x.payer.address, { admission }), /signed nonce awaiting finalization/);
  x.finalized(8n);
  await bridge.planReturn(held, recipient, x.payer.address, { admission });
});

test('an unsigned refusal releases the payer and an ambiguous signer response keeps its claim', async () => {
  class Store extends MemoryJournalStore {
    onClaim?: () => void;
    override async putIf(key: string, expected: string | null, value: string): Promise<boolean> {
      const written = await super.putIf(key, expected, value);
      if (written && key.startsWith('nb2/payer/v1/') && value.includes('#')) this.onClaim?.();
      return written;
    }
  }
  const store = new Store();
  const { x, bridge, owner, firstHeld, held } = await heldPair(store);
  const admission = { erc20Recovery: admissionFor(x) };
  const a = await bridge.planReturn(firstHeld, recipient, x.payer.address, { admission });
  const b = await bridge.planReturn(held, recipient, x.payer.address, { admission });
  store.onClaim = () => x.pending(256n);
  await assert.rejects(bridge.burn(a.returnId, { ...owner, signUnlock: async () => assert.fail('nonce recheck must precede signing') }, admission), /declared nonce horizon/);
  store.onClaim = undefined;
  x.pending();
  await bridge.planReturn(held, recipient, x.payer.address, { admission });
  await assert.rejects(bridge.burn(a.returnId, { ...owner, signUnlock: async () => { throw new WalletError('SigningDeclined'); } }, admission), { reason: 'SigningDeclined' });
  await assert.rejects(bridge.burn(b.returnId, { ...owner, signUnlock: async () => { throw new Error('signer disconnected'); } }, admission), /signer disconnected/);
  assert.equal((await bridge.journal.ret(hex(b.returnId)))?.status, 'planned');
  await assert.rejects(bridge.burn(a.returnId, owner, admission), /outstanding ERC20 return/);
});

test('legacy returns across domains keep their budgets and can claim the payer in sequence', async () => {
  const { x, bridge, held, store } = await heldPair();
  const chainId = x.cfg.chainId;
  const payer = x.payer.address;
  const admission = { erc20Recovery: admissionFor(x) };
  const planned = await bridge.planReturn(held, recipient, payer, { admission });
  const a = new Journal(store, key('old vault a'));
  const b = new Journal(store, key('old vault b'));
  const another = new Journal(store, key('known different chain'));
  const old = (journal: Journal, tag: string, calls: string, totalFee: string) => ({
    ...planned.record, ...journal.base(), returnId: hex(key(tag)), status: 'burned' as const,
    recovery: { ...planned.record.recovery!, calls, totalFee },
  });
  const first = old(a, 'legacy return a', '6', '60');
  const second = old(b, 'legacy return b', '7', '70');
  const offChain = old(another, 'unrelated chain return', '80', '800');
  await another.checkReturnPayer(chainId + 1n, payer, offChain.returnId);
  await another.putReturn(offChain);
  await a.putReturn(first);
  await b.putReturn(second);

  await assert.rejects(bridge.planReturn(held, recipient, payer, { admission }), /outstanding ERC20 return/);
  const drain = { mode: 'drain' as const, signingNonce: 0n, finalizedNonce: async () => 1n };
  const other = await a.checkReturnPayer(chainId, payer, first.returnId, true, drain);
  assert.equal(other.fees, 70n);
  assert.equal(other.calls, 7n);
  assert.equal(payerNonceLimit(255n, other), 248n);
  assert.equal(payerNonceLimit(245n, other), 245n, 'the current return may have an earlier deadline');
  await assert.rejects(b.checkReturnPayer(chainId, payer, second.returnId, true, { mode: 'drain' }), /outstanding ERC20 return/);
  await a.retForUpdate(first.returnId);
  await a.putReturn({ ...first, status: 'paid', paid: { txHash: hex(key('legacy paid a')), blockNumber: '21' } });
  assert.equal((await b.checkReturnPayer(chainId, payer, second.returnId, true, { ...drain, signingNonce: 1n })).calls, 0n);
  await b.retForUpdate(second.returnId);
  await b.putReturn({ ...second, status: 'paid', paid: { txHash: hex(key('legacy paid b')), blockNumber: '22' } });
  x.finalized(2n);
  await bridge.planReturn(held, recipient, payer, { admission });
});

test('a legacy drain waits for active recovery packets to be indexed and finalized', async () => {
  const { x, bridge, held, store } = await heldPair();
  const payer = x.payer.address;
  const chainId = x.cfg.chainId;
  const { record } = await bridge.planReturn(held, recipient, payer, { admission: { erc20Recovery: admissionFor(x) } });
  const a = new Journal(store, key('legacy execution domain'));
  const active = { ...record, ...a.base(), returnId: hex(key('legacy execution return')), status: 'burned' as const, executionPayer: hex(payer) };
  const claimant = { ...record, status: 'burned' as const };
  await a.putReturn(active);
  const obsolete = `nb2/payer-index/v1/${active.domain.slice(2)}/${active.returnId.slice(2)}`;
  await store.putIf(obsolete, null, '1');
  await bridge.journal.putReturn(claimant);
  const drain = { mode: 'drain' as const, signingNonce: 7n, finalizedNonce: () => bridge.evm.nonce(payer, 'finalized') };
  await assert.rejects(bridge.journal.checkReturnPayer(chainId, payer, claimant.returnId, true, drain), /local signed sends indexed/);
  const tx = await signTx(x.payer, { chainId, nonce: 7n, gas: 100_000n, maxFeePerGas: 10n,
    maxPriorityFeePerGas: 1n, to: bytes(x.a.recovery), value: 0n, data: new Uint8Array() });
  await a.registerPayerChain(chainId);
  await a.indexPayerSends(active, [tx.raw]);
  x.finalized(7n);
  await assert.rejects(bridge.journal.checkReturnPayer(chainId, payer, claimant.returnId, true, drain), /signed nonce awaiting finalization/);
  x.finalized(8n);
  const other = await bridge.journal.checkReturnPayer(chainId, payer, claimant.returnId, true, { ...drain, signingNonce: 8n });
  assert.equal(other.fees, BigInt(active.recovery!.totalFee));
});

test('a legacy claimant must leave a feasible full schedule for the earlier nonce deadline', async () => {
  const store = new MemoryJournalStore();
  const { x, bridge, held } = await heldPair(store);
  const payer = x.payer.address;
  const chainId = x.cfg.chainId;
  const { record } = await bridge.planReturn(held, recipient, payer, { admission: { erc20Recovery: admissionFor(x) } });
  const a = new Journal(store, key('later deadline'));
  const b = new Journal(store, key('earlier deadline'));
  const legacy = (journal: Journal, maxNonce: string) => ({
    ...record, ...journal.base(), returnId: hex(key(maxNonce)), status: 'burned' as const,
    recovery: { ...record.recovery!, calls: '8', envelope: { ...record.recovery!.envelope!, maxNonce } },
  });
  const later = legacy(a, '15');
  const earlier = legacy(b, '8');
  await a.putReturn(later);
  await b.putReturn(earlier);
  const drain = { mode: 'drain' as const, signingNonce: 0n, finalizedNonce: async () => 8n };
  await assert.rejects(a.checkReturnPayer(chainId, payer, later.returnId, true, drain), /remaining continuation schedule/);
  for (let nonce = 0n; nonce < 8n; nonce++) {
    await b.checkReturnPayer(chainId, payer, earlier.returnId, true, { ...drain, signingNonce: nonce });
  }
  await b.putReturn({ ...earlier, status: 'paid', paid: { txHash: hex(key('earlier payout')), blockNumber: '21' } });
  for (let nonce = 8n; nonce < 16n; nonce++) {
    await a.checkReturnPayer(chainId, payer, later.returnId, true, { ...drain, signingNonce: nonce });
  }
});

test('finalized Runs let both legacy returns drain at the exact 15/8 nonce and balance boundary', async () => {
  const { x, bridge, held, store } = await heldPair();
  const payer = x.payer.address;
  const { chainId } = x.cfg;
  const { record } = await bridge.planReturn(held, recipient, payer, { admission: { erc20Recovery: admissionFor(x) } });
  const a = new Journal(store, key('partial later domain'));
  const b = new Journal(store, key('partial earlier domain'));
  const legacy = (journal: Journal, maxNonce: string) => ({
    ...record, ...journal.base(), returnId: hex(key('partial ' + maxNonce)), status: 'burned' as const, executionPayer: hex(payer),
    recovery: { ...record.recovery!, calls: '8', totalFee: '100', ordinary: undefined,
      envelope: { ...record.recovery!.envelope!, maxNonce, maxFeePerGas: '1' } },
  });
  const later = legacy(a, '15');
  const earlier = legacy(b, '8');
  const checkpoints = [key('later checkpoint'), key('earlier checkpoint')];
  for (const [index, journal, legacy] of [[0, a, later], [1, b, earlier]] as const) {
    await journal.putReturn(legacy);
    const raw = await signTx(x.payer, { chainId, nonce: BigInt(index), gas: 100_000n, maxFeePerGas: 10n,
      maxPriorityFeePerGas: 1n, to: bytes(x.a.recovery), value: 0n, data: new Uint8Array() });
    await journal.registerPayerChain(chainId);
    await journal.indexPayerSends(legacy, [raw.raw]);
    await journal.indexRecoveryProgress(chainId, legacy, 1n, { blockNumber: BigInt(index + 20), blockHash: checkpoints[index] }, 80n);
  }
  let finalizedNonce = 2n;
  let finalizedHeight = 19n;
  let balance = 159n;
  bridge.evm.balance = async () => balance;
  const claim = (journal: Journal, legacy: typeof later, signingNonce: bigint) => journal.checkReturnPayer(chainId, payer, legacy.returnId, true, {
    mode: 'drain', signingNonce, finalizedNonce: async () => finalizedNonce,
    finalizedBlock: async (number, hash) => number <= finalizedHeight && hex(hash) === hex(checkpoints[Number(number) - 20]),
    beforeSigning: async (other) => { if (await bridge['freeErc20PayerBalance'](payer, other) < 80n) throw new Error('insufficient free balance'); },
  });
  await assert.rejects(claim(b, earlier, 2n), /remaining continuation schedule/);
  finalizedHeight = 21n;
  await assert.rejects(claim(a, later, 2n), /remaining continuation schedule/);
  finalizedNonce = 0n;
  await assert.rejects(claim(b, earlier, 2n), /signed nonce awaiting finalization/);
  finalizedNonce = 2n;
  await assert.rejects(claim(b, earlier, 2n), /insufficient free balance/);
  balance = 160n;
  const other = await claim(b, earlier, 2n);
  assert.equal(other.calls, 7n);
  assert.equal(other.fees, 80n);
  for (let nonce = 3n; nonce <= 8n; nonce++) await claim(b, earlier, nonce);
  await b.putReturn({ ...earlier, status: 'paid', paid: { txHash: hex(key('earlier settled')), blockNumber: '22' } });
  finalizedNonce = 9n;
  for (let nonce = 9n; nonce <= 15n; nonce++) await claim(a, later, nonce);
});

test('an ordinary claimant must authorize the full legacy suffix before reserving the payer', async () => {
  const { x, bridge, held } = await heldPair();
  const payer = x.payer.address;
  const erc20Recovery = admissionFor(x);
  const { record } = await bridge.planReturn(held, recipient, payer, { admission: { erc20Recovery } });
  const a = { ...record, status: 'burned' as const };
  const b = { ...a, returnId: hex(key('second ordinary legacy return')) };
  await bridge.journal.putReturn(a);
  await bridge.journal.putReturn(b);
  const request = { chainId: x.cfg.chainId, nonce: 1n, gas: 100_000n, maxFeePerGas: 10n,
    maxPriorityFeePerGas: 1n, to: x.cfg.vault, value: 0n, data: new Uint8Array(68) };
  let admitted = 0;
  const admit = async () => { admitted++; };
  const feeBudget = BigInt(a.recovery!.totalFee);
  const policy = erc20Recovery.limits;
  await assert.rejects(bridge['reserveOrdinaryPayer'](a, payer, request, {
    admit, erc20Recovery, erc20Policy: { maxNonce: 255n, feeBudget } as RedeemOptions['erc20Policy'],
  }), /authorized payer fee ceiling/);
  for (const maxFeePerGas of [undefined, 0n, '30', 30]) {
    await assert.rejects(bridge['reserveOrdinaryPayer'](a, payer, request, {
      admit, erc20Recovery, erc20Policy: { ...policy, maxFeePerGas, feeBudget } as RedeemOptions['erc20Policy'],
    }), /authorized payer fee ceiling/);
  }
  await assert.rejects(bridge['reserveOrdinaryPayer'](a, payer, request, {
    admit, erc20Recovery, erc20Policy: { ...policy, feeBudget: request.gas * request.maxFeePerGas },
  }), /authorized payer fee budget/);
  await assert.rejects(bridge['reserveOrdinaryPayer'](a, payer, request, {
    admit, erc20Recovery, erc20Policy: { ...policy, maxNonce: request.nonce, feeBudget },
  }), /remaining continuation schedule/);
  await assert.rejects(bridge['reserveOrdinaryPayer'](a, payer, request, {
    admit, erc20Recovery, erc20Policy: { ...policy, maxFeePerGas: 60n, feeBudget },
  }), /authorized payer fee budget/);
  assert.equal(admitted, 0);
  await bridge['reserveOrdinaryPayer'](b, payer, request, { admit, erc20Recovery, erc20Policy: { ...policy, maxFeePerGas: 60n, feeBudget: 2n * feeBudget } });
  assert.equal(admitted, 1);
  await assert.rejects(bridge.checkErc20Payer(a, payer), /outstanding ERC20 return/);
});

test('contested ordinary signing checks fallback signed bytes and per-packet fee limits', async () => {
  const { x, bridge, held } = await heldPair();
  const payer = x.payer.address;
  const { chainId, K } = x.cfg;
  const erc20Recovery = admissionFor(x);
  const { record } = await bridge.planReturn(held, recipient, payer, { admission: { erc20Recovery } });
  const first = { ...record, status: 'burned' as const };
  const second = { ...first, returnId: hex(key('other legacy signing envelope')) };
  await bridge.journal.putReturn(first);
  await bridge.journal.putReturn(second);
  const plan = first.recovery!;
  const policy = { ...erc20Recovery.limits, chainId, maxFeePerGas: 127n };
  const { calibration } = erc20Recovery;
  const { advance, settle } = quoteRecoveryGapBatch(K, plan.advanceGaps, calibration, policy)!;
  const run = quoteScheduledRecoveryRuns(held, plan.runCuts, 0, calibration, policy, true);
  const signedBytes = Math.max(advance.signedBytes, settle.signedBytes, ...run.map((quote) => quote.signedBytes));
  const request = { chainId, nonce: 1n, gas: 100_000n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n,
    to: x.cfg.vault, value: 0n, data: new Uint8Array(68) };
  const maxTransactionFee = 2_000_000n;
  assert.ok(quoteErc20Call(request.data.length, request.gas, { ...policy, maxFeePerGas: request.maxFeePerGas, maxTransactionFee }));
  const blocked = { erc20Recovery, admit: async () => assert.fail('fallback refusal must precede admission') };
  await assert.rejects(bridge['reserveOrdinaryPayer'](first, payer, request, {
    ...blocked, erc20Policy: { ...policy, maxFeePerGas: 254n, signedBytes },
  }), /outside the release limits/);
  await assert.rejects(bridge['reserveOrdinaryPayer'](first, payer, request, {
    ...blocked, erc20Policy: { ...policy, maxFeePerGas: request.maxFeePerGas, maxTransactionFee },
  }), /outside the release limits/);
  await bridge['reserveOrdinaryPayer'](second, payer, request, {
    erc20Recovery, admit: async () => {}, erc20Policy: { ...policy, maxFeePerGas: 254n, signedBytes: signedBytes + 1 },
  });
});

test('ordinary takeover migrates local Run fees and preserves the higher replacement fee', async () => {
  const { x, bridge, held } = await heldPair();
  const payer = x.payer.address;
  const { chainId, K } = x.cfg;
  const erc20Recovery = admissionFor(x);
  const { record } = await bridge.planReturn(held, recipient, payer, { admission: { erc20Recovery } });
  const first = { ...record, status: 'burned' as const, executionPayer: hex(payer) };
  const other = { ...record, status: 'burned' as const, returnId: hex(key('other legacy return waits during fee reconciliation')) };
  const journal = bridge.journal;
  await journal.putReturn(first);
  await journal.putReturn(other);
  const request = { chainId, nonce: 1n, gas: 100_000n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n,
    to: x.cfg.vault, value: 0n, data: new Uint8Array(68) };
  const raw = (signer: typeof x.payer, gas: bigint, chain = chainId, nonce = 0n, maxFeePerGas = 10n) =>
    signTx(signer, { ...request, gas, chainId: chain, nonce, maxFeePerGas, to: bytes(x.a.recovery) }).then((signed) => signed.raw);
  const id = `${first.domain.slice(2)}/${first.returnId.slice(2)}`;
  const watermark = `nb2/payer-sends/v1/${chainId}/${toHex(payer)}/${id}`;
  const feeIndex = `nb2/payer-fee-index/v2/${chainId}/${toHex(payer)}/${id}`;
  const legacy = new Journal(journal.store, key('unregistered legacy fee domain'));
  const unregistered = { ...first, ...legacy.base(), returnId: hex(key('unregistered execution return')) };
  const foreign = await raw(x.payer, 200n, chainId + 1n);
  const local = await raw(x.payer, 2n);
  await legacy.putReturn(unregistered);
  await legacy.indexPayerSends(unregistered, [foreign]);
  assert.equal(await journal.store.get(`nb2/domain-chain/v1/${toHex(legacy.domain)}`), null);
  assert.deepEqual(await journal.store.list(`nb2/payer-fee-index/v2/`), []);
  await legacy.registerPayerChain(chainId);
  // The old unscoped marker could have been written by the foreign packet.
  await journal.store.putIf(`nb2/payer-fee-index/v1/${toHex(legacy.domain)}/${unregistered.returnId.slice(2)}`, null, '1');
  await legacy.indexPayerSends(unregistered, [foreign, await raw(new LocalKeySigner(key('different local payer')), 200n)]);
  await assert.rejects(legacy.payerFees(unregistered, chainId, payer, 0n), /local signed fees indexed/);
  await assert.rejects(legacy.preparePayerBroadcast(unregistered, chainId, local), /local signed fees indexed/);
  await assert.rejects(legacy.preparePayerBroadcast(unregistered, chainId, foreign), /belongs to another chain/);
  await legacy.indexPayerSends(unregistered, [local]);
  const lower = await raw(x.payer, 1n);
  await legacy.preparePayerBroadcast(unregistered, chainId, lower);
  assert.deepEqual(await legacy.payerFees(unregistered, chainId, payer, 0n), { prior: 0n, atNonce: 20n });
  await legacy.putReturn({ ...unregistered, status: 'paid' });
  const second = new LocalKeySigner(key('other scoped execution payer'));
  await assert.rejects(legacy.preparePayerSigning(unregistered, chainId, second.address), /bound to execution payer/);
  await assert.rejects(legacy.preparePayerBroadcast(unregistered, chainId, await raw(second, 200n)), /bound to execution payer/);
  const oldOrdinary = { ...unregistered, returnId: hex(key('ordinary-only legacy return')), executionPayer: undefined,
    sends: [{ raw: hex(local), hash: hex(decodeSignedTx(local).hash), nonce: '0', gas: '2', at: '0' }] };
  await legacy.putReturn(oldOrdinary);
  await legacy.preparePayerBroadcast(oldOrdinary, chainId, local);
  assert.deepEqual(await legacy.payerFees(oldOrdinary, chainId, payer, 0n), { prior: 0n, atNonce: 20n });
  const plan = first.recovery!;
  const policy = { ...erc20Recovery.limits, chainId, maxFeePerGas: 20n };
  const attempts = BigInt(plan.ordinary!.attemptsBeforeFallback);
  const fallback = quoteScheduledRecoveryFee(held, K, {
    cuts: plan.runCuts, completedRuns: 1, batch: plan.advanceGaps,
    advances: BigInt(plan.calls) - BigInt(plan.runCuts.length) - attempts - 1n,
  }, erc20Recovery.calibration, policy);
  const ordinaryGas = BigInt(plan.ordinary!.gas);
  const allowance = ordinaryGas * policy.maxFeePerGas;
  const suffix = continuationReserve(fallback, allowance, attempts);
  await journal.indexRecoveryProgress(chainId, first, 1n, { blockNumber: 20n, blockHash: key('finalized local Run') });
  bridge.evm.isFinalizedBlock = async () => true;
  x.finalized(1n);
  const opts = { erc20Recovery, admit: async () => assert.fail('budget refusal must precede admission') };
  assert.equal(await journal.store.get(watermark), null);
  assert.equal(await journal.store.get(feeIndex), null);
  await assert.rejects(bridge['reserveOrdinaryPayer'](first, payer, request, {
    ...opts, erc20Policy: { ...policy, feeBudget: suffix },
  }), /local signed fees indexed/);
  await journal.indexPayerSends(first, []);
  assert.equal(await journal.store.get(feeIndex), null);
  await journal.indexPayerSends(first, [await raw(x.payer, 200n, chainId + 1n)]);
  assert.equal(await journal.store.get(feeIndex), null);
  await journal.store.putIf(watermark, null, '0');
  await journal.indexPayerSends(first, []);
  assert.equal(await journal.store.get(feeIndex), null);
  await assert.rejects(bridge['reserveOrdinaryPayer'](first, payer, request, {
    ...opts, erc20Policy: { ...policy, feeBudget: suffix + 20n },
  }), /local signed fees indexed/);
  await journal.indexPayerSends(first, await Promise.all([
    raw(x.payer, 2n), raw(x.payer, 1n), raw(new LocalKeySigner(key('peer Run signer')), 200n),
    raw(x.payer, 200n, chainId + 1n), raw(x.payer, 200n, chainId, request.nonce),
  ]));
  assert.equal(await journal.store.get(feeIndex), '1');
  assert.deepEqual(await journal.payerFees(first, chainId, payer, request.nonce), { prior: 20n, atNonce: 2000n });
  await assert.rejects(bridge['reserveOrdinaryPayer'](first, payer, request, {
    ...opts, erc20Policy: { ...policy, feeBudget: suffix + 19n },
  }), /authorized payer fee budget/);
  const higherBid = 30n;
  const oldFee = ordinaryGas * higherBid;
  await journal.retainPayerSend(first, await raw(x.payer, ordinaryGas, chainId, request.nonce, higherBid));
  const required = suffix - allowance + oldFee;
  await assert.rejects(bridge['reserveOrdinaryPayer'](first, payer, request, {
    ...opts, erc20Policy: { ...policy, feeBudget: suffix + 20n },
  }), /authorized payer fee budget/);
  await assert.rejects(bridge['reserveOrdinaryPayer'](first, payer, request, {
    ...opts, erc20Policy: { ...policy, feeBudget: required + 19n },
  }), /authorized payer fee budget/);
  await bridge['reserveOrdinaryPayer'](first, payer, request, {
    erc20Recovery, admit: async (_req, _prior, fee) => assert.equal(fee, required),
    erc20Policy: { ...policy, feeBudget: required + 20n },
  });
});

test('a finalized Run retains unused ordinary retry nonces and fees', async () => {
  const { x, bridge, held } = await heldPair();
  const payer = x.payer.address;
  const chainId = x.cfg.chainId;
  const { record } = await bridge.planReturn(held, recipient, payer, { admission: { erc20Recovery: admissionFor(x) } });
  const plan = { ...record.recovery!, calls: '10', totalFee: '120',
    envelope: { ...record.recovery!.envelope!, maxFeePerGas: '1' },
    ordinary: { ...record.recovery!.ordinary!, gas: '10', maxFeePerGas: '1', attemptsBeforeFallback: '2' } };
  const a = { ...record, status: 'burned' as const, recovery: plan };
  const b = { ...a, returnId: hex(key('other return retains ordinary retries')) };
  const journal = bridge.journal;
  await journal.putReturn(a);
  await journal.putReturn(b);
  await journal.indexRecoveryProgress(chainId, b, 1n, { blockNumber: 20n, blockHash: key('run checkpoint') }, 80n);
  const other = () => journal.checkReturnPayer(chainId, payer, a.returnId, false, {
    mode: 'drain', finalizedBlock: async () => true, finalizedNonce: async () => 2n,
  });
  assert.equal((await other()).calls, 9n);
  assert.equal((await other()).fees, 100n);
  const send = await signTx(x.payer, { chainId, nonce: 1n, gas: 10n, maxFeePerGas: 1n, maxPriorityFeePerGas: 0n,
    to: x.cfg.vault, value: 0n, data: new Uint8Array(68) });
  await journal.putReturn({ ...b, sends: [bridge['sendRecord'](send)] });
  assert.equal((await other()).calls, 8n);
  assert.equal((await other()).fees, 90n);
});

test('ordinary admission cannot mutate the request that the payer journal fences and signs', async () => {
  const { x, bridge, held, store } = await heldPair();
  const payer = x.payer.address;
  const erc20Recovery = admissionFor(x);
  const { record } = await bridge.planReturn(held, recipient, payer, { admission: { erc20Recovery } });
  const a = { ...record, status: 'burned' as const };
  const b = { ...a, returnId: hex(key('contested ordinary request')) };
  await bridge.journal.putReturn(a);
  await bridge.journal.putReturn(b);
  const data = new Uint8Array(68).fill(17);
  const nonce = await bridge.evm.nonce(payer);
  const fees = await bridge.evm.fees();
  const bid = 2n * fees.baseFee + fees.priority;
  let admitted = 0;
  const signer = { address: payer, signTransaction: async (request: Parameters<typeof x.payer.signTransaction>[0]) => {
    assert.equal(request.nonce, nonce);
    assert.equal(request.maxFeePerGas, bid);
    assert.deepEqual(request.data, data);
    assert.deepEqual(request.to, x.cfg.vault);
    const reservation = await store.get(`nb2/payer/v1/${x.cfg.chainId}/${toHex(payer)}`);
    assert.ok(reservation?.endsWith(`#nonce:${nonce}`));
    return x.payer.signTransaction(request);
  } };
  const tx = await bridge['signed'](signer, x.cfg.vault, data, 0n, 100_000n, (request) =>
    bridge['reserveOrdinaryPayer'](a, payer, request, {
      erc20Recovery, erc20Policy: { ...erc20Recovery.limits, feeBudget: BigInt(a.recovery!.totalFee) },
      admit: async (copy) => {
        admitted++;
        copy.nonce += 1n;
        copy.maxFeePerGas *= 2n;
        copy.maxPriorityFeePerGas += 1n;
        copy.data.fill(0);
        copy.to.fill(0);
      },
    }));
  assert.equal(admitted, 1);
  assert.equal(tx.request.nonce, nonce);
  assert.equal(tx.request.maxFeePerGas, bid);
  assert.deepEqual(tx.request.data, data);
});

test('two SDK attempts can both decline without releasing the payer while either still owns it', async () => {
  const { x, bridge, owner, firstHeld, held, store } = await heldPair();
  const peer = await NativeBridgeV2.open({ ...x.options(), journal: store });
  const admission = { erc20Recovery: admissionFor(x) };
  const a = await bridge.planReturn(firstHeld, recipient, x.payer.address, { admission });
  const b = await peer.planReturn(held, recipient, x.payer.address, { admission });
  function decliningSigner() {
    let entered!: () => void;
    let release!: () => void;
    const signing = new Promise<void>((resolve) => { entered = resolve; });
    const wait = new Promise<void>((resolve) => { release = resolve; });
    const signer = { ...owner, signUnlock: async () => {
      entered();
      await wait;
      throw new WalletError('SigningDeclined');
    } };
    return { signer, signing, release };
  }
  const first = decliningSigner();
  const retry = decliningSigner();
  const initial = assert.rejects(bridge.burn(a.returnId, first.signer, admission), { reason: 'SigningDeclined' });
  await first.signing;
  const second = assert.rejects(peer.burn(a.returnId, retry.signer, admission), { reason: 'SigningDeclined' });
  await retry.signing;
  first.release();
  await initial;
  await assert.rejects(bridge.burn(b.returnId, owner, admission), /outstanding ERC20 return/);
  retry.release();
  await second;
  assert.equal((await bridge.journal.ret(a.record.returnId))!.status, 'planned');
  await bridge.burn(b.returnId, owner, admission);
});
