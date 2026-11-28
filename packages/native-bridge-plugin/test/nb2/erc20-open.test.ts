import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { gunzipSync } from 'node:zlib';
import { toHex } from '../../src/bytes.js';
import { addressWord, decodeBytesReturn } from '../../src/nb2/abi.js';
import { ERC20_PROFILE_HASH, IMPORTED_TIP_PROFILE_HASH, NativeBridgeV2, type ReturnAdmission } from '../../src/nb2/bridge.js';
import { ascii, u256 } from '../../src/nb2/cbor.js';
import { decodeConfig, PRODUCTION_PARAMS } from '../../src/nb2/config.js';
import { HE } from '../../src/nb2/crypto.js';
import { decodeReceiptBacking, depositedData, TOPIC } from '../../src/nb2/deposit.js';
import { signTx } from '../../src/nb2/evm.js';
import { preflightRecovery, type RecoveryCalibrationRange, type RecoveryShape } from '../../src/nb2/recovery-cost.js';
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
  let probes = 0;
  const rpc: JsonRpc = {
    async call<T>(method: string, params: unknown[]): Promise<T> {
      if (method === 'eth_getCode' && typeof params[0] === 'string') {
        const runtime = deployment.code[params[0].toLowerCase()];
        if (runtime) return runtime as T;
      }
      if (method === 'eth_getBlockByNumber' && params[0] === '0x0') return deployment.genesis as T;
      if (method === 'eth_call') {
        const { to, data, gas } = params[0] as { to: string; data: string; gas?: string };
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
  return { agg, a, cfg, call, payer, tip, activationRound, options, blockRecipient: () => { preview = 'blocked'; }, probes: () => probes };
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

test('the second deposit in one certified receipt mints, and each new burn requires a continuation quote and fresh probe', async () => {
  const x = await world();
  const bridge = await NativeBridgeV2.open(x.options());
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

  const recipient = bytes('0x' + 'ab'.repeat(20));
  let ordinaryChecks = 0;
  let continuationChecks = 0;
  let feeBudget = 16_000_000n;
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
  const admission: ReturnAdmission = {
    ordinaryEnvelope: { encodedBytes: 524_288n, gas: 24_000_000n, gasFor: () => 1_000_000n },
    checkOrdinary: async (_, gas) => {
      const fees = await bridge.evm.fees();
      const cost = gas * (2n * fees.baseFee + fees.priority);
      assert.ok(cost > 0n && cost <= feeBudget && cost <= await bridge.evm.balance(x.payer.address));
      ordinaryChecks++;
    },
    recover: async (_, ordinary) => {
      continuationChecks++;
      const plan = await preflightRecovery(x.options().pins.gamma, held, x.tip.trust, PRODUCTION_PARAMS, graph, { ...graph, ranges }, {
        signedBytes: 524_288, calldataBytes: 393_216, gas: 24_000_000n, chainId: x.cfg.chainId,
        maxNonce: 255n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n, balance: 10n ** 20n, feeBudget,
      }, {
        signedStart: 0n, observed: 0n, duringProgress: 3n, peakSeals: 1n, elapsedMs: 1000n,
        receiptP99Ms: 1000n, advancePeakSeals: 1n, finalInclusionMs: 25n, finalPeakSeals: 1n, qualifiedForMs: 200_000n,
      }, undefined, { feeWindowMs: 400_000n, progressWindowMs: 100_000n, advanceWindowMs: 2000n,
        ordinary: ordinary && { ...ordinary, attemptsBeforeFallback: 1n, inclusionMs: 1000n } });
      return { generation: hex(graph.salt), calls: String(BigInt(plan.run.length) + plan.advance.calls + 1n),
        totalFee: String(plan.totalFee), runCuts: plan.run.map((cut) => cut.shape.operations), advanceGaps: plan.advance.quote.shape.gaps,
        ordinary: ordinary && { gas: String(ordinary.gas), calldataBytes: ordinary.calldataBytes, maxFeePerGas: '10', attemptsBeforeFallback: '1' },
        observed: '0', receiptP99Ms: '1000', finalInclusionMs: '25', qualifiedForMs: '200000' };
    },
  };
  await assert.rejects(bridge.planReturn(held, recipient, x.payer.address, { admission }), /insufficient authorized fee budget/);
  assert.equal(ordinaryChecks, 1);
  assert.equal(continuationChecks, 1);
  feeBudget = 10n ** 20n;
  const planned = await bridge.planReturn(held, recipient, x.payer.address, { admission });
  const before = x.agg.calls;
  x.blockRecipient();
  await assert.rejects(bridge.burn(planned.returnId, owner, admission), { reason: 'RecipientRefused' });
  assert.equal(x.probes(), 3);
  assert.equal((await bridge.journal.retForUpdate(hex(planned.returnId)))?.status, 'planned');
  assert.equal(x.agg.calls, before);
});
