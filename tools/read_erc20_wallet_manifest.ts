/** Read a candidate's exact manifest bytes without opening a wallet or contacting a chain. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { addressWord, redeemCalldataLength } from '../packages/native-bridge-plugin/src/nb2/abi.js';
import { buildParams, configIdentities, decodeConfig, domainOf } from '../packages/native-bridge-plugin/src/nb2/config.js';
import { HE } from '../packages/native-bridge-plugin/src/nb2/crypto.js';
import { erc20Create2 } from '../packages/native-bridge-plugin/src/nb2/erc20.js';
import { quoteOrdinaryExecution } from '../packages/native-bridge-plugin/src/nb2/recovery-cost.js';
import { gapProofLen } from '../packages/native-bridge-plugin/src/nb2/segment.js';
import { hx, pinsOf, type Wallet } from '../wallet/core.js';
import { readOrdinaryRanges, readRecoveryRelease } from '../wallet/recovery.js';

function checkHex(value: unknown, label: string, size?: number): void {
  assert(typeof value === 'string' && /^0x(?:[0-9a-f]{2})+$/.test(value)
    && (size === undefined || value.length === 2 + size * 2) && /[1-9a-f]/.test(value.slice(2)), `invalid ${label}`);
}

function readManifest(manifest: Wallet['release']) {
  const raw = manifest.pins;
  assert(raw && raw.build === 'production' && typeof raw.stateReadOnly === 'boolean', 'invalid production wallet pins');
  checkHex(raw.gamma, 'gamma');
  checkHex(raw.vaultRuntimeCodeHash, 'vault runtime hash', 32);
  for (const field of ['maxEncodedTxBytes', 'returnReserveSegments', 'deploymentBlock'] as const) {
    const value = raw[field];
    assert(typeof value === 'number' && Number.isSafeInteger(value) && value > 0, `invalid ${field}`);
  }
  for (const field of ['userGasLimit', 'gasReserve'] as const) {
    const value = raw[field];
    assert(typeof value === 'string' && /^(0|[1-9][0-9]{0,77})$/.test(value), `invalid ${field}`);
  }
  const activation = raw.erc20 as Record<string, unknown> | undefined;
  assert(activation && typeof activation.fundingQualified === 'boolean', 'missing ERC20 activation pins');
  checkHex(activation.factory, 'factory address', 20);
  for (const field of ['factoryRuntimeHash', 'vaultInitcodeHash', 'recoveryInitcodeHash', 'activationTx'] as const) {
    checkHex(activation[field], field, 32);
  }

  const pins = pinsOf(manifest);
  const cfg = decodeConfig(pins.gamma, buildParams(pins.build));
  const { erc20 } = cfg;
  assert(erc20 && pins.erc20, 'expected ERC20 configuration in gamma');
  assert.deepEqual({ asset: cfg.asset, ty: cfg.ty, aid: cfg.aid }, configIdentities(cfg), 'gamma asset identities mismatch');
  const { deployment, calibration, signingWindows, backlog } = readRecoveryRelease(manifest, pins.vaultRuntimeCodeHash, domainOf(pins.gamma));
  assert(signingWindows, 'missing recovery signing windows');
  assert.deepEqual(deployment.salt, erc20.generation, 'recovery salt differs from gamma');
  assert.deepEqual(deployment.pins, erc20.pins, 'recovery pins differ from gamma');
  const tokenWord = addressWord(erc20.token);
  assert.deepEqual(cfg.vault, erc20Create2(pins.erc20.factory, tokenWord, pins.erc20.vaultInitcodeHash), 'vault CREATE2 address mismatch');
  assert.deepEqual(deployment.recovery, erc20Create2(pins.erc20.factory, HE(tokenWord), pins.erc20.recoveryInitcodeHash), 'recovery CREATE2 address mismatch');

  const ordinary = (readOrdinaryRanges(manifest) ?? []).map((range) => {
    assert(range.execution > 0n && range.maxGaps <= 393_216n && range.maxEvidenceBytes <= 393_216, 'invalid ordinary gas range');
    const shape = { evidenceBytes: range.maxEvidenceBytes, lineage: [], pendingTransactions: range.maxOperations, proofs: range.maxGaps, K: cfg.K };
    const history = range.maxGaps === 0n ? 0 : 32 + Number(range.maxGaps) * gapProofLen(cfg.K);
    return { calldataBytes: redeemCalldataLength(range.maxEvidenceBytes, history), executionGas: range.execution,
      submittedGas: quoteOrdinaryExecution(shape, [range], pins.gasReserve) };
  });
  return {
    fundingQualified: pins.erc20.fundingQualified, gasReserve: pins.gasReserve, userGasLimit: pins.userGasLimit,
    maxEncodedTxBytes: pins.maxEncodedTxBytes, returnReserveSegments: pins.returnReserveSegments,
    semanticProfileSha256: hx(cfg.semanticProfileHash).slice(2),
    deployment: { chainId: cfg.chainId, executionGenesis: hx(cfg.executionGenesis), rootPin: hx(cfg.rootGenesis),
      vault: hx(cfg.vault), token: hx(erc20.token), recovery: hx(deployment.recovery), pins: hx(deployment.pins),
      vaultRuntimeHash: hx(pins.vaultRuntimeCodeHash), recoveryRuntimeHash: hx(deployment.runtimeHash),
      gammaSha256: createHash('sha256').update(pins.gamma).digest('hex') },
    signingWindows, backlog, ranges: calibration.ranges, ordinary,
  };
}

try {
  const manifest = readManifest(JSON.parse(readFileSync(0, 'utf8')));
  process.stdout.write(JSON.stringify(manifest, (_, value) => typeof value === 'bigint' ? String(value) : value));
} catch (error) {
  process.stderr.write(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
