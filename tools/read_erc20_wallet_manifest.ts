/** Read a candidate's exact manifest bytes without opening a wallet or contacting a chain. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { addressWord, redeemCalldataLength } from '../packages/native-bridge-plugin/src/nb2/abi.js';
import { otherBytes } from '../packages/native-bridge-plugin/src/nb2/bridge.js';
import { buildParams, configIdentities, decodeConfig, domainOf } from '../packages/native-bridge-plugin/src/nb2/config.js';
import { HE } from '../packages/native-bridge-plugin/src/nb2/crypto.js';
import { erc20Create2 } from '../packages/native-bridge-plugin/src/nb2/erc20.js';
import { quoteErc20Call, quoteOrdinaryExecution, quoteRecovery, quoteRunCut, type RecoveryCalibration, type RecoveryLimits } from '../packages/native-bridge-plugin/src/nb2/recovery-cost.js';
import { capacityPreflight } from '../packages/native-bridge-plugin/src/nb2/rules.js';
import { gapProofLen } from '../packages/native-bridge-plugin/src/nb2/segment.js';
import { MAX_TRANSFER_PAIR } from '../packages/native-bridge-plugin/src/nb2/token.js';
import { hx, pinsOf, type Wallet } from '../wallet/core.js';
import { readOrdinaryRanges, readRecoveryRelease } from '../wallet/recovery.js';

function checkHex(value: unknown, label: string, size?: number): void {
  assert(typeof value === 'string' && /^0x(?:[0-9a-f]{2})+$/.test(value)
    && (size === undefined || value.length === 2 + size * 2) && /[1-9a-f]/.test(value.slice(2)), `invalid ${label}`);
}

function checkRunRanges(calibration: RecoveryCalibration, limits: RecoveryLimits): void {
  const pageBytes = 4096;
  for (const range of calibration.ranges) {
    const { entry, pages, operations, receiptBytes } = range.max;
    if (entry !== 'run') continue;
    assert(Number.isSafeInteger(operations) && operations >= 1 && operations <= 16 &&
      Number.isSafeInteger(pages) && pages >= 1 && pages <= 32, 'invalid ERC20 manifest Run range');
    const isolated = { ...calibration, ranges: [range] };
    assert(quoteRecovery(range.max, isolated, limits, true), 'ERC20 wallet manifest Run range exceeds wallet limits');
    const checkCut = (resume: boolean) => {
      const first = resume ? pageBytes : 0;
      const end = first + pages * pageBytes;
      const spans = Array.from({ length: operations }, (_, i) => ({
        start: first + i, end: i === operations - 1 ? end : first + i + 1, claims: !resume && i === 0 ? 2 : 1,
      }));
      if (resume) spans.unshift({ start: 14, end: first, claims: 2 });
      // Full opened pages in a lineage with a later terminal pair. The SDK prices witnesses and the predecessor.
      assert(quoteRunCut(spans, Number(resume), spans.length, end + MAX_TRANSFER_PAIR + 4, isolated, limits, true),
        `ERC20 wallet manifest cannot quote ${resume ? 'Resume' : 'Start'} with ${operations} operations`);
    };
    if (range.minReceiptBytes === 0) checkCut(false);
    if (range.minReceiptBytes <= 1 && receiptBytes === 65_536) {
      checkCut(true);
      if (operations === 1) {
        // Admission must also quote the hypothetical terminal transfer on its own at an unaligned start.
        const start = 2 * pageBytes - 1;
        const end = start + MAX_TRANSFER_PAIR + 4;
        assert(quoteRunCut([{ start: 14, end: start, claims: 2 }, { start, end, claims: 1 }], 1, 2, end, isolated, limits, true),
          'ERC20 wallet manifest cannot quote the terminal Resume');
      }
    }
  }
}

function readManifest(manifest: Wallet['release']) {
  const raw = manifest.pins;
  assert(raw && raw.build === 'production' && raw.stateReadOnly === false, 'production wallet pins require stateReadOnly=false');
  assert(raw.maxEncodedTxBytes === 131_072 || raw.maxEncodedTxBytes === 524_288, 'invalid production maxEncodedTxBytes');
  checkHex(raw.gamma, 'gamma');
  checkHex(raw.vaultRuntimeCodeHash, 'vault runtime hash', 32);
  for (const field of ['returnReserveSegments', 'deploymentBlock'] as const) {
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

  const limits: RecoveryLimits = { gas: pins.userGasLimit, calldataBytes: 393_216, signedBytes: Number(pins.maxEncodedTxBytes),
    chainId: cfg.chainId, maxNonce: 0n, maxFeePerGas: 1n, maxPriorityFeePerGas: 0n, balance: 0n, feeBudget: 0n, worstCaseEnvelope: true };
  checkRunRanges(calibration, limits);
  const ordinary = (readOrdinaryRanges(manifest) ?? []).map((range) => {
    assert(range.execution > 0n && range.maxGaps <= 393_216n && range.maxEvidenceBytes <= 393_216, 'invalid ordinary gas range');
    const shape = { evidenceBytes: range.maxEvidenceBytes, lineage: [], pendingTransactions: range.maxOperations, proofs: range.maxGaps, K: cfg.K };
    const history = range.maxGaps === 0n ? 0 : 32 + Number(range.maxGaps) * gapProofLen(cfg.K);
    const calldataBytes = redeemCalldataLength(range.maxEvidenceBytes, history);
    const submittedGas = quoteOrdinaryExecution(shape, [range], pins.gasReserve);
    assert(submittedGas !== null, 'ERC20 wallet manifest cannot quote ordinary settlement');
    const bid = quoteErc20Call(calldataBytes, submittedGas, limits);
    assert(bid, 'ERC20 wallet manifest ordinary range exceeds wallet limits');
    capacityPreflight({ lMax: pins.maxEncodedTxBytes, lT: BigInt(range.maxEvidenceBytes), lO: BigInt(otherBytes(range.maxEvidenceBytes)),
      K: cfg.K, a: 0n, cObs: range.maxGaps, reserve: 0n, gasAt: () => submittedGas, userGasLimit: pins.userGasLimit });
    return { calldataBytes, executionGas: range.execution, submittedGas, signedBytes: bid.signedBytes, maxGaps: range.maxGaps };
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
