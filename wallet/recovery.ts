/** Durable, key-independent NB2-C return continuation for the reference wallet. */
import { randomBytes } from 'node:crypto';
import { existsSync, linkSync, lstatSync, readFileSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { eq } from '../packages/native-bridge-plugin/src/bytes.js';
import {
  AmbiguousBroadcast, CERTIFICATION_DEPTH, FAILURE_PROOF_READS, VANISHED_CLAIM_HORIZON, ProofUnavailable, EvmReader, HttpJsonRpc, Nb2Error, RpcError, RecoveryAuthority, RecoverySession, TOPIC, WalletError,
  buildParams, checkRemainingRecoveryRuns, decodeSignedTx, evidenceOf, preflightRecovery, quoteRecovery, quoteRecoveryGapBatch, recoveryCatchUpCalls, recoveryGeneration,
  payerNonceLimit, quoteErc20Call, quoteOrdinaryExecution, recoveryRpcSource, replacementBid, signTx, verifyRecoveryDependencies, type PayerCommitments, type Erc20ReturnRecovery, type Erc20SigningBounds,
  type OrdinaryCalibrationRange, type GapPrior, type RecoveryBacklog, type RecoveryCalibration,
  type RecoveryDeployment, type RecoveryEvent, type RecoveryLimits, type RecoveryQuote, type RecoveryReceipt,
  type ReturnAdmission, type ReturnRecord, type ReconcileResult, type TrustInput, type SendRecord, type RedeemOptions, type ReturnEvidence,
} from '../packages/native-bridge-plugin/src/nb2/index.js';
import { HE } from '../packages/native-bridge-plugin/src/nb2/crypto.js';
import { beInt } from '../packages/native-bridge-plugin/src/nb2/cbor.js';
import { fsyncDir, hx, readRetrying, unhex, writeDurable, type Wallet } from './core.js';

const uint = (s: unknown): bigint => {
  if (typeof s !== 'string' || !/^(0|[1-9][0-9]*)$/.test(s)) throw new Error('expected an unsigned decimal string');
  return BigInt(s);
};
function bytes(s: unknown, n?: number): Uint8Array {
  if (typeof s !== 'string' || !/^0x(?:[a-f0-9]{2})*$/.test(s)) throw new Error('expected lowercase hex');
  const value = unhex(s);
  if (n !== undefined && value.length !== n) throw new Error(`expected ${n} bytes`);
  return value;
}

export interface PayerPolicy {
  gas: bigint;
  signedBytes: number;
  calldataBytes: number;
  maxNonce: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  maxTransactionFee?: bigint;
  feeBudget: bigint;
  /** Qualified duration of the fee ceiling starting at the signing check. */
  feeWindowMs?: bigint;
  ordinaryAttemptsBeforeFallback?: bigint;
  archives: string[];
}

export function readPayerPolicy(path: string): PayerPolicy {
  const p = JSON.parse(readFileSync(path, 'utf8'));
  if (!Number.isSafeInteger(p.signedBytes) || p.signedBytes <= 0 || !Number.isSafeInteger(p.calldataBytes)
    || p.calldataBytes <= 0 || (p.archives !== undefined && (!Array.isArray(p.archives) || p.archives.some((url: unknown) => typeof url !== 'string')))) {
    throw new Error('invalid return payer policy');
  }
  return { gas: uint(p.gas), signedBytes: p.signedBytes, calldataBytes: p.calldataBytes, maxNonce: uint(p.maxNonce),
    maxFeePerGas: uint(p.maxFeePerGas), maxPriorityFeePerGas: uint(p.maxPriorityFeePerGas),
    maxTransactionFee: p.maxTransactionFee === undefined ? undefined : uint(p.maxTransactionFee),
    feeBudget: uint(p.feeBudget), feeWindowMs: p.feeWindowMs === undefined ? undefined : uint(p.feeWindowMs),
    ordinaryAttemptsBeforeFallback: p.ordinaryAttemptsBeforeFallback === undefined ? undefined : uint(p.ordinaryAttemptsBeforeFallback),
    archives: p.archives ?? [] };
}

interface ReleaseRecovery {
  deployment: RecoveryDeployment;
  generation: Uint8Array;
  calibration: RecoveryCalibration;
  backlog: Omit<RecoveryBacklog, 'signedStart' | 'observed'>;
  signingWindows?: Omit<Erc20SigningBounds, 'feeWindowMs' | 'ordinary'> & { ordinaryInclusionMs?: bigint };
}

function recoveryRelease(w: Wallet): ReleaseRecovery {
  const r = w.release.recovery as {
    salt: string; address: string; runtimeHash: string; pins: string;
    ranges: (Omit<RecoveryCalibration['ranges'][number], 'execution'> & { execution: string })[];
    backlog: Record<keyof Omit<RecoveryBacklog, 'signedStart' | 'observed'>, string>;
    signingWindows?: { progressWindowMs: string; maxRunCalls: number; advanceWindowMs: string; ordinaryInclusionMs?: string };
  } | undefined;
  if (!r || !Array.isArray(r.ranges) || !r.backlog) throw new Nb2Error('CapacityPreflight', 'qualified recovery release is required');
  const deployment = { salt: bytes(r.salt, 32), recovery: bytes(r.address, 20), runtimeHash: bytes(r.runtimeHash, 32),
    pins: bytes(r.pins, 32), vaultRuntimeHash: w.pins.vaultRuntimeCodeHash };
  const { pins, runtimeHash, vaultRuntimeHash } = deployment;
  const calibration = { pins, runtimeHash, vaultRuntimeHash,
    ranges: r.ranges.map(({ minReceiptBytes, max, execution }) => ({ minReceiptBytes, max, execution: uint(execution) })) };
  const b = r.backlog;
  const windows = r.signingWindows;
  const bound = (value: unknown): bigint => {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
      throw new Nb2Error('CapacityPreflight', 'missing or invalid recovery timing or arrival bound');
    }
    return BigInt(value);
  };
  return { deployment, calibration, generation: recoveryGeneration(deployment.salt, w.bridge.domain),
    signingWindows: windows && { progressWindowMs: bound(windows.progressWindowMs), maxRunCalls: windows.maxRunCalls, advanceWindowMs: bound(windows.advanceWindowMs),
      ordinaryInclusionMs: windows.ordinaryInclusionMs === undefined ? undefined : bound(windows.ordinaryInclusionMs) },
    backlog: { duringProgress: bound(b.duringProgress), peakSeals: bound(b.peakSeals), elapsedMs: bound(b.elapsedMs), receiptP99Ms: bound(b.receiptP99Ms),
      advancePeakSeals: bound(b.advancePeakSeals), finalInclusionMs: bound(b.finalInclusionMs), finalPeakSeals: bound(b.finalPeakSeals),
      qualifiedForMs: bound(b.qualifiedForMs) } };
}

async function checkGraph(w: Wallet, release: ReleaseRecovery): Promise<void> {
  const { evm, cfg } = w.bridge;
  const { recovery, runtimeHash, pins, vaultRuntimeHash } = release.deployment;
  const getter = (name: string) => HE(new TextEncoder().encode(name + '()')).subarray(0, 4);
  const [chainId, gamma, vault, ordinary, code, address, runtime, generation, installedPins] = await Promise.all([
    evm.chainId(), evm.vaultConfig(cfg.vault), evm.code(cfg.vault), evm.code(cfg.verifier), evm.code(recovery),
    evm.call(cfg.vault, getter('RECOVERY')), evm.call(cfg.vault, getter('RECOVERY_RUNTIME')),
    evm.call(cfg.vault, getter('RECOVERY_GENERATION')), evm.call(cfg.vault, getter('RECOVERY_PINS')),
  ]);
  const contractAddress = (value: Uint8Array) => value.length === 32 && beInt(value.subarray(0, 12)) === 0n
    ? value.subarray(12) : new Uint8Array();
  if (chainId !== cfg.chainId || !eq(gamma, w.pins.gamma) || !eq(HE(vault), vaultRuntimeHash!) ||
    !eq(HE(ordinary), cfg.verifierCodeHash) || !eq(HE(code), runtimeHash) ||
    !eq(contractAddress(address), recovery) ||
    !eq(runtime, runtimeHash) || !eq(generation, release.generation) || !eq(installedPins, pins)) {
    throw new WalletError('BadDeployment', 'installed recovery graph differs from the authenticated release');
  }
  try { await verifyRecoveryDependencies(evm, recovery); }
  catch (e) {
    if (e instanceof Nb2Error && e.rule === 'CapacityPreflight') throw new WalletError('BadDeployment', e.detail, e);
    throw e;
  }
}

interface FeeReservations { total: bigint; attempts: { nonce: bigint; fee: bigint }[] }

async function limitsOf(w: Wallet, p: PayerPolicy, payer: Uint8Array, reserved?: FeeReservations, replacementNonce?: bigint,
  otherReturns: PayerCommitments = { fees: 0n, calls: 0n }): Promise<RecoveryLimits & { currentBid: bigint }> {
  const evm = w.bridge.evm;
  const block = reserved?.attempts.length ? await evm.saneHead() : undefined;
  const [balance, minedNonce, nonce, fees, pendingBalance, finalizedBalance] = await Promise.all([
    evm.balance(payer, block), block === undefined ? 0n : evm.nonce(payer, block), evm.nonce(payer), evm.fees(),
    w.bridge.cfg.erc20 ? evm.balance(payer, 'pending') : undefined,
    otherReturns.finalizedNonce === undefined ? undefined : evm.balance(payer, 'finalized'),
  ]);
  const outstanding = reserved?.attempts.reduce((sum, tx) => tx.nonce >= minedNonce ? sum + tx.fee : sum, 0n) ?? 0n;
  const spent = reserved?.total ?? 0n;
  const currentBid = 2n * fees.baseFee + fees.priority;
  const maxNonce = payerNonceLimit(p.maxNonce, otherReturns);
  const currentNonce = replacementNonce ?? nonce;
  if (currentNonce > maxNonce || (otherReturns.finalizedNonce !== undefined && currentNonce < otherReturns.finalizedNonce)
    || currentBid > p.maxFeePerGas || fees.priority > p.maxPriorityFeePerGas || spent > p.feeBudget) {
    throw new Nb2Error('CapacityPreflight', 'current payer nonce, bids or remaining budget exceed the declared limits');
  }
  const free = balance - outstanding;
  const visible = pendingBalance !== undefined && pendingBalance < free ? pendingBalance : free;
  const spendable = (finalizedBalance !== undefined && finalizedBalance < visible ? finalizedBalance : visible) - otherReturns.fees;
  return { ...p, maxNonce, gas: p.gas < w.pins.userGasLimit ? p.gas : w.pins.userGasLimit,
    signedBytes: Math.min(p.signedBytes, Number(w.pins.maxEncodedTxBytes)), chainId: w.bridge.cfg.chainId, worstCaseEnvelope: !w.bridge.cfg.erc20,
    balance: spendable > 0n ? spendable : 0n, currentBid, feeBudget: p.feeBudget - spent };
}

async function otherErc20Reserves(w: Wallet, rec: ReturnRecord, payer: Uint8Array): Promise<PayerCommitments | undefined> {
  if (w.bridge.cfg.erc20) return w.bridge.checkErc20Payer(rec, payer);
}

/** Reserve the greatest fee at each payer nonce. At most one replacement can be mined. */
function reservedFees(w: Wallet, rec: ReturnRecord, payer: Uint8Array, ordinary: readonly SendRecord[] = rec.sends, replacing?: bigint): FeeReservations {
  const recovery = loadRecovery(w, rec);
  const raw = [...ordinary.map((send) => send.raw), ...(recovery?.attempts ?? []), ...(recovery?.superseded ?? []), ...(recovery?.replacedSettlements ?? [])];
  if (recovery?.pending) raw.push(recovery.pending.raw);
  if (recovery?.settled?.submitted) raw.push(recovery.settled.submitted.raw);
  const byNonce = new Map<bigint, bigint>();
  const legacy = uint(recovery?.fees ?? '0');
  for (const signed of raw) {
    const { request, from } = decodeSignedTx(bytes(signed));
    if (!eq(from, payer) || request.nonce === replacing) continue;
    const fee = request.gas * request.maxFeePerGas;
    if (fee > (byNonce.get(request.nonce) ?? 0n)) byNonce.set(request.nonce, fee);
  }
  const attempts = Array.from(byNonce, ([nonce, fee]) => ({ nonce, fee }));
  return { total: attempts.reduce((sum, tx) => sum + tx.fee, legacy), attempts };
}

function recoveryEmitter(w: Wallet): Uint8Array | undefined {
  return w.release.recovery === undefined ? undefined : recoveryRelease(w).deployment.recovery;
}

export function ordinaryPayout(w: Wallet, rec: ReturnRecord, policy?: PayerPolicy): RedeemOptions {
  const recovery = recoveryEmitter(w);
  if (!policy) return { recovery };
  return {
    envelope: ordinaryEnvelope(w, policy),
    archives: readers(w, policy),
    recovery,
    admit: async (req, prior) => {
      if (w.release.recovery !== undefined) await checkGraph(w, recoveryRelease(w));
      const limits = await limitsOf(w, policy, w.signer.address, reservedFees(w, rec, w.signer.address, prior, req.nonce), req.nonce,
        await otherErc20Reserves(w, rec, w.signer.address));
      const fee = req.gas * req.maxFeePerGas;
      if (w.bridge.cfg.erc20 && !quoteErc20Call(req.data.length, req.gas, limits)) {
        throw new Nb2Error('CapacityPreflight', 'ordinary payment is outside the ERC20 admission limits');
      }
      if (req.gas > limits.gas || req.nonce > limits.maxNonce || req.maxFeePerGas > limits.maxFeePerGas ||
        req.maxPriorityFeePerGas > limits.maxPriorityFeePerGas || req.data.length > limits.calldataBytes ||
        (!w.bridge.cfg.erc20 && req.data.length + 256 > limits.signedBytes) || fee > limits.balance || fee > limits.feeBudget ||
        (limits.maxTransactionFee !== undefined && fee > limits.maxTransactionFee)) {
        throw new Nb2Error('CapacityPreflight', 'ordinary payment exceeds the remaining payer limits');
      }
    },
  };
}

function ordinaryRanges(w: Wallet): OrdinaryCalibrationRange[] | undefined {
  const release = w.release.recovery as { ordinaryRanges?: {
    maxEvidenceBytes: number; maxOperations: number; maxGaps: string; execution: string;
  }[] } | undefined;
  if (release?.ordinaryRanges === undefined) return undefined;
  return release.ordinaryRanges.map(({ maxEvidenceBytes, maxOperations, maxGaps, execution }) => {
    if (!Number.isSafeInteger(maxEvidenceBytes) || maxEvidenceBytes < 1 || !Number.isSafeInteger(maxOperations) || maxOperations < 1) {
      throw new Nb2Error('CapacityPreflight', 'invalid ordinary gas range');
    }
    return { maxEvidenceBytes, maxOperations, maxGaps: uint(maxGaps), execution: uint(execution) };
  });
}

function ordinaryEnvelope(w: Wallet, policy: PayerPolicy): ReturnAdmission['ordinaryEnvelope'] {
  const erc20 = !!w.bridge.cfg.erc20;
  const ranges = ordinaryRanges(w);
  return { encodedBytes: erc20 ? w.pins.maxEncodedTxBytes : BigInt(Math.min(policy.signedBytes, policy.calldataBytes)),
    gas: erc20 && policy.gas > 24_000_000n ? 24_000_000n : policy.gas,
    gasFor: ranges && ((shape) => quoteOrdinaryExecution(shape, ranges, w.pins.gasReserve)) };
}

function erc20RecoveryInput(w: Wallet, policy: PayerPolicy): Erc20ReturnRecovery {
  const { deployment, calibration, backlog, signingWindows } = recoveryRelease(w);
  return { deployment, calibration, backlog, limits: { ...policy, balance: (1n << 256n) - 1n },
    signingBounds: signingWindows && policy.feeWindowMs !== undefined ? { ...signingWindows, feeWindowMs: policy.feeWindowMs } : undefined,
    ordinaryRanges: ordinaryRanges(w), ordinaryAttempts: { attemptsBeforeFallback: policy.ordinaryAttemptsBeforeFallback ?? 0n,
      inclusionMs: signingWindows?.ordinaryInclusionMs ?? 0n } };
}

export function walletAdmission(w: Wallet, policy?: PayerPolicy, backup?: string, replacing?: bigint): ReturnAdmission {
  const beforeCertification: ReturnAdmission['beforeCertification'] = backup ? async (rec) => publishReturnBackup(w, rec, backup) : undefined;
  if (w.bridge.cfg.erc20) return {
    erc20Recovery: policy && w.release.recovery !== undefined ? erc20RecoveryInput(w, policy) : undefined, beforeCertification,
  };
  return {
    ordinaryEnvelope: policy && ordinaryEnvelope(w, policy),
    checkOrdinary: w.release.recovery === undefined && policy === undefined ? undefined : async (rec, gas) => {
      if (!policy) throw new WalletError('PolicyRequired', 'explicit payer limits are required');
      if (w.release.recovery !== undefined) await checkGraph(w, recoveryRelease(w));
      const limits = await limitsOf(w, policy, bytes(rec.payer ?? rec.recipient, 20));
      const fee = gas * limits.currentBid;
      const cap = limits.maxTransactionFee ?? limits.feeBudget;
      if (w.pins.returnReserveSegments < 64n || gas > limits.gas || fee > cap || fee > limits.feeBudget || fee > limits.balance) {
        throw new Nb2Error('CapacityPreflight', 'ordinary return exceeds the payer or reserve limits');
      }
    },
    recover: w.release.recovery === undefined ? undefined : async (rec) => {
      if (!policy) throw new WalletError('PolicyRequired', 'explicit payer limits are required');
      const release = recoveryRelease(w);
      await checkGraph(w, release);
      const payer = bytes(rec.payer ?? rec.recipient, 20);
      const limits = await limitsOf(w, policy, payer, reservedFees(w, rec, payer, undefined, replacing), replacing,
        await otherErc20Reserves(w, rec, payer));
      const a = uint(rec.a);
      const { segment } = await w.bridge.evm.vaultState(w.bridge.cfg.vault);
      const plan = await preflightRecovery(w.pins.gamma, bytes(rec.source), w.trust, buildParams(w.pins.build),
        release.deployment, release.calibration, limits, { ...release.backlog, signedStart: a, observed: segment },
        rec.sealReceipt ? bytes(rec.sealReceipt) : undefined);
      const calls = BigInt(plan.run.length) + plan.advance.calls + 1n;
      if ((replacing ?? await w.bridge.evm.nonce(payer)) + calls - 1n > limits.maxNonce) {
        throw new Nb2Error('CapacityPreflight', 'recovery schedule exceeds the declared nonce horizon');
      }
      return { generation: hx(release.generation), calls: String(calls), totalFee: String(plan.totalFee),
        runCuts: plan.run.map((quote) => quote.shape.operations), advanceGaps: plan.advance.quote.shape.gaps,
        observed: String(segment < a ? a : segment), progressEnd: String((segment < a ? a : segment) + release.backlog.duringProgress),
        receiptP99Ms: String(release.backlog.receiptP99Ms),
        finalInclusionMs: String(release.backlog.finalInclusionMs), qualifiedForMs: String(release.backlog.qualifiedForMs) };
    },
    beforeCertification,
  };
}

/** Qualify a late ordinary burn for cold continuation under this payer's limits. */
export async function qualifyExistingRecovery(w: Wallet, rec: ReturnRecord, policy: PayerPolicy): Promise<ReturnRecord> {
  const { result, handoff } = await reconcileForPayout(w, rec, 'recovery', policy, false);
  if (result.state === 'needs-archive') archiveRequired(result.txHash, result.missing);
  if (result.state === 'vanished') paymentVanished(result.txHash);
  if (result.state === 'route-blocked') routeRequired(result);
  const current = await w.bridge.journal.retForUpdate(rec.returnId);
  if (current?.status === 'paid') return current;
  if (!current?.burned) throw new WalletError('NotPending', 'certify the exact burn before choosing recovery');
  if (hasPeerComplete(w, current) || current.recovery) return current;
  current.recovery = await qualifyLineage(w, current, policy, handoff?.nonce);
  await w.bridge.journal.putReturn(current);
  return current;
}

async function qualifyLineage(w: Wallet, rec: ReturnRecord, policy: PayerPolicy, replacing?: bigint) {
  if (w.bridge.cfg.erc20) {
    const input = erc20RecoveryInput(w, policy);
    await checkGraph(w, recoveryRelease(w));
    input.limits = { ...await limitsOf(w, policy, w.signer.address, reservedFees(w, rec, w.signer.address, undefined, replacing), replacing,
      await otherErc20Reserves(w, rec, w.signer.address)), maxNonce: policy.maxNonce };
    return w.bridge.qualifyErc20Recovery({ ...rec, payer: hx(w.signer.address) }, input, replacing);
  }
  const qualify = walletAdmission(w, policy, undefined, replacing).recover;
  if (!qualify) throw new Nb2Error('CapacityPreflight', 'qualified recovery release is required');
  return qualify({ ...rec, payer: hx(w.signer.address) });
}

/** After Complete, price only this payer's gap advances and settlement. */
async function qualifySettlement(w: Wallet, rec: ReturnRecord, policy: PayerPolicy, start: bigint, replacing?: bigint) {
  const release = recoveryRelease(w);
  await checkGraph(w, release);
  const { segment } = await w.bridge.evm.vaultState(w.bridge.cfg.vault);
  const observed = segment < start ? start : segment;
  const limits = await limitsOf(w, policy, w.signer.address, reservedFees(w, rec, w.signer.address, undefined, replacing), replacing,
    await otherErc20Reserves(w, rec, w.signer.address));
  const nonce = replacing ?? await w.bridge.evm.nonce(w.signer.address);
  const backlog = { ...release.backlog, signedStart: start, observed, duringProgress: 0n };
  const needed = observed - start + 64n;
  for (let batch = Number(needed < 1024n ? needed : 1024n); batch > 0; batch--) {
    const quote = quoteRecoveryGapBatch(w.bridge.cfg.K, batch, release.calibration, limits);
    if (!quote) continue;
    // The largest quoted batch consumes the fewest gap-advance nonces.
    const calls = recoveryCatchUpCalls(batch, backlog);
    const gapCalls = !w.bridge.cfg.erc20 && observed - start < BigInt(batch) ? 0n : calls;
    const fee = quote.advance.fee * calls + quote.settle.fee;
    if (nonce + gapCalls > limits.maxNonce || (gapCalls > 0n && (fee > limits.feeBudget || fee > limits.balance))) continue;
    return { generation: hx(release.generation), calls: String(calls + 1n), totalFee: String(fee),
      runCuts: [], advanceGaps: batch, observed: String(observed), receiptP99Ms: String(backlog.receiptP99Ms),
      finalInclusionMs: String(backlog.finalInclusionMs), qualifiedForMs: String(backlog.qualifiedForMs) };
  }
  throw new Nb2Error('CapacityPreflight', 'certified Complete needs locally qualified gap and settlement limits');
}

interface Backup {
  version: 1; gamma: string; vaultRuntimeHash: string; pending: ReturnRecord;
  recover?: true; handoff?: 'active'; activePayer?: string; terminal?: string; complete?: PortableComplete;
  checkpoint?: RecoveryJournal; paid?: ReturnRecord['paid'];
}

/** A holder-selected private file. Hard-link publication cannot clobber a changed destination. */
export async function publishReturnBackup(w: Wallet, rec: ReturnRecord, file: string): Promise<void> {
  if (!rec.burnRequest || !rec.certificationLocator) throw new Error('sign the return before exporting a relayer backup');
  const saved = loadRecovery(w, rec);
  const { source, amount, returnId, recipient, a, startHead, fromBlock, sealReceipt, burnTx, burnRequest, certificationLocator } = rec;
  const pending: ReturnRecord = { ...w.bridge.journal.base(), kind: 'return', status: 'burn-requested', sends: [], source, amount, returnId,
    recipient, a, startHead, fromBlock, sealReceipt, burnTx, burnRequest, certificationLocator };
  const endpoint = saved?.complete ?? saved?.cuts.find((item) => item.cut.kind === 'run' && item.state === undefined);
  const complete = endpoint && { seq: endpoint.seq, location: endpoint.location };
  const payer = boundPayer(rec, saved);
  const ordinary = blockedOrdinary(rec);
  const active = !rec.paid && (saved?.pending || saved?.superseded?.length || (!complete && payer) ||
    (ordinary && (!complete || !saved || !await completedOrdinaryHandoff(w, rec, saved, ordinary.txHash))));
  const copy: Backup = { version: 1, gamma: hx(w.pins.gamma), vaultRuntimeHash: hx(w.pins.vaultRuntimeCodeHash), pending,
    recover: rec.recovery ? true : undefined, handoff: active ? 'active' : undefined,
    activePayer: active && payer ? hx(payer.address) : undefined, terminal: complete ? saved!.evidence : rec.burned, complete,
    paid: rec.paid?.receipt ? rec.paid : undefined };
  const content = JSON.stringify(copy);
  if (existsSync(file)) {
    const existing = lstatSync(file);
    if (!existing.isFile() || (existing.mode & 0o077) !== 0 || readFileSync(file, 'utf8') !== content) {
      throw new Error('backup destination is already occupied');
    }
    fsyncDir(dirname(file));
    return;
  }
  const stage = join(dirname(file), `.nb2-backup-${randomBytes(16).toString('hex')}`);
  try {
    writeDurable(stage, content);
    linkSync(stage, file);
    fsyncDir(dirname(file));
  } finally {
    if (existsSync(stage)) unlinkSync(stage);
  }
}

type ImportEvidence = {
  terminal?: Uint8Array;
  paid?: ReturnRecord['paid'];
  beforeCommit?: Parameters<Wallet['bridge']['importPendingReturn']>[2];
};

/** All wallet return commands pass through this Paid-first gate before qualifying or signing. */
export async function reconcileReturn(w: Wallet, rec: ReturnRecord, policy?: PayerPolicy,
  incoming?: ImportEvidence, resubmit = true): Promise<{ record: ReturnRecord; result: ReconcileResult }> {
  const archive = policy ? readers(w, policy) : [w.bridge.evm];
  const journal = loadRecovery(w, rec);
  // this wallet's own settlement packets: their hashes are lookup hints, their bytes mark them as ours (never another party's payment)
  const own = [...(journal?.superseded ?? []), ...(journal?.replacedSettlements ?? [])].map((raw) => bytes(raw))
    .filter((raw) => eq(decodeSignedTx(raw).request.to, w.bridge.cfg.vault));
  if (journal?.pending?.cut.kind === 'settle') own.push(bytes(journal.pending.raw));
  const settlements = own.map((raw) => decodeSignedTx(raw).hash);
  const evidence: ReturnEvidence = { paid: incoming?.paid, settlements, own, pending: { recovery: recoveryEmitter(w) }, readOnly: !resubmit };
  const paidResult = (record: ReturnRecord): ReconcileResult =>
    record.paid ? { state: 'paid', txHash: bytes(record.paid.txHash, 32), blockNumber: uint(record.paid.blockNumber) }
      : record.paidProof ? { state: 'pending', txHash: bytes(record.paidProof.txHash, 32) } : { state: 'not-paid' };
  let record: ReturnRecord;
  let result: ReconcileResult;
  if (incoming) {
    record = await w.bridge.importPendingReturn(rec, incoming.terminal, incoming.beforeCommit, archive, evidence);
    result = paidResult(record);
  } else {
    result = await w.bridge.reconcile(bytes(rec.returnId, 32), archive, evidence);
    record = (await w.bridge.journal.ret(rec.returnId))!;
  }
  if (result.state === 'paid') retainPayment(w, record, hx(result.txHash));
  return { record, result };
}

export function restoreReturn(w: Wallet, file: string, policy?: PayerPolicy): Promise<ReturnRecord> {
  return importReturn(w, JSON.parse(readFileSync(file, 'utf8')) as Backup, policy);
}

export async function importReturn(w: Wallet, backup: Backup, policy?: PayerPolicy): Promise<ReturnRecord> {
  backup = structuredClone(backup);
  if (backup.version !== 1 || backup.gamma !== hx(w.pins.gamma) || backup.vaultRuntimeHash !== hx(w.pins.vaultRuntimeCodeHash)) {
    throw new WalletError('BadDeployment', 'backup belongs to another installed deployment');
  }
  const terminal = backup.terminal ?? backup.checkpoint?.evidence;
  const endpoint = backup.complete ?? backup.checkpoint?.cuts.find((item) => item.cut.kind === 'run' && item.state === undefined);
  const wantsRecovery = backup.recover === true || backup.pending.recovery !== undefined;
  const archive = policy ? readers(w, policy) : [w.bridge.evm];
  let freshCheckpoint: RecoveryJournal | undefined;
  const { record: selected } = await reconcileReturn(w, backup.pending, policy, {
    terminal: terminal === undefined ? undefined : bytes(terminal),
    paid: backup.paid,
    beforeCommit: async (verified, incoming) => {
      const local = loadRecovery(w, verified);
      const payer = boundPayer(verified, local);
      if (backup.handoff === 'active' && !payer && !local) {
        const address = backup.activePayer ? ` ${hx(bytes(backup.activePayer, 20))}` : '';
        throw new WalletError('NotPending', `active payer handoff is blocked. Resume on the original journal with payer${address} or request a resolved Complete or Paid backup`);
      }
      const held = local && activeRecovery(verified, local);
      let localComplete = !!local?.complete;
      if (local && held && (held.recovery || local.complete)) {
        const release = recoveryRelease(w);
        await checkGraph(w, release);
        const session = await openSession(w, release, held);
        const cursor = await replay(w, session, held, local);
        if (local.pending) {
          try {
            const outcome = await reconcilePendingPacket(w, held, release, session, local, cursor, archive);
            if (outcome.state === 'needs-archive' && !endpoint) archiveRequired(outcome.txHash, outcome.missing);
          } catch (e) {
            if (!endpoint || !(e instanceof Nb2Error && e.rule === 'EvidencePruned')) throw e;
          }
        }
        localComplete = !!cursor.gap;
      }
      if (endpoint) {
        const release = recoveryRelease(w);
        await checkGraph(w, release);
        const session = await openSession(w, release, incoming);
        await verifyComplete(w, session, endpoint);
        if (!localComplete) {
          const ordinary = blockedOrdinary(verified);
          if (ordinary) routeRequired(ordinary);
          const superseded = [...(local?.superseded ?? [])];
          if (local?.pending) superseded.push(local.pending.raw);
          const journal: RecoveryJournal = {
            ...initialJournal(session, incoming, release), complete: { seq: endpoint.seq, location: endpoint.location },
            fees: local?.fees, attempts: local?.attempts, signerEpochs: local?.signerEpochs, ordinaryHandoff: local?.ordinaryHandoff, replacedSettlements: local?.replacedSettlements, superseded: superseded.length ? superseded : undefined,
          };
          if ((await w.bridge.journal.ret(verified.returnId))?.burnRequest) saveRecovery(w, verified, journal);
          else freshCheckpoint = journal;
          return null;
        }
        return local?.complete && verified.recovery ? null : undefined;
      }
      // Legacy exports may have a peer Progress or Gap. They never install a peer cursor or plan.
      if (backup.checkpoint?.cuts.length && !local) {
        throw new WalletError('NotPending', 'peer Progress cannot transfer an active payer. Resume on its original journal or request a certified Complete or Paid backup');
      }
      if (local?.complete) return verified.recovery ? null : undefined;
      if (!verified.recovery && wantsRecovery && policy && !blockedOrdinary(verified)) return qualifyLineage(w, verified, policy);
    },
  });
  if (selected.status === 'paid' || selected.paidProof) return selected;
  if (freshCheckpoint) saveRecovery(w, selected, freshCheckpoint);
  if (selected.status === 'burn-requested') {
    await w.bridge.burn(bytes(selected.returnId, 32));
    const { record } = await reconcileReturn(w, selected, policy);
    if (record.status === 'paid') return record;
  }
  const confirmed = (await w.bridge.journal.ret(selected.returnId))!;
  await retainTerminal(w, confirmed);
  return confirmed;
}

/** Another party's payment was seen and is gone from the chain (not pruned): nothing is signed while it is held. */
export function paymentVanished(hash: Uint8Array): never {
  throw new WalletError('EvidenceMissing', `payment ${hx(hash)} by another party was seen and is no longer on the chain (no reader serves it on its canonical chain, ${CERTIFICATION_DEPTH} blocks on); nothing is signed while it is held: it is paid if that transaction lands again, and ${VANISHED_CLAIM_HORIZON} blocks after it was first seen the own payout proceeds`);
}

export function archiveRequired(hash: Uint8Array, missing?: string): never {
  throw new WalletError('EvidenceMissing', `needs archive for exact transaction ${hx(hash)}: the node no longer serves ${missing ?? 'its certified block, receipts or raw transactions'}. Add an archive reader that does, then resume`);
}

async function qualifyRestoredSchedule(w: Wallet, release: ReleaseRecovery, rec: ReturnRecord,
  journal?: RecoveryJournal, cursor?: Cursor): Promise<void> {
  const held = bytes(rec.source);
  const { runCuts, advanceGaps, observed: admittedObserved, progressEnd, envelope } = rec.recovery!;
  if (!cursor?.gap) checkSchedule(rec, w.bridge.returnHeadroom(held).operations);
  const { cfg, evm } = w.bridge;
  const limits: RecoveryLimits = {
    gas: envelope ? uint(envelope.gas) : w.pins.userGasLimit,
    signedBytes: envelope?.signedBytes ?? Number(w.pins.maxEncodedTxBytes), calldataBytes: envelope?.calldataBytes ?? 393_216,
    chainId: cfg.chainId, maxNonce: envelope ? uint(envelope.maxNonce) : 0n, maxFeePerGas: envelope ? uint(envelope.maxFeePerGas) : 1n,
    maxPriorityFeePerGas: envelope ? uint(envelope.maxPriorityFeePerGas) : 0n,
    balance: 0n, feeBudget: 0n, worstCaseEnvelope: !envelope,
  };
  if (!quoteRecoveryGapBatch(cfg.K, advanceGaps, release.calibration, limits)) {
    throw new Nb2Error('CapacityPreflight', 'portable gap batch or settlement suffix is outside the release limits');
  }
  const confirmedCuts = journal?.cuts.filter((item) => item.cut.kind === 'run').length ?? 0;
  if (!cursor?.gap) checkRemainingRecoveryRuns(held, runCuts, confirmedCuts, release.calibration, limits, !!cfg.erc20);
  const covered = cursor?.gap?.cursor?.next ?? uint(rec.a);
  const { segment } = await evm.vaultState(cfg.vault);
  const observed = segment > covered ? segment : covered;
  const bound = progressEnd === undefined ? uint(admittedObserved) + release.backlog.duringProgress : uint(progressEnd);
  const running = !cursor?.gap && confirmedCuts < runCuts.length;
  if (cfg.erc20 && running && observed > bound) throw new Nb2Error('CapacityPreflight', 'observed arrivals exceed the admitted Run endpoint');
  recoveryCatchUpCalls(advanceGaps, {
    ...release.backlog, signedStart: covered, observed, duringProgress: running && bound > observed ? bound - observed : 0n,
  });
}

type Cut = { kind: 'run'; count: number } | { kind: 'advance'; gaps: string[] } | { kind: 'settle'; gaps: string[] };
interface Location { txHash: string; blockNumber: string; blockHash: string; txIndex: string; logIndex: string; proof: string }
interface PortableComplete { seq: string; location: Location }
interface RecoveryJournal {
  version: 1;
  session: string; pageRoot: string; evidence: string; evidenceBytes: number; generation: string;
  complete?: PortableComplete;
  fees?: string;
  attempts?: string[];
  signerEpochs?: Record<string, string>;
  /** Earlier settlement bytes replaced at the same payer nonce. Reconcile them without resubmitting. */
  replacedSettlements?: string[];
  /** The ordinary send whose free nonce was used for the first continuation packet. */
  ordinaryHandoff?: string;
  /** Signed local attempts whose work has been superseded by a certified peer cursor. */
  superseded?: string[];
  cuts: { cut: Exclude<Cut, { kind: 'settle' }>; location: Location; seq: string; nonce: string; priorSeq: string; state?: string; endpoint?: string; head?: string }[];
  pending?: { cut: Cut; raw: string; txHash: string; nonce: string; priorSeq: string; failureProofReads?: number; failureBlock?: string };
  settled?: { paidTx: string; submitted?: RecoveryJournal['pending'] };
}
const pathOf = (w: Wallet, rec: ReturnRecord): string => {
  bytes(rec.returnId, 32);
  return join(w.dir, `recovery-${rec.returnId.slice(2)}.json`);
};
function loadRecovery(w: Wallet, rec: ReturnRecord): RecoveryJournal | undefined {
  const path = pathOf(w, rec);
  return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : undefined;
}

/** Import the pre-upgrade wallet's separately durable signed packets into the shared payer journal. */
export async function indexLocalRecoverySends(w: Wallet): Promise<void> {
  for (const { record } of await w.bridge.journal.allReturns()) {
    const saved = loadRecovery(w, record);
    const raw = [...(saved?.attempts ?? []), ...(saved?.superseded ?? []), ...(saved?.replacedSettlements ?? [])];
    if (saved?.pending) raw.push(saved.pending.raw);
    if (saved?.settled?.submitted) raw.push(saved.settled.submitted.raw);
    await w.bridge.journal.indexPayerSends(record, raw.map((signed) => bytes(signed)));
  }
}
export function hasPeerComplete(w: Wallet, rec: ReturnRecord): boolean {
  return loadRecovery(w, rec)?.complete !== undefined;
}

function saveRecovery(w: Wallet, rec: ReturnRecord, journal: RecoveryJournal): void {
  writeDurable(pathOf(w, rec), JSON.stringify(journal));
}

function initialJournal(s: RecoverySession, rec: ReturnRecord, release: ReleaseRecovery): RecoveryJournal {
  const evidence = evidenceOf(bytes(rec.burned!));
  return { version: 1, session: hx(s.id), pageRoot: hx(s.pageRoot), generation: hx(release.generation),
    evidence: hx(evidence), evidenceBytes: evidence.length, cuts: [] };
}

/** Commit the terminal continuation identity as soon as burn certification succeeds. */
export async function retainTerminal(w: Wallet, rec: ReturnRecord): Promise<void> {
  if (!rec.recovery || loadRecovery(w, rec)) return;
  const release = recoveryRelease(w);
  const session = await openSession(w, release, rec);
  saveRecovery(w, rec, initialJournal(session, rec, release));
}

const sessions = new WeakMap<Wallet, { burned: string; generation: string; trust: TrustInput; session: RecoverySession }>();

async function openSession(w: Wallet, release: ReleaseRecovery, rec: ReturnRecord): Promise<RecoverySession> {
  const generation = hx(release.generation);
  if ((rec.recovery && rec.recovery.generation !== generation) || !rec.burned) throw new WalletError('BadDeployment', 'return belongs to another generation or is uncertified');
  const cached = sessions.get(w);
  const trust = await w.bridge.verifyWithTrust(async (trust) => trust);
  let session = cached?.burned === rec.burned && cached.generation === generation && cached.trust === trust ? cached.session : undefined;
  if (session === undefined) {
    const authority = new RecoveryAuthority(trust, async (next) => w.persistAuthority(next));
    session = await RecoverySession.create(w.pins.gamma, evidenceOf(bytes(rec.burned)), authority, buildParams(w.pins.build), release.deployment);
  }
  if (rec.eta !== hx(session.redemptionId)) throw new WalletError('BadInput', 'continuation session has the wrong redemption ID');
  sessions.set(w, { burned: rec.burned, generation, trust, session });
  return session;
}

function checkSchedule(rec: ReturnRecord, operations: number): void {
  const { runCuts, advanceGaps } = rec.recovery!;
  if (!Array.isArray(runCuts) || runCuts.length > operations ||
    runCuts.some((count) => !Number.isSafeInteger(count) || count < 1 || count > 16) ||
    runCuts.reduce((sum, count) => sum + count, 0) !== operations ||
    !Number.isSafeInteger(advanceGaps) || advanceGaps < 1 || advanceGaps > 1024) {
    throw new Error('admitted schedule does not cover the certified lineage');
  }
}

interface Cursor { from: number; prior?: { seq: bigint; receipt: Uint8Array }; gap?: GapPrior }

function matches(r: RecoveryReceipt, saved: Location): boolean {
  return String(r.blockNumber) === saved.blockNumber && hx(r.blockHash) === saved.blockHash &&
    String(r.txIndex) === saved.txIndex && String(r.logIndex) === saved.logIndex;
}
function location(tx: string, r: RecoveryReceipt): Location {
  return { txHash: tx, blockNumber: String(r.blockNumber), blockHash: hx(r.blockHash), txIndex: String(r.txIndex),
    logIndex: String(r.logIndex), proof: hx(r.encoded) };
}
async function packetOf(s: RecoverySession, trust: TrustInput, rec: ReturnRecord, c: Cursor, cut: Cut) {
  if (cut.kind === 'run') {
    if (c.gap) throw new Error('lineage is already complete');
    return s.run(c.from, cut.count, trust, c.prior);
  }
  if (!c.gap || !c.prior) throw new Error('gap cut requires a certified Complete or Gap');
  const head = !c.gap.cursor && cut.gaps.length ? bytes(rec.startHead, 32) : undefined;
  return s.gaps(cut.kind === 'advance' ? 'advanceGaps' : 'redeemRecovered', trust, c.prior.receipt,
    c.gap, cut.gaps.map((g) => bytes(g)), head);
}

function activeRecovery(rec: ReturnRecord, journal: RecoveryJournal): ReturnRecord {
  return journal.complete ? { ...rec, burned: journal.evidence, recovery: undefined } : rec;
}

async function verifyComplete(w: Wallet, s: RecoverySession, endpoint: PortableComplete): Promise<Cursor> {
  bytes(endpoint.location.txHash, 32);
  const seq = uint(endpoint.seq);
  const receipt = await w.bridge.verifyWithTrust((trust) => s.verifyComplete(trust, bytes(endpoint.location.proof), seq));
  if (!matches(receipt, endpoint.location)) throw new Error('Complete locator disagrees with its authenticated receipt');
  return { from: s.operationCount, prior: { seq, receipt: receipt.encoded }, gap: { seq } };
}

async function replay(w: Wallet, s: RecoverySession, rec: ReturnRecord, journal: RecoveryJournal): Promise<Cursor> {
  const evidence = evidenceOf(bytes(rec.burned!));
  if (journal.version !== 1 || journal.evidenceBytes !== evidence.length || journal.session !== hx(s.id) || journal.pageRoot !== hx(s.pageRoot) || journal.generation !== hx(recoveryRelease(w).generation) ||
    journal.evidence !== hx(evidence)) throw new Error('recovery journal does not bind the certified evidence');
  if (!journal.complete) checkSchedule(rec, s.operationCount);
  const cursor = journal.complete ? await verifyComplete(w, s, journal.complete) : { from: 0 };
  for (const [i, item] of journal.cuts.entries()) {
    if (item.cut.kind === 'run' && item.cut.count !== rec.recovery!.runCuts[i]) throw new Error('portable cut disagrees with the admitted schedule');
    // The saved transaction hash is a lookup hint. The certificate binds the receipt index.
    bytes(item.location.txHash, 32);
    if (uint(item.priorSeq) !== (cursor.prior?.seq ?? 0n)) throw new Error('checkpoint has the wrong preceding sequence');
    uint(item.nonce);
    const packet = await w.bridge.verifyWithTrust((trust) => packetOf(s, trust, rec, cursor, item.cut));
    if (!packet.event) throw new Error('settlement is reconciled through the vault Paid receipt');
    const event = packet.event;
    const receipt = await w.bridge.verifyWithTrust((trust) => s.verifyEvent(trust, bytes(item.location.proof), event));
    if (!matches(receipt, item.location)) throw new Error('checkpoint locator disagrees with its authenticated receipt');
    advanceCursor(cursor, packet, receipt.encoded);
    const state = 'state' in packet && packet.state ? hx(packet.state) : undefined;
    if (item.seq !== String(cursor.prior!.seq) || item.state !== state ||
      item.endpoint !== (cursor.gap?.cursor && String(cursor.gap.cursor.next)) ||
      item.head !== (cursor.gap?.cursor && hx(cursor.gap.cursor.head))) throw new Error('saved checkpoint disagrees with the authenticated cut');
  }
  return cursor;
}

/** A receipt authenticates the cursor; its transaction must separately prove who used the nonce. */
async function completedOrdinaryHandoff(w: Wallet, rec: ReturnRecord, saved: RecoveryJournal, hash: Uint8Array): Promise<boolean> {
  if (saved.ordinaryHandoff !== hx(hash)) return false;
  try {
    const old = decodeSignedTx(bytes(rec.sends.at(-1)!.raw));
    const cut = saved.cuts.find((item) => item.nonce === String(old.request.nonce));
    if (!cut) return false;
    const release = recoveryRelease(w);
    const active = activeRecovery(rec, saved);
    const session = await openSession(w, release, active);
    if (!(await replay(w, session, active, saved)).gap) return false;
    const { blockHash, txHash, txIndex } = cut.location;
    const raw = await w.bridge.evm.transactionAt(bytes(blockHash, 32), uint(txIndex), bytes(txHash, 32));
    const mined = decodeSignedTx(raw);
    return eq(mined.from, old.from) && mined.request.nonce === old.request.nonce &&
      eq(mined.request.to, release.deployment.recovery);
  } catch {
    // Keep the export payer-bound if the proof or exact transaction is unavailable.
    return false;
  }
}

function advanceCursor(cursor: Cursor, packet: Awaited<ReturnType<typeof packetOf>>, receipt: Uint8Array): void {
  const seq = (cursor.prior?.seq ?? 0n) + 1n;
  cursor.prior = { seq, receipt };
  if ('end' in packet) {
    cursor.from = packet.end;
    if (packet.event.kind === 'complete') cursor.gap = { seq };
  } else {
    cursor.gap = { seq, cursor: { next: packet.next, head: packet.head! } };
  }
}

function readers(w: Wallet, policy: PayerPolicy): EvmReader[] {
  return [w.bridge.evm, ...policy.archives.map((url) => new EvmReader(readRetrying(new HttpJsonRpc(url))))];
}


async function segmentProofs(reader: EvmReader, w: Wallet, rec: ReturnRecord, start: bigint, end: bigint): Promise<Uint8Array[]> {
  const rows = await reader.segmentLogs(w.bridge.cfg.vault, uint(rec.fromBlock), start, end);
  const proofs: Uint8Array[] = [];
  for (const log of rows) {
    const proof = await reader.receiptProof(log.transactionHash, w.bridge.cfg.vault, TOPIC.SegmentSealed, true, log);
    proofs.push(proof.encoded);
  }
  return proofs;
}

export type PacketResult = { state: 'checkpoint' | 'retry'; txHash: Uint8Array };
export type RecoveryResult = Exclude<ReconcileResult, { state: 'not-paid' }> | PacketResult;

function retainPayment(w: Wallet, rec: ReturnRecord, txHash: string): void {
  const saved = loadRecovery(w, rec);
  if (!saved || saved.settled) return;
  saved.settled = { paidTx: txHash, submitted: saved.pending };
  delete saved.pending;
  saveRecovery(w, rec, saved);
}

type RouteBlocked = Extract<ReconcileResult, { state: 'route-blocked' }>;

function boundPayer(rec: ReturnRecord, journal?: RecoveryJournal) {
  const cold = journal?.attempts?.[0] ?? journal?.superseded?.[0] ?? journal?.pending?.raw ?? journal?.settled?.submitted?.raw;
  const raw = rec.sends[0]?.raw ?? cold;
  const first = raw && decodeSignedTx(bytes(raw));
  const address = rec.executionPayer ? bytes(rec.executionPayer, 20) : first ? first.from : undefined;
  if (address && first && !eq(address, first.from)) throw new WalletError('BadInput', 'execution payer disagrees with the first signed payout');
  if (address) return { address, txHash: first ? first.hash : bytes(rec.returnId, 32), route: cold ? 'recovery' as const : 'ordinary' as const };
}

function blockedOrdinary(rec: ReturnRecord): RouteBlocked | undefined {
  const send = rec.sends.at(-1);
  if (send && !rec.sends.some((prior) => prior.nonce === send.nonce && prior.failed)) return { state: 'route-blocked', route: 'ordinary', txHash: decodeSignedTx(bytes(send.raw)).hash };
}

export function routeRequired(result: RouteBlocked): never {
  if (result.payer) throw new WalletError('NotPending', `return is bound to payer ${hx(result.payer)}. Reopen the original journal with that payer`);
  throw new WalletError('NotPending', `route blocked by ${result.route} transaction ${hx(result.txHash)}. Resume that route with its payer and reconcile the exact send before switching routes`);
}

/** A certified event authenticates the cursor. Check nonce consumption independently. */
async function lowerRecoverySend(w: Wallet, rec: ReturnRecord, journal?: RecoveryJournal) {
  const raw = [...(journal?.superseded ?? []), ...(journal?.attempts ?? [])];
  if (!raw.length) return;
  const evm = w.bridge.evm;
  const block = await evm.saneHead();
  const sends = raw.map((signed) => ({ ...decodeSignedTx(bytes(signed)), raw: bytes(signed) }))
    .sort((a, b) => a.request.nonce < b.request.nonce ? -1 : a.request.nonce > b.request.nonce ? 1 : 0);
  const mined = new Map<string, bigint>();
  for (const send of sends) {
    const payer = hx(send.from);
    const nonce = mined.get(payer) ?? await evm.nonce(send.from, block);
    mined.set(payer, nonce);
    if (send.request.nonce >= nonce) return send;
  }
  if (journal?.superseded?.length) {
    journal.attempts = [...new Set([...(journal.attempts ?? []), ...journal.superseded])];
    delete journal.superseded;
    saveRecovery(w, rec, journal);
  }
}

async function reconcileForPayout(w: Wallet, rec: ReturnRecord, route: 'ordinary' | 'recovery', policy?: PayerPolicy, resubmit = true): Promise<{ record: ReturnRecord; result: ReconcileResult;
  handoff?: { hash: Uint8Array; nonce: bigint } }> {
  const first = await reconcileReturn(w, rec, policy, undefined, false);
  if (first.result.state === 'paid' || first.result.state === 'needs-archive' || first.result.state === 'vanished') return first;
  rec = first.record;
  const journal = loadRecovery(w, rec);
  const payer = boundPayer(rec, journal);
  if (payer && !eq(payer.address, w.signer.address)) {
    const result: RouteBlocked = { state: 'route-blocked', route: payer.route, txHash: payer.txHash, payer: payer.address };
    return { record: rec, result };
  }
  const ordinary = blockedOrdinary(rec);
  let handoff: { hash: Uint8Array; nonce: bigint } | undefined;
  const localOrdinary = ordinary && first.result.state === 'pending' && !rec.paidProof &&
    eq(first.result.txHash, ordinary.txHash);
  const resumed = localOrdinary && journal?.ordinaryHandoff === hx(ordinary.txHash);
  if (ordinary && route === 'recovery' && !resumed) {
    if (localOrdinary && policy && !journal?.pending) {
      const nonce = await w.bridge.expiredOrdinaryNonce(bytes(rec.returnId, 32), w.signer.address, readers(w, policy));
      if (nonce !== undefined) handoff = { hash: ordinary.txHash, nonce };
    }
    if (!handoff) return { record: rec, result: ordinary };
  }
  if (journal?.pending && route === 'ordinary') {
    const held = activeRecovery(rec, journal);
    const release = recoveryRelease(w);
    const session = await openSession(w, release, held);
    const cursor = await replay(w, session, held, journal);
    const outcome = await reconcilePendingPacket(w, held, release, session, journal, cursor, policy ? readers(w, policy) : [w.bridge.evm]);
    if (outcome.state === 'needs-archive') return { record: rec, result: outcome };
    if (journal.pending) {
      const result: RouteBlocked = { state: 'route-blocked', route: 'recovery', txHash: decodeSignedTx(bytes(journal.pending.raw)).hash };
      return { record: rec, result };
    }
  }
  const lower = await lowerRecoverySend(w, rec, journal);
  if (lower) {
    if (route !== 'recovery' || !eq(lower.from, w.signer.address)) {
      const result: RouteBlocked = { state: 'route-blocked', route: 'recovery', txHash: lower.hash };
      return { record: rec, result };
    }
    if (resubmit) {
      const epoch = journal?.signerEpochs?.[hx(lower.hash)];
      if (epoch === undefined) throw new WalletError('NotPending', 'retry needs the authenticated cut for the prior signed packet');
      await w.bridge.evm.checkReturnImport(w.bridge.cfg, uint(epoch), { ...lower.request, from: lower.from });
      if (w.bridge.cfg.erc20) await w.bridge.journal.retainPayerSend(rec, lower.raw);
      try { await w.bridge.evm.sendRaw(lower.raw); }
      catch (e) { if (!(e instanceof AmbiguousBroadcast)) throw e; }
    }
    return { record: rec, result: { state: 'pending', txHash: lower.hash } as const };
  }
  return route === 'recovery' && (resumed || handoff)
    ? { record: rec, result: { state: 'not-paid' } as const, handoff }
    : first;
}

/** Ordinary redeem shares payment closure and nonce reconciliation with recovery. */
export async function redeemOrdinary(w: Wallet, rec: ReturnRecord, policy?: PayerPolicy): Promise<ReconcileResult> {
  const { record, result } = await reconcileForPayout(w, rec, 'ordinary', policy);
  const last = record.sends.at(-1);
  const local = result.state === 'pending' && last && !record.paidProof &&
    last.failureProofReads === undefined && hx(result.txHash) === last.hash;
  if (result.state !== 'not-paid' && !local) return result;
  const payout = await w.bridge.submitRedeem(bytes(record.returnId, 32), w.signer, ordinaryPayout(w, record, policy));
  if (payout.state === 'paid') await reconcileReturn(w, record, policy);
  return payout;
}

/** Poll the exact observed settlement even if the reader has removed it from its pending block. */
export async function pollOrdinaryPayout(w: Wallet, rec: ReturnRecord, txHash: Uint8Array, policy?: PayerPolicy): Promise<ReconcileResult> {
  const current = await w.bridge.journal.ret(rec.returnId);
  if (current?.sends.some((send) => send.hash === hx(txHash))) return (await reconcileReturn(w, rec, policy)).result;
  const archive = policy ? readers(w, policy) : [w.bridge.evm];
  const result = await w.bridge.checkSettlement(bytes(rec.returnId, 32), archive, recoveryEmitter(w), txHash);
  if (result.state === 'paid') retainPayment(w, rec, hx(result.txHash));
  return result;
}

/** Execute at most one new packet. Reconcile the same saved bytes after an ambiguous send. */
export async function recoverStep(w: Wallet, rec: ReturnRecord, policy: PayerPolicy): Promise<RecoveryResult> {
  const archive = readers(w, policy);
  const first = await reconcileForPayout(w, rec, 'recovery', policy);
  if (first.result.state !== 'not-paid') return first.result;
  const handoff = first.handoff;
  rec = first.record;
  if (!rec.recovery && !hasPeerComplete(w, rec)) rec = await qualifyExistingRecovery(w, rec, policy);
  const release = recoveryRelease(w);
  await checkGraph(w, release);
  const local = loadRecovery(w, rec);
  if (local) rec = activeRecovery(rec, local);
  const s = await openSession(w, release, rec);
  const journal = local ?? initialJournal(s, rec, release);
  const cursor = await replay(w, s, rec, journal);

  const reconcile = () => reconcileReturn(w, rec, policy).then(({ result }) => result);
  let expired: ReturnType<typeof decodeSignedTx> | undefined;
  if (journal.pending) {
    try {
      return await reconcilePendingPacket(w, rec, release, s, journal, cursor, archive, reconcile);
    } catch (error) {
      if (!(error instanceof Nb2Error) || error.rule !== 'StaleEndpoint' || journal.pending.cut.kind !== 'settle') throw error;
      const previous = decodeSignedTx(bytes(journal.pending.raw));
      if (!eq(previous.from, w.signer.address) || await w.bridge.evm.nonce(previous.from, 'latest') !== previous.request.nonce) {
        return { state: 'pending', txHash: previous.hash };
      }
      expired = previous;
    }
  }

  {
    const replacing = expired?.request.nonce ?? handoff?.nonce;
    if (journal.complete) {
      rec = { ...rec, recovery: await qualifySettlement(w, rec, policy, cursor.gap?.cursor?.next ?? uint(rec.a), replacing) };
    } else {
      await qualifyRestoredSchedule(w, release, rec, journal, cursor);
    }
    const current = (await w.bridge.journal.ret(rec.returnId))!;
    const reservations = reservedFees(w, current, w.signer.address, undefined, replacing);
    const limits = await limitsOf(w, policy, w.signer.address, reservations, replacing, await otherErc20Reserves(w, current, w.signer.address));
    let cut: Cut;
    let quote: RecoveryQuote | null;
    let calldata: Uint8Array;
    let requiredSignerEpoch: bigint;
    let to = release.deployment.recovery;
    if (!cursor.gap) {
      const count = rec.recovery!.runCuts[journal.cuts.length];
      const packet = await s.run(cursor.from, count, w.trust, cursor.prior);
      cut = { kind: 'run', count };
      quote = quoteRecovery(packet.shape, release.calibration, limits, !!w.bridge.cfg.erc20);
      ({ calldata, requiredSignerEpoch } = packet);
    } else {
      const start = cursor.gap.cursor?.next ?? uint(rec.a);
      const { segment } = await w.bridge.evm.vaultState(w.bridge.cfg.vault);
      if (segment < start) throw new WalletError('NotPending', 'vault endpoint is behind the certified cursor');
      const batch = BigInt(rec.recovery!.advanceGaps);
      if (batch < 1n || batch > 1024n) throw new Error('invalid admitted gap batch');
      const end = segment - start >= batch ? start + batch : segment;
      const head = cursor.gap.cursor?.head ?? bytes(rec.startHead, 32);
      let gaps: Uint8Array[] | undefined;
      let error: unknown;
      for (const reader of archive) {
        try {
          const proofs = await segmentProofs(reader, w, rec, start, end);
          gaps = await w.bridge.verifyWithTrust((trust) => s.certifiedGaps(trust, start, head, proofs));
          break;
        } catch (e) { error = e; }
      }
      if (!gaps) throw error;
      const startHead = !cursor.gap.cursor && gaps.length > 0 ? head : undefined;
      const settlement = segment - start < batch ? await s.gaps('redeemRecovered', w.trust, cursor.prior!.receipt, cursor.gap, gaps, startHead) : undefined;
      const price = settlement && quoteRecovery(settlement.shape, release.calibration, limits);
      if (settlement && price) {
        cut = { kind: 'settle', gaps: gaps.map(hx) };
        ({ calldata, requiredSignerEpoch } = settlement);
        quote = price;
        to = w.bridge.cfg.vault;
      } else {
        if (BigInt(gaps.length) !== batch) throw new Nb2Error('CapacityPreflight', 'qualified settlement suffix exceeds payer limits');
        const packet = await s.gaps('advanceGaps', w.trust, cursor.prior!.receipt, cursor.gap, gaps, startHead);
        cut = { kind: 'advance', gaps: gaps.map(hx) };
        ({ calldata, requiredSignerEpoch } = packet);
        quote = quoteRecovery(packet.shape, release.calibration, limits);
      }
    }
    const pendingNonce = await w.bridge.evm.nonce(w.signer.address);
    const nonce = replacing ?? pendingNonce;
    if (quote === null || nonce > limits.maxNonce || quote.fee > limits.feeBudget || quote.fee > limits.balance) {
      throw new Nb2Error('CapacityPreflight', 'packet exceeds the remaining payer limits');
    }
    if (expired && pendingNonce > nonce &&
        (limits.maxFeePerGas < replacementBid(expired.request.maxFeePerGas) ||
         limits.maxPriorityFeePerGas < replacementBid(expired.request.maxPriorityFeePerGas))) {
      throw new Nb2Error('CapacityPreflight', 'a pooled settlement replacement exceeds the payer bid limit');
    }
    if (cut.kind === 'settle' || expired || handoff) {
      const replaced = expired ? [...(journal.replacedSettlements ?? []).filter((raw) =>
        decodeSignedTx(bytes(raw)).request.nonce === nonce).map((raw) => decodeSignedTx(bytes(raw)).hash), expired.hash] : [];
      const competing = await w.bridge.checkSettlement(bytes(rec.returnId, 32), archive, release.deployment.recovery, handoff?.hash, replaced);
      if (competing.state === 'paid') retainPayment(w, rec, hx(competing.txHash));
      if (competing.state !== 'not-paid') return competing;
    }
    if (w.bridge.cfg.erc20) {
      await w.bridge.checkErc20Payer(current, w.signer.address, true);
      const live = await limitsOf(w, policy, w.signer.address, reservations, replacing, await otherErc20Reserves(w, current, w.signer.address));
      const reserve = journal.complete ? uint(rec.recovery!.totalFee) : quote.fee;
      if (reserve > live.balance || reserve > live.feeBudget || nonce > live.maxNonce || nonce !== (replacing ?? await w.bridge.evm.nonce(w.signer.address))) {
        throw new Nb2Error('CapacityPreflight', 'recovery payer balance or nonce changed before signing');
      }
    }
    const tx = await signTx(w.signer, { chainId: limits.chainId, nonce, maxFeePerGas: limits.maxFeePerGas,
      maxPriorityFeePerGas: limits.maxPriorityFeePerGas, gas: quote.gas, to, value: 0n, data: calldata });
    if (w.bridge.cfg.erc20) await w.bridge.journal.indexPayerSends(current, [tx.raw]);
    if (tx.raw.length > quote.signedBytes) throw new Nb2Error('CapacityPreflight', 'signed recovery packet exceeds its bound');
    await w.bridge.evm.checkReturnImport(w.bridge.cfg, requiredSignerEpoch, { ...tx.request, from: w.signer.address });
    if (handoff) {
      const evm = w.bridge.evm;
      if (await evm.nonce(w.signer.address, 'latest') !== nonce || await evm.nonce(w.signer.address) !== nonce) {
        return { state: 'pending', txHash: handoff.hash };
      }
      journal.ordinaryHandoff = hx(handoff.hash);
    } else if (expired && await w.bridge.evm.nonce(w.signer.address, 'latest') !== nonce) {
      return { state: 'pending', txHash: expired.hash };
    }
    if (!current.executionPayer) {
      const durable = (await w.bridge.journal.retForUpdate(rec.returnId))!;
      durable.executionPayer = hx(w.signer.address);
      await w.bridge.journal.putReturn(durable);
    }
    if (expired) (journal.replacedSettlements ??= []).push(journal.pending!.raw);
    (journal.signerEpochs ??= {})[hx(tx.hash)] = String(requiredSignerEpoch);
    journal.pending = { cut, raw: hx(tx.raw), txHash: hx(tx.hash), nonce: String(nonce), priorSeq: String(cursor.prior?.seq ?? 0n) };
    saveRecovery(w, rec, journal);
  }
  return reconcilePendingPacket(w, rec, release, s, journal, cursor, archive, reconcile, true);
}

async function openPendingPacket(w: Wallet, rec: ReturnRecord, release: ReleaseRecovery, s: RecoverySession,
  cursor: Cursor, pending: NonNullable<RecoveryJournal['pending']>) {
  const raw = bytes(pending.raw);
  const { request, from, hash } = decodeSignedTx(raw);
  const packet = await w.bridge.verifyWithTrust((trust) => packetOf(s, trust, rec, cursor, pending.cut));
  if (hx(hash) !== pending.txHash || String(request.nonce) !== pending.nonce || String(cursor.prior?.seq ?? 0n) !== pending.priorSeq ||
    request.value !== 0n || request.chainId !== w.bridge.cfg.chainId || !eq(request.data, packet.calldata) ||
    !eq(request.to, pending.cut.kind === 'settle' ? w.bridge.cfg.vault : release.deployment.recovery)) {
    throw new Error('pending transaction does not match the authenticated cut');
  }
  return { raw, hash, packet, request, from };
}

/** Reconcile a durable send without signing. Restore only reads receipts. */
async function reconcilePendingPacket(w: Wallet, rec: ReturnRecord, release: ReleaseRecovery, s: RecoverySession,
  journal: RecoveryJournal, cursor: Cursor, archive: readonly EvmReader[],
  reconcile?: () => Promise<ReconcileResult>, preflighted = false): Promise<RecoveryResult> {
  const pending = journal.pending!;
  const { raw, hash, packet, request, from } = await openPendingPacket(w, rec, release, s, cursor, pending);
  const confirm = (receipt: RecoveryReceipt, txHint = hx(hash)): RecoveryResult => {
    if (pending.cut.kind === 'settle') throw new Error('settlement requires a certified Paid receipt');
    advanceCursor(cursor, packet, receipt.encoded);
    journal.cuts.push({ cut: pending.cut, location: location(txHint, receipt), seq: String(cursor.prior!.seq),
      nonce: pending.nonce, priorSeq: pending.priorSeq,
      ...(cursor.gap?.cursor ? { endpoint: String(cursor.gap.cursor.next), head: hx(cursor.gap.cursor.head) } : {}),
      ...('state' in packet && packet.state ? { state: hx(packet.state) } : {}) });
    (journal.attempts ??= []).push(pending.raw);
    delete journal.pending;
    saveRecovery(w, rec, journal);
    return { state: 'checkpoint', txHash: hash };
  };
  const ordinary = journal.ordinaryHandoff ? rec.sends.map((send) => send.raw) : [];
  const earlier = [...(journal.replacedSettlements ?? []), ...ordinary].map((signed) => decodeSignedTx(bytes(signed)))
    .filter((tx) => eq(tx.from, from) && tx.request.nonce === request.nonce);
  let pruned = false;
  let missing: string | undefined;
  let failed = false;
  let failedAt: bigint | undefined;
  const outcome = async (): Promise<'missing' | 'pending' | 'success' | 'earlier-paid' | 'failed'> => {
    let seen = false;
    let success = false;
    for (const tx of [hash, ...earlier.map((prior) => prior.hash)]) for (const reader of archive) {
      try {
        const receipt = await reader.receipt(tx);
        if (!receipt) continue;
        seen = true;
        if (BigInt(receipt.status) === 1n) {
          if (!eq(tx, hash)) return 'earlier-paid';
          success = true;
          continue;
        }
        failed = true;
        failedAt = BigInt(receipt.blockNumber);
        await w.bridge.verifyWithTrust((trust) => reader.verifyFailedReceipt(tx, w.bridge.cfg, trust, receipt, archive));
        return 'failed';
      } catch (e) {
        if (e instanceof WalletError && e.reason === 'TrustInput') throw e;
        if (e instanceof RpcError && e.retryable) throw e; // a transport failure is not an absence of evidence
        if (e instanceof ProofUnavailable && e.pruned || e instanceof Nb2Error && e.rule === 'EvidencePruned') {
          pruned = true; // the node's own answer, in this read, that it no longer holds part of the proof
          missing ??= e instanceof ProofUnavailable ? e.missing : (e as Nb2Error).detail ?? 'certified evidence';
        }
        // Metadata is only a hint. Try the next reader's complete proof.
      }
    }
    return success ? 'success' : seen ? 'pending' : 'missing';
  };
  let mined = await outcome();
  // A failed receipt seen before and gone from the chain CERTIFICATION_DEPTH blocks on, its nonce unused: the packet is alive again
  if (mined === 'missing' && pending.failureProofReads !== undefined && pending.failureBlock !== undefined &&
      await w.bridge.evm.saneHead() >= BigInt(pending.failureBlock) + CERTIFICATION_DEPTH && await w.bridge.evm.nonce(from, 'latest') <= request.nonce) {
    delete pending.failureProofReads;
    delete pending.failureBlock;
    saveRecovery(w, rec, journal);
  }
  if (mined === 'missing' && reconcile && pending.failureProofReads === undefined) {
    if (!preflighted) {
      await w.bridge.evm.checkReturnImport(w.bridge.cfg, packet.requiredSignerEpoch, { ...request, from });
      (journal.signerEpochs ??= {})[hx(hash)] = String(packet.requiredSignerEpoch);
      saveRecovery(w, rec, journal);
    }
    if (w.bridge.cfg.erc20) await w.bridge.journal.retainPayerSend(rec, raw);
    try { await w.bridge.evm.sendRaw(raw); }
    catch (e) { if (!(e instanceof AmbiguousBroadcast)) throw e; }
    mined = await outcome();
  }
  const unresolved = (): RecoveryResult => {
    // a marker that a failed receipt was seen (no blind resend), not a budget: a failure not certified yet stays pending
    if (failed || pending.failureProofReads !== undefined) {
      const reads = Math.min((pending.failureProofReads ?? 0) + 1, FAILURE_PROOF_READS);
      const block = failed && failedAt !== undefined ? String(failedAt) : pending.failureBlock;
      if (reads !== pending.failureProofReads || block !== pending.failureBlock) {
        pending.failureProofReads = reads;
        if (block !== undefined) pending.failureBlock = block;
        saveRecovery(w, rec, journal);
      }
    }
    if (pruned) return { state: 'needs-archive', txHash: hash, missing };
    return { state: 'pending', txHash: hash };
  };
  if (mined === 'missing' || mined === 'pending') return unresolved();
  if (mined === 'failed') {
    (journal.attempts ??= []).push(pending.raw);
    delete journal.pending;
    saveRecovery(w, rec, journal);
    return { state: 'retry', txHash: hash };
  }
  if (mined === 'earlier-paid' || pending.cut.kind === 'settle') {
    const result = await reconcile?.();
    return !result || result.state === 'not-paid' || result.state === 'pending' ? unresolved() : result;
  }
  let acquired;
  try {
    acquired = await w.bridge.verifyWithTrust((trust) => s.acquire(trust, packet.event!, archive.map((r) => recoveryRpcSource(r, hash))));
  } catch (e) {
    if (e instanceof WalletError && (e.reason === 'CompanionUnknown' || e.reason === 'EvidenceMissing')) {
      return unresolved();
    }
    throw e;
  }
  return confirm(acquired.receipt);
}

export async function returnHeadroom(w: Wallet, token: Uint8Array): Promise<string> {
  const held = await w.bridge.verifyToken(token);
  const { operations, bytes: size, ordinarySegments } = w.bridge.returnHeadroom(token);
  return `${held.amount} wei held, ${size} evidence bytes, room for at most ${ordinarySegments} ordinary gap proofs by size, ${Math.ceil(operations / 16)} minimum recovery packets through Complete; funding and gas are checked before signing`;
}
