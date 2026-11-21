/** Durable, key-independent NB2-C return continuation for the reference wallet. */
import { randomBytes } from 'node:crypto';
import { existsSync, linkSync, lstatSync, readFileSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { eq } from '../packages/native-bridge-plugin/src/bytes.js';
import {
  AmbiguousBroadcast, FAILURE_PROOF_READS, EvmReader, HttpJsonRpc, Nb2Error, RecoveryAuthority, RecoverySession, TOPIC, WalletError,
  buildParams, checkRemainingRecoveryRuns, decodeSignedTx, evidenceOf, gapProofLen, preflightRecovery, quoteRecovery, quoteRecoveryGapBatch, redeemCalldataLength, recoveryCatchUpCalls, recoveryGeneration,
  recoveryRpcSource, signTx, type GapPrior, type RecoveryBacklog, type RecoveryCalibration,
  type RecoveryDeployment, type RecoveryEvent, type RecoveryLimits, type RecoveryQuote, type RecoveryReceipt,
  type RedeemShape, type ReturnAdmission, type ReturnRecord, type ReconcileResult, type TrustInput, type SendRecord, type RedeemOptions, type ReturnEvidence,
} from '../packages/native-bridge-plugin/src/nb2/index.js';
import { SealAheadOfOrigin } from '../packages/native-bridge-plugin/src/nb2/trust.js';
import { HE } from '../packages/native-bridge-plugin/src/nb2/crypto.js';
import { beInt } from '../packages/native-bridge-plugin/src/nb2/cbor.js';
import { fsyncDir, hx, unhex, writeDurable, type Wallet } from './core.js';

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
    feeBudget: uint(p.feeBudget), archives: p.archives ?? [] };
}

interface ReleaseRecovery {
  deployment: RecoveryDeployment;
  generation: Uint8Array;
  calibration: RecoveryCalibration;
  backlog: Omit<RecoveryBacklog, 'signedStart' | 'observed'>;
}

function recoveryRelease(w: Wallet): ReleaseRecovery {
  const r = w.release.recovery as {
    salt: string; address: string; runtimeHash: string; pins: string;
    ranges: (Omit<RecoveryCalibration['ranges'][number], 'execution'> & { execution: string })[];
    backlog: Record<keyof Omit<RecoveryBacklog, 'signedStart' | 'observed'>, string>;
  } | undefined;
  if (r === undefined || !Array.isArray(r.ranges)) throw new Nb2Error('CapacityPreflight', 'qualified recovery release is required');
  const deployment = { salt: bytes(r.salt, 32), recovery: bytes(r.address, 20), runtimeHash: bytes(r.runtimeHash, 32),
    pins: bytes(r.pins, 32), vaultRuntimeHash: w.pins.vaultRuntimeCodeHash };
  const { pins, runtimeHash, vaultRuntimeHash } = deployment;
  const calibration = { pins, runtimeHash, vaultRuntimeHash,
    ranges: r.ranges.map(({ minReceiptBytes, max, execution }) => ({ minReceiptBytes, max, execution: uint(execution) })) };
  const b = r.backlog;
  return { deployment, calibration, generation: recoveryGeneration(deployment.salt, w.bridge.domain),
    backlog: { duringProgress: uint(b.duringProgress), peakSeals: uint(b.peakSeals), elapsedMs: uint(b.elapsedMs), receiptP99Ms: uint(b.receiptP99Ms),
      advancePeakSeals: uint(b.advancePeakSeals), finalInclusionMs: uint(b.finalInclusionMs), finalPeakSeals: uint(b.finalPeakSeals),
      qualifiedForMs: uint(b.qualifiedForMs) } };
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
  const registry = bytes('0xff00000000000000000000000000000000000002', 20);
  const [receipts, lineage, receiptHash, lineageHash, registryHash] = await Promise.all([
    evm.call(recovery, getter('RECEIPTS')), evm.call(recovery, getter('LINEAGE')),
    evm.call(recovery, getter('RECEIPTS_HASH')), evm.call(recovery, getter('LINEAGE_HASH')), evm.call(recovery, getter('REGISTRY_HASH')),
  ]);
  const helpers = [contractAddress(receipts), contractAddress(lineage), registry];
  const expected = [receiptHash, lineageHash, registryHash];
  if (helpers.some((helper) => helper.length !== 20)) throw new WalletError('BadDeployment', 'invalid recovery helper address');
  const codes = await Promise.all(helpers.map((helper) => evm.code(helper)));
  if (codes.some((code, i) => code.length === 0 || !eq(HE(code), expected[i]))) {
    throw new WalletError('BadDeployment', 'recovery helper runtime differs from the installed binding');
  }
}

interface FeeReservations { total: bigint; attempts: { nonce: bigint; fee: bigint }[] }

async function limitsOf(w: Wallet, p: PayerPolicy, payer: Uint8Array, reserved?: FeeReservations): Promise<RecoveryLimits & { currentBid: bigint }> {
  const evm = w.bridge.evm;
  const block = reserved?.attempts.length ? await evm.blockNumber() : undefined;
  const [balance, minedNonce, nonce, fees] = await Promise.all([
    evm.balance(payer, block), block === undefined ? 0n : evm.nonce(payer, block), evm.nonce(payer), evm.fees(),
  ]);
  const outstanding = reserved?.attempts.reduce((sum, tx) => tx.nonce >= minedNonce ? sum + tx.fee : sum, 0n) ?? 0n;
  const spent = reserved?.total ?? 0n;
  const currentBid = 2n * fees.baseFee + fees.priority;
  if (nonce > p.maxNonce || currentBid > p.maxFeePerGas || fees.priority > p.maxPriorityFeePerGas || spent > p.feeBudget) {
    throw new Nb2Error('CapacityPreflight', 'current payer nonce, bids or remaining budget exceed the declared limits');
  }
  return { ...p, gas: p.gas < w.pins.userGasLimit ? p.gas : w.pins.userGasLimit,
    signedBytes: Math.min(p.signedBytes, Number(w.pins.maxEncodedTxBytes)), chainId: w.bridge.cfg.chainId, worstCaseEnvelope: true,
    balance: balance > outstanding ? balance - outstanding : 0n, currentBid, feeBudget: p.feeBudget - spent };
}

/** Both routes reserve the maximum fee of each durable signed transaction, once per payer. */
function reservedFees(w: Wallet, rec: ReturnRecord, payer: Uint8Array, ordinary: readonly SendRecord[] = rec.sends): FeeReservations {
  const recovery = loadRecovery(w, rec);
  const raw = [...ordinary.map((send) => send.raw), ...(recovery?.attempts ?? []), ...(recovery?.superseded ?? [])];
  if (recovery?.pending) raw.push(recovery.pending.raw);
  if (recovery?.settled?.submitted) raw.push(recovery.settled.submitted.raw);
  const hashes = new Set<string>();
  const attempts: FeeReservations['attempts'] = [];
  let total = uint(recovery?.fees ?? '0'); // older local journals recorded only the total, conservatively retained
  for (const signed of raw) {
    const { request, from, hash } = decodeSignedTx(bytes(signed));
    if (!eq(from, payer) || hashes.has(hx(hash))) continue;
    hashes.add(hx(hash));
    const fee = request.gas * request.maxFeePerGas;
    attempts.push({ nonce: request.nonce, fee });
    total += fee;
  }
  return { total, attempts };
}

export function ordinaryPayout(w: Wallet, rec: ReturnRecord, policy: PayerPolicy): RedeemOptions {
  return {
    envelope: ordinaryEnvelope(w, policy),
    archives: readers(w, policy),
    admit: async (req, prior) => {
      if (w.release.recovery !== undefined) await checkGraph(w, recoveryRelease(w));
      const limits = await limitsOf(w, policy, w.signer.address, reservedFees(w, rec, w.signer.address, prior));
      const fee = req.gas * req.maxFeePerGas;
      if (req.gas > limits.gas || req.nonce > limits.maxNonce || req.maxFeePerGas > limits.maxFeePerGas ||
        req.maxPriorityFeePerGas > limits.maxPriorityFeePerGas || req.data.length > limits.calldataBytes ||
        req.data.length + 256 > limits.signedBytes || fee > limits.balance || fee > limits.feeBudget ||
        (limits.maxTransactionFee !== undefined && fee > limits.maxTransactionFee)) {
        throw new Nb2Error('CapacityPreflight', 'ordinary payment exceeds the remaining payer limits');
      }
    },
  };
}

function ordinaryGas(w: Wallet): ((shape: RedeemShape) => bigint | null) | undefined {
  const release = w.release.recovery as { ordinaryRanges?: {
    maxEvidenceBytes: number; maxOperations: number; maxGaps: string; execution: string;
  }[] } | undefined;
  if (release?.ordinaryRanges === undefined) return undefined;
  const ranges = release.ordinaryRanges.map(({ maxEvidenceBytes, maxOperations, maxGaps, execution }) => {
    if (!Number.isSafeInteger(maxEvidenceBytes) || maxEvidenceBytes < 1 || !Number.isSafeInteger(maxOperations) || maxOperations < 1) {
      throw new Nb2Error('CapacityPreflight', 'invalid ordinary gas range');
    }
    return { maxEvidenceBytes, maxOperations, maxGaps: uint(maxGaps), execution: uint(execution) };
  });
  return (s) => {
    const ops = s.lineage.reduce((n, level) => n + 1 + level.transfers.length, s.pendingTransactions);
    const costs = ranges.filter((r) => r.execution > 0n && s.evidenceBytes <= r.maxEvidenceBytes && ops <= r.maxOperations && s.proofs <= r.maxGaps);
    if (costs.length === 0) return null;
    const execution = costs.reduce((lowest, r) => r.execution < lowest ? r.execution : lowest, costs[0].execution);
    const historyBytes = s.proofs === 0n ? 0 : 32 + Number(s.proofs) * gapProofLen(s.K);
    const bytes = redeemCalldataLength(s.evidenceBytes, historyBytes);
    const reserve = w.pins.gasReserve < 500_000n ? 500_000n : w.pins.gasReserve;
    return 21_000n + 16n * BigInt(bytes) + (6n * execution + 4n) / 5n + reserve;
  };
}

function ordinaryEnvelope(w: Wallet, policy: PayerPolicy): ReturnAdmission['ordinaryEnvelope'] {
  return { encodedBytes: BigInt(Math.min(policy.signedBytes, policy.calldataBytes)), gas: policy.gas, gasFor: ordinaryGas(w) };
}

export function walletAdmission(w: Wallet, policy?: PayerPolicy, backup?: string): ReturnAdmission {
  return {
    ordinaryEnvelope: policy && ordinaryEnvelope(w, policy),
    checkOrdinary: w.release.recovery === undefined && policy === undefined ? undefined : async (rec, gas) => {
      if (!policy) throw new Nb2Error('CapacityPreflight', 'explicit payer limits are required');
      if (w.release.recovery !== undefined) await checkGraph(w, recoveryRelease(w));
      const limits = await limitsOf(w, policy, bytes(rec.payer ?? rec.recipient, 20));
      const fee = gas * limits.currentBid;
      const cap = limits.maxTransactionFee ?? limits.feeBudget;
      if (w.pins.returnReserveSegments < 64n || gas > limits.gas || fee > cap || fee > limits.feeBudget || fee > limits.balance) {
        throw new Nb2Error('CapacityPreflight', 'ordinary return exceeds the payer or reserve limits');
      }
    },
    recover: w.release.recovery === undefined ? undefined : async (rec) => {
      if (!policy) throw new Nb2Error('CapacityPreflight', 'explicit payer limits are required');
      const release = recoveryRelease(w);
      await checkGraph(w, release);
      const payer = bytes(rec.payer ?? rec.recipient, 20);
      const limits = await limitsOf(w, policy, payer, reservedFees(w, rec, payer));
      const a = uint(rec.a);
      const { segment } = await w.bridge.evm.vaultState(w.bridge.cfg.vault);
      const plan = await preflightRecovery(w.pins.gamma, bytes(rec.source), w.trust, buildParams(w.pins.build),
        release.deployment, release.calibration, limits, { ...release.backlog, signedStart: a, observed: segment < a ? a : segment },
        rec.sealReceipt ? bytes(rec.sealReceipt) : undefined);
      const calls = BigInt(plan.run.length) + plan.advance.calls + 1n;
      if ((await w.bridge.evm.nonce(payer)) + calls - 1n > limits.maxNonce) {
        throw new Nb2Error('CapacityPreflight', 'recovery schedule exceeds the declared nonce horizon');
      }
      return { generation: hx(release.generation), calls: String(calls), totalFee: String(plan.totalFee),
        runCuts: plan.run.map((quote) => quote.shape.operations), advanceGaps: plan.advance.quote.shape.gaps,
        observed: String(segment < a ? a : segment), receiptP99Ms: String(release.backlog.receiptP99Ms),
        finalInclusionMs: String(release.backlog.finalInclusionMs), qualifiedForMs: String(release.backlog.qualifiedForMs) };
    },
    beforeCertification: backup ? async (rec) => publishReturnBackup(w, rec, backup) : undefined,
  };
}

/** Qualify a late ordinary burn for cold continuation without changing the signed return. */
export async function qualifyExistingRecovery(w: Wallet, rec: ReturnRecord, policy: PayerPolicy): Promise<ReturnRecord> {
  const { result } = await reconcileReturn(w, rec, policy, undefined, false);
  if (result.state === 'needs-archive') archiveRequired(result.txHash);
  const current = await w.bridge.journal.retForUpdate(rec.returnId);
  if (current?.status === 'paid') return current;
  if (!current?.burned) throw new WalletError('NotPending', 'certify the exact burn before choosing recovery');
  if (current.recovery) return current;
  const staged = loadRecovery(w, current);
  if (staged?.route) {
    const release = recoveryRelease(w);
    const routed = { ...current, ...staged.route };
    await checkGraph(w, release);
    await replay(w, await openSession(w, release, routed), routed, staged);
    await w.bridge.journal.putReturn(routed);
    return routed;
  }
  const qualify = walletAdmission(w, policy).recover;
  if (!qualify) throw new Nb2Error('CapacityPreflight', 'qualified recovery release is required');
  current.recovery = await qualify({ ...current, payer: hx(w.signer.address) });
  await w.bridge.journal.putReturn(current);
  return current;
}

interface Backup {
  version: 1; gamma: string; vaultRuntimeHash: string; pending: ReturnRecord;
  terminal?: string; checkpoint?: RecoveryJournal; paid?: ReturnRecord['paid'];
}

/** A holder-selected private file. Hard-link publication cannot clobber a changed destination. */
export function publishReturnBackup(w: Wallet, rec: ReturnRecord, file: string): void {
  if (!rec.burnRequest || !rec.certificationLocator) throw new Error('sign the return before exporting a relayer backup');
  const saved = loadRecovery(w, rec);
  if (saved?.route && rec.recovery) rec = { ...rec, ...saved.route };
  const { source, amount, returnId, recipient, a, startHead, fromBlock, sealReceipt, burnTx, burnRequest, certificationLocator, recovery } = rec;
  const pending: ReturnRecord = { ...w.bridge.journal.base(), kind: 'return', status: 'burn-requested', sends: [], source, amount, returnId,
    recipient, a, startHead, fromBlock, sealReceipt, burnTx, burnRequest, certificationLocator, recovery };
  // Confirmed cuts and receipts are portable. The previous payer's pending transaction is local.
  const checkpoint = saved && rec.recovery && {
    ...saved, pending: undefined, settled: undefined, fees: undefined, attempts: undefined, superseded: undefined, route: undefined,
  };
  const copy: Backup = { version: 1, gamma: hx(w.pins.gamma), vaultRuntimeHash: hx(w.pins.vaultRuntimeCodeHash), pending, terminal: rec.burned, checkpoint, paid: rec.paid?.receipt ? rec.paid : undefined };
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
  const settlements = (journal?.superseded ?? []).map((raw) => decodeSignedTx(bytes(raw)))
    .filter((tx) => eq(tx.request.to, w.bridge.cfg.vault)).map((tx) => tx.hash);
  if (journal?.pending?.cut.kind === 'settle') settlements.push(decodeSignedTx(bytes(journal.pending.raw)).hash);
  const evidence: ReturnEvidence = { paid: incoming?.paid, settlements, readOnly: !resubmit };
  const paidResult = (record: ReturnRecord): ReconcileResult =>
    record.paid ? { state: 'paid', txHash: bytes(record.paid.txHash, 32), blockNumber: uint(record.paid.blockNumber) } : { state: 'not-paid' };
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
  const archive = policy ? readers(w, policy) : [w.bridge.evm];
  let freshCheckpoint: RecoveryJournal | undefined;
  const { record: selected } = await reconcileReturn(w, backup.pending, policy, {
    terminal: terminal === undefined ? undefined : bytes(terminal),
    paid: backup.paid,
    beforeCommit: async (verified, incoming) => {
      if (backup.checkpoint && (!incoming.recovery || !incoming.burned)) throw new Error('portable cuts require a certified recovery schedule');
      if (!verified.recovery && !incoming.recovery) return;
      const release = recoveryRelease(w);
      await checkGraph(w, release);
      const local = loadRecovery(w, verified);
      // A staged route is already durable when the active record write is interrupted.
      const held = local?.route && (verified.recovery || verified.burned) ? { ...verified, ...local.route } : verified;
      const localSession = held.recovery && local ? await openSession(w, release, held) : undefined;
      const localCursor = localSession && await replay(w, localSession, held, local!);
      const portable = backup.checkpoint;
      const candidate = portable && await replay(w, await openSession(w, release, incoming), incoming, portable);
      if (portable && candidate && (!localCursor || advances(candidate, localCursor))) {
        const { recovery, burned } = incoming;
        const route = { recovery: recovery!, burned: burned! };
        const superseded = [...(local?.superseded ?? [])];
        if (local?.pending && localCursor && localSession) {
          await openPendingPacket(w, held, release, localSession, localCursor, local.pending);
          superseded.push(local.pending.raw);
        }
        const journal: RecoveryJournal = {
          ...portable, route, pending: undefined, settled: undefined, fees: local?.fees,
          attempts: local?.attempts, superseded: superseded.length ? superseded : undefined,
        };
        // Certified work stands on its own. Any new packet must still qualify against this release.
        if (journal.cuts.length === 0) await qualifyRestoredSchedule(w, release, incoming, journal, candidate);
        // An installed route must see the new cursor and its nonce obligations in one durable write.
        // A fresh journal binds the signed return first, so a crash cannot leave an orphan route.
        if ((await w.bridge.journal.ret(verified.returnId))?.burnRequest) saveRecovery(w, verified, journal);
        else freshCheckpoint = journal;
        return 'incoming-recovery';
      }
      if (local?.pending && localSession && localCursor) {
        const read = await reconcilePendingPacket(w, held, release, localSession, local, localCursor, archive);
        if (read.state === 'needs-archive') archiveRequired(read.txHash);
      }
      const active = held.recovery ? held : incoming;
      if (active.recovery && !local?.pending && !local?.cuts.length) await qualifyRestoredSchedule(w, release, active, local, localCursor);
      if (local?.route && held.burned === incoming.burned &&
        JSON.stringify(held.recovery) === JSON.stringify(incoming.recovery)) return 'incoming-recovery';
    },
  });
  if (selected.status === 'paid') return selected;
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

export function archiveRequired(hash: Uint8Array): never {
  throw new WalletError('EvidenceMissing', `needs archive for exact transaction ${hx(hash)}. Add an archive reader with the certified block, receipts and raw transactions, then resume`);
}

function advances(candidate: Cursor, held: Cursor): boolean {
  if (candidate.from !== held.from) return candidate.from > held.from;
  const next = candidate.gap?.cursor?.next;
  return next !== undefined && (held.gap?.cursor === undefined || next > held.gap.cursor.next);
}

async function qualifyRestoredSchedule(w: Wallet, release: ReleaseRecovery, rec: ReturnRecord,
  journal?: RecoveryJournal, cursor?: Cursor): Promise<void> {
  const held = bytes(rec.source);
  const { runCuts, advanceGaps } = rec.recovery!;
  checkSchedule(rec, w.bridge.returnHeadroom(held).operations);
  const { cfg, evm } = w.bridge;
  // The wallet uses the same maximal envelope widths at admission, regardless of the current bids.
  const limits: RecoveryLimits = {
    gas: w.pins.userGasLimit, signedBytes: Number(w.pins.maxEncodedTxBytes), calldataBytes: 393_216,
    chainId: cfg.chainId, maxNonce: 0n, maxFeePerGas: 1n, maxPriorityFeePerGas: 0n,
    balance: 0n, feeBudget: 0n, worstCaseEnvelope: true,
  };
  if (!quoteRecoveryGapBatch(cfg.K, advanceGaps, release.calibration, limits)) {
    throw new Nb2Error('CapacityPreflight', 'portable gap batch or settlement suffix is outside the release limits');
  }
  const confirmedCuts = journal?.cuts.filter((item) => item.cut.kind === 'run').length ?? 0;
  checkRemainingRecoveryRuns(held, runCuts, confirmedCuts, release.calibration, limits);
  const covered = cursor?.gap?.cursor?.next ?? uint(rec.a);
  const { segment } = await evm.vaultState(cfg.vault);
  recoveryCatchUpCalls(advanceGaps, {
    ...release.backlog, signedStart: covered, observed: segment > covered ? segment : covered,
    duringProgress: confirmedCuts < runCuts.length ? release.backlog.duringProgress : 0n,
  });
}

type Cut = { kind: 'run'; count: number } | { kind: 'advance'; gaps: string[] } | { kind: 'settle'; gaps: string[] };
interface Location { txHash: string; blockNumber: string; blockHash: string; txIndex: string; logIndex: string; proof: string }
interface RecoveryJournal {
  version: 1;
  session: string; pageRoot: string; evidence: string; evidenceBytes: number; generation: string;
  fees?: string;
  attempts?: string[];
  /** Signed local attempts whose work has been superseded by a certified peer cursor. */
  superseded?: string[];
  /** Installed checkpoint route, staged together with its authenticated cuts. */
  route?: { recovery: NonNullable<ReturnRecord['recovery']>; burned: string };
  cuts: { cut: Exclude<Cut, { kind: 'settle' }>; location: Location; seq: string; nonce: string; priorSeq: string; state?: string; endpoint?: string; head?: string }[];
  pending?: { cut: Cut; raw: string; txHash: string; nonce: string; priorSeq: string; failureProofReads?: number };
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
function saveRecovery(w: Wallet, rec: ReturnRecord, journal: RecoveryJournal): void {
  writeDurable(pathOf(w, rec), JSON.stringify(journal));
}

function initialJournal(s: RecoverySession, rec: ReturnRecord): RecoveryJournal {
  const evidence = evidenceOf(bytes(rec.burned!));
  return { version: 1, session: hx(s.id), pageRoot: hx(s.pageRoot), generation: rec.recovery!.generation,
    evidence: hx(evidence), evidenceBytes: evidence.length, cuts: [] };
}

/** Commit the terminal continuation identity as soon as burn certification succeeds. */
export async function retainTerminal(w: Wallet, rec: ReturnRecord): Promise<void> {
  if (!rec.recovery || loadRecovery(w, rec)) return;
  const session = await openSession(w, recoveryRelease(w), rec);
  saveRecovery(w, rec, initialJournal(session, rec));
}

const sessions = new WeakMap<Wallet, { burned: string; generation: string; trust: TrustInput; session: RecoverySession }>();

async function openSession(w: Wallet, release: ReleaseRecovery, rec: ReturnRecord): Promise<RecoverySession> {
  const generation = hx(release.generation);
  if (rec.recovery?.generation !== generation || !rec.burned) throw new WalletError('BadDeployment', 'return belongs to another generation or is uncertified');
  const cached = sessions.get(w);
  const trust = w.trust;
  let session = cached?.burned === rec.burned && cached.generation === generation && cached.trust === trust ? cached.session : undefined;
  if (session === undefined) {
    const authority = new RecoveryAuthority(trust, async (next) => w.persistAuthority(next));
    session = await RecoverySession.create(w.pins.gamma, evidenceOf(bytes(rec.burned)), authority, buildParams(w.pins.build), release.deployment);
  }
  if (rec.eta !== hx(session.redemptionId)) throw new WalletError('BadInput', 'continuation session has the wrong redemption ID');
  checkSchedule(rec, session.operationCount);
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

async function replay(w: Wallet, s: RecoverySession, rec: ReturnRecord, journal: RecoveryJournal): Promise<Cursor> {
  const evidence = evidenceOf(bytes(rec.burned!));
  if (journal.version !== 1 || journal.evidenceBytes !== evidence.length || journal.session !== hx(s.id) || journal.pageRoot !== hx(s.pageRoot) || journal.generation !== rec.recovery?.generation ||
    journal.evidence !== hx(evidence)) throw new Error('recovery journal does not bind the certified evidence');
  const cursor: Cursor = { from: 0 };
  for (const [i, item] of journal.cuts.entries()) {
    if (item.cut.kind === 'run' && item.cut.count !== rec.recovery!.runCuts[i]) throw new Error('portable cut disagrees with the admitted schedule');
    // The saved transaction hash is a lookup hint. The certificate binds the receipt index.
    bytes(item.location.txHash, 32);
    if (uint(item.priorSeq) !== (cursor.prior?.seq ?? 0n)) throw new Error('checkpoint has the wrong preceding sequence');
    uint(item.nonce);
    const packet = await withFreshAuthority(w, () => packetOf(s, w.trust, rec, cursor, item.cut));
    if (!packet.event) throw new Error('settlement is reconciled through the vault Paid receipt');
    const event = packet.event;
    const receipt = await withFreshAuthority(w, () => s.verifyEvent(w.trust, bytes(item.location.proof), event));
    if (!matches(receipt, item.location)) throw new Error('checkpoint locator disagrees with its authenticated receipt');
    advanceCursor(cursor, packet, receipt.encoded);
    const state = 'state' in packet && packet.state ? hx(packet.state) : undefined;
    if (item.seq !== String(cursor.prior!.seq) || item.state !== state ||
      item.endpoint !== (cursor.gap?.cursor && String(cursor.gap.cursor.next)) ||
      item.head !== (cursor.gap?.cursor && hx(cursor.gap.cursor.head))) throw new Error('saved checkpoint disagrees with the authenticated cut');
  }
  return cursor;
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
  return [w.bridge.evm, ...policy.archives.map((url) => new EvmReader(new HttpJsonRpc(url)))];
}

async function withFreshAuthority<T>(w: Wallet, f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch (e) {
    if (!(e instanceof Nb2Error)) throw e;
    let cause = e;
    while (cause.inner && !(cause instanceof SealAheadOfOrigin)) cause = cause.inner;
    if (!e.retryable && !(cause instanceof SealAheadOfOrigin)) throw e;
    await w.refreshAuthority();
    return f();
  }
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

export type RecoveryResult = { state: 'paid'; txHash: Uint8Array; blockNumber: bigint } |
  { state: 'pending' | 'checkpoint' | 'retry' | 'needs-archive'; txHash: Uint8Array };

function retainPayment(w: Wallet, rec: ReturnRecord, txHash: string): void {
  const saved = loadRecovery(w, rec);
  if (!saved || saved.settled) return;
  saved.settled = { paidTx: txHash, submitted: saved.pending };
  delete saved.pending;
  saveRecovery(w, rec, saved);
}

/** A certified event authenticates the cursor. Check nonce consumption independently. */
async function reconcileLowerNonces(w: Wallet, rec: ReturnRecord): Promise<{ state: 'pending'; txHash: Uint8Array } | undefined> {
  const journal = loadRecovery(w, rec);
  const raw = [...(journal?.superseded ?? []), ...(journal?.attempts ?? [])];
  if (!raw.length) return;
  const block = await w.bridge.evm.blockNumber();
  const mined = await w.bridge.evm.nonce(w.signer.address, block);
  const unresolved = raw.map((signed) => ({ ...decodeSignedTx(bytes(signed)), raw: bytes(signed) }))
    .filter((tx) => eq(tx.from, w.signer.address) && tx.request.nonce >= mined)
    .sort((a, b) => a.request.nonce < b.request.nonce ? -1 : a.request.nonce > b.request.nonce ? 1 : 0)[0];
  if (!unresolved) return;
  try {
    await w.bridge.evm.sendRaw(unresolved.raw);
  } catch (e) {
    if (!(e instanceof AmbiguousBroadcast)) throw e;
  }
  // Wait for a mined nonce, even if this exact transaction is back in the pool.
  return { state: 'pending', txHash: unresolved.hash };
}

async function reconcileForPayout(w: Wallet, rec: ReturnRecord, policy?: PayerPolicy) {
  const journal = loadRecovery(w, rec);
  const priorAttempts = Boolean(journal?.superseded?.length || journal?.attempts?.length);
  const first = await reconcileReturn(w, rec, policy, undefined, !priorAttempts);
  if (first.result.state === 'paid' || first.result.state === 'needs-archive') return first;
  const blocked = await reconcileLowerNonces(w, first.record);
  if (blocked) return { record: first.record, result: blocked };
  return priorAttempts && first.result.state === 'pending' ? reconcileReturn(w, first.record, policy) : first;
}

/** Ordinary redeem shares payment closure and nonce reconciliation with recovery. */
export async function redeemOrdinary(w: Wallet, rec: ReturnRecord, policy?: PayerPolicy): Promise<ReconcileResult> {
  const { record, result } = await reconcileForPayout(w, rec, policy);
  if (result.state !== 'not-paid') return result;
  const payout = await w.bridge.submitRedeem(bytes(record.returnId, 32), w.signer, policy && ordinaryPayout(w, record, policy));
  if (payout.state === 'paid') await reconcileReturn(w, record, policy);
  return payout;
}

/** Execute at most one new packet. Reconcile the same saved bytes after an ambiguous send. */
export async function recoverStep(w: Wallet, rec: ReturnRecord, policy: PayerPolicy): Promise<RecoveryResult> {
  const archive = readers(w, policy);
  const first = await reconcileForPayout(w, rec, policy);
  if (first.result.state !== 'not-paid') return first.result;
  rec = first.record;
  const release = recoveryRelease(w);
  await checkGraph(w, release);
  const local = loadRecovery(w, rec);
  if (local?.route) rec = { ...rec, ...local.route };
  const s = await openSession(w, release, rec);
  const journal = local ?? initialJournal(s, rec);
  const cursor = await replay(w, s, rec, journal);

  if (journal.pending === undefined) {
    await qualifyRestoredSchedule(w, release, rec, journal, cursor);
    const current = (await w.bridge.journal.ret(rec.returnId))!;
    const limits = await limitsOf(w, policy, w.signer.address, reservedFees(w, current, w.signer.address));
    let cut: Cut;
    let quote: RecoveryQuote | null;
    let calldata: Uint8Array;
    let to = release.deployment.recovery;
    if (!cursor.gap) {
      const count = rec.recovery!.runCuts[journal.cuts.length];
      const packet = await s.run(cursor.from, count, w.trust, cursor.prior);
      cut = { kind: 'run', count };
      quote = quoteRecovery(packet.shape, release.calibration, limits);
      ({ calldata } = packet);
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
          gaps = await withFreshAuthority(w, () => s.certifiedGaps(w.trust, start, head, proofs));
          break;
        } catch (e) { error = e; }
      }
      if (!gaps) throw error;
      const startHead = !cursor.gap.cursor && gaps.length > 0 ? head : undefined;
      const settlement = segment - start < batch ? await s.gaps('redeemRecovered', w.trust, cursor.prior!.receipt, cursor.gap, gaps, startHead) : undefined;
      const price = settlement && quoteRecovery(settlement.shape, release.calibration, limits);
      if (settlement && price) {
        cut = { kind: 'settle', gaps: gaps.map(hx) };
        calldata = settlement.calldata;
        quote = price;
        to = w.bridge.cfg.vault;
      } else {
        if (BigInt(gaps.length) !== batch) throw new Nb2Error('CapacityPreflight', 'qualified settlement suffix exceeds payer limits');
        const packet = await s.gaps('advanceGaps', w.trust, cursor.prior!.receipt, cursor.gap, gaps, startHead);
        cut = { kind: 'advance', gaps: gaps.map(hx) };
        ({ calldata } = packet);
        quote = quoteRecovery(packet.shape, release.calibration, limits);
      }
    }
    const nonce = await w.bridge.evm.nonce(w.signer.address);
    if (quote === null || nonce > limits.maxNonce || quote.fee > limits.feeBudget || quote.fee > limits.balance) {
      throw new Nb2Error('CapacityPreflight', 'packet exceeds the remaining payer limits');
    }
    const tx = await signTx(w.signer, { chainId: limits.chainId, nonce, maxFeePerGas: limits.maxFeePerGas,
      maxPriorityFeePerGas: limits.maxPriorityFeePerGas, gas: quote.gas, to, value: 0n, data: calldata });
    if (tx.raw.length > quote.signedBytes) throw new Nb2Error('CapacityPreflight', 'signed recovery packet exceeds its bound');
    journal.pending = { cut, raw: hx(tx.raw), txHash: hx(tx.hash), nonce: String(nonce), priorSeq: String(cursor.prior?.seq ?? 0n) };
    saveRecovery(w, rec, journal);
  }
  return reconcilePendingPacket(w, rec, release, s, journal, cursor, archive, () => reconcileReturn(w, rec, policy).then(({ result }) => result));
}

async function openPendingPacket(w: Wallet, rec: ReturnRecord, release: ReleaseRecovery, s: RecoverySession,
  cursor: Cursor, pending: NonNullable<RecoveryJournal['pending']>) {
  const raw = bytes(pending.raw);
  const { request, hash } = decodeSignedTx(raw);
  const packet = await withFreshAuthority(w, () => packetOf(s, w.trust, rec, cursor, pending.cut));
  if (hx(hash) !== pending.txHash || String(request.nonce) !== pending.nonce || String(cursor.prior?.seq ?? 0n) !== pending.priorSeq ||
    request.value !== 0n || request.chainId !== w.bridge.cfg.chainId || !eq(request.data, packet.calldata) ||
    !eq(request.to, pending.cut.kind === 'settle' ? w.bridge.cfg.vault : release.deployment.recovery)) {
    throw new Error('pending transaction does not match the authenticated cut');
  }
  return { raw, hash, packet };
}

/** Reconcile a durable send without signing. Restore only reads receipts. */
async function reconcilePendingPacket(w: Wallet, rec: ReturnRecord, release: ReleaseRecovery, s: RecoverySession,
  journal: RecoveryJournal, cursor: Cursor, archive: readonly EvmReader[],
  reconcile?: () => Promise<ReconcileResult>): Promise<RecoveryResult> {
  const pending = journal.pending!;
  const { raw, hash, packet } = await openPendingPacket(w, rec, release, s, cursor, pending);
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
  let pruned = false;
  let failed = false;
  const outcome = async (): Promise<'missing' | 'pending' | 'success' | 'failed'> => {
    let seen = false;
    let success = false;
    for (const reader of archive) {
      try {
        const receipt = await reader.receipt(hash);
        if (!receipt) continue;
        seen = true;
        if (BigInt(receipt.status) === 1n) {
          success = true;
          continue;
        }
        failed = true;
        await withFreshAuthority(w, () => reader.verifyFailedReceipt(hash, w.bridge.cfg, w.trust, receipt));
        return 'failed';
      } catch (e) {
        if (e instanceof WalletError && e.reason === 'TrustInput') throw e;
        if (e instanceof Nb2Error && e.rule === 'EvidencePruned') pruned = true;
        // Metadata is only a hint. Try the next reader's complete proof.
      }
    }
    return success ? 'success' : seen ? 'pending' : 'missing';
  };
  let mined = await outcome();
  if (mined === 'missing' && reconcile && pending.failureProofReads === undefined) {
    try { await w.bridge.evm.sendRaw(raw); }
    catch (e) { if (!(e instanceof AmbiguousBroadcast)) throw e; }
    mined = await outcome();
  }
  const unresolved = (): RecoveryResult => {
    if (failed || pending.failureProofReads !== undefined) {
      const reads = pruned ? FAILURE_PROOF_READS : Math.min((pending.failureProofReads ?? 0) + 1, FAILURE_PROOF_READS);
      if (reads !== pending.failureProofReads) {
        pending.failureProofReads = reads;
        saveRecovery(w, rec, journal);
      }
    }
    if (pending.failureProofReads === FAILURE_PROOF_READS) return { state: 'needs-archive', txHash: hash };
    return { state: 'pending', txHash: hash };
  };
  if (mined === 'missing' || mined === 'pending') return unresolved();
  if (mined === 'failed') {
    (journal.attempts ??= []).push(pending.raw);
    delete journal.pending;
    saveRecovery(w, rec, journal);
    return { state: 'retry', txHash: hash };
  }
  if (pending.cut.kind === 'settle') {
    const result = await reconcile?.();
    return !result || result.state === 'not-paid' || result.state === 'pending' ? unresolved() : result;
  }
  let acquired;
  try {
    acquired = await s.acquire(w.trust, packet.event!, archive.map((r) => recoveryRpcSource(r, hash)), () => w.refreshAuthority());
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
