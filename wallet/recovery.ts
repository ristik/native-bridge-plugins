/** Durable, key-independent NB2-C return continuation for the reference wallet. */
import { randomBytes } from 'node:crypto';
import { existsSync, linkSync, lstatSync, readFileSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { eq } from '../packages/native-bridge-plugin/src/bytes.js';
import {
  AmbiguousBroadcast, EvmReader, HttpJsonRpc, Nb2Error, RecoveryAuthority, RecoverySession, TOPIC, WalletError,
  buildParams, decodeSignedTx, evidenceOf, gapProofLen, preflightRecovery, quoteRecovery, quoteRecoveryGapBatch, redeemCalldataLength, recoveryGeneration,
  recoveryRpcSource, signTx, type GapPrior, type RecoveryBacklog, type RecoveryCalibration,
  type RecoveryDeployment, type RecoveryEvent, type RecoveryLimits, type RecoveryQuote, type RecoveryReceipt,
  type RedeemShape, type ReturnAdmission, type ReturnRecord, type TrustInput, type SendRecord, type RedeemOptions,
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
  // Read the mined nonce first. If a send lands between reads, reserving it for this check is conservative.
  const minedNonce = reserved?.attempts.length ? await w.bridge.evm.nonce(payer, 'latest') : 0n;
  const outstanding = reserved?.attempts.reduce((sum, tx) => tx.nonce >= minedNonce ? sum + tx.fee : sum, 0n) ?? 0n;
  const spent = reserved?.total ?? 0n;
  const [balance, nonce, fees] = await Promise.all([w.bridge.evm.balance(payer), w.bridge.evm.nonce(payer), w.bridge.evm.fees()]);
  const currentBid = 2n * fees.baseFee + fees.priority;
  if (nonce > p.maxNonce || currentBid > p.maxFeePerGas || fees.priority > p.maxPriorityFeePerGas || spent > p.feeBudget) {
    throw new Nb2Error('CapacityPreflight', 'current payer nonce, bids or remaining budget exceed the declared limits');
  }
  return { ...p, gas: p.gas < w.pins.userGasLimit ? p.gas : w.pins.userGasLimit,
    signedBytes: Math.min(p.signedBytes, Number(w.pins.maxEncodedTxBytes)), chainId: w.bridge.cfg.chainId,
    balance: balance > outstanding ? balance - outstanding : 0n, currentBid, feeBudget: p.feeBudget - spent };
}

/** Both routes reserve the maximum fee of each durable signed transaction, once per payer. */
function reservedFees(w: Wallet, rec: ReturnRecord, payer: Uint8Array, ordinary: readonly SendRecord[] = rec.sends): FeeReservations {
  const recovery = loadRecovery(w, rec);
  const raw = [...ordinary.map((send) => send.raw), ...(recovery?.attempts ?? [])];
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
  const current = await w.bridge.journal.retForUpdate(rec.returnId);
  if (!current?.burned) throw new WalletError('NotPending', 'certify the exact burn before choosing recovery');
  if (current.status === 'paid' || current.recovery) return current;
  const qualify = walletAdmission(w, policy).recover;
  if (!qualify) throw new Nb2Error('CapacityPreflight', 'qualified recovery release is required');
  current.recovery = await qualify({ ...current, payer: hx(w.signer.address) });
  await w.bridge.journal.putReturn(current);
  return current;
}

interface Backup { version: 1; gamma: string; vaultRuntimeHash: string; pending: ReturnRecord; terminal?: string; checkpoint?: RecoveryJournal }

/** A holder-selected private file. Hard-link publication cannot clobber a changed destination. */
export function publishReturnBackup(w: Wallet, rec: ReturnRecord, file: string): void {
  if (!rec.burnRequest || !rec.certificationLocator) throw new Error('sign the return before exporting a relayer backup');
  const { source, amount, returnId, recipient, a, startHead, fromBlock, sealReceipt, burnTx, burnRequest, certificationLocator, recovery } = rec;
  const pending: ReturnRecord = { ...w.bridge.journal.base(), kind: 'return', status: 'burn-requested', sends: [], source, amount, returnId,
    recipient, a, startHead, fromBlock, sealReceipt, burnTx, burnRequest, certificationLocator, recovery };
  const saved = loadRecovery(w, rec);
  // Confirmed cuts and receipts are portable. The previous payer's pending transaction is local.
  const checkpoint = saved && { ...saved, pending: undefined, settled: undefined, fees: undefined, attempts: undefined };
  const copy: Backup = { version: 1, gamma: hx(w.pins.gamma), vaultRuntimeHash: hx(w.pins.vaultRuntimeCodeHash), pending, terminal: rec.burned, checkpoint };
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

export async function restoreReturn(w: Wallet, file: string): Promise<ReturnRecord> {
  const backup = JSON.parse(readFileSync(file, 'utf8')) as Backup;
  if (backup.version !== 1 || backup.gamma !== hx(w.pins.gamma) || backup.vaultRuntimeHash !== hx(w.pins.vaultRuntimeCodeHash)) {
    throw new WalletError('BadDeployment', 'backup belongs to another installed deployment');
  }
  const rec = backup.pending;
  // Older portable checkpoint files carry the same terminal bytes as their flat evidence.
  const terminal = backup.terminal ?? backup.checkpoint?.evidence;
  const release = rec.recovery ? recoveryRelease(w) : undefined;
  if (release) {
    await checkGraph(w, release);
    if (rec.recovery!.generation !== hx(release.generation)) throw new WalletError('BadDeployment', 'backup belongs to another recovery generation');
  }
  if (backup.checkpoint && !release) throw new Error('portable cuts require a recovery schedule');
  await w.bridge.importPendingReturn(rec, terminal === undefined ? undefined : bytes(terminal), async (verified) => {
    if (!release) return;
    checkSchedule(verified, w.bridge.returnHeadroom(bytes(verified.source)).operations);
    const { cfg } = w.bridge;
    // Check transport and gas independently of the relayer's bids and funding.
    // Maximal field widths cover the entire signed envelope.
    const maxFeePerGas = (1n << 256n) - 1n;
    const batch = quoteRecoveryGapBatch(cfg.K, verified.recovery!.advanceGaps, release.calibration, {
      gas: w.pins.userGasLimit, signedBytes: Number(w.pins.maxEncodedTxBytes), calldataBytes: 393_216,
      chainId: cfg.chainId, maxNonce: (1n << 64n) - 1n, maxFeePerGas, maxPriorityFeePerGas: maxFeePerGas,
      balance: 0n, feeBudget: 0n,
    });
    if (!batch) throw new Nb2Error('CapacityPreflight', 'portable gap batch or settlement suffix is outside the release limits');
    if (!backup.checkpoint) return;
    const session = await openSession(w, release, verified);
    await replay(w, session, verified, backup.checkpoint);
  });
  if (terminal === undefined) await w.bridge.burn(bytes(rec.returnId, 32));
  const confirmed = (await w.bridge.journal.ret(rec.returnId))!;
  if (backup.checkpoint && !loadRecovery(w, confirmed) && confirmed.burned === terminal) {
    saveRecovery(w, confirmed, { ...backup.checkpoint, pending: undefined, settled: undefined, fees: undefined, attempts: undefined });
  }
  await retainTerminal(w, confirmed);
  return confirmed;
}

type Cut = { kind: 'run'; count: number } | { kind: 'advance'; gaps: string[] } | { kind: 'settle'; gaps: string[] };
interface Location { txHash: string; blockNumber: string; blockHash: string; txIndex: string; logIndex: string; proof: string }
interface RecoveryJournal {
  version: 1;
  session: string; pageRoot: string; evidence: string; evidenceBytes: number; generation: string;
  fees?: string;
  attempts?: string[];
  cuts: { cut: Exclude<Cut, { kind: 'settle' }>; location: Location; seq: string; nonce: string; priorSeq: string; state?: string; endpoint?: string; head?: string }[];
  pending?: { cut: Cut; raw: string; txHash: string; nonce: string; priorSeq: string };
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
  { state: 'pending' | 'checkpoint' | 'retry'; txHash: Uint8Array };

/** Execute at most one new packet. Reconcile the same saved bytes after an ambiguous send. */
export async function recoverStep(w: Wallet, rec: ReturnRecord, policy: PayerPolicy): Promise<RecoveryResult> {
  const release = recoveryRelease(w);
  await checkGraph(w, release);
  const id = bytes(rec.returnId, 32);
  const archive = readers(w, policy);
  const reconcile = async () => {
    const result = await w.bridge.reconcile(id, archive);
    if (result.state === 'paid') {
      const saved = loadRecovery(w, rec);
      if (saved && !saved.settled) {
        saved.settled = { paidTx: hx(result.txHash), submitted: saved.pending };
        delete saved.pending;
        saveRecovery(w, rec, saved);
      }
    }
    return result;
  };
  const paid = await reconcile();
  if (paid.state !== 'not-paid') return paid;
  const s = await openSession(w, release, rec);
  const journal = loadRecovery(w, rec) ?? initialJournal(s, rec);
  const cursor = await replay(w, s, rec, journal);

  if (journal.pending === undefined) {
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
  const pending = journal.pending;
  const raw = bytes(pending.raw);
  const { request, hash } = decodeSignedTx(raw);
  const packet = await packetOf(s, w.trust, rec, cursor, pending.cut);
  if (hx(hash) !== pending.txHash || String(request.nonce) !== pending.nonce || String(cursor.prior?.seq ?? 0n) !== pending.priorSeq ||
    request.value !== 0n || request.chainId !== w.bridge.cfg.chainId || !eq(request.data, packet.calldata) ||
    !eq(request.to, pending.cut.kind === 'settle' ? w.bridge.cfg.vault : release.deployment.recovery)) {
    throw new Error('pending transaction does not match the authenticated cut');
  }
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
        await withFreshAuthority(w, () => reader.verifyFailedReceipt(hash, w.bridge.cfg, w.trust, receipt));
        return 'failed';
      } catch (e) {
        if (e instanceof WalletError && e.reason === 'TrustInput') throw e;
        // Metadata is only a hint. Try the next reader's complete proof.
      }
    }
    return success ? 'success' : seen ? 'pending' : 'missing';
  };
  let mined = await outcome();
  if (mined === 'missing') {
    try { await w.bridge.evm.sendRaw(raw); }
    catch (e) { if (!(e instanceof AmbiguousBroadcast)) throw e; }
    mined = await outcome();
  }
  if (mined === 'missing' || mined === 'pending') return { state: 'pending', txHash: hash };
  if (mined === 'failed') {
    (journal.attempts ??= []).push(pending.raw);
    delete journal.pending;
    saveRecovery(w, rec, journal);
    return { state: 'retry', txHash: hash };
  }
  if (pending.cut.kind === 'settle') {
    const result = await reconcile();
    return result.state === 'not-paid' ? { state: 'pending', txHash: hash } : result;
  }
  const acquired = await s.acquire(w.trust, packet.event!, archive.map((r) => recoveryRpcSource(r, hash)), () => w.refreshAuthority());
  advanceCursor(cursor, packet, acquired.receipt.encoded);
  journal.cuts.push({ cut: pending.cut, location: location(hx(hash), acquired.receipt), seq: String(cursor.prior!.seq),
    nonce: pending.nonce, priorSeq: pending.priorSeq,
    ...(cursor.gap?.cursor ? { endpoint: String(cursor.gap.cursor.next), head: hx(cursor.gap.cursor.head) } : {}),
    ...('state' in packet && packet.state ? { state: hx(packet.state) } : {}) });
  (journal.attempts ??= []).push(pending.raw);
  delete journal.pending;
  saveRecovery(w, rec, journal);
  return { state: 'checkpoint', txHash: hash };
}

export async function returnHeadroom(w: Wallet, token: Uint8Array): Promise<string> {
  const held = await w.bridge.verifyToken(token);
  const { operations, bytes: size, ordinarySegments } = w.bridge.returnHeadroom(token);
  return `${held.amount} wei held, ${size} evidence bytes, room for at most ${ordinarySegments} ordinary gap proofs by size, ${Math.ceil(operations / 16)} minimum recovery packets through Complete; funding and gas are checked before signing`;
}
