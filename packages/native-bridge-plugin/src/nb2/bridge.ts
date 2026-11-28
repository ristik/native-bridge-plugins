/**
 * The native bridge v2 wallet API (NB2-07, bft-core#1103). A wallet bridges native UCT with these calls and does not handle segments,
 * gap proofs or receipt tries itself:
 *
 *   EVM -> Unicity   planDeposit, submitDeposit, collectDepositProof, mint
 *   circulation      transfer, split (ordinary token operations; nothing touches the EVM)
 *   Unicity -> EVM   planReturn, burn, buildRedeem, submitRedeem, reconcile
 *
 * Network adapters fetch bytes; pure functions verify them offline. Every step is journaled BEFORE the step it enables, so a crash at
 * any point resumes by calling the same function again with the same identifier:
 *   - the deposit secret's intent and its backed-up high-water mark exist before value is sent (`submitDeposit` refuses otherwise);
 *   - every signed EVM transaction is journaled before it is broadcast, and an earlier send is reconciled before any new one;
 *   - a burn's exact request is journaled before it is certified, and the certified burn before success is reported;
 *   - the burn index comes from a verified SegmentSealed receipt (or is zero), never from a plain RPC number outside test deployments.
 */
import { concat, eq, toHex } from '../bytes.js';
import { addressWord, approveCalldata, classifyRedeemError, decodeBytesReturn, depositErc20Calldata, decodeDeposited, decodePaid, decodeRevert, depositCalldata, redeemCalldata, redeemCalldataLength, SELECTOR, type DecodedError, type RedeemAction } from './abi.js';
import { ascii, beInt, cArr, cBytes, u256 } from './cbor.js';
import { buildParams, configIdentities, decodeConfig, domainOf, log2, type Build, type Config } from './config.js';
import { HE, HU, parseKey, verifyUnlock } from './crypto.js';
import {
  TOPIC, depositTopic, decodeDepositProof, decodeReceiptBacking, depositIntentSecret, depositSalt, encodeReceiptBacking, firstOwnerOf, rhoOf, verifyDepositEvidence, verifyReceiptLog,
} from './deposit.js';
import { ERC20_RETURN_RISKS, erc20Create2, type Erc20ActivationPins } from './erc20.js';
import { Nb2Error, WalletError, fail, refuse } from './errors.js';
import { decodeSignedTx, replacementBid, signTx, type EvmSigner, type SignedTx, type TxRequest } from './evm.js';
import { bindHeader } from './header.js';
import { MeasuredGasModel, createAddress, redeemTxFraming, type GasModel, type RedeemShape } from './gas.js';
import {
  Journal, continuationReserve, dec, hex, undec, unhex, payerNonceLimit, remainingOrdinaryAttempts, remainingRecoveryCalls,
  type PayerCommitments, type DepositRecord, type IntentsRecord, type JournalStore, type ReturnRecord, type SendRecord, type SplitRecord,
} from './journal.js';
import { recoveredSettlementEta, recoveryGeneration, type RecoveryDeployment } from './recovery.js';
import { checkRecoveryCalibration, preflightRecovery, quoteErc20Call, quoteOrdinaryExecution, quoteScheduledRecoveryFee,
  type Erc20SigningBounds, type OrdinaryCalibrationRange,
  type RecoveryBacklog, type RecoveryCalibration, type RecoveryLimits } from './recovery-cost.js';
import { burnIndex, capacityExceeded, capacityPreflight, maxProofs, checkStateRead, verifySealReceipt, type SealReceipt } from './rules.js';
import { AmbiguousBroadcast, CERTIFICATION_DEPTH, EvmReader, ProofUnavailable, RpcError, revertDataOf, type JsonRpc, type ReceiptJson } from './rpc.js';
import type { RawLog } from './abi.js';
import { buildHistory, checkSegmentLog, gapProofLen, genesisHead, type Segment } from './segment.js';
import { MAX_MINT_PROOF, encodeToken, decodeToken, burnPredicate, signaturePredicate, tokenIdOf, valueData, lineageOf, parseTransfer, parseCertification, stateId, encodePredicate, encodeProof, encodeCertification } from './token.js';
import {
  appendTransfer, certifyChecked, headOf, childMint, freshMask, mintRequest, splitPlan, tokenOfChild, tokenOfMint, transferProofLimit, transferRequest, type Aggregator, type OwnerSigner,
} from './tokenops.js';
import { bindTrust, decodeUc, isCertificationTrustPending, verifyEvmUc, type TrustInput } from './trust.js';
import { burnTransitionId, decodeEvidence, encodeReturnData, evidenceOf, redemptionId, verifyHeld, verifyPart, verifySplit, type Verdict } from './verify.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

const assetSelector = (signature: string) => HE(ascii(signature)).slice(0, 4);

export async function verifyErc20Activation(
  evm: EvmReader, cfg: Config, gamma: Uint8Array, pins: Erc20ActivationPins, trust: TrustInput,
  vaultRuntime: Uint8Array, deploymentBlock: bigint,
): Promise<void> {
  return checkErc20Activation(evm, cfg, gamma, pins, vaultRuntime, deploymentBlock, (verify) => verify(trust));
}

async function checkErc20Activation(
  evm: EvmReader, cfg: Config, gamma: Uint8Array, pins: Erc20ActivationPins, vaultRuntime: Uint8Array, deploymentBlock: bigint,
  verifyWithTrust: (verify: (trust: TrustInput) => Promise<void>) => Promise<void>,
): Promise<void> {
  const erc20 = cfg.erc20;
  if (!erc20 || pins.factory.length !== 20 || [pins.factoryRuntimeHash, pins.vaultInitcodeHash,
    pins.recoveryInitcodeHash, pins.activationTx, vaultRuntime].some((v) => v.length !== 32)) {
    return refuse('BadDeployment', 'invalid ERC20 release pins');
  }
  const { asset, ty, aid } = configIdentities(cfg);
  if (!eq(asset, cfg.asset) || !eq(ty, cfg.ty) || !eq(aid, cfg.aid)) {
    return refuse('BadDeployment', 'ERC20 asset identity differs from the execution genesis and token');
  }
  const token = addressWord(erc20.token);
  const vault = erc20Create2(pins.factory, token, pins.vaultInitcodeHash);
  const recovery = erc20Create2(pins.factory, HE(token), pins.recoveryInitcodeHash);
  if (!eq(vault, cfg.vault)) return refuse('BadDeployment', 'the vault differs from the pinned CREATE2 address');

  const genesis = await evm.headerByNumber(0n);
  if (!genesis || !eq(genesis.hash, cfg.executionGenesis)) return refuse('BadDeployment', 'the RPC serves another execution genesis');
  const [factoryCode, ordinaryCode, recoveryCode, factoryCfg, vaultHash, recoveryHash, generation, graphPins] = await Promise.all([
    evm.code(pins.factory), evm.code(cfg.verifier), evm.code(recovery),
    evm.call(pins.factory, concat(assetSelector('config(address)'), token)),
    evm.call(pins.factory, assetSelector('VAULT_INITCODE_HASH()')),
    evm.call(pins.factory, assetSelector('RECOVERY_INITCODE_HASH()')),
    evm.call(pins.factory, assetSelector('GENERATION()')),
    evm.call(pins.factory, assetSelector('PINS()')),
  ]);
  if (!eq(HE(factoryCode), pins.factoryRuntimeHash) || !eq(HE(ordinaryCode), cfg.verifierCodeHash)
    || !eq(decodeBytesReturn(factoryCfg), gamma) || !eq(vaultHash, pins.vaultInitcodeHash)
    || !eq(recoveryHash, pins.recoveryInitcodeHash) || !eq(generation, erc20.generation)
    || !eq(graphPins, erc20.pins) || recoveryCode.length === 0) {
    return refuse('BadDeployment', 'the factory or verifier graph differs from the pinned deployment');
  }
  const expected = {
    topics: [TOPIC.ERC20Activated, token, addressWord(vault), addressWord(recovery)],
    data: concat(domainOf(gamma), vaultRuntime, HE(recoveryCode)),
  };
  const proof = await evm.receiptProof(pins.activationTx, pins.factory, TOPIC.ERC20Activated, false, expected, [], undefined, true);
  await verifyWithTrust(async (trust) => {
    const log = await verifyReceiptLog(cfg, trust, proof.proof, pins.factory);
    if (log.header.number !== deploymentBlock || log.topics.length !== expected.topics.length
      || log.topics.some((t, i) => !eq(t, expected.topics[i])) || !eq(log.data, expected.data)) {
      return refuse('BadDeployment', 'the certified activation differs from the pinned deployment');
    }
  });
}

/** Optional display metadata. The read budget and accepted reply sizes are bounded. */
export async function readErc20Metadata(evm: EvmReader, token: Uint8Array): Promise<{ symbol?: string; decimals?: number }> {
  const read = (name: string) => evm.call(token, assetSelector(name), undefined, 30_000n).catch(() => new Uint8Array());
  const [decimalReply, symbolReply] = await Promise.all([read('decimals()'), read('symbol()')]);
  const rawDecimals = decimalReply.length === 32 ? beInt(decimalReply) : 256n;
  const decimals = rawDecimals <= 36n ? Number(rawDecimals) : undefined;
  let symbol: string | undefined;
  if (symbolReply.length >= 64 && symbolReply.length <= 96) {
    try {
      const b = decodeBytesReturn(symbolReply);
      if (b.length <= 16 && b.every((x) => x >= 0x21 && x <= 0x7e)) symbol = new TextDecoder().decode(b) || undefined;
    } catch { /* fall back to the token address */ }
  }
  return { symbol, decimals };
}

/** Run the vault's bounded payout checks in an eth_call that always rolls back. */
export async function previewErc20Recipient(evm: EvmReader, cfg: Config, recipient: Uint8Array, amount: bigint): Promise<void> {
  if (!cfg.erc20) return;
  const data = concat(assetSelector('previewPayout(address,uint256)'), addressWord(recipient), u256(amount));
  try {
    await evm.call(cfg.vault, data, undefined, 350_000n);
  } catch (error) {
    const marker = error instanceof RpcError && error.code !== 0 ? revertDataOf(error) : null;
    if (marker && eq(marker, assetSelector('PayoutPreviewPassed()'))) return;
  }
  return refuse('RecipientRefused', 'the ERC20 payout simulation did not confirm an exact transfer');
}

/** Verify the three deployed dependencies against the authenticated recovery runtime's immutables. */
export async function verifyRecoveryDependencies(evm: EvmReader, recovery: Uint8Array): Promise<void> {
  const [receipts, lineage, receiptHash, lineageHash, registryHash] = await Promise.all(
    ['RECEIPTS()', 'LINEAGE()', 'RECEIPTS_HASH()', 'LINEAGE_HASH()', 'REGISTRY_HASH()'].map((getter) => evm.call(recovery, assetSelector(getter))));
  const address = (word: Uint8Array) => word.length === 32 && beInt(word.subarray(0, 12)) === 0n ? word.subarray(12) : fail('CapacityPreflight', 'invalid recovery helper address');
  const helpers = [address(receipts), address(lineage), unhex('0xff00000000000000000000000000000000000002')];
  const expected = [receiptHash, lineageHash, registryHash];
  const runtimes = await Promise.all(helpers.map((helper) => evm.code(helper)));
  if (runtimes.some((code, i) => code.length === 0 || !eq(HE(code), expected[i]))) {
    fail('CapacityPreflight', 'recovery dependency runtime differs from its pinned hash');
  }
}
/** The deployment manifest pins outside D (section 4.3; the manifest schema is NB2-09's). */
export interface DeploymentPins {
  gamma: Uint8Array;
  build: Build;
  vaultRuntimeCodeHash: Uint8Array;
  maxEncodedTxBytes: bigint;
  userGasLimit: bigint;
  gasReserve: bigint;
  returnReserveSegments: bigint;
  deploymentBlock: bigint;
  stateReadOnly: boolean;
  /** The plausibility bound of a stateReadOnly index read (default 64). */
  maxJump?: bigint;
  /** The chain's native gas schedules (CERT_BATCH_V2, the RSMT membership, SHA-256), as the default gas model names them. */
  nativeGasSchedule?: string;
  erc20?: Erc20ActivationPins;
}

export interface BridgeOptions {
  pins: DeploymentPins;
  trust: TrustInput;
  rpc: JsonRpc;
  aggregator: Aggregator;
  journal: JournalStore;
  /** k_w: the 32-byte wallet bridge key, derived from the wallet seed (see {@link deriveBridgeKey}). */
  bridgeKey: Uint8Array;
  /** The wallet-versioned name of the k_w derivation, recorded in the journal. */
  keyScheme?: string;
  /** Back up the intent high-water mark with the seed (section 12.1). Required unless `requireBackup` is false. */
  backup?: (intents: IntentsRecord) => Promise<void>;
  /** Default true: a deposit is not sent before its intent's high-water mark is backed up. */
  requireBackup?: boolean;
  gas?: GasModel;
  /** Blocks the head must advance, after a send's nonce is seen used without its success receipt, before the send counts as dead. */
  deadAfterBlocks?: bigint;
  /** A seal receipt older than this many blocks gives a warning: the index then reflects a stale view (default 7,200). */
  maxSealAgeBlocks?: bigint;
  /**
   * Extend the trust-base history (append the authenticated successor entries) when a certificate's epoch is not held yet. A seal
   * receipt or a token refused with the retryable NoEntryForEpoch is retried once after it; it is never treated as invalid.
   */
  refreshTrust?: () => Promise<TrustInput | void>;
  /** Required freshness window for a wallet using its configured live UTB source. */
  trustFreshnessMs?: number;
  /** Only for local fixtures that use an old verifier or have no live UTB source. */
  unsafeTestTrust?: boolean;
  /** Monotonic elapsed time. A new session starts stale because elapsed time across restarts is uncertain. */
  trustClock?: () => number;
  /** Receipt polling. */
  receiptTimeoutMs?: number;
  pollMs?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

/** SHA-256 of the revision-2 NB2 semantic descriptor shipped by bft-core#1299. */
export const IMPORTED_TIP_PROFILE_HASH = '63158aeb61ee273e6c319c19f1663ec3910d6b5403b7affc90dec31813514e7e';

export const ERC20_PROFILE_HASH = 'f05dd5c3563165d73c1cf91a5af79ec7afcaa77edc90061c6e7666bf53a8b0b6';

export const TESTNET_TRUST_FRESHNESS_MS = 15 * 60_000;
export const PRODUCTION_TRUST_FRESHNESS_MS = 7 * 24 * 60 * 60_000;

export const DEFAULT_KEY_SCHEME = 'nb2-hmac-sha256-v1';

/** k_w = HMAC-SHA256(key = seed, "unicity-nb2/wallet-bridge-key/v1"): the {@link DEFAULT_KEY_SCHEME} derivation. */
export const deriveBridgeKey = (seed: Uint8Array): Uint8Array => hmac(sha256, seed, ascii('unicity-nb2/wallet-bridge-key/v1'));

export interface DepositPlan { intent: bigint; amount: bigint; rho: Uint8Array; firstOwner: Uint8Array; calldata: Uint8Array; record: DepositRecord }

/** Ask for a verified alternative when the exact signed request holds a proof awaiting history. */
export interface ProofRecoveryOptions { recoverProof?: boolean }

export interface ReturnPlan {
  returnId: Uint8Array;
  amount: bigint;
  recipient: Uint8Array;
  a: bigint;
  /** The endpoint estimate and the history already owed from a. */
  cObs: bigint;
  pNow: bigint;
  /** The proofs that fit beside the evidence (bytes) and the remaining margin: pMax - (pNow + returnReserveSegments). */
  pMax: bigint;
  marginSegments: bigint;
  gasLimit: bigint;
  warnings: string[];
  record: ReturnRecord;
}

/** A wallet may admit recovery when the calibrated ordinary route cannot fit. */
export interface ReturnAdmission {
  ordinaryEnvelope?: { encodedBytes: bigint; gas: bigint; gasFor?: (shape: RedeemShape) => bigint | null };
  checkOrdinary?(record: ReturnRecord, gas: bigint): Promise<void>;
  /** Optional UCT admission policy. ERC20 uses the release inputs below. */
  recover?(record: ReturnRecord): Promise<NonNullable<ReturnRecord['recovery']>>;
  erc20Recovery?: Erc20ReturnRecovery;
  beforeCertification?(record: ReturnRecord): Promise<void>;
}

export interface Erc20ReturnRecovery {
  deployment: RecoveryDeployment;
  calibration: RecoveryCalibration;
  backlog: Omit<RecoveryBacklog, 'signedStart' | 'observed'>;
  limits: Omit<RecoveryLimits, 'chainId' | 'worstCaseEnvelope'>;
  signingBounds?: Omit<Erc20SigningBounds, 'ordinary'>;
  ordinaryAttempts?: Pick<NonNullable<Erc20SigningBounds['ordinary']>, 'attemptsBeforeFallback' | 'inclusionMs'>;
  ordinaryRanges?: readonly OrdinaryCalibrationRange[];
}

export interface RedeemOptions {
  recovery?: Uint8Array;
  envelope?: ReturnAdmission['ordinaryEnvelope'];
  archives?: readonly EvmReader[];
  /** Current payer authorization for taking an exclusive legacy ERC20 slot. */
  erc20Policy?: Omit<RecoveryLimits, 'chainId' | 'worstCaseEnvelope' | 'balance'>;
  erc20Recovery?: Pick<Erc20ReturnRecovery, 'deployment' | 'calibration'>;
  admit?: (request: TxRequest, prior: readonly SendRecord[], remainingFee?: bigint) => Promise<void>;
}

export interface RedeemTx { returnId: Uint8Array; calldata: Uint8Array; gasLimit: bigint; P: bigint; endpoint: bigint; history: Uint8Array; eta: Uint8Array; claimedStart: bigint }

export type ReconcileResult =
  | { state: 'paid'; txHash: Uint8Array; blockNumber: bigint }
  | { state: 'pending'; txHash: Uint8Array }
  /**
   * The node answered, in this read, that it no longer holds part of the proof (`missing` names it): read it from an archive. Never a
   * verdict on a block that is merely not certified yet, and never reached by counting reads.
   */
  | { state: 'needs-archive'; txHash: Uint8Array; missing?: string }
  /**
   * A payment by another party (an indexed or remembered claim, not one of this wallet's sends) was seen and is gone: no reader serves its
   * receipt, or only in a block that is not canonical, though every reader's head is CERTIFICATION_DEPTH past it. Not pruned and not
   * pending: the claim is not on the chain. Nothing is signed while it is held; it is paid if the transaction lands again. Once every
   * reader's head is VANISHED_CLAIM_HORIZON past the return's first unproven peer claim, it is dropped and the own payout proceeds.
   */
  | { state: 'vanished'; txHash: Uint8Array }
  | { state: 'route-blocked'; txHash: Uint8Array; route: 'ordinary' | 'recovery'; payer?: Uint8Array }
  | { state: 'not-paid'; lastFailure?: { txHash: Uint8Array; action: RedeemAction; error: DecodedError | null } };

export interface ReturnEvidence {
  /** Exact signed settlement hashes held locally. */
  settlements?: readonly Uint8Array[];
  /** Also check matching pending-block calls before reporting a provisional payment hint. */
  pending?: { recovery?: Uint8Array };
  /** A certified vault receipt. Its transaction hash is a lookup hint. */
  paid?: ReturnRecord['paid'];
  /**
   * This wallet's own signed transactions outside `sends` (a continuation route's settle packet and its replaced or superseded copies), as
   * raw bytes. A claim among them that left the chain is the wallet's own: its observation is dropped so the route offers the same bytes
   * again, never reported as another party's `vanished` payment.
   */
  own?: readonly Uint8Array[];
  readOnly?: boolean;
}

/**
 * The cap of the `paidProof.reads` and `failureProofReads` markers. They only remember that a proof read was tried (a resend waits for
 * it); reaching the cap never means needs-archive. A payout block not yet certified stays pending for as long as it takes.
 */
export const FAILURE_PROOF_READS = 3;

/**
 * Blocks, on every reader's own head, after this return first saw an unproven claim of another party's payment, before such a claim no
 * reader holds canonically is dropped and the wallet proceeds with its own payout (the vault's AlreadyPaid refuses a double payment).
 * Between CERTIFICATION_DEPTH and this horizon the claim is reported as `vanished`.
 */
export const VANISHED_CLAIM_HORIZON = 64n;

/** Where a receipt of a claim was served: by which reader, in which block. */
interface SeenReceipt { reader: EvmReader; number: bigint; hash: Uint8Array }

const optional = (d: string | undefined): bigint | undefined => (d === undefined ? undefined : undec(d));

/** What a pruned answer says is missing. */
const missingOf = (e: unknown): string | undefined =>
  e instanceof ProofUnavailable ? e.missing : e instanceof Nb2Error ? e.detail ?? 'certified evidence' : undefined;

const hexq = (b: Uint8Array): string => `0x${toHex(b)}`;

function redeemRefusal(e: DecodedError, detail?: string): Nb2Error {
  return new Nb2Error(e.rule, detail, e.args.map((v) => typeof v === 'bigint' ? String(v) : hexq(v)),
    e.inner && redeemRefusal(e.inner));
}

// Import folds together the exact signed request, its optional terminal, and a vault Paid receipt.
const RETURN_IMPORT = {
  absent:           { signed: 'adopt',   terminal: 'adopt',  paid: 'adopt' },
  planned:          { signed: 'adopt',   terminal: 'adopt',  paid: 'adopt' },
  'burn-requested': { signed: 'certify', terminal: 'attach', paid: 'reconcile' },
  burned:           { signed: 'keep',    terminal: 'keep',   paid: 'reconcile' },
  submitted:        { signed: 'keep',    terminal: 'keep',   paid: 'reconcile' },
  paid:             { signed: 'keep',    terminal: 'attach', paid: 'keep' },
} as const;

export class NativeBridgeV2 {
  public readonly cfg: Config;
  public readonly domain: Uint8Array;
  public readonly journal: Journal;
  public readonly evm: EvmReader;
  public readonly gas: GasModel;
  private readonly keyScheme: string;
  /** k_w, kept out of the options object. */
  readonly #kw: Uint8Array;
  private readonly opts: Omit<BridgeOptions, 'bridgeKey'>;
  /** In-process serialization per journal key (with the store's compare-and-swap across processes). */
  private readonly locks = new Map<string, Promise<unknown>>();
  /** Whether the gas model applies to this deployment (checked once, from its runtime codes and native gas schedule). */
  private gasFits: boolean | null = null;
  private lastTrustSync?: number;
  private trustSuspended = false;
  private refreshingTrust?: Promise<void>;

  private constructor(options: BridgeOptions) {
    const { bridgeKey, ...opts } = options;
    this.opts = opts;
    this.cfg = decodeConfig(opts.pins.gamma, buildParams(opts.pins.build));
    this.domain = domainOf(opts.pins.gamma);
    bindTrust(opts.trust, this.cfg);
    if (!opts.unsafeTestTrust && toHex(this.cfg.semanticProfileHash) !== (this.cfg.erc20 ? ERC20_PROFILE_HASH : IMPORTED_TIP_PROFILE_HASH)) {
      refuse('BadDeployment', 'the wallet requires the paired imported-tip NB2 semantic profile');
    }
    if (!opts.unsafeTestTrust) opts.trustFreshnessMs ??= PRODUCTION_TRUST_FRESHNESS_MS;
    if (opts.trustFreshnessMs !== undefined && (!Number.isFinite(opts.trustFreshnessMs) || opts.trustFreshnessMs <= 0)) {
      refuse('BadInput', 'the UTB freshness window must be positive and finite');
    }
    if (bridgeKey.length !== 32) refuse('BadInput', 'k_w is 32 bytes');
    this.#kw = bridgeKey.slice();
    if (opts.requireBackup !== false && opts.backup === undefined) refuse('BadInput', 'a backup of the intent high-water mark is required (or requireBackup: false on a test deployment)');
    this.journal = new Journal(opts.journal, this.domain);
    this.evm = new EvmReader(opts.rpc);
    this.gas = opts.gas ?? new MeasuredGasModel();
    this.keyScheme = opts.keyScheme ?? DEFAULT_KEY_SCHEME;
  }

  /**
   * Open the bridge for one pinned deployment. The installation check (section 4.3): the chain ID, the vault's exact Γ through config()
   * and its runtime code hash. These come from the RPC, which the wallet trusts here exactly as far as its manifest source.
   */
  public static async open(opts: BridgeOptions, check = true): Promise<NativeBridgeV2> {
    const b = new NativeBridgeV2({ ...opts, trust: await opts.trust.snapshot() });
    if (check || b.cfg.erc20) {
      if ((await b.evm.chainId()) !== b.cfg.chainId) refuse('BadDeployment', 'the RPC serves another chain');
      if (!eq(await b.evm.vaultConfig(b.cfg.vault), opts.pins.gamma)) refuse('BadDeployment', 'the vault\'s config() is not the pinned Γ');
      if (!eq(HE(await b.evm.code(b.cfg.vault)), opts.pins.vaultRuntimeCodeHash)) refuse('BadDeployment', 'the vault runtime code hash is not the pinned one');
      if (b.cfg.erc20) {
        if (!opts.pins.erc20) return refuse('BadDeployment', 'the ERC20 activation pins are missing');
        await checkErc20Activation(b.evm, b.cfg, opts.pins.gamma, opts.pins.erc20,
          opts.pins.vaultRuntimeCodeHash, opts.pins.deploymentBlock, (verify) => b.retryingTrust(verify));
        await b.journal.registerPayerChain(b.cfg.chainId);
      }
    }
    return b;
  }

  private sleep(ms: number): Promise<void> {
    return (this.opts.sleep ?? ((x) => new Promise((r) => setTimeout(r, x))))(ms);
  }
  private now(): number {
    return (this.opts.now ?? Date.now)();
  }

  /** Run `f` after every earlier call holding `key` in this instance has finished. */
  private async locked<T>(key: string, f: () => Promise<T>): Promise<T> {
    const prev = this.locks.get(key) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => { release = r; });
    const chained = prev.then(() => mine);
    this.locks.set(key, chained);
    await prev.catch(() => undefined);
    try {
      return await f();
    } finally {
      release();
      if (this.locks.get(key) === chained) this.locks.delete(key);
    }
  }

  // ==== EVM -> Unicity ==================================================================================================

  /** r for intent i (never stored unless the wallet asks: it is derivable from k_w and i). */
  public secretOf(i: bigint): Uint8Array {
    return depositIntentSecret(this.#kw, this.domain, i);
  }

  /**
   * Plan a deposit of `amount` to the Unicity owner `ownerKey` (compressed key): allocate a never-used intent i, derive r and rho, and
   * journal the plan with the new high-water mark, which is handed to the backup. Serialized: two plans never share an intent.
   */
  public planDeposit(amount: bigint, ownerKey: Uint8Array, minCredit?: bigint): Promise<DepositPlan> {
    if (amount <= 0n || amount >= 1n << 256n) refuse('BadInput', 'a deposit amount is a positive uint256');
    const erc20 = this.cfg.erc20;
    if (erc20 ? (minCredit === undefined || minCredit <= 0n || minCredit > amount) : minCredit !== undefined) {
      refuse('BadInput', 'ERC20 deposits require 0 < minCredit <= requested');
    }
    parseKey(ownerKey);
    return this.locked('intents', async () => {
      const cur = await this.journal.intentsForUpdate();
      if (cur !== null && cur.keyScheme !== this.keyScheme) refuse('BadInput', `the journal's intents use key scheme ${cur.keyScheme}`);
      const i = cur === null ? 0n : undec(cur.next);
      // a rewrite keeps the record's unknown fields (docs/nb2-journal.md)
      const intents: IntentsRecord = { ...(cur ?? {}), ...this.journal.base(), kind: 'intents', keyScheme: this.keyScheme, next: dec(i + 1n) };
      // the counter moves first, by compare-and-swap: a crash wastes intent i, another writer makes this one fail; i is never reused
      await this.journal.putIntents(intents);
      const r = this.secretOf(i);
      const rho = rhoOf(this.domain, r);
      const firstOwner = firstOwnerOf(ownerKey);
      const rec: DepositRecord = {
        ...this.journal.base(), kind: 'deposit', keyScheme: this.keyScheme, intent: dec(i), amount: dec(amount), ownerKey: hex(ownerKey),
        firstOwner: hex(firstOwner), rho: hex(rho), status: 'planned', backedUp: false, sends: [],
        ...(erc20 ? { erc20Token: hex(erc20.token), requested: dec(amount), minCredit: dec(minCredit!) } : {}),
        plannedBlock: dec(await this.evm.saneHead()),
      };
      await this.journal.putDeposit(rec);
      if (this.opts.backup) {
        await this.opts.backup(intents);
        rec.backedUp = true;
        await this.journal.putDeposit(rec);
      }
      return { intent: i, amount, rho, firstOwner, calldata: this.depositData(rec), record: rec };
    });
  }

  /** Record that the wallet backed up the high-water mark covering this intent by other means. */
  public markBackedUp(intent: bigint): Promise<void> {
    return this.locked(`deposit/${intent}`, async () => {
      const rec = await this.depositRecord(intent);
      rec.backedUp = true;
      await this.journal.putDeposit(rec);
    });
  }

  private async depositRecord(i: bigint): Promise<DepositRecord> {
    return (await this.journal.depositForUpdate(i)) ?? refuse('JournalNotPersisted', `no journal entry for intent ${i}`);
  }

  private requireErc20Qualification(): void {
    if (this.cfg.erc20 && !this.opts.unsafeTestTrust && (
      this.opts.pins.erc20?.fundingQualified !== true || this.opts.pins.returnReserveSegments < 64n)) {
      fail('CapacityPreflight', 'the ERC20 deployment is awaiting real-value qualification');
    }
  }

  private depositData(rec: DepositRecord): Uint8Array {
    const owner = unhex(rec.firstOwner);
    const rho = unhex(rec.rho);
    if (!this.cfg.erc20) return depositCalldata(owner, rho);
    if (rec.erc20Token !== hex(this.cfg.erc20.token) || rec.requested === undefined || rec.minCredit === undefined) {
      return refuse('JournalNotPersisted', 'the ERC20 intent is missing the token, requested amount or minimum credit');
    }
    const requested = undec(rec.requested);
    const min = undec(rec.minCredit);
    if (min <= 0n || min > requested || requested >= 1n << 256n) {
      return refuse('JournalNotPersisted', 'the ERC20 intent has invalid credit bounds');
    }
    return depositErc20Calldata(requested, min, owner, rho);
  }

  private async approveDeposit(rec: DepositRecord, signer: EvmSigner, token: Uint8Array): Promise<void> {
    const requested = undec(rec.requested!);
    const allowance = async () => {
      const reply = await this.evm.call(token, concat(SELECTOR.allowance, addressWord(signer.address), addressWord(this.cfg.vault)));
      if (reply.length !== 32) return refuse('ProviderFault', 'invalid ERC20 allowance response');
      return beInt(reply);
    };
    const save = () => this.journal.putDeposit(rec);
    if (rec.approvalSends?.length) {
      const landed = await this.landedSend(rec.approvalSends, save);
      if (landed === 'pending') return refuse('Unconfirmed', 'an earlier token approval is pending');
      rec.approvalSends = [];
      await save();
    }
    const current = await allowance();
    if (current === requested) return;
    for (const target of current === 0n ? [requested] : [0n, requested]) {
      const data = approveCalldata(this.cfg.vault, target);
      const estimate = await this.evm.estimateGas({ from: signer.address, to: token, data, value: 0n });
      if (!('gas' in estimate)) return refuse('Reverted', `token approval simulation refused: ${estimate.message}`);
      const gas = estimate.gas + (estimate.gas + 4n) / 5n;
      if (gas <= 0n || gas > this.opts.pins.userGasLimit) fail('CapacityExceeded', 'approval gas exceeds the user limit');
      const tx = await this.signed(signer, token, data, 0n, gas);
      rec.approvalSends = [this.sendRecord(tx)];
      await save();
      const receipt = await this.broadcastAndWait(tx);
      if (receipt === null) return refuse('Unconfirmed', 'token approval has no receipt yet');
      if (BigInt(receipt.status) !== 1n || await allowance() !== target) {
        return refuse('Reverted', 'token approval did not set the exact allowance');
      }
      rec.approvalSends = [];
      await save();
    }
  }

  /** Every Deposited event of the vault carrying `rho`, from block `from`, in chain order. */
  private async depositsWithRho(rho: Uint8Array, from: bigint): Promise<{ l: RawLog; n: bigint; amount: bigint; firstOwner: Uint8Array }[]> {
    const out: { l: RawLog; n: bigint; amount: bigint; firstOwner: Uint8Array }[] = [];
    for (const l of await this.evm.logs(this.cfg.vault, [hexq(depositTopic(this.cfg.erc20?.token))], from, await this.evm.saneHead())) {
      const d = decodeDeposited(l, this.cfg.erc20?.token);
      if (d !== null && eq(l.address, this.cfg.vault) && eq(d.domain, this.domain) && eq(d.rho, rho)) out.push({ l, n: d.n, amount: d.amount, firstOwner: d.firstOwner });
    }
    return out;
  }

  /**
   * Send the deposit. Refuses a plan whose journal entry is not persisted exactly as planned, or whose high-water mark is not backed
   * up. Earlier sends of the intent are reconciled first, and before the first send the vault's events are searched for a deposit that
   * already carries this rho (another device on the same backup), so a retry never deposits twice.
   */
  public submitDeposit(plan: DepositPlan | bigint, signer: EvmSigner): Promise<{ txHash: Uint8Array; depositNumber: bigint; blockNumber: bigint }> {
    const i = typeof plan === 'bigint' ? plan : plan.intent;
    const submit = () => this.locked(`deposit/${i}`, async () => {
      const rec = await this.journal.depositForUpdate(i);
      if (rec === null) refuse('JournalNotPersisted', `intent ${i} is not in the journal: plan it first`);
      if (typeof plan !== 'bigint' && (rec!.rho !== hex(plan.rho) || (rec!.requested ?? rec!.amount) !== dec(plan.amount))) refuse('JournalNotPersisted', 'the journal entry is not this plan');
      if (!eq(rhoOf(this.domain, this.secretOf(i)), unhex(rec!.rho))) refuse('JournalNotPersisted', 'the journal entry does not derive from this wallet key');
      const hw = await this.journal.intentsForUpdate();
      if (hw === null || undec(hw.next) <= i) refuse('JournalNotPersisted', 'the intent high-water mark does not cover this intent');
      if (this.opts.requireBackup !== false && !rec!.backedUp) refuse('JournalNotPersisted', 'the high-water mark covering this intent is not backed up');
      if (rec!.status !== 'planned' && rec!.status !== 'submitted') {
        return { txHash: unhex(rec!.depositTx!), depositNumber: undec(rec!.depositNumber!), blockNumber: undec(rec!.blockNumber!) };
      }
      const landed = await this.landedSend(rec!.sends, () => this.journal.putDeposit(rec!));
      if (landed === 'pending') refuse('Unconfirmed', 'an earlier deposit transaction may still be pending: wait or reconcile, never resend blindly');
      if (landed !== null) return this.recordDeposit(rec!, landed);
      if (rec!.sends.length === 0) {
        const seen = await this.depositsWithRho(unhex(rec!.rho), rec!.plannedBlock === undefined ? this.opts.pins.deploymentBlock : undec(rec!.plannedBlock));
        if (seen.length > 0) return this.adoptDeposits(rec!, seen);
      }
      const erc20 = this.cfg.erc20;
      const value = erc20 ? 0n : undec(rec!.amount);
      const data = this.depositData(rec!);
      if (erc20) {
        this.requireErc20Qualification();
        await this.approveDeposit(rec!, signer, erc20.token);
      }
      let gasLimit: bigint;
      if (await this.gasApplies()) {
        gasLimit = this.gas.depositGasLimit();
      } else {
        const estimate = await this.evm.estimateGas({ from: signer.address, to: this.cfg.vault, data, value });
        if (!('gas' in estimate)) refuse('Reverted', `deposit simulation refused: ${estimate.message}`);
        gasLimit = estimate.gas + (estimate.gas + 4n) / 5n;
      }
      if (gasLimit <= 0n || gasLimit > this.opts.pins.userGasLimit) fail('CapacityExceeded', 'deposit gas exceeds the user limit');
      const tx = await this.signed(signer, this.cfg.vault, data, value, gasLimit);
      rec!.sends.push(this.sendRecord(tx));
      rec!.status = 'submitted';
      await this.journal.putDeposit(rec!);
      const r = await this.broadcastAndWait(tx);
      if (r === null) refuse('Unconfirmed', `deposit 0x${toHex(tx.hash)} has no receipt yet: call submitDeposit again to reconcile`);
      if (BigInt(r!.status) !== 1n) refuse('Reverted', `deposit 0x${toHex(tx.hash)} reverted`);
      return this.recordDeposit(rec!, r!);
    });
    return this.cfg.erc20 ? this.locked(`erc20-approval/${toHex(signer.address)}`, submit) : submit();
  }

  private async recordDeposit(rec: DepositRecord, r: ReceiptJson): Promise<{ txHash: Uint8Array; depositNumber: bigint; blockNumber: bigint }> {
    const l = r.logs.find((x) => eq(unhex(x.address.toLowerCase()), this.cfg.vault) && x.topics[0]?.toLowerCase() === hex(depositTopic(this.cfg.erc20?.token)));
    if (l === undefined) refuse('ProviderFault', 'the deposit receipt has no Deposited log');
    const d = decodeDeposited({ address: this.cfg.vault, topics: l!.topics.map((x) => unhex(x.toLowerCase())), data: unhex(l!.data.toLowerCase()), blockNumber: 0n, blockHash: new Uint8Array(32), transactionHash: new Uint8Array(32), logIndex: 0n }, this.cfg.erc20?.token);
    if (d === null || !eq(d.rho, unhex(rec.rho))) refuse('ProviderFault', 'the Deposited log is not this intent\'s');
    // the event's D is this deployment's: the same rho under another vault configuration at this address is not this deposit
    if (!eq(d!.domain, this.domain)) refuse('ProviderFault', 'the Deposited log carries another deployment\'s domain D');
    if (this.cfg.erc20) {
      if (d!.amount > undec(rec.requested!) || d!.amount < undec(rec.minCredit!) || hex(d!.firstOwner) !== rec.firstOwner) {
        return refuse('ProviderFault', 'the ERC20 lock receipt differs from the journaled bounds');
      }
      rec.amount = dec(d!.amount);
    }
    rec.depositTx = r.transactionHash.toLowerCase();
    rec.blockNumber = dec(BigInt(r.blockNumber));
    rec.depositNumber = dec(d!.n);
    rec.status = 'deposited';
    // merge, never replace: the record's own deposit, what was journaled before, and every deposit carrying this rho on chain
    const own = { tx: rec.depositTx, depositNumber: rec.depositNumber, blockNumber: rec.blockNumber, amount: dec(d!.amount), firstOwner: hex(d!.firstOwner) };
    const scan = await this.depositsWithRho(unhex(rec.rho), rec.plannedBlock === undefined ? this.opts.pins.deploymentBlock : undec(rec.plannedBlock));
    this.mergeSeen(rec, [own, ...scan.map((x) => ({ tx: hex(x.l.transactionHash), depositNumber: dec(x.n), blockNumber: dec(x.l.blockNumber), amount: dec(x.amount), firstOwner: hex(x.firstOwner) }))]);
    await this.journal.putDeposit(rec);
    return { txHash: unhex(rec.depositTx), depositNumber: d!.n, blockNumber: BigInt(r.blockNumber) };
  }

  /** Merge deposit entries into `seenDeposits` by deposit number, keeping journaled tokens, in number order. */
  private mergeSeen(rec: DepositRecord, entries: NonNullable<DepositRecord['seenDeposits']>): void {
    const known = new Map((rec.seenDeposits ?? []).map((x) => [x.depositNumber, x]));
    for (const e of entries) if (!known.has(e.depositNumber)) known.set(e.depositNumber, e);
    rec.seenDeposits = [...known.values()].sort((a, b) => (undec(a.depositNumber) < undec(b.depositNumber) ? -1 : 1));
  }

  /** Journal the deposits found for a record's rho: the first becomes its own, every one is listed (each is a separate root token). */
  private async adoptDeposits(rec: DepositRecord, seen: { l: RawLog; n: bigint; amount: bigint; firstOwner: Uint8Array }[]): Promise<{ txHash: Uint8Array; depositNumber: bigint; blockNumber: bigint }> {
    this.mergeSeen(rec, seen.map((s) => ({ tx: hex(s.l.transactionHash), depositNumber: dec(s.n), blockNumber: dec(s.l.blockNumber), amount: dec(s.amount), firstOwner: hex(s.firstOwner) })));
    if (rec.status === 'planned' || rec.status === 'submitted') {
      const first = this.cfg.erc20 && rec.requested !== undefined && rec.minCredit !== undefined
        ? seen.find((s) => s.amount >= undec(rec.minCredit!) && s.amount <= undec(rec.requested!) && hex(s.firstOwner) === rec.firstOwner)
        : seen[0];
      if (!first) return refuse('ProviderFault', 'no ERC20 lock matches the journaled credit bounds and owner');
      rec.depositTx = hex(first.l.transactionHash);
      rec.blockNumber = dec(first.l.blockNumber);
      rec.depositNumber = dec(first.n);
      rec.amount = dec(first.amount);
      rec.firstOwner = hex(first.firstOwner);
      rec.ownerKey = hex(first.firstOwner.subarray(9));
      rec.status = 'deposited';
    }
    await this.journal.putDeposit(rec);
    return { txHash: unhex(rec.depositTx!), depositNumber: undec(rec.depositNumber!), blockNumber: undec(rec.blockNumber!) };
  }

  /** The receipt proof and J of deposit number `n` of intent `i`, verified offline. */
  private async proveDeposit(i: bigint, tx: Uint8Array, n: bigint, amount: bigint, firstOwner: Uint8Array): Promise<{ receiptProof: Uint8Array; reason: Uint8Array }> {
    const token = this.cfg.erc20?.token;
    const topic = depositTopic(token);
    const topics = token ? [topic, u256(n), addressWord(token)] : [topic, u256(n)];
    const rp = await this.evm.mintReceiptProof(tx, this.cfg.vault,
      token !== undefined || toHex(this.cfg.semanticProfileHash) === IMPORTED_TIP_PROFILE_HASH, topic, topics);
    const j = { d: this.domain, n, r: this.secretOf(i), proof: rp.proof };
    const ev = await this.retryingTrust((trust) => verifyDepositEvidence(this.cfg, this.domain, trust, j));
    if (ev.v !== amount || !eq(ev.firstOwner, firstOwner)) refuse('ProviderFault', 'the certified deposit is not the planned one');
    return { receiptProof: rp.encoded, reason: encodeReceiptBacking(j) };
  }

  /** The ordinary mint with reason J, certified by the aggregator and verified offline. */
  private async mintWith(reason: Uint8Array, ownerKey: Uint8Array, amount: bigint,
    saved: string | undefined, save: (proof: string) => Promise<void>, recoverProof?: boolean): Promise<Uint8Array> {
    const j = decodeReceiptBacking(reason);
    const m = {
      network: this.cfg.network, recipient: signaturePredicate(ownerKey), salt: depositSalt(this.domain, j.n, j.r), type: this.cfg.ty,
      justification: reason, data: valueData(this.cfg.aid, amount), deadline: null,
    };
    const { tx, cd } = mintRequest(m);
    return this.retainedCertification(cd, MAX_MINT_PROOF, saved, save, async (proof, trust) => {
      const token = tokenOfMint(tx, proof);
      const held = await verifyHeld(this.cfg, this.domain, trust, decodeToken(token));
      if (held.amount !== amount) refuse('ProviderFault', 'the minted amount differs');
      return token;
    }, { recoverProof });
  }

  /**
   * Fetch the certified header evidence and the block's receipts, build the receipt proof and verify it offline (section 6.2 steps 1 to
   * 7), then journal J. Retry `CompanionUnknown` after a round (the block's certificate is served once its child block exists).
   */
  public collectDepositProof(intent: bigint): Promise<{ reason: Uint8Array; depositNumber: bigint }> {
    return this.locked(`deposit/${intent}`, async () => {
      const rec = await this.depositRecord(intent);
      if (rec.status === 'proven' || rec.status === 'minted') return { reason: unhex(rec.reason!), depositNumber: undec(rec.depositNumber!) };
      if (rec.status !== 'deposited') refuse('NotPending', `intent ${intent} is ${rec.status}: submit the deposit first`);
      const n = undec(rec.depositNumber!);
      const p = await this.proveDeposit(intent, unhex(rec.depositTx!), n, undec(rec.amount), unhex(rec.firstOwner));
      rec.receiptProof = hex(p.receiptProof);
      rec.reason = hex(p.reason);
      rec.status = 'proven';
      await this.journal.putDeposit(rec);
      return { reason: p.reason, depositNumber: n };
    });
  }

  /** Mint with receipt-backed reason J. Recovery can look for a verified alternative to an ahead proof. */
  public mint(intent: bigint, options?: ProofRecoveryOptions): Promise<Uint8Array> {
    const recoverProof = options?.recoverProof;
    return this.locked(`deposit/${intent}`, async () => {
      const rec = await this.depositRecord(intent);
      if (rec.status === 'minted') return this.verifiedTokenBytes(unhex(rec.token!));
      if (rec.status !== 'proven') refuse('NotPending', `intent ${intent} is ${rec.status}: collect the deposit proof first`);
      const held = this.opts.trust;
      const token = await this.mintWith(unhex(rec.reason!), unhex(rec.ownerKey), undec(rec.amount), rec.mintProof, async (proof) => {
        rec.mintProof = proof;
        await this.journal.putDeposit(rec);
      }, recoverProof);
      rec.token = hex(token);
      delete rec.mintProof;
      rec.status = 'minted';
      const mine = rec.seenDeposits?.find((x) => x.depositNumber === rec.depositNumber);
      if (mine !== undefined) mine.token = rec.token;
      await this.journal.putDeposit(rec);
      return held === this.opts.trust && !this.refreshingTrust && !this.trustStale() ? token : this.verifiedTokenBytes(token);
    });
  }

  /**
   * Mint a further deposit that carries this intent's rho (`seenDeposits`): a reused secret, or a second device. Its value is a
   * separate root token with its own deposit number; nothing is lost.
   */
  public mintExtraDeposit(intent: bigint, depositNumber: bigint, options?: ProofRecoveryOptions): Promise<Uint8Array> {
    const recoverProof = options?.recoverProof;
    return this.locked(`deposit/${intent}`, async () => {
      const rec = await this.depositRecord(intent);
      const x = (rec.seenDeposits ?? []).find((s) => s.depositNumber === dec(depositNumber));
      if (x === undefined) refuse('NotPending', `no deposit number ${depositNumber} is journaled for intent ${intent}`);
      if (x!.token !== undefined) return this.verifiedTokenBytes(unhex(x!.token));
      const held = this.opts.trust;
      // the entry's own first owner: another device may have deposited this rho to another key
      const firstOwner = unhex(x!.firstOwner);
      const reason = x!.reason === undefined ? (await this.proveDeposit(intent, unhex(x!.tx), depositNumber, undec(x!.amount), firstOwner)).reason : unhex(x!.reason);
      const token = await this.mintWith(reason, firstOwner.subarray(9), undec(x!.amount), x!.mintProof, async (proof) => {
        x!.reason = hex(reason);
        x!.mintProof = proof;
        await this.journal.putDeposit(rec);
      }, recoverProof);
      x!.token = hex(token);
      delete x!.reason;
      delete x!.mintProof;
      await this.journal.putDeposit(rec);
      return held === this.opts.trust && !this.refreshingTrust && !this.trustStale() ? token : this.verifiedTokenBytes(token);
    });
  }

  /**
   * Recover deposits from the seed (k_w) and a backed-up high-water mark (section 5.1): every intent below `next` is matched by its rho
   * against the vault's Deposited events. A match upgrades a planned or submitted record (or creates the record) to deposited; every
   * deposit number seen for a rho is journaled. Intents without a matching event were never funded. A look-ahead past the mark does
   * not replace it.
   */
  public async recoverDeposits(next: bigint): Promise<bigint[]> {
    await this.locked('intents', async () => {
      const cur = await this.journal.intentsForUpdate();
      if (cur === null || undec(cur.next) < next) await this.journal.putIntents({ ...(cur ?? {}), ...this.journal.base(), kind: 'intents', keyScheme: this.keyScheme, next: dec(next) });
    });
    const want = new Map<string, bigint>();
    for (let i = 0n; i < next; i++) want.set(toHex(rhoOf(this.domain, this.secretOf(i))), i);
    const byIntent = new Map<bigint, { l: RawLog; n: bigint; amount: bigint; firstOwner: Uint8Array }[]>();
    for (const l of await this.evm.logs(this.cfg.vault, [hexq(depositTopic(this.cfg.erc20?.token))], this.opts.pins.deploymentBlock, await this.evm.saneHead())) {
      const d = decodeDeposited(l, this.cfg.erc20?.token);
      if (d === null || !eq(l.address, this.cfg.vault) || !eq(d.domain, this.domain)) continue;
      const i = want.get(toHex(d.rho));
      if (i === undefined) continue;
      byIntent.set(i, [...(byIntent.get(i) ?? []), { l, n: d.n, amount: d.amount, firstOwner: d.firstOwner }]);
    }
    const found: bigint[] = [];
    for (const [i, seen] of [...byIntent].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
      await this.locked(`deposit/${i}`, async () => {
        const rec: DepositRecord = (await this.journal.depositForUpdate(i)) ?? {
          ...this.journal.base(), kind: 'deposit', keyScheme: this.keyScheme, intent: dec(i), amount: dec(seen[0].amount),
          ownerKey: hex(seen[0].firstOwner.subarray(9)), firstOwner: hex(seen[0].firstOwner), rho: hex(rhoOf(this.domain, this.secretOf(i))),
          status: 'planned', backedUp: true, sends: [],
          ...(this.cfg.erc20 ? { erc20Token: hex(this.cfg.erc20.token) } : {}),
        };
        await this.adoptDeposits(rec, seen);
      });
      found.push(i);
    }
    return found;
  }

  // ==== circulation =====================================================================================================

  private async verifiedTokenBytes(token: Uint8Array): Promise<Uint8Array> {
    await this.verifyToken(token);
    return token;
  }

  /** Verify a held token fully offline (receipt origin, lineage, every certificate): its ID, amount, owner and spendable state. */
  public async verifyToken(token: Uint8Array): Promise<{ tokenId: Uint8Array; amount: bigint; owner: Uint8Array | null; state: Uint8Array }> {
    const part = decodeToken(token);
    const h = await this.retryingTrust((trust) => verifyHeld(this.cfg, this.domain, trust, part));
    return { tokenId: h.tokenId, amount: h.amount, owner: h.owner.type === 1n ? h.owner.params : null, state: h.state };
  }

  /** Verify incoming lineage and bind its receipt to the paired RPC's canonical child. */
  public async verifyReceivedToken(token: Uint8Array): ReturnType<NativeBridgeV2['verifyToken']> {
    if (!this.cfg.erc20 && toHex(this.cfg.semanticProfileHash) !== IMPORTED_TIP_PROFILE_HASH) return this.verifyToken(token);
    const part = decodeToken(Uint8Array.from(token));
    const mint = lineageOf(part)[0].mint;
    return this.retryingTrust(async (trust) => {
      const held = await verifyHeld(this.cfg, this.domain, trust, part);
      await this.evm.checkMintReceipt(decodeReceiptBacking(mint.justification!).proof);
      return { tokenId: held.tokenId, amount: held.amount, owner: held.owner.type === 1n ? held.owner.params : null, state: held.state };
    });
  }

  /** An ordinary transfer to `toKey`; the result is verified before it is returned. */
  public async transfer(token: Uint8Array, owner: OwnerSigner, toKey: Uint8Array, options?: ProofRecoveryOptions): Promise<Uint8Array> {
    const recoverProof = options?.recoverProof;
    token = Uint8Array.from(token);
    toKey = Uint8Array.from(toKey);
    parseKey(toKey);
    const id = hex(HU(token));
    return this.locked(`transfer/${id}`, async () => {
      let rec = await this.journal.transferForUpdate(id);
      if (rec === null) {
        await this.verifyToken(token);
        const { tx, cd } = await transferRequest(token, owner, { recipient: signaturePredicate(toKey), mask: freshMask(), data: null, deadline: null });
        rec = { ...this.journal.base(), kind: 'transfer', transferId: id, recipient: hex(toKey), tx: hex(tx), request: hex(cd) };
        await this.journal.putTransfer(rec);
      }
      if (rec.transferId !== id || rec.recipient !== hex(toKey)) refuse('JournalConflict', 'another transfer is held for this source');
      const tx = unhex(rec.tx);
      return this.retainedCertification(unhex(rec.request), transferProofLimit(tx), rec.proof, async (proof) => {
        rec.proof = proof;
        await this.journal.putTransfer(rec);
      }, async (proof, trust) => {
        const out = appendTransfer(token, tx, proof);
        const held = await verifyHeld(this.cfg, this.domain, trust, decodeToken(out));
        if (!eq(held.owner.params, toKey)) refuse('ProviderFault', 'the certified transfer has another recipient');
        return out;
      }, { recoverProof });
    });
  }

  /**
   * Split a held token into whole parts. The plan is journaled first, then the burn's
   * exact request, the burned parent and each child as it is minted; a call with the same `splitId` resumes.
   */
  public split(token: Uint8Array, owner: OwnerSigner, outputs: { ownerKey: Uint8Array; amount: bigint }[], splitId?: Uint8Array,
    options?: ProofRecoveryOptions): Promise<Uint8Array[]> {
    token = Uint8Array.from(token);
    outputs = outputs.map(({ ownerKey, amount }) => ({ ownerKey: Uint8Array.from(ownerKey), amount }));
    splitId = splitId === undefined ? undefined : Uint8Array.from(splitId);
    const id = splitId ?? HU(cArr(cBytes(ascii('UNICITY_NB2_WALLET_SPLIT')), cBytes(token)));
    const recoverProof = options?.recoverProof;
    return this.locked(`split/${toHex(id)}`, () => this.splitInner(token, owner, outputs, id, recoverProof));
  }

  private async splitInner(token: Uint8Array, owner: OwnerSigner, outputs: { ownerKey: Uint8Array; amount: bigint }[], id: Uint8Array,
    recoverProof?: boolean): Promise<Uint8Array[]> {
    let rec = await this.journal.splitForUpdate(hex(id));
    if (rec === null) {
      const held = await this.verifyToken(token);
      if (outputs.length === 0) refuse('BadInput', 'a split requires an output');
      let sum = 0n;
      for (const o of outputs) {
        if (o.amount <= 0n) refuse('BadInput', 'every output amount is positive');
        parseKey(o.ownerKey);
        sum += o.amount;
      }
      if (sum !== held.amount) refuse('BadInput', `the outputs sum to ${sum}, the token holds ${held.amount}`);
      rec = {
        ...this.journal.base(), kind: 'split', splitId: hex(id), source: hex(token), mask: hex(freshMask()), status: 'planned',
        outputs: outputs.map((o) => ({ ownerKey: hex(o.ownerKey), amount: dec(o.amount), salt: hex(crypto.getRandomValues(new Uint8Array(32))), token: null })),
      };
      await this.journal.putSplit(rec);
    }
    const parent = decodeToken(unhex(rec.source));
    const plan = splitPlan(parent, rec.outputs.map((o) => ({ ownerKey: unhex(o.ownerKey), amount: undec(o.amount), salt: unhex(o.salt) })), this.cfg.ty, this.cfg.aid, unhex(rec.mask));
    if (rec.status === 'planned') {
      const { tx, cd } = await transferRequest(unhex(rec.source), owner, plan.burn);
      rec.burnTx = hex(tx);
      rec.burnRequest = hex(cd);
      rec.status = 'burn-requested';
      await this.journal.putSplit(rec);
    }
    const verifyBurn = async (burned: Uint8Array, trust: TrustInput) => {
      const split = await verifySplit(this.cfg, this.domain, trust, decodeToken(burned));
      if (!eq(split.manifest, plan.tree.root)) refuse('ProviderFault', 'certified split manifest differs from the plan');
      return { burned, split };
    };
    const refreshBurn = async () => {
      const tx = unhex(rec.burnTx!);
      const verified = await this.retainedCertification(unhex(rec.burnRequest!), transferProofLimit(tx), rec.burnProof, async (proof) => {
        rec.burnProof = proof;
        await this.journal.putSplit(rec);
      }, (proof, trust) => verifyBurn(appendTransfer(unhex(rec.source), tx, proof), trust), { recoverProof });
      rec.burned = hex(verified.burned);
      delete rec.burnProof;
      rec.status = 'burned';
      await this.journal.putSplit(rec);
      return verified;
    };
    let verified;
    if (rec.status === 'burn-requested') {
      verified = await refreshBurn();
    } else {
      try {
        verified = await this.retryingTrust((trust) => verifyBurn(unhex(rec.burned!), trust));
      } catch (error) {
        // A journal from the previous verifier may have recorded an unchecked proof.
        if (rec.status !== 'burned' || !(error instanceof Nb2Error) || this.trustBehind(error) ||
            rec.outputs.some((output) => output.token !== null || output.mintProof !== undefined)) throw error;
        verified = await refreshBurn();
      }
    }
    const { burned, split } = verified;
    const held = this.opts.trust;
    const cached = rec.outputs.some((output) => output.token !== null);
    for (let k = 0; k < rec.outputs.length; k++) {
      const output = rec.outputs[k];
      if (output.token !== null) continue;
      const { mint, allocation } = childMint(split.link, plan.tree, plan.children[k]);
      const { tx, cd } = mintRequest(mint);
      const child = await this.retainedCertification(cd, MAX_MINT_PROOF, output.mintProof, async (proof) => {
        output.mintProof = proof;
        await this.journal.putSplit(rec);
      }, async (proof, trust) => {
        const token = tokenOfChild(burned, allocation, tx, proof);
        const held = await verifyHeld(this.cfg, this.domain, trust, decodeToken(token));
        if (held.amount !== undec(output.amount)) refuse('ProviderFault', 'a split child has another amount');
        return token;
      }, { recoverProof });
      output.token = hex(child);
      delete output.mintProof;
      await this.journal.putSplit(rec);
    }
    rec.status = 'minted';
    await this.journal.putSplit(rec);
    const children = rec.outputs.map((o) => unhex(o.token!));
    if (cached || held !== this.opts.trust || this.refreshingTrust || this.trustStale()) {
      await this.retryingTrust(async (trust) => {
        for (const token of children) await verifyHeld(this.cfg, this.domain, trust, decodeToken(token));
      });
    }
    return children;
  }

  // ==== Unicity -> EVM ==================================================================================================

  /** The newest verified seal receipt (section 12.2) and its container, or null when the vault has never sealed. */
  public async newestSealReceipt(): Promise<{ receipt: SealReceipt; encoded: Uint8Array } | null> {
    const log = await this.evm.newestSeal(this.cfg.vault, this.opts.pins.deploymentBlock);
    if (log === null) return null;
    const rp = await this.evm.receiptProof(log.transactionHash, this.cfg.vault, TOPIC.SegmentSealed, false, log);
    const receipt = await this.retryingTrust((trust) => verifySealReceipt(this.cfg, this.domain, trust, rp.encoded));
    return { receipt, encoded: rp.encoded };
  }

  private trustBehind(e: unknown): boolean {
    return isCertificationTrustPending(e);
  }

  /** Keep a certification result through trust refresh, retry and reload. */
  private async retainedCertification<T>(request: Uint8Array, maxBytes: number, saved: string | undefined,
    save: (proof: string) => Promise<void>, verify: (proof: Uint8Array, trust: TrustInput) => Promise<T>,
    options: ProofRecoveryOptions & { beforeCertification?: () => Promise<void> } = {}): Promise<T> {
    if (this.trustStale()) await this.syncTrust();
    let rejected = saved !== undefined;
    if (saved !== undefined && /^0x([0-9a-f]{2})*$/.test(saved)) {
      rejected = false;
      let replace = false;
      const verifySaved = async (trust: TrustInput) => {
        try { return await verify(unhex(saved), trust); } catch (error) {
          rejected = error instanceof Nb2Error && !this.trustBehind(error);
          replace = rejected || (options.recoverProof === true && isCertificationTrustPending(error));
          throw error;
        }
      };
      try {
        return options.recoverProof ? await this.retryingTrust(verifySaved, false) : await this.retryingTrust(verifySaved);
      } catch (error) {
        if (!replace) throw error;
      }
    }
    await options.beforeCertification?.();
    const proof = await certifyChecked(this.opts.aggregator, request, maxBytes);
    if (saved !== undefined) {
      try { await this.retryingTrust((trust) => verify(proof, trust), false); } catch (error) {
        // A proof awaiting trust can still be usable. Only stage an unverified
        // replacement when the old proof was definitively rejected.
        if (!rejected || !isCertificationTrustPending(error)) throw error;
        await save(hex(proof));
        return this.retryingTrust((trust) => verify(proof, trust));
      }
      await save(hex(proof));
      return this.retryingTrust((trust) => verify(proof, trust), false);
    }
    await save(hex(proof));
    return this.retryingTrust((trust) => verify(proof, trust));
  }

  private trustNow(): number {
    return (this.opts.trustClock ?? (() => performance.now()))();
  }

  private trustStale(): boolean {
    if (this.opts.trustFreshnessMs === undefined) return false;
    const now = this.trustNow();
    return this.trustSuspended || this.lastTrustSync === undefined || !Number.isFinite(now) || now < this.lastTrustSync ||
      now - this.lastTrustSync >= this.opts.trustFreshnessMs;
  }

  /** Synchronize through the same coalesced path used by verification. */
  public syncTrust(): Promise<void> {
    if (this.refreshingTrust) return this.refreshingTrust;
    this.refreshingTrust = this.installRefreshedTrust().catch((error: unknown) => {
      // A failed sync may have persisted a verified prefix. Suspend this session until it can install it.
      this.trustSuspended = true;
      throw error;
    }).finally(() => { this.refreshingTrust = undefined; });
    return this.refreshingTrust;
  }

  private async installRefreshedTrust(): Promise<void> {
    const start = this.trustNow();
    const offered = await this.opts.refreshTrust?.();
    if (!offered) {
      if (this.opts.trustFreshnessMs !== undefined) refuse('TrustInput', 'a successful UTB sync must return authenticated history');
      return;
    }
    const candidate = await offered.snapshot();
    bindTrust(candidate, this.cfg);
    const held = this.opts.trust;
    const tip = held.history.tip!;
    const match = candidate.history.entryForEpoch(tip.epoch);
    if (!match || !eq(await match.entryId(), await tip.entryId())) {
      refuse('TrustInput', 'authority refresh does not extend the installed history');
    }
    const key = this.journal.prefix + 'trust-sync';
    const previous = await this.journal.store.get(key);
    if (previous !== null) {
      let saved: { domain?: unknown; genesis?: unknown; tipEpoch?: unknown; tipId?: unknown } | null;
      try { saved = JSON.parse(previous); } catch { saved = null; }
      if (saved?.domain !== hex(this.domain) || saved.genesis !== hex(candidate.id)
          || typeof saved.tipEpoch !== 'string' || !/^[1-9][0-9]{0,19}$/.test(saved.tipEpoch)) {
        refuse('TrustInput', 'invalid durable UTB checkpoint');
      }
      const entry = candidate.history.entryForEpoch(BigInt(saved.tipEpoch));
      if (!entry || hex(await entry.entryId()) !== saved.tipId) {
        refuse('TrustInput', 'authority refresh does not extend the durable history');
      }
    }
    if (this.opts.trustFreshnessMs !== undefined || previous !== null) {
      const stamp = this.trustNow();
      if (!Number.isFinite(start) || !Number.isFinite(stamp) || start < 0 || stamp < start || (this.lastTrustSync !== undefined && start < this.lastTrustSync)) {
        this.lastTrustSync = undefined;
        refuse('TrustInput', 'the UTB sync clock is uncertain');
      }
      const end = candidate.history.tip!;
      const record = JSON.stringify({
        domain: hex(this.domain), genesis: hex(candidate.id), tipEpoch: String(end.epoch), tipId: hex(await end.entryId()), syncedAt: Date.now(),
      });
      if (!await this.journal.store.putIf(key, previous, record)) refuse('JournalConflict', 'the UTB sync record changed');
      this.lastTrustSync = start;
    }
    this.opts.trust = candidate;
    this.trustSuspended = false;
  }

  /** Apply wallet freshness and pinning to verification of wallet-managed journal evidence. */
  public verifyWithTrust<T>(verify: (trust: TrustInput) => Promise<T>, refreshOnMissing = true): Promise<T> {
    return this.retryingTrust(verify, refreshOnMissing);
  }

  /** Verify one decision against a held snapshot, repeating if another decision installed its successor. */
  private async retryingTrust<T>(f: (trust: TrustInput) => Promise<T>, refreshOnMissing = true): Promise<T> {
    if (this.refreshingTrust) await this.refreshingTrust;
    if (this.trustStale()) await this.syncTrust();
    let refreshed = false;
    for (;;) {
      if (this.trustStale()) refuse('TrustSyncRequired', 'the UTB freshness window elapsed before verification');
      const held = this.opts.trust;
      try {
        const result = await f(held);
        if (this.refreshingTrust) await this.refreshingTrust;
        if (held !== this.opts.trust) continue;
        if (this.trustStale()) refuse('TrustSyncRequired', 'the UTB freshness window elapsed before publication');
        return result;
      } catch (error) {
        if (held !== this.opts.trust) continue;
        if (refreshed || !refreshOnMissing || !this.trustBehind(error) || !this.opts.refreshTrust) throw error;
        refreshed = true;
        await this.syncTrust();
      }
    }
  }

  /** Byte headroom for the prospective terminal pair, independent of gas calibration. */
  public returnHeadroom(token: Uint8Array): { operations: number; bytes: number; ordinarySegments: bigint } {
    const part = decodeToken(token);
    const bytes = evidenceOf(token).length;
    const bound = bytes + burnPairBound(encodeReturnData({ d: this.domain, asset: this.cfg.asset,
      recipient: new Uint8Array(20), amount: this.cfg.Qmax, minIndex: (1n << 48n) - 1n }).length);
    const operations = lineageOf(part).reduce((n, level) => n + 1 + level.transfers.length, 1);
    const { pMax } = maxProofs(this.opts.pins.maxEncodedTxBytes, BigInt(bound), BigInt(otherBytes(bound)), this.cfg.K);
    return { operations, bytes, ordinarySegments: pMax };
  }

  private checkReturnRecipient(recipient: Uint8Array): void {
    if (recipient.length !== 20) refuse('BadInput', 'an EVM recipient is 20 bytes');
    if (recipient.every((x) => x === 0) || eq(recipient, this.cfg.vault)) refuse('RecipientRefused', 'the zero address and the vault are refused');
  }

  /**
   * Plan the return of a whole held part to `recipient` on the EVM: verify its full provenance, pick the index from a verified seal
   * receipt, and run the capacity preflight (section 12.5): the complete prospective return with the history already owed from `a` plus
   * `returnReserveSegments` must fit the encoded-transaction limit and `userGasLimit`, and `payer` must fund that gas limit. Journals the
   * plan; nothing irreversible happens here.
   */
  public async planReturn(token: Uint8Array, recipient: Uint8Array, payer: Uint8Array, opts: { useStateRead?: boolean; verifiedIndex?: bigint; admission?: ReturnAdmission } = {}): Promise<ReturnPlan> {
    token = Uint8Array.from(token);
    recipient = Uint8Array.from(recipient);
    payer = Uint8Array.from(payer);
    opts = { ...opts };
    const returnId = HU(token);
    return this.locked(`return/${toHex(returnId)}`, async () => {
      const part = decodeToken(token);
      const held = await this.retryingTrust((trust) => verifyHeld(this.cfg, this.domain, trust, part));
      this.checkReturnRecipient(recipient);
      const warnings: string[] = [];
      if (this.cfg.erc20) {
        warnings.push(ERC20_RETURN_RISKS);
        await previewErc20Recipient(this.evm, this.cfg, recipient, held.amount);
      }
      if ((await this.evm.code(recipient)).length > 0) warnings.push('the recipient is a contract: a payout it refuses strands the burn (simulation is not a guarantee)');
      // the index
      let a: bigint;
      let startHead: Uint8Array;
      let fromBlock = this.opts.pins.deploymentBlock;
      let sealReceipt: Uint8Array | undefined;
      if (opts.useStateRead) {
        const st = await this.evm.vaultState(this.cfg.vault);
        checkStateRead(this.opts.pins.stateReadOnly, st.segment, opts.verifiedIndex ?? 0n, this.opts.pins.maxJump ?? 64n);
        a = st.segment;
        startHead = a === 0n ? genesisHead(this.domain, this.cfg.K) : st.head;
      } else {
        const sr = await this.newestSealReceipt();
        ({ a, startHead } = burnIndex(this.cfg, this.domain, sr?.receipt ?? null));
        if (sr !== null) {
          fromBlock = sr.receipt.blockNumber;
          sealReceipt = sr.encoded;
          // availability, not safety: an old receipt anchors the burn low (more history to prove), never in the future
          const age = (await this.evm.saneHead()) - sr.receipt.blockNumber;
          if (age > (this.opts.maxSealAgeBlocks ?? 7_200n)) warnings.push(`the newest seal receipt served is ${age} blocks old: the provider may be hiding newer seals; the burn then owes more history`);
        }
      }
      const existing = await this.journal.retForUpdate(hex(returnId));
      if (existing !== null && existing.status !== 'planned') refuse('NotPending', `this part's return is already ${existing.status}`);
      const record: ReturnRecord = {
        ...this.journal.base(), kind: 'return', returnId: hex(returnId), source: hex(token), amount: dec(held.amount), recipient: hex(recipient), a: dec(a),
        startHead: hex(startHead), fromBlock: dec(fromBlock), ...(sealReceipt ? { sealReceipt: hex(sealReceipt) } : {}), payer: hex(payer), status: 'planned', sends: [],
      };
      const pf = await this.admitReturn(record, held.amount, opts.admission);
      await this.journal.putReturn(record);
      return { returnId, amount: held.amount, recipient, a, cObs: pf.cObs, pNow: pf.pNow, pMax: pf.pMax, marginSegments: pf.pMax - pf.need, gasLimit: pf.gas, warnings, record };
    });
  }

  /**
   * Whether the gas model applies to the deployment: a model that says which deployments it is calibrated for (the default does) is shown
   * the verifier's runtime code (whose hash must be Γ's), the vault's (whose hash must be the manifest's), the code at the verifier's first
   * CREATE address (its helper) and the manifest's native gas schedule; a model that does not say is the wallet's own choice.
   */
  private async gasApplies(): Promise<boolean> {
    if (this.gas.supportsDeployment === undefined) return true;
    if (this.gasFits === null) {
      const verifierCode = await this.evm.code(this.cfg.verifier);
      if (!eq(HE(verifierCode), this.cfg.verifierCodeHash)) refuse('BadDeployment', 'the verifier\'s runtime code is not the one Γ pins');
      const vaultCode = await this.evm.code(this.cfg.vault);
      if (!eq(HE(vaultCode), this.opts.pins.vaultRuntimeCodeHash)) refuse('BadDeployment', 'the vault runtime code hash is not the pinned one');
      let helperCode: Uint8Array;
      if (this.cfg.erc20) {
        const selector = (sig: string) => HE(ascii(sig)).subarray(0, 4);
        const address = await this.evm.call(this.cfg.verifier, selector('LINEAGE()'));
        if (address.length !== 32 || address.subarray(0, 12).some((b) => b !== 0)) {
          return refuse('BadDeployment', 'the ERC20 ordinary verifier returned an invalid lineage address');
        }
        helperCode = await this.evm.code(address.subarray(12));
        if (helperCode.length === 0 || !eq(HE(helperCode), await this.evm.call(this.cfg.verifier, selector('LINEAGE_HASH()')))) {
          return refuse('BadDeployment', 'the ERC20 lineage helper runtime differs from the verifier binding');
        }
      } else {
        helperCode = await this.evm.code(createAddress(this.cfg.verifier, 1n));
      }
      this.gasFits = this.gas.supportsDeployment({
        gamma: this.opts.pins.gamma, verifier: this.cfg.verifier, K: this.cfg.K, B: this.cfg.B, Qmax: this.cfg.Qmax, verifierCode, helperCode, vaultCode,
        ...(this.opts.pins.nativeGasSchedule === undefined ? {} : { nativeGasSchedule: this.opts.pins.nativeGasSchedule }),
      });
    }
    return this.gasFits;
  }

  /**
   * The section 12.5 preflight for burning `token` at index `a` to `recipient`, with a fresh endpoint estimate (c_obs = max(c, a); the
   * state read is an availability assumption, not evidence) and the payer's funds for the worst-case gas limit.
   */
  private async preflight(token: Uint8Array, amount: bigint, recipient: Uint8Array, a: bigint, payer: Uint8Array, admission?: ReturnAdmission) {
    const envelope = admission?.ordinaryEnvelope;
    if (!envelope?.gasFor && !(await this.gasApplies())) {
      fail('CapacityPreflight', `the gas model ${this.gas.name} is not calibrated for this deployment (its verifier, helper and vault code, its native gas schedule): supply a GasModel for it`);
    }
    const st = await this.evm.vaultState(this.cfg.vault);
    const cObs = st.segment > a ? st.segment : a;
    const R = encodeReturnData({ d: this.domain, asset: this.cfg.asset, recipient, amount, minIndex: a });
    const lT = BigInt(evidenceOf(token).length + burnPairBound(R.length));
    const lO = BigInt(otherBytes(Number(lT)));
    const lineage = lineageOf(decodeToken(token));
    const gasAt = (p: bigint): bigint | null => {
      const shape = { evidenceBytes: Number(lT), lineage, pendingTransactions: 1, proofs: p, K: this.cfg.K };
      return envelope?.gasFor ? envelope.gasFor(shape) : this.gas.redeemGasLimit(shape);
    };
    const pins = this.opts.pins;
    const lMax = envelope && envelope.encodedBytes < pins.maxEncodedTxBytes ? envelope.encodedBytes : pins.maxEncodedTxBytes;
    const userGasLimit = envelope && envelope.gas < pins.userGasLimit ? envelope.gas : pins.userGasLimit;
    const pf = capacityPreflight({ lMax, lT, lO, K: this.cfg.K, a, cObs, reserve: pins.returnReserveSegments, gasAt, userGasLimit });
    const calldataBytes = redeemCalldataLength(Number(lT), pf.need === 0n ? 0 : 32 + Number(pf.need) * gapProofLen(this.cfg.K));
    if (admission?.checkOrdinary) return { cObs, ...pf, calldataBytes };
    // the payer must fund the worst-case gas limit at the current fee level (twice the base fee plus the priority fee)
    const fees = await this.evm.fees();
    const cost = pf.gas * (2n * fees.baseFee + fees.priority);
    const bal = await this.evm.balance(payer);
    if (bal < cost) refuse('InsufficientFunds', `the payer holds ${bal} wei, the worst-case gas limit ${pf.gas} needs ${cost}`);
    return { cObs, ...pf, calldataBytes };
  }

  private async admitReturn(record: ReturnRecord, amount: bigint, admission?: ReturnAdmission) {
    this.requireErc20Qualification();
    delete record.recovery;
    if (this.cfg.erc20) return this.admitErc20Return(record, amount, admission?.erc20Recovery);
    const a = undec(record.a);
    let ordinary: Awaited<ReturnType<NativeBridgeV2['preflight']>>;
    try {
      const source = unhex(record.source);
      ordinary = await this.preflight(source, amount, unhex(record.recipient), a, unhex(record.payer ?? record.recipient), admission);
      await admission?.checkOrdinary?.(structuredClone(record), ordinary.gas);
    } catch (e) {
      if (!admission?.recover || !((e instanceof Nb2Error && e.rule === 'CapacityPreflight') ||
        (e instanceof WalletError && e.reason === 'InsufficientFunds'))) throw e;
      record.recovery = await admission.recover(structuredClone(record));
      const observed = undec(record.recovery.observed);
      return { cObs: observed, pNow: observed > a ? observed - a : 0n, need: 0n, pMax: 0n, gas: 0n };
    }
    return ordinary;
  }

  private erc20Limits(limits: Erc20ReturnRecovery['limits']): RecoveryLimits {
    const { chainId } = this.cfg;
    return { ...limits, chainId, worstCaseEnvelope: false,
      signedBytes: Math.min(limits.signedBytes, Number(this.opts.pins.maxEncodedTxBytes)),
      gas: limits.gas < this.opts.pins.userGasLimit ? limits.gas : this.opts.pins.userGasLimit };
  }

  private async checkErc20Funds(record: ReturnRecord, limits: RecoveryLimits, replacing?: bigint) {
    const payer = unhex(record.payer ?? record.recipient);
    const other = await this.checkErc20Payer(record, payer);
    const [free, nonce, fees] = await Promise.all([
      this.freeErc20PayerBalance(payer, other), replacing ?? this.evm.nonce(payer), this.evm.fees(),
    ]);
    const currentBid = 2n * fees.baseFee + fees.priority;
    if (currentBid > limits.maxFeePerGas || fees.priority > limits.maxPriorityFeePerGas) {
      fail('CapacityPreflight', 'current fees exceed the continuation bid limits');
    }
    return { nonce: other.finalizedNonce !== undefined && other.finalizedNonce > nonce ? other.finalizedNonce : nonce,
      maxNonce: payerNonceLimit(limits.maxNonce, other), balance: free < limits.balance ? free : limits.balance };
  }

  private async freeErc20PayerBalance(payer: Uint8Array, other: PayerCommitments): Promise<bigint> {
    const [balance, pending, finalized] = await Promise.all([this.evm.balance(payer), this.evm.balance(payer, 'pending'),
      other.finalizedNonce === undefined ? undefined : this.evm.balance(payer, 'finalized')]);
    const visible = balance < pending ? balance : pending;
    const free = (finalized !== undefined && finalized < visible ? finalized : visible) - other.fees;
    return free > 0n ? free : 0n;
  }

  /** Check persisted payer commitments, including nonces omitted from the pending RPC view. */
  public checkErc20Payer(record: ReturnRecord, payer: Uint8Array, reserve = false, fence?: string,
    send?: { nonce: bigint; remainingCalls: bigint; maxNonce?: bigint; beforeSigning?: (other: PayerCommitments) => Promise<void> }) {
    return this.journal.checkReturnPayer(this.cfg.chainId, payer, record.returnId, reserve, {
      mode: record.status === 'planned' ? 'admit' : 'drain', finalizedNonce: () => this.evm.nonce(payer, 'finalized'), fence,
      finalizedBlock: (number, hash) => this.evm.isFinalizedBlock(number, hash),
      signingNonce: send?.nonce, remainingCalls: send?.remainingCalls, maxNonce: send?.maxNonce, beforeSigning: send?.beforeSigning,
    });
  }

  private checkErc20Reserve(plan: NonNullable<ReturnRecord['recovery']>, funds: { nonce: bigint; maxNonce: bigint; balance: bigint }): void {
    if (funds.nonce + undec(plan.calls) - 1n > funds.maxNonce) fail('CapacityPreflight', 'continuation schedule exceeds the declared nonce horizon');
    if (undec(plan.totalFee) > funds.balance) fail('CapacityPreflight', 'insufficient free payer balance');
  }

  /** Price a complete ERC20 continuation from release inputs, including when adopting an already signed burn. */
  public async qualifyErc20Recovery(record: ReturnRecord, input: Erc20ReturnRecovery, replacing?: bigint) {
    return this.quoteErc20Continuation(structuredClone(record), structuredClone(input), undefined, replacing);
  }

  private async verifyErc20RecoveryRelease({ deployment, calibration }: Pick<Erc20ReturnRecovery, 'deployment' | 'calibration'>): Promise<void> {
    const token = this.cfg.erc20?.token;
    const pins = this.opts.pins.erc20;
    if (!token || !pins) fail('CapacityPreflight', 'a pinned ERC20 deployment is required');
    const recovery = erc20Create2(pins.factory, HE(addressWord(token)), pins.recoveryInitcodeHash);
    checkRecoveryCalibration(this.cfg, deployment, calibration, this.cfg.chainId);
    const [runtime, vault] = await Promise.all([this.evm.code(recovery), this.evm.code(this.cfg.vault)]);
    if (!eq(deployment.recovery, recovery) || !deployment.vaultRuntimeHash || !eq(deployment.vaultRuntimeHash, this.opts.pins.vaultRuntimeCodeHash) ||
        !eq(HE(runtime), deployment.runtimeHash) || !eq(HE(vault), deployment.vaultRuntimeHash)) {
      fail('CapacityPreflight', 'continuation calibration differs from the deployed graph');
    }
    await verifyRecoveryDependencies(this.evm, recovery);
  }

  private async quoteErc20Continuation(record: ReturnRecord, input: Erc20ReturnRecovery,
    ordinary?: { gas: bigint; calldataBytes: number }, replacing?: bigint): Promise<NonNullable<ReturnRecord['recovery']>> {
    await this.verifyErc20RecoveryRelease(input);
    const { deployment, calibration } = input;
    const limits = this.erc20Limits(input.limits);
    const funds = await this.checkErc20Funds(record, limits, replacing);
    const a = undec(record.a);
    const { segment } = await this.evm.vaultState(this.cfg.vault);
    const observed = segment > a ? segment : a;
    const backlog = { ...input.backlog, signedStart: a, observed };
    const bounds = input.signingBounds && { ...input.signingBounds,
      ordinary: ordinary && { ...ordinary, attemptsBeforeFallback: input.ordinaryAttempts?.attemptsBeforeFallback ?? 0n,
        inclusionMs: input.ordinaryAttempts?.inclusionMs ?? 0n } };
    const plan = await this.retryingTrust((trust) => preflightRecovery(this.opts.pins.gamma, unhex(record.source), trust,
      buildParams(this.opts.pins.build), deployment, calibration, { ...limits, balance: funds.balance }, backlog,
      record.sealReceipt ? unhex(record.sealReceipt) : undefined, bounds));
    const priced = { generation: hex(recoveryGeneration(deployment.salt, this.domain)),
      calls: dec(BigInt(plan.run.length) + plan.advance.calls + 1n + plan.priorAttempts), totalFee: dec(plan.totalFee),
      runCuts: plan.run.map((cut) => cut.shape.operations), advanceGaps: plan.advance.quote.shape.gaps,
      observed: dec(observed), progressEnd: dec(observed + backlog.duringProgress), receiptP99Ms: dec(backlog.receiptP99Ms),
      finalInclusionMs: dec(backlog.finalInclusionMs), qualifiedForMs: dec(backlog.qualifiedForMs),
      envelope: { gas: dec(limits.gas), signedBytes: limits.signedBytes, calldataBytes: limits.calldataBytes, maxNonce: dec(limits.maxNonce),
        maxFeePerGas: dec(limits.maxFeePerGas), maxPriorityFeePerGas: dec(limits.maxPriorityFeePerGas) },
      ordinary: ordinary && { gas: dec(ordinary.gas), calldataBytes: ordinary.calldataBytes,
        maxFeePerGas: dec(limits.maxFeePerGas), attemptsBeforeFallback: dec(plan.priorAttempts) } };
    this.checkErc20Reserve(priced, funds);
    return priced;
  }

  private async admitErc20Return(record: ReturnRecord, amount: bigint, input?: Erc20ReturnRecovery) {
    if (!input) fail('CapacityPreflight', 'a bounded ERC20 continuation quote is required');
    input = structuredClone(input);
    const a = undec(record.a);
    const limits = this.erc20Limits(input.limits);
    let ordinary: Awaited<ReturnType<NativeBridgeV2['preflight']>> | undefined;
    try {
      const candidate = await this.preflight(unhex(record.source), amount, unhex(record.recipient), a, unhex(record.payer ?? record.recipient), {
        ordinaryEnvelope: { encodedBytes: this.opts.pins.maxEncodedTxBytes, gas: limits.gas,
          gasFor: input.ordinaryRanges && ((shape) => quoteOrdinaryExecution(shape, input!.ordinaryRanges!, this.opts.pins.gasReserve)) },
      });
      if (quoteErc20Call(candidate.calldataBytes, candidate.gas, limits)) ordinary = candidate;
    } catch (e) {
      if (!((e instanceof Nb2Error && e.rule === 'CapacityPreflight') || (e instanceof WalletError && e.reason === 'InsufficientFunds'))) throw e;
    }
    record.recovery = await this.quoteErc20Continuation(record, input, ordinary);
    const observed = undec(record.recovery.observed);
    return ordinary ?? { cObs: observed, pNow: observed - a, need: 0n, pMax: 0n, gas: 0n };
  }

  private async verifyReturnAnchor(rec: ReturnRecord): Promise<void> {
    const seal = rec.sealReceipt ? await this.retryingTrust((trust) => verifySealReceipt(this.cfg, this.domain, trust, unhex(rec.sealReceipt!))) : null;
    const anchor = burnIndex(this.cfg, this.domain, seal);
    if (anchor.a !== undec(rec.a) || !eq(anchor.startHead, unhex(rec.startHead)) ||
      undec(rec.fromBlock) !== (seal?.blockNumber ?? this.opts.pins.deploymentBlock)) {
      refuse('BadInput', 'return start does not match its authenticated anchor');
    }
  }

  /** Authenticate the private request before a backup can submit it on another device. */
  private async validatePendingReturn(rec: ReturnRecord): Promise<Uint8Array> {
    const src = unhex(rec.source);
    const held = await this.verifyToken(src);
    const head = headOf(decodeToken(src));
    const receiver = unhex(rec.recipient);
    this.checkReturnRecipient(receiver);
    const a = undec(rec.a);
    const request = parseCertification(unhex(rec.burnRequest!));
    const rawTx = unhex(rec.burnTx!);
    const tx = parseTransfer(rawTx);
    const expected = encodeReturnData({ d: this.domain, asset: this.cfg.asset, recipient: receiver, amount: held.amount, minIndex: a });
    await this.verifyReturnAnchor(rec);
    if (rec.returnId !== hex(HU(src)) || held.amount !== undec(rec.amount) ||
      tx.data === null || !eq(tx.data, expected) || tx.deadline !== null || request.deadline !== null ||
      !eq(encodePredicate(tx.recipient), encodePredicate(burnPredicate(HU(expected)))) ||
      head.owner.type !== 1n || !eq(encodePredicate(head.owner), encodePredicate(request.source)) ||
      !eq(head.state, request.sourceHash) || !eq(HU(rawTx), request.txHash) ||
      rec.certificationLocator !== hex(stateId(request.source, request.sourceHash))) {
      refuse('BadInput', 'backup does not bind the exact signed return and authenticated start');
    }
    verifyUnlock(head.owner.params, head.state, request.txHash, request.unlock);
    return redemptionId(this.domain, burnTransitionId(stateId(request.source, request.sourceHash), request.txHash));
  }

  /** Authenticate the backup and its optional terminal proof before committing a return. */
  public async importPendingReturn(snapshot: ReturnRecord, terminal?: Uint8Array,
    beforeCommit?: (verified: ReturnRecord, incoming: ReturnRecord) => Promise<void | null | NonNullable<ReturnRecord['recovery']>>,
    archives: readonly EvmReader[] = [this.evm], evidence?: ReturnEvidence): Promise<ReturnRecord> {
    const rec = structuredClone(snapshot);
    const burned = terminal && Uint8Array.from(terminal);
    if (rec.domain !== hex(this.domain)) refuse('BadInput', 'return backup belongs to another deployment');
    if (!rec.burnRequest || !rec.burnTx || !rec.certificationLocator) refuse('BadInput', 'backup lacks an exact signed burn');
    const eta = hex(await this.validatePendingReturn(rec));
    const { source, amount, returnId, recipient, a, startHead, fromBlock, sealReceipt, burnTx, burnRequest, certificationLocator } = rec;
    const verified: ReturnRecord = { ...this.journal.base(), kind: 'return', status: 'burn-requested', sends: [],
      source, amount, returnId, recipient, a, startHead, fromBlock, sealReceipt, burnTx, burnRequest, certificationLocator };
    if (burned) {
      const part = decodeEvidence(evidenceOf(burned));
      const final = part.proofs.at(-1);
      if (!final || !eq(encodeCertification(final.cd), unhex(rec.burnRequest!)) ||
        !eq(appendTransfer(unhex(source), unhex(rec.burnTx!), encodeProof(final)), burned)) {
        refuse('BadInput', 'certified backup terminal does not extend the exact signed request');
      }
      const verdict = await this.retryingTrust((trust) => verifyPart(this.cfg, this.domain, trust, part));
      verified.status = 'burned';
      verified.burned = hex(burned);
      if (hex(verdict.eta) !== eta) refuse('BadInput', 'terminal disagrees with the signed redemption ID');
      verified.eta = eta;
    }
    return this.locked(`return/${returnId.slice(2)}`, async () => {
      const existing = await this.journal.retForUpdate(returnId);
      if (existing?.burnRequest !== undefined &&
        (existing.burnRequest !== burnRequest || existing.burnTx !== burnTx || existing.returnId !== returnId ||
          existing.source !== source || existing.amount !== amount || existing.recipient !== recipient || existing.a !== a ||
          existing.startHead !== startHead || existing.fromBlock !== fromBlock || existing.certificationLocator !== certificationLocator)) {
        refuse('JournalConflict', 'another signed return is held');
      }
      const row = RETURN_IMPORT[existing?.status ?? 'absent'];
      const action = row[burned ? 'terminal' : 'signed'];
      let selected = action === 'adopt' ? verified : existing!;
      if (action === 'attach' && !selected.burned) {
        selected.burned = verified.burned;
        selected.eta = eta;
        if (selected.status !== 'paid') selected.status = 'burned';
        // The known payment remains authoritative when a later backup supplies the missing burn.
        await this.journal.putReturn(selected);
      }
      if (row.paid === 'keep') return selected;
      // The signed request binds eta even when the holder has yet to obtain a terminal.
      const payment = { ...selected, eta };
      const payout = await this.findPaid(payment, archives, false, evidence);
      selected = payment;
      if (payout) {
        await this.journal.putReturn(payment);
        if (payout.state === 'needs-archive') this.requireReturnArchive(payout.txHash, payout.missing);
        return payment;
      }
      if (action === 'certify') {
        await this.certifyReturn(selected);
        // The signed request is already durable. Keep its verified result if future qualification fails.
        await this.journal.putReturn(selected);
      }
      if (beforeCommit && selected.sends.length) {
        const exact = await this.reconcileSend(selected, archives, false);
        if (exact.state === 'needs-archive') this.requireReturnArchive(exact.txHash, exact.missing);
      }
      if (selected.status === 'paid') return selected;
      const localPlan = await beforeCommit?.(structuredClone(selected), structuredClone(verified));
      if (localPlan !== undefined) selected = { ...selected, recovery: localPlan ?? undefined };
      if (selected !== existing) await this.journal.putReturn(selected);
      return selected;
    });
  }

  private requireReturnArchive(tx: Uint8Array, missing?: string): never {
    return refuse('EvidenceMissing', `needs archive for payment or exact failure ${hexq(tx)}: the node no longer serves ${missing ?? 'its certified block and receipt'}. Add a reader that does, then resume`);
  }

  private async returnRecord(id: Uint8Array): Promise<ReturnRecord> {
    return (await this.journal.retForUpdate(hex(id))) ?? refuse('JournalNotPersisted', `no journal entry for return ${hexq(id)}`);
  }

  /**
   * Certify the terminal burn of a planned return: R signs the recipient, the amount and the index. The exact request is journaled
   * before certification, the certified burn before this returns; a second call resumes the same burn and never makes another.
   */
  public burn(returnId: Uint8Array, owner?: OwnerSigner, admission?: ReturnAdmission, expectedRecipient?: Uint8Array,
    options?: ProofRecoveryOptions): Promise<{ burned: Uint8Array; eta: Uint8Array; verdict: Verdict }> {
    returnId = Uint8Array.from(returnId);
    const recipient = expectedRecipient && Uint8Array.from(expectedRecipient);
    const recoverProof = options?.recoverProof;
    return this.locked(`return/${toHex(returnId)}`, async () => {
      const record = await this.returnRecord(returnId);
      return this.burnInner(returnId, record, owner, admission, recipient, recoverProof);
    });
  }

  private async burnInner(returnId: Uint8Array, rec: ReturnRecord, owner?: OwnerSigner, admission?: ReturnAdmission, expectedRecipient?: Uint8Array,
    recoverProof?: boolean): Promise<{ burned: Uint8Array; eta: Uint8Array; verdict: Verdict }> {
    if (rec.status === 'planned') {
      // the last check before the irreversible step: the preflight again, at the journaled index, against a fresh state
      if (owner === undefined) return refuse('BadInput', 'only the holder can sign a new burn');
      if (admission || this.cfg.erc20) await this.verifyReturnAnchor(rec);
      const recipient = unhex(rec.recipient);
      this.checkReturnRecipient(recipient);
      if (expectedRecipient && !eq(recipient, expectedRecipient)) refuse('BadInput', 'planned return does not match the authorized recipient');
      const source = unhex(rec.source);
      const held = await this.verifyToken(source);
      if (rec.returnId !== hex(returnId) || !eq(HU(source), returnId) || held.amount !== undec(rec.amount)) {
        refuse('BadInput', 'planned return does not match the verified source and amount');
      }
      const admissionSnapshot = this.cfg.erc20 && admission?.erc20Recovery
        ? { ...admission, erc20Recovery: structuredClone(admission.erc20Recovery) } : admission;
      await this.admitReturn(rec, held.amount, admissionSnapshot);
      await previewErc20Recipient(this.evm, this.cfg, recipient, held.amount);
      const R = encodeReturnData({ d: this.domain, asset: this.cfg.asset, recipient, amount: held.amount, minIndex: undec(rec.a) });
      const { cancel, retain } = this.cfg.erc20 ? await this.checkErc20Payer(rec, unhex(rec.payer ?? rec.recipient), true, hex(freshMask())) : {};
      let signing = false;
      let declined = false;
      let signed: Awaited<ReturnType<typeof transferRequest>>;
      try {
        if (this.cfg.erc20) {
          this.checkErc20Reserve(rec.recovery!, await this.checkErc20Funds(rec, this.erc20Limits(admissionSnapshot!.erc20Recovery!.limits)));
        }
        signed = await transferRequest(source, { publicKey: owner.publicKey, signUnlock: async (message) => {
          signing = true;
          try { return await owner.signUnlock(message); }
          catch (e) { declined = e instanceof WalletError && e.reason === 'SigningDeclined'; throw e; }
        } }, { recipient: burnPredicate(HU(R)), mask: freshMask(), data: R, deadline: null });
      } catch (e) {
        if (!signing || declined) await cancel?.();
        else await retain?.();
        throw e;
      }
      await retain?.();
      const { tx, cd } = signed;
      rec.burnTx = hex(tx);
      rec.burnRequest = hex(cd);
      const request = parseCertification(cd);
      rec.certificationLocator = hex(stateId(request.source, request.sourceHash));
      rec.status = 'burn-requested';
      await this.journal.putReturn(rec);
    }
    if (rec.status === 'burn-requested' || (rec.status === 'paid' && !rec.burned)) {
      if (!rec.burnRequest || !rec.burnTx) refuse('EvidenceMissing', 'the exact signed burn is unavailable');
      await this.certifyReturn(rec, rec.status === 'burn-requested' && admission?.beforeCertification
        ? (record) => admission.beforeCertification!(record) : undefined, recoverProof);
      await this.journal.putReturn(rec);
    }
    const burned = unhex(rec.burned!);
    const part = decodeEvidence(evidenceOf(burned));
    const verdict = await this.retryingTrust((trust) => verifyPart(this.cfg, this.domain, trust, part));
    return { burned, eta: verdict.eta, verdict };
  }

  private async certifyReturn(rec: ReturnRecord, beforeCertification?: (record: ReturnRecord) => Promise<void>, recoverProof?: boolean): Promise<void> {
    const tx = unhex(rec.burnTx!);
    const { burned, v } = await this.retainedCertification(unhex(rec.burnRequest!), transferProofLimit(tx), rec.burnProof, async (proof) => {
      rec.burnProof = proof;
      await this.journal.putReturn(rec);
    }, async (proof, trust) => {
      const burned = appendTransfer(unhex(rec.source), tx, proof);
      const v = await verifyPart(this.cfg, this.domain, trust, decodeEvidence(evidenceOf(burned)));
      if (v.minSegment !== undec(rec.a) || v.amount !== undec(rec.amount) || !eq(v.recipient, unhex(rec.recipient))) refuse('ProviderFault', 'the certified burn is not the planned one');
      if (rec.eta !== undefined && rec.eta !== hex(v.eta)) refuse('JournalConflict', 'certified burn does not match the journaled redemption ID');
      return { burned, v };
    }, { recoverProof, beforeCertification: beforeCertification && (() => beforeCertification(structuredClone(rec))) });
    rec.burned = hex(burned);
    delete rec.burnProof;
    rec.eta = hex(v.eta);
    if (rec.status !== 'paid') rec.status = 'burned';
  }

  /**
   * Build the redeem transaction of a burned return: one SegmentSealed log per segment a .. c-1 from any provider, each checked
   * (length, order, M_j, head link from the journaled start head), the gap proofs, and the gas limit (expected cost plus gasReserve).
   * A missing or reordered log is missing evidence, never absence. Refuses with `CapacityExceeded` when the claim does not fit.
   */
  public buildRedeem(returnId: Uint8Array, envelope?: RedeemOptions['envelope']): Promise<RedeemTx> {
    returnId = Uint8Array.from(returnId);
    return this.locked(`return/${toHex(returnId)}`, async () => {
      const rec = await this.returnRecord(returnId);
      this.requireRedeemable(rec);
      return this.buildRedeemInner(rec, envelope);
    });
  }

  private requireRedeemable(rec: ReturnRecord): void {
    if (rec.status !== 'burned' && rec.status !== 'submitted') refuse('NotPending', `return ${rec.returnId} is ${rec.status}`);
  }

  private async buildRedeemInner(rec: ReturnRecord, envelope?: RedeemOptions['envelope']): Promise<RedeemTx> {
    const a = undec(rec.a);
    const eta = unhex(rec.eta!);
    const evidence = evidenceOf(unhex(rec.burned!));
    for (let attempt = 0; ; attempt++) {
      const st = await this.evm.vaultState(this.cfg.vault);
      if (st.segment < a) refuse('NotPending', `the vault is at segment ${st.segment}, below the burn index ${a}: wait (FutureIndex)`);
      const logs = await this.evm.segmentLogs(this.cfg.vault, undec(rec.fromBlock), a, st.segment);
      const segs: Segment[] = [];
      let before = unhex(rec.startHead);
      for (const l of logs) {
        const j = BigInt(hexq(l.topics[1]));
        const s = checkSegmentLog(this.domain, this.cfg.K, j, before, l.data);
        segs.push(s);
        before = s.after;
      }
      if (!eq(before, st.head)) {
        // the chain moved between the reads, or the provider is inconsistent: read again once
        if (attempt < 2) continue;
        refuse('ProviderFault', 'the served segment logs do not fold to the vault\'s current head');
      }
      const { history, paid } = buildHistory(segs, eta, a, st.segment, unhex(rec.startHead));
      if (paid !== null) refuse('AlreadyPaid', `the redemption ID is in sealed segment ${paid}: reconcile`);
      const P = st.segment - a;
      const calldata = redeemCalldata(evidence, eta, a, history);
      const pins = this.opts.pins;
      const lO = BigInt(otherBytes(evidence.length));
      const shape = { evidenceBytes: evidence.length, lineage: lineageOf(decodeToken(unhex(rec.burned!))),
        pendingTransactions: 0, proofs: P, K: this.cfg.K };
      const releaseBound = envelope?.gasFor?.(shape);
      if (releaseBound === null) fail('CapacityExceeded', 'ordinary packet is outside the release gas envelope');
      let gasLimit = envelope?.gasFor ? releaseBound ?? null : (await this.gasApplies()) ? this.gas.redeemGasLimit(shape) : null;
      const est = await this.evm.estimateGas({ from: unhex(rec.recipient), to: this.cfg.vault, data: calldata }).catch((e: unknown) => {
        if (releaseBound !== undefined && e instanceof RpcError) return { revert: null, message: e.message };
        throw e;
      });
      if ('gas' in est) {
        const estimated = est.gas + pins.gasReserve;
        if (estimated > (gasLimit ?? 0n) || !envelope?.gasFor) gasLimit = estimated;
      }
      else {
        const e = decodeRevert(est.revert ?? new Uint8Array());
        const action = classifyRedeemError(e);
        if (action === 'rebuild-history' && attempt < 2) continue;
        if (action === 'reconcile') refuse('AlreadyPaid', 'the vault reports AlreadyPaid: reconcile');
        if (e !== null) throw redeemRefusal(e, `simulation refused (${action})`);
        // no rule: an RPC without simulation; the model's bound stands
      }
      if (gasLimit === null) fail('CapacityExceeded', 'the gas cannot be bounded');
      const encoded = envelope && envelope.encodedBytes < pins.maxEncodedTxBytes ? envelope.encodedBytes : pins.maxEncodedTxBytes;
      const gasCap = envelope && envelope.gas < pins.userGasLimit ? envelope.gas : pins.userGasLimit;
      capacityExceeded(encoded, BigInt(evidence.length), lO, this.cfg.K, P, gasLimit!, gasCap);
      return { returnId: unhex(rec.returnId), calldata, gasLimit: gasLimit!, P, endpoint: st.segment, history, eta, claimedStart: a };
    }
  }

  /**
   * Send the redeem. Earlier sends are reconciled first (a pending one is never doubled; a landed one is the answer). Every signed
   * transaction is journaled before broadcast; an ambiguous broadcast is resolved by its receipt. A stale endpoint is rebuilt, never
   * the burn; failures are classified by error selector.
   */
  public submitRedeem(returnId: Uint8Array, signer: EvmSigner, options: RedeemOptions = {}): Promise<ReconcileResult> {
    returnId = Uint8Array.from(returnId);
    const payer: EvmSigner = { address: Uint8Array.from(signer.address), signTransaction: signer.signTransaction.bind(signer) };
    if (options.erc20Policy || options.erc20Recovery) options = {
      ...options, erc20Policy: options.erc20Policy && { ...options.erc20Policy }, erc20Recovery: structuredClone(options.erc20Recovery),
    };
    return this.locked(`return/${toHex(returnId)}`, () => this.submitRedeemInner(returnId, payer, options));
  }

  private async submitRedeemInner(returnId: Uint8Array, signer: EvmSigner, options: RedeemOptions = {}): Promise<ReconcileResult> {
    const archives = options.archives ?? [this.evm];
    // Reconciliation, construction and the journal CAS share this snapshot.
    const fresh = await this.returnRecord(returnId);
    const first = fresh.sends[0] && decodeSignedTx(unhex(fresh.sends[0].raw));
    const payer = fresh.executionPayer ? unhex(fresh.executionPayer) : first?.from;
    const different = payer && !eq(payer, signer.address);
    const pending = { recovery: options.recovery };
    let expired: TxRequest | undefined;
    let pooled = false;
    const prior = await this.reconcileRecord(fresh, archives, { readOnly: Boolean(different), pending },
      different ? undefined : (request, underpriced) => { expired = request; pooled = underpriced; });
    if (prior.state === 'paid' || prior.state === 'needs-archive' || prior.state === 'vanished') return prior;
    if (different) return { state: 'route-blocked', route: 'ordinary', txHash: first?.hash ?? returnId, payer };
    if (prior.state !== 'not-paid') return prior;
    let gasBump = 1n;
    for (let attempt = 0; attempt < 4; attempt++) {
      this.requireRedeemable(fresh);
      const superseded = expired ? fresh.sends.filter((send) => undec(send.nonce) === expired!.nonce).map((send) => unhex(send.hash)) : [];
      const competing = await this.settlementGate(fresh, archives, options.recovery, undefined, superseded);
      if (competing) return competing;
      let rtx: RedeemTx;
      try {
        rtx = await this.buildRedeemInner(fresh, options.envelope);
      } catch (error) {
        // A latest-state estimate can refuse a missing epoch before the finalized preflight runs.
        if (error instanceof Nb2Error && error.rule === 'VerifierRefused') await this.checkOrdinaryImport(fresh);
        throw error;
      }
      const gas = rtx.gasLimit * gasBump > this.opts.pins.userGasLimit ? this.opts.pins.userGasLimit : rtx.gasLimit * gasBump;
      const tx = await this.signed(signer, this.cfg.vault, rtx.calldata, 0n, gas,
        async (request) => {
          if (this.cfg.erc20) {
            const ordinary = fresh.recovery?.ordinary;
            const prior = new Set(fresh.sends.map((send) => undec(send.nonce)));
            if (!ordinary || (!prior.has(request.nonce) && BigInt(prior.size) >= undec(ordinary.attemptsBeforeFallback)) ||
              !quoteErc20Call(request.data.length, request.gas, {
                ...request, maxNonce: request.nonce, gas: undec(ordinary.gas), calldataBytes: ordinary.calldataBytes,
                maxFeePerGas: undec(ordinary.maxFeePerGas), signedBytes: Number(this.opts.pins.maxEncodedTxBytes), balance: 0n, feeBudget: 0n,
              }) || request.maxFeePerGas > undec(ordinary.maxFeePerGas) || !options.admit) {
              fail('CapacityPreflight', 'ordinary attempt exceeds its signing reserve');
            }
            await this.reserveOrdinaryPayer(fresh, signer.address, request, options);
          } else {
            await options.admit?.(structuredClone(request), structuredClone(fresh.sends));
          }
        }, expired && {
          nonce: expired.nonce, pooled, candidates: fresh.sends.filter((send) => undec(send.nonce) === expired!.nonce)
            .map((send) => decodeSignedTx(unhex(send.raw)).request),
        });
      if (this.cfg.erc20) await this.journal.retainPayerSend(fresh, tx.raw);
      // Until the exact call passes preflight it has never been broadcast. Leave
      // the burn rebuildable, including its history and route, on any refusal.
      await this.checkOrdinaryImport(fresh, tx.raw);
      if (expired && await this.evm.nonce(signer.address, 'latest') !== tx.request.nonce) {
        return { state: 'pending', txHash: unhex(fresh.sends.at(-1)!.hash) };
      }
      fresh.executionPayer ??= hex(signer.address);
      fresh.sends.push(this.sendRecord(tx));
      fresh.status = 'submitted';
      fresh.firstSendBlock = fresh.firstSendBlock ?? dec(await this.evm.saneHead());
      await this.journal.putReturn(fresh);
      expired = undefined;
      if (this.cfg.erc20) await this.journal.preparePayerBroadcast(fresh, this.cfg.chainId, tx.raw);
      const r = await this.broadcastAndWait(tx);
      if (r === null) return { state: 'pending', txHash: tx.hash };
      const outcome = await this.reconcileRecord(fresh, archives, { readOnly: true, pending });
      if (outcome.state !== 'not-paid') return outcome;
      // reverted: classify by simulating the same call at the current state
      const re = await this.evm.estimateGas({ from: signer.address, to: this.cfg.vault, data: rtx.calldata });
      const e = 'revert' in re ? decodeRevert(re.revert ?? new Uint8Array()) : null;
      const action = 'gas' in re ? 'retry-later' : classifyRedeemError(e);
      if (action === 'reconcile') return this.reconcileInner(returnId, archives);
      if (action === 'rebuild-history' || action === 'repair-proof') continue;
      if (action === 'retry-later') {
        if (e?.rule === 'VerifierRefused' && e.inner?.rule === 'QuorumNotMet') {
          throw redeemRefusal(e, 'simulation after reverted redeem refused (retry-later)');
        }
        gasBump = 2n; // an out-of-gas or a transient payout failure: one retry with more gas
        continue;
      }
      const detail = `redeem 0x${toHex(tx.hash)} reverted: stop and tell the user`;
      throw e === null ? new Nb2Error('PayoutFailed', detail) : redeemRefusal(e, detail);
    }
    return { state: 'not-paid' };
  }

  private async reserveOrdinaryPayer(record: ReturnRecord, payer: Uint8Array, request: TxRequest, options: RedeemOptions): Promise<void> {
    const plan = record.recovery!;
    const used = new Set<bigint>();
    if (record.sends.length) {
      const finalized = await this.evm.nonce(payer, 'finalized');
      for (const send of record.sends) {
        const tx = decodeSignedTx(unhex(send.raw));
        const { nonce, chainId } = tx.request;
        if (!eq(tx.from, payer) || chainId !== request.chainId || nonce >= finalized || nonce >= request.nonce) continue;
        used.add(nonce);
      }
    }
    const spentCalls = BigInt(used.size);
    const progress = await this.journal.finalizedRecoveryProgress(request.chainId, record,
      (number, hash) => this.evm.isFinalizedBlock(number, hash));
    const completed = progress?.completed ?? 0n;
    await this.checkErc20Payer(record, payer, true, undefined, {
      nonce: request.nonce, maxNonce: options.erc20Policy?.maxNonce, remainingCalls: remainingRecoveryCalls(plan, completed, spentCalls),
      beforeSigning: async (other) => {
        const packet = request.gas * request.maxFeePerGas;
        const fees = await this.journal.payerFees(record, request.chainId, payer, request.nonce);
        if (fees.atNonce > 0n && request.nonce < await this.evm.nonce(payer, 'finalized')) {
          fail('CapacityPreflight', 'ordinary replacement nonce is already finalized');
        }
        let needed = fees.atNonce > packet ? fees.atNonce : packet;
        const authorization = options.erc20Policy;
        if (other.contestedDrain) {
          if (!authorization || typeof authorization.maxFeePerGas !== 'bigint' || authorization.maxFeePerGas <= 0n ||
            authorization.maxFeePerGas < request.maxFeePerGas) {
            fail('CapacityPreflight', 'remaining continuation schedule needs an authorized payer fee ceiling');
          }
          const release = options.erc20Recovery;
          if (!release) fail('CapacityPreflight', 'remaining continuation schedule needs authenticated release calibration');
          await this.verifyErc20RecoveryRelease(release);
          if (plan.generation !== hex(recoveryGeneration(release.deployment.salt, this.domain))) {
            fail('CapacityPreflight', 'remaining continuation belongs to another recovery generation');
          }
          const limits = this.erc20Limits({ ...authorization, balance: 0n });
          if (request.maxPriorityFeePerGas > limits.maxPriorityFeePerGas || !quoteErc20Call(request.data.length, request.gas, {
            ...limits, maxNonce: request.nonce, maxFeePerGas: request.maxFeePerGas, maxPriorityFeePerGas: request.maxPriorityFeePerGas,
          })) fail('CapacityPreflight', 'ordinary call is outside the current payer limits');
          const runs = BigInt(plan.runCuts.length);
          const scheduledAdvances = undec(plan.calls) - remainingOrdinaryAttempts(plan) - 1n - runs;
          if (scheduledAdvances < 0n) fail('CapacityPreflight', 'admitted call count does not cover the recovery schedule');
          const advances = scheduledAdvances - (completed > runs ? completed - runs : 0n);
          const fallback = quoteScheduledRecoveryFee(unhex(record.source), this.cfg.K, {
            cuts: plan.runCuts, completedRuns: Number(completed < runs ? completed : runs),
            batch: plan.advanceGaps, advances: advances > 0n ? advances : 0n,
          }, release.calibration, limits);
          const attempts = remainingOrdinaryAttempts(plan, spentCalls);
          const ordinary = undec(plan.ordinary!.gas) * limits.maxFeePerGas;
          const allowance = attempts > 0n ? ordinary : 0n;
          const remainder = continuationReserve(fallback, ordinary, attempts) - allowance;
          needed = remainder + (needed > allowance ? needed : allowance);
        }
        if (typeof authorization?.feeBudget === 'bigint' && needed + fees.prior > authorization.feeBudget) {
          fail('CapacityPreflight', 'remaining continuation schedule exceeds the authorized payer fee budget');
        }
        if (needed > await this.freeErc20PayerBalance(payer, other)) {
          fail('CapacityPreflight', 'remaining continuation schedule exceeds the free payer balance');
        }
        await options.admit!(structuredClone(request), structuredClone(record.sends), needed);
        await this.journal.preparePayerSigning(record, request.chainId, payer);
      },
    });
  }

  /**
   * Look for Paid(eta) and the receipts of every journaled send; never changes the burn. A Paid log counts only from the vault and only
   * once its receipt is verified under the block's EVM UC (section 6.2 steps 2 to 5): a provider that invents or withholds Paid can
   * delay the wallet, never stop its redemption.
   */
  public reconcile(returnId: Uint8Array, archives: readonly EvmReader[] = [this.evm], evidence?: ReturnEvidence): Promise<ReconcileResult> {
    returnId = Uint8Array.from(returnId);
    return this.locked(`return/${toHex(returnId)}`, () => this.reconcileInner(returnId, archives, evidence));
  }

  /** Check whether the same payer can use an expired ordinary send's free nonce for continuation. */
  public expiredOrdinaryNonce(returnId: Uint8Array, payer: Uint8Array, archives: readonly EvmReader[]): Promise<bigint | undefined> {
    return this.locked(`return/${toHex(returnId)}`, async () => {
      const rec = await this.returnRecord(returnId);
      const last = rec.sends.at(-1);
      if (!last || !eq(decodeSignedTx(unhex(last.raw)).from, payer)) return;
      let nonce: bigint | undefined;
      const result = await this.reconcileRecord(rec, archives, { readOnly: true }, (request) => { nonce = request.nonce; });
      if (result.state === 'not-paid' && nonce !== undefined && await this.evm.nonce(payer) === nonce) return nonce;
    });
  }

  /** A final read-only check before signing a new settlement. */
  public checkSettlement(returnId: Uint8Array, archives: readonly EvmReader[], recovery?: Uint8Array, observed?: Uint8Array, replacing: readonly Uint8Array[] = []): Promise<ReconcileResult> {
    returnId = Uint8Array.from(returnId);
    return this.locked(`return/${toHex(returnId)}`, async () => {
      const rec = await this.returnRecord(returnId);
      if (rec.status === 'paid') return { state: 'paid', txHash: unhex(rec.paid!.txHash), blockNumber: undec(rec.paid!.blockNumber) };
      if (!rec.eta) return { state: 'not-paid' };
      return (await this.settlementGate(rec, archives, recovery, observed, replacing)) ?? { state: 'not-paid' };
    });
  }

  private async settlementGate(rec: ReturnRecord, archives: readonly EvmReader[], recovery?: Uint8Array,
    observed?: Uint8Array, replacing: readonly Uint8Array[] = []): Promise<ReconcileResult | undefined> {
    const pending = await this.pendingSettlements(rec, archives, recovery);
    const settlements = [...pending.values()].filter((hash) => !observed || !eq(hash, observed));
    if (observed) settlements.unshift(observed);
    const proof = await this.findPaid(rec, archives, true, { settlements: [...settlements, ...replacing] });
    if (proof) return proof;
    for (const hash of settlements) {
      if (pending.has(hex(hash)) && !replacing.some((prior) => eq(prior, hash)) && !(await this.exactFailure(hash, archives)).failed) {
        return { state: 'pending', txHash: hash };
      }
    }
  }

  private async pendingSettlements(rec: ReturnRecord, archives: readonly EvmReader[], recovery?: Uint8Array): Promise<Map<string, Uint8Array>> {
    const pending = new Map<string, Uint8Array>();
    const eta = unhex(rec.eta!);
    const failed = new Set(rec.sends.filter((s) => s.failed).map((s) => s.hash));
    for (const reader of archives) {
      let calls;
      try {
        calls = await reader.pendingCalls(this.cfg.vault);
      } catch {
        continue; // Pending-block transactions are optional gateway data.
      }
      for (const { hash, calldata } of calls) {
        if (failed.has(hex(hash))) continue;
        let matches = eq(calldata.subarray(0, 4), SELECTOR.redeem) && eq(calldata.subarray(36, 68), eta);
        if (!matches && recovery) {
          try {
            const claimed = await this.retryingTrust((trust) => recoveredSettlementEta(this.cfg, this.domain, trust, recovery, calldata));
            matches = claimed !== undefined && eq(claimed, eta);
          } catch {
            // A malformed or unverified pending call supplies no evidence.
          }
        }
        if (matches) pending.set(hex(hash), hash);
      }
    }
    return pending;
  }

  private async reconcileInner(returnId: Uint8Array, archives: readonly EvmReader[] = [this.evm], evidence?: ReturnEvidence): Promise<ReconcileResult> {
    return this.reconcileRecord(await this.returnRecord(returnId), archives, evidence);
  }

  private async reconcileRecord(rec: ReturnRecord, archives: readonly EvmReader[], evidence?: ReturnEvidence, onExpired?: (tx: TxRequest, underpriced: boolean) => void): Promise<ReconcileResult> {
    if (rec.status === 'paid') return { state: 'paid', txHash: unhex(rec.paid!.txHash), blockNumber: undec(rec.paid!.blockNumber) };
    if (rec.status === 'burn-requested') {
      const eta = hex(await this.validatePendingReturn(rec));
      return (await this.findPaid({ ...rec, eta }, archives, true, evidence)) ?? { state: 'not-paid' };
    }
    if (rec.eta === undefined) return { state: 'not-paid' };
    const paid = await this.findPaid(rec, archives, true, evidence);
    return paid ?? this.reconcileSend(rec, archives, evidence?.readOnly !== true, onExpired);
  }

  private async findPaid(rec: ReturnRecord, archives: readonly EvmReader[], persist = true, evidence?: ReturnEvidence): Promise<ReconcileResult | undefined> {
    const eta = unhex(rec.eta!);
    if (evidence?.paid?.receipt) {
      const verified = await this.recordPaid(rec, unhex(evidence.paid.txHash), unhex(evidence.paid.receipt), persist);
      if (!verified) refuse('BadInput', 'portable payment does not prove Paid for the signed redemption');
      return verified;
    }
    let available = false;
    let unavailable: unknown;
    const candidates = new Map<string, Uint8Array>();
    // pruned: a reader answered in this call that it no longer holds part of the proof (missing names it)
    // block: the latest block the claim was seen in (receipt or log); gone: a peer claim no reader holds on its canonical chain any more
    const hinted = new Map<string, { tx: Uint8Array; pruned: boolean; missing?: string; block?: bigint; gone?: boolean }>();
    const addHint = (tx: Uint8Array, pruned = false, missing?: string, block?: bigint) => {
      const key = hex(tx);
      const prior = hinted.get(key);
      const seen = prior?.block === undefined || (block !== undefined && block > prior.block) ? block : prior.block;
      hinted.set(key, { tx, pruned: pruned || prior?.pruned === true, missing: prior?.missing ?? missing, block: seen ?? prior?.block });
    };
    if (rec.paidProof) {
      const tx = unhex(rec.paidProof.txHash);
      candidates.set(rec.paidProof.txHash, tx);
      addHint(tx, false, undefined, rec.paidProof.block === undefined ? undefined : undec(rec.paidProof.block));
    }
    for (const tx of evidence?.settlements ?? []) candidates.set(hex(tx), tx);
    for (const send of rec.sends) {
      const { hash } = decodeSignedTx(unhex(send.raw));
      candidates.set(hex(hash), hash);
    }
    const searched = new Set<string>();
    const verify = async () => {
      for (const [hash, tx] of candidates) {
        if (searched.has(hash)) continue;
        searched.add(hash);
        for (const reader of archives) {
          const result = await this.verifiedPaid(rec, tx, reader, persist, archives);
          if (result?.state === 'paid') return result;
          if (result?.state === 'pending') addHint(tx);
          if (result?.state === 'needs-archive') addHint(tx, true, result.missing);
        }
      }
    };
    const localPaid = await verify();
    if (localPaid) return localPaid;

    for (const reader of archives) {
      try {
        const logs = await reader.paid(this.cfg.vault, eta, undec(rec.fromBlock));
        for (const l of logs) {
          const p = decodePaid(l);
          if (p === null || !eq(l.address, this.cfg.vault) || !eq(p.eta, eta) ||
            !eq(p.recipient, unhex(rec.recipient)) || p.amount !== undec(rec.amount) || l.blockNumber < undec(rec.fromBlock)) continue;
          addHint(l.transactionHash, false, undefined, l.blockNumber);
          candidates.set(hex(l.transactionHash), l.transactionHash);
        }
        available = true;
      } catch (e) {
        unavailable = e;
      }
    }
    const discoveredPaid = await verify();
    if (discoveredPaid) return discoveredPaid;

    if (hinted.size && evidence?.pending) {
      for (const [hash, tx] of await this.pendingSettlements(rec, archives, evidence.pending.recovery)) candidates.set(hash, tx);
      const pendingPaid = await verify();
      if (pendingPaid) return pendingPaid;
    }

    // Indexed or remembered claims trigger proof reads. A certified failure retires only that exact claim.
    let changed = false;
    const heads = new Map<EvmReader, bigint>();
    let peerSeen = false;
    // The lowest head any reader reports: peerClaimSince only ever moves down to it, so one spurious high head cannot push the horizon away
    const lowestHead = async () => {
      let low: bigint | undefined;
      for (const reader of archives) {
        let h = heads.get(reader);
        if (h === undefined) heads.set(reader, h = await reader.saneHead());
        if (low === undefined || h < low) low = h;
      }
      return low!;
    };
    if (rec.peerClaimSince !== undefined && hinted.size) {
      const low = await lowestHead();
      if (low < undec(rec.peerClaimSince)) {
        rec.peerClaimSince = dec(low);
        changed = true;
      }
    }
    const own = new Map((evidence?.own ?? []).map((raw) => { const signed = decodeSignedTx(raw); return [hex(signed.hash), signed] as const; }));
    for (const [hash, hint] of hinted) {
      const { tx } = hint;
      const send = rec.sends.find((s) => hex(decodeSignedTx(unhex(s.raw)).hash) === hash);
      const outcome = send?.failed ? undefined : await this.exactFailure(tx, archives);
      const failure = send?.failed ?? outcome?.failed;
      if (!failure) {
        for (const at of outcome?.at ?? []) if (hint.block === undefined || at.number > hint.block) hint.block = at.number;
        const mine = send ? decodeSignedTx(unhex(send.raw)) : own.get(hash);
        if (!mine && outcome) {
          peerSeen = true;
          // Another party's claim that no reader holds on its canonical chain VANISHED_CLAIM_HORIZON blocks after this return first saw
          // such a claim is dropped: a provider that invents Paid can delay the redemption, never stop it. The vault's AlreadyPaid refuses
          // a second payout of eta, so if the claim was real after all, this wallet's own payout is refused, never paid twice.
          if (await this.peerClaimExpired(outcome.at, optional(rec.peerClaimSince), archives, heads)) {
            if (rec.paidProof?.txHash === hash) delete rec.paidProof;
            changed = true;
            hinted.delete(hash);
            continue;
          }
        }
        if (!outcome || !await this.claimGone(outcome.at, hint.block ?? (mine ? optional(rec.firstSendBlock) : undefined), archives, heads)) continue;
        if (!mine) {
          hint.gone = true; // another party's payment: report it, sign nothing
          continue;
        }
        // this wallet's own send or packet is gone from the chain: forget the observation; reconcileSend (or the continuation route's
        // pending packet) offers the identical bytes again
        const signed = mine;
        if (await this.evm.nonce(signed.from, 'latest') > signed.request.nonce) continue; // its nonce is used: not gone, wait
        if (rec.paidProof?.txHash === hash) delete rec.paidProof;
        changed = true;
        hinted.delete(hash);
        continue;
      }
      if (send && !send.failed) {
        if (send.hash !== hash) refuse('BadInput', 'ordinary send hash does not match its signed transaction');
        send.failed = failure;
        delete send.failureProofReads;
        changed = true;
      }
      if (rec.paidProof?.txHash === hash) {
        delete rec.paidProof;
        changed = true;
      }
      hinted.delete(hash);
    }
    // The horizon runs from the first unproven peer claim this return saw (any hash: a provider rotating invented claims gains nothing)
    // (kept once set, never raised: a later claim no reader holds canonically gets no fresh delay; a real one is canonical and is never
    // dropped; a lower head reported later lowers it, so a lying high head delays at most until an honest reader is consulted)
    if (peerSeen && rec.peerClaimSince === undefined) {
      rec.peerClaimSince = dec(await lowestHead());
      changed = true;
    }
    const live = [...hinted.values()].filter(({ gone }) => !gone);
    const next = live.find(({ pruned }) => pruned) ?? live[0] ?? [...hinted.values()][0];
    if (next) {
      const txHash = hex(next.tx);
      // A marker of the claim under proof (a resend waits for it), not a budget: only this read's pruned answer means needs-archive.
      const reads = Math.min(FAILURE_PROOF_READS, (rec.paidProof?.txHash === txHash ? rec.paidProof.reads : 0) + 1);
      const block = next.block === undefined ? undefined : dec(next.block);
      if (rec.paidProof?.txHash !== txHash || rec.paidProof.reads !== reads || rec.paidProof.block !== block) {
        rec.paidProof = { txHash, reads, ...(block === undefined ? {} : { block }) };
        changed = true;
      }
      if (changed && persist) await this.journal.putReturn(rec);
      if (next.gone) return { state: 'vanished', txHash: next.tx };
      return next.pruned ? { state: 'needs-archive', txHash: next.tx, missing: next.missing } : { state: 'pending', txHash: next.tx };
    }
    if (changed && persist) await this.journal.putReturn(rec);
    if (!available && unavailable) throw unavailable;
  }

  /** Before signing again, reconcile the exact send. A finalized stale call may only be replaced at its unused nonce. */
  private async reconcileSend(rec: ReturnRecord, archives: readonly EvmReader[], resubmit: boolean, onExpired?: (tx: TxRequest, underpriced: boolean) => void): Promise<ReconcileResult> {
    const send = rec.sends.at(-1);
    if (!send) return { state: 'not-paid' };
    const raw = unhex(send.raw);
    const { hash: txHash, from, request } = decodeSignedTx(raw);
    if (hex(txHash) !== send.hash || request.nonce !== undec(send.nonce)) refuse('BadInput', 'ordinary send hash does not match its signed transaction');
    // A certified failure of any replacement at this nonce rules out all the others.
    const sameNonce = rec.sends.filter((prior) => prior.nonce === send.nonce).reverse();
    let evidence: { seen: boolean; pruned: boolean; attempted: boolean; missing?: string; at: SeenReceipt[] } | undefined;
    for (const prior of sameNonce) {
      const signed = decodeSignedTx(unhex(prior.raw));
      if (!eq(signed.from, from) || signed.request.nonce !== request.nonce || hex(signed.hash) !== prior.hash) {
        refuse('BadInput', 'ordinary replacement disagrees with its signed transaction');
      }
      if (prior.failed) {
        if (prior.failed.txHash !== prior.hash || unhex(prior.failed.blockHash).length !== 32) refuse('BadInput', 'certified failure disagrees with its signed transaction');
        return { state: 'not-paid' };
      }
      const outcome = await this.exactFailure(signed.hash, archives);
      if (outcome.failed) {
        prior.failed = outcome.failed;
        delete send.failureProofReads;
        await this.journal.putReturn(rec);
        return { state: 'not-paid' };
      }
      evidence = {
        seen: Boolean(evidence?.seen || outcome.seen),
        pruned: Boolean(evidence?.pruned || outcome.pruned),
        attempted: Boolean(evidence?.attempted || outcome.attempted),
        missing: evidence?.missing ?? outcome.missing,
        at: [...(evidence?.at ?? []), ...outcome.at],
      };
    }
    let { seen, pruned, attempted } = evidence!;
    const { missing, at } = evidence!;
    // A receipt seen before and gone from the chain (rolled back, or only in a block that is not canonical; its nonce unused): the send
    // is alive again, and the same bytes are offered again
    if (seen || send.failureProofReads !== undefined) {
      const ref = send.failureBlock !== undefined ? undec(send.failureBlock) : optional(rec.firstSendBlock);
      if (await this.claimGone(at, ref, archives, new Map()) && await this.evm.nonce(from, 'latest') <= request.nonce) {
        if (send.failureProofReads !== undefined || send.failureBlock !== undefined) {
          delete send.failureProofReads;
          delete send.failureBlock;
          await this.journal.putReturn(rec);
        }
        seen = pruned = attempted = false;
      }
    }
    const failedAt = at.reduce<bigint | undefined>((m, r) => (m === undefined || r.number > m ? r.number : m), undefined);
    if (attempted || send.failureProofReads !== undefined) {
      // A marker that a failed receipt was seen (no blind resend), not a budget: a failure not certified yet stays pending.
      const reads = Math.min((send.failureProofReads ?? 0) + 1, FAILURE_PROOF_READS);
      const block = attempted && failedAt !== undefined ? dec(failedAt) : send.failureBlock;
      if (reads !== send.failureProofReads || block !== send.failureBlock) {
        send.failureProofReads = reads;
        if (block !== undefined) send.failureBlock = block;
        await this.journal.putReturn(rec);
      }
    }
    if (pruned) return { state: 'needs-archive', txHash, missing };
    if (!seen && (resubmit || onExpired) && send.failureProofReads === undefined) {
      try { await this.checkOrdinaryImport(rec, raw); }
      catch (error) {
        if (!(error instanceof Nb2Error) || error.rule !== 'StaleEndpoint') throw error;
        if (onExpired && await this.evm.nonce(from, 'latest') === request.nonce) {
          onExpired(request, false);
          return { state: 'not-paid' };
        }
        return { state: 'pending', txHash };
      }
      if (resubmit) {
        if (this.cfg.erc20) await this.journal.preparePayerBroadcast(rec, this.cfg.chainId, raw);
        try { await this.evm.sendRaw(raw); }
        catch (error) {
          if (onExpired && error instanceof RpcError && /replacement transaction underpriced/i.test(error.message) &&
              await this.evm.nonce(from, 'latest') === request.nonce) {
            onExpired(request, true);
            return { state: 'not-paid' };
          }
          if (!(error instanceof AmbiguousBroadcast)) throw error;
        }
      }
    }
    return { state: 'pending', txHash };
  }

  private async checkOrdinaryImport(rec: ReturnRecord, raw?: Uint8Array): Promise<void> {
    const part = decodeToken(unhex(rec.burned!));
    const tx = raw && decodeSignedTx(raw);
    await this.retryingTrust(async (trust) => {
      await verifyPart(this.cfg, this.domain, trust, part);
      const lineage = lineageOf(part);
      const receipt = decodeReceiptBacking(lineage[0].mint.justification!).proof.uc;
      let epoch = decodeUc(receipt).unicitySeal.epoch;
      for (const level of lineage) {
        for (const proof of [level.mintProof, ...level.proofs]) {
          const signer = decodeUc(proof.uc).unicitySeal.epoch;
          if (signer > epoch) epoch = signer;
        }
      }
      await this.evm.checkReturnImport(this.cfg, epoch, tx && { ...tx.request, from: tx.from });
    });
  }

  private async exactFailure(txHash: Uint8Array, archives: readonly EvmReader[]) {
    let seen = false;
    let attempted = false;
    let pruned = false;
    let missing: string | undefined;
    const at: SeenReceipt[] = [];
    for (const reader of archives) {
      try {
        const receipt = await reader.receipt(txHash);
        if (!receipt) continue;
        seen = true;
        at.push({ reader, number: BigInt(receipt.blockNumber), hash: unhex(receipt.blockHash) });
        if (BigInt(receipt.status) !== 0n) continue;
        attempted = true;
        await this.retryingTrust((trust) => reader.verifyFailedReceipt(txHash, this.cfg, trust, receipt, archives));
        return { seen, attempted, pruned, missing, at, failed: { txHash: hex(txHash), blockHash: hex(unhex(receipt.blockHash)) } };
      } catch (e) {
        if (e instanceof WalletError && e.reason === 'TrustInput') throw e;
        if (e instanceof RpcError && e.retryable) throw e; // a transport failure is not an absence of evidence
        if (e instanceof ProofUnavailable && e.pruned || e instanceof Nb2Error && e.rule === 'EvidencePruned') {
          pruned = true;
          missing ??= missingOf(e);
        }
      }
    }
    return { seen, attempted, pruned, missing, at, failed: undefined };
  }

  /**
   * Whether another party's unproven claim has outlived the horizon: every reader's own head is VANISHED_CLAIM_HORIZON past `since` (when
   * this return first saw an unproven peer claim) and no reader serves its receipt in a block that is canonical on that reader. Block
   * numbers a provider attaches to the claim are not trusted here: an invented claim may name any block.
   */
  private async peerClaimExpired(at: readonly SeenReceipt[], since: bigint | undefined, archives: readonly EvmReader[], heads: Map<EvmReader, bigint>): Promise<boolean> {
    if (since === undefined) return false;
    for (const reader of archives) {
      let h = heads.get(reader);
      if (h === undefined) heads.set(reader, h = await reader.saneHead());
      if (h < since + VANISHED_CLAIM_HORIZON) return false;
    }
    for (const { reader, number, hash } of at) {
      const canonical = await reader.headerByNumber(number);
      if (canonical && eq(canonical.hash, hash)) return false;
    }
    return true;
  }

  /**
   * Whether a claim seen before is gone from the chain, by each reader's own head: every receipt still served is in a block that is not
   * canonical on that reader, and every reader's head is CERTIFICATION_DEPTH past it (`ref`, the block it was seen in, when no reader
   * serves a receipt any more). Near the head nothing is gone: a block not certified yet may still be replaced by its repeat.
   */
  private async claimGone(at: readonly SeenReceipt[], ref: bigint | undefined, archives: readonly EvmReader[], heads: Map<EvmReader, bigint>): Promise<boolean> {
    const head = async (reader: EvmReader) => {
      let h = heads.get(reader);
      if (h === undefined) heads.set(reader, h = await reader.saneHead());
      return h;
    };
    const seenAt = at.reduce<bigint | undefined>((m, r) => (m === undefined || r.number > m ? r.number : m), ref);
    if (seenAt === undefined) return false;
    for (const reader of archives) if (await head(reader) < seenAt + CERTIFICATION_DEPTH) return false;
    for (const { reader, number, hash } of at) {
      if (await head(reader) < number + CERTIFICATION_DEPTH) return false;
      const canonical = await reader.headerByNumber(number);
      if (!canonical || eq(canonical.hash, hash)) return false;
    }
    return true;
  }

  /**
   * Verify that transaction `tx` paid this return: its Paid log, from the vault, with topics [Paid, eta, recipient] and data the amount,
   * in a receipt verified under the block's certificate. Journals `paid` and returns it; 'pending' while the block is not certified yet;
   * null when the claim does not verify (it is ignored).
   */
  private async verifiedPaid(rec: ReturnRecord, tx: Uint8Array, reader = this.evm, persist = true, archives: readonly EvmReader[] = []): Promise<ReconcileResult | null> {
    const eta = unhex(rec.eta!);
    let receipt: Uint8Array;
    try {
      const recipientWord = concat(new Uint8Array(12), unhex(rec.recipient));
      const rp = await reader.receiptProof(tx, this.cfg.vault, TOPIC.Paid, false, {
        topics: [TOPIC.Paid, eta, recipientWord], data: u256(undec(rec.amount)),
      }, archives, (raw, encoded) => this.retryingTrust(async (trust) => {
        const uc = await verifyEvmUc(trust, encoded, this.cfg);
        bindHeader(raw, uc.inputRecord.blockHash, uc.inputRecord.nullableHash);
      }));
      receipt = rp.encoded;
    } catch (e) {
      if (e instanceof WalletError && e.reason === 'TrustInput') throw e;
      if (e instanceof RpcError && e.retryable) throw e;
      // not certified yet (no child, companion unknown) is pending; only a node's pruned answer is needs-archive
      if (e instanceof ProofUnavailable) return e.pruned ? { state: 'needs-archive', txHash: tx, missing: missingOf(e) } : { state: 'pending', txHash: tx };
      if (e instanceof WalletError && e.reason === 'CompanionUnknown') return { state: 'pending', txHash: tx };
      if (e instanceof Nb2Error && e.rule === 'EvidencePruned') return { state: 'needs-archive', txHash: tx, missing: missingOf(e) };
      return null; // unavailable from this reader, with no authenticated effect
    }
    try {
      return await this.recordPaid(rec, tx, receipt, persist);
    } catch (e) {
      // A lost compare-and-swap of the journal is never read as an unverified claim
      if (e instanceof WalletError && (e.reason === 'JournalConflict' || e.reason === 'JournalNotPersisted' || e.reason === 'TrustInput')) throw e;
      if (e instanceof Nb2Error || e instanceof WalletError) return null;
      throw e;
    }
  }

  private async recordPaid(rec: ReturnRecord, tx: Uint8Array, receipt: Uint8Array, persist: boolean): Promise<ReconcileResult | null> {
    if (tx.length !== 32) refuse('BadInput', 'payment transaction hint is not a hash');
    const proof = decodeDepositProof(receipt);
    const log = await this.retryingTrust((trust) => verifyReceiptLog(this.cfg, trust, proof));
    const recipient = concat(new Uint8Array(12), unhex(rec.recipient));
    if (log.topics.length !== 3 || !eq(log.topics[0], TOPIC.Paid) || !eq(log.topics[1], unhex(rec.eta!)) ||
      !eq(log.topics[2], recipient) || log.data.length !== 32 || beInt(log.data) !== undec(rec.amount) ||
      log.header.number < undec(rec.fromBlock)) return null;
    rec.paid = { txHash: hex(tx), blockNumber: dec(log.header.number), blockHash: hex(HE(proof.header)),
      receipt: hex(receipt), txIndex: dec(proof.txIndex), logIndex: dec(proof.logIndex) };
    rec.status = 'paid';
    delete rec.paidProof;
    if (persist) await this.journal.putReturn(rec);
    return { state: 'paid', txHash: tx, blockNumber: log.header.number };
  }

  // ==== status ==========================================================================================================

  /** Where every journaled deposit and return stands, in words. */
  public async status(): Promise<string[]> {
    const out: string[] = [];
    const say: Record<string, string> = {
      planned: 'planned: the secret is journaled; send the deposit', submitted: 'sent: waiting for the receipt (submitDeposit again reconciles)',
      deposited: 'deposited: waiting for the block certificate (collectDepositProof)', proven: 'proven: J is journaled; mint', minted: 'minted',
    };
    for (const d of await this.journal.deposits()) out.push(`deposit intent ${d.intent} of ${d.amount}: ${say[d.status]}`);
    const rsay: Record<string, string> = {
      planned: 'planned: preflight passed; burn', 'burn-requested': 'burn requested: call burn again to finish certification',
      burned: 'burned: build and submit the redeem', submitted: 'redeem sent: reconcile', paid: 'paid',
    };
    for (const r of await this.journal.returns()) out.push(`return ${r.returnId.slice(0, 18)} of ${r.amount} to ${r.recipient} (a = ${r.a}): ${rsay[r.status]}`);
    return out;
  }

  // ==== EVM plumbing ====================================================================================================

  private async signed(signer: EvmSigner, to: Uint8Array, data: Uint8Array, value: bigint, gas: bigint, admit?: (request: TxRequest) => Promise<void>, replace?: { nonce: bigint; pooled: boolean; candidates: TxRequest[] }): Promise<SignedTx> {
    const [nonce, fees] = await Promise.all([this.evm.nonce(signer.address), this.evm.fees()]);
    const request = { chainId: this.cfg.chainId, nonce, maxPriorityFeePerGas: fees.priority, maxFeePerGas: 2n * fees.baseFee + fees.priority,
      gas, to: Uint8Array.from(to), value, data: Uint8Array.from(data) };
    if (replace) {
      if (await this.evm.nonce(signer.address, 'latest') !== replace.nonce) refuse('NotPending', 'payout nonce changed during replacement');
      request.nonce = replace.nonce;
      if (replace.pooled || nonce > replace.nonce) {
        for (const prior of replace.candidates) {
          const fee = replacementBid(prior.maxFeePerGas);
          const priority = replacementBid(prior.maxPriorityFeePerGas);
          if (fee > request.maxFeePerGas) request.maxFeePerGas = fee;
          if (priority > request.maxPriorityFeePerGas) request.maxPriorityFeePerGas = priority;
        }
      }
    }
    await admit?.(request);
    return signTx(signer, request);
  }

  private sendRecord(tx: SignedTx): SendRecord {
    return { hash: hex(tx.hash), raw: hex(tx.raw), nonce: dec(tx.request.nonce), gas: dec(tx.request.gas), at: dec(this.now()) };
  }

  /** Broadcast and poll the receipt of the locally computed hash; null when none arrived in time (the send stays journaled). */
  private async broadcastAndWait(tx: SignedTx): Promise<ReceiptJson | null> {
    try {
      await this.evm.sendRaw(tx.raw);
    } catch (e) {
      if (!(e instanceof AmbiguousBroadcast)) throw e;
    }
    const deadline = this.now() + (this.opts.receiptTimeoutMs ?? 60_000);
    for (;;) {
      const r = await this.evm.receipt(tx.hash);
      if (r !== null) return r;
      if (this.now() >= deadline) return null;
      await this.sleep(this.opts.pollMs ?? 1_000);
    }
  }

  /**
   * The outcome of a record's earlier sends: a success receipt (the answer), 'pending', or null (none is alive: a new send is safe).
   * The order defends against a send mined between reads and against load-balanced backends at different heights: the account's MINED
   * nonce is read first, then every send's receipt; a success receipt is the answer whenever it is seen. A send whose nonce is used
   * without a success receipt is dead only after the head has advanced `deadAfterBlocks` since that was first seen (journaled in
   * `nonceUsedAt`), the block at `nonceUsedAt` has a certificate (a found companion), and every receipt is read again; until then it
   * is pending. A send still in a pool is broadcast again (same bytes).
   */
  private async landedSend(sends: SendRecord[], save: () => Promise<void>): Promise<ReceiptJson | 'pending' | null> {
    if (sends.length === 0) return null;
    const last = sends[sends.length - 1];
    const from = decodeSignedTx(unhex(last.raw)).from;
    const mined = await this.evm.nonce(from, 'latest');
    for (const s of sends) {
      const r = await this.evm.receipt(unhex(s.hash));
      if (r !== null && BigInt(r.status) === 1n) return r;
    }
    if (mined <= undec(last.nonce)) {
      // the nonce is unused by any mined transaction: the send is alive, in a pool or lost; offer the same bytes again
      try {
        await this.evm.sendRaw(unhex(last.raw));
      } catch (e) {
        if (!(e instanceof AmbiguousBroadcast)) throw e;
      }
      return 'pending';
    }
    // a mined transaction used the nonce, and no success receipt is visible: wait for depth before calling it dead
    const head = await this.evm.saneHead();
    if (last.nonceUsedAt === undefined) {
      last.nonceUsedAt = dec(head);
      await save();
      return 'pending';
    }
    if (head < undec(last.nonceUsedAt) + (this.opts.deadAfterBlocks ?? 6n)) return 'pending';
    // and the block at which the nonce was seen used is certified (a found companion, section 12.7): depth alone is not finality
    const at = await this.evm.headerByNumber(undec(last.nonceUsedAt));
    if (at === null) return 'pending';
    try {
      await this.evm.certificateOf(at.header, at.hash);
    } catch (e) {
      if (e instanceof WalletError || e instanceof Nb2Error) return 'pending';
      throw e;
    }
    for (const s of sends) {
      const r = await this.evm.receipt(unhex(s.hash));
      if (r !== null && BigInt(r.status) === 1n) return r;
    }
    return null;
  }
}

export { lineageOf };

/**
 * An upper bound of the encoded [burn transfer, inclusion proof] pair with return data of `rLen` bytes: the transfer, the
 * certification data, the reference time, an RSMT path of at most 256 siblings and an aggregator UC at its decoder bound.
 */
export const burnPairBound = (rLen: number): number => {
  const transfer = 3 + 1 + 45 + 34 + 3 + rLen + 9;
  const cd = 3 + 1 + 45 + 34 + 34 + 9 + 67;
  return 4 + 1 + transfer + 3 + 1 + cd + 9 + 3 + 32 + 32 * 256 + (24 << 10);
};

/** Everything of the redeem transaction besides the evidence and the gap proofs: ABI heads and padding, the start head, the envelope. */
export const otherBytes = (evidence: number): number => {
  const calldata = redeemCalldataLength(evidence, 32) + 31; // the start head, and the history's padding at most 31 bytes
  return calldata - evidence + redeemTxFraming(calldata);
};

export { encodeToken, log2, gapProofLen, decodeDepositProof };
