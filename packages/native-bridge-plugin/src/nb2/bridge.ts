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
import { classifyRedeemError, decodeDeposited, decodePaid, decodeRevert, depositCalldata, redeemCalldata, redeemCalldataLength, SELECTOR, type DecodedError, type RedeemAction } from './abi.js';
import { ascii, beInt, cArr, cBytes, u256 } from './cbor.js';
import { ASSET_UCT, buildParams, decodeConfig, domainOf, log2, type Build, type Config } from './config.js';
import { HE, HU, parseKey, verifyUnlock } from './crypto.js';
import {
  TOPIC, decodeDepositProof, decodeReceiptBacking, depositIntentSecret, depositSalt, encodeReceiptBacking, firstOwnerOf, rhoOf, verifyDepositEvidence, verifyReceiptLog,
} from './deposit.js';
import { Nb2Error, WalletError, fail, refuse } from './errors.js';
import { decodeSignedTx, replacementBid, signTx, type EvmSigner, type SignedTx, type TxRequest } from './evm.js';
import { bindHeader } from './header.js';
import { MeasuredGasModel, createAddress, redeemTxFraming, type GasModel, type RedeemShape } from './gas.js';
import {
  Journal, dec, hex, undec, unhex, type DepositRecord, type IntentsRecord, type JournalStore, type ReturnRecord, type SendRecord, type SplitRecord,
} from './journal.js';
import { recoveredSettlementEta } from './recovery.js';
import { burnIndex, capacityExceeded, capacityPreflight, maxProofs, checkStateRead, verifySealReceipt, type SealReceipt } from './rules.js';
import { AmbiguousBroadcast, EvmReader, ProofUnavailable, RpcError, type JsonRpc, type ReceiptJson } from './rpc.js';
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
  recover?(record: ReturnRecord): Promise<NonNullable<ReturnRecord['recovery']>>;
  beforeCertification?(record: ReturnRecord): Promise<void>;
}

export interface RedeemOptions {
  recovery?: Uint8Array;
  envelope?: ReturnAdmission['ordinaryEnvelope'];
  archives?: readonly EvmReader[];
  admit?: (request: TxRequest, prior: readonly SendRecord[]) => Promise<void>;
}

export interface RedeemTx { returnId: Uint8Array; calldata: Uint8Array; gasLimit: bigint; P: bigint; endpoint: bigint; history: Uint8Array; eta: Uint8Array; claimedStart: bigint }

export type ReconcileResult =
  | { state: 'paid'; txHash: Uint8Array; blockNumber: bigint }
  | { state: 'pending'; txHash: Uint8Array }
  | { state: 'needs-archive'; txHash: Uint8Array }
  | { state: 'route-blocked'; txHash: Uint8Array; route: 'ordinary' | 'recovery'; payer?: Uint8Array }
  | { state: 'not-paid'; lastFailure?: { txHash: Uint8Array; action: RedeemAction; error: DecodedError | null } };

export interface ReturnEvidence {
  /** Exact signed settlement hashes held locally. */
  settlements?: readonly Uint8Array[];
  /** Also check matching pending-block calls before reporting a provisional payment hint. */
  pending?: { recovery?: Uint8Array };
  /** A certified vault receipt. Its transaction hash is a lookup hint. */
  paid?: ReturnRecord['paid'];
  readOnly?: boolean;
}

export const FAILURE_PROOF_READS = 3;

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
    if (!opts.unsafeTestTrust && toHex(this.cfg.semanticProfileHash) !== IMPORTED_TIP_PROFILE_HASH) {
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
    if (check) {
      if ((await b.evm.chainId()) !== b.cfg.chainId) refuse('BadDeployment', 'the RPC serves another chain');
      if (!eq(await b.evm.vaultConfig(b.cfg.vault), opts.pins.gamma)) refuse('BadDeployment', 'the vault\'s config() is not the pinned Γ');
      if (!eq(HE(await b.evm.code(b.cfg.vault)), opts.pins.vaultRuntimeCodeHash)) refuse('BadDeployment', 'the vault runtime code hash is not the pinned one');
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
  public planDeposit(amount: bigint, ownerKey: Uint8Array): Promise<DepositPlan> {
    if (amount <= 0n) refuse('BadInput', 'a deposit amount is positive');
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
        firstOwner: hex(firstOwner), rho: hex(rho), status: 'planned', backedUp: false, sends: [], plannedBlock: dec(await this.evm.blockNumber()),
      };
      await this.journal.putDeposit(rec);
      if (this.opts.backup) {
        await this.opts.backup(intents);
        rec.backedUp = true;
        await this.journal.putDeposit(rec);
      }
      return { intent: i, amount, rho, firstOwner, calldata: depositCalldata(firstOwner, rho), record: rec };
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

  /** Every Deposited event of the vault carrying `rho`, from block `from`, in chain order. */
  private async depositsWithRho(rho: Uint8Array, from: bigint): Promise<{ l: RawLog; n: bigint; amount: bigint; firstOwner: Uint8Array }[]> {
    const out: { l: RawLog; n: bigint; amount: bigint; firstOwner: Uint8Array }[] = [];
    for (const l of await this.evm.logs(this.cfg.vault, [hexq(TOPIC.Deposited)], from, await this.evm.blockNumber())) {
      const d = decodeDeposited(l);
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
    return this.locked(`deposit/${i}`, async () => {
      const rec = await this.journal.depositForUpdate(i);
      if (rec === null) refuse('JournalNotPersisted', `intent ${i} is not in the journal: plan it first`);
      if (typeof plan !== 'bigint' && (rec!.rho !== hex(plan.rho) || rec!.amount !== dec(plan.amount))) refuse('JournalNotPersisted', 'the journal entry is not this plan');
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
      const value = undec(rec!.amount);
      const data = depositCalldata(unhex(rec!.firstOwner), unhex(rec!.rho));
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
  }

  private async recordDeposit(rec: DepositRecord, r: ReceiptJson): Promise<{ txHash: Uint8Array; depositNumber: bigint; blockNumber: bigint }> {
    const l = r.logs.find((x) => eq(unhex(x.address.toLowerCase()), this.cfg.vault) && x.topics.length === 2 && x.topics[0].toLowerCase() === hex(TOPIC.Deposited));
    if (l === undefined) refuse('ProviderFault', 'the deposit receipt has no Deposited log');
    const d = decodeDeposited({ address: this.cfg.vault, topics: l!.topics.map((x) => unhex(x.toLowerCase())), data: unhex(l!.data.toLowerCase()), blockNumber: 0n, blockHash: new Uint8Array(32), transactionHash: new Uint8Array(32), logIndex: 0n });
    if (d === null || !eq(d.rho, unhex(rec.rho))) refuse('ProviderFault', 'the Deposited log is not this intent\'s');
    // the event's D is this deployment's: the same rho under another vault configuration at this address is not this deposit
    if (!eq(d!.domain, this.domain)) refuse('ProviderFault', 'the Deposited log carries another deployment\'s domain D');
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
      const first = seen[0];
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
    const rp = await this.evm.mintReceiptProof(tx, this.cfg.vault, toHex(this.cfg.semanticProfileHash) === IMPORTED_TIP_PROFILE_HASH);
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
    for (const l of await this.evm.logs(this.cfg.vault, [hexq(TOPIC.Deposited)], this.opts.pins.deploymentBlock, await this.evm.blockNumber())) {
      const d = decodeDeposited(l);
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
    if (toHex(this.cfg.semanticProfileHash) !== IMPORTED_TIP_PROFILE_HASH) return this.verifyToken(token);
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
    const bound = bytes + burnPairBound(encodeReturnData({ d: this.domain, asset: ASSET_UCT,
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
          const age = (await this.evm.blockNumber()) - sr.receipt.blockNumber;
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
      const helperCode = await this.evm.code(createAddress(this.cfg.verifier, 1n));
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
  private async preflight(token: Uint8Array, amount: bigint, recipient: Uint8Array, a: bigint, payer: Uint8Array, admission?: ReturnAdmission): Promise<{ cObs: bigint; pNow: bigint; need: bigint; pMax: bigint; gas: bigint }> {
    const envelope = admission?.ordinaryEnvelope;
    if (!envelope?.gasFor && !(await this.gasApplies())) {
      fail('CapacityPreflight', `the gas model ${this.gas.name} is not calibrated for this deployment (its verifier, helper and vault code, its native gas schedule): supply a GasModel for it`);
    }
    const st = await this.evm.vaultState(this.cfg.vault);
    const cObs = st.segment > a ? st.segment : a;
    const R = encodeReturnData({ d: this.domain, asset: ASSET_UCT, recipient, amount, minIndex: a });
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
    if (admission?.checkOrdinary) return { cObs, ...pf };
    // the payer must fund the worst-case gas limit at the current fee level (twice the base fee plus the priority fee)
    const fees = await this.evm.fees();
    const cost = pf.gas * (2n * fees.baseFee + fees.priority);
    const bal = await this.evm.balance(payer);
    if (bal < cost) refuse('InsufficientFunds', `the payer holds ${bal} wei, the worst-case gas limit ${pf.gas} needs ${cost}`);
    return { cObs, ...pf };
  }

  private async admitReturn(record: ReturnRecord, amount: bigint, admission?: ReturnAdmission) {
    delete record.recovery;
    const a = undec(record.a);
    try {
      const source = unhex(record.source);
      const ordinary = await this.preflight(source, amount, unhex(record.recipient), a, unhex(record.payer ?? record.recipient), admission);
      await admission?.checkOrdinary?.(structuredClone(record), ordinary.gas);
      return ordinary;
    } catch (e) {
      if (!admission?.recover || !((e instanceof Nb2Error && e.rule === 'CapacityPreflight') ||
        (e instanceof WalletError && e.reason === 'InsufficientFunds'))) throw e;
      record.recovery = await admission.recover(structuredClone(record));
      const observed = undec(record.recovery.observed);
      return { cObs: observed, pNow: observed > a ? observed - a : 0n, need: 0n, pMax: 0n, gas: 0n };
    }
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
    const expected = encodeReturnData({ d: this.domain, asset: ASSET_UCT, recipient: receiver, amount: held.amount, minIndex: a });
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
        if (payout.state === 'needs-archive') this.requireReturnArchive(payout.txHash);
        return payment;
      }
      if (action === 'certify') {
        await this.certifyReturn(selected);
        // The signed request is already durable. Keep its verified result if future qualification fails.
        await this.journal.putReturn(selected);
      }
      if (beforeCommit && selected.sends.length) {
        const exact = await this.reconcileSend(selected, archives, false);
        if (exact.state === 'needs-archive') this.requireReturnArchive(exact.txHash);
      }
      if (selected.status === 'paid') return selected;
      const localPlan = await beforeCommit?.(structuredClone(selected), structuredClone(verified));
      if (localPlan !== undefined) selected = { ...selected, recovery: localPlan ?? undefined };
      if (selected !== existing) await this.journal.putReturn(selected);
      return selected;
    });
  }

  private requireReturnArchive(tx: Uint8Array): never {
    return refuse('EvidenceMissing', `needs archive for payment or exact failure ${hexq(tx)}. Add a reader that serves the certified block and receipt, then resume`);
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
    return this.locked(`return/${toHex(returnId)}`, () => this.burnInner(returnId, owner, admission, recipient, recoverProof));
  }

  private async burnInner(returnId: Uint8Array, owner?: OwnerSigner, admission?: ReturnAdmission, expectedRecipient?: Uint8Array,
    recoverProof?: boolean): Promise<{ burned: Uint8Array; eta: Uint8Array; verdict: Verdict }> {
    const rec = await this.returnRecord(returnId);
    if (rec.status === 'planned') {
      // the last check before the irreversible step: the preflight again, at the journaled index, against a fresh state
      if (owner === undefined) return refuse('BadInput', 'only the holder can sign a new burn');
      if (admission) await this.verifyReturnAnchor(rec);
      const recipient = unhex(rec.recipient);
      this.checkReturnRecipient(recipient);
      if (expectedRecipient && !eq(recipient, expectedRecipient)) refuse('BadInput', 'planned return does not match the authorized recipient');
      const source = unhex(rec.source);
      const held = await this.verifyToken(source);
      if (rec.returnId !== hex(returnId) || !eq(HU(source), returnId) || held.amount !== undec(rec.amount)) {
        refuse('BadInput', 'planned return does not match the verified source and amount');
      }
      await this.admitReturn(rec, held.amount, admission);
      const R = encodeReturnData({ d: this.domain, asset: ASSET_UCT, recipient, amount: held.amount, minIndex: undec(rec.a) });
      const { tx, cd } = await transferRequest(source, owner, { recipient: burnPredicate(HU(R)), mask: freshMask(), data: R, deadline: null });
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
    return this.locked(`return/${toHex(returnId)}`, () => this.submitRedeemInner(returnId, signer, options));
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
    const prior = await this.reconcileRecord(fresh, archives, { readOnly: Boolean(different), pending },
      (request) => { expired = request; });
    if (prior.state === 'paid' || prior.state === 'needs-archive') return prior;
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
        options.admit && ((request) => options.admit!(request, fresh.sends)), expired);
      // Until the exact call passes preflight it has never been broadcast. Leave
      // the burn rebuildable, including its history and route, on any refusal.
      await this.checkOrdinaryImport(fresh, tx.raw);
      if (expired && await this.evm.nonce(signer.address, 'latest') !== tx.request.nonce) {
        return { state: 'pending', txHash: unhex(fresh.sends.at(-1)!.hash) };
      }
      fresh.executionPayer ??= hex(signer.address);
      fresh.sends.push(this.sendRecord(tx));
      fresh.status = 'submitted';
      fresh.firstSendBlock = fresh.firstSendBlock ?? dec(await this.evm.blockNumber());
      await this.journal.putReturn(fresh);
      expired = undefined;
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

  /**
   * Look for Paid(eta) and the receipts of every journaled send; never changes the burn. A Paid log counts only from the vault and only
   * once its receipt is verified under the block's EVM UC (section 6.2 steps 2 to 5): a provider that invents or withholds Paid can
   * delay the wallet, never stop its redemption.
   */
  public reconcile(returnId: Uint8Array, archives: readonly EvmReader[] = [this.evm], evidence?: ReturnEvidence): Promise<ReconcileResult> {
    returnId = Uint8Array.from(returnId);
    return this.locked(`return/${toHex(returnId)}`, () => this.reconcileInner(returnId, archives, evidence));
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

  private async reconcileRecord(rec: ReturnRecord, archives: readonly EvmReader[], evidence?: ReturnEvidence, onExpired?: (tx: TxRequest) => void): Promise<ReconcileResult> {
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
    const hinted = new Map<string, { tx: Uint8Array; pruned: boolean }>();
    const addHint = (tx: Uint8Array, pruned = false) => {
      const key = hex(tx);
      hinted.set(key, { tx, pruned: pruned || hinted.get(key)?.pruned === true });
    };
    if (rec.paidProof) {
      const tx = unhex(rec.paidProof.txHash);
      candidates.set(rec.paidProof.txHash, tx);
      addHint(tx);
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
          if (result?.state === 'pending' || result?.state === 'needs-archive') addHint(tx, result.state === 'needs-archive');
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
          addHint(l.transactionHash);
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

    let changed = false;
    // Indexed or remembered claims trigger proof reads. A certified failure retires only that exact claim.
    for (const [hash, { tx }] of hinted) {
      const send = rec.sends.find((s) => hex(decodeSignedTx(unhex(s.raw)).hash) === hash);
      const failure = send?.failed ?? (await this.exactFailure(tx, archives)).failed;
      if (!failure) continue;
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
    const next = [...hinted.values()].find(({ pruned }) => pruned) ?? hinted.values().next().value;
    if (next) {
      const txHash = hex(next.tx);
      const reads = next.pruned ? FAILURE_PROOF_READS : Math.min(FAILURE_PROOF_READS, (rec.paidProof?.txHash === txHash ? rec.paidProof.reads : 0) + 1);
      if (rec.paidProof?.txHash !== txHash || rec.paidProof.reads !== reads) {
        rec.paidProof = { txHash, reads };
        changed = true;
      }
      if (changed && persist) await this.journal.putReturn(rec);
      return { state: reads >= FAILURE_PROOF_READS ? 'needs-archive' : 'pending', txHash: next.tx };
    }
    if (changed && persist) await this.journal.putReturn(rec);
    if (!available && unavailable) throw unavailable;
  }

  /** Before signing again, reconcile the exact send. A finalized stale call may only be replaced at its unused nonce. */
  private async reconcileSend(rec: ReturnRecord, archives: readonly EvmReader[], resubmit: boolean, onExpired?: (tx: TxRequest) => void): Promise<ReconcileResult> {
    const send = rec.sends.at(-1);
    if (!send) return { state: 'not-paid' };
    const raw = unhex(send.raw);
    const { hash: txHash, from, request } = decodeSignedTx(raw);
    if (hex(txHash) !== send.hash || request.nonce !== undec(send.nonce)) refuse('BadInput', 'ordinary send hash does not match its signed transaction');
    // A certified failure of any replacement at this nonce rules out all the others.
    const sameNonce = rec.sends.filter((prior) => prior.nonce === send.nonce).reverse();
    let evidence: { seen: boolean; pruned: boolean; attempted: boolean } | undefined;
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
      };
    }
    const { seen, pruned, attempted } = evidence!;
    if (attempted || send.failureProofReads !== undefined) {
      const reads = pruned ? FAILURE_PROOF_READS : Math.min((send.failureProofReads ?? 0) + 1, FAILURE_PROOF_READS);
      if (reads !== send.failureProofReads) {
        send.failureProofReads = reads;
        await this.journal.putReturn(rec);
      }
    }
    if (send.failureProofReads === FAILURE_PROOF_READS) return { state: 'needs-archive', txHash };
    if (!seen && resubmit && send.failureProofReads === undefined) {
      try { await this.checkOrdinaryImport(rec, raw); }
      catch (error) {
        if (!(error instanceof Nb2Error) || error.rule !== 'StaleEndpoint') throw error;
        if (onExpired && await this.evm.nonce(from, 'latest') === request.nonce) {
          onExpired(request);
          return { state: 'not-paid' };
        }
        return { state: 'pending', txHash };
      }
      try { await this.evm.sendRaw(raw); }
      catch (e) { if (!(e instanceof AmbiguousBroadcast)) throw e; }
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
    for (const reader of archives) {
      try {
        const receipt = await reader.receipt(txHash);
        if (!receipt) continue;
        seen = true;
        if (BigInt(receipt.status) !== 0n) continue;
        attempted = true;
        await this.retryingTrust((trust) => reader.verifyFailedReceipt(txHash, this.cfg, trust, receipt, archives));
        return { seen, attempted, pruned, failed: { txHash: hex(txHash), blockHash: hex(unhex(receipt.blockHash)) } };
      } catch (e) {
        if (e instanceof WalletError && e.reason === 'TrustInput') throw e;
        if (e instanceof ProofUnavailable && e.pruned || e instanceof Nb2Error && e.rule === 'EvidencePruned') pruned = true;
      }
    }
    return { seen, attempted, pruned, failed: undefined };
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
      if (e instanceof ProofUnavailable) return { state: e.pruned ? 'needs-archive' : 'pending', txHash: tx };
      if (e instanceof WalletError && e.reason === 'CompanionUnknown') return { state: 'pending', txHash: tx };
      if (e instanceof Nb2Error && e.rule === 'EvidencePruned') return { state: 'needs-archive', txHash: tx };
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

  private async signed(signer: EvmSigner, to: Uint8Array, data: Uint8Array, value: bigint, gas: bigint, admit?: (request: TxRequest) => Promise<void>, replace?: TxRequest): Promise<SignedTx> {
    const [nonce, fees] = await Promise.all([this.evm.nonce(signer.address), this.evm.fees()]);
    const request = { chainId: this.cfg.chainId, nonce, maxPriorityFeePerGas: fees.priority, maxFeePerGas: 2n * fees.baseFee + fees.priority, gas, to, value, data };
    if (replace) {
      if (await this.evm.nonce(signer.address, 'latest') !== replace.nonce) refuse('NotPending', 'payout nonce changed during replacement');
      request.nonce = replace.nonce;
      const fee = replacementBid(replace.maxFeePerGas);
      if (fee > request.maxFeePerGas) request.maxFeePerGas = fee;
      const priority = replacementBid(replace.maxPriorityFeePerGas);
      if (priority > request.maxPriorityFeePerGas) request.maxPriorityFeePerGas = priority;
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
    const head = await this.evm.blockNumber();
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
