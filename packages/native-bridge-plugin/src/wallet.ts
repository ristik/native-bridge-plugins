/**
 * Wallet integration over bridge-core's structural contracts.
 *
 * The SDK's genesis hooks cannot enforce the full-history profile, so a bare `WalletTokenPlugin`
 * registration is not enough. {@link NativeBridgePayments} is the native `BridgePayments` adapter:
 * it gates every import/receive, cached balance activation, transfer, burn and export on
 * {@link NativeBridge.verifyNativeToken}, binds validation caches to exact token bytes, the pinned
 * trust-base document digest and the manifest/profile revision, and re-checks every burned blob it
 * receives instead of trusting a wallet success flag. Generic split/partial-payment/merge operations
 * are not exposed for this token type.
 *
 * Construction functions take an optional, separate transport; the verifier API has no network
 * capability. `ChainFamily` of bridge-core is not widened: native identity types stay local.
 */
import {
  burnForReturn as coreBurnForReturn,
  mintBridgedToken as coreMintBridgedToken,
  recoverPendingBurns as coreRecoverPendingBurns,
  type BridgePayments,
  type BurnForReturnArgs,
  type BurnForReturnResult,
  type MintRequest,
  type WalletBurnResult,
  type WalletMintResult,
  type WalletPendingBurn,
  type WalletTokenPlugin,
} from '@unicitylabs/bridge-core';
import type { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import type { ConsolidationResult, ProofUnavailableReason } from '@unicitylabs/state-transition-sdk/lib/consolidation/ConsolidationResult.js';
import type { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { Token as TokenClass } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

import { preflightToken } from './resources.js';
import { concat, eq, toHex } from './bytes.js';
import { NativeError, fail, type NativeReason } from './errors.js';
import { checkJustification, checkMintData } from './history.js';
import { parseJustification, verifyLockProof } from './lockproof.js';
import { buildReturnProof, preflightBurn, refreshToken } from './proof.js';
import { H, deriveSalt, deriveTokenId, lockDigest, lockRecord, word } from './profile.js';
import { BridgedTokenIssuancePolicy, NativeBridge, NativeLockJustificationVerifier, type Expect, type VerifiedToken } from './verifier.js';

/** The wallet-side operations the adapter wraps. */
export interface NativeWalletBackend extends BridgePayments {
  /** The exact serialized token the wallet holds under `tokenId`, or null. */
  tokenBytes(tokenId: string): Promise<Uint8Array | null>;
  /** The recipient predicate (CBOR) the wallet will own a newly minted token with. */
  recipientPredicate(): Promise<Uint8Array>;
}

/** Revision strings that scope validation caches; any change invalidates every cached verdict. */
export interface PolicyRevision {
  manifestRevision: string;
  profileRevision: string;
}

/** The native plug-in: the bridge (deployments + pinned trust) plus its wallet-facing registrations. */
export interface NativeBridgePlugin {
  readonly bridge: NativeBridge;
  readonly revision: PolicyRevision;
  /** SDK registrations for wallets that wire the existing seams; not sufficient on their own. */
  readonly walletPlugin: WalletTokenPlugin;
  verifyNativeToken(bytes: Uint8Array, expect?: Expect): Promise<VerifiedToken>;
}

export function createNativeBridgePlugin(bridge: NativeBridge, revision: PolicyRevision): NativeBridgePlugin {
  const verifier = new NativeLockJustificationVerifier(bridge);
  const policies = bridge.registry.tokenTypes.map((ty) => new BridgedTokenIssuancePolicy(bridge, ty, `${revision.manifestRevision}/${revision.profileRevision}`));
  return {
    bridge,
    revision,
    walletPlugin: { id: 'native-bridge', mintJustificationVerifiers: [verifier], tokenIssuancePolicies: policies },
    verifyNativeToken: (bytes, expect = 'receipt') => bridge.verifyNativeTokenBytes(bytes, expect),
  };
}

/** Cache of verdicts bound to exact token bytes, the pinned document digest and the revisions. */
export class VerdictCache {
  private readonly ok = new Set<string>();

  public constructor(private readonly plugin: NativeBridgePlugin) {}

  private key(bytes: Uint8Array, expect: Expect): string {
    const r = this.plugin.revision;
    return `${expect}|${toHex(H(bytes))}|${toHex(this.plugin.bridge.trust.id)}|${r.manifestRevision}|${r.profileRevision}`;
  }

  public async verify(bytes: Uint8Array, expect: Expect): Promise<void> {
    const k = this.key(bytes, expect);
    if (this.ok.has(k)) return;
    await this.plugin.verifyNativeToken(bytes, expect);
    this.ok.add(k);
  }

  public get size(): number {
    return this.ok.size;
  }
}

/**
 * A redemption journal entry; burn acknowledgement is durable handoff, not vault payout. The states in order:
 * `burned` (the certified blob is durably handed off), `submitted` (a `redeem` was sent; every hash is kept in `redeemTxs`, an
 * unknown outcome is never forgotten), `redeemed` (the vault credited `amount` to `releaseTo`), `settled` (the claim of that credit
 * was confirmed by its receipt and by the `claimable` balance falling by the claimed amount: the native funds are paid).
 */
export interface RedemptionEntry {
  burnId: string;
  tokenId: string;
  burnedToken: Uint8Array;
  nullifier: Uint8Array;
  /** The lock nonce of the token: the vault keys its spent state by it (`spentNullifier(nonce)` holds the nullifier). */
  nonce: bigint;
  /** The redeemable native amount, in wei. */
  amount: bigint;
  releaseTo: Uint8Array;
  status: 'burned' | 'submitted' | 'redeemed' | 'settled';
  /** Every `redeem` transaction hash sent for this burn, oldest first. */
  redeemTxs: string[];
  /** A claim send was started (journalled BEFORE the send): without `claimTx` its hash may be lost, and no second claim is sent until the host decides (`abandonAttempt`). */
  claimStarted?: boolean;
  /** The claim transaction hash (`settled` once it is confirmed). */
  claimTx?: string;
}

/** The big-endian unsigned integer of a fixed-width byte string. */
export const uintOf = (b: Uint8Array): bigint => (b.length === 0 ? 0n : BigInt(`0x${toHex(b)}`));

/** A fresh `burned` entry for a verified return token. */
const burnedEntry = (burnId: string, tokenId: string, blob: Uint8Array, o: { nullifier: Uint8Array; nonce: bigint; amount: Uint8Array; releaseTo: Uint8Array }): RedemptionEntry =>
  ({ burnId, tokenId, burnedToken: blob, nullifier: o.nullifier, nonce: o.nonce, amount: uintOf(o.amount), releaseTo: o.releaseTo, status: 'burned', redeemTxs: [] });

export interface RedemptionJournal {
  put(entry: RedemptionEntry): Promise<void>;
  get(burnId: string): Promise<RedemptionEntry | null>;
  list(): Promise<RedemptionEntry[]>;
}

/** Explicit test/demo journal. Its writes are not durable; the handoff callback remains required. */
export class MemoryRedemptionJournal implements RedemptionJournal {
  private readonly m = new Map<string, RedemptionEntry>();
  public put(e: RedemptionEntry): Promise<void> {
    this.m.set(e.burnId, e);
    return Promise.resolve();
  }
  public get(id: string): Promise<RedemptionEntry | null> {
    return Promise.resolve(this.m.get(id) ?? null);
  }
  public list(): Promise<RedemptionEntry[]> {
    return Promise.resolve([...this.m.values()]);
  }
}

/** The gated `BridgePayments` adapter. */
export class NativeBridgePayments implements BridgePayments {
  public readonly cache: VerdictCache;

  public constructor(
    private readonly plugin: NativeBridgePlugin,
    private readonly backend: NativeWalletBackend,
    public readonly journal: RedemptionJournal,
  ) {
    this.cache = new VerdictCache(plugin);
  }

  /** Verify the certified EVM lock before the SDK mint options are submitted. */
  public async mintCustom(request: Parameters<BridgePayments['mintCustom']>[0]): Promise<WalletMintResult> {
    const bridge = this.plugin.bridge;
    const j = request.justification ?? fail('ErrMintJustif');
    const parsed = parseJustification(j);
    const dep = bridge.registry.find(bridge.trust.network.id, parsed.chainId, parsed.vault);
    if (!eq(request.tokenType, dep.cfg.ty)) fail('ErrMintType');
    const amount = checkMintData(dep, request.data);
    const nonce = checkJustification(dep, j);
    const salt = deriveSalt(dep.cfgHash, nonce);
    if (!eq(request.salt, salt)) fail('ErrMintSalt');
    const first = H(await this.backend.recipientPredicate());
    const digest = lockDigest(dep.cfgHash, nonce, lockRecord(dep.cfg.zeroAddress, dep.cfg.ty, dep.cfg.aid, amount, deriveTokenId(salt, dep.cfg.network), first));
    await verifyLockProof(dep, bridge.trust, parsed, digest);
    return this.backend.mintCustom(request);
  }

  /** Burn only a token that verifies as a native receipt; recheck the returned blob as a return. */
  public async burn(request: Parameters<BridgePayments['burn']>[0]): Promise<WalletBurnResult> {
    const bytes = (await this.backend.tokenBytes(request.tokenId)) ?? fail('ErrMissingBacking');
    await this.cache.verify(bytes, 'receipt');
    // Refuse a burn whose redemption envelope could never fit the profile bounds and the gas gate.
    await preflightBurn(this.plugin.bridge, bytes);
    const result = await this.backend.burn(request);
    if (!result.success || !result.burnedToken) return result;
    // Never trust a wallet success flag alone.
    await this.plugin.bridge.verifyBurnRequestBytes(bytes, result.burnedToken, request.reasonBytes);
    return result;
  }

  public tokenJustification(tokenId: string): Promise<Uint8Array | null> {
    return this.backend.tokenJustification(tokenId);
  }
  public pendingBurns(): Promise<readonly WalletPendingBurn[]> {
    return this.backend.pendingBurns();
  }
  public acknowledgeBurn(burnId: string): Promise<void> {
    return this.backend.acknowledgeBurn(burnId);
  }

  /** Gate for import/receive and cached balance activation. */
  public async receive(bytes: Uint8Array): Promise<VerifiedToken> {
    const v = await this.plugin.verifyNativeToken(bytes, 'receipt');
    await this.cache.verify(bytes, 'receipt');
    return v;
  }

  /** Gate for export: only a native receipt may leave the wallet as a token. */
  public async export(tokenId: string): Promise<Uint8Array> {
    const bytes = (await this.backend.tokenBytes(tokenId)) ?? fail('ErrMissingBacking');
    await this.cache.verify(bytes, 'receipt');
    return bytes;
  }
}

/** Mint through bridge-core with the native pre-check. Mint options use null deadlines by default. */
export function mintBridgedToken(payments: NativeBridgePayments, request: MintRequest): Promise<WalletMintResult> {
  return coreMintBridgedToken(payments, request);
}

/**
 * Burn for return: durable handoff of the full certified blob (journalled and rechecked as a native
 * return) before the wallet burn is acknowledged. Acknowledgement is not vault payout.
 */
export async function burnForReturn(
  plugin: NativeBridgePlugin,
  payments: NativeBridgePayments,
  // persist must durably store the complete blob before resolving, even with a memory journal.
  args: BurnForReturnArgs,
): Promise<BurnForReturnResult> {
  if (typeof args.persist !== 'function') throw new TypeError('A durable persist callback is required');
  return coreBurnForReturn(payments, {
    tokenId: args.tokenId,
    reasonBytes: args.reasonBytes,
    persist: async (blob, burnId) => {
      const v = await plugin.verifyNativeToken(blob, 'return');
      await payments.journal.put(burnedEntry(burnId, args.tokenId, blob, v.outcome));
      await args.persist(blob, burnId);
    },
  });
}

/** Recover interrupted burns. `persist` must durably store the complete blob before resolving. */
export function recoverPendingBurns(plugin: NativeBridgePlugin, payments: NativeBridgePayments, persist: BurnForReturnArgs['persist']): Promise<readonly BurnForReturnResult[]> {
  if (typeof persist !== 'function') throw new TypeError('A durable persist callback is required');
  return coreRecoverPendingBurns(payments, async (blob, burnId) => {
    const v = await plugin.verifyNativeToken(blob, 'return');
    const pending = (await payments.pendingBurns()).find((p) => p.burnId === burnId) ?? fail('ErrMissingBacking');
    const token = await TokenClass.fromCBOR(blob);
    const data = token.transactions.at(-1)?.data;
    if (!data || !eq(data, pending.reasonBytes)) fail('ErrBurnReason');
    // an interrupted burn that was already journalled keeps its later state (a redemption may be under way)
    const known = await payments.journal.get(burnId);
    if (!known) await payments.journal.put(burnedEntry(burnId, pending.tokenId, blob, v.outcome));
    await persist(blob, burnId);
  });
}

/** Source of fresh aggregator proofs for one token, in history order (host transport; untrusted). */
export type ProofSource = (token: Token) => Promise<InclusionProof[]>;

/**
 * The host's consolidation of a token (the SDK's uc-consolidation flow, `TokenProofClient.consolidate`, over the host's routing and
 * transport). It returns the SDK's result; a `ConsolidationError` of any kind (`cancelled`, `input`, `integrity`,
 * `invalid_response`, `rejected`, `server`, `timeout`, `transport`) is thrown as the SDK throws it and is never turned into a
 * fallback. Like a `ProofSource` it is host code and untrusted: only the outer proofs of its token are used, re-attached to the held
 * token's own transactions (`refreshToken`), so a token other than the held one is `ErrRefreshMismatch`.
 */
export type TokenConsolidator = (token: Token) => Promise<ConsolidationResult>;

/** The partition view's V1 shard limit (`MaxPartitionViewLeaves`): a larger partition is never consolidated. */
export const MAX_VIEW_SHARDS = 8;

/** The consolidated path's inputs from the host: its consolidator and the aggregation partition's shard count (its routing). */
export interface ConsolidationPath {
  consolidate: TokenConsolidator;
  partitionShards: number;
}

/**
 * How a return proof was assembled: from the consolidated token (one seal), or per SID: consolidation not used, the partition
 * over the view's shard limit (`overViewLimit`, consolidation not called), or consolidation `unavailable`.
 */
export type ReturnProofPath =
  | { kind: 'consolidated' }
  | { kind: 'per-sid'; overViewLimit?: true; unavailable?: ProofUnavailableReason; retryable?: boolean };

/**
 * One consolidation attempt for `held`: the outer proofs of the consolidated token (to be re-attached to `held` with
 * `refreshToken`), or none and the per-SID path with its cause (no consolidation configured, the partition over the view's shard
 * limit, consolidation `unavailable`). A `ConsolidationError` propagates.
 */
export async function consolidatedProofs(held: Token, consolidation?: ConsolidationPath): Promise<{ proofs?: InclusionProof[]; path: ReturnProofPath }> {
  if (!consolidation) return { path: { kind: 'per-sid' } };
  // a partition over the view's shard limit is never consolidated (the SDK would refuse its topology as an integrity error)
  if (consolidation.partitionShards > MAX_VIEW_SHARDS) return { path: { kind: 'per-sid', overViewLimit: true } };
  const r = await consolidation.consolidate(held);
  if (r.status === 'consolidated') return { proofs: [r.token.genesis, ...r.token.transactions].map((c) => c.inclusionProof), path: { kind: 'consolidated' } };
  return { path: { kind: 'per-sid', unavailable: r.reason, retryable: r.retryable } };
}

/** Attempts at fetching and assembling one return proof before it is reported unavailable. */
export const MAX_PROOF_ATTEMPTS = 3;

/**
 * Failures that mean the fetched (path, UC) pair raced a certificate or does not belong together: the
 * path does not verify under its own UC. They are retried a bounded number of times with a fresh fetch;
 * nothing is re-queried to make certificates converge, and a pair that never verifies is `ErrProofUnavailable`.
 */
export const PAIR_RACE: readonly NativeReason[] = ['ErrPathInvalid', 'ErrSdkVerification', 'ErrSealRoot'];

/**
 * Assemble the return proof, refreshing the aggregator proofs first from the optional transport.
 * Refresh keeps J/M/T/CD and the original `t`; a proof for another epoch is rejected by verification.
 * Every response keeps its own (path, UC) pair; assembly uses only what the transport returned.
 */
export async function buildNativeReturnProof(
  plugin: NativeBridgePlugin,
  tokenBytes: Uint8Array,
  source?: ProofSource,
  consolidation?: ConsolidationPath,
): Promise<{ encoded: Uint8Array; nullifier: Uint8Array; path: ReturnProofPath; tokenBytes: Uint8Array }> {
  preflightToken(tokenBytes);
  const held = await TokenClass.fromCBOR(tokenBytes);
  // The default: one consolidation attempt (the SDK makes two waves and never chases a newer seal). Its token is an ordinary token
  // whose outer proofs share one seal, so the anchor table is one anchor per shard; it is assembled as is, with no refetch. Only an
  // `unavailable` result (or no consolidation, or a partition over the view's limit) falls back to the per-SID path below. The
  // consolidated proofs are re-attached to the held token's own transactions, as a per-SID refresh is.
  const c = await consolidatedProofs(held, consolidation);
  const path = c.path;
  if (c.proofs) {
    const token = await refreshToken(held, c.proofs);
    const { encoded, verified } = await buildReturnProof(plugin.bridge, token);
    return { encoded, nullifier: verified.outcome.nullifier, path, tokenBytes: token.toCBOR() };
  }
  for (let attempt = 1; ; attempt++) {
    try {
      const token = source ? await refreshToken(held, await source(held)) : held;
      const { encoded, verified } = await buildReturnProof(plugin.bridge, token);
      return { encoded, nullifier: verified.outcome.nullifier, path, tokenBytes: token.toCBOR() };
    } catch (e) {
      if (!(e instanceof NativeError) || !PAIR_RACE.includes(e.reason)) throw e;
      // without a source nothing was refetched, so nothing raced: the held token's own failure stands. With one, the last reason is the cause.
      if (!source) throw e;
      if (attempt >= MAX_PROOF_ATTEMPTS) return fail('ErrProofUnavailable', `the fetched (path, certificate) pairs did not verify in ${MAX_PROOF_ATTEMPTS} fetches (last: ${e.reason})`);
    }
  }
}

/**
 * `claim(uint256 amount, address to)`: the vault's guarded pull payment, as calldata. An amount that does not fit a word, the zero address
 * and the vault itself are refused before any gas is paid (the vault would refuse the last two with `BadRecipient`).
 */
export function claimCalldata(amount: bigint, to: Uint8Array, vault: Uint8Array): Uint8Array {
  if (to.length !== 20 || vault.length !== 20 || amount <= 0n || amount >= 1n << 256n) fail('ErrLockInput');
  if (to.every((b) => b === 0) || eq(to, vault)) fail('ErrLockInput', 'the claim destination is the zero address or the vault');
  const sel = keccak_256(new TextEncoder().encode('claim(uint256,address)')).slice(0, 4);
  const addr = new Uint8Array(32);
  addr.set(to, 12);
  return concat(sel, word(amount), addr);
}

/**
 * Submit `claim` and return the transaction hash. This only SENDS: it does not wait for the receipt or read `claimable`. Use `claimCredited`
 * (`lifecycle.ts`) for the journalled path whose settlement is confirmed from the receipt and the balance, never from this call or the burn acknowledgement.
 * Only the credited recipient can redirect.
 */
export async function claim(
  send: (tx: { to: Uint8Array; data: Uint8Array }) => Promise<string>,
  vault: Uint8Array,
  amount: bigint,
  to: Uint8Array,
): Promise<string> {
  return send({ to: vault, data: claimCalldata(amount, to, vault) });
}

export { NativeError };
