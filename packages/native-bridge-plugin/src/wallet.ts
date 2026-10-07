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
import type { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { Token as TokenClass } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

import { preflightToken } from './resources.js';
import { concat, eq, toHex } from './bytes.js';
import { NativeError, fail } from './errors.js';
import { checkJustification, checkMintData } from './history.js';
import { parseJustification, verifyLockProof } from './lockproof.js';
import { buildReturnProof, refreshToken } from './proof.js';
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

/** A pending-redemption journal entry; burn acknowledgement is durable handoff, not vault payout. */
export interface RedemptionEntry {
  burnId: string;
  tokenId: string;
  burnedToken: Uint8Array;
  nullifier: Uint8Array;
  releaseTo: Uint8Array;
  status: 'burned' | 'submitted' | 'settled';
}

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
    const dep = bridge.registry.find(bridge.trust.base.networkId.id, parsed.chainId, parsed.vault);
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
      await payments.journal.put({ burnId, tokenId: args.tokenId, burnedToken: blob, nullifier: v.outcome.nullifier, releaseTo: v.outcome.releaseTo, status: 'burned' });
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
    await payments.journal.put({ burnId, tokenId: pending.tokenId, burnedToken: blob, nullifier: v.outcome.nullifier, releaseTo: v.outcome.releaseTo, status: 'burned' });
    await persist(blob, burnId);
  });
}

/** Source of fresh aggregator proofs for one token, in history order (host transport; untrusted). */
export type ProofSource = (token: Token) => Promise<InclusionProof[]>;

/**
 * Assemble the return proof, refreshing the aggregator proofs first from the optional transport.
 * Refresh keeps J/M/T/CD and the original `t`; a proof for another epoch is rejected by verification.
 */
export async function buildNativeReturnProof(plugin: NativeBridgePlugin, tokenBytes: Uint8Array, source?: ProofSource): Promise<{ encoded: Uint8Array; nullifier: Uint8Array }> {
  preflightToken(tokenBytes);
  let token = await TokenClass.fromCBOR(tokenBytes);
  if (source) token = await refreshToken(token, await source(token));
  const { encoded, verified } = await buildReturnProof(plugin.bridge, token);
  return { encoded, nullifier: verified.outcome.nullifier };
}

/** `claim(uint256 amount, address to)`: the vault's guarded pull payment, as calldata. */
export function claimCalldata(amount: bigint, to: Uint8Array): Uint8Array {
  if (to.length !== 20 || amount <= 0n) fail('ErrLockInput');
  const sel = keccak_256(new TextEncoder().encode('claim(uint256,address)')).slice(0, 4);
  const addr = new Uint8Array(32);
  addr.set(to, 12);
  return concat(sel, word(amount), addr);
}

/**
 * Submit `claim`: only the credited recipient can redirect. Settlement is confirmed from the claim
 * receipt and on-chain spent/credit state, never from the wallet burn acknowledgement.
 */
export async function claim(
  send: (tx: { to: Uint8Array; data: Uint8Array }) => Promise<string>,
  vault: Uint8Array,
  amount: bigint,
  to: Uint8Array,
): Promise<string> {
  return send({ to: vault, data: claimCalldata(amount, to) });
}

export { NativeError };
