/**
 * Full-history verification of a native bridge token and the SDK-seam adapters.
 *
 * A bare `WalletTokenPlugin` registration only sees genesis. {@link NativeBridge.verifyNativeToken}
 * (and {@link NativeBridgeTokenVerifier} on the SDK's `ITokenVerifier` seam) is the gate every
 * import, credit, transfer, burn and export must call. Nothing here has a network capability.
 */
import { UnicityCertificateVerifier } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/UnicityCertificateVerifier.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { Secp256k1SignatureVerifier } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { PredicateVerifierService } from '@unicitylabs/state-transition-sdk/lib/predicate/verification/PredicateVerifierService.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';
import { TokenVerifier } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/default/TokenVerifier.js';
import type { IMintJustificationVerifier } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/IMintJustificationVerifier.js';
import type { ITokenVerifier } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/ITokenVerifier.js';
import type { IVerificationContext } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/IVerificationContext.js';
import { MintJustificationVerifierService } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/MintJustificationVerifierService.js';
import { SplitMintJustificationVerifier } from '@unicitylabs/state-transition-sdk/lib/payment/SplitMintJustificationVerifier.js';
import { TokenIssuanceVerifierService } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/TokenIssuanceVerifierService.js';
import { VerificationContext } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/VerificationContext.js';
import type { WalletIssuancePolicy } from '@unicitylabs/bridge-core';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { preflightToken } from './resources.js';
import { eq, toHex } from './bytes.js';
import type { Deployment, DeploymentRegistry } from './deployment.js';
import { NativeError, fail, type NativeReason } from './errors.js';
import { decodeHistory, checkJustification, checkMintData, projectToken, verifyHistory, type Leaf, type Outcome } from './history.js';
import { COMPOSED_HISTORY, TAG_MINT_LOCK } from './limits.js';
import { parseJustification, verifyLockProof, type Justification, type VerifiedLock } from './lockproof.js';
import { verifyLineage, type LineageOutcome } from './lineage.js';
import { H, deriveSalt, deriveTokenId, lockDigest, lockRecord, shardCovers, shardDepth } from './profile.js';
import { WalletValue, isSplitReason, lineageProofs, rootJustification, splitChain } from './splitpart.js';
import { certificateFailure, type TrustInput } from './trust.js';

export type Expect = 'receipt' | 'return';

export interface VerifiedToken {
  /** For a split part, the lineage's root identity and every leaf of the lineage, root first (`lineage` below). */
  outcome: Outcome;
  lock: VerifiedLock;
  /** Index of the allow-listed deployment the token was verified under. */
  deployment: number;
  /** A split part's lineage (protocol 6): the part, the depth and the walk's charge; absent for a lock-backed token. */
  lineage?: LineageOutcome;
}

const reasonOf = (e: unknown): NativeReason | null => (e instanceof NativeError ? e.reason : null);

/** Name an SDK verification failure with the shared sentinel vocabulary. */
export function mapSdkFailure(r: VerificationResult<unknown>): NativeReason {
  const walk = (x: VerificationResult<unknown>): NativeReason | null => {
    switch (String(x.status)) {
      case 'PATH_INVALID': return 'ErrPathInvalid';
      case 'REQUEST_EXPIRED': return 'ErrDeadlineExpired';
      case 'REFERENCE_TIME_AFTER_ROUND': return 'ErrReferenceTimeFuture';
      case 'SHARD_ID_MISMATCH': return 'ErrShardMismatch';
      case 'CERTIFICATION_DATA_MISMATCH':
      case 'TRANSACTION_HASH_MISMATCH': return 'ErrCDMismatch';
      default:
    }
    if (x.rule === 'UnicitySealNetworkMatchesTrustBaseRule' && String(x.status) === String(VerificationStatus.FAIL)) return 'ErrSealNetwork';
    for (const c of x.results) {
      const m = walk(c);
      if (m) return m;
    }
    return null;
  };
  // certificate failures are named as for the embedded certificate: retryable missing epoch, structure, seal epoch, root, quorum
  return walk(r) ?? certificateFailure(r) ?? 'ErrSdkVerification';
}

/** Whether two authorities are the same history: the same network and the same genesis entry. */
function sameBase(a: IVerificationContext['trustBase'], b: IVerificationContext['trustBase']): boolean {
  return a.networkId.id === b.networkId.id && a.genesisEpoch === b.genesisEpoch && a.committee(a.genesisEpoch)?.id === b.committee(b.genesisEpoch)?.id;
}

export class NativeBridge {
  public constructor(
    public readonly registry: DeploymentRegistry,
    public readonly trust: TrustInput,
  ) {
    for (const d of registry.deployments) {
      if (d.cfg.network !== trust.network.id) fail('ErrNetworkMismatch');
    }
  }

  /** The SDK verification context with this bridge's justification verifier and issuance policies. */
  public async context(base?: Partial<Pick<IVerificationContext, 'predicateVerifier' | 'unicityCertificateVerifier'>>): Promise<VerificationContext> {
    // A split part's reason carries its burned parent: the SDK verifies the allocation and the parent recursively under this same
    // context, down to the root's lock reason; the issuance policies below admit a split output only of a deployment's own type.
    const mjvs = new MintJustificationVerifierService()
      .register(new NativeLockJustificationVerifier(this))
      .register(new SplitMintJustificationVerifier(WalletValue.decode));
    const tiv = new TokenIssuanceVerifierService(true);
    for (const ty of this.registry.tokenTypes) tiv.register(new BridgedTokenIssuancePolicy(this, ty));
    return new VerificationContext(
      await this.trust.authority(),
      base?.predicateVerifier ?? PredicateVerifierService.create(),
      base?.unicityCertificateVerifier ??
        new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier())),
      mjvs,
      tiv,
    );
  }

  /** Decode canonical token bytes (bounded, re-encoding equal) and verify them. */
  public async verifyNativeTokenBytes(bytes: Uint8Array, expect: Expect): Promise<VerifiedToken> {
    preflightToken(bytes);
    let token: Token;
    try {
      token = await Token.fromCBOR(bytes);
    } catch {
      return fail('ErrSdkDecode');
    }
    if (!eq(token.toCBOR(), bytes)) fail('ErrNonCanonical');
    return this.verifyNativeToken(token, expect);
  }

  /** Verify a return as the completion of this exact held-token burn request. */
  public async verifyBurnRequestBytes(held: Uint8Array, burned: Uint8Array, reason: Uint8Array): Promise<VerifiedToken> {
    await this.verifyNativeTokenBytes(held, 'receipt');
    const verified = await this.verifyNativeTokenBytes(burned, 'return');
    const before = await Token.fromCBOR(held);
    const after = await Token.fromCBOR(burned);
    if (after.transactions.length !== before.transactions.length + 1) fail('ErrBurnReason');
    const old = [before.genesis, ...before.transactions];
    const next = [after.genesis, ...after.transactions];
    for (let i = 0; i < old.length; i++) {
      if (!eq(CborDeserializer.decodeArray(old[i].toCBOR(), 2)[0], CborDeserializer.decodeArray(next[i].toCBOR(), 2)[0]) ||
          !eq(old[i].inclusionProof.certificationData.toCBOR(), next[i].inclusionProof.certificationData.toCBOR()) ||
          old[i].inclusionProof.referenceTime !== next[i].inclusionProof.referenceTime) fail('ErrBurnReason');
    }
    const data = after.transactions.at(-1)!.data;
    if (data === null || !eq(data, reason)) fail('ErrBurnReason');
    return verified;
  }

  public async verifyNativeToken(token: Token, expect: Expect, parts?: Partial<Pick<IVerificationContext, 'predicateVerifier' | 'unicityCertificateVerifier'>>): Promise<VerifiedToken> {
    preflightToken(token.toCBOR());
    const g = token.genesis;
    // The generic data hook skips null data, so missing genesis data/justification is explicit here.
    if (g.justification === null) fail('ErrMintJustif');
    if (isSplitReason(g.justification)) return this.verifySplitPart(token, expect, parts);
    if (g.data === null) fail('ErrMintData');
    // J's errors are already the oracle's (bft-core ParseJustification), so they pass through unchanged.
    const parsed: Justification = parseJustification(g.justification as Uint8Array);
    const index = this.registry.index(g.networkId.id, parsed.chainId, parsed.vault);
    const dep = this.registry.deployments[index];

    const hist = decodeHistory(projectToken(token), COMPOSED_HISTORY);
    const outcome = await verifyHistory(dep, hist, expect === 'return');
    const lock = await verifyLockProof(dep, this.trust, parsed, outcome.lockDigest);

    // Bridge-specific checks per leaf: aggregator admission, t <= IR (no cumulative path budget, owner section 36).
    const all = [g, ...token.transactions];
    for (let i = 0; i < all.length; i++) await this.checkLeaf(dep, all[i].inclusionProof, outcome.leaves[i]);

    // The SDK's own ordinary verification, with the same base throughout.
    const r = await new TokenVerifier().verify(token, await this.context(parts));
    if (r.status !== VerificationStatus.OK) fail(mapSdkFailure(r));
    return { outcome, lock, deployment: index };
  }

  /**
   * A split part (protocol 6): the lineage relation over the part's projection (its ancestry read from the exact reason bytes), the
   * root's lock proof against the root's lock digest, every leaf of the lineage (root first) admitted under the deployment's policy,
   * then the SDK's own verification (the split verifier walks the same ancestry).
   */
  private async verifySplitPart(token: Token, expect: Expect, parts?: Partial<Pick<IVerificationContext, 'predicateVerifier' | 'unicityCertificateVerifier'>>): Promise<VerifiedToken> {
    const g = token.genesis;
    if (g.data === null) fail('ErrMintData');
    const parsed: Justification = parseJustification(rootJustification(g.justification));
    const index = this.registry.index(g.networkId.id, parsed.chainId, parsed.vault);
    const dep = this.registry.deployments[index];

    const lineage = await verifyLineage(dep, decodeHistory(projectToken(token), COMPOSED_HISTORY), expect === 'return');
    const lock = await verifyLockProof(dep, this.trust, parsed, lineage.lockDigest);

    const proofs = lineageProofs(await splitChain(token));
    if (proofs.length !== lineage.leaves.length) fail('ErrCDMismatch');
    for (let i = 0; i < proofs.length; i++) await this.checkLeaf(dep, proofs[i], lineage.leaves[i]);

    const r = await new TokenVerifier().verify(token, await this.context(parts));
    if (r.status !== VerificationStatus.OK) fail(mapSdkFailure(r));
    return { outcome: lineage, lock, deployment: index, lineage };
  }

  private async checkLeaf(dep: Deployment, proof: CertifiedMintTransaction['inclusionProof'], leaf: Leaf): Promise<void> {
    const uc = proof.unicityCertificate;
    if (proof.referenceTime !== leaf.referenceTime) fail('ErrCDMismatch');
    const sid = await StateId.fromCertificationData(proof.certificationData);
    if (!eq(sid.data, leaf.sid) || !eq(proof.certificationData.transactionHash.data, leaf.txHash)) fail('ErrCDMismatch');
    // The seal epoch's committee first (protocol/trust-base.md order; the SDK token verification below checks the tree root before the epoch).
    this.trust.selectEpoch(uc);
    // Aggregator admission: the pinned policy names the partition only. The certificate authenticates its own historical shard and
    // configuration; the shard must be a canonical native ID whose prefix the leaf's state ID carries (the first `d` bits, `d` its own depth).
    if (uc.unicityTreeCertificate.partitionIdentifier !== BigInt(dep.policy.partition)) fail('ErrNotAdmitted');
    const shard = uc.shardTreeCertificate.shard.encode();
    try {
      shardDepth(shard);
    } catch {
      fail('ErrShardMismatch');
    }
    if (!shardCovers(shard, leaf.sid)) fail('ErrShardMismatch');
    if (leaf.referenceTime > uc.inputRecord.timestamp) fail('ErrReferenceTimeFuture');
  }
}

/** Verifies the native lock justification of a genesis fully offline (tag 39049, version 2). */
export class NativeLockJustificationVerifier implements IMintJustificationVerifier {
  public lastError: NativeReason | null = null;

  public constructor(private readonly bridge: NativeBridge) {}

  public get tag(): bigint {
    return TAG_MINT_LOCK;
  }

  /** Verify the genesis binding to the certified permanent lock; throws a {@link NativeError}. */
  public async check(genesis: CertifiedMintTransaction): Promise<void> {
    const j = genesis.justification;
    if (j === null) fail('ErrMintJustif');
    // J's errors are already the oracle's (bft-core ParseJustification), so they pass through unchanged.
    const parsed: Justification = parseJustification(j as Uint8Array);
    const dep = this.bridge.registry.find(genesis.networkId.id, parsed.chainId, parsed.vault);
    if (!eq(genesis.tokenType.bytes, dep.cfg.ty)) fail('ErrMintType');
    const amount = checkMintData(dep, genesis.data);
    const nonce = checkJustification(dep, j);
    const salt = deriveSalt(dep.cfgHash, nonce);
    if (!eq(genesis.salt.toBytes(), salt)) fail('ErrMintSalt');
    const id = deriveTokenId(salt, dep.cfg.network);
    const first = H(genesis.recipient.toCBOR());
    const digest = lockDigest(dep.cfgHash, nonce, lockRecord(dep.cfg.zeroAddress, dep.cfg.ty, dep.cfg.aid, amount, id, first));
    await verifyLockProof(dep, this.bridge.trust, parsed, digest);
  }

  public async verify(transaction: CertifiedMintTransaction): Promise<VerificationResult<VerificationStatus>> {
    this.lastError = null;
    try {
      await this.check(transaction);
      return new VerificationResult('NativeLockJustificationVerification', VerificationStatus.OK);
    } catch (e) {
      this.lastError = reasonOf(e);
      return new VerificationResult('NativeLockJustificationVerification', VerificationStatus.FAIL, this.lastError ?? String(e));
    }
  }
}

/**
 * Claims exactly the native asset for one token type: the exact lock reason and the exact value
 * envelope, no null or unknown reason. A split output (protocol 6) is admitted only when the root its
 * reason walks down to is a lock of an allow-listed deployment of this type and its value is that
 * deployment's exact envelope; the split verifier proves the allocation and the burned parent.
 */
export class BridgedTokenIssuancePolicy implements WalletIssuancePolicy {
  public readonly tokenType: TokenType;
  public readonly coinIds: readonly string[];
  public readonly revision?: string;
  public lastError: NativeReason | null = null;

  public constructor(
    private readonly bridge: NativeBridge,
    ty: Uint8Array,
    revision?: string,
  ) {
    this.tokenType = new TokenType(ty);
    this.coinIds = this.bridge.registry.deployments.filter((d) => eq(d.cfg.ty, ty)).map((d) => toHex(d.cfg.aid)).filter((c, i, a) => a.indexOf(c) === i);
    this.revision = revision;
  }

  public check(genesis: CertifiedMintTransaction): void {
    const j = genesis.justification;
    if (j === null) fail('ErrIssuanceReason');
    const split = isSplitReason(j);
    let dep: Deployment;
    try {
      const p = parseJustification(split ? rootJustification(j) : (j as Uint8Array));
      dep = this.bridge.registry.find(genesis.networkId.id, p.chainId, p.vault);
    } catch {
      return fail('ErrIssuanceReason');
    }
    if (!eq(genesis.tokenType.bytes, this.tokenType.bytes) || !eq(dep.cfg.ty, this.tokenType.bytes)) fail('ErrMintType');
    if (!split) {
      try {
        checkJustification(dep, j);
      } catch {
        return fail('ErrIssuanceReason');
      }
    }
    try {
      checkMintData(dep, genesis.data);
    } catch {
      return fail('ErrIssuanceData');
    }
  }

  public async verify(transaction: CertifiedMintTransaction): Promise<VerificationResult<VerificationStatus>> {
    this.lastError = null;
    try {
      this.check(transaction);
      return new VerificationResult('BridgedTokenIssuancePolicy', VerificationStatus.OK);
    } catch (e) {
      this.lastError = reasonOf(e);
      return new VerificationResult('BridgedTokenIssuancePolicy', VerificationStatus.FAIL, this.lastError ?? String(e));
    }
  }
}

/**
 * `ITokenVerifier` for the SDK seam: the SDK's ordinary verification composed with the strict
 * bridge verification. The caller's context must carry the same pinned trust base.
 */
export class NativeBridgeTokenVerifier implements ITokenVerifier {
  public lastError: NativeReason | null = null;

  public constructor(
    private readonly bridge: NativeBridge,
    private readonly expect: Expect = 'receipt',
  ) {}

  public async verify(token: Token, context: IVerificationContext): Promise<VerificationResult<VerificationStatus>> {
    this.lastError = null;
    try {
      if (!sameBase(context.trustBase, await this.bridge.trust.authority())) fail('ErrTrustBase');
      await this.bridge.verifyNativeToken(token, this.expect, {
        predicateVerifier: context.predicateVerifier,
        unicityCertificateVerifier: context.unicityCertificateVerifier,
      });
      return new VerificationResult('NativeBridgeTokenVerification', VerificationStatus.OK);
    } catch (e) {
      this.lastError = reasonOf(e);
      return new VerificationResult('NativeBridgeTokenVerification', VerificationStatus.FAIL, this.lastError ?? String(e));
    }
  }
}
