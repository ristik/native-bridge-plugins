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
import { TokenIssuanceVerifierService } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/TokenIssuanceVerifierService.js';
import { VerificationContext } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/VerificationContext.js';
import type { WalletIssuancePolicy } from '@unicitylabs/bridge-core';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { eq, toHex } from './bytes.js';
import type { Deployment, DeploymentRegistry } from './deployment.js';
import { NativeError, fail, type NativeReason } from './errors.js';
import { decodeHistory, checkJustification, checkMintData, projectToken, verifyHistory, type Leaf, type Outcome } from './history.js';
import { MAX_PATH_STEPS, MAX_TOKEN_BYTES, MAX_TRANSFERS, TAG_MINT_LOCK } from './limits.js';
import { parseJustification, verifyLockProof, type Justification, type VerifiedLock } from './lockproof.js';
import { H, deriveSalt, deriveTokenId, lockDigest, lockRecord } from './profile.js';
import type { TrustInput } from './trust.js';

export type Expect = 'receipt' | 'return';

export interface VerifiedToken {
  outcome: Outcome;
  lock: VerifiedLock;
  /** Index of the allow-listed deployment the token was verified under. */
  deployment: number;
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
    if (x.rule === 'UnicitySealHashMatchesWithRootHashRule' && String(x.status) === String(VerificationStatus.FAIL)) return 'ErrSealRoot';
    if (x.rule === 'UnicitySealQuorumSignaturesVerificationRule' && String(x.status) === String(VerificationStatus.FAIL)) return 'ErrQuorumNotMet';
    if (x.rule === 'UnicitySealNetworkMatchesTrustBaseRule' && String(x.status) === String(VerificationStatus.FAIL)) return 'ErrSealNetwork';
    for (const c of x.results) {
      const m = walk(c);
      if (m) return m;
    }
    return null;
  };
  return walk(r) ?? 'ErrSdkVerification';
}

function sameBase(a: IVerificationContext['trustBase'], b: IVerificationContext['trustBase']): boolean {
  return JSON.stringify(a.toJSON()) === JSON.stringify(b.toJSON());
}

export class NativeBridge {
  public constructor(
    public readonly registry: DeploymentRegistry,
    public readonly trust: TrustInput,
  ) {
    for (const d of registry.deployments) {
      if (d.cfg.network !== trust.base.networkId.id) fail('ErrNetworkMismatch');
    }
  }

  /** The SDK verification context with this bridge's justification verifier and issuance policies. */
  public context(base?: Partial<Pick<IVerificationContext, 'predicateVerifier' | 'unicityCertificateVerifier'>>): VerificationContext {
    const mjvs = new MintJustificationVerifierService().register(new NativeLockJustificationVerifier(this));
    const tiv = new TokenIssuanceVerifierService(true);
    for (const ty of this.registry.tokenTypes) tiv.register(new BridgedTokenIssuancePolicy(this, ty));
    return new VerificationContext(
      this.trust.base,
      base?.predicateVerifier ?? PredicateVerifierService.create(),
      base?.unicityCertificateVerifier ??
        new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier())),
      mjvs,
      tiv,
    );
  }

  /** Decode canonical token bytes (bounded, re-encoding equal) and verify them. */
  public async verifyNativeTokenBytes(bytes: Uint8Array, expect: Expect): Promise<VerifiedToken> {
    if (bytes.length > MAX_TOKEN_BYTES) fail('ErrInputTooLarge');
    let token: Token;
    try {
      token = await Token.fromCBOR(bytes);
    } catch {
      return fail('ErrSdkDecode');
    }
    if (!eq(token.toCBOR(), bytes)) fail('ErrNonCanonical');
    return this.verifyNativeToken(token, expect);
  }

  public async verifyNativeToken(token: Token, expect: Expect, parts?: Partial<Pick<IVerificationContext, 'predicateVerifier' | 'unicityCertificateVerifier'>>): Promise<VerifiedToken> {
    if (token.transactions.length > MAX_TRANSFERS) fail('ErrTooManyTx');
    const g = token.genesis;
    // The generic data hook skips null data, so missing genesis data/justification is explicit here.
    if (g.justification === null) fail('ErrMintJustif');
    if (g.data === null) fail('ErrMintData');
    let parsed: Justification;
    try {
      parsed = parseJustification(g.justification as Uint8Array);
    } catch (e) {
      const r = reasonOf(e);
      return fail(r === 'ErrInputTooLarge' || r === 'ErrProofTooLarge' || r === 'ErrTooDeep' || r === 'ErrTooManyItems' ? r : 'ErrMintJustif');
    }
    const index = this.registry.index(g.networkId.id, parsed.chainId, parsed.vault);
    const dep = this.registry.deployments[index];

    const hist = decodeHistory(projectToken(token));
    const outcome = await verifyHistory(dep, hist, expect === 'return');
    const lock = await verifyLockProof(dep, this.trust, parsed, outcome.lockDigest);

    // Bridge-specific checks per leaf: fixed-profile guards, aggregator admission, path budget, t <= IR.
    const steps = { n: 0 };
    const all = [g, ...token.transactions];
    for (let i = 0; i < all.length; i++) await this.checkLeaf(dep, all[i].inclusionProof, outcome.leaves[i], steps);

    // The SDK's own ordinary verification, with the same base throughout.
    const r = await new TokenVerifier().verify(token, this.context(parts));
    if (r.status !== VerificationStatus.OK) fail(mapSdkFailure(r));
    return { outcome, lock, deployment: index };
  }

  private async checkLeaf(dep: Deployment, proof: CertifiedMintTransaction['inclusionProof'], leaf: Leaf, steps: { n: number }): Promise<void> {
    const uc = proof.unicityCertificate;
    if (proof.referenceTime !== leaf.referenceTime) fail('ErrCDMismatch');
    const sid = await StateId.fromCertificationData(proof.certificationData);
    if (!eq(sid.data, leaf.sid) || !eq(proof.certificationData.transactionHash.data, leaf.txHash)) fail('ErrCDMismatch');
    this.trust.checkGuards(uc);
    // Aggregator admission against the pinned one-shard policy, never the certificate's own tuple.
    if (uc.unicityTreeCertificate.partitionIdentifier !== BigInt(dep.policy.partition) || !eq(uc.shardConfigurationHash, dep.policy.shardConf)) {
      fail('ErrNotAdmitted');
    }
    if (uc.shardTreeCertificate.shard.length !== 0) fail('ErrShardMismatch');
    steps.n += (proof.inclusionCertificate.encode().length - 32) / 32;
    if (steps.n > MAX_PATH_STEPS) fail('ErrTooManyPaths');
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
    let parsed: Justification;
    try {
      parsed = parseJustification(j as Uint8Array);
    } catch (e) {
      const r = reasonOf(e);
      return fail(r === 'ErrInputTooLarge' || r === 'ErrProofTooLarge' || r === 'ErrTooDeep' || r === 'ErrTooManyItems' ? r : 'ErrMintJustif');
    }
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
 * envelope, no split exception, no null or unknown reason.
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
    let dep: Deployment;
    try {
      const p = parseJustification(j as Uint8Array);
      dep = this.bridge.registry.find(genesis.networkId.id, p.chainId, p.vault);
    } catch {
      return fail('ErrIssuanceReason');
    }
    if (!eq(genesis.tokenType.bytes, this.tokenType.bytes) || !eq(dep.cfg.ty, this.tokenType.bytes)) fail('ErrMintType');
    try {
      checkJustification(dep, j);
    } catch {
      return fail('ErrIssuanceReason');
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
      if (!sameBase(context.trustBase, this.bridge.trust.base)) fail('ErrTrustBase');
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
