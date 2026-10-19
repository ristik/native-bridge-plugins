/**
 * Trust input: one explicitly provisioned, fixed SDK `RootTrustBase`, used as is.
 *
 * Supported profile (design v2): unit-weight validators, one fixed epoch/committee, SDK count
 * quorum `N - (N-1)/3`. Epoch changes, appended trust-base records, newer bases fetched by the
 * caller, arbitrary weights and retained historical authority are common SDK work (ristik/bft-core#421)
 * and are DEFERRED / unsupported here; unsupported configurations are rejected at installation.
 *
 * `trustBaseId = SHA256(B)` for the exact bytes `B` of the pinned SDK JSON document
 * (`UTF8(JSON.stringify(RootTrustBase.fromJSON(source).toJSON()))`). The bytes are hashed as
 * installed, never a reconstructed object.
 */
import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { RootTrustBaseV2 } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseHistory } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseHistory.js';
import type { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { UnicityCertificateVerifier } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/UnicityCertificateVerifier.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { Secp256k1SignatureVerifier } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import type { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { preflightUc } from './resources.js';
import { eq } from './bytes.js';
import { fail, type NativeReason } from './errors.js';
import { H } from './profile.js';

/** Reject any configuration outside the fixed unit-weight profile. */
export function checkFixedProfile(tb: RootTrustBase): void {
  const nodes = [...tb.rootNodes.values()];
  const n = BigInt(nodes.length);
  if (n === 0n || tb.version !== 1n || nodes.some((x) => x.stakedAmount !== 1n) || tb.quorumThreshold !== n - (n - 1n) / 3n) {
    fail('ErrUnsupportedTrustBase');
  }
}

export class TrustInput {
  private history: Promise<TrustBaseHistory> | null = null;

  private constructor(
    public readonly base: RootTrustBase,
    public readonly id: Uint8Array,
  ) {}

  /** Load the pinned document: exact-bytes digest equals the pin, SDK parse, fixed profile. */
  public static fromJson(document: Uint8Array, pinnedId: Uint8Array): TrustInput {
    const id = H(document);
    if (!eq(id, pinnedId)) fail('ErrTrustBaseDigest');
    let base: RootTrustBase;
    try {
      base = RootTrustBase.fromJSON(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(document)));
    } catch {
      return fail('ErrTrustBase');
    }
    checkFixedProfile(base);
    return new TrustInput(base, id);
  }

  /**
   * The SDK trust-base history this input verifies against: the version-2 genesis of the pinned document, built once. The document's
   * digest pin authenticates it; its genesis EntryID is derived here, not supplied.
   */
  public authority(): Promise<TrustBaseHistory> {
    this.history ??= (async (): Promise<TrustBaseHistory> => {
      const genesis = RootTrustBaseV2.genesisFromLegacy(this.base);
      return TrustBaseHistory.fromLegacyGenesis(this.base, await genesis.entryId());
    })();
    return this.history;
  }

  /**
   * Scope guards of the fixed profile for any certificate: the seal's network and epoch equal the
   * pinned base and its root round is at least `epochStartRound`. They reject use outside the
   * profile; they implement no epoch evolution.
   */
  public checkGuards(uc: UnicityCertificate): void {
    const seal = uc.unicitySeal;
    if (!seal.networkId.equals(this.base.networkId)) fail('ErrSealNetwork');
    if (seal.epoch !== this.base.epoch) fail('ErrEpochMismatch');
    if (seal.rootChainRoundNumber < this.base.epochStartRound) fail('ErrRoundBeforeEpochStart');
  }

  /**
   * Verify an embedded certificate with the SDK's certificate verifier for its own partition (the EVM partition pin is the caller's):
   * native format and structure, the tree path to the seal hash, and the seal under its epoch's committee (B1 rule).
   */
  public async verifyEmbeddedUc(uc: UnicityCertificate): Promise<void> {
    preflightUc(uc.toCBOR());
    this.checkGuards(uc);
    const verifier = new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier()));
    const r = await verifier.verifyCertificate(await this.authority(), uc, { partitionId: uc.unicityTreeCertificate.partitionIdentifier });
    if (r.status !== VerificationStatus.OK) fail(embeddedFailure(r));
  }
}

/** The sentinel of the first failing rule of an embedded-certificate verification. */
function embeddedFailure(r: VerificationResult<unknown>): NativeReason {
  const walk = (x: VerificationResult<unknown>): NativeReason | null => {
    if (String(x.status) !== String(VerificationStatus.OK)) {
      switch (x.rule) {
        case 'UnicityCertificateFormatRule':
        case 'UnicityCertificateStructureRule': return 'ErrCertStructure';
        case 'UnicitySealHashMatchesWithRootHashRule': return 'ErrSealRoot';
        // a malformed signature map (format bounds) is a structure failure, as natively; a valid map short of quorum is not
        case 'UnicitySealQuorumSignaturesVerificationRule': return (x as { verdict?: string }).verdict === 'malformed' ? 'ErrCertStructure' : 'ErrQuorumNotMet';
        default:
      }
    }
    for (const c of x.results) {
      const m = walk(c);
      if (m) return m;
    }
    return null;
  };
  return walk(r) ?? 'ErrQuorumNotMet';
}
