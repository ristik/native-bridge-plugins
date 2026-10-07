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
import type { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { UnicitySealHashMatchesWithRootHashRule } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealHashMatchesWithRootHashRule.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { Secp256k1SignatureVerifier } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { eq } from './bytes.js';
import { fail } from './errors.js';
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
   * Verify an embedded certificate with the SDK's existing UC rules. `UnicityCertificateVerifier`
   * takes an inclusion proof, so its two constituent public rules are called directly.
   */
  public async verifyEmbeddedUc(uc: UnicityCertificate): Promise<void> {
    this.checkGuards(uc);
    if ((await UnicitySealHashMatchesWithRootHashRule.verify(uc)).status !== VerificationStatus.OK) fail('ErrSealRoot');
    const rule = new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier());
    if ((await rule.verify(this.base, uc.unicitySeal)).status !== VerificationStatus.OK) fail('ErrQuorumNotMet');
  }
}
