/**
 * Trust input: the network's Unicity Trust Base history, installed from a release bundle (tag 39015: the genesis entry and every later entry,
 * each witnessed by its predecessor's committee) and pinned by the EntryID of its genesis entry.
 *
 * `trustBaseId` is that genesis EntryID: a lock proof and every manifest entry name it, and a history is the same trust input exactly when it
 * has the same network and genesis. Each certificate is verified by the SDK against the committee of its own epoch (weighted quorum, the upstream
 * seal rule: each signature counts alone, an unknown signer or a signature that is not an exact recoverable one of its member counts zero;
 * the epoch's round interval); a certificate of an epoch newer than the latest held entry is `ErrNoEntryForEpoch`, retryable once
 * the history holds the newer entries (fetched by the wallet, never by the plug-in).
 */
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { TRUST_BASE_BUNDLE_LIMITS } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/ReleasePin.js';
import { TrustBaseBundle } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseBundle.js';
import { TrustBaseHistory } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseHistory.js';
import type { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { UnicityCertificateVerifier } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/UnicityCertificateVerifier.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { UnicitySealTrustBaseEntryRule } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealTrustBaseEntryRule.js';
import { findNoTrustBaseEntry } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/TrustBaseEntryResult.js';
import { Secp256k1SignatureVerifier } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Secp256k1SignatureVerifier.js';
import type { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { preflightUc } from './resources.js';
import { fail, type NativeReason } from './errors.js';

export class TrustInput {
  private constructor(
    /** The held history; the wallet appends newer entries to it (each verified from its predecessor), never replaces held ones. */
    public readonly history: TrustBaseHistory,
    /** The genesis EntryID: the value a lock proof's `trustBaseId` and the manifest pin must equal. */
    public readonly id: Uint8Array,
  ) {}

  /**
   * Install a release bundle: complete (no continuation), contiguous from its genesis, every link witnessed by the predecessor's quorum, and
   * its genesis EntryID equal to the pin.
   */
  public static async fromBundle(bundle: Uint8Array, pin: Uint8Array): Promise<TrustInput> {
    let decoded: TrustBaseBundle;
    try {
      decoded = await TrustBaseBundle.decode(bundle, TRUST_BASE_BUNDLE_LIMITS);
    } catch {
      return fail('ErrTrustBase');
    }
    // the pin is the genesis EntryID: a bundle of another genesis is a digest failure, any other defect of the chain is a trust base failure
    const genesis = decoded.entries[0];
    if (genesis === undefined) return fail('ErrTrustBase');
    const id = await genesis.entryId();
    if (id.length !== pin.length || id.some((b, i) => b !== pin[i])) return fail('ErrTrustBaseDigest');
    let history: TrustBaseHistory;
    try {
      history = await TrustBaseHistory.fromBundle(decoded, pin);
    } catch {
      return fail('ErrTrustBase');
    }
    return new TrustInput(history, pin.slice());
  }

  public get network(): NetworkId {
    // a history installed from a bundle is never empty
    return this.history.networkId ?? fail('ErrTrustBase');
  }

  /** The history to verify against. */
  public async authority(): Promise<TrustBaseHistory> {
    return this.history;
  }

  /**
   * Select the committee of the certificate's seal epoch (protocol/trust-base.md steps 1-4, before any structure, root or signature check, as
   * the oracle orders them): another network `ErrSealNetwork`, an epoch newer than the latest held `ErrNoEntryForEpoch`, before the genesis or
   * outside the epoch's round interval `ErrSealEpoch`.
   */
  public selectEpoch(uc: UnicityCertificate): void {
    if (!uc.unicitySeal.networkId.equals(this.network)) fail('ErrSealNetwork');
    const entry = UnicitySealTrustBaseEntryRule.verify(this.history, uc.unicitySeal);
    if (entry.status !== VerificationStatus.OK) fail(findNoTrustBaseEntry(entry) !== null ? 'ErrNoEntryForEpoch' : 'ErrSealEpoch');
  }

  /**
   * Verify an embedded certificate with the SDK's certificate verifier for its own partition (the EVM partition pin is the caller's): the seal
   * epoch's committee first ({@link selectEpoch}), then native format and structure, the tree path to the seal hash, and the seal under that
   * committee (the upstream seal rule).
   */
  public async verifyEmbeddedUc(uc: UnicityCertificate): Promise<void> {
    preflightUc(uc.toCBOR());
    this.selectEpoch(uc);
    // the B1 profile bounds the supplied signatures at 16 (ErrTooManySigs)
    const verifier = new UnicityCertificateVerifier(
      new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier(), undefined, { maxSignatures: 16 }),
    );
    const r = await verifier.verifyCertificate(this.history, uc, { partitionId: uc.unicityTreeCertificate.partitionIdentifier });
    if (r.status !== VerificationStatus.OK) fail(certificateFailure(r) ?? 'ErrQuorumNotMet');
  }
}

/**
 * The sentinel of a failed certificate verification, from its verdict class and failing rule: an epoch newer than the latest held entry is
 * retryable (`ErrNoEntryForEpoch`); malformed material and native structure failures are `ErrCertStructure`; the seal's epoch and interval
 * (`ErrSealEpoch`), tree root and quorum keep their own names. Null when no certificate rule failed.
 */
export function certificateFailure(r: VerificationResult<unknown>): NativeReason | null {
  if (findNoTrustBaseEntry(r) !== null) return 'ErrNoEntryForEpoch';
  const walk = (x: VerificationResult<unknown>): NativeReason | null => {
    if (String(x.status) !== String(VerificationStatus.OK)) {
      const verdict = (x as { verdict?: string }).verdict;
      switch (x.rule) {
        case 'UnicityCertificateFormatRule':
        case 'UnicityCertificateStructureRule': return 'ErrCertStructure';
        case 'UnicitySealHashMatchesWithRootHashRule': return 'ErrSealRoot';
        // the seal's network, epoch or round interval against the held history (network is checked before, by the caller)
        case 'UnicitySealTrustBaseEntryRule': return 'ErrSealEpoch';
        // a malformed signature map (count and identifier bounds) is a structure failure, as natively; a signature that does not count is not one
        case 'UnicitySealQuorumSignaturesVerificationRule': return verdict === 'malformed' ? 'ErrCertStructure' : 'ErrQuorumNotMet';
        default:
      }
    }
    for (const c of x.results) {
      const m = walk(c);
      if (m) return m;
    }
    return null;
  };
  return walk(r);
}
