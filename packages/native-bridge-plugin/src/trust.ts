/**
 * Trust input: the network's Unicity Trust Base history, installed from a release bundle (tag 39015: the genesis entry and every later entry,
 * each witnessed by its predecessor's committee) and pinned by the EntryID of its genesis entry.
 *
 * `trustBaseId` is that genesis EntryID: a lock proof and every manifest entry name it, and a history is the same trust input exactly when it
 * has the same network and genesis. Each certificate is verified by the SDK against the committee of its own epoch (weighted quorum, the native
 * B1 seal rule, the epoch's round interval); a certificate of an epoch newer than the latest held entry is `ErrNoEntryForEpoch`, retryable once
 * the history holds the newer entries (fetched by the wallet, never by the plug-in).
 */
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { TrustBaseError } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseError.js';
import { TrustBaseHistory } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseHistory.js';
import type { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { CertificateVerificationResult } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/CertificateVerdict.js';
import { UnicityCertificateVerifier } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/UnicityCertificateVerifier.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
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
    let history: TrustBaseHistory;
    try {
      history = await TrustBaseHistory.fromBundle(bundle, pin);
    } catch (e) {
      return fail(e instanceof TrustBaseError && e.reason === 'genesis' ? 'ErrTrustBaseDigest' : 'ErrTrustBase');
    }
    return new TrustInput(history, pin.slice());
  }

  public get network(): NetworkId {
    return this.history.networkId;
  }

  /** The history to verify against. */
  public async authority(): Promise<TrustBaseHistory> {
    return this.history;
  }

  /**
   * Verify an embedded certificate with the SDK's certificate verifier for its own partition (the EVM partition pin is the caller's):
   * native format and structure, the tree path to the seal hash, and the seal under its epoch's committee (B1 rule).
   */
  public async verifyEmbeddedUc(uc: UnicityCertificate): Promise<void> {
    preflightUc(uc.toCBOR());
    if (!uc.unicitySeal.networkId.equals(this.history.networkId)) fail('ErrSealNetwork');
    const verifier = new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier()));
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
  if (CertificateVerificationResult.findMissingEpoch(r)) return 'ErrNoEntryForEpoch';
  const walk = (x: VerificationResult<unknown>): NativeReason | null => {
    if (String(x.status) !== String(VerificationStatus.OK)) {
      const verdict = (x as { verdict?: string }).verdict;
      switch (x.rule) {
        case 'UnicityCertificateFormatRule':
        case 'UnicityCertificateStructureRule': return 'ErrCertStructure';
        case 'UnicitySealHashMatchesWithRootHashRule': return 'ErrSealRoot';
        // the seal's network, epoch or round interval against the held history (network is checked before, by the caller)
        case 'UnicitySealAuthorityRule': return 'ErrSealEpoch';
        // a malformed signature map (format bounds) is a structure failure, as natively
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
