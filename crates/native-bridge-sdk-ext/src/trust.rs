//! Trust input: the network's Unicity Trust Base history, installed from a release bundle (tag
//! 39015: the genesis entry and every later entry, each witnessed by its predecessor's committee)
//! and pinned by the EntryID of its genesis entry.
//!
//! `trustBaseId` is that genesis EntryID: a lock proof and every manifest entry name it, and a
//! history is the same trust input exactly when it has the same network and genesis. Each
//! certificate is verified by the SDK against the committee of its own epoch (weighted quorum, the
//! native B1 seal rule, the epoch's round interval); a certificate of an epoch newer than the
//! latest held entry is [`NativeError::NoEntryForEpoch`](crate::NativeError::NoEntryForEpoch),
//! retryable once the history holds the newer entries (fetched by the wallet, never by the
//! plug-in).

use unicity_token::api::bft::{HistoryError, TrustBaseHistory, UnicityCertificate};
use unicity_token::api::NetworkId;
use unicity_token::verify::{verify_certificate_of_partition, SealSession, VerificationError};

use crate::error::{NativeError as E, Result};

/// The installed trust: the held SDK history and its genesis EntryID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustInput {
    history: TrustBaseHistory,
    id: [u8; 32],
}

impl TrustInput {
    /// Install a release bundle: complete (no continuation), contiguous from its genesis, every
    /// link witnessed by the predecessor's quorum, and its genesis EntryID equal to the pin.
    pub fn from_bundle(bundle: &[u8], pin: &[u8; 32]) -> Result<Self> {
        let history = TrustBaseHistory::from_bundle(bundle, Some(*pin)).map_err(|e| match e {
            HistoryError::PinMismatch => E::TrustBaseDigest,
            _ => E::TrustBase,
        })?;
        Ok(TrustInput { history, id: *pin })
    }

    /// The held history (the wallet appends newer entries to its own copy and reinstalls).
    pub fn history(&self) -> &TrustBaseHistory {
        &self.history
    }

    pub fn network_id(&self) -> NetworkId {
        self.history.network_id()
    }

    /// The genesis EntryID: the value a lock proof's `trustBaseId` and the manifest pin must equal.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
}

/// The SDK's certificate verification of the embedded EVM certificate for its own partition (the
/// EVM partition, shard and configuration pins are the caller's): native structure, the recomputed
/// unicity-tree root equals the seal hash, and the seal under its epoch's committee and interval
/// with the native (B1) rule, where an unknown signer or an invalid signature fails the seal.
pub fn verify_embedded_uc(input: &TrustInput, uc: &UnicityCertificate) -> Result<()> {
    crate::resources::preflight_uc(&uc.to_cbor())?;
    if uc.unicity_seal.network_id != input.network_id() {
        return Err(E::SealNetwork);
    }
    let mut session = SealSession::new(input.history());
    // the policy only namespaces the session's memo, which lives for this call alone
    verify_certificate_of_partition(
        &mut session,
        uc,
        uc.unicity_tree_certificate.partition_identifier,
        &[0; 32],
    )
    .map_err(|e| certificate_failure(&e).unwrap_or(E::CertStructure))
}

/// The sentinel of a certificate failure, as the TypeScript projection names it: an epoch newer
/// than the latest held entry is retryable; the seal's epoch and interval, network, tree root and
/// quorum keep their own names; malformed material and native structure failures are
/// [`E::CertStructure`]. `None` for an error that is not a certificate failure.
pub fn certificate_failure(e: &VerificationError) -> Option<E> {
    Some(match e {
        VerificationError::UnknownTrustEpoch { .. } => E::NoEntryForEpoch,
        VerificationError::EpochBeforeGenesis
        | VerificationError::SealBeforeEpochStart
        | VerificationError::SealAfterAuthorityEnd => E::SealEpoch,
        VerificationError::SealNetworkMismatch => E::SealNetwork,
        VerificationError::SealRootMismatch => E::SealRoot,
        VerificationError::QuorumNotMet | VerificationError::SealSignerInvalid => E::QuorumNotMet,
        VerificationError::SealMalformed
        | VerificationError::CertificateBodyInvalid
        | VerificationError::PartitionMismatch => E::CertStructure,
        _ => return None,
    })
}
