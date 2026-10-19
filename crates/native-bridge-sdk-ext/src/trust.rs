//! Trust input: one explicitly provisioned, fixed SDK trust base, used as is.
//!
//! **Supported profile (design v2).** Unit-weight validators, one fixed epoch/committee, quorum
//! `N - (N-1)/3` (equal to the SDK's weighted `floor(2W/3)+1` for unit weights). Epoch changes,
//! appended trust-base records, newer bases fetched by the caller, arbitrary weights and retained
//! historical authority are common SDK work tracked in ristik/bft-core#421 and are **DEFERRED /
//! unsupported** here. Unsupported configurations are rejected at installation, never flattened
//! into unit weights.
//!
//! `trustBaseId = SHA256(B)` where `B` is the exact bytes of the pinned SDK JSON document
//! (`UTF8(JSON.stringify(RootTrustBase.fromJSON(source).toJSON()))` of the JS SDK 3.0.1). The
//! identifier hashes the installed original bytes, never a reconstructed Rust object. The
//! document becomes the genesis entry of a one-entry SDK [`TrustBaseHistory`], as the JS SDK's
//! `RootTrustBaseV2.genesisFromLegacy` does, and every certificate is verified against it.

use alloc::vec;

use unicity_token::api::bft::{TrustBaseEntry, TrustBaseHistory, UnicityCertificate};
use unicity_token::api::NetworkId;
use unicity_token::verify::{verify_certificate_of_partition, SealSession, VerificationError};

use crate::error::{NativeError as E, Result};
#[cfg(feature = "host")]
use crate::profile::h;

/// The installed trust: the SDK history (one genesis entry) and the digest of the exact document
/// that defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustInput {
    history: TrustBaseHistory,
    id: [u8; 32],
}

/// Reject any configuration outside the fixed unit-weight profile.
pub fn check_fixed_profile(entry: &TrustBaseEntry) -> Result<()> {
    entry.validate().map_err(|_| E::UnsupportedTrustBase)?;
    let n = entry.members.len() as u64;
    if n == 0
        || entry.members.iter().any(|m| m.weight != 1)
        || entry.quorum_threshold != n - (n - 1) / 3
    {
        return Err(E::UnsupportedTrustBase);
    }
    Ok(())
}

/// The genesis entry of a version-1 SDK JSON trust document, field for field as the JS SDK's
/// `RootTrustBaseV2.genesisFromLegacy`: zero previous identity, no signatures, the document's
/// threshold, members in document order, an empty hash read as absent.
#[cfg(feature = "host")]
fn genesis_of_json(text: &str) -> Option<TrustBaseEntry> {
    use alloc::vec::Vec;
    use serde_json::Value;
    use unicity_token::api::bft::TrustBaseMember;
    use unicity_token::crypto::signature::PublicKey;
    let v: Value = serde_json::from_str(text).ok()?;
    let num = |x: &Value| -> Option<u64> {
        match x {
            Value::String(s) => s.parse().ok(),
            Value::Number(n) => n.as_u64(),
            _ => None,
        }
    };
    let hash = |x: &Value| -> Option<Option<Vec<u8>>> {
        match x {
            Value::Null => Some(None),
            Value::String(s) => crate::profile::from_hex(s).map(Some),
            _ => None,
        }
    };
    if num(v.get("version")?)? != 1 {
        return None;
    }
    let network = NetworkId::new(u16::try_from(num(v.get("networkId")?)?).ok()?).ok()?;
    let mut members = Vec::new();
    for n in v.get("rootNodes")?.as_array()? {
        let key =
            PublicKey::from_bytes(&crate::profile::from_hex(n.get("sigKey")?.as_str()?)?).ok()?;
        members.push(TrustBaseMember::new(
            n.get("nodeId")?.as_str()?,
            key,
            num(n.get("stake")?)?,
        ));
    }
    Some(TrustBaseEntry::new(
        network,
        num(v.get("epoch")?)?,
        num(v.get("epochStartRound")?)?,
        members,
        num(v.get("quorumThreshold")?)?,
        hash(v.get("stateHash")?)?,
        hash(v.get("changeRecordHash")?)?,
        [0; 32],
    ))
}

impl TrustInput {
    /// Load the pinned document: the digest of the exact bytes must equal the pin, the document must
    /// parse as an SDK trust base, and the configuration must be in the fixed profile.
    #[cfg(feature = "host")]
    pub fn from_json(document: &[u8], pinned_id: &[u8; 32]) -> Result<Self> {
        let id = h(document);
        if &id != pinned_id {
            return Err(E::TrustBaseDigest);
        }
        let text = core::str::from_utf8(document).map_err(|_| E::TrustBase)?;
        let entry = genesis_of_json(text).ok_or(E::TrustBase)?;
        Self::from_provisioned(entry, id)
    }

    /// Alloc-only provisioning from an SDK genesis entry. The caller must have bound `entry` to the
    /// document whose SHA-256 is `document_id` (for example by loading the same bytes with the
    /// host loader at provisioning time); an independently asserted object/ID pair is never
    /// trustworthy.
    pub fn from_provisioned(entry: TrustBaseEntry, document_id: [u8; 32]) -> Result<Self> {
        check_fixed_profile(&entry)?;
        // authenticated by the document digest, not by a witness: a chain of one trusted entry
        let history = TrustBaseHistory::from_trusted_chain(vec![entry])
            .map_err(|_| E::UnsupportedTrustBase)?;
        Ok(TrustInput {
            history,
            id: document_id,
        })
    }

    /// The SDK history every certificate is verified against.
    pub fn history(&self) -> &TrustBaseHistory {
        &self.history
    }

    /// The one entry of the fixed profile.
    pub fn base(&self) -> &TrustBaseEntry {
        self.history.genesis()
    }

    pub fn network_id(&self) -> NetworkId {
        self.history.network_id()
    }

    /// `SHA256(B)`: the value a lock proof's `trustBaseId` and the manifest pin must equal.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Scope guards of the fixed profile for any certificate (ordinary or embedded): the seal's
    /// network and epoch equal the pinned base and its root round is at least `epochStartRound`.
    /// These reject use outside the profile; they implement no epoch evolution.
    pub fn check_guards(&self, uc: &UnicityCertificate) -> Result<()> {
        let seal = &uc.unicity_seal;
        let base = self.base();
        if seal.network_id != base.network_id {
            return Err(E::SealNetwork);
        }
        if seal.epoch != base.epoch {
            return Err(E::EpochMismatch);
        }
        if seal.root_chain_round_number < base.epoch_start {
            return Err(E::RoundBeforeEpochStart);
        }
        Ok(())
    }
}

/// The SDK's certificate verification of the embedded EVM certificate for its own partition (the
/// EVM partition, shard and configuration pins are the caller's): native structure, the recomputed
/// unicity-tree root equals the seal hash, and the seal under its epoch's committee with the native
/// (B1) rule, where an unknown signer or an invalid signature fails the seal.
pub fn verify_embedded_uc(input: &TrustInput, uc: &UnicityCertificate) -> Result<()> {
    crate::resources::preflight_uc(&uc.to_cbor())?;
    input.check_guards(uc)?;
    let mut session = SealSession::new(input.history());
    // the policy only namespaces the session's memo, which lives for this call alone
    verify_certificate_of_partition(
        &mut session,
        uc,
        uc.unicity_tree_certificate.partition_identifier,
        &[0; 32],
    )
    .map_err(|e| embedded_failure(&e))
}

/// The sentinel of an embedded-certificate failure, as the TypeScript projection names it.
fn embedded_failure(e: &VerificationError) -> E {
    match e {
        VerificationError::SealRootMismatch => E::SealRoot,
        VerificationError::SealNetworkMismatch => E::SealNetwork,
        VerificationError::QuorumNotMet | VerificationError::SealSignerInvalid => E::QuorumNotMet,
        _ => E::CertStructure,
    }
}
