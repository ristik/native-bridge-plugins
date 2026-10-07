//! Trust input: one explicitly provisioned, fixed SDK `RootTrustBase`, used as is.
//!
//! **Supported profile (design v2).** Unit-weight validators, one fixed epoch/committee, SDK count
//! quorum `N - (N-1)/3`. Epoch changes, appended trust-base records, newer bases fetched by the
//! caller, arbitrary weights and retained historical authority are common SDK work tracked in
//! ristik/bft-core#421 and are **DEFERRED / unsupported** here. Unsupported configurations are
//! rejected at installation, never flattened into unit weights.
//!
//! `trustBaseId = SHA256(B)` where `B` is the exact bytes of the pinned SDK JSON document
//! (`UTF8(JSON.stringify(RootTrustBase.fromJSON(source).toJSON()))` of the JS SDK 3.0.1). The
//! identifier hashes the installed original bytes, never a reconstructed Rust object.
//!
//! The Rust SDK's standalone certificate check is private, so [`verify_embedded_uc`] reproduces only
//! that SDK composition with public primitives for the embedded EVM certificate. Ordinary proofs
//! use the SDK's own verification. The helper can disappear when the SDK exposes it.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use unicity_token::api::bft::{RootTrustBase, UnicityCertificate};
use unicity_token::crypto::signature::Signature;

use crate::error::{NativeError as E, Result};
#[cfg(feature = "host")]
use crate::profile::h;

/// The installed trust: the SDK base and the digest of the exact document that defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustInput {
    base: RootTrustBase,
    id: [u8; 32],
}

/// Reject any configuration outside the fixed unit-weight profile.
pub fn check_fixed_profile(tb: &RootTrustBase) -> Result<()> {
    tb.validate().map_err(|_| E::UnsupportedTrustBase)?;
    let n = tb.root_nodes.len() as u64;
    if tb.version != 1
        || tb.root_nodes.iter().any(|node| node.stake != 1)
        || tb.quorum_threshold != n - (n - 1) / 3
    {
        return Err(E::UnsupportedTrustBase);
    }
    Ok(())
}

impl TrustInput {
    /// Load the pinned document: the digest of the exact bytes must equal the pin, the document must
    /// parse with the SDK loader, and the configuration must be in the fixed profile.
    #[cfg(feature = "host")]
    pub fn from_json(document: &[u8], pinned_id: &[u8; 32]) -> Result<Self> {
        let id = h(document);
        if &id != pinned_id {
            return Err(E::TrustBaseDigest);
        }
        let text = core::str::from_utf8(document).map_err(|_| E::TrustBase)?;
        let base = RootTrustBase::from_json(text).map_err(|_| E::TrustBase)?;
        check_fixed_profile(&base)?;
        Ok(TrustInput { base, id })
    }

    /// Alloc-only provisioning from SDK objects. The caller must have bound `base` to the document
    /// whose SHA-256 is `document_id` (for example by loading the same bytes with the SDK loader
    /// at provisioning time); an independently asserted object/ID pair is never trustworthy.
    pub fn from_provisioned(base: RootTrustBase, document_id: [u8; 32]) -> Result<Self> {
        check_fixed_profile(&base)?;
        Ok(TrustInput {
            base,
            id: document_id,
        })
    }

    pub fn base(&self) -> &RootTrustBase {
        &self.base
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
        if seal.network_id != self.base.network_id {
            return Err(E::SealNetwork);
        }
        if seal.epoch != self.base.epoch {
            return Err(E::EpochMismatch);
        }
        if seal.root_chain_round_number < self.base.epoch_start_round {
            return Err(E::RoundBeforeEpochStart);
        }
        Ok(())
    }
}

/// The SDK's certificate rule for the embedded EVM certificate: network, recomputed unicity-tree
/// root equals the seal hash, and at least `quorum_threshold` distinct valid root-node signatures
/// over the seal hash. Unknown or invalid signatures are skipped, as in the SDK.
pub fn verify_embedded_uc(input: &TrustInput, uc: &UnicityCertificate) -> Result<()> {
    crate::resources::preflight_uc(&uc.to_cbor())?;
    input.check_guards(uc)?;
    let tb = input.base();
    tb.validate().map_err(|_| E::TrustBase)?;
    let seal = &uc.unicity_seal;
    let computed = uc.computed_seal_hash().map_err(|_| E::SealRoot)?;
    if computed.data() != seal.hash.as_slice() {
        return Err(E::SealRoot);
    }
    let digest = seal.calculate_hash();
    let mut counted: BTreeSet<&str> = BTreeSet::new();
    let mut keys = Vec::new();
    for (node_id, sig) in &seal.signatures {
        if counted.contains(node_id.as_str()) {
            continue;
        }
        let Some(key) = tb.signing_key(node_id) else {
            continue;
        };
        if keys.contains(&key) {
            continue;
        }
        let Ok(sig) = Signature::decode(sig) else {
            continue;
        };
        if sig.verify(digest.data(), key) {
            counted.insert(node_id.as_str());
            keys.push(key);
        }
    }
    if (counted.len() as u64) < tb.quorum_threshold {
        return Err(E::QuorumNotMet);
    }
    Ok(())
}
