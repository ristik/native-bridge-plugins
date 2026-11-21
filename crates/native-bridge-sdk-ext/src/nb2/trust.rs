//! Historical authority (section 11.3; `trust.ts`, bft-core `nb2ref/trust.go`). The trust input is the network's Unicity Trust
//! Base history, installed from a release bundle and pinned by its genesis EntryID (`Γ.rootGenesis32`). Every UC is judged
//! under the entry of its own seal epoch by the upstream seal rule: an unknown signer or a signature that fails the weighting
//! rule counts zero, the weights reach floor(2W/3)+1 of that entry, and no legacy pre-scan rejects a seal for a signature's
//! length or recovery byte.

use unicity_token::api::bft::{ShardId, UnicityCertificate};
use unicity_token::cbor::{DecodeLimits, Decoder};
use unicity_token::verify::{verify_certificate_of_partition, SealSession};

use super::cbor::{array, is_bytes, is_uint, scan_native, tag_content};
use super::config::Config;
use super::errors::{fail, fail_d, refuse, wrap, Error, Nb2Error, Result, Rule, WalletReason};
use crate::error::NativeError;
pub use crate::trust::{AuthenticatedOrigin, TrustInput};

/// The B1 bound of one certificate's bytes (b1ref.MaxUCBytes).
pub const MAX_B1_UC_BYTES: usize = 24_576;
const MAX_B1_SIGNATURES: usize = 16;

/// The history must be the one Γ names: its genesis EntryID is rootGenesis32 and its network Γ's.
pub fn bind_trust(t: &TrustInput, c: &Config) -> Result<()> {
    if !t.origin().is_some_and(|origin| origin.root_round > 0) {
        return refuse(
            WalletReason::TrustInput,
            "an authenticated B1 origin is required",
        );
    }
    if t.id() != c.root_genesis || t.network_id().id() != c.network {
        return refuse(
            WalletReason::TrustInput,
            "the trust-base history is not the one Γ names",
        );
    }
    Ok(())
}

const TAG_UC: u64 = 39001;

struct SdkField {
    index: usize,
    arity: usize,
    required: usize,
    tag: u64,
    major: u8,
}

const SDK_FIELDS: [SdkField; 4] = [
    SdkField {
        index: 1,
        arity: 10,
        required: 5,
        tag: 39002,
        major: 2,
    },
    SdkField {
        index: 4,
        arity: 3,
        required: 2,
        tag: 39003,
        major: 4,
    },
    SdkField {
        index: 5,
        arity: 3,
        required: 2,
        tag: 39004,
        major: 4,
    },
    SdkField {
        index: 6,
        arity: 8,
        required: 7,
        tag: 39005,
        major: 5,
    },
];

/// The SDK codec subset of a certificate (field majors, seal network 1..65535, byte-string signatures), then the native scan.
fn scan_certificate(raw: &[u8]) -> Result<()> {
    if raw.len() > MAX_B1_UC_BYTES {
        return fail(Rule::InputTooLarge);
    }
    let root = scan_native(raw)?;
    let uc = array(tag_content(&root, TAG_UC)?, 7)?;
    for f in &SDK_FIELDS {
        let body = tag_content(&uc[f.index], f.tag)?;
        let k = array(body, f.arity)?;
        if k[f.required].major != f.major {
            return fail_d(Rule::Shape, alloc::format!("SDK field {}", f.index));
        }
    }
    let seal = &uc[6].kids[0].kids;
    if !is_uint(&seal[1]) || seal[1].arg == 0 || seal[1].arg > 65535 {
        return fail_d(Rule::Shape, "seal network");
    }
    let sigs = &seal[7].kids;
    if sigs.len() > 2 * MAX_B1_SIGNATURES {
        return fail_d(Rule::InputTooLarge, "seal signatures");
    }
    let mut i = 1;
    while i < sigs.len() {
        if !is_bytes(&sigs[i]) {
            return fail_d(Rule::Shape, "seal signature");
        }
        i += 2;
    }
    crate::resources::native_uc_scan(raw, MAX_B1_UC_BYTES)
        .map_err(|e| Error::Rule(Nb2Error::with_detail(Rule::Shape, e.name())))
}

/// The bounded certificate scan and the canonical decode; every failure is `UnsupportedCertificateEncoding`.
pub fn decode_uc(raw: &[u8]) -> Result<UnicityCertificate> {
    scan_certificate(raw).map_err(|e| wrap(Rule::UnsupportedCertificateEncoding, e))?;
    let uc = UnicityCertificate::from_cbor(Decoder::with_limits(raw, DecodeLimits::DEFAULT))
        .map_err(|e| {
            Error::Rule(Nb2Error::with_detail(
                Rule::UnsupportedCertificateEncoding,
                alloc::format!("{e:?}"),
            ))
        })?;
    if uc.to_cbor() != raw {
        return fail_d(Rule::UnsupportedCertificateEncoding, "noncanonical");
    }
    Ok(uc)
}

fn native_to_rule(e: NativeError) -> Rule {
    match e {
        NativeError::SealNetwork => Rule::SealNetwork,
        NativeError::NoEntryForEpoch => Rule::NoEntryForEpoch,
        NativeError::SealEpoch => Rule::SealEpoch,
        NativeError::CertStructure => Rule::CertStructure,
        NativeError::SealRoot => Rule::SealRoot,
        NativeError::QuorumNotMet => Rule::QuorumNotMet,
        _ => Rule::CertStructure,
    }
}

/// One UC for the expected partition and shard, in the order of bft-core `nb2ref` (after the NB2-05 UC order): the seal's
/// network (`SealNetwork`), the structure (`CertStructure`: partition, shard, input record, a 32-byte ShardConfHash), the shard
/// and unicity tree folds over the UC's own ShardConfHash to the seal hash (`SealRoot`), then the entry of the seal's epoch
/// (`NoEntryForEpoch`, `SealEpoch`) and the quorum under it (`QuorumNotMet`). No expected configuration hash is supplied.
pub fn uc_check(
    t: &TrustInput,
    uc: &UnicityCertificate,
    partition: u32,
    shard: &[u8],
) -> Result<()> {
    if uc.unicity_seal.network_id != t.network_id() {
        return fail(Rule::SealNetwork);
    }
    if uc.shard_configuration_hash.len() != 32 {
        return fail_d(Rule::CertStructure, "ShardConfHash is not 32 bytes");
    }
    if uc.shard_tree_certificate.shard.encode() != shard {
        return fail_d(Rule::CertStructure, "shard");
    }
    if uc.unicity_tree_certificate.partition_identifier != partition {
        return fail_d(Rule::CertStructure, "partition");
    }
    if uc.unicity_seal.signatures.len() > MAX_B1_SIGNATURES {
        return fail(Rule::UnsupportedCertificateEncoding);
    }
    let Some(origin) = t.origin().filter(|origin| origin.root_round > 0) else {
        return refuse(
            WalletReason::TrustInput,
            "an authenticated B1 origin is required",
        );
    };
    if uc.unicity_seal.epoch > origin.usable_epoch
        || uc.unicity_seal.root_chain_round_number > origin.root_round
    {
        return fail_d(Rule::SealEpoch, "seal exceeds the authenticated B1 origin");
    }
    let mut session = SealSession::new(t.history());
    verify_certificate_of_partition(
        &mut session,
        uc,
        uc.unicity_tree_certificate.partition_identifier,
        &[0; 32],
    )
    .map_err(|e| {
        let rule = crate::trust::certificate_failure(&e).map_or(Rule::QuorumNotMet, native_to_rule);
        Error::Rule(Nb2Error::with_detail(rule, alloc::format!("{e:?}")))
    })
}

/// A deposit or seal receipt's EVM certificate for exactly (Γ.evmPartition, Γ.evmShard). Every failure is `DepositUC` except
/// `NoEntryForEpoch`, which keeps its retryable name (carrying `DepositUC`, its on-chain name).
pub fn verify_evm_uc(t: &TrustInput, raw: &[u8], c: &Config) -> Result<UnicityCertificate> {
    let uc = decode_uc(raw).map_err(|e| wrap(Rule::DepositUC, e))?;
    if ShardId::decode(&c.evm_shard).is_err() {
        return fail_d(Rule::DepositUC, "Γ.evmShard");
    }
    match uc_check(t, &uc, c.evm_partition, &c.evm_shard) {
        Ok(()) => Ok(uc),
        Err(Error::Rule(e)) if e.rule == Rule::NoEntryForEpoch => Err(Error::Rule(Nb2Error {
            detail: e.detail,
            ..Nb2Error::wrapping(Rule::NoEntryForEpoch, Nb2Error::new(Rule::DepositUC))
        })),
        Err(e) => Err(wrap(Rule::DepositUC, e)),
    }
}

/// Whether a state ID falls in a shard's key range (the shard ID's bits are a prefix of the ID's).
pub fn in_shard(shard: &ShardId, sid: &[u8]) -> bool {
    shard.is_prefix_of(sid)
}

/// The shard of a certificate, re-encoded.
pub fn shard_bytes(uc: &UnicityCertificate) -> alloc::vec::Vec<u8> {
    uc.shard_tree_certificate.shard.encode()
}

/// For one complete seal and shard, canonical UC equality implies exact B1 claim equality.
#[derive(Default)]
pub(crate) struct ClaimConsistency {
    claims: alloc::collections::BTreeMap<([u8; 32], u32, alloc::vec::Vec<u8>), [u8; 32]>,
}

impl ClaimConsistency {
    pub(crate) fn check(&mut self, uc: &UnicityCertificate, raw: &[u8]) -> Result<()> {
        let key = (
            super::crypto::hu(&[&uc.unicity_seal.to_cbor()]),
            uc.unicity_tree_certificate.partition_identifier,
            shard_bytes(uc),
        );
        let digest = super::crypto::hu(&[raw]);
        if self
            .claims
            .get(&key)
            .is_some_and(|previous| *previous != digest)
        {
            return fail_d(
                Rule::CertStructure,
                "conflicting claims for the same seal and shard",
            );
        }
        self.claims.insert(key, digest);
        Ok(())
    }
}
