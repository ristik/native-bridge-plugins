//! The embedded lock proof and its fully offline verification.
//!
//! `J = tag(39049,[2,chainId,b(vault20),b(zero20),nonce,LockProof])` and
//! `LockProof = [1,b(cfg32),b(trustBaseId32),b(evmPDR),b(evmUC),b(headerRLP),[b(accountNode)...],[b(storageNode)...]]`.
//! Verification uses only the token's bytes and the pinned deployment and trust bundle: no RPC, no
//! node, no URL resolution, no witness provider.

use alloc::vec::Vec;

use unicity_token::api::bft::UnicityCertificate;
use unicity_token::cbor::{
    encode_array, encode_byte_string, encode_null, encode_tag, encode_uint, Decoder,
};

use crate::deployment::Deployment;
use crate::error::{NativeError as E, Result};
use crate::header;
use crate::limits::*;
use crate::mpt;
use crate::profile::{account_trie_key, h, keccak, lock_digest_slot, storage_trie_key};
use crate::rlp;
use crate::scan::{fixed, pdr_elements, scan_one, Item};
use crate::trust::{self, TrustInput};

/// A parsed, bounded lock proof borrowing the justification bytes.
#[derive(Debug, Clone)]
pub struct LockProof<'a> {
    pub cfg: [u8; 32],
    pub trust_base_id: [u8; 32],
    pub pdr: &'a [u8],
    pub uc: &'a [u8],
    pub header: &'a [u8],
    pub account_nodes: Vec<&'a [u8]>,
    pub storage_nodes: Vec<&'a [u8]>,
}

/// A parsed justification J.
#[derive(Debug, Clone)]
pub struct Justification<'a> {
    pub chain_id: u64,
    pub vault: [u8; 20],
    pub zero: [u8; 20],
    pub nonce: u64,
    pub proof: LockProof<'a>,
}

fn nodes<'a>(it: &Item<'a>, total: &mut usize) -> Result<Vec<&'a [u8]>> {
    let list = it.any_array().ok_or(E::Shape)?;
    if list.len() > MAX_MPT_NODES {
        return Err(E::ProofTooLarge);
    }
    let mut out = Vec::new();
    for n in list {
        let b = n.bytes()?;
        if b.is_empty() || b.len() > MAX_MPT_NODE_BYTES {
            return Err(E::ProofTooLarge);
        }
        *total += b.len();
        out.push(b);
    }
    Ok(out)
}

impl<'a> LockProof<'a> {
    /// Parse one scanned LockProof item, enforcing exact arity and every size bound before any
    /// cryptography or allocation proportional to untrusted lengths.
    pub fn parse(it: &Item<'a>) -> Result<Self> {
        let k = it.array(8).ok_or(E::Shape)?;
        k[0].version(LOCK_PROOF_VERSION)?;
        let pdr = k[3].bytes()?;
        let uc = k[4].bytes()?;
        let header = k[5].bytes()?;
        if pdr.is_empty() || pdr.len() > MAX_PDR_BYTES || uc.is_empty() || uc.len() > MAX_UC_BYTES {
            return Err(E::ProofTooLarge);
        }
        if header.is_empty() || header.len() > MAX_HEADER_BYTES {
            return Err(E::ProofTooLarge);
        }
        let mut total = 0usize;
        let account_nodes = nodes(&k[6], &mut total)?;
        let storage_nodes = nodes(&k[7], &mut total)?;
        if total > MAX_MPT_TOTAL_BYTES {
            return Err(E::ProofTooLarge);
        }
        Ok(LockProof {
            cfg: fixed(&k[1])?,
            trust_base_id: fixed(&k[2])?,
            pdr,
            uc,
            header,
            account_nodes,
            storage_nodes,
        })
    }

    /// The exact canonical encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let acct: Vec<Vec<u8>> = self
            .account_nodes
            .iter()
            .map(|n| encode_byte_string(n))
            .collect();
        let stor: Vec<Vec<u8>> = self
            .storage_nodes
            .iter()
            .map(|n| encode_byte_string(n))
            .collect();
        let a: Vec<&[u8]> = acct.iter().map(Vec::as_slice).collect();
        let s: Vec<&[u8]> = stor.iter().map(Vec::as_slice).collect();
        encode_array(&[
            &encode_uint(LOCK_PROOF_VERSION),
            &encode_byte_string(&self.cfg),
            &encode_byte_string(&self.trust_base_id),
            &encode_byte_string(self.pdr),
            &encode_byte_string(self.uc),
            &encode_byte_string(self.header),
            &encode_array(&a),
            &encode_array(&s),
        ])
    }
}

/// Encode J from the header fields and an already-encoded LockProof.
pub fn encode_justification(
    chain_id: u64,
    vault: &[u8; 20],
    zero: &[u8; 20],
    nonce: u64,
    lock_proof: &[u8],
) -> Vec<u8> {
    encode_tag(
        TAG_MINT_LOCK,
        &encode_array(&[
            &encode_uint(MINT_LOCK_VERSION),
            &encode_uint(chain_id),
            &encode_byte_string(vault),
            &encode_byte_string(zero),
            &encode_uint(nonce),
            lock_proof,
        ]),
    )
}

/// Parse J. The caller keeps `j` alive for as long as the borrowed proof is used.
pub fn parse_justification(j: &[u8]) -> Result<Justification<'_>> {
    if j.len() > MAX_JUSTIFICATION_BYTES {
        return Err(E::InputTooLarge);
    }
    let root = scan_one(j)?;
    let c = root.tag_content(TAG_MINT_LOCK)?;
    let k = c.array(6).ok_or(E::Shape)?;
    k[0].version(MINT_LOCK_VERSION)?;
    let parsed = Justification {
        chain_id: k[1].uint()?,
        vault: fixed(&k[2])?,
        zero: fixed(&k[3])?,
        nonce: k[4].uint()?,
        proof: LockProof::parse(&k[5])?,
    };
    Ok(parsed)
}

pub(crate) fn config_hash(pdr_elems: &[&[u8]]) -> [u8; 32] {
    // Every non-membership setting: validators, epoch and activation round are neutralised.
    let mut parts: Vec<Vec<u8>> = pdr_elems[..12].iter().map(|e| e.to_vec()).collect();
    parts.push(encode_uint(0));
    parts.push(encode_uint(0));
    parts.push(encode_null());
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    h(&encode_tag(39008, &encode_array(&refs)))
}

/// The genesis `ConfigHash` of a canonical PDR: every non-membership setting.
pub fn config_hash_of_pdr(pdr: &[u8]) -> Result<[u8; 32]> {
    let elems = pdr_elements(pdr).map_err(|_| E::EvmConfigPin)?;
    if elems.len() != 15 {
        return Err(E::EvmConfigPin);
    }
    Ok(config_hash(&elems))
}

fn small_uint(raw: &[u8]) -> Result<u64> {
    scan_one(raw)?.uint()
}

/// The result of an offline lock-proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLock {
    pub trust_base_id: [u8; 32],
    pub evm_block_number: u64,
    pub evm_root_round: u64,
}

/// Verify a lock proof against the pinned deployment and trust bundle, in the specified order.
///
/// `expected_digest` is the lock digest reconstructed from the actual mint and configuration.
pub fn verify(
    dep: &Deployment,
    trust: &TrustInput,
    j: &Justification<'_>,
    expected_digest: &[u8; 32],
) -> Result<VerifiedLock> {
    let lp = &j.proof;
    // Chain, vault, native asset and cfg must match the allow-listed deployment.
    if j.chain_id != dep.cfg.chain_id || j.vault != dep.cfg.vault || j.zero != dep.cfg.zero_address
    {
        return Err(E::MintJustif);
    }
    if lp.cfg != dep.cfg_hash {
        return Err(E::LockProofCfg);
    }
    // The proof names the trust base that authenticates it; it never supplies keys.
    let entry_id = lp.trust_base_id;
    if entry_id != trust.id() {
        return Err(E::LockProofTrust);
    }
    crate::resources::preflight_uc(lp.uc)?;
    let uc = {
        let d = Decoder::with_limits(lp.uc, unicity_token::cbor::DecodeLimits::DEFAULT);
        let uc = UnicityCertificate::from_cbor(d).map_err(|_| E::UnsupportedCertificateEncoding)?;
        if uc.to_cbor() != lp.uc {
            return Err(E::UnsupportedCertificateEncoding);
        }
        uc
    };
    trust::verify_embedded_uc(trust, &uc)?;
    // Admitted EVM partition, shard and configuration: pinned, never taken from the UC tuple.
    if uc.unicity_tree_certificate.partition_identifier != dep.cfg.evm_partition {
        return Err(E::EvmPartition);
    }
    if uc.shard_tree_certificate.shard.encode() != dep.cfg.evm_shard {
        return Err(E::EvmShard);
    }
    if h(lp.pdr).as_slice() != uc.shard_configuration_hash.as_slice() {
        return Err(E::EvmConfigHash);
    }
    let elems = pdr_elements(lp.pdr).map_err(|_| E::EvmConfigPin)?;
    if elems.len() != 15 {
        return Err(E::EvmConfigPin);
    }
    let net = small_uint(elems[1]).map_err(|_| E::EvmConfigPin)?;
    let part = small_uint(elems[2]).map_err(|_| E::EvmConfigPin)?;
    let shard = scan_one(elems[3])
        .and_then(|i| i.bytes().map(|b| b.to_vec()))
        .map_err(|_| E::EvmConfigPin)?;
    if net != dep.cfg.network as u64
        || part != dep.cfg.evm_partition as u64
        || shard != dep.cfg.evm_shard
    {
        return Err(E::EvmConfigPin);
    }
    if config_hash(&elems) != dep.evm_config_hash {
        return Err(E::EvmConfigPin);
    }
    // The certified shard epoch must be the epoch the carried PDR describes.
    if small_uint(elems[12]).map_err(|_| E::EvmConfigPin)? != uc.input_record.epoch {
        return Err(E::EvmConfigPin);
    }
    // keccak256(headerRLP) == IR.blockHash and header.stateRoot == IR.hash: a signature over an
    // unrelated state root is insufficient.
    let block_hash = uc.input_record.block_hash.as_deref().ok_or(E::HeaderHash)?;
    if block_hash.len() != 32 || uc.input_record.hash.len() != 32 {
        return Err(E::HeaderHash);
    }
    if keccak(&[lp.header]).as_slice() != block_hash {
        return Err(E::HeaderHash);
    }
    let hdr = header::decode(lp.header, dep.header)?;
    if hdr.state_root.as_slice() != uc.input_record.hash.as_slice() {
        return Err(E::HeaderRoot);
    }
    // Account MPT at keccak256(vault) under header.stateRoot; codeHash == immutable runtime pin.
    let account = mpt::verify_proof(
        &hdr.state_root,
        &account_trie_key(&dep.cfg.vault),
        &lp.account_nodes,
    )
    .map_err(|_| E::AccountProof)?;
    let acct = rlp::decode(&account).map_err(|_| E::AccountProof)?;
    let f = acct.list().map_err(|_| E::AccountProof)?;
    if f.len() != 4 {
        return Err(E::AccountProof);
    }
    let storage_root: [u8; 32] = f[2]
        .bytes()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(E::AccountProof)?;
    let code_hash: [u8; 32] = f[3]
        .bytes()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(E::AccountProof)?;
    f[0].u64().map_err(|_| E::AccountProof)?;
    if f[1].bytes().map_err(|_| E::AccountProof)?.len() > 32 {
        return Err(E::AccountProof);
    }
    if code_hash != dep.vault_code_hash {
        return Err(E::AccountCode);
    }
    // Storage MPT at keccak256(keccak256(abi.encode(nonce, 5))).
    let key = storage_trie_key(&lock_digest_slot(j.nonce));
    let stored =
        mpt::verify_proof(&storage_root, &key, &lp.storage_nodes).map_err(|_| E::StorageProof)?;
    let word = rlp::decode(&stored).map_err(|_| E::StorageValue)?;
    let v = word.bytes().map_err(|_| E::StorageValue)?;
    if v.is_empty() || v.len() > 32 || v[0] == 0 {
        return Err(E::StorageValue);
    }
    let mut padded = [0u8; 32];
    padded[32 - v.len()..].copy_from_slice(v);
    if &padded != expected_digest {
        return Err(E::LockDigest);
    }
    Ok(VerifiedLock {
        trust_base_id: entry_id,
        evm_block_number: hdr.number,
        evm_root_round: uc.unicity_seal.root_chain_round_number,
    })
}
