//! Immutable configuration `Cfg`, the one-shard aggregator policy and every cfg-bound derivation of
//! the native profile (protocol version 2).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use sha2::{Digest, Sha256};
use sha3::Keccak256;
use unicity_token::cbor::{encode_array, encode_byte_string, encode_null, encode_tag, encode_uint};

use crate::error::{NativeError as E, Result};
use crate::limits::*;
use crate::scan::{fixed, scan_one};

const CFG_DOMAIN: &[u8] = b"UNICITY_BR_CFG";
const POLICY_DOMAIN: &[u8] = b"UNICITY_BR_AGG_ONE";

/// The one-byte native encoding of the empty shard prefix (not the empty bstr).
pub const EMPTY_PREFIX_SHARD: [u8; 1] = [0x80];

/// Raw SHA-256.
pub fn h(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Keccak-256 over the concatenation of `parts`.
pub fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak256::new();
    for p in parts {
        k.update(p);
    }
    k.finalize().into()
}

/// Lowercase hex without prefix.
pub fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Decode lowercase/uppercase hex of an exact length.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let raw = s.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks(2) {
        out.push(nib(pair[0])? << 4 | nib(pair[1])?);
    }
    Some(out)
}

/// Immutable bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cfg {
    pub network: u16,
    pub root_genesis: [u8; 32],
    pub chain_id: u64,
    pub execution_genesis: [u8; 32],
    pub evm_partition: u32,
    pub evm_shard: Vec<u8>,
    pub vault: [u8; 20],
    pub zero_address: [u8; 20],
    pub ty: [u8; 32],
    pub aid: [u8; 32],
    pub semantic_profile_hash: [u8; 32],
    pub token_verifier_address: [u8; 20],
    pub token_verifier_code_hash: [u8; 32],
    pub b1_profile_hash: [u8; 32],
    pub aggregator_policy_hash: [u8; 32],
}

impl Cfg {
    /// The exact canonical Cfg encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_array(&[
            &encode_byte_string(CFG_DOMAIN),
            &encode_uint(self.network as u64),
            &encode_byte_string(&self.root_genesis),
            &encode_uint(self.chain_id),
            &encode_byte_string(&self.execution_genesis),
            &encode_uint(self.evm_partition as u64),
            &encode_byte_string(&self.evm_shard),
            &encode_byte_string(&self.vault),
            &encode_byte_string(&self.zero_address),
            &encode_byte_string(&self.ty),
            &encode_byte_string(&self.aid),
            &encode_byte_string(&self.semantic_profile_hash),
            &encode_byte_string(&self.token_verifier_address),
            &encode_byte_string(&self.token_verifier_code_hash),
            &encode_byte_string(&self.b1_profile_hash),
            &encode_byte_string(&self.aggregator_policy_hash),
        ])
    }

    /// `cfg = H(Cfg)`.
    pub fn hash(&self) -> [u8; 32] {
        h(&self.to_bytes())
    }

    /// Strictly decode Cfg bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Cfg> {
        if b.len() > MAX_SEMANTIC_BYTES {
            return Err(E::InputTooLarge);
        }
        let root = scan_one(b)?;
        let k = root.array(16).ok_or(E::Shape)?;
        if k[0].bytes().map_err(|_| E::Shape)? != CFG_DOMAIN {
            return Err(E::Shape);
        }
        Ok(Cfg {
            network: k[1].uint_max(0xffff)? as u16,
            root_genesis: fixed(&k[2])?,
            chain_id: k[3].uint()?,
            execution_genesis: fixed(&k[4])?,
            evm_partition: k[5].uint_max(0xffff_ffff)? as u32,
            evm_shard: k[6].bytes()?.to_vec(),
            vault: fixed(&k[7])?,
            zero_address: fixed(&k[8])?,
            ty: fixed(&k[9])?,
            aid: fixed(&k[10])?,
            semantic_profile_hash: fixed(&k[11])?,
            token_verifier_address: fixed(&k[12])?,
            token_verifier_code_hash: fixed(&k[13])?,
            b1_profile_hash: fixed(&k[14])?,
            aggregator_policy_hash: fixed(&k[15])?,
        })
    }
}

/// `D = networkDecimal:rootGenesisHex:executionGenesisHex:chainIdDecimal:zeroAddressHex`.
///
/// Decimal integers have no leading zeros; genesis hex is lowercase 64 characters; the zero address
/// is 40 zero characters; none carries a `0x` prefix.
pub fn identity_domain(
    network: u16,
    root_genesis: &[u8; 32],
    execution_genesis: &[u8; 32],
    chain_id: u64,
) -> String {
    let mut d = String::new();
    let _ = write!(d, "{network}:");
    d.push_str(&hex_lower(root_genesis));
    d.push(':');
    d.push_str(&hex_lower(execution_genesis));
    let _ = write!(d, ":{chain_id}:");
    d.push_str(&hex_lower(&[0u8; 20]));
    d
}

/// `ty = SHA256(UTF8("unicity-bridge:unicity-native:" + D))`. The vault is deliberately not part of
/// the type: approved replacement vaults represent the same asset.
pub fn derive_type(
    network: u16,
    root_genesis: &[u8; 32],
    execution_genesis: &[u8; 32],
    chain_id: u64,
) -> [u8; 32] {
    let mut s = String::from("unicity-bridge:unicity-native:");
    s.push_str(&identity_domain(
        network,
        root_genesis,
        execution_genesis,
        chain_id,
    ));
    h(s.as_bytes())
}

/// `aid = SHA256(UTF8("unicity-bridge-coin:unicity-native:" + D))`.
pub fn derive_asset(
    network: u16,
    root_genesis: &[u8; 32],
    execution_genesis: &[u8; 32],
    chain_id: u64,
) -> [u8; 32] {
    let mut s = String::from("unicity-bridge-coin:unicity-native:");
    s.push_str(&identity_domain(
        network,
        root_genesis,
        execution_genesis,
        chain_id,
    ));
    h(s.as_bytes())
}

/// The common wallet value envelope: `tag(39050,[1,[[b(aid),b(amount)]],null])`, one inline entry,
/// no memo. `amount` is minimal positive big-endian.
pub fn value_envelope(aid: &[u8; 32], amount: &[u8]) -> Vec<u8> {
    let entry = encode_array(&[&encode_byte_string(aid), &encode_byte_string(amount)]);
    encode_tag(
        TAG_WALLET_VALUE,
        &encode_array(&[&encode_uint(1), &encode_array(&[&entry]), &encode_null()]),
    )
}

/// The sole admitted aggregator policy body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub partition: u32,
    pub shard_conf: [u8; 32],
}

impl Policy {
    /// `C("UNICITY_BR_AGG_ONE", partition, b(0x80), b(shardConfHash))`.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_array(&[
            &encode_byte_string(POLICY_DOMAIN),
            &encode_uint(self.partition as u64),
            &encode_byte_string(&EMPTY_PREFIX_SHARD),
            &encode_byte_string(&self.shard_conf),
        ])
    }

    /// `aggregatorPolicyHash = H(exact policy bytes)`.
    pub fn hash(&self) -> [u8; 32] {
        h(&self.to_bytes())
    }

    /// Strictly decode a policy body of at most 128 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Policy> {
        if b.len() > MAX_POLICY_BYTES {
            return Err(E::InputTooLarge);
        }
        let root = scan_one(b)?;
        let k = root.array(4).ok_or(E::Shape)?;
        if k[0].bytes().map_err(|_| E::Shape)? != POLICY_DOMAIN {
            return Err(E::Shape);
        }
        let partition = k[1].uint_max(0xffff_ffff)? as u32;
        if k[2].bytes().map_err(|_| E::Shape)? != EMPTY_PREFIX_SHARD {
            return Err(E::Shape);
        }
        Ok(Policy {
            partition,
            shard_conf: fixed(&k[3])?,
        })
    }
}

/// `salt = H(C("UNICITY_BR_SALT", b(cfg), n))`.
pub fn derive_salt(cfg: &[u8; 32], n: u64) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(b"UNICITY_BR_SALT"),
        &encode_byte_string(cfg),
        &encode_uint(n),
    ]))
}

/// `id = H(C(b(salt), network))`.
pub fn derive_token_id(salt: &[u8; 32], network: u16) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(salt),
        &encode_uint(network as u64),
    ]))
}

/// Lock record `K = [b(zero), b(ty), b(aid), b(amount), b(id), b(H(P0))]`.
pub fn lock_record(
    zero: &[u8; 20],
    ty: &[u8; 32],
    aid: &[u8; 32],
    amount: &[u8],
    id: &[u8; 32],
    rcpt: &[u8; 32],
) -> Vec<u8> {
    encode_array(&[
        &encode_byte_string(zero),
        &encode_byte_string(ty),
        &encode_byte_string(aid),
        &encode_byte_string(amount),
        &encode_byte_string(id),
        &encode_byte_string(rcpt),
    ])
}

/// `d = H(C("UNICITY_BR_LOCK", b(cfg), n, K))`. Binds cfg, nonce, amount, id and recipient; not J
/// and not the mint transaction hash, so there is no circularity with the embedded proof.
pub fn lock_digest(cfg: &[u8; 32], n: u64, k: &[u8]) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(b"UNICITY_BR_LOCK"),
        &encode_byte_string(cfg),
        &encode_uint(n),
        k,
    ]))
}

/// The exact terminal return reason R (tag 39048, unchanged by SDK 3.0.1).
pub fn return_reason(
    chain_id: u64,
    vault: &[u8; 20],
    zero: &[u8; 20],
    ty: &[u8; 32],
    aid: &[u8; 32],
    recipient: &[u8; 20],
    amount: &[u8],
) -> Vec<u8> {
    encode_tag(
        TAG_RETURN_REASON,
        &encode_array(&[
            &encode_uint(1),
            &encode_uint(chain_id),
            &encode_byte_string(vault),
            &encode_byte_string(zero),
            &encode_byte_string(ty),
            &encode_byte_string(aid),
            &encode_byte_string(recipient),
            &encode_byte_string(amount),
            &encode_byte_string(zero),
            &encode_byte_string(&[]),
            &encode_uint(0),
        ]),
    )
}

/// `btid = H(C("unicity-burn-transition:v1", b(sid), b(txHash)))`.
pub fn burn_id(sid: &[u8; 32], tx_hash: &[u8; 32]) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(b"unicity-burn-transition:v1"),
        &encode_byte_string(sid),
        &encode_byte_string(tx_hash),
    ]))
}

/// `eta = H(C("UNICITY_BR_NUL", b(cfg), b(btid)))`. Excludes referenceTime, paths, anchor round,
/// unlock representation and submitter.
pub fn nullifier(cfg: &[u8; 32], btid: &[u8; 32]) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(b"UNICITY_BR_NUL"),
        &encode_byte_string(cfg),
        &encode_byte_string(btid),
    ]))
}

/// The certified leaf value `v = H(C(b(txHash32), t))`.
pub fn leaf_value(tx_hash: &[u8; 32], reference_time: u64) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(tx_hash),
        &encode_uint(reference_time),
    ]))
}

// ---- vault storage layout ----------------------------------------------------------------------

pub const SLOT_LOCK_DIGEST: u64 = 5;
pub const SLOT_SPENT_NULLIFIER: u64 = 6;
pub const SLOT_CLAIMABLE: u64 = 7;

pub fn word(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

/// Logical slot `keccak256(abi.encode(key, base))` for a right-aligned key.
pub fn mapping_slot(key: &[u8], base: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[32 - key.len()..].copy_from_slice(key);
    keccak(&[&k, &word(base)])
}

pub fn lock_digest_slot(n: u64) -> [u8; 32] {
    mapping_slot(&word(n), SLOT_LOCK_DIGEST)
}
pub fn spent_slot(n: u64) -> [u8; 32] {
    mapping_slot(&word(n), SLOT_SPENT_NULLIFIER)
}
pub fn claimable_slot(a: &[u8; 20]) -> [u8; 32] {
    mapping_slot(a, SLOT_CLAIMABLE)
}
/// Ethereum storage trie key `keccak256(logicalSlot)`.
pub fn storage_trie_key(slot: &[u8; 32]) -> [u8; 32] {
    keccak(&[slot])
}
/// Ethereum account trie key `keccak256(address)`.
pub fn account_trie_key(a: &[u8; 20]) -> [u8; 32] {
    keccak(&[a])
}
