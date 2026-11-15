//! The pinned execution header (section 6.2 step 3; `header.ts`): the go-ethereum v1.14.11 Cancun `types.Header`, exactly 20
//! RLP fields ending at `parentBeaconBlockRoot`. The decoder accepts exactly what go-ethereum decodes into that struct and
//! re-encodes identically, plus the profile's constraints; every failure is `DepositHeader`.

use alloc::vec::Vec;
use num_bigint::BigUint;

use super::crypto::he;
use super::errors::{fail_d, Result, Rule};
use super::rlp::{rlp_bytes, rlp_decode, rlp_list, rlp_u64_enc, rlp_uint, rlp_uint_enc};
use super::util::to_u64;

/// keccak256(RLP([]))
pub fn empty_uncle_hash() -> [u8; 32] {
    he(&[&[0xc0]])
}

/// keccak256(RLP("")), the empty trie root.
pub fn empty_trie_root() -> [u8; 32] {
    he(&[&[0x80]])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub parent_hash: Vec<u8>,
    pub ommers_hash: Vec<u8>,
    pub beneficiary: Vec<u8>,
    pub state_root: Vec<u8>,
    pub transactions_root: Vec<u8>,
    pub receipts_root: Vec<u8>,
    pub logs_bloom: Vec<u8>,
    pub difficulty: BigUint,
    pub number: BigUint,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: Vec<u8>,
    pub nonce: Vec<u8>,
    pub base_fee_per_gas: BigUint,
    pub withdrawals_root: Vec<u8>,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
    pub parent_beacon_block_root: Vec<u8>,
}

impl Header {
    /// The block number (below 2^63 for every bound header).
    pub fn number_u64(&self) -> u64 {
        to_u64(&self.number).unwrap_or(u64::MAX)
    }
}

pub fn encode_header(h: &Header) -> Vec<u8> {
    rlp_list(&[
        rlp_bytes(&h.parent_hash),
        rlp_bytes(&h.ommers_hash),
        rlp_bytes(&h.beneficiary),
        rlp_bytes(&h.state_root),
        rlp_bytes(&h.transactions_root),
        rlp_bytes(&h.receipts_root),
        rlp_bytes(&h.logs_bloom),
        rlp_uint_enc(&h.difficulty),
        rlp_uint_enc(&h.number),
        rlp_u64_enc(h.gas_limit),
        rlp_u64_enc(h.gas_used),
        rlp_u64_enc(h.timestamp),
        rlp_bytes(&h.extra_data),
        rlp_bytes(&h.mix_hash),
        rlp_bytes(&h.nonce),
        rlp_uint_enc(&h.base_fee_per_gas),
        rlp_bytes(&h.withdrawals_root),
        rlp_u64_enc(h.blob_gas_used),
        rlp_u64_enc(h.excess_blob_gas),
        rlp_bytes(&h.parent_beacon_block_root),
    ])
}

/// Decode the pinned header shape (exact field widths, canonical integers, 20 fields, identical re-encoding); `DepositHeader`
/// otherwise.
pub fn decode_header(raw: &[u8]) -> Result<Header> {
    let it = match rlp_decode(raw) {
        Ok(it) => it,
        Err(_) => return fail_d(Rule::DepositHeader, "not RLP"),
    };
    if !it.list || it.kids.len() != 20 {
        return fail_d(Rule::DepositHeader, "not the 20-field Cancun header");
    }
    let k = &it.kids;
    let fixed = |i: usize, n: usize| -> Result<Vec<u8>> {
        if k[i].list || k[i].str.len() != n {
            return fail_d(Rule::DepositHeader, alloc::format!("field {i}"));
        }
        Ok(k[i].str.to_vec())
    };
    let int = |i: usize, max: usize| -> Result<BigUint> {
        match rlp_uint(&k[i], max) {
            Some(v) => Ok(v),
            None => fail_d(Rule::DepositHeader, alloc::format!("field {i}")),
        }
    };
    let int8 = |i: usize| -> Result<u64> { Ok(to_u64(&int(i, 8)?).expect("8 bytes")) };
    let bytes = |i: usize| -> Result<Vec<u8>> {
        if k[i].list {
            return fail_d(Rule::DepositHeader, alloc::format!("field {i}"));
        }
        Ok(k[i].str.to_vec())
    };
    let h = Header {
        parent_hash: fixed(0, 32)?,
        ommers_hash: fixed(1, 32)?,
        beneficiary: fixed(2, 20)?,
        state_root: fixed(3, 32)?,
        transactions_root: fixed(4, 32)?,
        receipts_root: fixed(5, 32)?,
        logs_bloom: fixed(6, 256)?,
        difficulty: int(7, 32)?,
        number: int(8, 32)?,
        gas_limit: int8(9)?,
        gas_used: int8(10)?,
        timestamp: int8(11)?,
        extra_data: bytes(12)?,
        mix_hash: fixed(13, 32)?,
        nonce: fixed(14, 8)?,
        base_fee_per_gas: int(15, 32)?,
        withdrawals_root: fixed(16, 32)?,
        blob_gas_used: int8(17)?,
        excess_blob_gas: int8(18)?,
        parent_beacon_block_root: fixed(19, 32)?,
    };
    if encode_header(&h) != raw {
        return fail_d(Rule::DepositHeader, "not canonical");
    }
    Ok(h)
}

/// Bind a header to its certified input record: `H_E(headerRLP) == IR.blockHash` and `header.stateRoot == IR.hash`, then the
/// profile's constraints (zero difficulty, empty uncles and withdrawals, no blob gas, a nonzero u64 base fee, at most 32 extra
/// bytes, number below 2^63).
pub fn bind_header(
    raw: &[u8],
    ir_block_hash: Option<&[u8]>,
    ir_hash: Option<&[u8]>,
) -> Result<Header> {
    let h = decode_header(raw)?;
    if h.number.bits() > 64 {
        return fail_d(Rule::DepositHeader, "number");
    }
    match (ir_block_hash, ir_hash) {
        (Some(bh), Some(sh)) if he(&[raw]) == bh && h.state_root == sh => {}
        _ => return fail_d(Rule::DepositHeader, "not the certified block"),
    }
    let base = &h.base_fee_per_gas;
    if h.number.bits() > 63
        || h.ommers_hash != empty_uncle_hash()
        || h.difficulty.bits() != 0
        || base.bits() == 0
        || base.bits() > 64
        || h.withdrawals_root != empty_trie_root()
        || h.blob_gas_used != 0
        || h.excess_blob_gas != 0
        || h.extra_data.len() > 32
    {
        return fail_d(Rule::DepositHeader, "outside the pinned profile");
    }
    Ok(h)
}
