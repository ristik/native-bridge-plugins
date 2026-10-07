//! The native execution profile's block header: RLP, Cancun-era fields, no uncles, no difficulty.

use crate::error::{NativeError as E, Result};
use crate::rlp;

/// `keccak256(rlp([]))`, the empty-uncle-list hash.
pub const EMPTY_UNCLE_HASH: [u8; 32] = [
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
];
/// The empty trie root, also the empty withdrawals root.
pub const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// The pinned header shape: the number of RLP fields. 20 is the Cancun header through
/// `parentBeaconBlockRoot`; 21 appends the Prague `requestsHash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderProfile {
    pub fields: u8,
}

/// What the proof needs from a header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub state_root: [u8; 32],
    pub number: u64,
}

/// Decode and check a header against the pinned profile.
pub fn decode(raw: &[u8], profile: HeaderProfile) -> Result<Header> {
    let it = rlp::decode(raw).map_err(|_| E::HeaderProfile)?;
    let f = it.list().map_err(|_| E::HeaderProfile)?;
    if !matches!(profile.fields, 20 | 21) || f.len() != profile.fields as usize {
        return Err(E::HeaderProfile);
    }
    let h32 = |i: usize| -> Result<[u8; 32]> {
        let b = f[i].bytes().map_err(|_| E::HeaderProfile)?;
        b.try_into().map_err(|_| E::HeaderProfile)
    };
    let int = |i: usize| f[i].u64().map_err(|_| E::HeaderProfile);
    let empty =
        |i: usize| -> Result<bool> { Ok(f[i].bytes().map_err(|_| E::HeaderProfile)?.is_empty()) };
    h32(0)?; // parent hash
    if h32(1)? != EMPTY_UNCLE_HASH {
        return Err(E::HeaderProfile);
    }
    if f[2].bytes().map_err(|_| E::HeaderProfile)?.len() != 20 {
        return Err(E::HeaderProfile);
    }
    let state_root = h32(3)?;
    h32(4)?;
    h32(5)?;
    if f[6].bytes().map_err(|_| E::HeaderProfile)?.len() != 256 {
        return Err(E::HeaderProfile);
    }
    if !empty(7)? {
        return Err(E::HeaderProfile); // difficulty 0
    }
    let number = int(8)?;
    int(9)?;
    int(10)?;
    int(11)?;
    if f[12].bytes().map_err(|_| E::HeaderProfile)?.len() > 32 {
        return Err(E::HeaderProfile);
    }
    h32(13)?;
    if f[14].bytes().map_err(|_| E::HeaderProfile)?.len() != 8 {
        return Err(E::HeaderProfile);
    }
    if int(15)? == 0 {
        return Err(E::HeaderProfile); // base fee must be positive
    }
    if h32(16)? != EMPTY_TRIE_ROOT || int(17)? != 0 || int(18)? != 0 {
        return Err(E::HeaderProfile);
    }
    h32(19)?;
    if profile.fields == 21 {
        h32(20)?;
    }
    Ok(Header { state_root, number })
}
