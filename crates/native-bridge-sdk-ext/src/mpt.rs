//! Ethereum Merkle-Patricia inclusion proofs.
//!
//! A proof is the ordered root-to-leaf list of node encodings that are *hashed* into their parent;
//! nodes shorter than 32 bytes are embedded in the parent and never listed separately. bft-core
//! `mptVerify` exactly, with its reasons: a node that is not canonical, mis-hashed or out of order
//! `ErrMPTNode`; a path the supplied nodes do not take to its end `ErrMPTPath`; the key absent
//! `ErrMPTAbsent`; a node left unused `ErrMPTExtraneous`. The root is hash-referenced whatever its
//! size. No RSMT call verifies an EVM MPT.

use alloc::vec::Vec;

use crate::error::{NativeError as E, Result};
use crate::profile::keccak;
use crate::rlp::{self, Rlp};

fn nibbles(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() * 2);
    for b in key {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

/// A compact-encoded path, `(is_leaf, nibbles)`: flag nibble 0/1 extension even/odd, 2/3 leaf
/// even/odd; an even path has a zero padding nibble. `None` if the item is not one.
fn hex_prefix(item: &Rlp<'_>) -> Option<(bool, Vec<u8>)> {
    let Rlp::Bytes(b, _) = item else { return None };
    let first = *b.first()?;
    let flag = first >> 4;
    if flag > 3 {
        return None;
    }
    let mut out = Vec::new();
    if flag & 1 != 0 {
        out.push(first & 0x0f);
    } else if first & 0x0f != 0 {
        return None;
    }
    out.extend(nibbles(&b[1..]));
    Some((flag >= 2, out))
}

/// The value, once the walk has used exactly the supplied nodes.
fn finish(used: usize, total: usize, v: &[u8]) -> Result<Vec<u8>> {
    if used != total {
        return Err(E::MPTExtraneous);
    }
    Ok(v.to_vec())
}

/// The value of `key` (32 bytes, the hashed path) under `root`.
pub fn verify_proof<'n>(root: &[u8; 32], key: &[u8], nodes: &[&'n [u8]]) -> Result<Vec<u8>> {
    let path = nibbles(key);
    let mut nib: &[u8] = &path;
    let first: &'n [u8] = nodes.first().ok_or(E::MPTNode)?;
    if keccak(&[first]) != *root {
        return Err(E::MPTNode);
    }
    // the current node's encoding: a supplied node, or an embedded child inside one
    let mut cur_raw: &'n [u8] = first;
    let mut used = 1usize;
    loop {
        let cur = rlp::decode(cur_raw).map_err(|_| E::MPTNode)?;
        let Rlp::List(kids, _) = &cur else {
            return Err(E::MPTNode);
        };
        let child: &Rlp<'n> = match kids.len() {
            17 => {
                let Some((&n, tail)) = nib.split_first() else {
                    return match &kids[16] {
                        Rlp::Bytes(v, _) if !v.is_empty() => finish(used, nodes.len(), v),
                        _ => Err(E::MPTAbsent),
                    };
                };
                nib = tail;
                let c = &kids[n as usize];
                if matches!(c, Rlp::Bytes(b, _) if b.is_empty()) {
                    return Err(E::MPTAbsent);
                }
                c
            }
            2 => {
                let (leaf, seg) = hex_prefix(&kids[0]).ok_or(E::MPTNode)?;
                if seg.len() > nib.len() || nib[..seg.len()] != seg[..] {
                    return Err(E::MPTAbsent);
                }
                nib = &nib[seg.len()..];
                let v = &kids[1];
                if leaf {
                    if !nib.is_empty() {
                        return Err(E::MPTPath); // the leaf ends before the key does
                    }
                    return match v {
                        Rlp::Bytes(b, _) if !b.is_empty() => finish(used, nodes.len(), b),
                        _ => Err(E::MPTNode),
                    };
                }
                if seg.is_empty() {
                    return Err(E::MPTNode); // an extension consumes at least one nibble
                }
                v
            }
            _ => return Err(E::MPTNode),
        };
        // the child: embedded (under 32 bytes) or a hash reference to the next supplied node
        cur_raw = match child {
            Rlp::List(_, raw) => {
                if raw.len() >= 32 {
                    return Err(E::MPTNode);
                }
                raw
            }
            Rlp::Bytes(h, _) if h.len() == 32 => {
                let n: &'n [u8] = nodes.get(used).ok_or(E::MPTPath)?; // a hash reference with no supplied node
                if n.len() < 32 || keccak(&[n])[..] != h[..] {
                    return Err(E::MPTNode);
                }
                used += 1;
                n
            }
            _ => return Err(E::MPTNode),
        };
    }
}
