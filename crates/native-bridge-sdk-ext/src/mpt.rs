//! Ethereum Merkle-Patricia inclusion proofs.
//!
//! A proof is the ordered root-to-leaf list of node encodings that are *hashed* into their parent;
//! nodes shorter than 32 bytes are embedded in the parent and never listed separately. Verification
//! enforces hex-prefix rules, the embedded/hash-reference split, full key consumption, and that the
//! list holds exactly the nodes on the path: no duplicate, extraneous or missing node and no unused
//! suffix. No RSMT call verifies an EVM MPT.

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

/// Decode a hex-prefix path: `(is_leaf, nibbles)`.
fn hex_prefix(b: &[u8]) -> Result<(bool, Vec<u8>)> {
    let first = *b.first().ok_or(E::MptMalformed)?;
    let flag = first >> 4;
    if flag > 3 {
        return Err(E::MptMalformed);
    }
    let leaf = flag & 2 != 0;
    let odd = flag & 1 != 0;
    let mut out = Vec::new();
    if odd {
        out.push(first & 0x0f);
    } else if first & 0x0f != 0 {
        return Err(E::MptMalformed);
    }
    out.extend(nibbles(&b[1..]));
    Ok((leaf, out))
}

enum Child<'a> {
    Hash([u8; 32]),
    Embedded(&'a Rlp<'a>),
}

fn child_ref<'a, 'b>(item: &'b Rlp<'a>) -> Result<Child<'b>>
where
    'a: 'b,
{
    match item {
        Rlp::Bytes(b, _) if b.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(b);
            Ok(Child::Hash(h))
        }
        Rlp::List(_, raw) if raw.len() < 32 => Ok(Child::Embedded(item)),
        _ => Err(E::MptMalformed),
    }
}

/// Verify that `key` maps to a non-empty value under `root`, returning that value.
pub fn verify_proof(root: &[u8; 32], key: &[u8], nodes: &[&[u8]]) -> Result<Vec<u8>> {
    let path = nibbles(key);
    let mut rest: &[u8] = &path;
    let mut used = 0usize;
    // Decoded listed nodes must outlive the walk.
    let decoded: Vec<Rlp<'_>> = nodes
        .iter()
        .map(|n| rlp::decode(n))
        .collect::<Result<_>>()?;
    let mut expect = Some(Child::Hash(*root));
    let mut current: &Rlp<'_>;
    loop {
        current = match expect.take().ok_or(E::MptMalformed)? {
            Child::Hash(h) => {
                let idx = used;
                let node = nodes.get(idx).ok_or(E::MptMalformed)?;
                // A node of fewer than 32 bytes is always embedded, never referenced by hash.
                if node.len() < 32 || keccak(&[node]) != h {
                    return Err(E::MptMalformed);
                }
                used += 1;
                &decoded[idx]
            }
            Child::Embedded(item) => item,
        };
        let list = current.list().map_err(|_| E::MptMalformed)?;
        match list.len() {
            17 => {
                let Some((&n, tail)) = rest.split_first() else {
                    // A branch value cannot terminate a fixed-length key.
                    return Err(E::MptMalformed);
                };
                expect = Some(child_ref(&list[n as usize]).map_err(|_| E::MptMalformed)?);
                rest = tail;
            }
            2 => {
                let (leaf, seg) = hex_prefix(list[0].bytes()?).map_err(|_| E::MptMalformed)?;
                if leaf {
                    if seg != rest {
                        return Err(E::MptMalformed);
                    }
                    let value = list[1].bytes().map_err(|_| E::MptMalformed)?;
                    if value.is_empty() || used != nodes.len() {
                        return Err(E::MptMalformed);
                    }
                    return Ok(value.to_vec());
                }
                if seg.is_empty() || !rest.starts_with(&seg) {
                    return Err(E::MptMalformed);
                }
                rest = &rest[seg.len()..];
                expect = Some(child_ref(&list[1]).map_err(|_| E::MptMalformed)?);
            }
            _ => return Err(E::MptMalformed),
        }
    }
}
