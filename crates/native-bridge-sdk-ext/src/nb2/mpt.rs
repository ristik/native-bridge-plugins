//! Ethereum Merkle-Patricia trie (`mpt.ts`): the strict inclusion check of bft-core `nb2ref/mpt.go` (an unhashed key of any
//! length, the nodes exactly the root-to-leaf path in order, every hash reference consuming the next node, an embedded node
//! consuming none, the key consumed completely, no duplicate, unused or out-of-order node), and a builder of a whole trie with the
//! path of one key, which the wallet uses to turn a block's receipts into a receipt-trie proof.

use alloc::vec::Vec;

use super::crypto::he;
use super::rlp::{rlp_bytes, rlp_decode, rlp_list, RlpItem};

/// The path does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MptError;

fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

fn hex_prefix(it: &RlpItem<'_>) -> Option<(Vec<u8>, bool)> {
    if it.list || it.str.is_empty() {
        return None;
    }
    let f = it.str[0] >> 4;
    if f > 3 {
        return None;
    }
    let mut path = Vec::new();
    if f & 1 == 1 {
        path.push(it.str[0] & 0x0f);
    } else if it.str[0] & 0x0f != 0 {
        return None;
    }
    for &b in &it.str[1..] {
        path.push(b >> 4);
        path.push(b & 0x0f);
    }
    Some((path, f >= 2))
}

/// The value stored at `key` under `root`.
pub fn mpt_verify(root: &[u8], key: &[u8], nodes: &[Vec<u8>]) -> Result<Vec<u8>, MptError> {
    let nib_owned = nibbles(key);
    let mut nib: &[u8] = &nib_owned;
    if nodes.is_empty() || he(&[&nodes[0]]) != root {
        return Err(MptError);
    }
    let mut cur = rlp_decode(&nodes[0]).map_err(|_| MptError)?;
    let mut used = 1usize;
    let finish = |used: usize, v: &[u8]| {
        if used != nodes.len() {
            Err(MptError)
        } else {
            Ok(v.to_vec())
        }
    };
    loop {
        if !cur.list {
            return Err(MptError);
        }
        let child: RlpItem<'_>;
        if cur.kids.len() == 17 {
            if nib.is_empty() {
                let v = &cur.kids[16];
                if v.list || v.str.is_empty() {
                    return Err(MptError);
                }
                return finish(used, v.str);
            }
            child = cur.kids[nib[0] as usize].clone();
            nib = &nib[1..];
            if !child.list && child.str.is_empty() {
                return Err(MptError);
            }
        } else if cur.kids.len() == 2 {
            let (path, leaf) = hex_prefix(&cur.kids[0]).ok_or(MptError)?;
            if path.len() > nib.len() || path.iter().zip(nib.iter()).any(|(a, b)| a != b) {
                return Err(MptError);
            }
            nib = &nib[path.len()..];
            let v = &cur.kids[1];
            if leaf {
                if !nib.is_empty() || v.list || v.str.is_empty() {
                    return Err(MptError);
                }
                return finish(used, v.str);
            }
            if path.is_empty() {
                return Err(MptError);
            }
            child = v.clone();
        } else {
            return Err(MptError);
        }
        if child.list {
            if child.raw.len() >= 32 {
                return Err(MptError);
            }
            cur = child;
        } else if child.str.len() == 32 {
            if used >= nodes.len() {
                return Err(MptError);
            }
            let n = &nodes[used];
            if n.len() < 32 || he(&[n]) != child.str {
                return Err(MptError);
            }
            cur = rlp_decode(n).map_err(|_| MptError)?;
            used += 1;
        } else {
            return Err(MptError);
        }
    }
}

// ---- builder ----------------------------------------------------------------------------------

fn compact(n: &[u8], leaf: bool) -> Vec<u8> {
    let flag = (if leaf { 2 } else { 0 }) | (n.len() as u8 & 1);
    let mut out = Vec::new();
    let mut i = 0;
    if n.len() % 2 == 1 {
        out.push(flag << 4 | n[0]);
        i = 1;
    } else {
        out.push(flag << 4);
    }
    while i < n.len() {
        out.push(n[i] << 4 | n[i + 1]);
        i += 2;
    }
    out
}

fn reference(node: &[u8]) -> Vec<u8> {
    if node.len() < 32 {
        node.to_vec()
    } else {
        rlp_bytes(&he(&[node]))
    }
}

struct Entry<'a> {
    k: Vec<u8>,
    v: &'a [u8],
}

fn build(
    entries: &[&Entry<'_>],
    depth: usize,
    target: Option<&[u8]>,
    path: &mut Vec<Vec<u8>>,
) -> Vec<u8> {
    let on_path = target.is_some_and(|t| entries.iter().any(|e| e.k == t));
    let node = if entries.len() == 1 && entries[0].k.len() >= depth {
        rlp_list(&[
            rlp_bytes(&compact(&entries[0].k[depth..], true)),
            rlp_bytes(entries[0].v),
        ])
    } else {
        // a value ending exactly here sits in the branch's 17th slot
        let here: Vec<&Entry<'_>> = entries
            .iter()
            .copied()
            .filter(|e| e.k.len() == depth)
            .collect();
        let deeper: Vec<&Entry<'_>> = entries
            .iter()
            .copied()
            .filter(|e| e.k.len() > depth)
            .collect();
        let mut cp = 0;
        if here.is_empty() {
            let first = &deeper[0].k;
            while deeper
                .iter()
                .all(|e| e.k.len() > depth + cp && e.k[depth + cp] == first[depth + cp])
            {
                cp += 1;
            }
        }
        if cp > 0 {
            let child = build(entries, depth + cp, target, path);
            rlp_list(&[
                rlp_bytes(&compact(&deeper[0].k[depth..depth + cp], false)),
                reference(&child),
            ])
        } else {
            let mut items = Vec::with_capacity(17);
            for n in 0..16u8 {
                let group: Vec<&Entry<'_>> =
                    deeper.iter().copied().filter(|e| e.k[depth] == n).collect();
                items.push(if group.is_empty() {
                    rlp_bytes(&[])
                } else {
                    reference(&build(&group, depth + 1, target, path))
                });
            }
            items.push(rlp_bytes(if here.len() == 1 { here[0].v } else { &[] }));
            rlp_list(&items)
        }
    };
    // the proof carries every hash-referenced node of the path (an embedded one travels inside its parent); the root always
    if on_path && (node.len() >= 32 || depth == 0) {
        path.push(node.clone());
    }
    node
}

/// Build the trie of `entries` (distinct keys): its root and the root-to-leaf path of `target` (empty if `target` is None).
pub fn build_trie(
    entries: &[(Vec<u8>, Vec<u8>)],
    target: Option<&[u8]>,
) -> ([u8; 32], Vec<Vec<u8>>) {
    if entries.is_empty() {
        return (he(&[&rlp_bytes(&[])]), Vec::new());
    }
    let es: Vec<Entry<'_>> = entries
        .iter()
        .map(|(k, v)| Entry { k: nibbles(k), v })
        .collect();
    let refs: Vec<&Entry<'_>> = es.iter().collect();
    let t = target.map(nibbles);
    let mut path = Vec::new();
    let root = build(&refs, 0, t.as_deref(), &mut path);
    path.reverse();
    (he(&[&root]), path)
}
