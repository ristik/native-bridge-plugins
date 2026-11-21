use alloc::boxed::Box;
use alloc::vec::Vec;
use num_bigint::BigUint;

use super::cbor::*;
use super::config::{domain, tag};
use super::crypto::hu;
use super::errors::{fail, rule_err, Result, Rule};
use super::token::{encode_predicate, token_id_of, MintTx};
use super::util::{max_bits, u256};

const MAX_SUM_PROOF_STEPS: usize = 256;

fn valid_amount(v: &BigUint) -> bool {
    v.bits() > 0 && v.bits() <= 256
}

fn key_bit(key: &[u8], i: usize) -> bool {
    (key[i >> 3] >> (7 - (i & 7))) & 1 == 1
}

pub fn sum_leaf_hash(key: &[u8], data: &[u8], value: &BigUint) -> Option<[u8; 32]> {
    if !valid_amount(value) {
        return None;
    }
    Some(hu(&[&[0x10], key, data, &u256(value)]))
}

pub fn sum_node_hash(
    depth: u8,
    hl: &[u8],
    sl: &BigUint,
    hr: &[u8],
    sr: &BigUint,
) -> Option<([u8; 32], BigUint)> {
    if !valid_amount(sl) || !valid_amount(sr) {
        return None;
    }
    let sum = sl + sr;
    if sum > max_bits(256) {
        return None;
    }
    Some((hu(&[&[0x11, depth], hl, &u256(sl), hr, &u256(sr)]), sum))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumStep {
    pub depth: u8,
    pub hash: Vec<u8>,
    pub sum: BigUint,
}

pub fn encode_sum_proof(p: &[SumStep]) -> Vec<u8> {
    c_arr_v(
        &p.iter()
            .map(|s| c_arr_v(&[c_uint(s.depth as u64), c_bytes(&s.hash), c_amount(&s.sum)]))
            .collect::<Vec<_>>(),
    )
}

pub fn decode_sum_proof(bytes: &[u8]) -> Result<Vec<SumStep>> {
    let it = scan_bounded_array(bytes, &[], MAX_SUM_PROOF_STEPS, Rule::SplitProofShape)?;
    if it.major != MAJ_ARRAY {
        return fail(Rule::SplitProofShape);
    }
    let mut p = Vec::new();
    let mut prev = 256u64;
    for k in &it.kids {
        let kids = array(k, 3).map_err(|_| rule_err(Rule::SplitProofShape))?;
        let d = uint_in(&kids[0], 0, 255).map_err(|_| rule_err(Rule::SplitProofShape))?;
        if d >= prev {
            return fail(Rule::SplitProofShape);
        }
        prev = d;
        let hash = bytes_n(&kids[1], 32).map_err(|_| rule_err(Rule::SplitProofShape))?;
        let sum = amount(&kids[2]).map_err(|_| rule_err(Rule::SplitProofShape))?;
        p.push(SumStep {
            depth: d as u8,
            hash: hash.to_vec(),
            sum,
        });
    }
    Ok(p)
}

/// Fold the leaf to the root; the root sum iff the fold equals `root`.
pub fn verify_sum_proof(
    p: &[SumStep],
    key: &[u8],
    data: &[u8],
    value: &BigUint,
    root: &[u8],
) -> Option<BigUint> {
    let mut hash = sum_leaf_hash(key, data, value)?;
    let mut sum = value.clone();
    for s in p {
        let r = if key_bit(key, s.depth as usize) {
            sum_node_hash(s.depth, &s.hash, &s.sum, &hash, &sum)
        } else {
            sum_node_hash(s.depth, &hash, &sum, &s.hash, &s.sum)
        }?;
        hash = r.0;
        sum = r.1;
    }
    if hash.as_slice() == root {
        Some(sum)
    } else {
        None
    }
}

pub fn encode_split_manifest(root: &[u8]) -> Vec<u8> {
    c_tag(tag::SPLIT_MANIFEST, &c_arr(&[&c_bytes(root)]))
}

/// A split burn's data; any failure is `SplitManifest`.
pub fn decode_split_manifest(b: &[u8]) -> Result<[u8; 32]> {
    let f = || -> Result<[u8; 32]> {
        let it = scan_one(b)?;
        let k = array(tag_content(&it, tag::SPLIT_MANIFEST)?, 1)?;
        Ok(super::util::arr(bytes_n(&k[0], 32)?))
    };
    f().map_err(|_| rule_err(Rule::SplitManifest))
}

/// The child mint's commitment without its justification.
pub fn split_output_commitment(parent_id: &[u8], m: &MintTx) -> [u8; 32] {
    let child_id = token_id_of(&m.salt, m.network);
    hu(&[&c_arr_v(&[
        c_bytes(domain::SPLIT_OUTPUT.as_bytes()),
        c_bytes(parent_id),
        c_uint(m.network as u64),
        c_bytes(&encode_predicate(&m.recipient)),
        c_bytes(&m.salt),
        c_bytes(&child_id),
        c_bytes(&m.ty),
        c_bytes(m.data.as_deref().unwrap_or(&[])),
        c_deadline(m.deadline),
    ])])
}

pub fn parent_link(
    d: &[u8],
    id: &[u8],
    sid: &[u8],
    tx_hash: &[u8],
    manifest: &[u8],
    value: &BigUint,
) -> [u8; 32] {
    hu(&[
        b"UNICITY/NB2/1.1/PARENT",
        d,
        id,
        sid,
        tx_hash,
        manifest,
        &u256(value),
    ])
}

pub fn decode_split_justification(bytes: &[u8]) -> Result<[u8; 32]> {
    let decode = || {
        let it = scan_one(bytes)?;
        let fields = array(tag_content(&it, tag::SPLIT_JUSTIFICATION)?, 2)?;
        version(&fields[0], 2)?;
        Ok(super::util::arr(bytes_n(&fields[1], 32)?))
    };
    decode().map_err(|_: super::errors::Error| rule_err(Rule::SplitJustif))
}

pub fn encode_split_justification(link: &[u8]) -> Vec<u8> {
    c_tag(
        tag::SPLIT_JUSTIFICATION,
        &c_arr(&[&c_uint(2), &c_bytes(link)]),
    )
}

// ---- the allocation tree (the SDK's radix sparse Merkle sum tree), for building splits and fixtures -------------------

#[derive(Debug, Clone)]
struct SumNode {
    leaf: bool,
    key: [u8; 32],
    depth: u8,
    left: Option<Box<SumNode>>,
    right: Option<Box<SumNode>>,
    hash: [u8; 32],
    sum: BigUint,
}

#[derive(Debug, Clone)]
pub struct SumLeaf {
    pub key: [u8; 32],
    pub data: [u8; 32],
    pub value: BigUint,
}

fn subtree(nodes: Vec<SumNode>, start: usize) -> Result<SumNode> {
    if nodes.len() == 1 {
        return Ok(nodes.into_iter().next().expect("one"));
    }
    let mut depth = start;
    while depth < 256 {
        let first = key_bit(&nodes[0].key, depth);
        if nodes.iter().any(|n| key_bit(&n.key, depth) != first) {
            break;
        }
        depth += 1;
    }
    if depth == 256 {
        return fail(Rule::SplitProofShape);
    }
    let (l, r): (Vec<SumNode>, Vec<SumNode>) =
        nodes.into_iter().partition(|n| !key_bit(&n.key, depth));
    let ln = subtree(l, depth + 1)?;
    let rn = subtree(r, depth + 1)?;
    let (hash, sum) = sum_node_hash(depth as u8, &ln.hash, &ln.sum, &rn.hash, &rn.sum)
        .ok_or_else(|| rule_err(Rule::SplitProofShape))?;
    Ok(SumNode {
        leaf: false,
        key: [0; 32],
        depth: depth as u8,
        left: Some(Box::new(ln)),
        right: Some(Box::new(rn)),
        hash,
        sum,
    })
}

/// The allocation tree of a split.
#[derive(Debug, Clone)]
pub struct SumTree {
    root_node: SumNode,
}

impl SumTree {
    pub fn build(leaves: &[SumLeaf]) -> Result<SumTree> {
        if leaves.is_empty() {
            return fail(Rule::SplitProofShape);
        }
        let mut nodes = Vec::with_capacity(leaves.len());
        for l in leaves {
            let h = sum_leaf_hash(&l.key, &l.data, &l.value)
                .ok_or_else(|| rule_err(Rule::SplitProofShape))?;
            nodes.push(SumNode {
                leaf: true,
                key: l.key,
                depth: 0,
                left: None,
                right: None,
                hash: h,
                sum: l.value.clone(),
            });
        }
        nodes.sort_by_key(|a| a.key);
        for i in 1..nodes.len() {
            if nodes[i].key == nodes[i - 1].key {
                return fail(Rule::SplitProofShape);
            }
        }
        Ok(SumTree {
            root_node: subtree(nodes, 0)?,
        })
    }

    pub fn root(&self) -> [u8; 32] {
        self.root_node.hash
    }

    pub fn proof(&self, key: &[u8; 32]) -> Option<Vec<SumStep>> {
        let mut steps = Vec::new();
        let mut n = &self.root_node;
        while !n.leaf {
            let right = key_bit(key, n.depth as usize);
            let (sib, next) = if right {
                (n.left.as_ref()?, n.right.as_ref()?)
            } else {
                (n.right.as_ref()?, n.left.as_ref()?)
            };
            steps.push(SumStep {
                depth: n.depth,
                hash: sib.hash.to_vec(),
                sum: sib.sum.clone(),
            });
            n = next;
        }
        if &n.key != key {
            return None;
        }
        steps.reverse();
        Some(steps)
    }
}
