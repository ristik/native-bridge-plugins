//! Split primitives of the lineage relation (protocol 6, bft-core `docs/design/bridge-split-lineage-spec.md`, Go
//! `bridgeprofile/split.go`). The byte formats are the SDK's (`payment::{manifest, commitment, justification}` and the radix sum
//! tree); nothing here is bridge-specific except the single-asset restriction.

use alloc::vec::Vec;

use num_bigint::BigUint;
use unicity_token::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint};

use crate::error::{NativeError as E, Result};
use crate::limits::{MAX_SUM_PROOF_STEPS, TAG_SPLIT_JUSTIFICATION, TAG_SPLIT_MANIFEST};
use crate::profile::h;
use crate::scan::{fixed, scan_counted, scan_one, Item, Kind};

const SUM_LEAF_PREFIX: u8 = 0x10;
const SUM_NODE_PREFIX: u8 = 0x11;
const SPLIT_OUTPUT_DOMAIN: &[u8] = b"UNICITY_SPLIT_OUTPUT";

/// The protocol amount domain `1 <= v < 2^256`.
fn valid_amount(v: &BigUint) -> bool {
    v.bits() > 0 && v.bits() <= 256
}

fn u256(v: &BigUint) -> [u8; 32] {
    let b = v.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

/// Minimal positive big-endian bytes (the CBOR amount of a sum step).
pub fn amount_bytes(v: &BigUint) -> Vec<u8> {
    if v.bits() == 0 {
        Vec::new()
    } else {
        v.to_bytes_be()
    }
}

/// Bit `i` of a 256-bit key, MSB first (the SDK's one radix bit order).
fn key_bit(key: &[u8; 32], i: u8) -> bool {
    key[(i / 8) as usize] >> (7 - i % 8) & 1 == 1
}

/// `SHA-256(0x10 || key || data || u256(value))`, or `None` outside the amount domain.
pub fn sum_leaf_hash(key: &[u8; 32], data: &[u8; 32], value: &BigUint) -> Option<[u8; 32]> {
    if !valid_amount(value) {
        return None;
    }
    let mut b = Vec::with_capacity(97);
    b.push(SUM_LEAF_PREFIX);
    b.extend_from_slice(key);
    b.extend_from_slice(data);
    b.extend_from_slice(&u256(value));
    Some(h(&b))
}

/// `SHA-256(0x11 || depth || hL || u256(sL) || hR || u256(sR))` and the checked 256-bit sum, or `None`.
pub fn sum_node_hash(
    depth: u8,
    hl: &[u8; 32],
    sl: &BigUint,
    hr: &[u8; 32],
    sr: &BigUint,
) -> Option<([u8; 32], BigUint)> {
    if !valid_amount(sl) || !valid_amount(sr) {
        return None;
    }
    let sum = sl + sr;
    if sum.bits() > 256 {
        return None;
    }
    let mut b = Vec::with_capacity(130);
    b.push(SUM_NODE_PREFIX);
    b.push(depth);
    b.extend_from_slice(hl);
    b.extend_from_slice(&u256(sl));
    b.extend_from_slice(hr);
    b.extend_from_slice(&u256(sr));
    Some((h(&b), sum))
}

/// One sibling entry of a leaf-to-root path: the parent's bifurcation depth, the sibling subtree hash and its positive sum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumStep {
    pub depth: u8,
    pub hash: [u8; 32],
    pub sum: BigUint,
}

/// The exact CBOR `[[depth, b(hash), b(sum)], ...]`.
pub fn sum_proof_bytes(p: &[SumStep]) -> Vec<u8> {
    let steps: Vec<Vec<u8>> = p
        .iter()
        .map(|s| {
            encode_array(&[
                &encode_uint(s.depth as u64),
                &encode_byte_string(&s.hash),
                &encode_byte_string(&amount_bytes(&s.sum)),
            ])
        })
        .collect();
    let refs: Vec<&[u8]> = steps.iter().map(Vec::as_slice).collect();
    encode_array(&refs)
}

/// Strictly decode an allocation proof item (bft-core `decodeSumProof`).
pub fn decode_sum_proof_item(it: &Item<'_>) -> Result<Vec<SumStep>> {
    let kids = it.any_array().ok_or(E::Shape)?;
    if kids.len() > MAX_SUM_PROOF_STEPS {
        return Err(E::SplitProofShape);
    }
    let mut out = Vec::with_capacity(kids.len());
    let mut prev = 256u16;
    for k in kids {
        let step = k.array(3).ok_or(E::Shape)?;
        let d = step[0].uint_max(255).map_err(|_| E::SplitProofShape)? as u16;
        if d >= prev {
            return Err(E::SplitProofShape);
        }
        prev = d;
        let hash: [u8; 32] = fixed(&step[1])?;
        // a minimal positive big-endian amount of at most 32 bytes
        let sum = match &step[2].kind {
            Kind::Bytes(b) if !b.is_empty() && b.len() <= 32 && b[0] != 0 => {
                BigUint::from_bytes_be(b)
            }
            _ => return Err(E::SplitProofShape),
        };
        out.push(SumStep {
            depth: d as u8,
            hash,
            sum,
        });
    }
    Ok(out)
}

/// Reconstruct the root from the leaf upward; the reconstructed root sum iff the root hash equals `root`. The caller compares that sum
/// with the authenticated source amount: the root hash alone does not conserve value.
pub fn verify_sum_proof(
    p: &[SumStep],
    key: &[u8; 32],
    data: &[u8; 32],
    value: &BigUint,
    root: &[u8; 32],
) -> Option<BigUint> {
    if p.len() > MAX_SUM_PROOF_STEPS {
        return None;
    }
    let mut hash = sum_leaf_hash(key, data, value)?;
    let mut sum = value.clone();
    let mut prev = 256u16;
    for s in p {
        if s.depth as u16 >= prev || !valid_amount(&s.sum) {
            return None;
        }
        let (nh, ns) = if key_bit(key, s.depth) {
            sum_node_hash(s.depth, &s.hash, &s.sum, &hash, &sum)?
        } else {
            sum_node_hash(s.depth, &hash, &sum, &s.hash, &s.sum)?
        };
        hash = nh;
        sum = ns;
        prev = s.depth as u16;
    }
    (hash == *root).then_some(sum)
}

/// The manifest `tag(39046,[b(root)])`: the bridge admits one asset, so exactly one root.
pub fn split_manifest_bytes(root: &[u8; 32]) -> Vec<u8> {
    encode_tag(
        TAG_SPLIT_MANIFEST,
        &encode_array(&[&encode_byte_string(root)]),
    )
}

/// Strictly decode a burn transfer's data as a single-root manifest; returns the root.
pub fn decode_split_manifest(b: &[u8]) -> Result<[u8; 32]> {
    let root = scan_one(b).map_err(|_| E::SplitManifest)?;
    let c = root
        .tag_content(TAG_SPLIT_MANIFEST)
        .map_err(|_| E::SplitManifest)?;
    let k = c.array(1).ok_or(E::SplitManifest)?;
    fixed(&k[0]).map_err(|_| E::SplitManifest)
}

/// `SHA-256(CBOR([b("UNICITY_SPLIT_OUTPUT"), b(sourceId), network, b(encodedRecipient), b(salt), b(childId), b(type),
/// b(exactPaymentBytes)]))`: the child mint without its justification.
pub fn split_output_commitment(
    source_id: &[u8; 32],
    network: u16,
    recipient: &[u8],
    salt: &[u8; 32],
    child_id: &[u8; 32],
    ty: &[u8; 32],
    data: &[u8],
) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(SPLIT_OUTPUT_DOMAIN),
        &encode_byte_string(source_id),
        &encode_uint(network as u64),
        &encode_byte_string(recipient),
        &encode_byte_string(salt),
        &encode_byte_string(child_id),
        &encode_byte_string(ty),
        &encode_byte_string(data),
    ]))
}

/// The decoded split mint reason `tag(39044,[token,[proof]])`: the exact burned source token bytes (an inline item, never
/// re-encoded), its one allocation proof (one asset) and the item count of the justification's own scan, which the composition
/// charges.
#[derive(Debug, Clone)]
pub struct SplitJustification {
    pub token: Vec<u8>,
    pub proof: Vec<SumStep>,
    pub items: usize,
}

/// The exact encoding of a justification from the burned token's bytes and the proof.
pub fn split_justification_bytes(token: &[u8], proof: &[SumStep]) -> Vec<u8> {
    encode_tag(
        TAG_SPLIT_JUSTIFICATION,
        &encode_array(&[token, &encode_array(&[&sum_proof_bytes(proof)])]),
    )
}

/// The tag number of a justification without scanning it: the first head must be a shortest-form tag head.
pub fn justification_tag(j: Option<&[u8]>) -> Option<u64> {
    let j = j?;
    let ib = *j.first()?;
    if ib >> 5 != 6 {
        return None;
    }
    let ai = ib & 0x1f;
    if ai < 24 {
        return Some(ai as u64);
    }
    if ai > 27 {
        return None;
    }
    let n = 1usize << (ai - 24);
    if j.len() - 1 < n {
        return None;
    }
    let arg = j[1..=n].iter().fold(0u64, |a, &x| a << 8 | x as u64);
    let short = match ai {
        24 => arg < 24,
        25 => arg <= 0xff,
        26 => arg <= 0xffff,
        _ => arg <= 0xffff_ffff,
    };
    (!short).then_some(arg)
}

/// Strictly decode a split mint reason. The burned token is decoded strictly by the caller.
pub fn decode_split_justification(j: &[u8]) -> Result<SplitJustification> {
    let (root, items) = scan_counted(j, usize::MAX, true).map_err(|_| E::SplitJustif)?;
    let c = root
        .tag_content(TAG_SPLIT_JUSTIFICATION)
        .map_err(|_| E::SplitJustif)?;
    let k = c.array(2).ok_or(E::SplitJustif)?;
    let proofs = match (&k[0].kind, &k[1].kind) {
        (Kind::Tag(..), Kind::Array(p)) => p,
        _ => return Err(E::SplitJustif),
    };
    if proofs.len() != 1 {
        return Err(E::SplitProofCount);
    }
    Ok(SplitJustification {
        token: k[0].raw(j).to_vec(),
        proof: decode_sum_proof_item(&proofs[0])?,
        items,
    })
}
