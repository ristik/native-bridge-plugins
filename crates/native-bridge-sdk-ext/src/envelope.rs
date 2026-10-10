//! The proof envelope `abi.encode(bytes policyBody, bytes history, Anchor[] anchors, LeafProof[]
//! leafProofs)` and the composing verifier's policy and input-record checks.
//!
//! `Anchor = (uint32 partition, bytes shard, bytes32 shardConfHash, bytes32 expectedStateRoot,
//! bytes32 expectedIRHash, bytes uc, bytes inputRecord)`: the exact canonical native InputRecord
//! opening is appended after `uc`, all earlier fields keep their order.

use alloc::vec::Vec;

use crate::error::{NativeError as E, Result};
use crate::limits::*;
use crate::profile::{h, Cfg, Policy};
use crate::scan::{fixed, scan_one};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub partition: u32,
    pub shard: Vec<u8>,
    pub shard_conf_hash: [u8; 32],
    pub expected_state_root: [u8; 32],
    pub expected_ir_hash: [u8; 32],
    pub uc: Vec<u8>,
    pub input_record: Vec<u8>,
}

/// `(uint16 anchorIndex, bytes32 bitmap, bytes32[] siblings)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafProof {
    pub anchor_index: u16,
    pub bitmap: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub policy_body: Vec<u8>,
    pub history: Vec<u8>,
    pub anchors: Vec<Anchor>,
    pub leaf_proofs: Vec<LeafProof>,
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn pad(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(32) * 32, 0);
}

fn enc_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = word_u64(b.len() as u64).to_vec();
    pad(&mut out, b);
    out
}

fn enc_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = word_u64(items.len() as u64).to_vec();
    let mut off = items.len() * 32;
    for it in items {
        out.extend_from_slice(&word_u64(off as u64));
        off += it.len();
    }
    for it in items {
        out.extend_from_slice(it);
    }
    out
}

impl Envelope {
    /// The canonical ABI encoding.
    pub fn encode(&self) -> Vec<u8> {
        let a = enc_bytes(&self.policy_body);
        let b = enc_bytes(&self.history);
        let anchors: Vec<Vec<u8>> = self
            .anchors
            .iter()
            .map(|x| {
                // head: partition, off(shard), conf, root, ir, off(uc), off(inputRecord) = 7 words
                let shard = enc_bytes(&x.shard);
                let uc = enc_bytes(&x.uc);
                let ir = enc_bytes(&x.input_record);
                let mut t = Vec::new();
                t.extend_from_slice(&word_u64(x.partition as u64));
                t.extend_from_slice(&word_u64(7 * 32));
                t.extend_from_slice(&x.shard_conf_hash);
                t.extend_from_slice(&x.expected_state_root);
                t.extend_from_slice(&x.expected_ir_hash);
                t.extend_from_slice(&word_u64((7 * 32 + shard.len()) as u64));
                t.extend_from_slice(&word_u64((7 * 32 + shard.len() + uc.len()) as u64));
                t.extend_from_slice(&shard);
                t.extend_from_slice(&uc);
                t.extend_from_slice(&ir);
                t
            })
            .collect();
        let c = enc_array(&anchors);
        let leaves: Vec<Vec<u8>> = self
            .leaf_proofs
            .iter()
            .map(|x| {
                let mut t = Vec::new();
                t.extend_from_slice(&word_u64(x.anchor_index as u64));
                t.extend_from_slice(&x.bitmap);
                t.extend_from_slice(&word_u64(3 * 32));
                t.extend_from_slice(&word_u64(x.siblings.len() as u64));
                for s in &x.siblings {
                    t.extend_from_slice(s);
                }
                t
            })
            .collect();
        let d = enc_array(&leaves);
        let mut out = Vec::new();
        let mut off = 4 * 32;
        for part in [&a, &b, &c, &d] {
            out.extend_from_slice(&word_u64(off as u64));
            off += part.len();
        }
        for part in [&a, &b, &c, &d] {
            out.extend_from_slice(part);
        }
        out
    }

    /// Decode and reject noncanonical offsets, padding, aliases and trailing data by requiring
    /// that re-encoding reproduces the input exactly. Counts are bounded before allocation.
    pub fn decode(b: &[u8]) -> Result<Envelope> {
        if b.len() > MAX_ENVELOPE_BYTES {
            return Err(E::InputTooLarge);
        }
        if b.len() % 32 != 0 || b.len() < 4 * 32 {
            return Err(E::ABIFraming);
        }
        bound_counts(b)?;
        let env = Self::decode_lenient(b).ok_or(E::ABIFraming)?;
        if env.encode() != b {
            return Err(E::ABIFraming);
        }
        Ok(env)
    }

    fn decode_lenient(b: &[u8]) -> Option<Envelope> {
        let w = |off: usize| word_at(b, off);
        let usz = |v: u64| usize::try_from(v).ok();
        let add = |a: usize, c: usize| a.checked_add(c);
        let fixed32 =
            |off: usize| -> Option<[u8; 32]> { b.get(off..add(off, 32)?)?.try_into().ok() };
        let bytes_at = |off: usize| -> Option<Vec<u8>> {
            let len = usz(w(off)?)?;
            let start = add(off, 32)?;
            Some(b.get(start..add(start, len)?)?.to_vec())
        };
        let policy_body = bytes_at(usz(w(0)?)?)?;
        let history = bytes_at(usz(w(32)?)?)?;
        let a_base = usz(w(64)?)?;
        let na = usz(w(a_base)?)?;
        let mut anchors = Vec::new();
        for i in 0..na {
            let t = add(
                add(a_base, 32)?,
                usz(w(add(add(a_base, 32)?, i.checked_mul(32)?)?)?)?,
            )?;
            let part = w(t)?;
            if part > u32::MAX as u64 {
                return None;
            }
            anchors.push(Anchor {
                partition: part as u32,
                shard: bytes_at(add(t, usz(w(add(t, 32)?)?)?)?)?,
                shard_conf_hash: fixed32(add(t, 64)?)?,
                expected_state_root: fixed32(add(t, 96)?)?,
                expected_ir_hash: fixed32(add(t, 128)?)?,
                uc: bytes_at(add(t, usz(w(add(t, 5 * 32)?)?)?)?)?,
                input_record: bytes_at(add(t, usz(w(add(t, 6 * 32)?)?)?)?)?,
            });
        }
        let l_base = usz(w(96)?)?;
        let nl = usz(w(l_base)?)?;
        let mut leaf_proofs = Vec::new();
        for i in 0..nl {
            let head = add(add(l_base, 32)?, i.checked_mul(32)?)?;
            let t = add(add(l_base, 32)?, usz(w(head)?)?)?;
            let idx = w(t)?;
            if idx > u16::MAX as u64 {
                return None;
            }
            let s_off = add(t, usz(w(add(t, 64)?)?)?)?;
            let ns = usz(w(s_off)?)?;
            let mut siblings = Vec::new();
            for j in 0..ns {
                siblings.push(fixed32(add(add(s_off, 32)?, j.checked_mul(32)?)?)?);
            }
            leaf_proofs.push(LeafProof {
                anchor_index: idx as u16,
                bitmap: fixed32(add(t, 32)?)?,
                siblings,
            });
        }
        Some(Envelope {
            policy_body,
            history,
            anchors,
            leaf_proofs,
        })
    }
}

/// The word at `off` as a u64; a read past the end or a value above 2^64-1 is None.
fn word_at(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(32)?)?;
    if s[..24].iter().any(|&x| x != 0) {
        return None;
    }
    Some(u64::from_be_bytes(s[24..].try_into().ok()?))
}

/// Reads the declared counts straight from the head words and walks the leaf proofs with
/// overflow-safe offsets, so an over-budget anchor, leaf or cumulative sibling count is rejected
/// before anything is allocated.
fn bound_counts(b: &[u8]) -> Result<()> {
    let n = b.len() as u64;
    let word = |off: u64| -> Option<u64> { word_at(b, usize::try_from(off).ok()?) };
    let off_anchors = word(64).ok_or(E::ABIFraming)?;
    let off_leaves = word(96).ok_or(E::ABIFraming)?;
    if off_anchors > n || off_leaves > n {
        return Err(E::ABIFraming);
    }
    let na = word(off_anchors).filter(|&v| v <= n).ok_or(E::ABIFraming)?;
    if na > MAX_ANCHORS as u64 {
        return Err(E::TooManyPaths);
    }
    // Every anchor's UC is bounded from its declared length before anything is allocated.
    for i in 0..na {
        let t = (off_anchors + 32)
            .checked_add(word(off_anchors + 32 + 32 * i).ok_or(E::ABIFraming)?)
            .ok_or(E::ABIFraming)?;
        let uc_rel = t.checked_add(5 * 32).and_then(word).ok_or(E::ABIFraming)?;
        let uc_len = t.checked_add(uc_rel).and_then(word).ok_or(E::ABIFraming)?;
        if uc_len > MAX_ANCHOR_UC_BYTES as u64 {
            return Err(E::InputTooLarge);
        }
    }
    let nl = word(off_leaves).filter(|&v| v <= n).ok_or(E::ABIFraming)?;
    if nl > MAX_LEAVES as u64 {
        return Err(E::TooManyPaths);
    }
    let mut steps = 0u64;
    for i in 0..nl {
        let rel = word(off_leaves + 32 + 32 * i).ok_or(E::ABIFraming)?;
        let t = (off_leaves + 32).checked_add(rel).ok_or(E::ABIFraming)?;
        let s_rel = t.checked_add(64).and_then(word).ok_or(E::ABIFraming)?;
        let s_off = t.checked_add(s_rel).ok_or(E::ABIFraming)?;
        let ns = word(s_off).ok_or(E::ABIFraming)?;
        if ns > MAX_RSMT_SIBLINGS as u64 || ns > MAX_PATH_STEPS as u64 - steps {
            return Err(E::TooManyPaths);
        }
        steps += ns;
    }
    Ok(())
}

/// The composing verifier's opening, run before the kernel and before any B1 call: the supplied body is
/// hashed against `Cfg.aggregatorPolicyHash` before it is interpreted, decoded, the aggregator partition
/// must differ from the EVM partition and the anchor count must be within the bound. A submitted anchor
/// table never chooses its own admission.
pub fn check_policy_body(cfg: &Cfg, env: &Envelope) -> Result<Policy> {
    if env.policy_body.len() > MAX_POLICY_BYTES {
        return Err(E::InputTooLarge);
    }
    if h(&env.policy_body) != cfg.aggregator_policy_hash {
        return Err(E::PolicyHash);
    }
    let pol = Policy::from_bytes(&env.policy_body)?;
    if pol.to_bytes() != env.policy_body {
        return Err(E::NonCanonical);
    }
    if pol.partition == cfg.evm_partition {
        return Err(E::PolicyPartition);
    }
    if env.anchors.is_empty() || env.anchors.len() > MAX_ANCHORS {
        return Err(E::PolicyAnchors);
    }
    Ok(pol)
}

/// The anchor each leaf is certified by: an index into the envelope's anchor table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorPlan {
    pub leaf_anchor: Vec<usize>,
}

/// The envelope's anchor table must be exactly the function of the exported leaves the profile
/// defines: one leaf proof per leaf in kernel order; every anchor's partition, shard and configuration
/// equal to a policy row; anchors pairwise distinct by complete UC bytes (byte-identical UCs are one
/// anchor, never two); anchors numbered by first use in leaf order with none unused; and each leaf's
/// `anchorIndex` naming an anchor of the leaf's own shard (the top `depth` bits of its state ID).
/// Different UCs of one shard, even of one root round, are separate anchors. The number of anchors is
/// not tied to the number of shards.
pub fn plan_anchors(pol: &Policy, env: &Envelope, sids: &[[u8; 32]]) -> Result<AnchorPlan> {
    if env.leaf_proofs.len() != sids.len() {
        return Err(E::PolicyLeafCount);
    }
    if env.anchors.is_empty() || env.anchors.len() > MAX_ANCHORS || env.anchors.len() > sids.len() {
        return Err(E::PolicyAnchors);
    }
    let mut row_of = Vec::new();
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for a in &env.anchors {
        let row = (0..pol.shard_confs.len())
            .find(|&r| a.shard.as_slice() == pol.shard_id(r))
            .ok_or(E::PolicyTuple)?;
        if a.partition != pol.partition || a.shard_conf_hash != pol.shard_confs[row] {
            return Err(E::PolicyTuple);
        }
        row_of.push(row);
        let uc = h(&a.uc);
        if seen.contains(&uc) {
            return Err(E::PolicyAnchors);
        }
        seen.push(uc);
    }
    let mut leaf_anchor = Vec::new();
    let mut next = 0usize;
    for (i, sid) in sids.iter().enumerate() {
        let idx = usize::from(env.leaf_proofs[i].anchor_index);
        if idx >= env.anchors.len() || idx > next || row_of[idx] != pol.shard_row(sid) {
            return Err(E::PolicyLeafIndex);
        }
        if idx == next {
            next += 1;
        }
        leaf_anchor.push(idx);
    }
    if next != env.anchors.len() {
        return Err(E::PolicyAnchors);
    }
    Ok(AnchorPlan { leaf_anchor })
}

/// The fields of the exact canonical native InputRecord opening (tag 39002, version 1, arity 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRecordOpening {
    pub round: u64,
    pub epoch: u64,
    pub state_hash: [u8; 32],
    pub timestamp: u64,
}

/// Bound, scan and parse an InputRecord opening under the strict field, null and width rules.
pub fn parse_input_record(raw: &[u8]) -> Result<InputRecordOpening> {
    if raw.len() > MAX_INPUT_RECORD_BYTES {
        return Err(E::InputTooLarge);
    }
    let root = scan_one(raw)?;
    let k = root
        .tag_content(TAG_INPUT_RECORD)?
        .array(10)
        .ok_or(E::Shape)?;
    k[0].version(1)?;
    // previousHash (3) and blockHash (7) and executedTransactionsHash (9) are null or 32 bytes.
    for i in [3usize, 7, 9] {
        if let Some(b) = k[i].nullable_bytes()? {
            if b.len() != 32 {
                return Err(E::Length);
            }
        }
    }
    k[5].nullable_bytes()?; // summary value: null or bytes
    k[8].uint()?; // fees
    Ok(InputRecordOpening {
        round: k[1].uint()?,
        epoch: k[2].uint()?,
        state_hash: fixed(&k[4])?,
        timestamp: k[6].uint()?,
    })
}

/// Open every anchor and bound every leaf's reference time by the timestamp of the leaf's own anchor
/// (`t <=` its own IR time, never another anchor's): `H(inputRecord) == expectedIRHash` and the opened
/// state hash equals `expectedStateRoot`. Only after the B1 call authenticates an anchor does its
/// opened timestamp authorise this.
pub fn check_anchors(
    env: &Envelope,
    plan: &AnchorPlan,
    leaf_times: &[u64],
) -> Result<Vec<InputRecordOpening>> {
    let mut opened = Vec::new();
    for a in &env.anchors {
        if h(&a.input_record) != a.expected_ir_hash {
            return Err(E::InputRecordMismatch);
        }
        let ir = parse_input_record(&a.input_record)?;
        if ir.state_hash != a.expected_state_root {
            return Err(E::InputRecordMismatch);
        }
        opened.push(ir);
    }
    for (i, &t) in leaf_times.iter().enumerate() {
        if t > opened[plan.leaf_anchor[i]].timestamp {
            return Err(E::ReferenceTimeFuture);
        }
    }
    Ok(opened)
}
