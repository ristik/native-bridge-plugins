//! The shared direct-call gas gate (interop.md "Direct-call gas gate"): the same formula, with the same
//! constants, as the oracle (`bridgeprofile/gas.go`), the contract (`BridgeBounds.sol`, `UcScan.sol`)
//! and the TypeScript plug-in. Every term is the native price of a call the composing verifier makes,
//! computed from complete bounded scans, never from caller-declared costs. It is an admission rule, not a
//! measured fit.

use crate::envelope::{Anchor, Envelope, LeafProof};
use crate::error::{NativeError as E, Result};
use crate::limits::*;
use crate::profile::Policy;

const INTRINSIC_BASE: u64 = 21_000;
const PER_BYTE: u64 = 16;
const B2_BASE: u64 = 26_000;
const B2_PER_BYTE: u64 = 20;
const B2_PER_LEAF: u64 = 14_000;
const UC_BASE: u64 = 1_243_700;
const UC_PER_SIGNATURE: u64 = 6_000;
const PER_STEP: u64 = 250;
const RSMT_BASE: u64 = 2_000;
/// UC_V1 request without shard and UC: header 4, partition 4, shard length 2, three words, UC length 4.
const UC_REQUEST_FIXED: u64 = 110;
/// RSMT_MEMBER_V1 request without siblings.
const RSMT_REQUEST_FIXED: u64 = 136;

const fn pad32(n: u64) -> u64 {
    (n + 31) & !31
}

/// `G_intrinsic = 21000 + 16*len(envelope)`.
pub const fn intrinsic_gas(envelope_bytes: u64) -> u64 {
    INTRINSIC_BASE + PER_BYTE * envelope_bytes
}

/// `len(abi.encode(uint8 op, bytes cfg, bytes payload))`.
pub const fn kernel_request_bytes(cfg_bytes: u64, payload_bytes: u64) -> u64 {
    96 + 32 + pad32(cfg_bytes) + 32 + pad32(payload_bytes)
}

/// `G_B2 = 26000 + 20*B_sem + 14000*L`.
pub const fn b2_gas(request_bytes: u64, leaves: u64) -> u64 {
    B2_BASE + B2_PER_BYTE * request_bytes + B2_PER_LEAF * leaves
}

/// `G_UC = 1243700 + 16*B_a + 6000*S_a + 250*P_a` with `B_a = 110 + len(shard) + len(uc)`.
pub const fn uc_gas(shard_bytes: u64, uc_bytes: u64, signatures: u64, steps: u64) -> u64 {
    UC_BASE
        + PER_BYTE * (UC_REQUEST_FIXED + shard_bytes + uc_bytes)
        + UC_PER_SIGNATURE * signatures
        + PER_STEP * steps
}

/// `G_RSMT = 2000 + 16*(136 + 32*s) + 250*(1 + s)`.
pub const fn rsmt_gas(siblings: u64) -> u64 {
    RSMT_BASE + PER_BYTE * (RSMT_REQUEST_FIXED + 32 * siblings) + PER_STEP * (1 + siblings)
}

// ---- the bounded scan of an anchor's UnicityCertificate -----------------------------------------

const TAG_UC: u64 = 39001;
const TAG_SHARD_TREE: u64 = 39003;
const TAG_UNICITY_TREE: u64 = 39004;
const TAG_SEAL: u64 = 39005;

/// One strict head: shortest form, definite length. Returns `(major, argument, next position)`.
fn head(b: &[u8], pos: usize) -> Result<(u8, u64, usize)> {
    let ib = *b.get(pos).ok_or(E::Truncated)?;
    let (major, ai) = (ib >> 5, ib & 0x1f);
    if ai < 24 {
        return Ok((major, u64::from(ai), pos + 1));
    }
    if ai > 27 {
        return Err(if ai == 31 {
            E::ForbiddenCBOR
        } else {
            E::NonCanonical
        });
    }
    let n = 1usize << (ai - 24);
    let raw = b.get(pos + 1..pos + 1 + n).ok_or(E::Truncated)?;
    let arg = raw.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    if (ai == 24 && arg < 24)
        || (ai == 25 && arg <= 0xff)
        || (ai == 26 && arg <= 0xffff)
        || (ai == 27 && arg <= 0xffff_ffff)
    {
        return Err(E::NonCanonical);
    }
    Ok((major, arg, pos + 1 + n))
}

/// Skip one complete item. Every iteration consumes at least one byte.
fn skip(b: &[u8], start: usize) -> Result<usize> {
    let mut pos = start;
    let mut pending: u64 = 1;
    while pending != 0 {
        let (major, arg, next) = head(b, pos)?;
        pos = next;
        pending -= 1;
        match major {
            2 | 3 => {
                if arg > (b.len() - pos) as u64 {
                    return Err(E::Truncated);
                }
                pos += arg as usize;
            }
            4 | 5 => {
                if arg > b.len() as u64 {
                    return Err(E::Truncated);
                }
                pending += if major == 5 { 2 * arg } else { arg };
            }
            6 => pending += 1,
            _ => {}
        }
    }
    Ok(pos)
}

fn tagged(b: &[u8], pos: usize, tag: u64, n: u64) -> Result<usize> {
    let (major, arg, p) = head(b, pos)?;
    if major != 6 || arg != tag {
        return Err(E::Tag);
    }
    let (major, arg, p) = head(b, p)?;
    if major != 4 || arg != n {
        return Err(E::Shape);
    }
    Ok(p)
}

/// Element count of an array (major 4) or map (major 5) at `pos`; null is empty.
fn count(b: &[u8], pos: usize, want: u8) -> Result<(usize, usize)> {
    if b.get(pos) == Some(&0xf6) {
        return Ok((0, pos + 1));
    }
    let (major, arg, next) = head(b, pos)?;
    if major != want || arg > b.len() as u64 {
        return Err(E::Shape);
    }
    Ok((arg as usize, next))
}

/// What the strict structural scan of one anchor's certificate found, and its price.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorScan {
    /// Single-claim 0x0100 request bytes.
    pub request: u64,
    /// Signature entries of the seal (`S`).
    pub sigs: u64,
    /// Shard-tree siblings plus unicity tree steps (`P`).
    pub steps: u64,
    /// `G_UC`.
    pub gas: u64,
}

/// Bound the anchor's UC and price its 0x0100 call. The certificate must name the claim's shard and
/// carry exactly `depth` shard-tree siblings (the policy topology is complete and uniform); the unicity
/// path and the seal are bounded by B1's own sublimits.
pub fn scan_anchor(a: &Anchor, depth: u8) -> Result<AnchorScan> {
    if a.uc.len() > MAX_ANCHOR_UC_BYTES {
        return Err(E::InputTooLarge);
    }
    // Whatever the shape failure, B1 would not authenticate this certificate (oracle `ErrAnchorAuth`).
    scan_uc(a, depth).map_err(|_| E::AnchorAuth)
}

fn scan_uc(a: &Anchor, depth: u8) -> Result<AnchorScan> {
    let b = a.uc.as_slice();
    let mut pos = tagged(b, 0, TAG_UC, 7)?;
    for _ in 0..4 {
        pos = skip(b, pos)?; // version, input record, technical hash, configuration hash
    }
    pos = tagged(b, pos, TAG_SHARD_TREE, 3)?;
    pos = skip(b, pos)?; // version
    let (major, len, next) = head(b, pos)?;
    let end = next
        .checked_add(usize::try_from(len).map_err(|_| E::Shape)?)
        .filter(|&e| e <= b.len())
        .ok_or(E::Shape)?;
    if major != 2 || b[next..end] != a.shard[..] {
        return Err(E::ShardMismatch);
    }
    let (siblings, next) = count(b, end, 4)?;
    if siblings != usize::from(depth) {
        return Err(E::ShardMismatch);
    }
    pos = next;
    for _ in 0..siblings {
        pos = skip(b, pos)?;
    }
    pos = tagged(b, pos, TAG_UNICITY_TREE, 3)?;
    pos = skip(b, pos)?; // version
    pos = skip(b, pos)?; // partition
    let (steps, next) = count(b, pos, 4)?;
    if steps > MAX_UNICITY_STEPS {
        return Err(E::Shape);
    }
    pos = next;
    for _ in 0..steps {
        pos = skip(b, pos)?;
    }
    pos = tagged(b, pos, TAG_SEAL, 8)?;
    for _ in 0..7 {
        pos = skip(b, pos)?;
    }
    let (sigs, _) = count(b, pos, 5)?;
    if sigs > MAX_SIGNATURES {
        return Err(E::Shape);
    }
    let steps_total = (siblings + steps) as u64;
    Ok(AnchorScan {
        request: UC_REQUEST_FIXED + a.shard.len() as u64 + b.len() as u64,
        sigs: sigs as u64,
        steps: steps_total,
        gas: uc_gas(
            a.shard.len() as u64,
            b.len() as u64,
            sigs as u64,
            steps_total,
        ),
    })
}

/// Bound one leaf path (bitmap popcount equal to the sibling count, at most `MAX_RSMT_SIBLINGS`) and
/// price its 0x0102 call. Returns `(gas, steps)`.
pub fn leaf_path_gas(p: &LeafProof) -> Result<(u64, u64)> {
    let pop: usize = p.bitmap.iter().map(|b| b.count_ones() as usize).sum();
    if pop != p.siblings.len() {
        return Err(E::PathBitmap);
    }
    if pop > MAX_RSMT_SIBLINGS {
        return Err(E::TooManyPaths);
    }
    Ok((rsmt_gas(pop as u64), pop as u64))
}

/// The components of the gate and its total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    pub intrinsic: u64,
    pub b2: u64,
    pub uc: u64,
    pub rsmt: u64,
    pub steps: u64,
    /// The gated sum including the fixed reserve.
    pub total: u64,
}

/// Price a complete bounded envelope against `budget`; above it is `GasBudget` (BudgetExceeded).
pub fn compute_gate(
    envelope_bytes: usize,
    kernel_request: u64,
    env: &Envelope,
    pol: &Policy,
    budget: u64,
) -> Result<Gate> {
    let mut g = Gate {
        intrinsic: intrinsic_gas(envelope_bytes as u64),
        b2: b2_gas(kernel_request, env.leaf_proofs.len() as u64),
        uc: 0,
        rsmt: 0,
        steps: 0,
        total: 0,
    };
    for a in &env.anchors {
        let s = scan_anchor(a, pol.depth)?;
        g.uc += s.gas;
        g.steps += s.steps;
    }
    for p in &env.leaf_proofs {
        let (gas, steps) = leaf_path_gas(p)?;
        g.rsmt += gas;
        g.steps += steps;
    }
    if g.steps > MAX_PATH_STEPS as u64 {
        return Err(E::TooManyPaths);
    }
    g.total = g.intrinsic + g.b2 + g.uc + g.rsmt + GAS_RESERVE;
    if g.total > budget {
        return Err(E::GasBudget);
    }
    Ok(g)
}

/// Lower bounds for the best-case projection, each at most what a real bundle can cost: the smallest
/// certificate in the corpus (the one-signature fixture, 445 bytes; the DN-B committee's is 811), one
/// signature, and an input record of no bytes (a structural minimum; a real one is larger).
pub const BEST_UC_BYTES: u64 = 445;
pub const BEST_IR_BYTES: u64 = 0;
pub const BEST_SIGNATURES: u64 = 1;

/// The burn-time best-case projection: the gate of the redemption envelope a token with `leaves` leaves
/// (the burn included) and a `history_bytes` history would need if everything the burn cannot yet know
/// turns out as small as it can: the fewest anchors (`anchors`, the distinct shards the known leaves
/// occupy), the smallest certificates (`BEST_UC_BYTES`, one signature, only the depth-many shard
/// siblings as steps) and empty paths. The burn is refused only when even this cannot pass the gas gate;
/// whether the bundle actually fetched passes is the gate's decision at redemption. Returns the gate and
/// the projected envelope bytes.
pub fn projected_gate(
    cfg_bytes: u64,
    policy_bytes: u64,
    depth: u64,
    anchors: u64,
    leaves: u64,
    history_bytes: u64,
) -> (Gate, u64) {
    let word = 32u64;
    let bytes_field = |n: u64| word + pad32(n);
    let anchor_bytes =
        7 * word + bytes_field(1) + bytes_field(BEST_UC_BYTES) + bytes_field(BEST_IR_BYTES);
    let leaf_bytes = 3 * word + word;
    let envelope = 4 * word
        + bytes_field(policy_bytes)
        + bytes_field(history_bytes)
        + word
        + anchors * (word + anchor_bytes)
        + word
        + leaves * (word + leaf_bytes);
    let mut g = Gate {
        intrinsic: intrinsic_gas(envelope),
        b2: b2_gas(kernel_request_bytes(cfg_bytes, history_bytes), leaves),
        uc: anchors * uc_gas(1, BEST_UC_BYTES, BEST_SIGNATURES, depth),
        rsmt: leaves * rsmt_gas(0),
        steps: anchors * depth,
        total: 0,
    };
    g.total = g.intrinsic + g.b2 + g.uc + g.rsmt + GAS_RESERVE;
    (g, envelope)
}
