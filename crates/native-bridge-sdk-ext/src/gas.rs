//! The shared direct-call gas gate (interop.md "Direct-call gas gate"): the same formula, with the same constants, as the oracle
//! (`bridgeprofile/gas.go`), the contract (`BridgeBounds.sol`, `CertGroups.sol`) and the TypeScript plug-in. Every term is the
//! native price of a call the composing verifier makes, or the bounded execution of the verifier itself, computed from complete
//! bounded scans, never from caller-declared costs. It is an admission rule, not a measured fit:
//!
//! `G_gate = 21000 + 16*D_max + 80*B_env + 1000*J + G_kernel + G_batch + sum_i G_leaf(i) + 1,000,000`

use crate::certgroups::{batch_gas, count_items, measure, Counts};
use crate::envelope::{Envelope, LeafProof};
use crate::error::{NativeError as E, Result};
use crate::limits::*;

const INTRINSIC_BASE: u64 = 21_000;
const PER_BYTE: u64 = 16;
/// The composing verifier's own execution per envelope byte.
const EXEC_PER_BYTE: u64 = 80;
const B2_BASE: u64 = 26_000;
const B2_PER_BYTE: u64 = 20;
const B2_PER_LEAF: u64 = 14_000;
const PER_STEP: u64 = 250;
const RSMT_BASE: u64 = 2_000;
/// RSMT_MEMBER_V1 request without siblings.
const RSMT_REQUEST_FIXED: u64 = 136;
/// The canonical two-bytes-argument TokenVerifier call: selector 4, two offsets and two lengths 128.
const CALL_FIXED: u64 = 4 + 128;

/// Items of the fixed-shape objects the verifier opens itself: Cfg, policy, one IR opening per anchor.
pub const CFG_ITEMS: usize = 17;
pub const POLICY_ITEMS: usize = 4;
pub const IR_ITEMS: usize = 12;

const fn pad32(n: u64) -> u64 {
    (n + 31) & !31
}

/// `D_max = 4 + 128 + pad32(B_cfg) + pad32(B_env)`: the calldata of the canonical call, an allowance.
pub const fn max_calldata(cfg_bytes: u64, envelope_bytes: u64) -> u64 {
    CALL_FIXED + pad32(cfg_bytes) + pad32(envelope_bytes)
}

/// `21000 + 16*D_max + 80*B_env`.
pub const fn intrinsic_gas(cfg_bytes: u64, envelope_bytes: u64) -> u64 {
    INTRINSIC_BASE
        + PER_BYTE * max_calldata(cfg_bytes, envelope_bytes)
        + EXEC_PER_BYTE * envelope_bytes
}

/// `len(abi.encode(uint8 op, bytes cfg, bytes payload))`.
pub const fn kernel_request_bytes(cfg_bytes: u64, payload_bytes: u64) -> u64 {
    96 + 32 + pad32(cfg_bytes) + 32 + pad32(payload_bytes)
}

/// `G_kernel = 26000 + 20*B_kernel + 14000*L`.
pub const fn b2_gas(request_bytes: u64, leaves: u64) -> u64 {
    B2_BASE + B2_PER_BYTE * request_bytes + B2_PER_LEAF * leaves
}

/// `G_leaf = 2000 + 16*(136 + 32*s) + 250*(1 + s)`.
pub const fn rsmt_gas(siblings: u64) -> u64 {
    RSMT_BASE + PER_BYTE * (RSMT_REQUEST_FIXED + 32 * siblings) + PER_STEP * (1 + siblings)
}

/// `G_items = 1000*J`.
pub const fn item_gas(items: u64) -> u64 {
    BRIDGE_ITEM_GAS * items
}

/// The items the verifier itself opens besides the UC occurrences: Cfg, policy and one IR opening per anchor.
pub const fn fixed_items(anchors: usize) -> usize {
    CFG_ITEMS + POLICY_ITEMS + IR_ITEMS * anchors
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
    /// `G_batch`.
    pub batch: u64,
    /// `G_items`.
    pub items: u64,
    pub rsmt: u64,
    pub steps: u64,
    /// `J`, the bridge CBOR item occurrences.
    pub j: u64,
    /// The grouping the batch is priced by.
    pub grouping: Counts,
    /// The gated sum including the fixed reserve.
    pub total: u64,
}

/// Price a complete bounded envelope against `budget`; above it is `GasBudget` (BudgetExceeded).
pub fn compute_gate(
    cfg: &[u8],
    envelope_bytes: usize,
    kernel_request: u64,
    env: &Envelope,
    budget: u64,
) -> Result<Gate> {
    // J: the item occurrences of the Cfg, the policy body, every anchor IR opening and (counted by the batch scan) every anchor
    // UC, each once, against the one shared budget. A malformed object is its own shape failure; crossing the budget is
    // TooManyItems.
    let mut spent = 0usize;
    let mut take = |b: &[u8]| -> Result<()> {
        match count_items(b, BRIDGE_CBOR_ITEMS - spent) {
            Ok(n) => {
                spent += n;
                Ok(())
            }
            Err(E::TooManyItems) => Err(E::TooManyItems),
            Err(_) => Err(E::Shape),
        }
    };
    take(cfg)?;
    take(&env.policy_body)?;
    for a in &env.anchors {
        take(&a.input_record)?;
    }
    // A malformed certificate is an anchor-authentication failure, an over-bound one a budget refusal.
    let grouping = measure(&env.anchors, spent).map_err(|e| match e {
        E::TooManyItems | E::TooManyPaths => e,
        _ => E::AnchorAuth,
    })?;
    let j = spent as u64 + grouping.items;
    let mut rsmt = 0u64;
    let mut steps = grouping.p;
    for p in &env.leaf_proofs {
        let (gas, st) = leaf_path_gas(p)?;
        rsmt += gas;
        steps += st;
    }
    if steps > MAX_PATH_STEPS as u64 {
        return Err(E::TooManyPaths);
    }
    let mut g = Gate {
        intrinsic: intrinsic_gas(cfg.len() as u64, envelope_bytes as u64),
        b2: b2_gas(kernel_request, env.leaf_proofs.len() as u64),
        batch: batch_gas(&grouping),
        items: item_gas(j),
        rsmt,
        steps,
        j,
        grouping,
        total: 0,
    };
    g.total = g.intrinsic + g.b2 + g.batch + g.items + g.rsmt + GAS_RESERVE;
    if g.total > budget {
        return Err(E::GasBudget);
    }
    Ok(g)
}

/// Lower bounds for the best-case projection, each at most what a real bundle can cost: the smallest certificate in the corpus
/// (the one-signature fixture, 445 bytes at depth 0), one signature, and an input record of no bytes.
pub const BEST_UC_BYTES: u64 = 445;
pub const BEST_IR_BYTES: u64 = 0;
pub const BEST_SIGNATURES: u64 = 1;
/// The CBOR items of the smallest certificate: the fixture's depth-0 certificate has 45 with four signatures, each signature
/// entry is two (key and value).
pub const BEST_UC_ITEMS: u64 = 39;

/// The burn-time best-case projection: the gate of the redemption envelope a token with `leaves` leaves (the burn included) and a
/// `history_bytes` history would need if everything the burn cannot yet know turns out as small as it can: ONE anchor (a single
/// certificate may serve every leaf, so the best case is never one anchor per shard), the smallest certificate and empty paths.
/// The burn is refused only when even this cannot pass the gas gate; whether the bundle actually fetched passes is the gate's
/// decision at redemption. Returns the gate and the projected envelope bytes.
pub fn projected_gate(
    cfg_bytes: u64,
    policy_bytes: u64,
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
        + (word + anchor_bytes)
        + word
        + leaves * (word + leaf_bytes);
    let grouping = Counts {
        k: 1,
        c: 4 + 106 + 1 + BEST_UC_BYTES,
        e: 1,
        s: 1,
        q: BEST_SIGNATURES,
        a: 1,
        p: 0,
        items: BEST_UC_ITEMS,
    };
    let j = fixed_items(1) as u64 + grouping.items;
    let mut g = Gate {
        intrinsic: intrinsic_gas(cfg_bytes, envelope),
        b2: b2_gas(kernel_request_bytes(cfg_bytes, history_bytes), leaves),
        batch: batch_gas(&grouping),
        items: item_gas(j),
        rsmt: leaves * rsmt_gas(0),
        steps: 0,
        j,
        grouping,
        total: 0,
    };
    g.total = g.intrinsic + g.b2 + g.batch + g.items + g.rsmt + GAS_RESERVE;
    (g, envelope)
}
