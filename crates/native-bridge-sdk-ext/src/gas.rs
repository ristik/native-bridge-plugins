//! The gas estimate of a redemption. Since B7 direct PR 2 the composition is one native call, BRIDGE_COMPOSE_V1 at 0x0105, and
//! its charge is the trial schedule of bft-core `bridgeprofile/native.go` (`ComposeGas`), computed here from the same scans:
//!
//! `G_compose = 100000 + 2*B + 20*J + 16000*L + 6000*Q + 29900*E + 2000*A + 250*P + 50*K*ceil(log2 K)`
//!
//! with B the native input bytes (`abi.encode(uint8 op, bytes cfg, bytes envelope)`), J the CBOR item heads of the Cfg, the policy
//! body, the history, every anchor UC and every anchor IR opening, L the leaves, Q/E/A/K the CERT_BATCH_V2 grouping of the anchor
//! table and P its certificate steps plus every leaf's RSMT siblings. The transaction estimate (`total`) adds the calldata intrinsic
//! gas and the fixed reserve for the wrapper and the vault. It is a number a wallet sets its gas limit from, never an admission
//! rule (owner section 36). The protocol-5 composite (`legacy_total` and its components) is kept only because the corpus `gate`
//! cases still publish it.

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

/// The dimensions the BRIDGE_COMPOSE_V1 schedule prices (bft-core `ComposeDims`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ComposeDims {
    pub b: u64,
    pub j: u64,
    pub l: u64,
    pub q: u64,
    pub e: u64,
    pub a: u64,
    pub k: u64,
    pub p: u64,
}

pub const COMPOSE_BASE: u64 = 100_000;
pub const COMPOSE_PER_BYTE: u64 = 2;
pub const COMPOSE_PER_ITEM: u64 = 20;
pub const COMPOSE_PER_LEAF: u64 = 16_000;
pub const COMPOSE_PER_SIGNATURE: u64 = 6_000;
pub const COMPOSE_PER_EPOCH: u64 = 29_900;
pub const COMPOSE_PER_CLAIM: u64 = 2_000;
pub const COMPOSE_PER_STEP: u64 = 250;
pub const COMPOSE_PER_GROUP_STEP: u64 = 50;

/// `50*K*ceil(log2 K)`: sort-based grouping of K claim occurrences (zero for K <= 1).
pub const fn compose_group_gas(k: u64) -> u64 {
    if k <= 1 {
        0
    } else {
        COMPOSE_PER_GROUP_STEP * k * (64 - (k - 1).leading_zeros() as u64)
    }
}

/// The native charge of a BRIDGE_COMPOSE_V1 call that succeeds.
pub const fn compose_gas(d: &ComposeDims) -> u64 {
    COMPOSE_BASE
        + COMPOSE_PER_BYTE * d.b
        + COMPOSE_PER_ITEM * d.j
        + COMPOSE_PER_LEAF * d.l
        + COMPOSE_PER_SIGNATURE * d.q
        + COMPOSE_PER_EPOCH * d.e
        + COMPOSE_PER_CLAIM * d.a
        + COMPOSE_PER_STEP * d.p
        + compose_group_gas(d.k)
}

/// `21000 + 16*D_max`: the calldata intrinsic gas of the canonical two-bytes-argument call.
pub const fn calldata_gas(cfg_bytes: u64, envelope_bytes: u64) -> u64 {
    INTRINSIC_BASE + PER_BYTE * max_calldata(cfg_bytes, envelope_bytes)
}

/// The CBOR item heads of one object, 0 when it does not scan (bft-core charges an object's J only once it scans).
fn items_or_zero(b: &[u8]) -> u64 {
    count_items(b, MAX_CBOR_ITEMS).map_or(0, |n| n as u64)
}

/// The estimate of a redemption: the BRIDGE_COMPOSE_V1 dimensions and charge, the transaction estimate, and the protocol-5
/// composite of the corpus `gate` cases with its components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    pub compose: ComposeDims,
    /// `G_compose`, the native charge.
    pub native: u64,
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
    /// The transaction estimate: `21000 + 16*D_max + G_compose + 1,000,000`.
    pub total: u64,
    /// The protocol-5 composite `G_gate`.
    pub legacy_total: u64,
}

impl Gate {
    fn finish(mut self, cfg_bytes: u64, envelope_bytes: u64) -> Self {
        self.legacy_total =
            self.intrinsic + self.b2 + self.batch + self.items + self.rsmt + GAS_RESERVE;
        self.native = compose_gas(&self.compose);
        self.total = calldata_gas(cfg_bytes, envelope_bytes) + self.native + GAS_RESERVE;
        self
    }
}

/// Estimate a complete bounded envelope (never a refusal): the native charge, the transaction estimate and the legacy composite.
pub fn compute_gate(
    cfg: &[u8],
    envelope_bytes: usize,
    kernel_request: u64,
    env: &Envelope,
) -> Result<Gate> {
    // J: the item occurrences of the Cfg, the policy body, every anchor IR opening and (counted by the batch scan) every anchor
    // UC, each once. There is no shared budget: each object is bounded by its own native scan (TooManyItems), and every item is
    // charged. A malformed object is its own shape failure.
    let mut spent = 0usize;
    let mut take = |b: &[u8]| -> Result<()> {
        match count_items(b, MAX_CBOR_ITEMS) {
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
    let grouping = measure(&env.anchors).map_err(|e| match e {
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
    let (cfg_bytes, env_bytes) = (cfg.len() as u64, envelope_bytes as u64);
    let compose = ComposeDims {
        b: kernel_request_bytes(cfg_bytes, env_bytes),
        j: j + items_or_zero(&env.history),
        l: env.leaf_proofs.len() as u64,
        q: grouping.q,
        e: grouping.e,
        a: grouping.a,
        k: grouping.k,
        p: steps,
    };
    let g = Gate {
        compose,
        native: 0,
        intrinsic: intrinsic_gas(cfg_bytes, env_bytes),
        b2: b2_gas(kernel_request, env.leaf_proofs.len() as u64),
        batch: batch_gas(&grouping),
        items: item_gas(j),
        rsmt,
        steps,
        j,
        grouping,
        total: 0,
        legacy_total: 0,
    };
    Ok(g.finish(cfg_bytes, env_bytes))
}

/// Lower bounds for the best-case projection, each at most what a real bundle can cost: the smallest certificate in the corpus
/// (the one-signature fixture, 445 bytes at depth 0), one signature, and an input record of no bytes.
pub const BEST_UC_BYTES: u64 = 445;
pub const BEST_IR_BYTES: u64 = 0;
pub const BEST_SIGNATURES: u64 = 1;
/// The CBOR items of the smallest certificate: the fixture's depth-0 certificate has 45 with four signatures, each signature
/// entry is two (key and value).
pub const BEST_UC_ITEMS: u64 = 39;

/// The burn-time best-case projection with the shard count unknown: one anchor (a single certificate may serve every leaf). See
/// [`projected_gate_anchors`].
pub fn projected_gate(
    cfg_bytes: u64,
    policy_bytes: u64,
    leaves: u64,
    history_bytes: u64,
) -> (Gate, u64) {
    projected_gate_anchors(cfg_bytes, policy_bytes, leaves, history_bytes, 1)
}

/// The burn-time best-case projection: the estimate of the redemption envelope a token with `leaves` leaves (the burn included) and a
/// `history_bytes` history would need if everything the burn cannot yet know turns out as small as it can: the consolidated
/// bundle, `anchors` anchors (one per aggregator shard the leaves touch, at least 1, at most `leaves`) under ONE seal, the smallest
/// certificates and empty paths. It is the burn-time estimate only: nothing is refused for its size (owner section 36). Returns
/// the estimate and the projected envelope bytes.
pub fn projected_gate_anchors(
    cfg_bytes: u64,
    policy_bytes: u64,
    leaves: u64,
    history_bytes: u64,
    anchors: u64,
) -> (Gate, u64) {
    let k = anchors.min(leaves).max(1);
    let word = 32u64;
    let bytes_field = |n: u64| word + pad32(n);
    let anchor_bytes =
        7 * word + bytes_field(1) + bytes_field(BEST_UC_BYTES) + bytes_field(BEST_IR_BYTES);
    let leaf_bytes = 3 * word + word;
    let envelope = 4 * word
        + bytes_field(policy_bytes)
        + bytes_field(history_bytes)
        + word
        + k * (word + anchor_bytes)
        + word
        + leaves * (word + leaf_bytes);
    let grouping = Counts {
        k,
        c: 4 + k * (106 + 1 + BEST_UC_BYTES),
        e: 1,
        s: 1,
        q: BEST_SIGNATURES,
        a: k,
        p: 0,
        items: k * BEST_UC_ITEMS,
    };
    let j = fixed_items(k as usize) as u64 + grouping.items;
    // The history's own items are not counted (a lower bound: the burn cannot see the final history's encoding).
    let compose = ComposeDims {
        b: kernel_request_bytes(cfg_bytes, envelope),
        j,
        l: leaves,
        q: BEST_SIGNATURES,
        e: 1,
        a: k,
        k,
        p: 0,
    };
    let g = Gate {
        compose,
        native: 0,
        intrinsic: intrinsic_gas(cfg_bytes, envelope),
        b2: b2_gas(kernel_request_bytes(cfg_bytes, history_bytes), leaves),
        batch: batch_gas(&grouping),
        items: item_gas(j),
        rsmt: leaves * rsmt_gas(0),
        steps: 0,
        j,
        grouping,
        total: 0,
        legacy_total: 0,
    };
    (g.finish(cfg_bytes, envelope), envelope)
}
