//! The resource policy of the direct path (owner section 36, bft-core briefs/b7-direct-uncapped-design.md section 1) and fixed
//! protocol bytes of the native profile (protocol version 4).
//!
//! The numbers of the first block are the `limits` of `protocol/profile-v5.json`, the single source shared with the oracle, the
//! contract and the TypeScript plug-in (`tests/limits_and_shards.rs` pins them). There is no gas ceiling and no history cap: the
//! composition (BRIDGE_COMPOSE_V1) streams the history and the anchor table, bounded by the envelope (the ingress bound the pool and
//! RPC carry), the u16 anchor wire width and its gas (bft-core briefs/dev4-b7-native-compose-spec.md section 7). The transfer, leaf
//! and semantic-byte bounds are the standalone B2 kernel's own (0x0104, which prepareLock calls); the rest are per-object shape
//! bounds. Every count is checked before allocation or cryptography.

// ---- profile parameters (profile-v5.json `limits`) ----------------------------------------------
/// Distinct UC anchors of one redemption: the wire width (the CERT_BATCH_V2 claim count and every anchorIndex are u16).
pub const MAX_ANCHORS: usize = 65535;
/// Standalone B2 transfers including the final burn (ureth b2 `MAX_TRANSFERS`).
pub const MAX_TRANSFERS: usize = 64;
/// Standalone B2 leaves: the mint and every transfer (the kernel's result bound).
pub const MAX_LEAVES: usize = MAX_TRANSFERS + 1;
/// Standalone B2 history and Cfg input (ureth b2 `MAX_HISTORY`).
pub const MAX_SEMANTIC_BYTES: usize = 128 << 10;
/// Ingress: the composition's only aggregate byte bound.
pub const MAX_ENVELOPE_BYTES: usize = 2 << 20;
pub const MAX_ANCHOR_UC_BYTES: usize = 8 << 10;
pub const MAX_RSMT_SIBLINGS: usize = 32;
pub const MAX_POLICY_BYTES: usize = 512;
/// B1's own sublimits, which the gate prices.
pub const MAX_UNICITY_STEPS: usize = 32;
/// Signatures of one seal (`CERT_BATCH_V2`, contract section 4).
pub const MAX_SIGS_PER_SEAL: usize = 16;
/// A native shard ID is 1..33 bytes (depth 0..256).
pub const MAX_SHARD_BYTES: usize = 33;
pub const MAX_SHARD_DEPTH: usize = 256;

// ---- the gas estimate (interop.md "Direct-call gas estimate") ------------------------------------
pub const GAS_RESERVE: u64 = 1_000_000;
/// The price of one bridge CBOR item occurrence (Cfg, policy, every UC and every IR opening).
pub const BRIDGE_ITEM_GAS: u64 = 1000;

pub const MAX_CBOR_DEPTH: usize = 16;
pub const MAX_CBOR_ITEMS: usize = 32768;
pub const MAX_RLP_DEPTH: usize = 16;
pub const MAX_AMOUNT_BYTES: usize = 32;

/// The aggregate bounds of one history decode: bytes, transfers (the final burn included) and the CBOR items of the whole history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryBounds {
    pub bytes: usize,
    pub transfers: usize,
    pub items: usize,
}
/// The standalone kernel's (0x0104).
pub const KERNEL_HISTORY: HistoryBounds = HistoryBounds {
    bytes: MAX_SEMANTIC_BYTES,
    transfers: MAX_TRANSFERS,
    items: MAX_CBOR_ITEMS,
};
/// The composition's: the history is bounded by the envelope that carries it; every item and leaf is paid.
pub const COMPOSED_HISTORY: HistoryBounds = HistoryBounds {
    bytes: MAX_ENVELOPE_BYTES,
    transfers: usize::MAX,
    items: usize::MAX,
};

/// The mint justification J as carried in the SDK mint.
pub const MAX_JUSTIFICATION_BYTES: usize = 64 << 10;
pub const MAX_UC_BYTES: usize = 16 << 10;
pub const MAX_PDR_BYTES: usize = 16 << 10;
pub const MAX_HEADER_BYTES: usize = 2 << 10;
pub const MAX_MPT_NODES: usize = 65;
pub const MAX_MPT_NODE_BYTES: usize = 1 << 10;
pub const MAX_MPT_TOTAL_BYTES: usize = 24 << 10;
/// The native InputRecord opening is small and fixed in shape.
pub const MAX_INPUT_RECORD_BYTES: usize = 512;
/// The native sublimit of the certified input record's summary value (`InputRecord._scan`).
pub const MAX_IR_SUMMARY_BYTES: usize = 256;

pub const TAG_PREDICATE: u64 = 39032;
pub const TAG_MINT: u64 = 39041;
pub const TAG_TRANSFER: u64 = 39045;
pub const TAG_CERTIFICATION: u64 = 39031;
pub const TAG_MINT_LOCK: u64 = 39049;
pub const TAG_RETURN_REASON: u64 = 39048;
pub const TAG_WALLET_VALUE: u64 = 39050;
pub const TAG_INPUT_RECORD: u64 = 39002;
pub const TAG_TOKEN: u64 = 39040;
pub const TAG_INCLUSION: u64 = 39033;
pub const TOKEN_VERSION: u64 = 2;
pub const INCLUSION_VERSION: u64 = 1;
/// The SDK token decode (bft-core `DecodeToken`): a whole token and one proof's certificate. A nested ancestor also lies inside the
/// envelope, so the envelope bound binds first.
pub const MAX_DECODED_TOKEN_BYTES: usize = 4 << 20;
pub const MAX_PROOF_UC_BYTES: usize = 24 << 10;

// ---- protocol 6: split lineage (bft-core docs/design/bridge-split-lineage-spec.md) ----
pub const SPLIT_PROTO_VERSION: u32 = 6;
pub const TAG_SPLIT_JUSTIFICATION: u64 = 39044;
pub const TAG_SPLIT_MANIFEST: u64 = 39046;
/// One allocation-proof step per key bit.
pub const MAX_SUM_PROOF_STEPS: usize = 256;

pub const MINT_LOCK_VERSION: u64 = 2;
pub const LOCK_PROOF_VERSION: u64 = 1;

pub const PRED_SIGNATURE: u8 = 1;
pub const PRED_BURN: u8 = 2;

/// The bridge identity family of this profile.
pub use crate::{NATIVE_BRIDGE_FAMILY as FAMILY, SDK_VERSION};

/// A whole token as it travels (genesis with embedded lock proof plus every certified transfer).
pub const MAX_TOKEN_BYTES: usize = 2 << 20;
