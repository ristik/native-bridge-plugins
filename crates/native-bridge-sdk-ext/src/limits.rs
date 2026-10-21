//! The resource policy of the direct path (owner section 36, bft-core briefs/b7-direct-uncapped-design.md section 1) and fixed
//! protocol bytes of the native profile (protocol version 4).
//!
//! The numbers of the first block are the `limits` of `protocol/profile-v5.json`, the single source shared with the oracle, the
//! contract and the TypeScript plug-in (`tests/limits_and_shards.rs` pins them). There is no gas ceiling and no bridge-specific
//! history cap: the aggregate bounds are the native kernels' own (B2 transfers and history, B1 claims) until the native composition
//! streams them; the envelope bound is the ingress bound the pool and RPC carry; the rest are per-object shape bounds. Every count is
//! checked before allocation or cryptography.

// ---- profile parameters (profile-v5.json `limits`) ----------------------------------------------
/// Distinct UC anchors of one redemption (one per distinct complete UC): B1's claim bound.
pub const MAX_ANCHORS: usize = 16;
/// B2 transfers including the final burn (ureth b2 `MAX_TRANSFERS`).
pub const MAX_TRANSFERS: usize = 64;
/// B2 leaves of one redemption: the mint and every transfer (the kernel's result bound).
pub const MAX_LEAVES: usize = MAX_TRANSFERS + 1;
/// B2 history (ureth b2 `MAX_HISTORY`).
pub const MAX_SEMANTIC_BYTES: usize = 128 << 10;
/// Ingress: above every envelope the native bounds admit.
pub const MAX_ENVELOPE_BYTES: usize = 512 << 10;
pub const MAX_ANCHOR_UC_BYTES: usize = 8 << 10;
pub const MAX_RSMT_SIBLINGS: usize = 32;
pub const MAX_POLICY_BYTES: usize = 512;
/// B1's own sublimits, which the gate prices.
pub const MAX_UNICITY_STEPS: usize = 32;
/// Signatures of one seal and over one batch (`CERT_BATCH_V2`), contract section 4.
pub const MAX_SIGS_PER_SEAL: usize = 16;
pub const MAX_TOTAL_SIGS: usize = 256;
/// A native shard ID is 1..33 bytes (depth 0..256).
pub const MAX_SHARD_BYTES: usize = 33;
pub const MAX_SHARD_DEPTH: usize = 256;
/// The batch request: bytes and the raw (pre-deduplication) path steps of all occurrences.
pub const MAX_BATCH_BYTES: usize = 262_144;
pub const MAX_RAW_STEPS: usize = 4_608;

// ---- the gas estimate (interop.md "Direct-call gas estimate") ------------------------------------
pub const GAS_RESERVE: u64 = 1_000_000;
/// The price of one bridge CBOR item occurrence (Cfg, policy, every UC and every IR opening).
pub const BRIDGE_ITEM_GAS: u64 = 1000;

pub const MAX_CBOR_DEPTH: usize = 16;
pub const MAX_CBOR_ITEMS: usize = 32768;
pub const MAX_RLP_DEPTH: usize = 16;
pub const MAX_AMOUNT_BYTES: usize = 32;

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

pub const MINT_LOCK_VERSION: u64 = 2;
pub const LOCK_PROOF_VERSION: u64 = 1;

pub const PRED_SIGNATURE: u8 = 1;
pub const PRED_BURN: u8 = 2;

/// The bridge identity family of this profile.
pub use crate::{NATIVE_BRIDGE_FAMILY as FAMILY, SDK_VERSION};

/// A whole token as it travels (genesis with embedded lock proof plus every certified transfer).
pub const MAX_TOKEN_BYTES: usize = 2 << 20;
