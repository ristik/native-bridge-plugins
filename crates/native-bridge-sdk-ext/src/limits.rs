//! Named profile-v3 bounds and fixed protocol bytes of the native profile (protocol version 3).
//!
//! The numbers of the first block are the `limits` of `protocol/profile-v3.json`, the single source
//! shared with the oracle, the contract and the TypeScript plug-in (`tests/limits.rs` pins them). A
//! later profile version raises them together with the gas budget. Limits are intersected, not
//! additive entitlements: every cumulative bound is checked before allocation or cryptography.

// ---- profile parameters (profile-v3.json `limits`) ----------------------------------------------
/// Distinct UC anchors of one redemption (one per distinct complete UC).
pub const MAX_ANCHORS: usize = 2;
/// B2 leaves of one redemption: the mint, every transfer and the final burn.
pub const MAX_LEAVES: usize = 16;
pub const MAX_TRANSFERS: usize = MAX_LEAVES - 1;
pub const MAX_SEMANTIC_BYTES: usize = 16 << 10;
pub const MAX_ENVELOPE_BYTES: usize = 64 << 10;
pub const MAX_ANCHOR_UC_BYTES: usize = 8 << 10;
pub const MAX_RSMT_SIBLINGS: usize = 32;
pub const MAX_PATH_STEPS: usize = 2048;
pub const MAX_POLICY_BYTES: usize = 512;
/// B1's own sublimits, which the gate prices.
pub const MAX_UNICITY_STEPS: usize = 32;
pub const MAX_SIGNATURES: usize = 64;

// ---- the shared gas gate (interop.md "Direct-call gas gate") ------------------------------------
/// DN-B ordinary transaction capacity.
pub const TX_GAS_BUDGET: u64 = 7_000_000;
pub const GAS_RESERVE: u64 = 1_000_000;

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
