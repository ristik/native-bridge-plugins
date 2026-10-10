/**
 * Named profile-v3 bounds and fixed protocol constants. The numbers of the first block are the
 * `limits` of `protocol/profile-v3.json` (the single source shared with the oracle and the contract;
 * `test/limits.test.ts` pins them): a later profile version raises them together with the gas budget.
 * Limits are intersected, never additive entitlements, and every cumulative bound is checked before
 * allocation or cryptography.
 */
export const NATIVE_BRIDGE_PROTO_VERSION = 3 as const;

// ---- profile parameters (profile-v3.json `limits`) -------------------------------------------------
/** Distinct UC anchors of one redemption (one per distinct complete UC): a parser ceiling, the gas gate decides each bundle. */
export const MAX_ANCHORS = 4;
/** B2 leaves of one redemption: the mint, every transfer and the final burn. */
export const MAX_LEAVES = 16;
export const MAX_TRANSFERS = MAX_LEAVES - 1;
export const MAX_SEMANTIC_BYTES = 16 << 10;
export const MAX_ENVELOPE_BYTES = 64 << 10;
export const MAX_ANCHOR_UC_BYTES = 8 << 10;
export const MAX_RSMT_SIBLINGS = 32;
export const MAX_PATH_STEPS = 2048;
export const MAX_POLICY_BYTES = 512;
/** B1's own sublimits, which the gate prices. */
export const MAX_UNICITY_STEPS = 32;
export const MAX_SIGNATURES = 64;

// ---- the shared gas gate (interop.md "Direct-call gas gate") ----------------------------------------
/** DN-B ordinary transaction capacity. */
export const TX_GAS_BUDGET = 7_000_000;
export const GAS_RESERVE = 1_000_000;

export const MAX_CBOR_DEPTH = 16;
export const MAX_CBOR_ITEMS = 32768;
export const MAX_RLP_DEPTH = 16;
export const MAX_AMOUNT_BYTES = 32;

export const MAX_JUSTIFICATION_BYTES = 64 << 10;
export const MAX_UC_BYTES = 16 << 10;
export const MAX_PDR_BYTES = 16 << 10;
export const MAX_HEADER_BYTES = 2 << 10;
export const MAX_MPT_NODES = 65;
export const MAX_MPT_NODE_BYTES = 1 << 10;
export const MAX_MPT_TOTAL_BYTES = 24 << 10;
export const MAX_INPUT_RECORD_BYTES = 512;
export const MAX_TOKEN_BYTES = 2 << 20;

export const TAG_PREDICATE = 39032n;
export const TAG_MINT = 39041n;
export const TAG_TRANSFER = 39045n;
export const TAG_CERTIFICATION = 39031n;
export const TAG_MINT_LOCK = 39049n;
export const TAG_RETURN_REASON = 39048n;
export const TAG_WALLET_VALUE = 39050n;
export const TAG_INPUT_RECORD = 39002n;

export const MINT_LOCK_VERSION = 2n;
export const LOCK_PROOF_VERSION = 1n;

export const PRED_SIGNATURE = 1;
export const PRED_BURN = 2;

export const NATIVE_BRIDGE_FAMILY = 'unicity-native' as const;
export const FAMILY = NATIVE_BRIDGE_FAMILY;
export const SDK_VERSION = '3.0.1' as const;
