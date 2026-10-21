/**
 * The resource policy of the direct path (owner section 36, bft-core briefs/b7-direct-uncapped-design.md section 1) and fixed
 * protocol constants. The numbers of the first block are the `limits` of `protocol/profile-v5.json` (the single source shared with
 * the oracle and the contract; `test/limits.test.ts` pins them). There is no gas ceiling and no bridge-specific history cap: the
 * aggregate bounds are the native kernels' own (B2 transfers and history, B1 claims) until the native composition streams them;
 * the envelope bound is the ingress bound the pool and RPC carry; the rest are per-object shape bounds. Every count is checked
 * before allocation or cryptography.
 */
export const NATIVE_BRIDGE_PROTO_VERSION = 5 as const;

// ---- profile parameters (profile-v5.json `limits`) -------------------------------------------------
/** Distinct UC anchors of one redemption (one per distinct complete UC): B1's claim bound. */
export const MAX_ANCHORS = 16;
/** B2 transfers including the final burn (ureth b2 `MAX_TRANSFERS`). */
export const MAX_TRANSFERS = 64;
/** B2 leaves of one redemption: the mint and every transfer (the kernel's result bound). */
export const MAX_LEAVES = MAX_TRANSFERS + 1;
/** B2 history (ureth b2 `MAX_HISTORY`). */
export const MAX_SEMANTIC_BYTES = 128 << 10;
/** Ingress: above every envelope the native bounds admit. */
export const MAX_ENVELOPE_BYTES = 512 << 10;
export const MAX_ANCHOR_UC_BYTES = 8 << 10;
export const MAX_RSMT_SIBLINGS = 32;
export const MAX_POLICY_BYTES = 512;
/** B1's own sublimits, which the gate prices. */
export const MAX_UNICITY_STEPS = 32;
/** Signatures of one seal and over one batch (`CERT_BATCH_V2`), contract section 4. */
export const MAX_SIGS_PER_SEAL = 16;
export const MAX_TOTAL_SIGS = 256;
/** A native shard ID is 1..33 bytes (depth 0..256). */
export const MAX_SHARD_BYTES = 33;
export const MAX_SHARD_DEPTH = 256;
/** The batch request: claim count, bytes and the raw (pre-deduplication) path steps of all occurrences. */
export const MAX_BATCH_BYTES = 262_144;
export const MAX_RAW_STEPS = 4_608;
export const MAX_BATCH_UC_BYTES = 24_576;

// ---- the gas estimate (interop.md "Direct-call gas estimate") ----------------------------------------
export const GAS_RESERVE = 1_000_000;
/** The price of one bridge CBOR item occurrence (Cfg, policy, every UC and every IR opening). */
export const BRIDGE_ITEM_GAS = 1000;

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
/** The native sublimit of the certified input record's summary value (`InputRecord._scan`, `resources.ts`). */
export const MAX_IR_SUMMARY_BYTES = 256;
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
export const SDK_VERSION = '4.0.0' as const;
