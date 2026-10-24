/**
 * The resource policy of the direct path (owner section 36, bft-core briefs/b7-direct-uncapped-design.md section 1) and fixed
 * protocol constants. The numbers of the first block are the `limits` of `protocol/profile-v6.json` (the single source shared with
 * the oracle and the contract; `test/limits.test.ts` pins them). There is no gas ceiling and no history cap: the composition
 * (BRIDGE_COMPOSE_V1) streams the history and the anchor table, bounded by the envelope (the ingress bound the pool and RPC carry),
 * the u16 anchor wire width and its gas (bft-core briefs/dev4-b7-native-compose-spec.md section 7). The transfer, leaf and
 * semantic-byte bounds are the standalone B2 kernel's own (0x0104, which prepareLock calls); the rest are per-object shape bounds.
 * Every count is checked before allocation or cryptography.
 */
export const NATIVE_BRIDGE_PROTO_VERSION = 6 as const;

// ---- profile parameters (profile-v6.json `limits`) -------------------------------------------------
/** Distinct UC anchors of one redemption: the wire width (the CERT_BATCH_V2 claim count and every anchorIndex are u16). */
export const MAX_ANCHORS = 65535;
/** Standalone B2 transfers including the final burn (ureth b2 `MAX_TRANSFERS`). */
export const MAX_TRANSFERS = 64;
/** Standalone B2 leaves: the mint and every transfer (the kernel's result bound). */
export const MAX_LEAVES = MAX_TRANSFERS + 1;
/** Standalone B2 history and Cfg input (ureth b2 `MAX_HISTORY`). */
export const MAX_SEMANTIC_BYTES = 128 << 10;
/** Ingress: the composition's only aggregate byte bound. */
export const MAX_ENVELOPE_BYTES = 2 << 20;
export const MAX_ANCHOR_UC_BYTES = 8 << 10;
export const MAX_RSMT_SIBLINGS = 32;
export const MAX_POLICY_BYTES = 512;
/** B1's own sublimits, which the gate prices. */
export const MAX_UNICITY_STEPS = 32;
/** Signatures of one seal (`CERT_BATCH_V2`, contract section 4). */
export const MAX_SIGS_PER_SEAL = 16;
/** A native shard ID is 1..33 bytes (depth 0..256). */
export const MAX_SHARD_BYTES = 33;
export const MAX_SHARD_DEPTH = 256;
export const MAX_BATCH_UC_BYTES = 24_576;

// ---- the gas estimate (interop.md "Direct-call gas estimate") ----------------------------------------
export const GAS_RESERVE = 1_000_000;
/** The price of one bridge CBOR item occurrence (Cfg, policy, every UC and every IR opening). */
export const BRIDGE_ITEM_GAS = 1000;

export const MAX_CBOR_DEPTH = 16;
export const MAX_CBOR_ITEMS = 32768;
export const MAX_RLP_DEPTH = 16;
export const MAX_AMOUNT_BYTES = 32;

/** The aggregate bounds of one history decode: bytes, transfers (the final burn included) and the CBOR items of the whole history. */
export interface HistoryBounds { readonly bytes: number; readonly transfers: number; readonly items: number }
/** The standalone kernel's (0x0104). */
export const KERNEL_HISTORY: HistoryBounds = { bytes: MAX_SEMANTIC_BYTES, transfers: MAX_TRANSFERS, items: MAX_CBOR_ITEMS };
/** The composition's: the history is bounded by the envelope that carries it; every item and leaf is paid. */
export const COMPOSED_HISTORY: HistoryBounds = { bytes: MAX_ENVELOPE_BYTES, transfers: Number.MAX_SAFE_INTEGER, items: Number.MAX_SAFE_INTEGER };

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
export const TAG_TOKEN = 39040n;
export const TAG_INCLUSION = 39033n;
export const TOKEN_VERSION = 2n;
export const INCLUSION_VERSION = 1n;
/** The SDK token decode (bft-core `DecodeToken`): a whole token and one proof's certificate. A nested ancestor also lies inside the
 * envelope, so the envelope bound binds first. */
export const MAX_DECODED_TOKEN_BYTES = 4 << 20;
export const MAX_PROOF_UC_BYTES = 24 << 10;

// ---- protocol 6: split lineage (bft-core docs/design/bridge-split-lineage-spec.md) ------------------
export const SPLIT_PROTO_VERSION = NATIVE_BRIDGE_PROTO_VERSION;
export const TAG_SPLIT_JUSTIFICATION = 39044n;
export const TAG_SPLIT_MANIFEST = 39046n;
/** One allocation-proof step per key bit. */
export const MAX_SUM_PROOF_STEPS = 256;
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
