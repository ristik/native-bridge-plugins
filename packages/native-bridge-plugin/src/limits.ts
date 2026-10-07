/** Provisional DEV bounds and fixed protocol constants (protocol version 2). Limits are intersected. */
export const NATIVE_BRIDGE_PROTO_VERSION = 2 as const;

export const MAX_TRANSFERS = 64;
export const MAX_LEAVES = MAX_TRANSFERS + 1;
export const MAX_SEMANTIC_BYTES = 128 << 10;
export const MAX_ENVELOPE_BYTES = 256 << 10;
export const MAX_CBOR_DEPTH = 16;
export const MAX_CBOR_ITEMS = 32768;
export const MAX_RLP_DEPTH = 16;
export const MAX_PATH_STEPS = 2048;
export const MAX_POLICY_BYTES = 128;
export const MAX_AMOUNT_BYTES = 32;
export const MAX_ANCHORS = 1;

export const MAX_JUSTIFICATION_BYTES = 64 << 10;
export const MAX_UC_BYTES = 16 << 10;
export const MAX_PDR_BYTES = 16 << 10;
export const MAX_HEADER_BYTES = 2 << 10;
export const MAX_MPT_NODES = 65;
export const MAX_MPT_NODE_BYTES = 1 << 10;
export const MAX_MPT_TOTAL_BYTES = 24 << 10;
export const MAX_INPUT_RECORD_BYTES = 1 << 10;
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
