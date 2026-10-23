/**
 * BRIDGE_COMPOSE_V1 (0x0105), the native composition of B7 direct PR 2 (bft-core `bridgeprofile/native.go`): the input encoding,
 * the fixed 384-byte output and the append-only status table (`config/compose-status.json` in the corpus). The wrapper reverts
 * `BridgeRejected(uint256 status)` with these codes; a host decodes them with `composeStatusName`.
 */
import { concat } from './bytes.js';

export const COMPOSE_ADDRESS = '0x0000000000000000000000000000000000000105' as const;
/** `bytes32("UNICITY_BRIDGE_COMPOSE_V1")`, left aligned. */
export const COMPOSE_MARKER: Uint8Array = (() => {
  const m = new Uint8Array(32);
  m.set(new TextEncoder().encode('UNICITY_BRIDGE_COMPOSE_V1'));
  return m;
})();
export const COMPOSE_OUTPUT_BYTES = 384;

/** Status code i is `COMPOSE_STATUS[i - 1]`; code 0 is success. Append-only, pinned against the corpus. */
export const COMPOSE_STATUS: readonly string[] = ["ErrTruncated","ErrTrailing","ErrNonCanonical","ErrForbiddenCBOR","ErrShape","ErrTag","ErrVersion","ErrLength","ErrIntRange","ErrABIFraming","ErrBadOperation","ErrDeadline","ErrInputTooLarge","ErrTooManyTx","ErrTooManyItems","ErrTooDeep","ErrTooManyPaths","ErrJustificationTooLarge","ErrLockProofTooLarge","ErrCfgMismatch","ErrPolicyHash","ErrPolicyTuple","ErrPolicyAnchors","ErrPolicyLeafIndex","ErrPolicyLeafCount","ErrPolicyPartition","ErrPredicate","ErrMintShape","ErrLockProofShape","ErrLockProofCfg","ErrMintJustif","ErrMintSalt","ErrMintType","ErrMintData","ErrTransferData","ErrCDMismatch","ErrUnlock","ErrUnlockLength","ErrUnlockScalars","ErrUnlockRecovery","ErrUnlockKey","ErrMinterKey","ErrRepeatedSID","ErrNoTransfers","ErrHasTransfers","ErrBurnNotFinal","ErrNotBurn","ErrBurnReason","ErrReturnData","ErrReturnAmount","ErrReturnRecip","ErrLockInput","ErrZeroDigest","ErrDeadlineMismatch","ErrDeadlineExpired","ErrIROpening","ErrIRShape","ErrIRState","ErrIRTime","ErrPathBitmap","ErrAnchorAuth","ErrLeafProof"];

/** The reason name of a status code: `ok` for 0, `undefined` for an unknown code. */
export const composeStatusName = (code: number): string | undefined => (code === 0 ? 'ok' : COMPOSE_STATUS[code - 1]);

const word = (v: bigint): Uint8Array => {
  const w = new Uint8Array(32);
  for (let i = 31, x = v; i >= 0 && x > 0n; i--, x >>= 8n) w[i] = Number(x & 0xffn);
  return w;
};
const padded = (b: Uint8Array): Uint8Array => concat(word(BigInt(b.length)), b, new Uint8Array((32 - (b.length % 32)) % 32));

/** `abi.encode(uint8 op, bytes cfg, bytes envelope)`: the canonical native input (its length is the schedule's B). */
export function composeInput(op: number, cfg: Uint8Array, envelope: Uint8Array): Uint8Array {
  const c = padded(cfg);
  return concat(word(BigInt(op)), word(96n), word(BigInt(96 + c.length)), c, padded(envelope));
}

/** The status word of a 384-byte output, or `undefined` when the bytes are not an output (wrong length or marker). */
export function composeOutputStatus(out: Uint8Array): number | undefined {
  if (out.length !== COMPOSE_OUTPUT_BYTES || !COMPOSE_MARKER.every((x, i) => out[i] === x)) return undefined;
  let s = 0n;
  for (let i = 32; i < 64; i++) s = (s << 8n) | BigInt(out[i]);
  return Number(s);
}

// ---- BRIDGE_COMPOSE_V2 (protocol 6, bft-core `native_lineage.go`) ----------------------------------------

/** `bytes32("UNICITY_BRIDGE_COMPOSE_V2")`, left aligned. */
export const COMPOSE_MARKER_V2: Uint8Array = (() => {
  const m = new Uint8Array(32);
  m.set(new TextEncoder().encode('UNICITY_BRIDGE_COMPOSE_V2'));
  return m;
})();
/** Fifteen words: V1's twelve (the root's identity), then partTokenId, partAmount and splitDepth. */
export const COMPOSE_OUTPUT_BYTES_V2 = 15 * 32;

/** The V1 table with the split reasons appended, then the two certificate-codec reasons an embedded ancestor proof can raise. */
export const COMPOSE_STATUS_V2: readonly string[] = [
  ...COMPOSE_STATUS,
  'ErrSplitJustif', 'ErrSplitProofCount', 'ErrSplitProofShape', 'ErrSplitManifest', 'ErrSplitBurn', 'ErrSplitProof', 'ErrSplitSum',
  'ErrCertScan', 'ErrCertSigLength',
];

export const composeStatusNameV2 = (code: number): string | undefined => (code === 0 ? 'ok' : COMPOSE_STATUS_V2[code - 1]);

/** A decoded successful V2 output (amounts minimal big-endian, as the relation returns them). */
export interface ComposeResultV2 {
  cfg: Uint8Array;
  nonce: bigint;
  amount: Uint8Array;
  tokenId: Uint8Array;
  salt: Uint8Array;
  firstPredicateHash: Uint8Array;
  lockDigest: Uint8Array;
  releaseTo: Uint8Array;
  nullifier: Uint8Array;
  leafCount: bigint;
  partTokenId: Uint8Array;
  partAmount: Uint8Array;
  splitDepth: bigint;
}

const wordAt = (b: Uint8Array, i: number): Uint8Array => b.subarray(32 * i, 32 * i + 32);
const big = (w: Uint8Array): bigint => w.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
const minimal = (w: Uint8Array): Uint8Array => w.subarray(w.findIndex((x) => x !== 0) === -1 ? w.length : w.findIndex((x) => x !== 0));

/**
 * Strictly decode a V2 output (bft-core `DecodeComposeOutputV2`): the marker, a status in the table, every field zero on a failure,
 * and on success words that fit (a 64-bit nonce and depth, a 20-byte releaseTo). `undefined` for anything else.
 */
export function decodeComposeOutputV2(out: Uint8Array): { status: number; result?: ComposeResultV2 } | undefined {
  if (out.length !== COMPOSE_OUTPUT_BYTES_V2 || !COMPOSE_MARKER_V2.every((x, i) => out[i] === x)) return undefined;
  const status = big(wordAt(out, 1));
  if (status >= BigInt(COMPOSE_STATUS_V2.length + 1)) return undefined;
  if (status !== 0n) return out.subarray(64).every((x) => x === 0) ? { status: Number(status) } : undefined;
  const nonce = big(wordAt(out, 3));
  const depth = big(wordAt(out, 14));
  if (nonce >> 64n !== 0n || depth >> 64n !== 0n || out.subarray(288, 300).some((x) => x !== 0)) return undefined;
  return {
    status: 0,
    result: {
      cfg: wordAt(out, 2), nonce, amount: minimal(wordAt(out, 4)), tokenId: wordAt(out, 5), salt: wordAt(out, 6),
      firstPredicateHash: wordAt(out, 7), lockDigest: wordAt(out, 8), releaseTo: out.subarray(300, 320), nullifier: wordAt(out, 10),
      leafCount: big(wordAt(out, 11)), partTokenId: wordAt(out, 12), partAmount: minimal(wordAt(out, 13)), splitDepth: depth,
    },
  };
}
