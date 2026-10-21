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
