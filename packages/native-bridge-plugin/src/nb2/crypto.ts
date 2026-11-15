/** Hashes and the SDK unlock rule (bft-core `nb2ref/crypto.go`). */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

import { concat, eq } from '../bytes.js';
import { ascii, beInt, cArr, cBytes } from './cbor.js';
import { fail } from './errors.js';

/** H_U: raw SHA-256, the Unicity hash. */
export const HU = (...parts: Uint8Array[]): Uint8Array => sha256(concat(...parts));
/** H_E: EVM keccak256. */
export const HE = (...parts: Uint8Array[]): Uint8Array => keccak_256(concat(...parts));
/** I(h) = 0x0000 || h. */
export const imprint = (h: Uint8Array): Uint8Array => concat(Uint8Array.of(0, 0), h);

export const SECP_N = secp256k1.Point.Fn.ORDER;
const HALF_N = SECP_N >> 1n;

/** H(C(b(sourceHash32), b(txHash32))). */
export const unlockMessage = (sourceHash: Uint8Array, txHash: Uint8Array): Uint8Array => HU(cArr(cBytes(sourceHash), cBytes(txHash)));

/**
 * The SDK token-unlock rule, unchanged from protocol 7: exactly 65 bytes r||s||id (`UnlockLength`), 1 <= r < n and 1 <= s <= n/2
 * (`UnlockScalars`), id in 0..1 (`UnlockRecovery`; IDs 2 and 3 are refused for NB2), the key recovered with the supplied id equal to the source key (`UnlockKey`), then
 * the compact verification (defense in depth, reported as `UnlockKey`). Nothing is normalised.
 */
export function verifyUnlock(key33: Uint8Array, sourceHash: Uint8Array, txHash: Uint8Array, unlock: Uint8Array): void {
  if (unlock.length !== 65) fail('UnlockLength');
  const r = beInt(unlock.subarray(0, 32));
  const s = beInt(unlock.subarray(32, 64));
  if (r === 0n || r >= SECP_N || s === 0n || s > HALF_N) fail('UnlockScalars');
  const id = unlock[64];
  // NB2-eligible unlocks use recovery ID 0 or 1 (astra delta review 2026-11-15): 2 and 3 are refused everywhere, so a lineage holding
  // one is not returnable even though it stays valid natively
  if (id > 1) fail('UnlockRecovery');
  const digest = unlockMessage(sourceHash, txHash);
  let recovered: Uint8Array | null;
  try {
    recovered = secp256k1.Signature.fromBytes(concat(Uint8Array.of(id), unlock.subarray(0, 64)), 'recovered').recoverPublicKey(digest).toBytes(true);
  } catch {
    recovered = null;
  }
  if (recovered === null || !eq(recovered, key33)) fail('UnlockKey');
  if (!secp256k1.verify(unlock.subarray(0, 64), digest, key33, { prehash: false, lowS: true, format: 'compact' })) fail('UnlockKey');
}

/** r||s||id over the unlock message, low-s, with the signer's recovery ID. */
export function signUnlock(priv: Uint8Array, sourceHash: Uint8Array, txHash: Uint8Array): Uint8Array {
  const rec = secp256k1.sign(unlockMessage(sourceHash, txHash), priv, { prehash: false, lowS: true, format: 'recovered' });
  return concat(rec.subarray(1, 65), rec.subarray(0, 1));
}

/** H(C(b("I_AM_UNIVERSAL_MINTER_FOR_"), b(id))). */
export const minterScalar = (id: Uint8Array): Uint8Array => HU(cArr(cBytes(ascii('I_AM_UNIVERSAL_MINTER_FOR_')), cBytes(id)));

/** A minter scalar is admitted only as a valid secp256k1 secret, 1 <= k < n, never reduced modulo n. */
export function minterScalarValid(k: Uint8Array): boolean {
  const v = beInt(k);
  return v > 0n && v < SECP_N;
}

/** The universal minter's compressed public key for a token ID (an invalid scalar: no such ID is known, about 2^-128 per ID). */
export function minterKey(id: Uint8Array): Uint8Array {
  const k = minterScalar(id);
  if (!minterScalarValid(k)) throw new Error('nb2: minter scalar outside [1, n)');
  return secp256k1.getPublicKey(k, true);
}

/** A compressed secp256k1 key on the curve (`Predicate` otherwise). */
export function parseKey(b: Uint8Array): Uint8Array {
  if (b.length !== 33 || (b[0] !== 2 && b[0] !== 3)) fail('Predicate');
  try {
    secp256k1.Point.fromBytes(b);
  } catch {
    fail('Predicate');
  }
  return b;
}
