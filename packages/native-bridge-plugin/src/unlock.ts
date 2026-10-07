import { secp256k1 } from '@noble/curves/secp256k1.js';
import { DataHash } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHash.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { Signature } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Signature.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';

import { eq } from './bytes.js';
import { fail } from './errors.js';
import { H, arr, bs } from './profile.js';

const N = secp256k1.Point.Fn.ORDER;
const HALF_N = N >> 1n;

/** `H(C(b(sourceHash32), b(txHash32)))` with no extra prehash. */
export const unlockMessage = (sourceHash: Uint8Array, txHash: Uint8Array): Uint8Array => H(arr(bs(sourceHash), bs(txHash)));

const toBig = (b: Uint8Array): bigint => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);

/**
 * The one token-unlock acceptance rule: exactly 65 bytes, 1<=r<n, 1<=s<=n/2, recovery ID 0..3,
 * recover the signer, require equality with the reconstructed source key, then verify the compact
 * signature through the SDK. No normalisation; IDs 2/3 need a real matching recovery.
 */
export async function verifyUnlock(key33: Uint8Array, sourceHash: Uint8Array, txHash: Uint8Array, unlock: Uint8Array): Promise<void> {
  if (unlock.length !== 65) fail('ErrUnlockLength');
  const r = toBig(unlock.subarray(0, 32));
  const s = toBig(unlock.subarray(32, 64));
  if (r === 0n || r >= N || s === 0n || s > HALF_N) fail('ErrUnlockScalars');
  if (unlock[64] > 3) fail('ErrUnlockRecovery');
  const digest = unlockMessage(sourceHash, txHash);
  let recovered: Uint8Array | null = null;
  try {
    recovered = secp256k1.Signature.fromBytes(new Uint8Array([unlock[64], ...unlock.subarray(0, 64)]), 'recovered')
      .recoverPublicKey(digest)
      .toBytes();
  } catch {
    recovered = null;
  }
  if (recovered === null || !eq(recovered, key33)) fail('ErrUnlockKey');
  const ok = await SigningService.verifyWithPublicKey(new DataHash(HashAlgorithm.SHA256, digest), Signature.decode(unlock), key33);
  if (!ok) fail('ErrUnlock');
}

export function parseKey(b: Uint8Array): Uint8Array {
  if (b.length !== 33 || (b[0] !== 2 && b[0] !== 3) || !secp256k1.utils.isValidPublicKey(b, true)) return fail('ErrPredicate');
  return b;
}
