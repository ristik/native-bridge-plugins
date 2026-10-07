//! The one token-unlock acceptance rule of the native profile.
//!
//! Exactly 65 bytes; `1 <= r < n`; `1 <= s <= n/2`; recovery ID 0..=3. The signer is recovered from
//! the digest and `(r, s, id)` and must equal the reconstructed source key; only then is `(r, s)`
//! verified against that key. The supplied recovery ID and a high-`s` signature are never
//! normalised. The SDK's generic signature verification ignores the recovery byte, so every
//! universal-minter and transfer unlock goes through [`verify_unlock`].

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use unicity_token::cbor::{encode_array, encode_byte_string};

use crate::error::{NativeError as E, Result};
use crate::profile::h;

/// `H(C(b(sourceHash32), b(txHash32)))`, with no extra prehash.
pub fn unlock_message(source_hash: &[u8; 32], tx_hash: &[u8; 32]) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(source_hash),
        &encode_byte_string(tx_hash),
    ]))
}

/// Verify an unlock against the reconstructed source key.
pub fn verify_unlock(
    key: &VerifyingKey,
    source_hash: &[u8; 32],
    tx_hash: &[u8; 32],
    unlock: &[u8],
) -> Result<()> {
    if unlock.len() != 65 {
        return Err(E::UnlockLength);
    }
    // from_slice rejects r or s equal to zero or at least n.
    let sig = Signature::from_slice(&unlock[..64]).map_err(|_| E::UnlockScalars)?;
    // normalize_s returns Some(..) iff s was high.
    if sig.normalize_s().is_some() {
        return Err(E::UnlockScalars);
    }
    if unlock[64] > 3 {
        return Err(E::UnlockRecovery);
    }
    let rid = RecoveryId::from_byte(unlock[64]).ok_or(E::UnlockRecovery)?;
    let digest = unlock_message(source_hash, tx_hash);
    let recovered =
        VerifyingKey::recover_from_prehash(&digest, &sig, rid).map_err(|_| E::UnlockKey)?;
    if recovered != *key {
        return Err(E::UnlockKey);
    }
    key.verify_prehash(&digest, &sig).map_err(|_| E::Unlock)
}

/// Parse a 33-byte compressed key; uncompressed and identity forms are not admitted.
pub fn parse_key(b: &[u8]) -> Result<VerifyingKey> {
    if b.len() != 33 || (b[0] != 2 && b[0] != 3) {
        return Err(E::Predicate);
    }
    VerifyingKey::from_sec1_bytes(b).map_err(|_| E::Predicate)
}
