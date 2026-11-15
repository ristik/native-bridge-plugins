//! Hashes and the SDK unlock rule (`crypto.ts`; bft-core `nb2ref/crypto.go`).

use alloc::vec::Vec;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use super::cbor::{c_arr, c_bytes};
use super::errors::{fail, Result, Rule};
use super::util::arr;

/// H_U: raw SHA-256, the Unicity hash.
pub fn hu(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// H_E: EVM keccak256.
pub fn he(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-SHA256(key, msg).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&hu(&[key]));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = hu(&[&ipad, msg]);
    hu(&[&opad, &inner])
}

/// I(h) = 0x0000 || h.
pub fn imprint(h: &[u8]) -> Vec<u8> {
    super::util::cat(&[&[0, 0], h])
}

/// H(C(b(sourceHash32), b(txHash32))).
pub fn unlock_message(source_hash: &[u8], tx_hash: &[u8]) -> [u8; 32] {
    hu(&[&c_arr(&[&c_bytes(source_hash), &c_bytes(tx_hash)])])
}

/// The SDK token-unlock rule, unchanged from protocol 7: exactly 65 bytes r||s||id (`UnlockLength`), 1 <= r < n and
/// 1 <= s <= n/2 (`UnlockScalars`), id in 0..1 (`UnlockRecovery`; IDs 2 and 3 are refused for NB2), the key recovered with the
/// supplied id equal to the source key (`UnlockKey`), then the compact verification (defense in depth, reported as
/// `UnlockKey`). Nothing is normalised.
pub fn verify_unlock(
    key33: &[u8],
    source_hash: &[u8],
    tx_hash: &[u8],
    unlock: &[u8],
) -> Result<()> {
    verify_unlock_digest(key33, &unlock_message(source_hash, tx_hash), unlock)
}

/// The unlock rule over a given 32-byte message (the vectors' `primitives.unlockRecovery` form).
pub fn verify_unlock_digest(key33: &[u8], digest: &[u8; 32], unlock: &[u8]) -> Result<()> {
    if unlock.len() != 65 {
        return fail(Rule::UnlockLength);
    }
    // from_slice rejects r or s equal to zero or at least n; normalize_s is Some iff s is above n/2
    let sig = match Signature::from_slice(&unlock[..64]) {
        Ok(s) => s,
        Err(_) => return fail(Rule::UnlockScalars),
    };
    if sig.normalize_s().is_some() {
        return fail(Rule::UnlockScalars);
    }
    let id = unlock[64];
    // NB2-eligible unlocks use recovery ID 0 or 1 (astra delta review 2026-11-15): 2 and 3 are refused everywhere, so a lineage
    // holding one is not returnable even though it stays valid natively
    if id > 1 {
        return fail(Rule::UnlockRecovery);
    }
    let rid = RecoveryId::from_byte(id).expect("0 or 1");
    let recovered = VerifyingKey::recover_from_prehash(digest, &sig, rid).ok();
    let key = match recovered {
        Some(k) if k.to_encoded_point(true).as_bytes() == key33 => k,
        _ => return fail(Rule::UnlockKey),
    };
    if key.verify_prehash(digest, &sig).is_err() {
        return fail(Rule::UnlockKey);
    }
    Ok(())
}

/// A low-s recoverable signature r||s||id over a 32-byte prehash.
pub fn sign_recoverable(priv32: &[u8], digest: &[u8; 32]) -> [u8; 65] {
    let sk = SigningKey::from_slice(priv32).expect("nb2: a valid secp256k1 secret");
    let (sig, rid) = sk.sign_prehash_recoverable(digest).expect("nb2: signing");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = rid.to_byte();
    out
}

/// r||s||id over the unlock message, low-s, with the signer's recovery ID.
pub fn sign_unlock(priv32: &[u8], source_hash: &[u8], tx_hash: &[u8]) -> [u8; 65] {
    sign_recoverable(priv32, &unlock_message(source_hash, tx_hash))
}

/// The compressed public key of a secret.
pub fn public_key(priv32: &[u8]) -> [u8; 33] {
    let sk = SigningKey::from_slice(priv32).expect("nb2: a valid secp256k1 secret");
    arr(sk.verifying_key().to_encoded_point(true).as_bytes())
}

/// H(C(b("I_AM_UNIVERSAL_MINTER_FOR_"), b(id))).
pub fn minter_scalar(id: &[u8]) -> [u8; 32] {
    hu(&[&c_arr(&[
        &c_bytes(b"I_AM_UNIVERSAL_MINTER_FOR_"),
        &c_bytes(id),
    ])])
}

/// A minter scalar is admitted only as a valid secp256k1 secret, 1 <= k < n, never reduced modulo n.
pub fn minter_scalar_valid(k: &[u8]) -> bool {
    SigningKey::from_slice(k).is_ok()
}

/// The universal minter's compressed public key for a token ID (an invalid scalar: no such ID is known, about 2^-128 per ID).
pub fn minter_key(id: &[u8]) -> [u8; 33] {
    let k = minter_scalar(id);
    assert!(minter_scalar_valid(&k), "nb2: minter scalar outside [1, n)");
    public_key(&k)
}

/// A compressed secp256k1 key on the curve (`Predicate` otherwise).
pub fn parse_key(b: &[u8]) -> Result<()> {
    if b.len() != 33 || (b[0] != 2 && b[0] != 3) {
        return fail(Rule::Predicate);
    }
    if VerifyingKey::from_sec1_bytes(b).is_err() {
        return fail(Rule::Predicate);
    }
    Ok(())
}

/// The uncompressed 64-byte point of a compressed key (for EVM addresses).
pub fn uncompressed(pub33: &[u8]) -> Option<[u8; 64]> {
    let k = VerifyingKey::from_sec1_bytes(pub33).ok()?;
    let p = k.to_encoded_point(false);
    Some(arr(&p.as_bytes()[1..]))
}

/// Recover the compressed key of a recoverable signature r||s (64 bytes) with recovery `id` over `digest`.
pub fn recover(digest: &[u8; 32], rs: &[u8], id: u8) -> Option<[u8; 33]> {
    let sig = Signature::from_slice(rs).ok()?;
    let rid = RecoveryId::from_byte(id)?;
    let k = VerifyingKey::recover_from_prehash(digest, &sig, rid).ok()?;
    Some(arr(k.to_encoded_point(true).as_bytes()))
}
