//! Byte helpers (`bytes.ts`).

use alloc::string::String;
use alloc::vec::Vec;
use num_bigint::BigUint;

/// The concatenation of `parts`.
pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// Lowercase hex without `0x`.
pub fn to_hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 * b.len());
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// `0x` + lowercase hex.
pub fn hex0x(b: &[u8]) -> String {
    let mut s = String::from("0x");
    s.push_str(&to_hex(b));
    s
}

/// Strict lowercase/uppercase hex of even length, without prefix.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(nib(p[0])? << 4 | nib(p[1])?))
        .collect()
}

/// A fixed-size copy of a slice of exactly `N` bytes.
pub fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(b);
    out
}

/// The unsigned big-endian value of `b`.
pub fn be_int(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(b)
}

/// The minimal big-endian bytes of `v` (empty for zero).
pub fn min_bytes(v: &BigUint) -> Vec<u8> {
    if v.bits() == 0 {
        Vec::new()
    } else {
        v.to_bytes_be()
    }
}

/// Fixed-width big-endian, or None when `v` does not fit.
pub fn be_fixed(v: &BigUint, width: usize) -> Option<Vec<u8>> {
    let b = min_bytes(v);
    if b.len() > width {
        return None;
    }
    let mut out = alloc::vec![0u8; width - b.len()];
    out.extend_from_slice(&b);
    Some(out)
}

/// u256 of a value known to fit (panics otherwise: a caller bug).
pub fn u256(v: &BigUint) -> [u8; 32] {
    arr(&be_fixed(v, 32).expect("nb2: value does not fit 32 bytes"))
}

/// u256 of a u64.
pub fn u256_64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// The u64 of a big integer that fits, else None.
pub fn to_u64(v: &BigUint) -> Option<u64> {
    let d = v.to_u64_digits();
    match d.len() {
        0 => Some(0),
        1 => Some(d[0]),
        _ => None,
    }
}

/// The value of a 32-byte word as u64 when its high 24 bytes are zero.
pub fn word_u64(w: &[u8]) -> Option<u64> {
    if w.len() != 32 || w[..24].iter().any(|&x| x != 0) {
        return None;
    }
    Some(u64::from_be_bytes(arr(&w[24..])))
}

/// `2^n - 1`.
pub fn max_bits(n: u64) -> BigUint {
    (BigUint::from(1u8) << n) - 1u8
}
