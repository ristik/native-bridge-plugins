//! A strict, minimal RLP reader and the encoder (`rlp.ts`; bft-core `nb2ref/rlp.go`): every non-minimal length, a single byte
//! below 0x80 wrapped as a string, trailing bytes and nesting over 16 reject. Callers report failures under their own rule.

use alloc::vec::Vec;
use num_bigint::BigUint;

use super::util::{be_int, cat, min_bytes};

pub const MAX_RLP_DEPTH: usize = 16;

/// One RLP item: a list (its kids) or a string, with its raw encoding.
#[derive(Debug, Clone)]
pub struct RlpItem<'a> {
    pub list: bool,
    pub str: &'a [u8],
    pub kids: Vec<RlpItem<'a>>,
    pub raw: &'a [u8],
}

/// A malformed RLP item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RlpError;

type R<T> = core::result::Result<T, RlpError>;

fn read_len(b: &[u8], ll: usize) -> R<usize> {
    if ll > 4 || b.len() < ll || b[0] == 0 {
        return Err(RlpError);
    }
    Ok(b[..ll].iter().fold(0usize, |n, &x| n * 256 + x as usize))
}

fn read(b: &[u8], depth: usize) -> R<(RlpItem<'_>, usize)> {
    if b.is_empty() || depth > MAX_RLP_DEPTH {
        return Err(RlpError);
    }
    let p = b[0] as usize;
    if p < 0x80 {
        return Ok((
            RlpItem {
                list: false,
                str: &b[..1],
                kids: Vec::new(),
                raw: &b[..1],
            },
            1,
        ));
    }
    if p <= 0xb7 {
        let n = p - 0x80;
        if b.len() < 1 + n {
            return Err(RlpError);
        }
        if n == 1 && b[1] < 0x80 {
            return Err(RlpError);
        }
        return Ok((
            RlpItem {
                list: false,
                str: &b[1..1 + n],
                kids: Vec::new(),
                raw: &b[..1 + n],
            },
            1 + n,
        ));
    }
    if p <= 0xbf {
        let ll = p - 0xb7;
        let n = read_len(&b[1..], ll)?;
        if n < 56 || n > b.len() - 1 - ll {
            return Err(RlpError);
        }
        return Ok((
            RlpItem {
                list: false,
                str: &b[1 + ll..1 + ll + n],
                kids: Vec::new(),
                raw: &b[..1 + ll + n],
            },
            1 + ll + n,
        ));
    }
    let (hdr, n) = if p <= 0xf7 {
        (1, p - 0xc0)
    } else {
        let ll = p - 0xf7;
        let n = read_len(&b[1..], ll)?;
        if n < 56 {
            return Err(RlpError);
        }
        (1 + ll, n)
    };
    if n > b.len() - hdr {
        return Err(RlpError);
    }
    let mut it = RlpItem {
        list: true,
        str: &[],
        kids: Vec::new(),
        raw: &b[..hdr + n],
    };
    let mut off = hdr;
    while off < hdr + n {
        let (kid, used) = read(&b[off..hdr + n], depth + 1)?;
        it.kids.push(kid);
        off += used;
    }
    Ok((it, hdr + n))
}

/// Exactly one item spanning all of `b`.
pub fn rlp_decode(b: &[u8]) -> R<RlpItem<'_>> {
    let (it, n) = read(b, 0)?;
    if n != b.len() {
        return Err(RlpError);
    }
    Ok(it)
}

/// A canonical RLP integer string: no leading zero byte, at most `max` bytes (the empty string is zero).
pub fn rlp_uint(it: &RlpItem<'_>, max: usize) -> Option<BigUint> {
    if it.list || it.str.len() > max || (!it.str.is_empty() && it.str[0] == 0) {
        return None;
    }
    Some(be_int(it.str))
}

/// `rlp_uint` of at most 8 bytes, as u64.
pub fn rlp_u64(it: &RlpItem<'_>) -> Option<u64> {
    rlp_uint(it, 8).map(|v| super::util::to_u64(&v).expect("8 bytes"))
}

// ---- encoder ----

fn len_bytes(n: usize) -> Vec<u8> {
    let b = (n as u64).to_be_bytes();
    let i = b.iter().position(|&x| x != 0).unwrap_or(8);
    b[i..].to_vec()
}

pub fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    if b.len() < 56 {
        return cat(&[&[0x80 + b.len() as u8], b]);
    }
    let l = len_bytes(b.len());
    cat(&[&[0xb7 + l.len() as u8], &l, b])
}

pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = items.concat();
    if body.len() < 56 {
        return cat(&[&[0xc0 + body.len() as u8], &body]);
    }
    let l = len_bytes(body.len());
    cat(&[&[0xf7 + l.len() as u8], &l, &body])
}

/// RLP of an unsigned integer.
pub fn rlp_uint_enc(v: &BigUint) -> Vec<u8> {
    rlp_bytes(&min_bytes(v))
}

pub fn rlp_u64_enc(v: u64) -> Vec<u8> {
    rlp_uint_enc(&BigUint::from(v))
}

/// RLP(i) for an unsigned index: the receipt-trie key.
pub fn rlp_index_key(i: u64) -> Vec<u8> {
    rlp_u64_enc(i)
}
