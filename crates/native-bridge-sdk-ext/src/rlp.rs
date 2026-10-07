//! Strict RLP: canonical heads only, bounded depth, exact consumption.

use alloc::vec::Vec;

use crate::error::{NativeError as E, Result};
use crate::limits::MAX_RLP_DEPTH;

/// A decoded RLP item: a byte string or a list, with its raw encoding.
#[derive(Debug, Clone)]
pub enum Rlp<'a> {
    Bytes(&'a [u8], &'a [u8]),
    List(Vec<Rlp<'a>>, &'a [u8]),
}

impl<'a> Rlp<'a> {
    /// The complete raw encoding of this item.
    pub fn raw(&self) -> &'a [u8] {
        match self {
            Rlp::Bytes(_, r) | Rlp::List(_, r) => r,
        }
    }
    pub fn bytes(&self) -> Result<&'a [u8]> {
        match self {
            Rlp::Bytes(b, _) => Ok(b),
            Rlp::List(..) => Err(E::RlpMalformed),
        }
    }
    pub fn list(&self) -> Result<&[Rlp<'a>]> {
        match self {
            Rlp::List(l, _) => Ok(l),
            Rlp::Bytes(..) => Err(E::RlpMalformed),
        }
    }
    /// A canonical unsigned integer: minimal big-endian, no leading zero byte, at most 8 bytes.
    pub fn u64(&self) -> Result<u64> {
        let b = self.bytes()?;
        if b.len() > 8 || (!b.is_empty() && b[0] == 0) {
            return Err(E::RlpMalformed);
        }
        Ok(b.iter().fold(0u64, |a, &x| a << 8 | x as u64))
    }
}

/// Decode exactly one item spanning all of `b`.
pub fn decode(b: &[u8]) -> Result<Rlp<'_>> {
    let (item, used) = item(b, 0)?;
    if used != b.len() {
        return Err(E::RlpMalformed);
    }
    Ok(item)
}

fn be_len(b: &[u8]) -> Result<usize> {
    if b.is_empty() || b[0] == 0 || b.len() > 4 {
        return Err(E::RlpMalformed);
    }
    Ok(b.iter().fold(0usize, |a, &x| a << 8 | x as usize))
}

fn item(b: &[u8], depth: usize) -> Result<(Rlp<'_>, usize)> {
    if depth > MAX_RLP_DEPTH {
        return Err(E::RlpMalformed);
    }
    let p = *b.first().ok_or(E::RlpMalformed)?;
    let (is_list, head, len) = match p {
        0x00..=0x7f => return Ok((Rlp::Bytes(&b[..1], &b[..1]), 1)),
        0x80..=0xb7 => (false, 1, (p - 0x80) as usize),
        0xb8..=0xbf | 0xf8..=0xff => {
            let n = if p >= 0xf8 {
                (p - 0xf7) as usize
            } else {
                (p - 0xb7) as usize
            };
            let lb = b.get(1..1 + n).ok_or(E::RlpMalformed)?;
            let len = be_len(lb)?;
            if len < 56 {
                return Err(E::RlpMalformed);
            }
            (p >= 0xf8, 1 + n, len)
        }
        0xc0..=0xf7 => (true, 1, (p - 0xc0) as usize),
    };
    let end = head.checked_add(len).ok_or(E::RlpMalformed)?;
    let body = b.get(head..end).ok_or(E::RlpMalformed)?;
    if !is_list {
        // A single byte below 0x80 must be its own encoding.
        if len == 1 && body[0] < 0x80 {
            return Err(E::RlpMalformed);
        }
        return Ok((Rlp::Bytes(body, &b[..end]), end));
    }
    let mut kids = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let (k, used) = item(&body[pos..], depth + 1)?;
        kids.push(k);
        pos += used;
    }
    Ok((Rlp::List(kids, &b[..end]), end))
}

/// Encode a byte string.
pub fn encode_bytes(s: &[u8]) -> Vec<u8> {
    if s.len() == 1 && s[0] < 0x80 {
        return s.to_vec();
    }
    let mut out = head(0x80, s.len());
    out.extend_from_slice(s);
    out
}

/// Encode a list of already-encoded items.
pub fn encode_list(items: &[&[u8]]) -> Vec<u8> {
    let n: usize = items.iter().map(|i| i.len()).sum();
    let mut out = head(0xc0, n);
    for i in items {
        out.extend_from_slice(i);
    }
    out
}

/// Encode an unsigned integer canonically.
pub fn encode_u64(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let skip = b.iter().take_while(|&&x| x == 0).count();
    encode_bytes(&b[skip..])
}

fn head(base: u8, len: usize) -> Vec<u8> {
    if len < 56 {
        return alloc::vec![base + len as u8];
    }
    let lb = (len as u64).to_be_bytes();
    let skip = lb.iter().take_while(|&&x| x == 0).count();
    let mut out = alloc::vec![base + 55 + (8 - skip) as u8];
    out.extend_from_slice(&lb[skip..]);
    out
}
