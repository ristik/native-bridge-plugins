//! Strict scanners.
//!
//! [`scan_one`] reads the profile's CBOR subset: unsigned integers, byte strings, arrays, tags and
//! null, with shortest-form heads and definite lengths. Text strings, maps, floats and every other
//! simple value are forbidden. [`pdr_elements`] splits a native partition-description record, the one
//! structure that legitimately carries text and a map, while still demanding canonical encoding.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::{NativeError as E, Result};
use crate::limits::{MAX_AMOUNT_BYTES, MAX_CBOR_DEPTH, MAX_CBOR_ITEMS};

/// One scanned item with its byte span in the scanned buffer.
#[derive(Debug)]
pub struct Item<'a> {
    pub start: usize,
    pub end: usize,
    pub kind: Kind<'a>,
}

#[derive(Debug)]
pub enum Kind<'a> {
    Uint(u64),
    Bytes(&'a [u8]),
    Array(Vec<Item<'a>>),
    Tag(u64, Box<Item<'a>>),
    Null,
}

/// Scan exactly one item spanning all of `b`.
pub fn scan_one(b: &[u8]) -> Result<Item<'_>> {
    let mut s = Scanner {
        b,
        pos: 0,
        tokens: 0,
    };
    let it = s.item(0)?;
    if s.pos != b.len() {
        return Err(E::Trailing);
    }
    Ok(it)
}

struct Scanner<'a> {
    b: &'a [u8],
    pos: usize,
    tokens: usize,
}

/// Read one head; returns `(major, argument)` and rejects non-shortest forms.
fn read_head(b: &[u8], pos: &mut usize) -> Result<(u8, u64)> {
    let ib = *b.get(*pos).ok_or(E::Truncated)?;
    *pos += 1;
    let (major, ai) = (ib >> 5, ib & 0x1f);
    if ai < 24 {
        return Ok((major, ai as u64));
    }
    if ai > 27 {
        return Err(if ai == 31 {
            E::ForbiddenCBOR
        } else {
            E::NonCanonical
        });
    }
    let n = 1usize << (ai - 24);
    if b.len() - *pos < n {
        return Err(E::Truncated);
    }
    let mut arg = 0u64;
    for i in 0..n {
        arg = arg << 8 | b[*pos + i] as u64;
    }
    *pos += n;
    let short = match ai {
        24 => arg < 24,
        25 => arg <= 0xff,
        26 => arg <= 0xffff,
        _ => arg <= 0xffff_ffff,
    };
    if short {
        return Err(E::NonCanonical);
    }
    Ok((major, arg))
}

impl<'a> Scanner<'a> {
    fn item(&mut self, depth: usize) -> Result<Item<'a>> {
        let start = self.pos;
        self.tokens += 1;
        if self.tokens > MAX_CBOR_ITEMS {
            return Err(E::TooManyItems);
        }
        if let Some(&ib) = self.b.get(self.pos) {
            let mj = ib >> 5;
            if mj == 3 || mj == 5 || (mj == 7 && ib != 0xf6) {
                return Err(E::ForbiddenCBOR);
            }
        }
        let (major, arg) = read_head(self.b, &mut self.pos)?;
        let rest = (self.b.len() - self.pos) as u64;
        let kind = match major {
            0 => Kind::Uint(arg),
            2 => {
                if arg > rest {
                    return Err(E::Truncated);
                }
                let d = &self.b[self.pos..self.pos + arg as usize];
                self.pos += arg as usize;
                Kind::Bytes(d)
            }
            4 => {
                if depth + 1 > MAX_CBOR_DEPTH {
                    return Err(E::TooDeep);
                }
                if arg > rest {
                    return Err(E::Truncated);
                }
                let mut kids = Vec::new();
                for _ in 0..arg {
                    kids.push(self.item(depth + 1)?);
                }
                Kind::Array(kids)
            }
            6 => {
                if depth + 1 > MAX_CBOR_DEPTH {
                    return Err(E::TooDeep);
                }
                Kind::Tag(arg, Box::new(self.item(depth + 1)?))
            }
            7 => Kind::Null,
            _ => return Err(E::ForbiddenCBOR),
        };
        Ok(Item {
            start,
            end: self.pos,
            kind,
        })
    }
}

impl<'a> Item<'a> {
    pub fn raw<'b>(&self, b: &'b [u8]) -> &'b [u8] {
        &b[self.start..self.end]
    }
    pub fn array(&self, n: usize) -> Option<&[Item<'a>]> {
        match &self.kind {
            Kind::Array(k) if k.len() == n => Some(k),
            _ => None,
        }
    }
    pub fn any_array(&self) -> Option<&[Item<'a>]> {
        match &self.kind {
            Kind::Array(k) => Some(k),
            _ => None,
        }
    }
    /// Bytes of exactly `n` bytes.
    pub fn bytes_n(&self, n: usize) -> Result<&'a [u8]> {
        match &self.kind {
            Kind::Bytes(d) if d.len() == n => Ok(d),
            Kind::Bytes(_) => Err(E::Length),
            _ => Err(E::Shape),
        }
    }
    pub fn bytes(&self) -> Result<&'a [u8]> {
        match &self.kind {
            Kind::Bytes(d) => Ok(d),
            _ => Err(E::Shape),
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self.kind, Kind::Null)
    }
    pub fn tag_content(&self, tag: u64) -> Result<&Item<'a>> {
        match &self.kind {
            Kind::Tag(t, c) if *t == tag => Ok(c),
            Kind::Tag(_, _) => Err(E::Tag),
            _ => Err(E::Shape),
        }
    }
    pub fn uint(&self) -> Result<u64> {
        match self.kind {
            Kind::Uint(v) => Ok(v),
            _ => Err(E::Shape),
        }
    }
    pub fn uint_max(&self, max: u64) -> Result<u64> {
        match self.kind {
            Kind::Uint(v) if v <= max => Ok(v),
            Kind::Uint(_) => Err(E::IntRange),
            _ => Err(E::Shape),
        }
    }
    /// A wire version field that must equal `want`.
    pub fn version(&self, want: u64) -> Result<()> {
        match self.kind {
            Kind::Uint(v) if v == want => Ok(()),
            Kind::Uint(_) => Err(E::Version),
            _ => Err(E::Shape),
        }
    }
    /// A positive minimal big-endian amount of at most 32 bytes.
    pub fn amount(&self) -> Result<&'a [u8]> {
        let d = self.bytes()?;
        if d.is_empty() || d.len() > MAX_AMOUNT_BYTES || d[0] == 0 {
            return Err(E::IntRange);
        }
        Ok(d)
    }
    /// `null` or a byte string.
    pub fn nullable_bytes(&self) -> Result<Option<&'a [u8]>> {
        match &self.kind {
            Kind::Null => Ok(None),
            Kind::Bytes(d) => Ok(Some(d)),
            _ => Err(E::Shape),
        }
    }
    /// `null` or an unsigned integer (a request deadline).
    pub fn nullable_uint(&self) -> Result<Option<u64>> {
        match &self.kind {
            Kind::Null => Ok(None),
            Kind::Uint(v) => Ok(Some(*v)),
            _ => Err(E::Shape),
        }
    }
}

/// Copy a fixed-width byte string out of an item.
pub fn fixed<const N: usize>(it: &Item<'_>) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    out.copy_from_slice(it.bytes_n(N)?);
    Ok(out)
}

// ---- partition description records -------------------------------------------------------------

/// Split a canonical native tag(39008, PDR array) into the raw bytes of its elements.
///
/// The PDR carries text (partition parameters) and a map, so it cannot use [`scan_one`]. Canonical
/// form is still enforced: shortest heads, definite lengths, strictly bytewise-increasing map keys,
/// valid UTF-8, no floats, no nested tags and no simple value other than null and booleans.
pub fn pdr_elements(b: &[u8]) -> Result<Vec<&[u8]>> {
    let mut pos = 0usize;
    let mut tokens = 2usize;
    let (major, tag) = read_head(b, &mut pos)?;
    if major != 6 {
        return Err(E::Shape);
    }
    if tag != 39008 {
        return Err(E::Tag);
    }
    let (major, n) = read_head(b, &mut pos)?;
    if major != 4 || n != 15 {
        return Err(E::Shape);
    }
    if n > b.len() as u64 {
        return Err(E::Truncated);
    }
    let mut out = Vec::new();
    for _ in 0..n {
        let start = pos;
        skip_canonical(b, &mut pos, 2, &mut tokens)?;
        out.push(&b[start..pos]);
    }
    if pos != b.len() {
        return Err(E::Trailing);
    }
    Ok(out)
}

fn skip_canonical(b: &[u8], pos: &mut usize, depth: usize, tokens: &mut usize) -> Result<()> {
    *tokens += 1;
    if *tokens > MAX_CBOR_ITEMS {
        return Err(E::TooManyItems);
    }
    if depth > MAX_CBOR_DEPTH {
        return Err(E::TooDeep);
    }
    let first = *b.get(*pos).ok_or(E::Truncated)?;
    let (major, arg) = read_head(b, pos)?;
    let rest = (b.len() - *pos) as u64;
    match major {
        0 | 1 => Ok(()),
        2 | 3 => {
            if arg > rest {
                return Err(E::Truncated);
            }
            let data = &b[*pos..*pos + arg as usize];
            *pos += arg as usize;
            if major == 3 && core::str::from_utf8(data).is_err() {
                return Err(E::NonCanonical);
            }
            Ok(())
        }
        4 => {
            if arg > rest {
                return Err(E::Truncated);
            }
            for _ in 0..arg {
                skip_canonical(b, pos, depth + 1, tokens)?;
            }
            Ok(())
        }
        5 => {
            if arg > rest {
                return Err(E::Truncated);
            }
            let mut prev: Option<&[u8]> = None;
            for _ in 0..arg {
                let ks = *pos;
                skip_canonical(b, pos, depth + 1, tokens)?;
                let key = &b[ks..*pos];
                if let Some(p) = prev {
                    if p >= key {
                        return Err(E::NonCanonical);
                    }
                }
                prev = Some(key);
                skip_canonical(b, pos, depth + 1, tokens)?;
            }
            Ok(())
        }
        7 if first == 0xf6 || first == 0xf4 || first == 0xf5 => Ok(()),
        _ => Err(E::ForbiddenCBOR),
    }
}
