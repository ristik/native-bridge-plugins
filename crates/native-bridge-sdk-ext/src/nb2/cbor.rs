//! Canonical CBOR of the v2 profile (section 3), a port of `cbor.ts` (bft-core `nb2ref/cbor.go`). The encoder writes shortest
//! heads and definite lengths. The decoder is a strict scanner: shortest heads, definite lengths, complete consumption, and no
//! negative integers, floats, text strings, maps or simple values other than null in any v2 structure. A native certificate
//! (inline in an inclusion proof) is the one place text strings and maps are admitted (`scan_native`).

use alloc::vec::Vec;
use num_bigint::BigUint;

use super::errors::{fail, Result, Rule};
use super::util::{be_int, cat, min_bytes};

pub const MAX_CBOR_DEPTH: usize = 16;
const MAX_CBOR_ITEMS: usize = 1 << 20;

pub const MAJ_UINT: u8 = 0;
pub const MAJ_BYTES: u8 = 2;
pub const MAJ_TEXT: u8 = 3;
pub const MAJ_ARRAY: u8 = 4;
pub const MAJ_MAP: u8 = 5;
pub const MAJ_TAG: u8 = 6;
pub const MAJ_SIMPLE: u8 = 7;

pub const MAX_U64: u64 = u64::MAX;

// ---- encoder ----------------------------------------------------------------------------------

pub fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    if n < 24 {
        alloc::vec![m | n as u8]
    } else if n < 1 << 8 {
        alloc::vec![m | 24, n as u8]
    } else if n < 1 << 16 {
        cat(&[&[m | 25], &(n as u16).to_be_bytes()])
    } else if n < 1 << 32 {
        cat(&[&[m | 26], &(n as u32).to_be_bytes()])
    } else {
        cat(&[&[m | 27], &n.to_be_bytes()])
    }
}

pub fn u64be(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

pub fn u16be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

pub fn c_uint(n: u64) -> Vec<u8> {
    head(MAJ_UINT, n)
}

pub fn c_bytes(b: &[u8]) -> Vec<u8> {
    cat(&[&head(MAJ_BYTES, b.len() as u64), b])
}

pub fn c_tag(tag: u64, content: &[u8]) -> Vec<u8> {
    cat(&[&head(MAJ_TAG, tag), content])
}

pub fn c_arr(items: &[&[u8]]) -> Vec<u8> {
    let mut out = head(MAJ_ARRAY, items.len() as u64);
    for i in items {
        out.extend_from_slice(i);
    }
    out
}

/// `c_arr` over owned items.
pub fn c_arr_v(items: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = items.iter().map(|x| x.as_slice()).collect();
    c_arr(&refs)
}

pub const C_NULL: [u8; 1] = [0xf6];

pub fn c_null_or(b: Option<&[u8]>) -> Vec<u8> {
    match b {
        None => C_NULL.to_vec(),
        Some(b) => c_bytes(b),
    }
}

/// The minimal unsigned big-endian bytes of a positive amount.
pub fn amount_bytes(v: &BigUint) -> Vec<u8> {
    assert!(v.bits() > 0, "nb2: an amount is positive");
    min_bytes(v)
}

pub fn c_amount(v: &BigUint) -> Vec<u8> {
    c_bytes(&amount_bytes(v))
}

/// An SDK deadline: unset (None) or a u64 in [1, 2^64-1].
pub type Deadline = Option<u64>;

pub fn c_deadline(d: Deadline) -> Vec<u8> {
    match d {
        None => C_NULL.to_vec(),
        Some(v) => c_uint(v),
    }
}

// ---- strict scanner -------------------------------------------------------------------------------

/// One scanned item: its major type, argument, extent in the scanned buffer, its byte or text payload, and its children.
#[derive(Debug, Clone)]
pub struct Item<'a> {
    pub major: u8,
    pub arg: u64,
    pub start: usize,
    pub end: usize,
    pub data: &'a [u8],
    pub kids: Vec<Item<'a>>,
    pub is_null: bool,
}

struct Scanner<'a> {
    b: &'a [u8],
    pos: usize,
    tokens: usize,
    native: bool,
}

impl<'a> Scanner<'a> {
    fn head(&mut self) -> Result<(u8, u64)> {
        let b = self.b;
        if self.pos >= b.len() {
            return fail(Rule::Truncated);
        }
        let ib = b[self.pos];
        self.pos += 1;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if ai < 24 {
            return Ok((major, ai as u64));
        }
        if ai > 27 {
            return fail(Rule::NonCanonical);
        }
        let n = 1usize << (ai - 24);
        if b.len() - self.pos < n {
            return fail(Rule::Truncated);
        }
        let mut arg = 0u64;
        for i in 0..n {
            arg = arg << 8 | b[self.pos + i] as u64;
        }
        self.pos += n;
        if (ai == 24 && arg < 24)
            || (ai == 25 && arg <= 0xff)
            || (ai == 26 && arg <= 0xffff)
            || (ai == 27 && arg <= 0xffff_ffff)
        {
            return fail(Rule::NonCanonical);
        }
        Ok((major, arg))
    }

    fn item(&mut self, depth: usize, limit: Option<(&[usize], u64, Rule)>) -> Result<Item<'a>> {
        let b = self.b;
        let start = self.pos;
        self.tokens += 1;
        if self.tokens > MAX_CBOR_ITEMS {
            return fail(Rule::InputTooLarge);
        }
        if self.pos < b.len() {
            let mj = b[self.pos] >> 5;
            if mj == 1
                || (!self.native && (mj == MAJ_TEXT || mj == MAJ_MAP))
                || (mj == MAJ_SIMPLE && b[self.pos] != 0xf6)
            {
                return fail(Rule::NonCanonical);
            }
        }
        let (major, arg) = self.head()?;
        if let Some(([], max, rule)) = limit {
            if major == MAJ_ARRAY && arg > max {
                return fail(rule);
            }
        }
        let mut it = Item {
            major,
            arg,
            start,
            end: 0,
            data: &[],
            kids: Vec::new(),
            is_null: false,
        };
        let rest = (b.len() - self.pos) as u64;
        match major {
            MAJ_UINT => {}
            MAJ_BYTES | MAJ_TEXT => {
                if arg > rest {
                    return fail(Rule::Truncated);
                }
                it.data = &b[self.pos..self.pos + arg as usize];
                self.pos += arg as usize;
            }
            MAJ_ARRAY | MAJ_TAG | MAJ_MAP => {
                if depth + 1 > MAX_CBOR_DEPTH {
                    return fail(Rule::InputTooLarge);
                }
                let n = if major == MAJ_TAG {
                    1
                } else if arg > rest {
                    return fail(Rule::Truncated);
                } else if major == MAJ_MAP {
                    let n = 2 * arg;
                    if n > rest {
                        return fail(Rule::Truncated);
                    }
                    n
                } else {
                    arg
                };
                for index in 0..n {
                    let child_limit = limit.and_then(|(path, max, rule)| {
                        let (&first, rest) = path.split_first()?;
                        (first as u64 == index).then_some((rest, max, rule))
                    });
                    let k = self.item(depth + 1, child_limit)?;
                    it.kids.push(k);
                }
            }
            MAJ_SIMPLE => it.is_null = true,
            _ => return fail(Rule::NonCanonical),
        }
        it.end = self.pos;
        Ok(it)
    }
}

fn scan_with<'a>(
    b: &'a [u8],
    native: bool,
    limit: Option<(&[usize], u64, Rule)>,
) -> Result<Item<'a>> {
    let mut s = Scanner {
        b,
        pos: 0,
        tokens: 0,
        native,
    };
    let it = s.item(0, limit)?;
    if s.pos != b.len() {
        return fail(Rule::Trailing);
    }
    Ok(it)
}

/// Exactly one strict item spanning all of `b`.
/// Apply a count bound to one array by its child indices, counting a tag's child as index zero.
pub fn scan_bounded_array<'a>(
    b: &'a [u8],
    path: &[usize],
    max: usize,
    rule: Rule,
) -> Result<Item<'a>> {
    scan_with(b, false, Some((path, max as u64, rule)))
}

pub fn scan_one(b: &[u8]) -> Result<Item<'_>> {
    scan_with(b, false, None)
}

/// One item that may embed a native certificate (text strings and maps admitted).
pub fn scan_native(b: &[u8]) -> Result<Item<'_>> {
    scan_with(b, true, None)
}

/// The tag number at the head of `b`, without scanning further; None when it is not a well-formed tag head.
pub fn head_tag(b: &[u8]) -> Option<u64> {
    if b.is_empty() {
        return None;
    }
    let mut s = Scanner {
        b,
        pos: 0,
        tokens: 0,
        native: false,
    };
    match s.head() {
        Ok((MAJ_TAG, arg)) => Some(arg),
        _ => None,
    }
}

// ---- item accessors (the Go reference's methods) -----------------------------------------------------

pub fn raw<'a>(b: &'a [u8], it: &Item<'_>) -> &'a [u8] {
    &b[it.start..it.end]
}

pub fn is_uint(it: &Item<'_>) -> bool {
    it.major == MAJ_UINT
}

pub fn is_bytes(it: &Item<'_>) -> bool {
    it.major == MAJ_BYTES
}

pub fn is_tag(it: &Item<'_>) -> bool {
    it.major == MAJ_TAG
}

pub fn array<'i, 'a>(it: &'i Item<'a>, n: usize) -> Result<&'i [Item<'a>]> {
    if it.major != MAJ_ARRAY || it.kids.len() != n {
        return fail(Rule::Shape);
    }
    Ok(&it.kids)
}

pub fn bytes_n<'a>(it: &Item<'a>, n: usize) -> Result<&'a [u8]> {
    if it.major != MAJ_BYTES {
        return fail(Rule::Shape);
    }
    if it.data.len() != n {
        return fail(Rule::Length);
    }
    Ok(it.data)
}

pub fn bstr<'a>(it: &Item<'a>) -> Result<&'a [u8]> {
    if it.major != MAJ_BYTES {
        return fail(Rule::Shape);
    }
    Ok(it.data)
}

pub fn tag_content<'i, 'a>(it: &'i Item<'a>, tag: u64) -> Result<&'i Item<'a>> {
    if it.major != MAJ_TAG {
        return fail(Rule::Shape);
    }
    if it.arg != tag {
        return fail(Rule::Tag);
    }
    Ok(&it.kids[0])
}

pub fn uint_in(it: &Item<'_>, lo: u64, hi: u64) -> Result<u64> {
    if it.major != MAJ_UINT {
        return fail(Rule::Shape);
    }
    if it.arg < lo || it.arg > hi {
        return fail(Rule::IntRange);
    }
    Ok(it.arg)
}

pub fn version(it: &Item<'_>, want: u64) -> Result<()> {
    if it.major != MAJ_UINT {
        return fail(Rule::Shape);
    }
    if it.arg != want {
        return fail(Rule::Version);
    }
    Ok(())
}

pub fn literal(it: &Item<'_>, s: &str) -> Result<()> {
    if it.major != MAJ_BYTES || it.data != s.as_bytes() {
        return fail(Rule::Shape);
    }
    Ok(())
}

/// An Amount: a minimal positive big-endian byte string of 1 to 32 bytes.
pub fn amount(it: &Item<'_>) -> Result<BigUint> {
    if it.major != MAJ_BYTES {
        return fail(Rule::Shape);
    }
    let d = it.data;
    if d.is_empty() {
        return fail(Rule::IntRange);
    }
    if d.len() > 32 {
        return fail(Rule::Length);
    }
    if d[0] == 0 {
        return fail(Rule::NonCanonical);
    }
    Ok(be_int(d))
}

pub fn deadline(it: &Item<'_>) -> Result<Deadline> {
    if it.is_null {
        return Ok(None);
    }
    Ok(Some(uint_in(it, 1, MAX_U64)?))
}

pub fn nullable_bytes<'a>(it: &Item<'a>) -> Result<Option<&'a [u8]>> {
    if it.is_null {
        return Ok(None);
    }
    Ok(Some(bstr(it)?))
}
