//! Bounded canonical scan before SDK decoding, including CBOR hidden in payload byte strings.
//! Native UC sublimits: summary 256 bytes; shard 256 bits/33 bytes/256 siblings;
//! Unicity path 32 steps; seal 64 signatures; signer ID 128 UTF-8 bytes.
use crate::error::{NativeError as E, Result};
use crate::limits::*;
use alloc::vec::Vec;

struct Node<'a> {
    major: u8,
    arg: u64,
    start: usize,
    end: usize,
    depth: usize,
    data: &'a [u8],
    kids: Vec<Node<'a>>,
}
#[derive(Default)]
struct Budget {
    items: usize,
    paths: usize,
}
impl Budget {
    fn add_paths(&mut self, n: usize) -> Result<()> {
        if n > MAX_PATH_STEPS - self.paths {
            return Err(E::TooManyPaths);
        }
        self.paths += n;
        Ok(())
    }
}
fn scan<'a>(b: &'a [u8], budget: &mut Budget, depth: usize) -> Result<Node<'a>> {
    fn read<'a>(b: &'a [u8], pos: &mut usize, budget: &mut Budget, d: usize) -> Result<Node<'a>> {
        if d > MAX_CBOR_DEPTH {
            return Err(E::TooDeep);
        }
        budget.items += 1;
        if budget.items > MAX_CBOR_ITEMS {
            return Err(E::TooManyItems);
        }
        let start = *pos;
        let ib = *b.get(*pos).ok_or(E::Truncated)?;
        *pos += 1;
        let (major, ai) = (ib >> 5, ib & 31);
        if ai > 27 {
            return Err(E::ForbiddenCBOR);
        }
        let mut arg = ai as u64;
        if ai >= 24 {
            let n = 1usize << (ai - 24);
            if b.len() - *pos < n {
                return Err(E::Truncated);
            }
            arg = 0;
            for _ in 0..n {
                arg = arg << 8 | b[*pos] as u64;
                *pos += 1;
            }
            if arg < (if ai == 24 { 24 } else { 1u64 << (8 * (n / 2)) }) {
                return Err(E::NonCanonical);
            }
        }
        if matches!(major, 4..=6) && d + 1 > MAX_CBOR_DEPTH {
            return Err(E::TooDeep);
        }
        let mut data = &b[*pos..*pos];
        let mut kids = Vec::new();
        match major {
            2 | 3 => {
                if arg > (b.len() - *pos) as u64 {
                    return Err(E::Truncated);
                }
                data = &b[*pos..*pos + arg as usize];
                *pos += arg as usize;
                if major == 3 {
                    core::str::from_utf8(data).map_err(|_| E::NonCanonical)?;
                }
            }
            4 | 5 => {
                let count = arg
                    .checked_mul(if major == 5 { 2 } else { 1 })
                    .ok_or(E::TooManyItems)?;
                if count > (MAX_CBOR_ITEMS - budget.items) as u64 {
                    return Err(E::TooManyItems);
                }
                if count > (b.len() - *pos) as u64 {
                    return Err(E::Truncated);
                }
                for _ in 0..count {
                    kids.push(read(b, pos, budget, d + 1)?);
                }
                if major == 5 {
                    for i in (2..kids.len()).step_by(2) {
                        if b[kids[i - 2].start..kids[i - 2].end] >= b[kids[i].start..kids[i].end] {
                            return Err(E::NonCanonical);
                        }
                    }
                }
            }
            6 => kids.push(read(b, pos, budget, d + 1)?),
            7 if ib != 0xf6 && ib != 0xf4 && ib != 0xf5 => return Err(E::ForbiddenCBOR),
            _ => {}
        }
        Ok(Node {
            major,
            arg,
            start,
            end: *pos,
            depth: d,
            data,
            kids,
        })
    }
    let mut pos = 0;
    let root = read(b, &mut pos, budget, depth)?;
    if pos != b.len() {
        return Err(E::Trailing);
    }
    Ok(root)
}
fn array<'n, 'a>(n: &'n Node<'a>, count: Option<usize>) -> Result<&'n [Node<'a>]> {
    if n.major != 4 || count.is_some_and(|c| c != n.kids.len()) {
        return Err(E::UnsupportedCertificateEncoding);
    }
    Ok(&n.kids)
}
fn tagged<'n, 'a>(n: &'n Node<'a>, tag: u64, count: usize) -> Result<&'n [Node<'a>]> {
    if n.major != 6 || n.arg != tag {
        return Err(E::UnsupportedCertificateEncoding);
    }
    array(&n.kids[0], Some(count))
}
fn uint(n: &Node<'_>, max: u64) -> Result<()> {
    if n.major != 0 || n.arg > max {
        return Err(E::UnsupportedCertificateEncoding);
    }
    Ok(())
}
fn version(n: &Node<'_>) -> Result<()> {
    uint(n, u64::MAX)?;
    if n.arg != 1 {
        return Err(E::UnsupportedCertificateEncoding);
    }
    Ok(())
}
fn hash(n: &Node<'_>, nullable: bool) -> Result<()> {
    if !(nullable && n.major == 7 && n.arg == 22) && (n.major != 2 || n.data.len() != 32) {
        return Err(E::UnsupportedCertificateEncoding);
    }
    Ok(())
}
fn uc(n: &Node<'_>, budget: &mut Budget) -> Result<()> {
    if n.end - n.start > MAX_UC_BYTES {
        return Err(E::ProofTooLarge);
    }
    let k = tagged(n, 39001, 7)?;
    version(&k[0])?;
    let ir = tagged(&k[1], 39002, 10)?;
    version(&ir[0])?;
    for i in [1, 2, 6, 8] {
        uint(&ir[i], u64::MAX)?;
    }
    hash(&ir[3], true)?;
    hash(&ir[4], false)?;
    if ir[5].major != 2 {
        return Err(E::UnsupportedCertificateEncoding);
    }
    if ir[5].data.len() > 256 {
        return Err(E::ProofTooLarge);
    }
    hash(&ir[7], true)?;
    hash(&ir[9], true)?;
    hash(&k[2], true)?;
    hash(&k[3], false)?;
    let st = tagged(&k[4], 39003, 3)?;
    version(&st[0])?;
    if st[1].major != 2 || st[1].data.is_empty() {
        return Err(E::UnsupportedCertificateEncoding);
    }
    if st[1].data.len() > 33 {
        return Err(E::ProofTooLarge);
    }
    let last = *st[1].data.last().ok_or(E::UnsupportedCertificateEncoding)?;
    if last == 0 {
        return Err(E::UnsupportedCertificateEncoding);
    }
    if st[1].data.len() * 8 - last.trailing_zeros() as usize - 1 > 256 {
        return Err(E::ProofTooLarge);
    }
    let siblings = array(&st[2], None)?;
    if siblings.len() > 256 {
        return Err(E::ProofTooLarge);
    }
    for x in siblings {
        hash(x, false)?;
    }
    let ut = tagged(&k[5], 39004, 3)?;
    version(&ut[0])?;
    uint(&ut[1], u32::MAX as u64)?;
    let steps = array(&ut[2], None)?;
    if steps.len() > 32 {
        return Err(E::ProofTooLarge);
    }
    for step in steps {
        let x = array(step, Some(2))?;
        uint(&x[0], u32::MAX as u64)?;
        hash(&x[1], false)?;
    }
    budget.add_paths(siblings.len() + steps.len())?;
    let seal = tagged(&k[6], 39005, 8)?;
    version(&seal[0])?;
    for i in [2, 3, 4] {
        uint(&seal[i], u64::MAX)?;
    }
    uint(&seal[1], u16::MAX as u64)?;
    hash(&seal[5], true)?;
    hash(&seal[6], false)?;
    if seal[7].major != 5 {
        return Err(E::UnsupportedCertificateEncoding);
    }
    let sigs = &seal[7].kids;
    if sigs.len() > 128 {
        return Err(E::ProofTooLarge);
    }
    for pair in sigs.chunks_exact(2) {
        if pair[0].major != 3 {
            return Err(E::UnsupportedCertificateEncoding);
        }
        if pair[0].data.len() > 128 {
            return Err(E::ProofTooLarge);
        }
        if pair[1].major != 2 || pair[1].data.len() != 65 || pair[1].data[64] > 1 {
            return Err(E::UnsupportedCertificateEncoding);
        }
    }
    Ok(())
}
fn nested(n: Option<&Node<'_>>, max: usize, certificate: bool, budget: &mut Budget) -> Result<()> {
    if let Some(x) = n.filter(|x| x.major == 2) {
        if x.data.len() > max {
            return Err(E::ProofTooLarge);
        }
        match scan(x.data, budget, x.depth + 1) {
            Ok(root) => {
                if certificate {
                    uc(&root, budget)?;
                } else {
                    visit(&root, budget)?;
                }
            }
            Err(e) if e.family() != crate::error::Family::Budget => {
                if certificate {
                    return Err(E::UnsupportedCertificateEncoding);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn visit(n: &Node<'_>, budget: &mut Budget) -> Result<()> {
    if n.major == 6 {
        if n.arg == 39001 {
            return uc(n, budget);
        }
        let body = &n.kids[0];
        if body.major == 4 {
            let k = &body.kids;
            match n.arg {
                39040
                    if k.get(2)
                        .is_some_and(|x| x.major == 4 && x.kids.len() > MAX_TRANSFERS) =>
                {
                    return Err(E::TooManyTx)
                }
                39032 => nested(k.get(1), MAX_TOKEN_BYTES, false, budget)?, // CBOR predicate code.
                39041 => {
                    nested(k.get(5), MAX_JUSTIFICATION_BYTES, false, budget)?;
                    nested(k.get(6), MAX_TOKEN_BYTES, false, budget)?;
                }
                39045 => nested(k.get(3), MAX_TOKEN_BYTES, false, budget)?,
                39049 => {
                    if let Some(lp) = k.get(5).filter(|x| x.major == 4) {
                        if lp
                            .kids
                            .get(5)
                            .is_some_and(|x| x.major == 2 && x.data.len() > MAX_HEADER_BYTES)
                        {
                            return Err(E::ProofTooLarge);
                        }
                        let mut total = 0;
                        for list in [lp.kids.get(6), lp.kids.get(7)]
                            .into_iter()
                            .flatten()
                            .filter(|x| x.major == 4)
                        {
                            if list.kids.len() > MAX_MPT_NODES {
                                return Err(E::ProofTooLarge);
                            }
                            for node in list.kids.iter().filter(|x| x.major == 2) {
                                if node.data.len() > MAX_MPT_NODE_BYTES
                                    || node.data.len() > MAX_MPT_TOTAL_BYTES - total
                                {
                                    return Err(E::ProofTooLarge);
                                }
                                total += node.data.len();
                            }
                        }
                        nested(lp.kids.get(3), MAX_PDR_BYTES, false, budget)?;
                        nested(lp.kids.get(4), MAX_UC_BYTES, true, budget)?;
                    }
                }
                39033 => {
                    if let Some(x) = k.get(3).filter(|x| x.major == 2) {
                        let len = x.data.len();
                        if len < 32 || len % 32 != 0 {
                            return Err(E::UnsupportedCertificateEncoding);
                        }
                        let paths = (len - 32) / 32;
                        if paths > 256 {
                            return Err(E::ProofTooLarge);
                        }
                        budget.add_paths(paths)?;
                        uc(k.get(4).ok_or(E::UnsupportedCertificateEncoding)?, budget)?;
                        return Ok(()); // UC paths have already been counted.
                    }
                }
                _ => {}
            }
        }
    }
    for child in &n.kids {
        visit(child, budget)?;
    }
    Ok(())
}
/// Full token and nested payload budgets, before generic SDK allocation or cryptography.
pub fn preflight_token(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(E::InputTooLarge);
    }
    let mut budget = Budget::default();
    visit(&scan(bytes, &mut budget, 0)?, &mut budget)
}
/// The native/SDK certificate intersection and native sublimits, for standalone embedded checks.
pub fn preflight_uc(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_UC_BYTES {
        return Err(E::ProofTooLarge);
    }
    let mut budget = Budget::default();
    let checked = scan(bytes, &mut budget, 0).and_then(|n| uc(&n, &mut budget));
    checked.map_err(|e| {
        if e.family() == crate::error::Family::Budget {
            e
        } else {
            E::UnsupportedCertificateEncoding
        }
    })
}
