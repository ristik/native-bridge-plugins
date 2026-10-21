//! The bridge's side of `CERT_BATCH_V2` (`protocol/interop.md`, "Direct-call gas gate"): the structural scan of every claim's
//! UnicityCertificate and the canonical first-occurrence grouping the batch price is computed from. It mirrors the contract's
//! `CertGroups.sol`, the oracle's `b1ref.Group` and the TypeScript `certgroups.ts`; it does no cryptography.
//!
//! `K` claim occurrences, `C` request bytes, `E` distinct declared epochs, `S` distinct complete seals (the whole tagged CBOR
//! slice, signature map included), `Q` the sum of their signature counts, `A` distinct claims (the whole packed claim: expected
//! tuple and full UC bytes), `P` the shard siblings plus Unicity-tree steps of the distinct claims.
//!
//! Identity is exact bytes. A claim's shard-tree depth comes from its own native shard ID, never from a policy. `items` counts the
//! CBOR items of every UC occurrence before deduplication; there is no shared item budget (owner section 36): each UC is bounded
//! by its own native scan (`MAX_CBOR_ITEMS`) and every item is charged. The anchor table is grouped under the composition's limits
//! (`b1ref.Composed`): up to the u16 wire count of claims, with no request-byte, raw-step or signature aggregate (bft-core
//! briefs/dev4-b7-native-compose-spec.md section 7); each UC keeps its own bounds.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::envelope::Anchor;
use crate::error::{NativeError as E, Result};
use crate::limits::*;
use crate::profile::shard_depth;

/// The most claims one composed batch carries (`K`): the u16 wire count.
pub const MAX_CLAIMS: usize = MAX_ANCHORS;
const CLAIM_FIXED: usize = 106; // partition 4 + shardLen 2 + three hashes 96 + ucLen 4

// ---- the frozen price schedule ----
const SCAN_BASE: u64 = 60_000;
const SCAN_PER_BYTE: u64 = 16;
const SCAN_PER_PAIR: u64 = 500;
const COMMON_READS: u64 = 1_100;
const PER_EPOCH: u64 = 29_900;
const PER_SIGNATURE: u64 = 6_000;
const PER_CLAIM: u64 = 2_000;
const PER_STEP: u64 = 250;

const TAG_UC: u64 = 39001;
const TAG_SHARD_TREE: u64 = 39003;
const TAG_UNICITY_TREE: u64 = 39004;
const TAG_SEAL: u64 = 39005;

/// `K`, `C`, `E`, `S`, `Q`, `A`, `P` and the item count of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub k: u64,
    pub c: u64,
    pub e: u64,
    pub s: u64,
    pub q: u64,
    pub a: u64,
    pub p: u64,
    /// CBOR items over all UC occurrences, before deduplication.
    pub items: u64,
}

/// `G_scan(C, K) = 60000 + 16*C + 500*K*(K-1)`.
pub const fn scan_gas(c: u64, k: u64) -> u64 {
    SCAN_BASE + SCAN_PER_BYTE * c + SCAN_PER_PAIR * k * (k.saturating_sub(1))
}

/// `G_batch`: what the native call is forwarded and charges.
pub const fn batch_gas(n: &Counts) -> u64 {
    scan_gas(n.c, n.k)
        + COMMON_READS
        + PER_EPOCH * n.e
        + PER_SIGNATURE * n.q
        + PER_CLAIM * n.a
        + PER_STEP * n.p
}

struct Budget {
    limit: usize,
    items: usize,
    steps: usize,
}

/// One strict head: shortest form, definite length only. Returns `(major, argument, next position)`.
fn head(b: &[u8], pos: usize) -> Result<(u8, u64, usize)> {
    let ib = *b.get(pos).ok_or(E::Truncated)?;
    let (major, ai) = (ib >> 5, ib & 0x1f);
    if ai < 24 {
        return Ok((major, u64::from(ai), pos + 1));
    }
    if ai > 27 {
        return Err(if ai == 31 {
            E::ForbiddenCBOR
        } else {
            E::NonCanonical
        });
    }
    let n = 1usize << (ai - 24);
    let raw = b.get(pos + 1..pos + 1 + n).ok_or(E::Truncated)?;
    let arg = raw.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    if (ai == 24 && arg < 24)
        || (ai == 25 && arg <= 0xff)
        || (ai == 26 && arg <= 0xffff)
        || (ai == 27 && arg <= 0xffff_ffff)
    {
        return Err(E::NonCanonical);
    }
    Ok((major, arg, pos + 1 + n))
}

fn item(bud: &mut Budget) -> Result<()> {
    bud.items += 1;
    if bud.items > bud.limit {
        return Err(E::TooManyItems);
    }
    Ok(())
}

/// A declared container whose immediate children alone exceed what is left is refused before any of them is walked.
fn fits(bud: &Budget, children: u64) -> Result<()> {
    if children > (bud.limit - bud.items) as u64 {
        return Err(E::TooManyItems);
    }
    Ok(())
}

/// Skip one complete item; `base` containers already enclose it (the nesting bound counts from the UC root).
fn skip(b: &[u8], start: usize, bud: &mut Budget, base: usize) -> Result<usize> {
    let mut pos = start;
    let mut left: Vec<u64> = Vec::new();
    let mut depth = base;
    loop {
        let (major, arg, next) = head(b, pos)?;
        item(bud)?;
        pos = next;
        let mut kids = 0u64;
        match major {
            2 | 3 => {
                if arg > (b.len() - pos) as u64 {
                    return Err(E::Truncated);
                }
                pos += arg as usize;
            }
            4 | 5 => {
                if arg > b.len() as u64 {
                    return Err(E::Truncated);
                }
                kids = if major == 5 { 2 * arg } else { arg };
                fits(bud, kids)?;
            }
            6 => kids = 1,
            _ => {}
        }
        if kids != 0 {
            depth += 1;
            if depth > MAX_CBOR_DEPTH {
                return Err(E::TooManyItems);
            }
            if left.len() <= depth {
                left.resize(depth + 1, 0);
            }
            left[depth] = kids;
            continue;
        }
        while depth != base {
            left[depth] -= 1;
            if left[depth] != 0 {
                break;
            }
            depth -= 1;
        }
        if depth == base {
            return Ok(pos);
        }
    }
}

fn skip_n(b: &[u8], mut pos: usize, n: usize, bud: &mut Budget, base: usize) -> Result<usize> {
    for _ in 0..n {
        pos = skip(b, pos, bud, base)?;
    }
    Ok(pos)
}

/// `tag(t, array(n))`; returns the position of the first element. Counts the two heads as items.
fn tagged(b: &[u8], pos: usize, tag: u64, n: u64, bud: &mut Budget) -> Result<usize> {
    let (major, arg, p) = head(b, pos)?;
    if major != 6 || arg != tag {
        return Err(E::Tag);
    }
    let (major, arg, p) = head(b, p)?;
    if major != 4 || arg != n {
        return Err(E::Shape);
    }
    item(bud)?;
    item(bud)?;
    Ok(p)
}

/// Element count of an array (major 4) or map (major 5) at `pos`; null is empty.
fn count(b: &[u8], pos: usize, want: u8, bud: &mut Budget) -> Result<(usize, usize)> {
    item(bud)?;
    if b.get(pos) == Some(&0xf6) {
        return Ok((0, pos + 1));
    }
    let (major, arg, next) = head(b, pos)?;
    if major != want || arg > b.len() as u64 {
        return Err(E::Shape);
    }
    fits(bud, if want == 5 { 2 * arg } else { arg })?;
    Ok((arg as usize, next))
}

struct Occurrence {
    epoch: u64,
    seal_start: usize,
    seal_len: usize,
    sigs: usize,
    steps: usize,
}

/// `tag(39001,[1, IR, h, h, tag(39003,[1, shard, [sib*]]), tag(39004,[1, partition, [step*]]), tag(39005,[1, ..., sigs])])`,
/// no trailing byte.
fn scan(a: &Anchor, bud: &mut Budget) -> Result<Occurrence> {
    let uc = a.uc.as_slice();
    let d = shard_depth(&a.shard)?;
    let mut pos = tagged(uc, 0, TAG_UC, 7, bud)?;
    for _ in 0..4 {
        pos = skip(uc, pos, bud, 2)?; // version, input record, technical hash, shard configuration hash
    }
    pos = tagged(uc, pos, TAG_SHARD_TREE, 3, bud)?;
    pos = skip(uc, pos, bud, 4)?; // version
    let (major, len, next) = head(uc, pos)?;
    let end = usize::try_from(len)
        .ok()
        .and_then(|l| next.checked_add(l))
        .filter(|&e| e <= uc.len())
        .ok_or(E::Truncated)?;
    if major != 2 || uc[next..end] != a.shard[..] {
        return Err(E::ShardMismatch);
    }
    item(bud)?;
    let (siblings, next) = count(uc, end, 4, bud)?;
    if siblings != d {
        return Err(E::ShardMismatch);
    }
    pos = skip_n(uc, next, siblings, bud, 5)?;
    pos = tagged(uc, pos, TAG_UNICITY_TREE, 3, bud)?;
    pos = skip(uc, pos, bud, 4)?; // version
    pos = skip(uc, pos, bud, 4)?; // partition
    let (steps, next) = count(uc, pos, 4, bud)?;
    if steps > MAX_UNICITY_STEPS {
        return Err(E::TooManyItems);
    }
    pos = skip_n(uc, next, steps, bud, 5)?;
    let seal_start = pos;
    let total = siblings + steps;
    bud.steps += total;
    pos = tagged(uc, pos, TAG_SEAL, 8, bud)?;
    pos = skip(uc, pos, bud, 4)?; // version
    pos = skip(uc, pos, bud, 4)?; // network
    pos = skip(uc, pos, bud, 4)?; // root round
    let (major, epoch, next) = head(uc, pos)?;
    if major != 0 {
        return Err(E::Shape);
    }
    item(bud)?;
    pos = skip(uc, next, bud, 4)?; // timestamp
    pos = skip(uc, pos, bud, 4)?; // previous hash
    pos = skip(uc, pos, bud, 4)?; // hash
    let (sigs, next) = count(uc, pos, 5, bud)?;
    if sigs > MAX_SIGS_PER_SEAL {
        return Err(E::TooManyItems);
    }
    pos = skip_n(uc, next, 2 * sigs, bud, 5)?;
    if pos != uc.len() {
        return Err(E::Shape);
    }
    Ok(Occurrence {
        epoch,
        seal_start,
        seal_len: pos - seal_start,
        sigs,
        steps: total,
    })
}

/// The CBOR item occurrences of one complete canonical object (a `J` contribution), refused as soon as the next item would cross
/// `left`.
pub fn count_items(b: &[u8], left: usize) -> Result<usize> {
    let mut bud = Budget {
        limit: left,
        items: 0,
        steps: 0,
    };
    let end = skip(b, 0, &mut bud, 0)?;
    if end != b.len() {
        return Err(E::Trailing);
    }
    Ok(bud.items)
}

fn claim_key(a: &Anchor) -> Vec<u8> {
    let mut k = Vec::with_capacity(4 + a.shard.len() + 96 + a.uc.len());
    k.extend_from_slice(&a.partition.to_be_bytes());
    k.extend_from_slice(&(a.shard.len() as u16).to_be_bytes());
    k.extend_from_slice(&a.shard);
    k.extend_from_slice(&a.shard_conf_hash);
    k.extend_from_slice(&a.expected_state_root);
    k.extend_from_slice(&a.expected_ir_hash);
    k.extend_from_slice(&a.uc);
    k
}

/// Scan and group the claims of one batch. Each UC occurrence is scanned within its own `MAX_CBOR_ITEMS`.
pub fn measure(claims: &[Anchor]) -> Result<Counts> {
    let k = claims.len();
    if k == 0 || k > MAX_CLAIMS {
        return Err(E::TooManyPaths);
    }
    let mut n = Counts {
        k: k as u64,
        c: 4,
        ..Counts::default()
    };
    let mut bud = Budget {
        limit: 0,
        items: 0,
        steps: 0,
    };
    let mut epochs = BTreeSet::new();
    let mut seals: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    for a in claims {
        n.c += (CLAIM_FIXED + a.shard.len() + a.uc.len()) as u64;
        bud.limit = bud.items + MAX_CBOR_ITEMS;
        let o = scan(a, &mut bud)?;
        if epochs.insert(o.epoch) {
            n.e += 1;
        }
        if seals.insert(a.uc[o.seal_start..o.seal_start + o.seal_len].to_vec()) {
            n.s += 1;
            n.q += o.sigs as u64;
        }
        if seen.insert(claim_key(a)) {
            n.a += 1;
            n.p += o.steps as u64;
        }
    }
    n.items = bud.items as u64;
    Ok(n)
}

/// The `CERT_BATCH_V2` request: `version 2 | flags 0 | K:u16 | Claim[K]`, each `partition:u32 | shardLen:u16 | shard | three
/// hashes | ucLen:u32 | uc`.
pub fn batch_request(claims: &[Anchor]) -> Result<Vec<u8>> {
    if claims.is_empty() || claims.len() > MAX_CLAIMS {
        return Err(E::TooManyPaths);
    }
    let mut out = alloc::vec![2u8, 0];
    out.extend_from_slice(&(claims.len() as u16).to_be_bytes());
    for a in claims {
        out.extend_from_slice(&a.partition.to_be_bytes());
        out.extend_from_slice(&(a.shard.len() as u16).to_be_bytes());
        out.extend_from_slice(&a.shard);
        out.extend_from_slice(&a.shard_conf_hash);
        out.extend_from_slice(&a.expected_state_root);
        out.extend_from_slice(&a.expected_ir_hash);
        out.extend_from_slice(&(a.uc.len() as u32).to_be_bytes());
        out.extend_from_slice(&a.uc);
    }
    Ok(out)
}
