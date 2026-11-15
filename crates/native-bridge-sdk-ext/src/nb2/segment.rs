//! Segments, the sorted circular-gap tree, gap proofs, the archive chain (section 10), the wallet's `SegmentSealed` log check
//! and its history builder (section 12.3); `segment.ts`, bft-core `nb2ref/segment.go`.

use alloc::vec::Vec;

use super::cbor::{u16be, u64be};
use super::config::log2;
use super::crypto::he;
use super::deposit::{tag_archive_genesis, tag_archive_step};
use super::errors::{fail_d, Error, Nb2Error, Result, Rule};
use super::util::{arr, cat, u256_64};

/// bucket(eta) = eta >> (256 - log2 B).
pub fn bucket_of(eta: &[u8], b: u64) -> usize {
    (eta[0] >> (8 - log2(b))) as usize
}

pub fn gap_leaf(l: &[u8], u: &[u8]) -> [u8; 32] {
    he(&[&[0x00], l, u])
}

pub fn gap_node(l: &[u8], r: &[u8]) -> [u8; 32] {
    he(&[&[0x01], l, r])
}

/// 65 + 32h bytes.
pub fn gap_proof_len(k: u64) -> usize {
    65 + 32 * log2(k) as usize
}

/// A segment's sorted identifiers and its tree levels.
#[derive(Debug, Clone)]
pub struct GapTree {
    pub z: Vec<[u8; 32]>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl GapTree {
    /// Requires a power-of-two count >= 2, strictly increasing.
    pub fn build(z: &[[u8; 32]]) -> Option<GapTree> {
        let k = z.len();
        if k < 2 || k & (k - 1) != 0 {
            return None;
        }
        for i in 1..k {
            if z[i - 1] >= z[i] {
                return None;
            }
        }
        let leaves: Vec<[u8; 32]> = (0..k).map(|i| gap_leaf(&z[i], &z[(i + 1) % k])).collect();
        let mut levels = alloc::vec![leaves];
        while levels.last().expect("a level").len() > 1 {
            let row = levels.last().expect("a level");
            let next: Vec<[u8; 32]> = (0..row.len() / 2)
                .map(|i| gap_node(&row[2 * i], &row[2 * i + 1]))
                .collect();
            levels.push(next);
        }
        Some(GapTree {
            z: z.to_vec(),
            levels,
        })
    }

    /// M_j
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().expect("a level")[0]
    }

    /// The gap proof of `eta`, or None when `eta` is one of the identifiers (paid in this segment).
    pub fn prove(&self, eta: &[u8; 32]) -> Option<Vec<u8>> {
        let k = self.z.len();
        let mut i = 0;
        while i < k && self.z[i] < *eta {
            i += 1;
        }
        if i < k && self.z[i] == *eta {
            return None;
        }
        let g = if i == 0 || i == k { k - 1 } else { i - 1 };
        let mut out = cat(&[&[g as u8], &self.z[g], &self.z[(g + 1) % k]]);
        let mut pos = g;
        for row in &self.levels[..self.levels.len() - 1] {
            out.extend_from_slice(&row[pos ^ 1]);
            pos >>= 1;
        }
        Some(out)
    }
}

/// M derived from a gap proof for `eta` (section 10.2), or None when the proof is invalid.
pub fn gap_root(k: u64, eta: &[u8], proof: &[u8]) -> Option<[u8; 32]> {
    let h = log2(k) as usize;
    if proof.len() != 65 + 32 * h {
        return None;
    }
    let i = proof[0] as u64;
    let l = &proof[1..33];
    let u = &proof[33..65];
    if i >= k {
        return None;
    }
    if i < k - 1 {
        if !(l < u && l < eta && eta < u) {
            return None;
        }
    } else if !(u < l && (l < eta || eta < u)) {
        return None;
    }
    let mut x = gap_leaf(l, u);
    for s in 0..h {
        let sib = &proof[65 + 32 * s..97 + 32 * s];
        x = if (i >> s) & 1 == 0 {
            gap_node(&x, sib)
        } else {
            gap_node(sib, &x)
        };
    }
    Some(x)
}

/// H_0 = H_E(ARCHIVE_GENESIS || D || u16(K)).
pub fn genesis_head(d: &[u8], k: u64) -> [u8; 32] {
    he(&[&tag_archive_genesis(), d, &u16be(k as u16)])
}

/// H_{j+1} = H_E(ARCHIVE_STEP || D || u64(j) || H_j || M_j).
pub fn next_head(d: &[u8], j: u64, hj: &[u8], mj: &[u8]) -> [u8; 32] {
    he(&[&tag_archive_step(), d, &u64be(j), hj, mj])
}

/// Redeem step 3: fold from `start_head` through j = a .. a+P-1; `BadGapProof(position)` for a refused proof.
pub fn fold_history(
    d: &[u8],
    k: u64,
    eta: &[u8],
    a: u64,
    start_head: &[u8],
    proofs: &[&[u8]],
) -> Result<[u8; 32]> {
    let mut x: [u8; 32] = arr(start_head);
    for (p, pr) in proofs.iter().enumerate() {
        let Some(m) = gap_root(k, eta, pr) else {
            return Err(Error::Rule(Nb2Error::with_args(
                Rule::BadGapProof,
                alloc::vec![alloc::format!("{p}")],
            )));
        };
        x = next_head(d, a + p as u64, &x, &m);
    }
    Ok(x)
}

/// The redeem history: empty for P = 0, else startHead || proof_0 || ... || proof_{P-1}.
pub fn encode_history(start_head: &[u8], proofs: &[Vec<u8>]) -> Vec<u8> {
    if proofs.is_empty() {
        return Vec::new();
    }
    let mut out = start_head.to_vec();
    for p in proofs {
        out.extend_from_slice(p);
    }
    out
}

/// Split a history into its start head and proofs (the vault's step 1 framing); None when the length is not admitted.
pub fn split_history(k: u64, history: &[u8]) -> Option<([u8; 32], Vec<&[u8]>)> {
    if history.is_empty() {
        return Some(([0; 32], Vec::new()));
    }
    let pl = gap_proof_len(k);
    if history.len() < 32 + pl || (history.len() - 32) % pl != 0 {
        return None;
    }
    Some((arr(&history[..32]), history[32..].chunks(pl).collect()))
}

/// The 128 + 32K bytes of SegmentSealed(c, H_c, H_{c+1}, z_0 || ... || z_{K-1}).
pub fn segment_sealed_data(before: &[u8], after: &[u8], z: &[[u8; 32]]) -> Vec<u8> {
    let mut out = cat(&[before, after, &u256_64(0x60), &u256_64(32 * z.len() as u64)]);
    for x in z {
        out.extend_from_slice(x);
    }
    out
}

/// One verified SegmentSealed log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub index: u64,
    pub before: [u8; 32],
    pub after: [u8; 32],
    pub z: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

/// The wallet's check of the SegmentSealed log of segment j (section 12.3): exact length, the offset and length words, strictly
/// sorted identifiers, and H_{j+1} == NextHead(D, j, headBefore, M_j) == headAfter with headBefore the expected previous head.
/// Every failure is `SegmentLog`.
pub fn check_segment_log(
    d: &[u8],
    k: u64,
    j: u64,
    expect_before: &[u8],
    data: &[u8],
) -> Result<Segment> {
    if data.len() as u64 != 128 + 32 * k {
        return fail_d(Rule::SegmentLog, alloc::format!("length {}", data.len()));
    }
    if data[64..96] != u256_64(0x60) || data[96..128] != u256_64(32 * k) {
        return fail_d(Rule::SegmentLog, "offset or length word");
    }
    let z: Vec<[u8; 32]> = (0..k as usize)
        .map(|i| arr(&data[128 + 32 * i..160 + 32 * i]))
        .collect();
    let Some(tree) = GapTree::build(&z) else {
        return fail_d(Rule::SegmentLog, "identifiers not strictly sorted");
    };
    let s = Segment {
        index: j,
        before: arr(&data[..32]),
        after: arr(&data[32..64]),
        z,
        root: tree.root(),
    };
    if s.before != expect_before || next_head(d, j, &s.before, &s.root) != s.after {
        return fail_d(Rule::SegmentLog, "chain link");
    }
    Ok(s)
}

/// A built history: its bytes, or the segment in which `eta` was paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    pub history: Vec<u8>,
    pub paid: Option<u64>,
}

/// The wallet's proof builder (section 12.3): one gap proof of `eta` per verified segment a .. e-1 (in order, contiguous) and
/// the start head H_a. `paid` when `eta` is in one of them.
pub fn build_history(
    segs: &[Segment],
    eta: &[u8; 32],
    a: u64,
    e: u64,
    ha: &[u8],
) -> Result<History> {
    let mut proofs = Vec::new();
    for j in a..e {
        let seg = segs.get((j - a) as usize);
        let Some(seg) = seg.filter(|s| s.index == j) else {
            return fail_d(
                Rule::SegmentLog,
                alloc::format!("segment {j} missing or out of order"),
            );
        };
        match GapTree::build(&seg.z)
            .expect("a verified segment")
            .prove(eta)
        {
            None => {
                return Ok(History {
                    history: Vec::new(),
                    paid: Some(j),
                })
            }
            Some(p) => proofs.push(p),
        }
    }
    Ok(History {
        history: encode_history(ha, &proofs),
        paid: None,
    })
}
