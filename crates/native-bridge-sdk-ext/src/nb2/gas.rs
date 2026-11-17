//! Size and gas bounds of a redemption (sections 12.4 and 12.5; `gas.ts`). The preflight needs a CONSERVATIVE bound of the
//! complete redeem transaction before the burn exists: its encoded size and its gas limit (expected cost plus `gasReserve`).
//! The gas part is a named, replaceable component: [`GasModel`]. The default [`MeasuredGasModel`] (bound-nb2-1179,
//! `docs/nb2-gas-model.md`) bounds the redeem term by term from the deployed verifier's cost structure, with the TypeScript
//! plug-in's results exactly (`tests/nb2-gas`), and fails closed (None, which the preflight reports as `CapacityPreflight`).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use unicity_token::api::bft::UnicityCertificate;
use unicity_token::cbor::{DecodeLimits, Decoder};

use super::abi::redeem_calldata_length;
use super::cbor::{array, bstr, bytes_n, head_tag, is_uint, raw, scan_native, tag_content};
use super::config::tag;
use super::crypto::{he, hu};
use super::deposit::decode_receipt_backing;
use super::segment::gap_proof_len;
use super::split::decode_split_justification;
use super::token::{
    concat, encode_token, mint_source_hash, result_state, state_id, token_id_of, Predicate, Token,
    PRED_SIGNATURE,
};
use super::util::to_hex;

/// What the gas model sees of a prospective redemption.
pub struct RedeemShape<'a> {
    /// The evidence bytes (`C(1, Token)`), or an upper bound of their length when the burn does not exist yet.
    pub evidence_bytes: usize,
    /// The decoded token of the lineage walk, root first, when known (counts certificates, signatures and paths).
    pub lineage: &'a [Token],
    /// Transactions the evidence will hold that are not in `lineage` yet (the burn about to be made).
    pub pending_transactions: usize,
    /// Historical gap proofs.
    pub proofs: u64,
    pub k: u64,
}

/// A gas model: the gas limit of a redeem (expected cost plus gasReserve), or None when it cannot be bounded.
pub trait GasModel: Send + Sync {
    fn name(&self) -> &str;
    fn redeem_gas_limit(&self, s: &RedeemShape<'_>) -> Option<u64>;
    /// The gas limit of a deposit call.
    fn deposit_gas_limit(&self) -> u64;
    /// Whether the model is calibrated for the deployment's verifier, given its runtime code (whose hash the bridge has checked against
    /// Γ); None for a model that does not say, which is the wallet's own choice and is used as supplied.
    fn supports_verifier(&self, _code: &[u8]) -> Option<bool> {
        None
    }
}

/// Measured by #1098 (K = 64, B = 16, optimizer runs 200): replay and settlement only.
pub mod measured {
    pub const GAS_RESERVE: u64 = 500_000;
    /// The more expensive of the P = 0 endpoints.
    pub const PREVIOUS_ENDPOINT: u64 = 78_083;
    pub const PER_SEGMENT: u64 = 5_950;
    pub const DEPOSIT_FIRST: u64 = 48_758;
}

const TX_BASE: u64 = 21_000;
const CALLDATA_NONZERO: u64 = 16;

/// Upper-bound guesses for the unmeasured verifier, from the B1 price schedule (bft-core `b1ref/limits.go`, profile 7) charged
/// for EVERY certificate occurrence as its own call, plus a per-byte charge for parsing and hashing the evidence in Solidity.
pub mod provisional {
    pub const PER_EVIDENCE_BYTE: u64 = 128;
    pub const PER_CERTIFICATE: u64 = 60_000 + 1_100 + 29_900 + 2_000;
    pub const PER_CERTIFICATE_BYTE: u64 = 16;
    pub const PER_SIGNATURE: u64 = 7_200;
    pub const MAX_SIGNATURES: usize = 16;
    pub const PER_PATH_STEP: u64 = 250;
    pub const PER_TRANSACTION: u64 = 3_000 + 2_000 + 256 * 250;
    pub const RECEIPT_PROOF: u64 = 200_000;
    /// A pending transaction's own certificate.
    pub const PENDING_CERTIFICATE_BYTES: u64 = 24_576;
}

/// The provisional model of NB2-07.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProvisionalGasModel;

impl GasModel for ProvisionalGasModel {
    fn name(&self) -> &str {
        "provisional-nb2-07"
    }

    fn redeem_gas_limit(&self, s: &RedeemShape<'_>) -> Option<u64> {
        use provisional as p;
        let mut verifier = p::RECEIPT_PROOF + p::PER_EVIDENCE_BYTE * s.evidence_bytes as u64;
        let mut transactions = 0u64;
        for tok in s.lineage {
            let proofs = core::iter::once(&tok.mint_proof).chain(tok.proofs.iter());
            for pr in proofs {
                transactions += 1;
                let sigs = count_signatures(&pr.uc)?;
                if sigs > p::MAX_SIGNATURES {
                    return None;
                }
                verifier += p::PER_CERTIFICATE
                    + p::PER_CERTIFICATE_BYTE * pr.uc.len() as u64
                    + p::PER_SIGNATURE * sigs as u64
                    + p::PER_PATH_STEP * (pr.siblings.len() as u64 + 32);
            }
        }
        // the root's EVM UC (inside J) and every pending transaction's future certificate, at the bounds
        let pending = s.pending_transactions as u64;
        verifier += (pending + 1)
            * (p::PER_CERTIFICATE
                + p::PER_CERTIFICATE_BYTE * p::PENDING_CERTIFICATE_BYTES
                + p::PER_SIGNATURE * p::MAX_SIGNATURES as u64
                + p::PER_PATH_STEP * 288);
        verifier += (transactions + pending) * p::PER_TRANSACTION;
        let history_bytes = if s.proofs == 0 {
            0
        } else {
            32 + s.proofs as usize * gap_proof_len(s.k)
        };
        let calldata =
            CALLDATA_NONZERO * redeem_calldata_length(s.evidence_bytes, history_bytes) as u64;
        let settlement = measured::PREVIOUS_ENDPOINT + measured::PER_SEGMENT * s.proofs;
        Some(TX_BASE + calldata + settlement + verifier + measured::GAS_RESERVE)
    }

    fn deposit_gas_limit(&self) -> u64 {
        2 * measured::DEPOSIT_FIRST + 50_000
    }
}

/// The redeem gas bound (bft-core#1179, `docs/nb2-gas-model.md`; `gas.ts` `REDEEM_GAS`, with identical results): an upper bound of
/// the vault redeem's gas limit, term by term from the deployed verifier's cost structure, not a fit to the token's length:
///
/// ```text
///   limit = transaction + vault + batch + membership + sha256 + execution + memory + forwarding + gasReserve
/// ```
///
/// The token's own proofs are counted exactly; the pending burn of a preflight at the decoder bounds. A UC that does not parse, or
/// has more than 16 signatures, gives None (`CapacityPreflight`). See `gas.ts` for each term.
pub mod redeem_gas {
    pub const TX_BASE: u64 = 21_000;
    pub const CALLDATA_BYTE: u64 = 16;
    pub const VAULT_WORST_CALL: u64 = 507_215;
    pub const PER_SEGMENT: u64 = 6_000;
    pub const COPY_WORD: u64 = 3;
    pub const BATCH_CALL: u64 = 61_100;
    pub const BATCH_BYTE: u64 = 16;
    pub const BATCH_PAIR: u64 = 500;
    pub const BATCH_EPOCH: u64 = 29_900;
    pub const BATCH_SIGNATURE: u64 = 7_200;
    pub const BATCH_CLAIM: u64 = 2_000;
    pub const BATCH_PATH: u64 = 250;
    pub const BATCH_CLAIMS: usize = 16;
    pub const BATCH_BYTES: usize = 262_144;
    pub const MEMBER_CALL: u64 = 2_000;
    pub const MEMBER_BYTE: u64 = 16;
    pub const MEMBER_STEP: u64 = 250;
    pub const SHA256_CALL: u64 = 60;
    pub const SHA256_WORD: u64 = 12;
    pub const VERIFIER_BASE: u64 = 158_000;
    pub const PER_TOKEN: u64 = 0;
    pub const PER_EDGE: u64 = 57_149;
    pub const PER_ALLOC_STEP: u64 = 2_000;
    pub const PER_STEP: u64 = 16_851;
    pub const PER_PARENT_STEP: u64 = 15_435;
    pub const PER_TX_WORD: u64 = 3;
    pub const PER_SIBLING: u64 = 3;
    pub const PER_ITEM: u64 = 757;
    pub const PER_UC_PARSE: u64 = 19_100;
    pub const PER_UC_BYTE: u64 = 7;
    pub const PER_UC_IR_BYTE: u64 = 27;
    pub const PER_UC_SIGNATURE: u64 = 1_784;
    pub const PER_UC_STC: u64 = 1_798;
    pub const PER_UC_UTC: u64 = 2_146;
    pub const PER_UC_SLOW_BYTE: u64 = 315;
    pub const PER_KEY_LOOKUP: u64 = 0;
    pub const PER_DECOMPRESS: u64 = 2_100;
    pub const PER_PROBE: u64 = 271;
    pub const PER_CLAIM: u64 = 1_039;
    pub const J_BYTE: u64 = 10;
    pub const PER_RLP_ITEM: u64 = 450;
    pub const PER_RLP_HEAD: u64 = 1_100;
    pub const PER_RLP_KIDS: u64 = 2_000;
    pub const COLD_ACCESS: u64 = 5_200;
    pub const MEM_BASE: usize = 320;
    pub const MEM_PER_STEP_100: usize = 6_744;
    pub const MEM_PER_PARENT_STEP_100: usize = 0;
    pub const MEM_PER_CLAIM_WORD_100: usize = 103;
    pub const MEM_PER_UC_WORD_100: usize = 306;
    pub const MEM_PER_PATH_WORD_100: usize = 123;
    pub const MEM_PER_TOKEN_100: usize = 28_523;
    pub const MEM_PER_EDGE_100: usize = 0;
    pub const MEM_PER_ALLOC_STEP_100: usize = 600;
    pub const MEM_PER_J_WORD_100: usize = 200;
    pub const PENDING_TX_BYTES: usize = 256;
    pub const PENDING_UC_BYTES: usize = 24_576;
    pub const PENDING_SIGNATURES: usize = 16;
    pub const PENDING_ID_BYTES: usize = 128;
    pub const PENDING_IR_BYTES: usize = 448;
    pub const PENDING_STC: usize = 256;
    pub const PENDING_UTC: usize = 32;
    pub const PENDING_SHARD_BYTES: usize = 33;
    pub const PENDING_SIBLINGS: usize = 256;
    pub const PENDING_UC_ITEMS: usize = 40 + 256 + 3 * 32 + 2 * 16;
    pub const PENDING_PAIR_ITEMS: usize = 32;
    pub const MAX_SIGNATURES: usize = 16;
    pub const KEY_CACHE: usize = 128;
}

/// One UC as the verifier, its helper and the batch see it.
#[derive(Clone)]
struct UcShape {
    bytes: usize,
    ir: usize,
    signatures: usize,
    stc: usize,
    utc: usize,
    slow: usize,
    epoch: Option<u64>,
    claim_bytes: usize,
    claim_key: Option<[u8; 32]>,
}

/// One distinct claim of the batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub bytes: usize,
    pub signatures: usize,
    pub path: usize,
    pub epoch: Option<u64>,
}

/// A UC's shape as the helper's parse prices it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UcCost {
    pub bytes: usize,
    pub ir: usize,
    pub signatures: usize,
    pub stc: usize,
    pub utc: usize,
    pub slow: usize,
}

/// The helper's certificate() on one UC, at the bound's coefficients (its execution and its frame's memory).
pub fn helper_gas(c: &UcCost) -> u64 {
    use redeem_gas as g;
    let u = |n: usize| n as u64;
    g::PER_UC_PARSE
        + g::PER_UC_BYTE * u(c.bytes)
        + g::PER_UC_IR_BYTE * u(c.ir)
        + g::PER_UC_SIGNATURE * u(c.signatures)
        + g::PER_UC_STC * u(c.stc)
        + g::PER_UC_UTC * u(c.utc)
        + g::PER_UC_SLOW_BYTE * u(c.slow)
        + helper_memory(c.bytes)
}

/// What the bound counts, extracted from the lineage (`gas.ts` RedeemFeatures).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemFeatures {
    pub tokens: usize,
    pub edges: usize,
    pub alloc_steps: usize,
    pub steps: usize,
    pub parent_steps: usize,
    pub tx_words: usize,
    pub max_tx: usize,
    pub siblings: usize,
    pub uc_parses: usize,
    pub uc_bytes: usize,
    pub uc_ir: usize,
    pub uc_signatures: usize,
    pub uc_stc: usize,
    pub uc_utc: usize,
    pub uc_slow: usize,
    pub helper_memory: u64,
    pub evm_uc: UcCost,
    pub rcpt_items: usize,
    pub rcpt_heads: usize,
    pub rcpt_kids: usize,
    pub rcpt_words: usize,
    pub uc_costs: Vec<UcCost>,
    pub path_words: usize,
    pub max_uc: usize,
    pub scratch: usize,
    pub items: usize,
    pub j_bytes: usize,
    pub key_lookups: usize,
    pub decompressions: usize,
    pub probes: usize,
    pub claims: Vec<Claim>,
}

/// The heads of a CBOR item sequence (definite lengths, string payloads skipped): the items the verifier's scanner visits.
pub fn cbor_items(b: &[u8]) -> usize {
    let mut n = 0;
    let mut p = 0usize;
    while p < b.len() {
        let ib = b[p];
        p += 1;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        let mut arg = ai as usize;
        if (24..=27).contains(&ai) {
            let w = 1usize << (ai - 24);
            arg = 0;
            for k in 0..w {
                arg = arg
                    .wrapping_mul(256)
                    .wrapping_add(*b.get(p + k).unwrap_or(&0) as usize);
            }
            p += w;
        }
        if major == 2 || major == 3 {
            p = p.saturating_add(arg);
        }
        n += 1;
    }
    n
}

/// A UC in Nb2Cert.parse's shape: tag 39001 [1, IR, trHash, scHash, STC, UTC, seal]; None when it is not that shape.
fn uc_shape(uc: &[u8]) -> Option<UcShape> {
    let it = scan_native(uc).ok()?;
    let c = array(tag_content(&it, 39001).ok()?, 7).ok()?;
    let ir = &c[1];
    let irc = array(tag_content(ir, 39002).ok()?, 10).ok()?;
    let sch = bytes_n(&c[3], 32).ok()?;
    let stc = array(tag_content(&c[4], 39003).ok()?, 3).ok()?;
    let shard = bstr(&stc[1]).ok()?;
    let utc = array(tag_content(&c[5], 39004).ok()?, 3).ok()?;
    let seal = array(tag_content(&c[6], 39005).ok()?, 8).ok()?;
    let sigs = &seal[7];
    if stc[2].major != 4
        || !is_uint(&utc[1])
        || utc[2].major != 4
        || !is_uint(&seal[3])
        || sigs.major != 5
    {
        return None;
    }
    let mut slow = 0;
    for k in (0..sigs.kids.len()).step_by(2) {
        if sigs.kids[k].major != 3 {
            return None;
        }
        let id = sigs.kids[k].data;
        if id.iter().any(|&x| x >= 0x80) {
            slow += id.len();
        }
    }
    let state_hash = bytes_n(&irc[4], 32).ok()?;
    let partition = u32::try_from(utc[1].arg).ok()?;
    let shard_len = u16::try_from(shard.len()).ok()?;
    let uc_len = u32::try_from(uc.len()).ok()?;
    let ir_hash = hu(&[raw(uc, ir)]);
    let claim = concat(&[
        &partition.to_be_bytes(),
        &shard_len.to_be_bytes(),
        shard,
        sch,
        state_hash,
        &ir_hash,
        &uc_len.to_be_bytes(),
        uc,
    ]);
    Some(UcShape {
        bytes: uc.len(),
        ir: ir.end - ir.start,
        signatures: sigs.kids.len() / 2,
        stc: stc[2].kids.len(),
        utc: utc[2].kids.len(),
        slow,
        epoch: Some(seal[3].arg),
        claim_bytes: claim.len(),
        claim_key: Some(he(&[&claim])),
    })
}

/// An RLP item as Nb2Evm.head reads it.
#[derive(Clone, Copy)]
struct Rlp {
    list: bool,
    pos: usize,
    len: usize,
    end: usize,
}

fn rlp_head(b: &[u8], p: usize, end: usize) -> Option<Rlp> {
    if p >= end {
        return None;
    }
    let x = b[p];
    let be = |q: usize, n: usize| -> Option<usize> {
        if n > 4 || q + n > end || b[q] == 0 {
            return None;
        }
        Some(
            b[q..q + n]
                .iter()
                .fold(0usize, |v, &d| v * 256 + d as usize),
        )
    };
    let (list, hdr, len) = if x < 0x80 {
        return Some(Rlp {
            list: false,
            pos: p,
            len: 1,
            end: p + 1,
        });
    } else if x <= 0xb7 {
        (false, 1, (x - 0x80) as usize)
    } else if x <= 0xbf {
        let ll = (x - 0xb7) as usize;
        (false, 1 + ll, be(p + 1, ll)?)
    } else if x <= 0xf7 {
        (true, 1, (x - 0xc0) as usize)
    } else {
        let ll = (x - 0xf7) as usize;
        (true, 1 + ll, be(p + 1, ll)?)
    };
    if p + hdr + len > end {
        return None;
    }
    Some(Rlp {
        list,
        pos: p + hdr,
        len,
        end: p + hdr + len,
    })
}

/// Every RLP item in [p, end) (check()'s visits), or None when it is not RLP.
fn rlp_items(b: &[u8], mut p: usize, end: usize, depth: usize) -> Option<usize> {
    let mut n = 0;
    while p < end {
        let it = rlp_head(b, p, end)?;
        if depth > 16 {
            return None;
        }
        n += 1;
        if it.list {
            n += rlp_items(b, it.pos, it.end, depth + 1)?;
        }
        p = it.end;
    }
    Some(n)
}

fn rlp_kids(b: &[u8], it: &Rlp) -> Option<Vec<Rlp>> {
    let mut out = Vec::new();
    let mut q = it.pos;
    while q < it.end {
        let k = rlp_head(b, q, it.end)?;
        q = k.end;
        out.push(k);
    }
    Some(out)
}

struct ReceiptShape {
    items: usize,
    heads: usize,
    kids: usize,
    words: usize,
}

/// The receipt helper's walk of J's deposit proof (`gas.ts` receiptShape): check() of the header, every trie node and the receipt;
/// kids() of the header (20), each node (17), the receipt (4) and the log (3); head() of every log up to the selected one and of its
/// topics; those calls' allocations and the log's data.
fn receipt_shape(header: &[u8], nodes: &[Vec<u8>], log_index: u64) -> Option<ReceiptShape> {
    let mut sh = ReceiptShape {
        items: 0,
        heads: 0,
        kids: 0,
        words: 0,
    };
    let largest = nodes
        .iter()
        .map(|x| x.len())
        .chain(core::iter::once(header.len()))
        .max()
        .unwrap_or(0);
    sh.words = 128 + 2 * nodes.len() + 18 + 20 + ceil32(largest);
    fn kids_of(sh: &mut ReceiptShape, b: &[u8], it: &Rlp, max: usize) -> Option<Vec<Rlp>> {
        let k = rlp_kids(b, it)?;
        sh.kids += 1;
        sh.heads += k.len();
        sh.words += 1 + 5 * max + 4 * k.len();
        Some(k)
    }
    fn top(sh: &mut ReceiptShape, b: &[u8]) -> Option<Rlp> {
        let n = rlp_items(b, 0, b.len(), 0)?;
        let it = rlp_head(b, 0, b.len())?;
        if it.end != b.len() {
            return None;
        }
        sh.items += n;
        Some(it)
    }
    let h = top(&mut sh, header)?;
    if !h.list {
        return None;
    }
    kids_of(&mut sh, header, &h, 20)?;
    let mut value: Option<&[u8]> = None;
    for (i, node) in nodes.iter().enumerate() {
        let it = top(&mut sh, node)?;
        if !it.list {
            return None;
        }
        let k = kids_of(&mut sh, node, &it, 17)?;
        if i == nodes.len() - 1 {
            let v = match k.len() {
                17 => k[16],
                2 => k[1],
                _ => return None,
            };
            if v.list {
                return None;
            }
            value = Some(&node[v.pos..v.end]);
        }
    }
    let value = value.filter(|v| !v.is_empty())?;
    let r = if value[0] < 0xc0 { &value[1..] } else { value };
    let rt = top(&mut sh, r)?;
    if !rt.list {
        return None;
    }
    let f = kids_of(&mut sh, r, &rt, 4)?;
    if f.len() != 4 || !f[3].list {
        return None;
    }
    let mut q = f[3].pos;
    let mut sel = None;
    let mut i = 0u64;
    while q < f[3].end {
        let it = rlp_head(r, q, f[3].end)?;
        sh.heads += 1;
        sh.words += 4;
        if i == log_index {
            sel = Some(it);
            break;
        }
        i += 1;
        q = it.end;
    }
    let sel = sel.filter(|s| s.list)?;
    let lk = kids_of(&mut sh, r, &sel, 3)?;
    if lk.len() != 3 || !lk[1].list {
        return None;
    }
    let topics = rlp_kids(r, &lk[1])?;
    sh.heads += topics.len();
    sh.words += 4 * topics.len() + 1 + topics.len() + 1 + ceil32(lk[2].len);
    Some(sh)
}

/// One open-addressing table of the verifier (linear probing from the key's low bits), counting its probes and its misses.
struct ProbeTable {
    slots: Vec<Option<[u8; 32]>>,
    probes: usize,
    misses: usize,
}

impl ProbeTable {
    fn new(size: usize) -> Self {
        Self {
            slots: alloc::vec![None; size],
            probes: 0,
            misses: 0,
        }
    }

    /// Look up or insert KEY; a full table answers a miss without storing (the key cache).
    fn lookup(&mut self, key: &[u8; 32]) {
        let mask = self.slots.len() - 1;
        let low = u32::from_be_bytes([key[28], key[29], key[30], key[31]]) as usize;
        let mut i = low & mask;
        for _ in 0..=mask {
            self.probes += 1;
            match &self.slots[i] {
                Some(s) if s == key => return,
                None => {
                    self.slots[i] = Some(*key);
                    self.misses += 1;
                    return;
                }
                _ => i = (i + 1) & mask,
            }
        }
        self.misses += 1;
    }
}

/// The part's current owner and state (`tokenops` head, repeated here to keep this module free of the signing code).
fn head_of(t: &Token) -> (Predicate, [u8; 32]) {
    let id = token_id_of(&t.mint.salt, t.mint.network);
    let mut state = result_state(&mint_source_hash(&id), &id);
    let mut owner = t.mint.recipient.clone();
    for tr in &t.transfers {
        state = result_state(&state, &tr.mask);
        owner = tr.recipient.clone();
    }
    (owner, state)
}

/// The verifier's table size for N entries (_pow2: at least 16).
fn pow2_at(n: usize) -> usize {
    let mut p = 16;
    while p < n {
        p <<= 1;
    }
    p
}

const fn ceil32(n: usize) -> usize {
    n.div_ceil(32)
}

/// The memory expansion of WORDS words (the Yellow Paper's C_mem).
pub fn memory_gas(words: usize) -> u64 {
    let w = words as u64;
    3 * w + w * w / 512
}

/// One helper call's frame: the UC copied for the claim, the claim and the ABI answer (about three UCs of memory).
fn helper_memory(uc_bytes: usize) -> u64 {
    memory_gas(3 * ceil32(uc_bytes) + 64)
}

struct StepShape {
    tx: usize,
    siblings: usize,
    uc: UcShape,
    sid: [u8; 32],
}

/// The features of a prospective redemption; None when a UC does not parse or has more signatures than the bound.
pub fn redeem_features(s: &RedeemShape<'_>) -> Option<RedeemFeatures> {
    use redeem_gas as g;
    let l = s.lineage;
    if l.is_empty() || s.pending_transactions > 1 {
        return None;
    }
    let pending = s.pending_transactions == 1;
    let mut cache: BTreeMap<[u8; 32], Option<UcShape>> = BTreeMap::new();
    let mut shape_of = |uc: &[u8]| -> Option<UcShape> {
        let k = hu(&[uc]);
        let u = cache.entry(k).or_insert_with(|| uc_shape(uc)).clone()?;
        (u.signatures <= g::MAX_SIGNATURES).then_some(u)
    };
    let mut steps: Vec<StepShape> = Vec::new();
    for t in l {
        let proofs = core::iter::once(&t.mint_proof).chain(t.proofs.iter());
        let raws = core::iter::once(&t.mint_raw).chain(t.transfers_raw.iter());
        for (p, r) in proofs.zip(raws) {
            let uc = shape_of(&p.uc)?;
            steps.push(StepShape {
                tx: r.len(),
                siblings: p.siblings.len(),
                uc,
                sid: state_id(&p.cd.source, &p.cd.source_hash),
            });
        }
    }
    let part = &l[l.len() - 1];
    let (owner, state) = head_of(part);
    if pending {
        let uc = UcShape {
            bytes: g::PENDING_UC_BYTES,
            ir: g::PENDING_IR_BYTES,
            signatures: g::PENDING_SIGNATURES,
            stc: g::PENDING_STC,
            utc: g::PENDING_UTC,
            slow: g::PENDING_SIGNATURES * g::PENDING_ID_BYTES,
            epoch: None,
            claim_bytes: 4 + 2 + g::PENDING_SHARD_BYTES + 96 + 4 + g::PENDING_UC_BYTES,
            claim_key: None,
        };
        steps.push(StepShape {
            tx: g::PENDING_TX_BYTES,
            siblings: g::PENDING_SIBLINGS,
            uc,
            sid: state_id(&owner, &state),
        });
    }
    let n = steps.len();
    let j = l[0]
        .mint
        .justification
        .as_deref()
        .filter(|j| head_tag(j) == Some(tag::RECEIPT_BACKING))?;
    let dp = decode_receipt_backing(j).ok()?.proof;
    let evm = shape_of(&dp.uc)?;
    let rcpt = receipt_shape(&dp.header, &dp.nodes, dp.log_index)?;
    let mut items = 2 + cbor_items(&encode_token(part)) + cbor_items(j);
    if pending {
        items += g::PENDING_PAIR_ITEMS + g::PENDING_UC_ITEMS;
    }
    let mut alloc_steps = 0;
    for t in &l[1..] {
        let sj = t.mint.justification.as_deref()?;
        items += cbor_items(sj);
        alloc_steps += decode_split_justification(sj).ok()?.proof.len();
    }
    let mut keys = ProbeTable::new(g::KEY_CACHE);
    let mut key_lookups = 0;
    let mut key = |p: &Predicate, keys: &mut ProbeTable| {
        if p.ty == PRED_SIGNATURE {
            key_lookups += 1;
            keys.lookup(&he(&[&p.params]));
        }
    };
    for (i, t) in l.iter().enumerate().rev() {
        key(&t.mint.recipient, &mut keys);
        key(&t.mint_proof.cd.source, &mut keys);
        for (tr, pr) in t.transfers.iter().zip(t.proofs.iter()) {
            key(&tr.recipient, &mut keys);
            key(&pr.cd.source, &mut keys);
        }
        if i == l.len() - 1 && pending {
            key(&owner, &mut keys);
        }
    }
    let mut sids = ProbeTable::new(pow2_at(2 * n));
    for st in &steps {
        let mut k = st.sid;
        if k == [0u8; 32] {
            k[31] = 1;
        }
        sids.lookup(&k);
    }
    let mut claim_ids = ProbeTable::new(pow2_at(2 * (n + 1)));
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut claims = Vec::new();
    let mut unknown_probes = 0;
    for u in core::iter::once(&evm).chain(steps.iter().map(|st| &st.uc)) {
        let c = Claim {
            bytes: u.claim_bytes,
            signatures: u.signatures,
            path: u.stc + u.utc,
            epoch: u.epoch,
        };
        match u.claim_key {
            None => {
                unknown_probes += seen.len() + 1;
                claims.push(c);
            }
            Some(k) => {
                claim_ids.lookup(&k);
                if seen.insert(k) {
                    claims.push(c);
                }
            }
        }
    }
    let mut f = RedeemFeatures {
        tokens: l.len(),
        edges: l.len() - 1,
        alloc_steps,
        steps: n,
        parent_steps: l[..l.len() - 1].iter().map(|t| 1 + t.transfers.len()).sum(),
        tx_words: 0,
        max_tx: 0,
        siblings: 0,
        uc_parses: n + 1,
        uc_bytes: evm.bytes,
        uc_ir: evm.ir,
        uc_signatures: evm.signatures,
        uc_stc: evm.stc,
        uc_utc: evm.utc,
        uc_slow: evm.slow,
        helper_memory: memory_gas(3 * ceil32(evm.bytes) + 64 + rcpt.words),
        evm_uc: UcCost {
            bytes: evm.bytes,
            ir: evm.ir,
            signatures: evm.signatures,
            stc: evm.stc,
            utc: evm.utc,
            slow: evm.slow,
        },
        uc_costs: Vec::new(),
        rcpt_items: rcpt.items,
        rcpt_heads: rcpt.heads,
        rcpt_kids: rcpt.kids,
        rcpt_words: rcpt.words,
        path_words: 0,
        max_uc: evm.bytes,
        scratch: 24,
        items,
        j_bytes: j.len(),
        key_lookups,
        decompressions: keys.misses,
        probes: keys.probes + sids.probes + claim_ids.probes + unknown_probes,
        claims,
    };
    // a transaction is hashed from a copy at the free pointer; every later step allocates at least two copies of its UC over that scratch
    let mut after = 0usize;
    for st in steps.iter().rev() {
        f.scratch = f.scratch.max((ceil32(st.tx) + 1).saturating_sub(after));
        after += 2 * ceil32(st.uc.bytes);
    }
    for st in &steps {
        f.tx_words += ceil32(st.tx);
        f.max_tx = f.max_tx.max(st.tx);
        f.siblings += st.siblings;
        f.uc_bytes += st.uc.bytes;
        f.uc_ir += st.uc.ir;
        f.uc_signatures += st.uc.signatures;
        f.uc_stc += st.uc.stc;
        f.uc_utc += st.uc.utc;
        f.uc_slow += st.uc.slow;
        f.helper_memory += helper_memory(st.uc.bytes);
        let c = UcCost {
            bytes: st.uc.bytes,
            ir: st.uc.ir,
            signatures: st.uc.signatures,
            stc: st.uc.stc,
            utc: st.uc.utc,
            slow: st.uc.slow,
        };
        if !f.uc_costs.contains(&c) {
            f.uc_costs.push(c);
        }
        f.path_words += 1 + ceil32(104 + 32 * (st.siblings + 1));
        f.max_uc = f.max_uc.max(st.uc.bytes);
    }
    Some(f)
}

/// CERT_BATCH_V2 over the distinct claims in the verifier's batching (_flush): (gas, calls, the largest call's gas).
pub fn batch_gas(claims: &[Claim]) -> (u64, usize, u64) {
    use redeem_gas as g;
    let m = claims.len();
    if m == 0 {
        return (0, 0, 0);
    }
    let per = m.div_ceil(m.div_ceil(g::BATCH_CLAIMS));
    let (mut gas, mut largest, mut calls) = (0u64, 0u64, 0usize);
    let mut s = 0;
    while s < m {
        let mut e = s;
        let mut bytes = 4;
        while e < m && e - s < per && bytes + claims[e].bytes <= g::BATCH_BYTES {
            bytes += claims[e].bytes;
            e += 1;
        }
        if e == s {
            bytes += claims[e].bytes;
            e += 1;
        }
        let k = (e - s) as u64;
        let mut epochs: BTreeSet<(bool, u64)> = BTreeSet::new();
        let (mut q, mut p) = (0u64, 0u64);
        for (i, c) in claims.iter().enumerate().take(e).skip(s) {
            epochs.insert(match c.epoch {
                Some(ep) => (true, ep),
                None => (false, i as u64),
            });
            q += c.signatures as u64;
            p += c.path as u64;
        }
        let c = g::BATCH_CALL
            + g::BATCH_BYTE * bytes as u64
            + g::BATCH_PAIR * k * (k - 1)
            + g::BATCH_EPOCH * epochs.len() as u64
            + g::BATCH_SIGNATURE * q
            + g::BATCH_CLAIM * k
            + g::BATCH_PATH * p;
        gas += c;
        largest = largest.max(c);
        calls += 1;
        s = e;
    }
    (gas, calls, largest)
}

/// The verifier frame's memory high-water bound (words): its hash tables exactly, what else it allocates, its largest scratch use.
pub fn verifier_memory_words(f: &RedeemFeatures) -> usize {
    use redeem_gas as g;
    let n = f.steps;
    let tables = pow2_at(2 * (n + 1)) + pow2_at(2 * n) + (n + 1) + 2 * g::KEY_CACHE;
    let per = g::MEM_PER_STEP_100 * n
        + g::MEM_PER_PARENT_STEP_100 * f.parent_steps
        + g::MEM_PER_CLAIM_WORD_100 * f.claims.iter().map(|c| ceil32(c.bytes) + 1).sum::<usize>()
        + g::MEM_PER_UC_WORD_100 * ceil32(f.uc_bytes)
        + g::MEM_PER_PATH_WORD_100 * f.path_words
        + g::MEM_PER_TOKEN_100 * f.tokens
        + g::MEM_PER_EDGE_100 * f.edges
        + g::MEM_PER_ALLOC_STEP_100 * f.alloc_steps
        + g::MEM_PER_J_WORD_100 * ceil32(f.j_bytes);
    g::MEM_BASE + per.div_ceil(100) + tables + f.scratch
}

/// The bound's terms, each an upper bound of its part of the redeem's gas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasTerms {
    pub transaction: u64,
    pub vault: u64,
    pub batch: u64,
    pub membership: u64,
    pub sha256: u64,
    pub execution: u64,
    pub memory: u64,
    pub forwarding: u64,
    pub reserve: u64,
    pub limit: u64,
    pub memory_words: usize,
}

/// The terms of a redemption with FEATURES, EVIDENCE_BYTES of evidence and PROOFS historical gap proofs at K.
pub fn price_features(f: &RedeemFeatures, evidence_bytes: usize, proofs: u64, k: u64) -> GasTerms {
    use redeem_gas as g;
    let u = |n: usize| n as u64;
    let history_bytes = if proofs == 0 {
        0
    } else {
        32 + proofs as usize * gap_proof_len(k)
    };
    let transaction =
        g::TX_BASE + g::CALLDATA_BYTE * u(redeem_calldata_length(evidence_bytes, history_bytes));
    let vw = ceil32(evidence_bytes) + 64;
    let vault =
        g::VAULT_WORST_CALL + g::PER_SEGMENT * proofs + g::COPY_WORD * u(vw) + memory_gas(vw);
    let (batch, _, largest) = batch_gas(&f.claims);
    let membership = u(f.steps) * (g::MEMBER_CALL + g::MEMBER_BYTE * 136 + g::MEMBER_STEP)
        + u(f.siblings) * (32 * g::MEMBER_BYTE + g::MEMBER_STEP);
    let sha256 = u(f.steps) * g::SHA256_CALL + u(f.tx_words) * g::SHA256_WORD;
    let execution = g::VERIFIER_BASE
        + g::PER_TOKEN * u(f.tokens)
        + g::PER_EDGE * u(f.edges)
        + g::PER_ALLOC_STEP * u(f.alloc_steps)
        + g::PER_STEP * u(f.steps)
        + g::PER_PARENT_STEP * u(f.parent_steps)
        + g::PER_TX_WORD * u(f.tx_words)
        + g::PER_SIBLING * u(f.siblings)
        + g::PER_ITEM * u(f.items)
        + g::PER_UC_PARSE * u(f.uc_parses)
        + g::PER_UC_BYTE * u(f.uc_bytes)
        + g::PER_UC_IR_BYTE * u(f.uc_ir)
        + g::PER_UC_SIGNATURE * u(f.uc_signatures)
        + g::PER_UC_STC * u(f.uc_stc)
        + g::PER_UC_UTC * u(f.uc_utc)
        + g::PER_UC_SLOW_BYTE * u(f.uc_slow)
        + f.helper_memory
        + g::PER_KEY_LOOKUP * u(f.key_lookups)
        + g::PER_DECOMPRESS * u(f.decompressions)
        + g::PER_PROBE * u(f.probes)
        + g::PER_CLAIM * u(f.claims.len())
        + g::J_BYTE * u(f.j_bytes)
        + g::PER_RLP_ITEM * u(f.rcpt_items)
        + g::PER_RLP_HEAD * u(f.rcpt_heads)
        + g::PER_RLP_KIDS * u(f.rcpt_kids)
        + g::COLD_ACCESS;
    let memory_words = verifier_memory_words(f);
    let memory = memory_gas(memory_words);
    let verifier = batch + membership + sha256 + execution + memory;
    // EIP-150 at the verifier's own calls: the largest of its batch calls, its helper calls (one a UC; J's receipt with its EVM UC)
    let mut largest = largest;
    for c in &f.uc_costs {
        largest = largest.max(helper_gas(c));
    }
    largest = largest.max(
        helper_gas(&f.evm_uc) - helper_memory(f.evm_uc.bytes)
            + memory_gas(3 * ceil32(f.evm_uc.bytes) + 64 + f.rcpt_words)
            + g::J_BYTE * u(f.j_bytes)
            + g::PER_RLP_ITEM * u(f.rcpt_items)
            + g::PER_RLP_HEAD * u(f.rcpt_heads)
            + g::PER_RLP_KIDS * u(f.rcpt_kids),
    );
    let inner = largest / 63 + 1;
    let forwarding = (verifier + inner) / 63 + 1 + inner;
    let reserve = measured::GAS_RESERVE;
    let limit = transaction + vault + verifier + forwarding + reserve;
    GasTerms {
        transaction,
        vault,
        batch,
        membership,
        sha256,
        execution,
        memory,
        forwarding,
        reserve,
        limit,
        memory_words,
    }
}

/// The terms of a prospective redemption, or None when it cannot be bounded.
pub fn redeem_gas_terms(s: &RedeemShape<'_>) -> Option<GasTerms> {
    redeem_features(s).map(|f| price_features(&f, s.evidence_bytes, s.proofs, s.k))
}

/// The verifier build [`redeem_gas`] is calibrated for (`gas.ts` CALIBRATED_VERIFIER): unicity-pos-contracts 884c4829
/// `src/nb2/verifier` (solc 0.8.37, via-IR, optimizer runs 1), compared with its immutables zeroed, pinning the calibrated helper.
pub mod calibrated_verifier {
    pub const CODE_LENGTH: usize = 19_574;
    pub const MASKED_CODE_HASH: &str =
        "65fbc862ae2ea16729506cd9e6a62458785751b690103ce25d9515495029f201";
    pub const IMMUTABLES: [(usize, usize); 8] = [
        (325, 32),
        (368, 32),
        (3_071, 32),
        (8_417, 32),
        (8_473, 32),
        (8_541, 32),
        (12_187, 32),
        (15_504, 32),
    ];
    pub const HELPER_CODE_HASH_AT: [usize; 2] = [368, 8_417];
    pub const HELPER_CODE_HASH: &str =
        "16f1381ed6c1d9cd1c14b467fcfb2ec84ab8903f65da506048fbb2e2c10ffe23";
}

/// Whether CODE is the calibrated verifier build (immutables zeroed) pinning the calibrated helper.
pub fn calibrated_verifier(code: &[u8]) -> bool {
    use calibrated_verifier as c;
    if code.len() != c::CODE_LENGTH {
        return false;
    }
    if c::HELPER_CODE_HASH_AT
        .iter()
        .any(|&at| to_hex(&code[at..at + 32]) != c::HELPER_CODE_HASH)
    {
        return false;
    }
    let mut m = code.to_vec();
    for (at, n) in c::IMMUTABLES {
        m[at..at + n].fill(0);
    }
    to_hex(&he(&[&m])) == c::MASKED_CODE_HASH
}

/// The default model: [`redeem_gas`], for the calibrated verifier build only (the bridge refuses it for any other).
#[derive(Debug, Clone, Copy, Default)]
pub struct MeasuredGasModel;

impl GasModel for MeasuredGasModel {
    fn name(&self) -> &str {
        "bound-nb2-1179"
    }

    fn redeem_gas_limit(&self, s: &RedeemShape<'_>) -> Option<u64> {
        redeem_gas_terms(s).map(|t| t.limit)
    }

    fn deposit_gas_limit(&self) -> u64 {
        2 * measured::DEPOSIT_FIRST + 50_000
    }

    fn supports_verifier(&self, code: &[u8]) -> Option<bool> {
        Some(calibrated_verifier(code))
    }
}

/// The signature count of a UC's seal, from its full canonical decode; None (fail closed) when the UC does not decode.
fn count_signatures(uc: &[u8]) -> Option<usize> {
    UnicityCertificate::from_cbor(Decoder::with_limits(uc, DecodeLimits::DEFAULT))
        .ok()
        .map(|u| u.unicity_seal.signatures.len())
}

/// The encoded size of a signed EIP-1559 redeem transaction around `calldata` bytes: the envelope, nine scalar fields at their
/// widest, the 20-byte target, an empty access list and a 65-byte signature, plus the RLP heads of the data string and the list.
pub fn redeem_tx_framing(calldata: usize) -> usize {
    1 + 9 + 9 * 9 + 21 + 1 + 3 * 33 + if calldata >= 56 { 5 } else { 1 } + 5
}
