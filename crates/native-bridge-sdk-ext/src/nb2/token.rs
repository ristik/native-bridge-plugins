use alloc::vec::Vec;
use num_bigint::BigUint;

use super::cbor::*;
use super::config::tag;
use super::crypto::{hu, imprint, parse_key};
use super::errors::{fail, Result, Rule};
use super::util::{arr, cat, min_bytes};

pub const TX_VERSION: u64 = 2;
pub const CERT_VERSION: u64 = 2;
pub const INCLUSION_VERSION: u64 = 1;
pub const VALUE_VERSION: u64 = 1;
pub const ENGINE_BUILTIN: u64 = 1;
pub const PRED_SIGNATURE: u64 = 1;
pub const PRED_BURN: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Predicate {
    pub ty: u64,
    pub params: Vec<u8>,
}

pub fn encode_predicate(p: &Predicate) -> Vec<u8> {
    c_tag(
        tag::PREDICATE,
        &c_arr(&[
            &c_uint(ENGINE_BUILTIN),
            &c_bytes(&c_uint(p.ty)),
            &c_bytes(&p.params),
        ]),
    )
}

pub fn signature_predicate(key33: &[u8]) -> Predicate {
    Predicate {
        ty: PRED_SIGNATURE,
        params: key33.to_vec(),
    }
}

pub fn burn_predicate(reason_hash: &[u8]) -> Predicate {
    Predicate {
        ty: PRED_BURN,
        params: reason_hash.to_vec(),
    }
}

fn decode_predicate(it: &Item<'_>) -> Result<Predicate> {
    let k = array(tag_content(it, tag::PREDICATE)?, 3)?;
    if !is_uint(&k[0]) || !is_bytes(&k[1]) || !is_bytes(&k[2]) {
        return fail(Rule::Shape);
    }
    if k[0].arg != ENGINE_BUILTIN {
        return fail(Rule::Predicate);
    }
    let code = k[1].data;
    if code.len() != 1 || (code[0] != 1 && code[0] != 2) {
        return fail(Rule::Predicate);
    }
    let p = Predicate {
        ty: code[0] as u64,
        params: k[2].data.to_vec(),
    };
    if p.ty == PRED_SIGNATURE {
        parse_key(&p.params)?;
    } else if p.params.len() != 32 {
        return fail(Rule::Predicate);
    }
    Ok(p)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintTx {
    pub network: u16,
    pub recipient: Predicate,
    pub salt: Vec<u8>,
    pub ty: Vec<u8>,
    pub justification: Option<Vec<u8>>,
    pub data: Option<Vec<u8>>,
    pub deadline: Deadline,
}

pub fn encode_mint(m: &MintTx) -> Vec<u8> {
    c_tag(
        tag::MINT,
        &c_arr_v(&[
            c_uint(TX_VERSION),
            c_uint(m.network as u64),
            encode_predicate(&m.recipient),
            c_bytes(&m.salt),
            c_bytes(&m.ty),
            c_null_or(m.justification.as_deref()),
            c_null_or(m.data.as_deref()),
            c_deadline(m.deadline),
        ]),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTx {
    pub recipient: Predicate,
    pub mask: Vec<u8>,
    pub data: Option<Vec<u8>>,
    pub deadline: Deadline,
}

pub fn encode_transfer(t: &TransferTx) -> Vec<u8> {
    c_tag(
        tag::TRANSFER,
        &c_arr_v(&[
            c_uint(TX_VERSION),
            encode_predicate(&t.recipient),
            c_bytes(&t.mask),
            c_null_or(t.data.as_deref()),
            c_deadline(t.deadline),
        ]),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certification {
    pub source: Predicate,
    pub source_hash: Vec<u8>,
    pub tx_hash: Vec<u8>,
    pub deadline: Deadline,
    pub unlock: Vec<u8>,
}

pub fn encode_certification(c: &Certification) -> Vec<u8> {
    c_tag(
        tag::CERTIFICATION,
        &c_arr_v(&[
            c_uint(CERT_VERSION),
            encode_predicate(&c.source),
            c_bytes(&c.source_hash),
            c_bytes(&c.tx_hash),
            c_deadline(c.deadline),
            c_bytes(&c.unlock),
        ]),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub cd: Certification,
    pub t: u64,
    pub bitmap: Vec<u8>,
    pub siblings: Vec<Vec<u8>>,
    pub uc: Vec<u8>,
}

pub fn encode_proof(p: &InclusionProof) -> Vec<u8> {
    let mut path = p.bitmap.clone();
    for s in &p.siblings {
        path.extend_from_slice(s);
    }
    c_tag(
        tag::INCLUSION,
        &c_arr_v(&[
            c_uint(INCLUSION_VERSION),
            encode_certification(&p.cd),
            c_uint(p.t),
            c_bytes(&path),
            p.uc.clone(),
        ]),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageLevel {
    pub allocation: Vec<u8>,
    pub mint: MintTx,
    pub mint_proof: InclusionProof,
    pub transfers: Vec<TransferTx>,
    pub proofs: Vec<InclusionProof>,
    /// The exact transaction bytes, as decoded.
    pub mint_raw: Vec<u8>,
    pub transfers_raw: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub ancestors: Vec<LineageLevel>,
    pub part: LineageLevel,
}

impl core::ops::Deref for Token {
    type Target = LineageLevel;
    fn deref(&self) -> &Self::Target {
        &self.part
    }
}

impl Token {
    pub fn levels(&self) -> impl Iterator<Item = &LineageLevel> {
        self.ancestors.iter().chain(core::iter::once(&self.part))
    }
}

pub const MAX_TRANSFER_PAIR: usize = 40_960;
pub const MAX_ROOT_MINT: usize = 66_048;
pub const MAX_CHILD_MINT: usize = 512;
pub const MAX_ALLOCATION: usize = 20_480;
const FLAT_HEADER: &[u8] = b"NB2L\x01\x01";

fn push_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("blob length fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
}

pub fn frame_level(allocation: &[u8], mint: &[u8], proof: &[u8], pairs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for bytes in [allocation, mint, proof] {
        push_blob(&mut out, bytes);
    }
    out.extend_from_slice(&(pairs.len() as u64).to_be_bytes());
    for pair in pairs {
        push_blob(&mut out, pair);
    }
    out
}

pub fn encode_level(level: &LineageLevel) -> Vec<u8> {
    let pairs: Vec<_> = level
        .transfers_raw
        .iter()
        .zip(&level.proofs)
        .map(|(tx, proof)| c_arr(&[tx, &encode_proof(proof)]))
        .collect();
    frame_level(
        &level.allocation,
        &level.mint_raw,
        &encode_proof(&level.mint_proof),
        &pairs,
    )
}

pub fn frame_lineage(levels: &[Vec<u8>]) -> Vec<u8> {
    let mut out = FLAT_HEADER.to_vec();
    out.extend_from_slice(&(levels.len() as u64).to_be_bytes());
    for level in levels {
        out.extend_from_slice(level);
    }
    out
}

pub fn encode_token(t: &Token) -> Vec<u8> {
    frame_lineage(&t.levels().map(encode_level).collect::<Vec<_>>())
}

fn take<'a>(left: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if n > left.len() {
        return fail(Rule::Length);
    }
    let (out, rest) = left.split_at(n);
    *left = rest;
    Ok(out)
}

fn framed<'a>(left: &mut &'a [u8], max: usize) -> Result<&'a [u8]> {
    let n = u32::from_be_bytes(arr(take(left, 4)?)) as usize;
    if n > max {
        return fail(Rule::InputTooLarge);
    }
    take(left, n)
}

/// Import exact signed bytes. Counts drive reads only after checking remaining bytes.
pub fn decode_token(mut left: &[u8]) -> Result<Token> {
    if take(&mut left, FLAT_HEADER.len())? != FLAT_HEADER {
        return fail(Rule::EvidenceShape);
    }
    let n = u64::from_be_bytes(arr(take(&mut left, 8)?));
    if n == 0 || n > (left.len() / 20) as u64 {
        return fail(Rule::EvidenceShape);
    }
    let mut levels = Vec::new();
    for i in 0..n {
        let allocation = framed(&mut left, if i == 0 { 0 } else { MAX_ALLOCATION })?.to_vec();
        if i != 0 && allocation.is_empty() {
            return fail(Rule::SplitProofShape);
        }
        let mint_raw = framed(
            &mut left,
            if i == 0 {
                MAX_ROOT_MINT
            } else {
                MAX_CHILD_MINT
            },
        )?;
        let mint = decode_mint(&scan_one(mint_raw)?)?;
        let proof_raw = framed(&mut left, 40_960 - 8)?;
        let mint_proof = decode_proof(&scan_native(proof_raw)?, proof_raw)?;
        let count = u64::from_be_bytes(arr(take(&mut left, 8)?));
        if count > (left.len() / 4) as u64 {
            return fail(Rule::Length);
        }
        let mut level = LineageLevel {
            allocation,
            mint,
            mint_raw: mint_raw.to_vec(),
            mint_proof,
            transfers: Vec::new(),
            transfers_raw: Vec::new(),
            proofs: Vec::new(),
        };
        for _ in 0..count {
            let pair = framed(&mut left, MAX_TRANSFER_PAIR)?;
            let item = scan_native(pair)?;
            let p = array(&item, 2)?;
            level.transfers.push(decode_transfer(&p[0])?);
            level.transfers_raw.push(raw(pair, &p[0]).to_vec());
            level.proofs.push(decode_proof(&p[1], pair)?);
        }
        levels.push(level);
    }
    if !left.is_empty() {
        return fail(Rule::Trailing);
    }
    let part = levels.pop().expect("nonempty lineage");
    Ok(Token {
        part,
        ancestors: levels,
    })
}

fn decode_mint(it: &Item<'_>) -> Result<MintTx> {
    let k = array(tag_content(it, tag::MINT)?, 8)?;
    version(&k[0], TX_VERSION)?;
    let network = uint_in(&k[1], 1, 65535)? as u16;
    let recipient = decode_predicate(&k[2])?;
    let salt = bytes_n(&k[3], 32)?.to_vec();
    let ty = bytes_n(&k[4], 32)?.to_vec();
    let justification = nullable_bytes(&k[5])?.map(|x| x.to_vec());
    let data = nullable_bytes(&k[6])?.map(|x| x.to_vec());
    Ok(MintTx {
        network,
        recipient,
        salt,
        ty,
        justification,
        data,
        deadline: deadline(&k[7])?,
    })
}

fn decode_transfer(it: &Item<'_>) -> Result<TransferTx> {
    let k = array(tag_content(it, tag::TRANSFER)?, 5)?;
    version(&k[0], TX_VERSION)?;
    let recipient = decode_predicate(&k[1])?;
    let mask = bytes_n(&k[2], 32)?.to_vec();
    let data = nullable_bytes(&k[3])?.map(|x| x.to_vec());
    Ok(TransferTx {
        recipient,
        mask,
        data,
        deadline: deadline(&k[4])?,
    })
}

fn decode_cd(it: &Item<'_>) -> Result<Certification> {
    let k = array(tag_content(it, tag::CERTIFICATION)?, 6)?;
    version(&k[0], CERT_VERSION)?;
    let source = decode_predicate(&k[1])?;
    let source_hash = bytes_n(&k[2], 32)?.to_vec();
    let tx_hash = bytes_n(&k[3], 32)?.to_vec();
    let dl = deadline(&k[4])?;
    Ok(Certification {
        source,
        source_hash,
        tx_hash,
        deadline: dl,
        unlock: bytes_n(&k[5], 65)?.to_vec(),
    })
}

const MAX_PROOF_UC_BYTES: usize = 24 << 10;

fn decode_proof(it: &Item<'_>, b: &[u8]) -> Result<InclusionProof> {
    let k = array(tag_content(it, tag::INCLUSION)?, 5)?;
    version(&k[0], INCLUSION_VERSION)?;
    let cd = decode_cd(&k[1])?;
    let t = uint_in(&k[2], 0, MAX_U64)?;
    let path = bstr(&k[3])?;
    if path.len() < 32 || path.len() % 32 != 0 {
        return fail(Rule::Length);
    }
    let bitmap = &path[..32];
    let pop: usize = bitmap.iter().map(|x| x.count_ones() as usize).sum();
    if path.len() != 32 + 32 * pop {
        return fail(Rule::Length);
    }
    let siblings = (0..pop)
        .map(|i| path[32 + 32 * i..64 + 32 * i].to_vec())
        .collect();
    if !is_tag(&k[4]) {
        return fail(Rule::Shape);
    }
    if k[4].end - k[4].start > MAX_PROOF_UC_BYTES {
        return fail(Rule::InputTooLarge);
    }
    Ok(InclusionProof {
        cd,
        t,
        bitmap: bitmap.to_vec(),
        siblings,
        uc: raw(b, &k[4]).to_vec(),
    })
}

/// sid = H(C(Psource, b(sourceHash32))).
pub fn state_id(source: &Predicate, source_hash: &[u8]) -> [u8; 32] {
    hu(&[&c_arr(&[&encode_predicate(source), &c_bytes(source_hash)])])
}

/// The output state H(C(b(I(sourceHash)), b(mask))); a mint's mask is the token ID.
pub fn result_state(source_hash: &[u8], mask: &[u8]) -> [u8; 32] {
    hu(&[&c_arr(&[&c_bytes(&imprint(source_hash)), &c_bytes(mask)])])
}

/// v = H(C(b(txHash32), t)).
pub fn leaf_value(tx_hash: &[u8], t: u64) -> [u8; 32] {
    hu(&[&c_arr(&[&c_bytes(tx_hash), &c_uint(t)])])
}

/// id = H(C(b(salt), network)).
pub fn token_id_of(salt: &[u8], network: u16) -> [u8; 32] {
    hu(&[&c_arr(&[&c_bytes(salt), &c_uint(network as u64)])])
}

/// h0 = H(C(b(id), b(H("TOKENID")))).
pub fn mint_source_hash(id: &[u8]) -> [u8; 32] {
    let suffix = hu(&[b"TOKENID"]);
    hu(&[&c_arr(&[&c_bytes(id), &c_bytes(&suffix)])])
}

/// tag(39050, [1, [[b(aid32), b(v)]], null]).
pub fn value_data(aid: &[u8], v: &BigUint) -> Vec<u8> {
    let vb = min_bytes(v);
    c_tag(
        tag::VALUE,
        &c_arr(&[
            &c_uint(VALUE_VERSION),
            &c_arr(&[&c_arr(&[&c_bytes(aid), &c_bytes(&vb)])]),
            &C_NULL,
        ]),
    )
}

/// A 32-byte copy.
pub fn a32(b: &[u8]) -> [u8; 32] {
    arr(b)
}

/// `cat` re-export for callers composing proofs.
pub fn concat(parts: &[&[u8]]) -> Vec<u8> {
    cat(parts)
}
