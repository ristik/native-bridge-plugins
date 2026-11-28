//! Deposit, mint reason and deposit proof (sections 5 and 6; `deposit.ts`, bft-core `nb2ref/deposit.go`).

use alloc::vec::Vec;
use num_bigint::BigUint;

use super::cbor::*;
use super::config::{domain, tag, Config, MAX_DEPOSIT, MAX_INDEX, V2_VERSION};
use super::crypto::{he, hmac_sha256, hu};
use super::errors::{fail, Result, Rule};
use super::header::{bind_header, Header};
use super::mpt::mpt_verify;
use super::rlp::{rlp_decode, rlp_index_key, rlp_uint, RlpItem};
use super::token::{encode_predicate, value_data, MintTx};
use super::trust::{verify_evm_uc, TrustInput};
use super::util::{be_int, cat, u256, u256_64};

/// Profile bounds of the deposit evidence (`profile.json` `limits`), checked before any cryptography.
pub mod limits {
    pub const JUSTIFICATION_BYTES: usize = 65536;
    pub const UC_BYTES: usize = 16384;
    pub const HEADER_BYTES: usize = 2048;
    pub const RECEIPT_NODES: usize = 65;
    pub const RECEIPT_BRANCH_NODE_BYTES: usize = 1024;
    pub const RECEIPT_LEAF_NODE_BYTES: usize = 49152;
}

pub const FIRST_OWNER_BYTES: usize = 42;

pub fn tag_deposit_secret() -> [u8; 32] {
    he(&[b"UNICITY_NB2_DEPOSIT_SECRET"])
}

pub fn tag_archive_genesis() -> [u8; 32] {
    he(&[b"UNICITY_NB2_ARCHIVE_GENESIS"])
}

pub fn tag_archive_step() -> [u8; 32] {
    he(&[b"UNICITY_NB2_ARCHIVE_STEP"])
}

/// The event topics.
pub mod topic {
    use super::he;

    pub fn deposited() -> [u8; 32] {
        he(&[b"Deposited(uint64,bytes32,uint256,bytes32,bytes)"])
    }

    pub fn erc20_deposited() -> [u8; 32] {
        he(&[b"ERC20Deposited(uint64,address,bytes32,uint256,bytes32,bytes)"])
    }
    pub fn erc20_activated() -> [u8; 32] {
        he(&[b"ERC20Activated(address,address,address,bytes32,bytes32,bytes32)"])
    }
    pub fn paid() -> [u8; 32] {
        he(&[b"Paid(bytes32,address,uint256)"])
    }

    pub fn segment_sealed() -> [u8; 32] {
        he(&[b"SegmentSealed(uint64,bytes32,bytes32,bytes)"])
    }
}

/// r = HMAC-SHA256(key = k_w, msg = C(b("UNICITY_NB2_DEPOSIT_INTENT"), b(D), i)).
pub fn deposit_intent_secret(kw: &[u8], d: &[u8], i: u64) -> [u8; 32] {
    hmac_sha256(
        kw,
        &c_arr(&[
            &c_bytes(domain::DEPOSIT_INTENT.as_bytes()),
            &c_bytes(d),
            &c_uint(i),
        ]),
    )
}

/// rho = H_E(DEPOSIT_SECRET || D || r).
pub fn rho_of(d: &[u8], r: &[u8]) -> [u8; 32] {
    he(&[&tag_deposit_secret(), d, r])
}

/// salt_n = H_U(C(b("UNICITY_NB2_DEPOSIT_SALT"), b(D), n, b(r))).
pub fn deposit_salt(d: &[u8], n: u64, r: &[u8]) -> [u8; 32] {
    hu(&[&c_arr(&[
        &c_bytes(domain::DEPOSIT_SALT.as_bytes()),
        &c_bytes(d),
        &c_uint(n),
        &c_bytes(r),
    ])])
}

/// The 9-byte head of the 42-byte first owner tag(39032, [1, b(0x01), b(key33)]).
pub const FIRST_OWNER_PREFIX: [u8; 9] = [0xd9, 0x98, 0x78, 0x83, 0x01, 0x41, 0x01, 0x58, 0x21];

pub fn first_owner_of(key33: &[u8]) -> Vec<u8> {
    cat(&[&FIRST_OWNER_PREFIX, key33])
}

/// DepositProof = [1, b(evmUC), b(headerRLP), txIndex, logIndex, [b(receiptNodeRLP), ...]], also the seal receipt container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositProof {
    pub uc: Vec<u8>,
    pub header: Vec<u8>,
    pub tx_index: u64,
    pub log_index: u64,
    pub nodes: Vec<Vec<u8>>,
}

pub fn encode_deposit_proof(p: &DepositProof) -> Vec<u8> {
    c_arr_v(&[
        c_uint(V2_VERSION),
        c_bytes(&p.uc),
        c_bytes(&p.header),
        c_uint(p.tx_index),
        c_uint(p.log_index),
        c_arr_v(&p.nodes.iter().map(|n| c_bytes(n)).collect::<Vec<_>>()),
    ])
}

/// J = tag(39051, [1, b(D), n, b(r), DepositProof]). Its `Debug` redacts the secret r.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiptBacking {
    pub d: [u8; 32],
    pub n: u64,
    pub r: [u8; 32],
    pub proof: DepositProof,
}

impl core::fmt::Debug for ReceiptBacking {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReceiptBacking")
            .field("d", &self.d)
            .field("n", &self.n)
            .field("r", &"<redacted>")
            .field("proof", &self.proof)
            .finish()
    }
}

pub fn encode_receipt_backing(j: &ReceiptBacking) -> Vec<u8> {
    c_tag(
        tag::RECEIPT_BACKING,
        &c_arr_v(&[
            c_uint(V2_VERSION),
            c_bytes(&j.d),
            c_uint(j.n),
            c_bytes(&j.r),
            encode_deposit_proof(&j.proof),
        ]),
    )
}

pub fn decode_receipt_backing(b: &[u8]) -> Result<ReceiptBacking> {
    if b.len() > limits::JUSTIFICATION_BYTES {
        return fail(Rule::InputTooLarge);
    }
    let it = scan_bounded_array(b, &[0, 4, 5], limits::RECEIPT_NODES, Rule::InputTooLarge)?;
    let k = array(tag_content(&it, tag::RECEIPT_BACKING)?, 5)?;
    version(&k[0], V2_VERSION)?;
    let d = super::util::arr(bytes_n(&k[1], 32)?);
    let n = uint_in(&k[2], 1, MAX_DEPOSIT)?;
    let r = super::util::arr(bytes_n(&k[3], 32)?);
    Ok(ReceiptBacking {
        d,
        n,
        r,
        proof: decode_deposit_proof_item(&k[4])?,
    })
}

/// A standalone DepositProof container (a seal receipt).
pub fn decode_deposit_proof(b: &[u8]) -> Result<DepositProof> {
    if b.len() > limits::JUSTIFICATION_BYTES {
        return fail(Rule::InputTooLarge);
    }
    if b.first().is_some_and(|head| head >> 5 != MAJ_ARRAY) {
        return fail(Rule::Shape);
    }
    decode_deposit_proof_item(&scan_bounded_array(
        b,
        &[5],
        limits::RECEIPT_NODES,
        Rule::InputTooLarge,
    )?)
}

fn decode_deposit_proof_item(it: &Item<'_>) -> Result<DepositProof> {
    let k = array(it, 6)?;
    version(&k[0], V2_VERSION)?;
    let blob = |x: &Item<'_>, max: usize| -> Result<Vec<u8>> {
        let v = bstr(x)?;
        if v.len() > max {
            return fail(Rule::InputTooLarge);
        }
        Ok(v.to_vec())
    };
    let uc = blob(&k[1], limits::UC_BYTES)?;
    let header = blob(&k[2], limits::HEADER_BYTES)?;
    let tx_index = uint_in(&k[3], 0, MAX_INDEX)?;
    let log_index = uint_in(&k[4], 0, MAX_INDEX)?;
    if k[5].major != MAJ_ARRAY {
        return fail(Rule::Shape);
    }
    let last = k[5].kids.len().wrapping_sub(1);
    let mut nodes = Vec::with_capacity(k[5].kids.len());
    for (i, x) in k[5].kids.iter().enumerate() {
        nodes.push(blob(
            x,
            if i == last {
                limits::RECEIPT_LEAF_NODE_BYTES
            } else {
                limits::RECEIPT_BRANCH_NODE_BYTES
            },
        )?);
    }
    Ok(DepositProof {
        uc,
        header,
        tx_index,
        log_index,
        nodes,
    })
}

/// A receipt log as the verifier authenticated it.
#[derive(Debug, Clone)]
pub struct ReceiptLog {
    pub address: Vec<u8>,
    pub topics: Vec<Vec<u8>>,
    pub data: Vec<u8>,
    pub header: Header,
}

/// A legacy receipt or type || RLP(...) with type 1..3 (`ReceiptType`), status 1 (`ReceiptStatus`); the logs list.
fn decode_receipt(v: &[u8]) -> Result<RlpItem<'_>> {
    if v.is_empty() {
        return fail(Rule::ReceiptType);
    }
    let mut body = v;
    if v[0] < 0xc0 {
        if v[0] < 1 || v[0] > 3 {
            return fail(Rule::ReceiptType);
        }
        body = &v[1..];
    }
    let it = match rlp_decode(body) {
        Ok(it) => it,
        Err(_) => return fail(Rule::ReceiptType),
    };
    if !it.list || it.kids.len() != 4 {
        return fail(Rule::ReceiptType);
    }
    let mut kids = it.kids.into_iter();
    let status = kids.next().expect("4");
    let gas = kids.next().expect("4");
    let bloom = kids.next().expect("4");
    let logs = kids.next().expect("4");
    if rlp_uint(&gas, 32).is_none()
        || status.list
        || bloom.list
        || bloom.str.len() != 256
        || !logs.list
    {
        return fail(Rule::ReceiptType);
    }
    if status.str.len() != 1 || status.str[0] != 1 {
        return fail(Rule::ReceiptStatus);
    }
    Ok(logs)
}

pub fn deposit_topic(token: Option<&[u8; 20]>) -> [u8; 32] {
    match token {
        Some(_) => topic::erc20_deposited(),
        None => topic::deposited(),
    }
}

pub fn deposit_topics(topics: &[Vec<u8>], token: Option<&[u8; 20]>) -> bool {
    match (token, topics) {
        (None, [topic, _]) => *topic == deposit_topic(None),
        (Some(token), [topic, _, address]) => {
            *topic == deposit_topic(Some(token))
                && address.len() == 32
                && address[..12] == [0; 12]
                && address[12..] == token[..]
        }
        _ => false,
    }
}

/// Section 6.2 steps 2 to 5 up to the emitter: the EVM UC (`DepositUC`), the header bound to its input record
/// (`DepositHeader`), the receipt path keyed by RLP(txIndex) (`ReceiptPath`), type and status, `logs[logIndex]` (`LogIndex`)
/// and its address (`LogEmitter`). The caller checks its event's topics and data.
pub fn verify_receipt_log(c: &Config, t: &TrustInput, p: &DepositProof) -> Result<ReceiptLog> {
    verify_receipt_log_at(c, t, p, &c.vault)
}

pub(crate) fn verify_receipt_log_at(
    c: &Config,
    t: &TrustInput,
    p: &DepositProof,
    emitter: &[u8; 20],
) -> Result<ReceiptLog> {
    let uc = verify_evm_uc(t, &p.uc, c)?;
    let header = bind_header(
        &p.header,
        uc.input_record.block_hash.as_deref(),
        uc.input_record.hash.as_deref(),
    )?;
    let value = deposit_receipt_value(p, &header)?;
    let l = deposit_receipt_log(p, &value)?;
    // the emitter before the topics (section 6.2 step 5)
    if l.kids[0].str != emitter {
        return fail(Rule::LogEmitter);
    }
    let mut topics = Vec::new();
    for tp in &l.kids[1].kids {
        if tp.list || tp.str.len() != 32 {
            return fail(Rule::LogTopics);
        }
        topics.push(tp.str.to_vec());
    }
    Ok(ReceiptLog {
        address: l.kids[0].str.to_vec(),
        topics,
        data: l.kids[2].str.to_vec(),
        header,
    })
}

fn deposit_receipt_value(p: &DepositProof, header: &Header) -> Result<Vec<u8>> {
    mpt_verify(&header.receipts_root, &rlp_index_key(p.tx_index), &p.nodes)
        .or_else(|_| fail(Rule::ReceiptPath))
}

fn deposit_receipt_log<'a>(p: &DepositProof, value: &'a [u8]) -> Result<RlpItem<'a>> {
    let logs = decode_receipt(value)?;
    if p.log_index >= logs.kids.len() as u64 {
        return fail(Rule::LogIndex);
    }
    let l = logs
        .kids
        .into_iter()
        .nth(p.log_index as usize)
        .expect("checked receipt log index");
    if !l.list
        || l.kids.len() != 3
        || l.kids[0].list
        || l.kids[0].str.len() != 20
        || !l.kids[1].list
        || l.kids[2].list
    {
        return fail(Rule::LogIndex);
    }
    Ok(l)
}

/// Identify a native record in a shared journal from its locally retained root mint receipt.
#[cfg(feature = "host")]
pub(crate) fn is_native_uct_deposit(p: &DepositProof, domain: &[u8]) -> Result<bool> {
    let value = deposit_receipt_value(p, &super::header::decode_header(&p.header)?)?;
    let log = deposit_receipt_log(p, &value)?;
    let topics = &log.kids[1].kids;
    Ok(topics.len() == 2
        && !topics[0].list
        && topics[0].str == topic::deposited()
        && !topics[1].list
        && topics[1].str.len() == 32
        && log.kids[2].str.get(..32) == Some(domain))
}

/// The 224-byte data of Deposited(n, D, v, rho, firstOwner).
pub fn deposited_data(d: &[u8], v: &BigUint, rho: &[u8], first_owner: &[u8]) -> Vec<u8> {
    let mut out = cat(&[
        d,
        &u256(v),
        rho,
        &u256_64(0x80),
        &u256_64(first_owner.len() as u64),
        first_owner,
    ]);
    let pad = (32 - out.len() % 32) % 32;
    out.resize(out.len() + pad, 0);
    out
}

/// What a verified deposit receipt authenticates.
#[derive(Debug, Clone)]
pub struct DepositEvidence {
    pub v: BigUint,
    pub first_owner: Vec<u8>,
    pub block_number: u64,
}

/// Section 6.2 steps 1 to 7 for a decoded J: the domain (`MintDomain`), the receipt log, its topics and data, the secret
/// opening. It returns the deposited amount and the first owner. The wallet runs it before minting; the verifier runs it inside
/// the root mint check.
pub fn verify_deposit_evidence(
    c: &Config,
    d: &[u8],
    t: &TrustInput,
    j: &ReceiptBacking,
) -> Result<DepositEvidence> {
    if j.d != d {
        return fail(Rule::MintDomain);
    }
    let log = verify_receipt_log(c, t, &j.proof)?;
    if !deposit_topics(&log.topics, c.erc20.as_ref().map(|e| &e.token))
        || log.topics[1] != u256_64(j.n)
    {
        return fail(Rule::LogTopics);
    }
    let data = &log.data;
    if data.len() != 224 {
        return fail(Rule::LogData);
    }
    let v = be_int(&data[32..64]);
    let owner = data[160..160 + FIRST_OWNER_BYTES].to_vec();
    if data[96..128] != u256_64(0x80)
        || data[128..160] != u256_64(FIRST_OWNER_BYTES as u64)
        || data[160 + FIRST_OWNER_BYTES..].iter().any(|&x| x != 0)
        || data[..32] != j.d
        || v.bits() == 0
    {
        return fail(Rule::LogData);
    }
    if rho_of(&j.d, &j.r) != data[64..96] {
        return fail(Rule::SecretOpening);
    }
    Ok(DepositEvidence {
        v,
        first_owner: owner,
        block_number: log.header.number_u64(),
    })
}

/// Section 6.2 for a root mint whose reason is J, in order: J and the deposited amount v.
pub fn verify_root_mint(
    c: &Config,
    d: &[u8],
    t: &TrustInput,
    m: &MintTx,
) -> Result<(ReceiptBacking, BigUint)> {
    let Some(just) = &m.justification else {
        return fail(Rule::MintReason);
    };
    let j = decode_receipt_backing(just)?;
    let ev = verify_deposit_evidence(c, d, t, &j)?;
    if m.salt != deposit_salt(d, j.n, &j.r) {
        return fail(Rule::MintSalt);
    }
    if m.ty != c.ty {
        return fail(Rule::MintType);
    }
    if encode_predicate(&m.recipient) != ev.first_owner {
        return fail(Rule::MintOwner);
    }
    match &m.data {
        Some(data) if *data == value_data(&c.aid, &ev.v) => {}
        _ => return fail(Rule::MintData),
    }
    Ok((j, ev.v))
}
