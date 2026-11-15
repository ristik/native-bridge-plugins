//! The token verifier relation (section 11.2; `verify.ts`): `verify_return(Γ, evidence)` under the trust-base history, in the
//! frozen order of bft-core `nb2ref/verify.go`, so a multi-fault input classifies the same way in every implementation:
//!
//!  1. Γ (`ConfigShape`).
//!  2. evidence = C(1, Token): the outer pair is `EvidenceShape`; the token and every nested item fail with the 14.1 rules.
//!  3. The walk from the returned part to the root (39044 split reasons; 39051 ends it; anything else `MintReason`).
//!  4. The root's J (section 6.2, in its order).
//!  5. Root first, every token of the walk: mint fields, `NoTransfers`, the mint and each transfer with its inclusion proof,
//!     the intermediate transfers, a parent's split burn, each child's allocation edge.
//!  6. The part's terminal burn.
//!  7. btid and eta.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use num_bigint::BigUint;

use super::cbor::*;
use super::config::{
    asset_uct, decode_config, domain, domain_of, tag, Config, Params, MAX_SEGMENT, V2_VERSION,
};
use super::crypto::{hu, minter_key, parse_key, verify_unlock};
use super::deposit::verify_root_mint;
use super::errors::{fail, fail_d, rule_err, wrap, Error, Result, Rule};
use super::split::{
    decode_split_justification, decode_split_manifest, split_output_commitment, verify_sum_proof,
    SplitJustification,
};
use super::token::*;
use super::trust::{bind_trust, decode_uc, in_shard, uc_check, TrustInput};
use super::util::{arr, cat, u256, u256_64};

/// The authenticated return tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub domain: [u8; 32],
    pub eta: [u8; 32],
    pub min_segment: u64,
    pub asset: [u8; 32],
    pub recipient: [u8; 20],
    pub amount: BigUint,
}

/// The verifier's exact 192-byte return data.
pub fn verdict_abi(v: &Verdict) -> Vec<u8> {
    cat(&[
        &v.domain,
        &v.eta,
        &u256_64(v.min_segment),
        &v.asset,
        &[0u8; 12],
        &v.recipient,
        &u256(&v.amount),
    ])
}

/// btid = H_U(C(b("UNICITY_NB2_BURN"), b(sidBurn), b(txHashBurn))).
pub fn burn_transition_id(sid: &[u8], tx_hash: &[u8]) -> [u8; 32] {
    hu(&[&c_arr(&[
        &c_bytes(domain::BURN.as_bytes()),
        &c_bytes(sid),
        &c_bytes(tx_hash),
    ])])
}

/// eta = H_U(C(b("UNICITY_NB2_REDEMPTION"), b(D), b(btid))).
pub fn redemption_id(d: &[u8], btid: &[u8]) -> [u8; 32] {
    hu(&[&c_arr(&[
        &c_bytes(domain::REDEMPTION.as_bytes()),
        &c_bytes(d),
        &c_bytes(btid),
    ])])
}

/// R = tag(39052, [1, b(D), b(asset32), b(recipient20), b(v), a]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnData {
    pub d: [u8; 32],
    pub asset: [u8; 32],
    pub recipient: [u8; 20],
    pub amount: BigUint,
    pub min_index: u64,
}

pub fn encode_return_data(r: &ReturnData) -> Vec<u8> {
    c_tag(
        tag::SEGMENT_RETURN,
        &c_arr_v(&[
            c_uint(V2_VERSION),
            c_bytes(&r.d),
            c_bytes(&r.asset),
            c_bytes(&r.recipient),
            c_amount(&r.amount),
            c_uint(r.min_index),
        ]),
    )
}

/// evidence = C(1, Token).
pub fn evidence_of(token: &[u8]) -> Vec<u8> {
    cat(&[&head(MAJ_ARRAY, 2), &c_uint(V2_VERSION), token])
}

/// The verifier: the verdict, or the rule that refuses the evidence.
pub fn verify_return(gamma: &[u8], evidence: &[u8], t: &TrustInput, p: &Params) -> Result<Verdict> {
    let c = decode_config(gamma, p)?;
    bind_trust(t, &c)?;
    let part = decode_evidence(evidence)?;
    verify_part(&c, &domain_of(gamma), t, &part)
}

pub fn decode_evidence(b: &[u8]) -> Result<Token> {
    let it = scan_native(b)?;
    if it.major != MAJ_ARRAY || it.kids.len() != 2 || it.kids[1].major != MAJ_TAG {
        return fail(Rule::EvidenceShape);
    }
    if !is_uint(&it.kids[0]) || it.kids[0].arg != V2_VERSION {
        return fail(Rule::EvidenceShape);
    }
    decode_token_item(&it.kids[1], b)
}

#[derive(Debug, Clone)]
struct Level {
    id: [u8; 32],
    amount: BigUint,
    manifest: Option<[u8; 32]>,
    last_sid: [u8; 32],
    last_tx: [u8; 32],
}

pub fn verify_part(c: &Config, d: &[u8; 32], t: &TrustInput, part: &Token) -> Result<Verdict> {
    let (lv, r) = walk(c, d, t, part, false)?;
    let r = r.expect("a return");
    let btid = burn_transition_id(&lv.last_sid, &lv.last_tx);
    Ok(Verdict {
        domain: *d,
        eta: redemption_id(d, &btid),
        min_segment: r.min_index,
        asset: r.asset,
        recipient: r.recipient,
        amount: lv.amount,
    })
}

/// A held (not burned) part: the same walk and every check of steps 3 to 5; its own transfers all go to signature owners with
/// null data.
#[derive(Debug, Clone)]
pub struct Held {
    pub token_id: [u8; 32],
    pub amount: BigUint,
    pub owner: Predicate,
}

pub fn verify_held(c: &Config, d: &[u8; 32], t: &TrustInput, part: &Token) -> Result<Held> {
    let (lv, _) = walk(c, d, t, part, true)?;
    let owner = part
        .transfers
        .last()
        .map_or_else(|| part.mint.recipient.clone(), |x| x.recipient.clone());
    Ok(Held {
        token_id: lv.id,
        amount: lv.amount,
        owner,
    })
}

fn walk(
    c: &Config,
    d: &[u8; 32],
    t: &TrustInput,
    part: &Token,
    held: bool,
) -> Result<(Level, Option<ReturnData>)> {
    // 3. The walk, part first.
    let mut chain: Vec<Token> = alloc::vec![part.clone()];
    let mut just: Vec<SplitJustification> = Vec::new();
    loop {
        let cur = chain.last().expect("nonempty");
        let tg = cur.mint.justification.as_deref().and_then(head_tag);
        if tg == Some(tag::RECEIPT_BACKING) {
            break;
        }
        if tg != Some(tag::SPLIT_JUSTIFICATION) {
            return fail(Rule::MintReason);
        }
        let sj = decode_split_justification(cur.mint.justification.as_deref().expect("tagged"))?;
        let parent = sj.parent.clone();
        just.push(sj);
        chain.push(parent);
    }
    // 4. The root's J.
    let top = chain.len() - 1;
    verify_root_mint(c, d, t, &chain[top].mint)?;
    // 5. Root first.
    let mut seen = BTreeSet::new();
    let mut parent: Option<Level> = None;
    let mut part_level: Option<Level> = None;
    for i in (0..=top).rev() {
        let mut lv = verify_level(c, t, &chain[i], &mut seen, held && i == 0)?;
        if i < top {
            check_split_edge(parent.as_ref().expect("parent"), &lv, &chain[i], &just[i])?;
        }
        if i > 0 {
            check_split_burn(&chain[i], &mut lv)?;
        }
        parent = Some(lv.clone());
        part_level = Some(lv);
    }
    let lv = part_level.expect("a level");
    // 6. The terminal return burn (7, the identifiers, is the caller's).
    let r = if held {
        None
    } else {
        Some(check_return(c, d, part, &lv)?)
    };
    Ok((lv, r))
}

fn parse_mint_data(c: &Config, data: Option<&[u8]>) -> Result<BigUint> {
    let Some(data) = data else {
        return fail(Rule::MintData);
    };
    let f = || -> Result<BigUint> {
        let it = scan_one(data)?;
        let v = array(tag_content(&it, tag::VALUE)?, 3)?;
        version(&v[0], VALUE_VERSION)?;
        if !v[2].is_null {
            return fail(Rule::MintData);
        }
        let assets = &v[1];
        if assets.major != MAJ_ARRAY || assets.kids.len() != 1 {
            return fail(Rule::MintData);
        }
        let pair = array(&assets.kids[0], 2)?;
        if bytes_n(&pair[0], 32)? != c.aid {
            return fail(Rule::MintData);
        }
        amount(&pair[1])
    };
    f().map_err(|_| rule_err(Rule::MintData))
}

fn verify_level(
    c: &Config,
    t: &TrustInput,
    tok: &Token,
    seen: &mut BTreeSet<[u8; 32]>,
    held: bool,
) -> Result<Level> {
    let m = &tok.mint;
    if m.network != c.network || m.recipient.ty != PRED_SIGNATURE {
        return fail(Rule::MintShape);
    }
    if m.ty != c.ty {
        return fail(Rule::MintType);
    }
    let amt = parse_mint_data(c, m.data.as_deref())?;
    if tok.transfers.is_empty() && !held {
        return fail(Rule::NoTransfers);
    }
    let id = token_id_of(&m.salt, m.network);
    let mut lv = Level {
        id,
        amount: amt,
        manifest: None,
        last_sid: [0; 32],
        last_tx: [0; 32],
    };
    let h0 = mint_source_hash(&id);
    check_step(
        c,
        t,
        &signature_predicate(&minter_key(&id)),
        &h0,
        &tok.mint_raw,
        m.deadline,
        &tok.mint_proof,
        seen,
    )?;
    let mut state = result_state(&h0, &id);
    let mut owner = m.recipient.clone();
    for (i, tr) in tok.transfers.iter().enumerate() {
        let (sid, tx_hash) = check_step(
            c,
            t,
            &owner,
            &state,
            &tok.transfers_raw[i],
            tr.deadline,
            &tok.proofs[i],
            seen,
        )?;
        lv.last_sid = sid;
        lv.last_tx = tx_hash;
        if i < tok.transfers.len() - 1 || held {
            if tr.recipient.ty != PRED_SIGNATURE {
                return fail(Rule::BurnNotFinal);
            }
            if tr.data.is_some() {
                return fail(Rule::TransferData);
            }
        }
        state = result_state(&state, &tr.mask);
        owner = tr.recipient.clone();
    }
    Ok(lv)
}

#[allow(clippy::too_many_arguments)]
fn check_step(
    c: &Config,
    t: &TrustInput,
    source: &Predicate,
    source_hash: &[u8],
    tx_raw: &[u8],
    e: Deadline,
    p: &InclusionProof,
    seen: &mut BTreeSet<[u8; 32]>,
) -> Result<([u8; 32], [u8; 32])> {
    let cd = &p.cd;
    let tx_hash = hu(&[tx_raw]);
    if encode_predicate(&cd.source) != encode_predicate(source)
        || cd.source_hash != source_hash
        || cd.tx_hash != tx_hash
    {
        return fail(Rule::CDMismatch);
    }
    if cd.deadline != e {
        return fail(Rule::DeadlineMismatch);
    }
    if source.ty != PRED_SIGNATURE {
        return fail(Rule::BurnNotFinal);
    }
    if parse_key(&source.params).is_err() {
        return fail(Rule::BurnNotFinal);
    }
    verify_unlock(&source.params, source_hash, &tx_hash, &cd.unlock)?;
    if let Some(e) = e {
        if p.t >= e {
            return fail(Rule::DeadlineExpired);
        }
    }
    let sid = state_id(source, source_hash);
    if !seen.insert(sid) {
        return fail(Rule::RepeatedSID);
    }
    verify_inclusion(c, t, &sid, &leaf_value(&tx_hash, p.t), p)?;
    Ok((sid, tx_hash))
}

/// One aggregator inclusion proof: the UC (its encoding, its epoch's entry, partition `aggregatorPartition` and its own shard,
/// the folds and the quorum), the shard owning the state ID, the RSMT membership of (sid, v) under the certified state root
/// (`InclusionProof`), and t <= IR.timestamp of that UC (`ReferenceTime`).
fn verify_inclusion(
    c: &Config,
    t: &TrustInput,
    sid: &[u8; 32],
    value: &[u8; 32],
    p: &InclusionProof,
) -> Result<()> {
    let uc = decode_uc(&p.uc)?;
    let shard = uc.shard_tree_certificate.shard.clone();
    uc_check(t, &uc, c.aggregator_partition, &shard.encode())?;
    if !in_shard(&shard, sid) {
        return fail_d(
            Rule::InclusionProof,
            "state ID outside the certificate's shard",
        );
    }
    match uc.input_record.hash.as_deref() {
        Some(root) if root.len() == 32 && rsmt_member(root, sid, value, &p.bitmap, &p.siblings) => {
        }
        _ => return fail(Rule::InclusionProof),
    }
    if p.t > uc.input_record.timestamp {
        return fail(Rule::ReferenceTime);
    }
    Ok(())
}

fn rsmt_leaf(key: &[u8], value: &[u8]) -> [u8; 32] {
    hu(&[&[0x00], key, value])
}

fn rsmt_node(l: &[u8], r: &[u8], depth: u8, region: &[u8]) -> [u8; 32] {
    hu(&[&[0x01, depth], region, l, r])
}

fn key_bit_at(key: &[u8], pos: usize) -> u8 {
    (key[pos >> 3] >> (7 - (pos & 7))) & 1
}

fn prefix_region(key: &[u8], depth: usize) -> [u8; 32] {
    let mut region = [0u8; 32];
    let full = depth >> 3;
    let partial = depth & 7;
    region[..full].copy_from_slice(&key[..full]);
    if partial != 0 {
        region[full] = key[full] & ((0xffu16 << (8 - partial)) & 0xff) as u8;
    }
    region
}

/// Fold (key, value) along the path (siblings root to leaf, bitmap bit d MSB-first) to `root`: the generic RSMT membership.
pub fn rsmt_member(
    root: &[u8],
    key: &[u8],
    value: &[u8],
    bitmap: &[u8],
    siblings: &[Vec<u8>],
) -> bool {
    if root.iter().all(|&x| x == 0) {
        return false;
    }
    let mut h = rsmt_leaf(key, value);
    let mut idx = siblings.len() as isize;
    for d in (0..=255usize).rev() {
        if bitmap[d >> 3] & (0x80 >> (d & 7)) == 0 {
            continue;
        }
        idx -= 1;
        if idx < 0 {
            return false;
        }
        let sib = &siblings[idx as usize];
        let region = prefix_region(key, d);
        h = if key_bit_at(key, d) == 1 {
            rsmt_node(sib, &h, d as u8, &region)
        } else {
            rsmt_node(&h, sib, d as u8, &region)
        };
    }
    idx == 0 && h.as_slice() == root
}

/// A parent's terminal transfer burns exactly its manifest; a return burn fails here, so a token cannot both split and return.
fn check_split_burn(tok: &Token, lv: &mut Level) -> Result<()> {
    let last = tok.transfers.last().expect("a split parent has transfers");
    let Some(data) = last
        .data
        .as_deref()
        .filter(|_| last.recipient.ty == PRED_BURN)
    else {
        return fail(Rule::SplitBurn);
    };
    let root = decode_split_manifest(data)?;
    let manifest = c_tag(tag::SPLIT_MANIFEST, &c_arr(&[&c_bytes(&root)]));
    if last.recipient.params != hu(&[&manifest]) {
        return fail(Rule::SplitBurn);
    }
    lv.manifest = Some(root);
    Ok(())
}

fn check_split_edge(
    parent: &Level,
    child: &Level,
    tok: &Token,
    sj: &SplitJustification,
) -> Result<()> {
    let data = split_output_commitment(&parent.id, &tok.mint);
    let manifest = parent.manifest.expect("a parent's manifest");
    let Some(sum) = verify_sum_proof(&sj.proof, &child.id, &data, &child.amount, &manifest) else {
        return fail(Rule::SplitProof);
    };
    if sum != parent.amount {
        return fail(Rule::SplitSum);
    }
    Ok(())
}

fn check_return(c: &Config, d: &[u8; 32], part: &Token, lv: &Level) -> Result<ReturnData> {
    let last = part.transfers.last().expect("NoTransfers checked");
    if last.recipient.ty != PRED_BURN {
        return fail(Rule::NotBurn);
    }
    let r = decode_return_data(last.data.as_deref())?;
    if r.min_index > MAX_SEGMENT {
        return fail(Rule::ReturnIndex);
    }
    if r.d != *d {
        return fail(Rule::ReturnDomain);
    }
    if r.asset != asset_uct() {
        return fail(Rule::ReturnAsset);
    }
    if r.amount != lv.amount {
        return fail(Rule::ReturnAmount);
    }
    if r.recipient.iter().all(|&x| x == 0) || r.recipient == c.vault {
        return fail(Rule::ReturnRecipient);
    }
    if last.recipient.params != hu(&[last.data.as_deref().expect("decoded")]) {
        return fail(Rule::BurnReason);
    }
    Ok(r)
}

/// Strictly decode R; any failure to be exactly a tag(39052, ...) R is `ReturnData`.
pub fn decode_return_data(b: Option<&[u8]>) -> Result<ReturnData> {
    let Some(b) = b else {
        return fail(Rule::ReturnData);
    };
    let root = scan_one(b).map_err(|e| wrap(Rule::ReturnData, e))?;
    let k = (|| -> Result<&[Item<'_>]> {
        let k = array(tag_content(&root, tag::SEGMENT_RETURN)?, 6)?;
        version(&k[0], V2_VERSION)?;
        Ok(k)
    })()
    .map_err(|_| rule_err(Rule::ReturnData))?;
    let f = || -> Result<ReturnData> {
        let d = arr(bytes_n(&k[1], 32)?);
        let asset = arr(bytes_n(&k[2], 32)?);
        let recipient = arr(bytes_n(&k[3], 20)?);
        if !is_uint(&k[5]) {
            return fail(Rule::ReturnData);
        }
        let amount = amount(&k[4])?;
        Ok(ReturnData {
            d,
            asset,
            recipient,
            amount,
            min_index: k[5].arg,
        })
    };
    f().map_err(|e| match e {
        Error::Rule(n) if n.rule == Rule::ReturnData => Error::Rule(n),
        _ => rule_err(Rule::ReturnData),
    })
}
