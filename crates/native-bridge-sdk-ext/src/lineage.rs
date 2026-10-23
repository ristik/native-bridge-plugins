//! The lineage relation (protocol 6, bft-core `docs/design/bridge-split-lineage-spec.md` section 3, Go `bridgeprofile/lineage.go`):
//! a redeemed part is a token whose mint justification is either the lock reason (the root) or a split reason carrying the burned
//! parent token. Verification starts at the root and descends: every token's complete history is checked as in the protocol 5
//! relation, a parent ends in a split burn that commits a manifest, and every child is an allocation of that manifest. Depth 0 is an
//! ordinary full redemption.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use num_bigint::BigUint;

use crate::deployment::Deployment;
use crate::error::{NativeError as E, Result};
use crate::history::{
    check_justification, check_mint_data, check_return, check_step, mint_source_hash, minter_key,
    result_state, History, Leaf, Outcome, Pred, Transfer,
};
use crate::limits::{
    HistoryBounds, COMPOSED_HISTORY, PRED_BURN, PRED_SIGNATURE, TAG_MINT_LOCK,
    TAG_SPLIT_JUSTIFICATION,
};
use crate::profile::{
    burn_id, derive_salt, derive_token_id, h, lock_digest, lock_record, nullifier,
};
use crate::sdktoken::decode_token;
use crate::split::{
    decode_split_justification, decode_split_manifest, justification_tag, split_manifest_bytes,
    split_output_commitment, verify_sum_proof, SplitJustification,
};
use crate::unlock::parse_key;

// Work charges of the lineage walk (trial values, spec section 6), each taken before the work it pays for.
/// Scanning and hashing one nested byte: the outer mint and every justification descended into.
pub const SPLIT_PER_BYTE: u64 = 16;
/// One allocation proof: the commitment and the leaf hash, then each node hash.
pub const SPLIT_EDGE_BASE: u64 = 20_000;
pub const SPLIT_PER_STEP: u64 = 1_500;
/// The composition's per-item price, charged for every justification descended into (gas.rs `COMPOSE_PER_ITEM`).
const PER_ITEM: u64 = 20;

/// One token of a verified lineage, root first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelInfo {
    pub token_id: [u8; 32],
    pub amount: Vec<u8>,
    /// certified leaves the token contributes: its mint and every transfer
    pub leaves: usize,
}

/// A verified redemption: the root's identity (words 3 to 8 of BRIDGE_COMPOSE_V2) in `outcome`, the part's return (`release_to`,
/// `nullifier`), every leaf in root-to-part order, the part and the depth. `split_gas` is the walk's byte, item and edge charge
/// beyond the protocol 5 schedule; the ancestors' leaves are in that schedule's `L` (one leaf proof per leaf of the whole lineage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageOutcome {
    pub outcome: Outcome,
    pub part_token_id: [u8; 32],
    pub part_amount: Vec<u8>,
    pub depth: usize,
    pub levels: Vec<LevelInfo>,
    pub split_gas: u64,
}

struct LevelState {
    id: [u8; 32],
    amount: Vec<u8>,
    nonce: u64,
    leaves: Vec<Leaf>,
    manifest_root: Option<[u8; 32]>,
}

/// The return operation: `history` is the redeemed part's projection; its ancestry is read from the exact bytes of its mint reason.
pub fn verify_lineage_return(dep: &Deployment, history: &[u8]) -> Result<LineageOutcome> {
    verify_lineage_return_within(dep, history, COMPOSED_HISTORY)
}

/// [`verify_lineage_return`] under explicit history bounds.
pub fn verify_lineage_return_within(
    dep: &Deployment,
    history: &[u8],
    lim: HistoryBounds,
) -> Result<LineageOutcome> {
    let h = History::decode_within(history, lim)?;
    if h.transfers.is_empty() {
        return Err(E::NoTransfers);
    }
    verify_lineage(dep, h)
}

/// The walk (part first), then the verification (root first).
pub fn verify_lineage(dep: &Deployment, part: History) -> Result<LineageOutcome> {
    let mut split_gas = SPLIT_PER_BYTE * part.mint_raw.len() as u64;
    let mut chain: Vec<History> = Vec::new();
    let mut just: Vec<SplitJustification> = Vec::new(); // just[i] is chain[i]'s reason; chain[i+1] is its burned token
    let mut cur = part;
    loop {
        let tag = justification_tag(cur.mint.justification.as_deref()).ok_or(E::MintJustif)?;
        if tag == TAG_MINT_LOCK {
            chain.push(cur);
            break;
        }
        if tag != TAG_SPLIT_JUSTIFICATION {
            return Err(E::MintJustif);
        }
        let j = cur.mint.justification.as_deref().unwrap_or_default();
        split_gas += SPLIT_PER_BYTE * j.len() as u64;
        let sj = decode_split_justification(j)?;
        split_gas += PER_ITEM * sj.items as u64;
        let parent = decode_token(&sj.token)?.project();
        just.push(sj);
        chain.push(cur);
        cur = parent;
    }

    let d = chain.len() - 1;
    let ch = dep.cfg_hash;
    let mut seen = BTreeSet::new();
    let mut out = LineageOutcome {
        outcome: Outcome {
            cfg: ch,
            nonce: 0,
            amount: Vec::new(),
            token_id: [0; 32],
            salt: [0; 32],
            first_predicate_hash: [0; 32],
            lock_digest: [0; 32],
            release_to: [0; 20],
            nullifier: [0; 32],
            leaves: Vec::new(),
        },
        part_token_id: [0; 32],
        part_amount: Vec::new(),
        depth: d,
        levels: Vec::new(),
        split_gas: 0,
    };
    let mut parent: Option<LevelState> = None;
    for i in (0..=d).rev() {
        let hist = &chain[i];
        let mut lv = verify_level(dep, hist, i == d, &mut seen)?;
        if i < d {
            split_gas +=
                check_split_edge(parent.as_ref().ok_or(E::MintJustif)?, &lv, hist, &just[i])?;
        }
        out.outcome.leaves.extend(lv.leaves.iter().cloned());
        out.levels.push(LevelInfo {
            token_id: lv.id,
            amount: lv.amount.clone(),
            leaves: lv.leaves.len(),
        });
        let last = lv.leaves.last().ok_or(E::NoTransfers)?.clone();
        let last_t = hist.transfers.last().ok_or(E::NoTransfers)?;
        if i == 0 {
            let mut rr = out.outcome.clone();
            rr.amount = lv.amount.clone();
            check_return(&dep.cfg, &mut rr, last_t)?;
            out.outcome.release_to = rr.release_to;
            out.outcome.nullifier = nullifier(&ch, &burn_id(&last.sid, &last.tx_hash));
            if out.outcome.nullifier == [0u8; 32] {
                return Err(E::ZeroDigest);
            }
            out.part_token_id = lv.id;
            out.part_amount = lv.amount.clone();
        } else {
            check_split_burn(last_t, &mut lv)?;
        }
        if i == d {
            let m = &hist.mint;
            let o = &mut out.outcome;
            o.nonce = lv.nonce;
            o.salt = m.salt;
            o.token_id = lv.id;
            o.amount = lv.amount.clone();
            o.first_predicate_hash = h(&m.recipient.to_bytes());
            o.lock_digest = lock_digest(
                &ch,
                lv.nonce,
                &lock_record(
                    &dep.cfg.zero_address,
                    &dep.cfg.ty,
                    &dep.cfg.aid,
                    &lv.amount,
                    &lv.id,
                    &o.first_predicate_hash,
                ),
            );
            if o.lock_digest == [0u8; 32] {
                return Err(E::ZeroDigest);
            }
        }
        parent = Some(lv);
    }
    out.split_gas = split_gas;
    Ok(out)
}

/// One token's mint and complete transfer history as in the protocol 5 relation, except the terminal transfer, which the caller
/// classifies. A root's mint reason is the lock reason with the derived salt; a child's is the split reason, checked against its
/// parent by [`check_split_edge`], and its salt is free (its ID derives from it).
fn verify_level(
    dep: &Deployment,
    h: &History,
    root: bool,
    seen: &mut BTreeSet<[u8; 32]>,
) -> Result<LevelState> {
    let cfg = &dep.cfg;
    let m = &h.mint;
    if m.network != cfg.network || m.recipient.typ != PRED_SIGNATURE {
        return Err(E::MintShape);
    }
    if m.ty != cfg.ty {
        return Err(E::MintType);
    }
    let mut nonce = 0;
    if root {
        nonce = check_justification(dep, m.justification.as_deref())?;
        if m.salt != derive_salt(&dep.cfg_hash, nonce) {
            return Err(E::MintSalt);
        }
    }
    let id = derive_token_id(&m.salt, cfg.network);
    let amount = check_mint_data(dep, m.data.as_deref())?;
    if h.transfers.is_empty() {
        return Err(E::NoTransfers);
    }
    let mk = minter_key(&id)?;
    let mk_pub = mk.verifying_key();
    let minter = Pred::signature(mk_pub.to_encoded_point(true).as_bytes());
    let h0 = mint_source_hash(&id);
    let mut leaves = Vec::with_capacity(1 + h.transfers.len());
    leaves.push(check_step(
        &minter,
        &h0,
        &h.mint_raw,
        m.expires_at,
        &h.mint_cd,
        h.mint_t,
        mk_pub,
        seen,
    )?);
    let mut state = result_state(&h0, &id);
    let mut owner = m.recipient.clone();
    for (i, t) in h.transfers.iter().enumerate() {
        // the owner is a signature predicate: the mint recipient or the previous intermediate recipient
        let key = parse_key(&owner.params)?;
        leaves.push(check_step(
            &owner,
            &state,
            &h.transfers_raw[i],
            t.expires_at,
            &h.cds[i],
            h.times[i],
            &key,
            seen,
        )?);
        if i < h.transfers.len() - 1 {
            if t.recipient.typ != PRED_SIGNATURE {
                return Err(E::BurnNotFinal);
            }
            if t.data.is_some() {
                return Err(E::TransferData);
            }
        }
        state = result_state(&state, &t.mask);
        owner = t.recipient.clone();
    }
    Ok(LevelState {
        id,
        amount,
        nonce,
        leaves,
        manifest_root: None,
    })
}

/// A parent's final transfer burns exactly its manifest: `Burn(SHA-256(b_M))` with `b_M` the transfer's data. A return burn fails
/// here (its data is a return reason), so a token cannot be both returned and split.
fn check_split_burn(t: &Transfer, lv: &mut LevelState) -> Result<()> {
    let data = match (&t.data, t.recipient.typ) {
        (Some(d), PRED_BURN) => d,
        _ => return Err(E::SplitBurn),
    };
    let root = decode_split_manifest(data)?;
    let bytes = split_manifest_bytes(&root);
    if t.recipient.params != h(&bytes) || bytes != *data {
        return Err(E::SplitBurn);
    }
    lv.manifest_root = Some(root);
    Ok(())
}

/// One edge: the child's allocation proof against the parent's manifest root with the child's recomputed commitment, and the
/// reconstructed root sum equal to the parent's authenticated amount (value conservation). Network and type equality follow from both
/// mints being checked against the configuration. Returns the edge's charge.
fn check_split_edge(
    parent: &LevelState,
    child: &LevelState,
    h: &History,
    sj: &SplitJustification,
) -> Result<u64> {
    let m = &h.mint;
    let data = m.data.as_deref().ok_or(E::MintData)?;
    let d = split_output_commitment(
        &parent.id,
        m.network,
        &m.recipient.to_bytes(),
        &m.salt,
        &child.id,
        &m.ty,
        data,
    );
    let root = parent.manifest_root.ok_or(E::SplitBurn)?;
    let sum = verify_sum_proof(
        &sj.proof,
        &child.id,
        &d,
        &BigUint::from_bytes_be(&child.amount),
        &root,
    )
    .ok_or(E::SplitProof)?;
    if sum != BigUint::from_bytes_be(&parent.amount) {
        return Err(E::SplitSum);
    }
    Ok(SPLIT_EDGE_BASE + SPLIT_PER_STEP * sj.proof.len() as u64)
}
