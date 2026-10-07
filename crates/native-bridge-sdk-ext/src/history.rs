//! The compact history projection `C([M,CD0,t0],[[T1,CD1,t1],...])` and the pure token-semantics
//! relation for SDK 3.0.1 bytes.
//!
//! The relation reconstructs every source state and owner, checks byte equality with each
//! certification data item including the request deadline, recomputes the transaction hash, state id
//! and certified leaf value, validates each unlock by recovery equality and exports every leaf
//! obligation. It does not check inclusion paths, the embedded lock proof's cryptography or
//! aggregator admission: those need the pinned trust bundle and belong to the wrappers.
//!
//! Projection tuples are *not* SDK certified-transaction tuples; the SDK's certified transaction
//! has exactly two elements and carries `t` inside its inclusion proof.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use k256::ecdsa::{SigningKey, VerifyingKey};
use num_bigint::BigUint;
use unicity_token::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint};

use crate::deployment::Deployment;
use crate::error::{NativeError as E, Result};
use crate::limits::*;
use crate::lockproof::{encode_justification, parse_justification};
use crate::profile::*;
use crate::scan::{fixed, scan_one, Item, Kind};
use crate::unlock::{parse_key, verify_unlock};

/// An admitted predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pred {
    pub typ: u8,
    pub params: Vec<u8>,
}

impl Pred {
    /// `tag(39032,[1,b(encode_uint(type)),b(params)])`.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_tag(
            TAG_PREDICATE,
            &encode_array(&[
                &encode_uint(1),
                &encode_byte_string(&encode_uint(self.typ as u64)),
                &encode_byte_string(&self.params),
            ]),
        )
    }
    pub fn signature(key33: &[u8]) -> Pred {
        Pred {
            typ: PRED_SIGNATURE,
            params: key33.to_vec(),
        }
    }
    pub fn burn(reason_hash: &[u8; 32]) -> Pred {
        Pred {
            typ: PRED_BURN,
            params: reason_hash.to_vec(),
        }
    }
}

fn decode_predicate(it: &Item<'_>) -> Result<Pred> {
    let c = it.tag_content(TAG_PREDICATE)?;
    let k = c.array(3).ok_or(E::Shape)?;
    match k[0].kind {
        Kind::Uint(1) => {}
        Kind::Uint(_) => return Err(E::Predicate),
        _ => return Err(E::Shape),
    }
    let (code, params) = match (&k[1].kind, &k[2].kind) {
        (Kind::Bytes(c), Kind::Bytes(p)) => (*c, *p),
        _ => return Err(E::Shape),
    };
    if code.len() != 1 || (code[0] != PRED_SIGNATURE && code[0] != PRED_BURN) {
        return Err(E::Predicate);
    }
    if code[0] == PRED_SIGNATURE {
        parse_key(params)?;
    } else if params.len() != 32 {
        return Err(E::Predicate);
    }
    Ok(Pred {
        typ: code[0],
        params: params.to_vec(),
    })
}

/// A request deadline: null or an integer in `[1, 2^64-1]`.
fn deadline(it: &Item<'_>) -> Result<Option<u64>> {
    match it.nullable_uint()? {
        Some(0) => Err(E::IntRange),
        e => Ok(e),
    }
}

/// Decoded mint transaction (`tag(39041,[2,network,P0,b(salt),b(ty),b(J),b(data),e])`).
#[derive(Debug, Clone)]
pub struct Mint {
    pub network: u16,
    pub recipient: Pred,
    pub salt: [u8; 32],
    pub ty: [u8; 32],
    pub justification: Option<Vec<u8>>,
    pub data: Option<Vec<u8>>,
    pub expires_at: Option<u64>,
}

/// Decoded transfer transaction (`tag(39045,[2,Pnext,b(mask),dataOrNull,e])`).
#[derive(Debug, Clone)]
pub struct Transfer {
    pub recipient: Pred,
    pub mask: [u8; 32],
    pub data: Option<Vec<u8>>,
    pub expires_at: Option<u64>,
}

/// Decoded certification data (`tag(39031,[2,Psource,b(sourceHash),b(txHash),e,b(unlock65)])`).
#[derive(Debug, Clone)]
pub struct Cd {
    pub source: Pred,
    pub source_hash: [u8; 32],
    pub tx_hash: [u8; 32],
    pub expires_at: Option<u64>,
    pub unlock: Vec<u8>,
}

fn decode_cd(it: &Item<'_>) -> Result<Cd> {
    let c = it.tag_content(TAG_CERTIFICATION)?;
    let k = c.array(6).ok_or(E::Shape)?;
    k[0].version(2)?;
    Ok(Cd {
        source: decode_predicate(&k[1])?,
        source_hash: fixed(&k[2])?,
        tx_hash: fixed(&k[3])?,
        expires_at: deadline(&k[4])?,
        unlock: k[5].bytes().map_err(|_| E::Shape)?.to_vec(),
    })
}

fn decode_mint(it: &Item<'_>) -> Result<Mint> {
    let c = it.tag_content(TAG_MINT)?;
    let k = c.array(8).ok_or(E::Shape)?;
    k[0].version(2)?;
    Ok(Mint {
        network: k[1].uint_max(0xffff)? as u16,
        recipient: decode_predicate(&k[2])?,
        salt: fixed(&k[3])?,
        ty: fixed(&k[4])?,
        justification: k[5].nullable_bytes()?.map(<[u8]>::to_vec),
        data: k[6].nullable_bytes()?.map(<[u8]>::to_vec),
        expires_at: deadline(&k[7])?,
    })
}

fn decode_transfer(it: &Item<'_>) -> Result<Transfer> {
    let c = it.tag_content(TAG_TRANSFER)?;
    let k = c.array(5).ok_or(E::Shape)?;
    k[0].version(2)?;
    Ok(Transfer {
        recipient: decode_predicate(&k[1])?,
        mask: fixed(&k[2])?,
        data: k[3].nullable_bytes()?.map(<[u8]>::to_vec),
        expires_at: deadline(&k[4])?,
    })
}

/// A decoded history with the raw transaction encodings its hashes cover.
#[derive(Debug, Clone)]
pub struct History {
    pub mint: Mint,
    pub mint_cd: Cd,
    pub mint_t: u64,
    pub transfers: Vec<Transfer>,
    pub cds: Vec<Cd>,
    pub times: Vec<u64>,
    mint_raw: Vec<u8>,
    transfers_raw: Vec<Vec<u8>>,
}

impl History {
    /// Strictly decode a history; the transfer count is bounded before any transfer is decoded.
    pub fn decode(b: &[u8]) -> Result<History> {
        if b.len() > MAX_SEMANTIC_BYTES {
            return Err(E::InputTooLarge);
        }
        let root = scan_one(b)?;
        let k = root.array(2).ok_or(E::Shape)?;
        let head = k[0].array(3).ok_or(E::Shape)?;
        let list = k[1].any_array().ok_or(E::Shape)?;
        if list.len() > MAX_TRANSFERS {
            return Err(E::TooManyTx);
        }
        let mint = decode_mint(&head[0])?;
        let mint_raw = head[0].raw(b).to_vec();
        let mint_cd = decode_cd(&head[1])?;
        let mint_t = head[2].uint().map_err(|_| E::Shape)?;
        let (mut transfers, mut cds, mut times, mut transfers_raw) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for p in list {
            let tuple = p.array(3).ok_or(E::Shape)?;
            transfers.push(decode_transfer(&tuple[0])?);
            cds.push(decode_cd(&tuple[1])?);
            times.push(tuple[2].uint().map_err(|_| E::Shape)?);
            transfers_raw.push(tuple[0].raw(b).to_vec());
        }
        Ok(History {
            mint,
            mint_cd,
            mint_t,
            transfers,
            cds,
            times,
            mint_raw,
            transfers_raw,
        })
    }

    /// The raw mint encoding (its hash is the certified transaction hash).
    pub fn mint_raw(&self) -> &[u8] {
        &self.mint_raw
    }
}

/// One certified-leaf obligation `(sid, txHash, t, v)` plus the request deadline it was checked
/// against, in transaction order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub sid: [u8; 32],
    pub tx_hash: [u8; 32],
    pub reference_time: u64,
    pub value: [u8; 32],
    pub expires_at: Option<u64>,
}

/// A kernel result: `(cfg, nonce, amount, tokenId, salt, firstPredicateHash, lockDigest, releaseTo,
/// nullifier, Leaf[])`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub cfg: [u8; 32],
    pub nonce: u64,
    pub amount: Vec<u8>,
    pub token_id: [u8; 32],
    pub salt: [u8; 32],
    pub first_predicate_hash: [u8; 32],
    pub lock_digest: [u8; 32],
    pub release_to: [u8; 20],
    pub nullifier: [u8; 32],
    pub leaves: Vec<Leaf>,
}

/// `sid = H(C(P_source, b(sourceHash)))`.
pub fn state_id(source: &Pred, source_hash: &[u8; 32]) -> [u8; 32] {
    h(&encode_array(&[
        &source.to_bytes(),
        &encode_byte_string(source_hash),
    ]))
}

/// The state after a transition: `H(C(b(0000||sourceHash), b(mask)))`.
pub fn result_state(source_hash: &[u8; 32], mask: &[u8]) -> [u8; 32] {
    let mut imprint = [0u8; 34];
    imprint[2..].copy_from_slice(source_hash);
    h(&encode_array(&[
        &encode_byte_string(&imprint),
        &encode_byte_string(mask),
    ]))
}

/// The mint's source state hash for a token id.
pub fn mint_source_hash(id: &[u8; 32]) -> [u8; 32] {
    h(&encode_array(&[
        &encode_byte_string(id),
        &encode_byte_string(&h(b"TOKENID")),
    ]))
}

fn minter_key(id: &[u8; 32]) -> Result<SigningKey> {
    let k = h(&encode_array(&[
        &encode_byte_string(b"I_AM_UNIVERSAL_MINTER_FOR_"),
        &encode_byte_string(id),
    ]));
    SigningKey::from_slice(&k).map_err(|_| E::MinterKey)
}

fn amount_ok(a: &[u8]) -> bool {
    !a.is_empty() && a.len() <= MAX_AMOUNT_BYTES && a[0] != 0
}

/// `prepareLock`: validate a lock request and derive the values the vault compares with its own.
pub fn prepare_lock(cfg: &Cfg, n: u64, amount: &[u8], p0: &[u8]) -> Result<Outcome> {
    if n == 0 || !amount_ok(amount) {
        return Err(E::LockInput);
    }
    if p0.len() > MAX_SEMANTIC_BYTES {
        return Err(E::InputTooLarge);
    }
    let pred = decode_predicate(&scan_one(p0)?)?;
    if pred.typ != PRED_SIGNATURE || pred.to_bytes() != p0 {
        return Err(E::Predicate);
    }
    let ch = cfg.hash();
    let salt = derive_salt(&ch, n);
    let id = derive_token_id(&salt, cfg.network);
    let first = h(p0);
    let digest = lock_digest(
        &ch,
        n,
        &lock_record(&cfg.zero_address, &cfg.ty, &cfg.aid, amount, &id, &first),
    );
    if digest == [0u8; 32] {
        return Err(E::ZeroDigest);
    }
    Ok(Outcome {
        cfg: ch,
        nonce: n,
        amount: amount.to_vec(),
        token_id: id,
        salt,
        first_predicate_hash: first,
        lock_digest: digest,
        release_to: [0; 20],
        nullifier: [0; 32],
        leaves: Vec::new(),
    })
}

/// The mint operation: the history must hold zero transfers.
pub fn verify_mint(dep: &Deployment, history: &[u8]) -> Result<Outcome> {
    let h = History::decode(history)?;
    if !h.transfers.is_empty() {
        return Err(E::HasTransfers);
    }
    verify_history(dep, &h)
}

/// The return operation: the terminal burn is required.
pub fn verify_return(dep: &Deployment, history: &[u8]) -> Result<Outcome> {
    let h = History::decode(history)?;
    if h.transfers.is_empty() {
        return Err(E::NoTransfers);
    }
    verify_history(dep, &h)
}

/// The receipt relation: genesis plus zero or more signature transfers, no burn.
pub fn verify_receipt(dep: &Deployment, history: &[u8]) -> Result<Outcome> {
    verify_history_mode(dep, &History::decode(history)?, Mode::Receipt)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Zero or more signature transfers; a burn is never accepted.
    Receipt,
    /// A terminal burn is required.
    Return,
}

/// Parse and cross-check the mint justification, returning the nonce. The lock proof's bytes are
/// bounded and structurally parsed here; its cryptography needs the trust bundle.
pub fn check_justification(dep: &Deployment, j: Option<&[u8]>) -> Result<u64> {
    let j = j.ok_or(E::MintJustif)?;
    let parsed = parse_justification(j).map_err(|e| match e {
        E::InputTooLarge | E::ProofTooLarge | E::TooDeep | E::TooManyItems => e,
        _ => E::MintJustif,
    })?;
    if parsed.chain_id != dep.cfg.chain_id
        || parsed.vault != dep.cfg.vault
        || parsed.zero != dep.cfg.zero_address
        || parsed.nonce == 0
    {
        return Err(E::MintJustif);
    }
    if encode_justification(
        parsed.chain_id,
        &parsed.vault,
        &parsed.zero,
        parsed.nonce,
        &parsed.proof.to_bytes(),
    ) != j
    {
        return Err(E::MintJustif);
    }
    Ok(parsed.nonce)
}

/// Exactly `tag(39050,[1,[[b(aid),b(amount)]],null])`; one entry, no memo.
pub fn check_mint_data(dep: &Deployment, d: Option<&[u8]>) -> Result<Vec<u8>> {
    let d = d.ok_or(E::MintData)?;
    let root = scan_one(d).map_err(|_| E::MintData)?;
    let c = root
        .tag_content(TAG_WALLET_VALUE)
        .map_err(|_| E::MintData)?;
    let k = c.array(3).ok_or(E::MintData)?;
    k[0].version(1).map_err(|_| E::MintData)?;
    let assets = k[1].array(1).ok_or(E::MintData)?;
    let entry = assets[0].array(2).ok_or(E::MintData)?;
    let aid: [u8; 32] = fixed(&entry[0]).map_err(|_| E::MintData)?;
    if aid != dep.cfg.aid || !k[2].is_null() {
        return Err(E::MintData);
    }
    let amount = entry[1].amount().map_err(|_| E::MintData)?.to_vec();
    if value_envelope(&aid, &amount) != d {
        return Err(E::MintData);
    }
    Ok(amount)
}

#[allow(clippy::too_many_arguments)]
fn check_step(
    source: &Pred,
    source_hash: &[u8; 32],
    tx_raw: &[u8],
    tx_deadline: Option<u64>,
    cd: &Cd,
    t: u64,
    key: &VerifyingKey,
    seen: &mut BTreeSet<[u8; 32]>,
) -> Result<Leaf> {
    if cd.source.to_bytes() != source.to_bytes() || cd.source_hash != *source_hash {
        return Err(E::CDMismatch);
    }
    let tx_hash = h(tx_raw);
    if cd.tx_hash != tx_hash || cd.expires_at != tx_deadline {
        return Err(E::CDMismatch);
    }
    // For an explicit deadline the leaf must have been created strictly before it.
    if let Some(e) = tx_deadline {
        if t >= e {
            return Err(E::DeadlineExpired);
        }
    }
    verify_unlock(key, source_hash, &tx_hash, &cd.unlock)?;
    let sid = state_id(source, source_hash);
    if !seen.insert(sid) {
        return Err(E::RepeatedSID);
    }
    Ok(Leaf {
        sid,
        tx_hash,
        reference_time: t,
        value: leaf_value(&tx_hash, t),
        expires_at: tx_deadline,
    })
}

/// The return relation over a decoded history (a terminal burn is required).
pub fn verify_history(dep: &Deployment, hist: &History) -> Result<Outcome> {
    verify_history_mode(
        dep,
        hist,
        if hist.transfers.is_empty() {
            Mode::Receipt
        } else {
            Mode::Return
        },
    )
}

/// Public entry for the full-history wrapper: `want_burn` selects the return or receipt relation.
pub fn verify_history_as(dep: &Deployment, hist: &History, want_burn: bool) -> Result<Outcome> {
    let mode = if want_burn {
        Mode::Return
    } else {
        Mode::Receipt
    };
    if want_burn && hist.transfers.is_empty() {
        return Err(E::NoTransfers);
    }
    verify_history_mode(dep, hist, mode)
}

fn verify_history_mode(dep: &Deployment, hist: &History, mode: Mode) -> Result<Outcome> {
    let cfg = &dep.cfg;
    let ch = dep.cfg_hash;
    let m = &hist.mint;
    if m.network != cfg.network || m.recipient.typ != PRED_SIGNATURE {
        return Err(E::MintShape);
    }
    if m.ty != cfg.ty {
        return Err(E::MintType);
    }
    let n = check_justification(dep, m.justification.as_deref())?;
    let salt = derive_salt(&ch, n);
    if m.salt != salt {
        return Err(E::MintSalt);
    }
    let id = derive_token_id(&salt, cfg.network);
    let amount = check_mint_data(dep, m.data.as_deref())?;
    let first = h(&m.recipient.to_bytes());
    let digest = lock_digest(
        &ch,
        n,
        &lock_record(&cfg.zero_address, &cfg.ty, &cfg.aid, &amount, &id, &first),
    );
    if digest == [0u8; 32] {
        return Err(E::ZeroDigest);
    }
    let mut out = Outcome {
        cfg: ch,
        nonce: n,
        amount,
        token_id: id,
        salt,
        first_predicate_hash: first,
        lock_digest: digest,
        release_to: [0; 20],
        nullifier: [0; 32],
        leaves: Vec::new(),
    };

    let mk = minter_key(&id)?;
    let mk_pub = mk.verifying_key();
    let minter_pred = Pred::signature(mk_pub.to_encoded_point(true).as_bytes());
    let h0 = mint_source_hash(&id);
    let mut seen = BTreeSet::new();
    out.leaves.push(check_step(
        &minter_pred,
        &h0,
        &hist.mint_raw,
        m.expires_at,
        &hist.mint_cd,
        hist.mint_t,
        mk_pub,
        &mut seen,
    )?);
    let mut state = result_state(&h0, &id);
    let mut owner = m.recipient.clone();

    for (i, t) in hist.transfers.iter().enumerate() {
        let last = i == hist.transfers.len() - 1;
        let key = parse_key(&owner.params)?;
        let leaf = check_step(
            &owner,
            &state,
            &hist.transfers_raw[i],
            t.expires_at,
            &hist.cds[i],
            hist.times[i],
            &key,
            &mut seen,
        )?;
        let (sid, th) = (leaf.sid, leaf.tx_hash);
        out.leaves.push(leaf);
        if last && mode == Mode::Return {
            check_return(cfg, &mut out, t)?;
            out.nullifier = nullifier(&ch, &burn_id(&sid, &th));
            if out.nullifier == [0u8; 32] {
                return Err(E::ZeroDigest);
            }
        } else {
            // Receipt histories and every intermediate step are signature transfers with no data.
            if t.recipient.typ != PRED_SIGNATURE {
                return Err(if last {
                    E::UnexpectedBurn
                } else {
                    E::BurnNotFinal
                });
            }
            if t.data.is_some() {
                return Err(E::TransferData);
            }
        }
        state = result_state(&state, &t.mask);
        owner = t.recipient.clone();
    }
    Ok(out)
}

fn check_return(cfg: &Cfg, out: &mut Outcome, t: &Transfer) -> Result<()> {
    if t.recipient.typ != PRED_BURN {
        return Err(E::NotBurn);
    }
    let data = t.data.as_deref().ok_or(E::ReturnData)?;
    if data.len() > MAX_SEMANTIC_BYTES {
        return Err(E::InputTooLarge);
    }
    let root = scan_one(data).map_err(|_| E::ReturnData)?;
    let c = root
        .tag_content(TAG_RETURN_REASON)
        .map_err(|_| E::ReturnData)?;
    let k = c.array(11).ok_or(E::ReturnData)?;
    k[0].version(1).map_err(|_| E::ReturnData)?;
    let chain = k[1].uint().map_err(|_| E::ReturnData)?;
    if chain != cfg.chain_id {
        return Err(E::ReturnData);
    }
    let bad = |_| E::ReturnData;
    let vault: [u8; 20] = fixed(&k[2]).map_err(bad)?;
    let zero: [u8; 20] = fixed(&k[3]).map_err(bad)?;
    let ty: [u8; 32] = fixed(&k[4]).map_err(bad)?;
    let aid: [u8; 32] = fixed(&k[5]).map_err(bad)?;
    let recip: [u8; 20] = fixed(&k[6]).map_err(bad)?;
    if vault != cfg.vault || zero != cfg.zero_address || ty != cfg.ty || aid != cfg.aid {
        return Err(E::ReturnData);
    }
    let amt = k[7].amount().map_err(|_| E::ReturnAmount)?;
    if BigUint::from_bytes_be(amt) != BigUint::from_bytes_be(&out.amount) {
        return Err(E::ReturnAmount);
    }
    let zero2: [u8; 20] = fixed(&k[8]).map_err(bad)?;
    let empty_ok = matches!(&k[9].kind, Kind::Bytes(d) if d.is_empty());
    let zero_ok = matches!(k[10].kind, Kind::Uint(0));
    if zero2 != cfg.zero_address || !empty_ok || !zero_ok {
        return Err(E::ReturnData);
    }
    if recip == [0u8; 20] || recip == cfg.vault {
        return Err(E::ReturnRecip);
    }
    if t.recipient.params != h(data) {
        return Err(E::BurnReason);
    }
    out.release_to = recip;
    Ok(())
}

// ---- projection adapter ------------------------------------------------------------------------

/// Export the compact history of an SDK [`unicity_token::Token`]: the unchanged tagged transactions
/// and certification data with each original reference time `t`, and no inclusion proofs.
pub fn project(token: &unicity_token::Token) -> Vec<u8> {
    use unicity_token::transaction::Transaction;
    let g = token.genesis();
    let head = encode_array(&[
        &g.transaction().to_cbor(),
        &g.inclusion_proof().certification_data.to_cbor(),
        &encode_uint(g.inclusion_proof().reference_time),
    ]);
    let mut tuples: Vec<Vec<u8>> = Vec::new();
    for t in token.transactions() {
        tuples.push(encode_array(&[
            &t.transaction().to_cbor(),
            &t.inclusion_proof().certification_data.to_cbor(),
            &encode_uint(t.inclusion_proof().reference_time),
        ]));
    }
    let refs: Vec<&[u8]> = tuples.iter().map(Vec::as_slice).collect();
    encode_array(&[&head, &encode_array(&refs)])
}
