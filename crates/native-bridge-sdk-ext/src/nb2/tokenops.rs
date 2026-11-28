use alloc::string::String;
use alloc::vec::Vec;
use num_bigint::BigUint;

use super::cbor::*;
use super::config::tag;
use super::crypto::{
    hu, minter_scalar, minter_scalar_valid, parse_key, public_key, sign_recoverable, sign_unlock,
    unlock_message, verify_unlock,
};
use super::deposit::{decode_receipt_backing, limits};
use super::errors::{refuse, Error, Result, WalletReason};
use super::split::{
    decode_split_justification, encode_split_justification, encode_split_manifest,
    encode_sum_proof, split_output_commitment, SumLeaf, SumTree,
};
use super::token::*;

/// A Unicity owner key: its compressed public key and the 65-byte r||s||id unlock signature over a 32-byte message.
pub trait OwnerSigner {
    fn public_key(&self) -> [u8; 33];
    fn sign_unlock(&self, message: &[u8; 32]) -> core::result::Result<[u8; 65], String>;
    /// A signer may report SigningDeclined only if it guarantees no signature was produced.
    fn sign_unlock_for_burn(&self, message: &[u8; 32]) -> Result<[u8; 65]> {
        self.sign_unlock(message).map_err(Error::Other)
    }
}

/// An owner key held in memory.
#[derive(Clone)]
pub struct LocalOwner {
    key: [u8; 32],
    public: [u8; 33],
}

impl Drop for LocalOwner {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

pub fn local_owner(private_key: &[u8]) -> LocalOwner {
    let key: [u8; 32] = super::util::arr(private_key);
    LocalOwner {
        public: public_key(&key),
        key,
    }
}

impl OwnerSigner for LocalOwner {
    fn public_key(&self) -> [u8; 33] {
        self.public
    }

    fn sign_unlock(&self, message: &[u8; 32]) -> core::result::Result<[u8; 65], String> {
        Ok(sign_recoverable(&self.key, message))
    }
}

/// The aggregator: certify a request (exact CD bytes) and return its inclusion proof (exact bytes). Resubmitting must be harmless.
pub trait Aggregator {
    fn certify(&self, request: &[u8]) -> Result<Vec<u8>>;
}

/// A transaction and its certification request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub tx: Vec<u8>,
    pub cd: Vec<u8>,
}

/// The certification request of a mint: the universal minter's unlock over (h0, txHash).
pub fn mint_request(m: &MintTx) -> Result<Request> {
    let reason = m.justification.as_deref().unwrap_or_default();
    let tx = encode_mint(m);
    let kind = head_tag(reason);
    let fits = match kind {
        Some(tag::RECEIPT_BACKING) => {
            reason.len() <= limits::JUSTIFICATION_BYTES && tx.len() <= MAX_ROOT_MINT
        }
        Some(tag::SPLIT_JUSTIFICATION) => tx.len() <= MAX_CHILD_MINT,
        _ => false,
    };
    if !fits {
        return refuse(
            WalletReason::BadInput,
            "missing or oversized bridge mint reason",
        );
    }
    if kind == Some(tag::RECEIPT_BACKING) {
        decode_receipt_backing(reason)?;
    } else {
        decode_split_justification(reason)?;
    }
    let id = token_id_of(&m.salt, m.network);
    let h0 = mint_source_hash(&id);
    let tx_hash = hu(&[&tx]);
    let key = minter_scalar(&id);
    if !minter_scalar_valid(&key) {
        return refuse(WalletReason::BadInput, "invalid universal minter scalar");
    }
    let unlock = sign_unlock(&key, &h0, &tx_hash);
    let pk = public_key(&key);
    verify_unlock(&pk, &h0, &tx_hash, &unlock)?;
    let cd = Certification {
        source: signature_predicate(&pk),
        source_hash: h0.to_vec(),
        tx_hash: tx_hash.to_vec(),
        deadline: m.deadline,
        unlock: unlock.to_vec(),
    };
    Ok(Request {
        tx,
        cd: encode_certification(&cd),
    })
}

/// Export a certified root.
pub fn token_of_mint(tx: &[u8], proof: &[u8]) -> Vec<u8> {
    frame_lineage(&[frame_level(&[], tx, proof, &[])])
}

/// Add the child level to the exact signed records of the parent.
pub fn token_of_child(
    parent: &[u8],
    allocation: &[u8],
    tx: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>> {
    let parent = decode_token(parent)?;
    let mut levels: Vec<_> = parent.levels().map(encode_level).collect();
    levels.push(frame_level(allocation, tx, proof, &[]));
    Ok(frame_lineage(&levels))
}

/// Preserve the exact signed bytes when appending a certified transfer.
pub fn append_transfer(token: &[u8], tx: &[u8], proof: &[u8]) -> Result<Vec<u8>> {
    let part = decode_token(token)?;
    let mut levels: Vec<_> = part.ancestors.iter().map(encode_level).collect();
    let mut pairs: Vec<_> = part
        .transfers_raw
        .iter()
        .zip(&part.proofs)
        .map(|(tx, proof)| c_arr(&[tx, &encode_proof(proof)]))
        .collect();
    pairs.push(c_arr(&[tx, proof]));
    levels.push(frame_level(
        &part.allocation,
        &part.mint_raw,
        &encode_proof(&part.mint_proof),
        &pairs,
    ));
    Ok(frame_lineage(&levels))
}

/// The current owner predicate and state of a decoded token.
pub fn head_of(t: &LineageLevel) -> (Predicate, [u8; 32]) {
    let id = token_id_of(&t.mint.salt, t.mint.network);
    let mut state = result_state(&mint_source_hash(&id), &id);
    let mut owner = t.mint.recipient.clone();
    for tr in &t.transfers {
        state = result_state(&state, &tr.mask);
        owner = tr.recipient.clone();
    }
    (owner, state)
}

/// A transfer of `token` and its certification request, signed by the current owner.
pub fn transfer_request(token: &[u8], owner: &dyn OwnerSigner, tr: &TransferTx) -> Result<Request> {
    transfer_request_with(token, owner, tr, |message| {
        owner.sign_unlock(message).map_err(Error::Other)
    })
}

pub(crate) fn transfer_request_with(
    token: &[u8],
    owner: &dyn OwnerSigner,
    tr: &TransferTx,
    sign: impl FnOnce(&[u8; 32]) -> Result<[u8; 65]>,
) -> Result<Request> {
    let t = decode_token(token)?;
    let (head_owner, state) = head_of(&t);
    if head_owner.ty != PRED_SIGNATURE || head_owner.params != owner.public_key() {
        return refuse(WalletReason::BadInput, "the token is not owned by this key");
    }
    let tx = encode_transfer(tr);
    let tx_hash = hu(&[&tx]);
    let unlock = sign(&unlock_message(&state, &tx_hash))?;
    // the owner's signature is checked by the NB2 unlock rule (recovery ID 0 or 1 included) before anything is journaled or certified
    verify_unlock(&head_owner.params, &state, &tx_hash, &unlock)?;
    let cd = Certification {
        source: head_owner,
        source_hash: state.to_vec(),
        tx_hash: tx_hash.to_vec(),
        deadline: tr.deadline,
        unlock: unlock.to_vec(),
    };
    Ok(Request {
        tx,
        cd: encode_certification(&cd),
    })
}

/// Certify and check that the proof is for exactly this request.
pub fn certify_checked(agg: &dyn Aggregator, cd: &[u8]) -> Result<Vec<u8>> {
    let proof = agg.certify(cd)?;
    let it = scan_native(&proof)?;
    let k = array(tag_content(&it, tag::INCLUSION)?, 5)?;
    if raw(&proof, &k[1]) != cd {
        return refuse(
            WalletReason::ProviderFault,
            "the inclusion proof is not for the submitted request",
        );
    }
    Ok(proof)
}

/// One output of a split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitOutput {
    pub owner_key: Vec<u8>,
    pub amount: BigUint,
    pub salt: Vec<u8>,
    pub deadline: Deadline,
}

/// The fixed parts of a split: the manifest, its burn transfer, and each child's mint template (without its justification).
#[derive(Debug, Clone)]
pub struct SplitPlan {
    pub manifest: Vec<u8>,
    pub burn: TransferTx,
    pub children: Vec<MintTx>,
    pub tree: SumTree,
    pub parent_id: [u8; 32],
}

pub fn split_plan(
    parent: &LineageLevel,
    outputs: &[SplitOutput],
    ty: &[u8],
    aid: &[u8],
    mask: &[u8],
    deadline: Deadline,
) -> Result<SplitPlan> {
    for output in outputs {
        parse_key(&output.owner_key)?;
        if output.salt.len() != 32 || output.deadline == Some(0) {
            return refuse(WalletReason::BadInput, "invalid child salt or deadline");
        }
    }
    let parent_id = token_id_of(&parent.mint.salt, parent.mint.network);
    let children: Vec<MintTx> = outputs
        .iter()
        .map(|o| MintTx {
            network: parent.mint.network,
            recipient: signature_predicate(&o.owner_key),
            salt: o.salt.clone(),
            ty: ty.to_vec(),
            justification: None,
            data: Some(value_data(aid, &o.amount)),
            deadline: o.deadline,
        })
        .collect();
    let leaves: Vec<SumLeaf> = children
        .iter()
        .zip(outputs)
        .map(|(m, o)| SumLeaf {
            key: token_id_of(&m.salt, m.network),
            data: split_output_commitment(&parent_id, m),
            value: o.amount.clone(),
        })
        .collect();
    let tree = SumTree::build(&leaves)?;
    let manifest = encode_split_manifest(&tree.root());
    let burn = TransferTx {
        recipient: burn_predicate(&hu(&[&manifest])),
        mask: mask.to_vec(),
        data: Some(manifest.clone()),
        deadline,
    };
    Ok(SplitPlan {
        manifest,
        burn,
        children,
        tree,
        parent_id,
    })
}

/// Prepare a child after the parent split verifier has derived its authenticated link.
pub fn child_mint(link: &[u8; 32], tree: &SumTree, child: &MintTx) -> Result<(MintTx, Vec<u8>)> {
    let Some(proof) = tree.proof(&token_id_of(&child.salt, child.network)) else {
        return refuse(WalletReason::BadInput, "child not in the allocation tree");
    };
    Ok((
        MintTx {
            justification: Some(encode_split_justification(link)),
            ..child.clone()
        },
        encode_sum_proof(&proof),
    ))
}

/// A fresh 32-byte random value (a state mask or a salt).
#[cfg(feature = "host")]
pub fn fresh_mask() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("nb2: the system RNG");
    b
}
