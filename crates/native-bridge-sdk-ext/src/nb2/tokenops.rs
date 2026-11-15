//! Ordinary token operations on the unchanged SDK wire (`tokenops.ts`): the root mint with the receipt-backed reason, transfers,
//! the return burn and the split (burn-and-mint with the protocol 6 lineage formats). Transactions are built byte for byte as
//! the SDK builds them, signed by the owner's [`OwnerSigner`] (the universal minter for a mint), and certified by an
//! [`Aggregator`]. Every certified result is verified offline by this package's verifier before the bridge returns it.

use alloc::string::String;
use alloc::vec::Vec;
use num_bigint::BigUint;

use super::cbor::*;
use super::config::tag;
use super::crypto::{
    hu, minter_scalar, public_key, sign_recoverable, sign_unlock, unlock_message, verify_unlock,
};
use super::errors::{refuse, Error, Result, WalletReason};
use super::split::{
    encode_split_justification, encode_split_manifest, split_output_commitment, SumLeaf, SumTree,
};
use super::token::*;

/// A Unicity owner key: its compressed public key and the 65-byte r||s||id unlock signature over a 32-byte message.
pub trait OwnerSigner {
    fn public_key(&self) -> [u8; 33];
    fn sign_unlock(&self, message: &[u8; 32]) -> core::result::Result<[u8; 65], String>;
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
    let tx = encode_mint(m);
    let id = token_id_of(&m.salt, m.network);
    let h0 = mint_source_hash(&id);
    let tx_hash = hu(&[&tx]);
    let key = minter_scalar(&id);
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

/// The exact token of one certified mint.
pub fn token_of_mint(tx: &[u8], proof: &[u8]) -> Vec<u8> {
    c_tag(
        tag::TOKEN,
        &c_arr(&[&c_uint(2), &c_arr(&[tx, proof]), &c_arr(&[])]),
    )
}

/// A token with one more certified transfer: the exact earlier pairs, then (tx, proof).
pub fn append_transfer(token: &[u8], tx: &[u8], proof: &[u8]) -> Result<Vec<u8>> {
    let it = scan_native(token)?;
    let k = array(tag_content(&it, tag::TOKEN)?, 3)?;
    let mut pairs: Vec<Vec<u8>> = k[2].kids.iter().map(|p| raw(token, p).to_vec()).collect();
    pairs.push(c_arr(&[tx, proof]));
    Ok(c_tag(
        tag::TOKEN,
        &c_arr(&[&c_uint(2), raw(token, &k[1]), &c_arr_v(&pairs)]),
    ))
}

/// The current owner predicate and state of a decoded token.
pub fn head_of(t: &Token) -> (Predicate, [u8; 32]) {
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
    let t = decode_token(token)?;
    let (head_owner, state) = head_of(&t);
    if head_owner.ty != PRED_SIGNATURE || head_owner.params != owner.public_key() {
        return refuse(WalletReason::BadInput, "the token is not owned by this key");
    }
    let tx = encode_transfer(tr);
    let tx_hash = hu(&[&tx]);
    let unlock = owner
        .sign_unlock(&unlock_message(&state, &tx_hash))
        .map_err(Error::Other)?;
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
    parent: &Token,
    outputs: &[SplitOutput],
    ty: &[u8],
    aid: &[u8],
    mask: &[u8],
    deadline: Deadline,
) -> Result<SplitPlan> {
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
            deadline: None,
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

/// A child's mint with its split reason over the exact burned parent token.
pub fn child_mint(burned_parent: &[u8], tree: &SumTree, child: &MintTx) -> Result<MintTx> {
    let Some(proof) = tree.proof(&token_id_of(&child.salt, child.network)) else {
        return refuse(WalletReason::BadInput, "child not in the allocation tree");
    };
    Ok(MintTx {
        justification: Some(encode_split_justification(burned_parent, &proof)),
        ..child.clone()
    })
}

/// A fresh 32-byte random value (a state mask or a salt).
#[cfg(feature = "host")]
pub fn fresh_mask() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("nb2: the system RNG");
    b
}
