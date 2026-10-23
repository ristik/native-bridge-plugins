//! The wallet side of a split part (protocol 6): the strict value-envelope payment decoder the SDK's split verifier needs, the walk
//! from a part to its root's lock reason (the root decides the deployment) and the part's ancestry as SDK tokens, root first, whose
//! proofs witness the lineage's leaves in the relation's order.

use alloc::vec::Vec;

use num_bigint::BigUint;
use unicity_token::api::InclusionProof;
use unicity_token::payment::{Asset, AssetId, PaymentAssetCollection, SplitMintJustification};
use unicity_token::Token;

use crate::error::{NativeError as E, Result};
use crate::limits::{TAG_MINT_LOCK, TAG_SPLIT_JUSTIFICATION, TAG_WALLET_VALUE};
use crate::profile::value_envelope;
use crate::scan::{fixed, scan_one};
use crate::sdktoken::decode_token;
use crate::split::{decode_split_justification, justification_tag};

/// The bridge's value envelope `tag(39050,[1,[[b(aid32),b(amount)]],null])` as SDK payment data: exactly one asset, no memo, the
/// exact canonical bytes. The deployment's asset is the issuance policy's check; this decoder only refuses everything that is not an
/// envelope. It is a [`unicity_token::payment::PaymentDataDecoder`].
pub fn wallet_value(
    bytes: &[u8],
) -> core::result::Result<PaymentAssetCollection, unicity_token::error::Error> {
    let bad = |_| unicity_token::error::Error::UnexpectedValue("not a wallet value envelope");
    let root = scan_one(bytes).map_err(bad)?;
    let k = root
        .tag_content(TAG_WALLET_VALUE)
        .map_err(bad)?
        .array(3)
        .ok_or(E::MintData)
        .map_err(bad)?;
    k[0].version(1).map_err(bad)?;
    let entry = k[1].array(1).ok_or(E::MintData).map_err(bad)?[0]
        .array(2)
        .ok_or(E::MintData)
        .map_err(bad)?;
    let aid: [u8; 32] = fixed(&entry[0]).map_err(bad)?;
    let amount = entry[1].amount().map_err(bad)?;
    if !k[2].is_null() || value_envelope(&aid, amount) != bytes {
        return Err(bad(E::MintData));
    }
    PaymentAssetCollection::create([Asset::new(
        AssetId::new(aid.to_vec()),
        BigUint::from_bytes_be(amount),
    )])
}

/// Whether a mint justification is a split reason (the token is a split part, not a lock-backed root).
pub fn is_split_reason(j: Option<&[u8]>) -> bool {
    justification_tag(j) == Some(TAG_SPLIT_JUSTIFICATION)
}

/// The lock reason of a part's root: walk the exact split reasons (each embeds its burned parent) down to the token minted from the
/// lock. Structure only: the relation and the SDK verify the walk; this only finds which deployment the part belongs to.
pub fn root_justification(j: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut cur = j.map(<[u8]>::to_vec);
    loop {
        match justification_tag(cur.as_deref()) {
            Some(TAG_MINT_LOCK) => return cur.ok_or(E::MintJustif),
            Some(TAG_SPLIT_JUSTIFICATION) => {
                let sj = decode_split_justification(cur.as_deref().unwrap_or_default())?;
                cur = decode_token(&sj.token)?.mint.justification;
            }
            _ => return Err(E::MintJustif),
        }
    }
}

/// The part's ancestry as SDK tokens, root first, ending with the part itself.
pub fn split_chain(part: &Token) -> Result<Vec<Token>> {
    let mut chain = alloc::vec![part.clone()];
    loop {
        let j = chain[0].genesis().transaction().justification();
        if !is_split_reason(j) {
            break;
        }
        let sj =
            SplitMintJustification::from_cbor(j.unwrap_or_default()).map_err(|_| E::SplitJustif)?;
        chain.insert(0, sj.token().clone());
    }
    Ok(chain)
}

/// Every certified transaction's proof of the lineage, root first, in the relation's leaf order (each token's mint, then its
/// transfers).
pub fn lineage_proofs(chain: &[Token]) -> Vec<InclusionProof> {
    chain
        .iter()
        .flat_map(|t| {
            core::iter::once(t.genesis().inclusion_proof().clone())
                .chain(t.transactions().iter().map(|c| c.inclusion_proof().clone()))
        })
        .collect()
}
