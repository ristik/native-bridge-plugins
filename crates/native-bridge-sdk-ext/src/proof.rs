//! Return proof assembly and aggregator refresh.
//!
//! Return assembly may refresh *aggregator* paths and unicity certificates over the same
//! `(sid, txHash, t)` leaves for the verifier's current window, with no change to J, M or token
//! ownership. The original `t` and every certification data byte are kept; a refreshed proof that
//! changes either is rejected. Fetching is the host's concern: this module only consumes proofs.

use alloc::vec::Vec;

use unicity_token::api::InclusionProof;
use unicity_token::transaction::{
    CertifiedMintTransaction, CertifiedTransferTransaction, Transaction,
};
use unicity_token::Token;

use crate::deployment::Deployment;
use crate::envelope::{check_anchor, check_policy, Anchor, Envelope, LeafProof};
use crate::error::{NativeError as E, Result};
use crate::history::{self, History};
use crate::limits::*;
use crate::profile::h;
use crate::token::{Expect, NativeBridge, VerifiedToken};

/// Replace every aggregator inclusion proof of `token` with the freshly fetched proof for the same
/// leaf. `fresh` is ordered like the history: genesis first.
pub fn refresh_token(token: &Token, fresh: &[InclusionProof]) -> Result<Token> {
    if fresh.len() != 1 + token.transactions().len() {
        return Err(E::RefreshMismatch);
    }
    let same = |old: &InclusionProof, new: &InclusionProof| -> Result<()> {
        if old.certification_data != new.certification_data
            || old.reference_time != new.reference_time
        {
            return Err(E::RefreshMismatch);
        }
        Ok(())
    };
    same(token.genesis().inclusion_proof(), &fresh[0])?;
    let genesis =
        CertifiedMintTransaction::new(token.genesis().transaction().clone(), fresh[0].clone());
    let mut transfers = Vec::new();
    for (t, p) in token.transactions().iter().zip(&fresh[1..]) {
        same(t.inclusion_proof(), p)?;
        transfers.push(CertifiedTransferTransaction::new(
            t.transaction().clone(),
            p.clone(),
        ));
    }
    Ok(Token::new(genesis, transfers))
}

/// Assemble the return envelope from a token whose every aggregator proof is anchored at one
/// unicity certificate. The token is verified in full as a return first.
pub fn build_return_proof(
    bridge: &NativeBridge,
    token: &Token,
) -> Result<(Envelope, VerifiedToken)> {
    let verified = bridge.verify_native_token(token, Expect::Return)?;
    let dep: &Deployment = &bridge.registry.deployments()[verified.deployment];
    let history_bytes = history::project(token);
    // Decoding again keeps the exported bytes the single source of truth.
    History::decode(&history_bytes)?;

    let g = token.genesis();
    let mut proofs: Vec<&InclusionProof> = alloc::vec![g.inclusion_proof()];
    for t in token.transactions() {
        proofs.push(t.inclusion_proof());
    }
    let uc = &proofs[0].unicity_certificate;
    let uc_bytes = uc.to_cbor();
    if proofs
        .iter()
        .any(|p| p.unicity_certificate.to_cbor() != uc_bytes)
    {
        // Proofs span different roots: refresh them to one current root first.
        return Err(E::PolicyAnchors);
    }
    let ir = uc.input_record.to_cbor();
    let state_root: [u8; 32] = uc
        .input_record
        .hash
        .as_slice()
        .try_into()
        .map_err(|_| E::PathInvalid)?;
    let anchor = Anchor {
        partition: dep.policy.partition,
        shard: crate::profile::EMPTY_PREFIX_SHARD.to_vec(),
        shard_conf_hash: dep.policy.shard_conf,
        expected_state_root: state_root,
        expected_ir_hash: h(&ir),
        uc: uc_bytes,
        input_record: ir,
    };
    let mut leaf_proofs = Vec::new();
    for p in &proofs {
        let enc = p.inclusion_certificate.encode();
        let mut bitmap = [0u8; 32];
        bitmap.copy_from_slice(&enc[..32]);
        let siblings = enc[32..]
            .chunks_exact(32)
            .map(|c| <[u8; 32]>::try_from(c).expect("32"))
            .collect();
        leaf_proofs.push(LeafProof {
            anchor_index: 0,
            bitmap,
            siblings,
        });
    }
    let env = Envelope {
        policy_body: dep.policy.to_bytes(),
        history: history_bytes,
        anchors: alloc::vec![anchor],
        leaf_proofs,
    };
    if env.encode().len() > MAX_ENVELOPE_BYTES {
        return Err(E::InputTooLarge);
    }
    // The composing verifier's own tuple and opening checks must pass on what we assembled.
    check_policy(&dep.cfg, &env, 1 + token.transactions().len())?;
    let times: Vec<u64> = verified
        .outcome
        .leaves
        .iter()
        .map(|l| l.reference_time)
        .collect();
    check_anchor(&env.anchors[0], &times)?;
    Ok((env, verified))
}

/// All transaction objects of a token in history order, for callers that fetch proofs per leaf.
pub fn leaf_transactions(token: &Token) -> Vec<(Vec<u8>, [u8; 32])> {
    let mut out = Vec::new();
    let g = token.genesis().transaction();
    out.push((
        g.to_cbor(),
        *unicity_token::api::StateId::derive(g.lock_script(), g.source_state_hash()).bytes(),
    ));
    for t in token.transactions() {
        let tx = t.transaction();
        out.push((
            tx.to_cbor(),
            *unicity_token::api::StateId::derive(tx.lock_script(), tx.source_state_hash()).bytes(),
        ));
    }
    out
}
