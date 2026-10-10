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
use crate::envelope::{
    check_anchors, check_policy_body, plan_anchors, Anchor, Envelope, LeafProof,
};
use crate::error::{NativeError as E, Result};
use crate::gas::{compute_gate, kernel_request_bytes, projected_gate, Gate};
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
    let refreshed = Token::new(genesis, transfers);
    crate::resources::preflight_token(&refreshed.to_cbor())?;
    Ok(refreshed)
}

/// Assemble the return envelope from a token whose every aggregator proof carries its own (path, UC)
/// pair. The token is verified in full as a return first.
///
/// The anchor table is the profile's: one anchor per distinct complete UC (byte-identical UCs are one
/// anchor), in first-use leaf order, each claim derived from its UC and the pinned policy row of its
/// shard. Nothing here re-queries to make certificates converge: the pairs are used as fetched, and an
/// envelope that needs more anchors than the profile bound, or does not fit the shared gas gate, is
/// `PolicyAnchors` or `GasBudget` (BudgetExceeded), never truncated or split.
pub fn build_return_proof(
    bridge: &NativeBridge,
    token: &Token,
) -> Result<(Envelope, VerifiedToken, Gate)> {
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
    let mut anchors: Vec<Anchor> = Vec::new();
    let mut ucs: Vec<Vec<u8>> = Vec::new();
    let mut leaf_proofs = Vec::new();
    for (i, p) in proofs.iter().enumerate() {
        let uc_bytes = p.unicity_certificate.to_cbor();
        let idx = match ucs.iter().position(|u| *u == uc_bytes) {
            Some(idx) => idx,
            None => {
                let row = dep.policy.shard_row(&verified.outcome.leaves[i].sid);
                let ir = p.unicity_certificate.input_record.to_cbor();
                let state_root: [u8; 32] = p
                    .unicity_certificate
                    .input_record
                    .hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| E::PathInvalid)?;
                anchors.push(Anchor {
                    partition: dep.policy.partition,
                    shard: dep.policy.shard_id(row).to_vec(),
                    shard_conf_hash: dep.policy.shard_confs[row],
                    expected_state_root: state_root,
                    expected_ir_hash: h(&ir),
                    uc: uc_bytes.clone(),
                    input_record: ir,
                });
                ucs.push(uc_bytes);
                ucs.len() - 1
            }
        };
        let enc = p.inclusion_certificate.encode();
        let mut bitmap = [0u8; 32];
        bitmap.copy_from_slice(&enc[..32]);
        let siblings = enc[32..]
            .chunks_exact(32)
            .map(|c| <[u8; 32]>::try_from(c).expect("32"))
            .collect();
        leaf_proofs.push(LeafProof {
            anchor_index: idx as u16,
            bitmap,
            siblings,
        });
    }
    let env = Envelope {
        policy_body: dep.policy.to_bytes(),
        history: history_bytes,
        anchors,
        leaf_proofs,
    };
    let encoded = env.encode();
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(E::InputTooLarge);
    }
    // The composing verifier's own checks must pass on what we assembled, in its order: policy opening,
    // anchor table, the shared gas gate, then every anchor's opening and every leaf's own anchor time.
    let sids: Vec<[u8; 32]> = verified.outcome.leaves.iter().map(|l| l.sid).collect();
    let pol = check_policy_body(&dep.cfg, &env)?;
    let plan = plan_anchors(&pol, &env, &sids)?;
    let gate = compute_gate(
        encoded.len(),
        kernel_request_bytes(dep.cfg.to_bytes().len() as u64, env.history.len() as u64),
        &env,
        &pol,
        TX_GAS_BUDGET,
    )?;
    let times: Vec<u64> = verified
        .outcome
        .leaves
        .iter()
        .map(|l| l.reference_time)
        .collect();
    check_anchors(&env, &plan, &times)?;
    Ok((env, verified, gate))
}

/// An upper bound on the size of the burn leaf's contribution to the history projection (the transfer, its
/// certification data with its unlock script and the terminal return reason).
pub const BURN_HISTORY_BYTES: usize = 1024;

/// The burn-time preflight. A burn that could never be redeemed under the profile bounds and the
/// shared gas gate is refused before the wallet burns anything: more leaves than the profile admits, a
/// history or envelope over its bound, or a worst-case envelope over the transaction budget. Beyond the
/// bounds the answer is `GasBudget`/`TooManyTx`/`InputTooLarge` (BudgetExceeded), never a truncated
/// history or a partial redemption. `token` is the held receipt the burn would spend.
pub fn preflight_burn(bridge: &NativeBridge, token: &Token) -> Result<Gate> {
    let dep = deployment_of(bridge, token)?;
    let leaves = token.transactions().len() + 2; // the mint, every transfer and the burn
    if leaves > MAX_LEAVES {
        return Err(E::TooManyTx);
    }
    // The history bound is hard and no refresh can fix it, so it errs safe: the burn leaf is assumed to
    // add up to `BURN_HISTORY_BYTES`. The gate projection uses the known history only, a lower bound.
    let history = history::project(token).len();
    if history + BURN_HISTORY_BYTES > MAX_SEMANTIC_BYTES {
        return Err(E::InputTooLarge);
    }
    // the fewest anchors the known leaves can need: one per shard they occupy
    let mut rows: Vec<usize> = leaf_routes(bridge, token)?.iter().map(|r| r.row).collect();
    rows.sort_unstable();
    rows.dedup();
    let (gate, envelope) = projected_gate(
        dep.cfg.to_bytes().len() as u64,
        dep.policy.to_bytes().len() as u64,
        u64::from(dep.policy.depth),
        rows.len() as u64,
        leaves as u64,
        history as u64,
    );
    if envelope > MAX_ENVELOPE_BYTES as u64 {
        return Err(E::InputTooLarge);
    }
    if gate.total > TX_GAS_BUDGET {
        return Err(E::GasBudget);
    }
    Ok(gate)
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

fn deployment_of<'a>(bridge: &'a NativeBridge, token: &Token) -> Result<&'a Deployment> {
    let mint = token.genesis().transaction();
    let j = mint.justification().ok_or(E::MintJustif)?;
    let parsed = crate::lockproof::parse_justification(j)?;
    bridge
        .registry
        .find(mint.network_id().id(), parsed.chain_id, &parsed.vault)
}

/// Where one history leaf's aggregator proof is served: the policy row of its own shard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafRoute {
    /// The leaf's position in the history (genesis first).
    pub index: usize,
    /// The raw 32-byte state ID `get_inclusion_proof.v2` is asked for.
    pub sid: [u8; 32],
    /// The policy row of the leaf's shard: the top `depth` bits of the state ID.
    pub row: usize,
    /// The native shard ID of that row.
    pub shard: Vec<u8>,
}

/// Route every leaf of `token` to its shard. The host maps rows to its aggregator endpoints
/// (installation metadata, never a verification input) and fetches `get_inclusion_proof.v2` per leaf;
/// whatever certificate each response carries is kept with its path. Nothing is re-queried to make
/// certificates converge.
pub fn leaf_routes(bridge: &NativeBridge, token: &Token) -> Result<Vec<LeafRoute>> {
    let dep = deployment_of(bridge, token)?;
    Ok(leaf_transactions(token)
        .into_iter()
        .enumerate()
        .map(|(index, (_, sid))| {
            let row = dep.policy.shard_row(&sid);
            LeafRoute {
                index,
                sid,
                row,
                shard: dep.policy.shard_id(row).to_vec(),
            }
        })
        .collect())
}
