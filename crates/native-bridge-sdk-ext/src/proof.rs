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
use crate::gas::{compute_gate, kernel_request_bytes, projected_gate_anchors, Gate};
use crate::history::{self, History};
use crate::limits::*;
use crate::profile::h;
use crate::splitpart::{is_split_reason, lineage_proofs, root_justification, split_chain};
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
/// anchor), in first-use leaf order, each claim read from its own UC (its shard, shard configuration hash and
/// partition: the policy names only the partition, and the UC authenticates the rest). Nothing here re-queries to make certificates converge: the pairs are used as fetched, and an
/// envelope that needs more anchors than the profile bound is `PolicyAnchors` or `TooManyPaths`, never
/// truncated or split. The returned `Gate` is the gas estimate the redemption should be sent with; it is
/// never a refusal (owner section 36).
pub fn build_return_proof(
    bridge: &NativeBridge,
    token: &Token,
) -> Result<(Envelope, VerifiedToken, Gate)> {
    build_return_proof_with(bridge, token, None)
}

/// [`build_return_proof`] with optional fresh witnesses: one per leaf (for a split part, every leaf of the lineage, root first), each
/// for the same certified leaf (the same certification data and reference time). They go into the envelope only: an ancestor's
/// proofs inside its embedded token are never rewritten (that would change the descendant's mint hash). Their certificates are the
/// chain's to authenticate (B1); the anchor plan and openings below check the rest.
pub fn build_return_proof_with(
    bridge: &NativeBridge,
    token: &Token,
    witnesses: Option<&[InclusionProof]>,
) -> Result<(Envelope, VerifiedToken, Gate)> {
    let verified = bridge.verify_native_token(token, Expect::Return)?;
    let dep: &Deployment = &bridge.registry.deployments()[verified.deployment];
    let history_bytes = history::project(token);
    // Decoding again keeps the exported bytes the single source of truth.
    History::decode_composed(&history_bytes)?;

    // A split part's leaves are the whole lineage's, root first.
    let embedded: Vec<InclusionProof> = if verified.lineage.is_some() {
        lineage_proofs(&split_chain(token)?)
    } else {
        lineage_proofs(core::slice::from_ref(token))
    };
    let proofs: Vec<InclusionProof> = match witnesses {
        None => embedded,
        Some(fresh) => {
            if fresh.len() != embedded.len()
                || embedded.iter().zip(fresh).any(|(a, b)| {
                    a.certification_data.to_cbor() != b.certification_data.to_cbor()
                        || a.reference_time != b.reference_time
                })
            {
                return Err(E::RefreshMismatch);
            }
            fresh.to_vec()
        }
    };
    let mut anchors: Vec<Anchor> = Vec::new();
    let mut ucs: Vec<Vec<u8>> = Vec::new();
    let mut leaf_proofs = Vec::new();
    for p in proofs.iter() {
        let uc_bytes = p.unicity_certificate.to_cbor();
        let idx = match ucs.iter().position(|u| *u == uc_bytes) {
            Some(idx) => idx,
            None => {
                let ir = p.unicity_certificate.input_record.to_cbor();
                let state_root: [u8; 32] = p
                    .unicity_certificate
                    .input_record
                    .hash
                    .as_deref()
                    .and_then(|h| h.try_into().ok())
                    .ok_or(E::PathInvalid)?;
                anchors.push(Anchor {
                    partition: p
                        .unicity_certificate
                        .unicity_tree_certificate
                        .partition_identifier,
                    shard: p.unicity_certificate.shard_tree_certificate.shard.encode(),
                    shard_conf_hash: p
                        .unicity_certificate
                        .shard_configuration_hash
                        .as_slice()
                        .try_into()
                        .map_err(|_| E::PathInvalid)?,
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
    // anchor table, the gas estimate, then every anchor's opening and every leaf's own anchor time.
    let sids: Vec<[u8; 32]> = verified.outcome.leaves.iter().map(|l| l.sid).collect();
    let pol = check_policy_body(&dep.cfg, &env)?;
    let plan = plan_anchors(&pol, &env, &sids)?;
    let mut gate = compute_gate(
        &dep.cfg.to_bytes(),
        encoded.len(),
        kernel_request_bytes(dep.cfg.to_bytes().len() as u64, env.history.len() as u64),
        &env,
    )?;
    // BRIDGE_COMPOSE_V2 also charges the lineage walk (spec section 6) on top of the schedule over every leaf
    if let Some(l) = &verified.lineage {
        gate.native += l.split_gas;
        gate.total += l.split_gas;
    }
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

/// The burn-time preflight. A burn that could never be redeemed under the resource policy is refused
/// before the wallet burns anything: more leaves than the native kernel admits, or a history or envelope
/// over its bound (`TooManyTx`/`InputTooLarge`, BudgetExceeded), never a truncated history or a partial
/// redemption. There is no gas ceiling (owner section 36): the returned best-case estimate is only that.
/// `token` is the held receipt the burn would spend.
pub fn preflight_burn(bridge: &NativeBridge, token: &Token) -> Result<Gate> {
    preflight_burn_shards(bridge, token, 1)
}

/// [`preflight_burn`] when the host knows how many aggregator shards the leaves touch (its routing of
/// [`leaf_state_ids`]): the best case is then the consolidated bundle, one anchor per shard (at most one per
/// leaf) under one seal. With `shards` 1 it is `preflight_burn`: a single certificate may serve every leaf.
/// The projection is a lower bound only while the topology does not merge: the redemption comes later, and a
/// shard merge before it lowers the anchors the leaves need, so a host that may see a merge passes the merged
/// count (or 1); over-counting `shards` could refuse a burn that would pass.
pub fn preflight_burn_shards(bridge: &NativeBridge, token: &Token, shards: usize) -> Result<Gate> {
    let dep = deployment_of(bridge, token)?;
    if is_split_reason(token.genesis().transaction().justification()) {
        return preflight_split_burn(bridge, token, dep, shards);
    }
    let leaves = token.transactions().len() + 2; // the mint, every transfer and the burn
    check_burn_projection_anchors(
        dep.cfg.to_bytes().len() as u64,
        dep.policy.to_bytes().len() as u64,
        leaves as u64,
        history::project(token).len(),
        shards.min(leaves) as u64,
    )
}

/// The size refusal of the preflight and its best-case estimate, on the projection's inputs. The composition
/// has no history bound of its own: the only refusal is the envelope (the ingress bound), which no refresh can
/// fix, so it errs safe: the burn leaf is assumed to add up to `BURN_HISTORY_BYTES` to the best-case envelope.
/// The estimate uses the known history only, a lower bound.
pub fn check_burn_projection(
    cfg_len: u64,
    policy_len: u64,
    leaves: u64,
    history: usize,
) -> Result<Gate> {
    check_burn_projection_anchors(cfg_len, policy_len, leaves, history, 1)
}

/// [`check_burn_projection`] with the best case of `anchors` anchors under one seal.
pub fn check_burn_projection_anchors(
    cfg_len: u64,
    policy_len: u64,
    leaves: u64,
    history: usize,
    anchors: u64,
) -> Result<Gate> {
    let (gate, envelope) =
        projected_gate_anchors(cfg_len, policy_len, leaves, history as u64, anchors);
    if envelope + BURN_HISTORY_BYTES as u64 > MAX_ENVELOPE_BYTES as u64 {
        return Err(E::InputTooLarge);
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

/// A split part's burn-time estimate: the whole lineage's leaves plus the burn, the part's history (its ancestry is inside its mint)
/// and the walk's charge (spec section 6), which the burn does not change. The held part is verified first (the receipt relation): a
/// part that could not be redeemed is never burned.
fn preflight_split_burn(
    bridge: &NativeBridge,
    token: &Token,
    dep: &Deployment,
    shards: usize,
) -> Result<Gate> {
    let held = bridge.verify_native_token(token, Expect::Receipt)?;
    let leaves = held.outcome.leaves.len() + 1;
    let mut gate = check_burn_projection_anchors(
        dep.cfg.to_bytes().len() as u64,
        dep.policy.to_bytes().len() as u64,
        leaves as u64,
        history::project(token).len(),
        shards.min(leaves) as u64,
    )?;
    let split = held.lineage.map_or(0, |l| l.split_gas);
    gate.native += split;
    gate.total += split;
    Ok(gate)
}

fn deployment_of<'a>(bridge: &'a NativeBridge, token: &Token) -> Result<&'a Deployment> {
    let mint = token.genesis().transaction();
    let j = root_justification(mint.justification())?;
    let parsed = crate::lockproof::parse_justification(&j)?;
    bridge
        .registry
        .find(mint.network_id().id(), parsed.chain_id, &parsed.vault)
}

/// The raw 32-byte state ID of every history leaf (genesis first): what `get_inclusion_proof.v2` is asked for.
pub fn leaf_state_ids(token: &Token) -> Vec<[u8; 32]> {
    leaf_transactions(token)
        .into_iter()
        .map(|(_, sid)| sid)
        .collect()
}
