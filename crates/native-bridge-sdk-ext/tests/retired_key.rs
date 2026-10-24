#![allow(clippy::type_complexity, unused_imports, dead_code)]
//! Retired-key forged history (bft-core #438, from B5 #66): after two committee rotations, a
//! token history whose anchor is sealed by a rotated-out committee is refused, whether the retired
//! keys claim their own (closed) epoch or the current one. The bridge holds the whole history
//! (epochs 2 to 4), so every refusal is the seal's, never a missing epoch; the control anchor of
//! the current committee verifies and builds a return proof.

mod common;
use common::*;
use native_bridge_sdk_ext::proof::{build_return_proof, refresh_token};
use native_bridge_sdk_ext::token::{Expect, NativeBridge};
use native_bridge_sdk_ext::NativeError as E;
use unicity_token::api::{InclusionCertificate, InclusionProof};
use unicity_token::Token;

const T0: u64 = 1_700_000_040;
const UC_TS: u64 = 1_700_000_900;

struct Rotated {
    w: World,
    /// epoch 3 (from round 1000, ended at round 2000)
    r3: Root,
    /// epoch 4 (from round 2000, current)
    r4: Root,
    out: TokenOut,
    /// a bridge that holds epochs 2 to 4
    held: NativeBridge,
}

fn rotated() -> Rotated {
    let w = make_world(20);
    let out = build_token(
        &w,
        &spec(1),
        &[tx_step(2, 7, T0 + 10), burn_step(T0 + 20)],
        T0,
        UC_TS,
    );
    let r3 = next_epoch(&w.agg, 1000, 4, 30);
    let r4 = next_epoch(&r3, 2000, 4, 40);
    let held = NativeBridge::new(w.bridge.registry.clone(), trust_input(&r4)).unwrap();
    Rotated {
        w,
        r3,
        r4,
        out,
        held,
    }
}

/// The held token with every leaf re-anchored under one certificate sealed by `by` claiming root
/// epoch `epoch` at root round 2500.
fn forged(x: &Rotated, by: &Root, epoch: u64) -> Token {
    let leaves = &x.out.leaves;
    let (root, _) = tree(leaves, &leaves[0].0);
    let uc = make_uc(
        by,
        &UcSpec {
            partition: AGG_PARTITION,
            conf: x.w.agg_conf.to_vec(),
            epoch_ir: 1,
            root_epoch: epoch,
            round: 2500,
            timestamp: UC_TS + 5000,
            state_hash: root.to_vec(),
            block_hash: None,
            signers: 4,
        },
    );
    let all: Vec<&InclusionProof> = std::iter::once(x.out.token.genesis().inclusion_proof())
        .chain(
            x.out
                .token
                .transactions()
                .iter()
                .map(|t| t.inclusion_proof()),
        )
        .collect();
    let proofs: Vec<InclusionProof> = all
        .iter()
        .enumerate()
        .map(|(i, old)| InclusionProof {
            certification_data: old.certification_data.clone(),
            reference_time: old.reference_time,
            inclusion_certificate: InclusionCertificate::decode(&tree(leaves, &leaves[i].0).1)
                .unwrap(),
            unicity_certificate: uc.clone(),
        })
        .collect();
    refresh_token(&x.out.token, &proofs).unwrap()
}

#[test]
fn control_the_current_committees_anchor_verifies_and_builds_a_return_proof() {
    let x = rotated();
    let token = forged(&x, &x.r4, 4);
    x.held.verify_native_token(&token, Expect::Return).unwrap();
    let (env, _, _) = build_return_proof(&x.held, &token).unwrap();
    assert_eq!(env.anchors.len(), 1);
}

#[test]
fn the_retired_epoch_2_committee_claiming_its_own_epoch_after_its_end_is_refused() {
    let x = rotated();
    let token = forged(&x, &x.w.agg, 2);
    assert_eq!(
        x.held
            .verify_native_token(&token, Expect::Return)
            .unwrap_err(),
        E::SealEpoch
    );
    assert_eq!(
        build_return_proof(&x.held, &token).unwrap_err(),
        E::SealEpoch
    );
}

#[test]
fn the_retired_epoch_2_committee_claiming_the_current_epoch_is_no_quorum() {
    let x = rotated();
    let token = forged(&x, &x.w.agg, 4);
    assert_eq!(
        x.held
            .verify_native_token(&token, Expect::Return)
            .unwrap_err(),
        E::QuorumNotMet
    );
    assert_eq!(
        build_return_proof(&x.held, &token).unwrap_err(),
        E::QuorumNotMet
    );
}

#[test]
fn the_epoch_3_committee_retired_at_round_2000_is_refused_like_epoch_2s() {
    let x = rotated();
    for (epoch, want) in [(3, E::SealEpoch), (4, E::QuorumNotMet)] {
        let token = forged(&x, &x.r3, epoch);
        assert_eq!(
            x.held
                .verify_native_token(&token, Expect::Return)
                .unwrap_err(),
            want
        );
    }
}
