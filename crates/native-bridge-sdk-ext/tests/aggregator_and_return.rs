#![allow(
    clippy::type_complexity,
    clippy::ptr_arg,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    unused_imports,
    unused_variables,
    dead_code
)]
//! Aggregator admission, refresh preserving `t`, and the return envelope.

mod common;
use common::*;
use native_bridge_sdk_ext::envelope::*;
use native_bridge_sdk_ext::proof::{build_return_proof, refresh_token};
use native_bridge_sdk_ext::token::Expect;
use native_bridge_sdk_ext::NativeError as E;
use unicity_token::api::{InclusionCertificate, InclusionProof};
use unicity_token::transaction::Transaction;

const T0: u64 = 1_700_000_040;
const UC_TS: u64 = 1_700_000_900;

fn ret(w: &World) -> TokenOut {
    build_token(
        w,
        &spec(1),
        &[tx_step(2, 7, T0 + 10), burn_step(T0 + 20)],
        T0,
        UC_TS,
    )
}

#[test]
fn return_envelope_round_trips_and_passes_policy_and_anchor_checks() {
    let w = make_world(20);
    let out = ret(&w);
    let (env, v) = build_return_proof(&w.bridge, &out.token).unwrap();
    let bytes = env.encode();
    let back = Envelope::decode(&bytes).unwrap();
    assert_eq!(back, env);
    assert_eq!(env.leaf_proofs.len(), 3);
    check_policy(&w.dep.cfg, &back, 3).unwrap();
    let times: Vec<u64> = v.outcome.leaves.iter().map(|l| l.reference_time).collect();
    let ir = check_anchor(&back.anchors[0], &times).unwrap();
    assert_eq!(ir.timestamp, UC_TS);
}

#[test]
fn envelope_framing_is_canonical() {
    let w = make_world(20);
    let (env, _) = build_return_proof(&w.bridge, &ret(&w).token).unwrap();
    let good = env.encode();
    let mut trailing = good.clone();
    trailing.extend([0u8; 32]);
    assert_eq!(Envelope::decode(&trailing).unwrap_err(), E::ABIFraming);
    let mut unaligned = good.clone();
    unaligned.push(0);
    assert_eq!(Envelope::decode(&unaligned).unwrap_err(), E::ABIFraming);
    let mut pad = good.clone();
    // Dirty padding after the (non-multiple-of-32) policy body.
    let off = 4 * 32 + 32 + env.policy_body.len();
    pad[off] = 1;
    assert_eq!(Envelope::decode(&pad).unwrap_err(), E::ABIFraming);
}

#[test]
fn policy_check_names_each_tuple_mismatch() {
    let w = make_world(20);
    let (env, _) = build_return_proof(&w.bridge, &ret(&w).token).unwrap();
    let cfg = &w.dep.cfg;
    let mut e = env.clone();
    e.policy_body[3] ^= 1;
    assert_eq!(check_policy(cfg, &e, 3).unwrap_err(), E::PolicyHash);
    let mut e = env.clone();
    e.anchors.push(e.anchors[0].clone());
    assert_eq!(check_policy(cfg, &e, 3).unwrap_err(), E::PolicyAnchors);
    let mut e = env.clone();
    e.anchors[0].shard = vec![0x40];
    assert_eq!(check_policy(cfg, &e, 3).unwrap_err(), E::PolicyTuple);
    let mut e = env.clone();
    e.anchors[0].partition += 1;
    assert_eq!(check_policy(cfg, &e, 3).unwrap_err(), E::PolicyTuple);
    assert_eq!(check_policy(cfg, &env, 2).unwrap_err(), E::PolicyLeafCount);
    let mut e = env.clone();
    e.leaf_proofs[1].anchor_index = 1;
    assert_eq!(check_policy(cfg, &e, 3).unwrap_err(), E::PolicyLeafIndex);
}

#[test]
fn input_record_opening_is_bound_to_the_anchor() {
    let w = make_world(20);
    let (env, v) = build_return_proof(&w.bridge, &ret(&w).token).unwrap();
    let times: Vec<u64> = v.outcome.leaves.iter().map(|l| l.reference_time).collect();
    let mut a = env.anchors[0].clone();
    a.input_record[10] ^= 1; // false opening: hash no longer equals expectedIRHash
    assert_eq!(
        check_anchor(&a, &times).unwrap_err(),
        E::InputRecordMismatch
    );
    let mut a = env.anchors[0].clone();
    a.expected_state_root[0] ^= 1;
    assert_eq!(
        check_anchor(&a, &times).unwrap_err(),
        E::InputRecordMismatch
    );
    // A time later than the authenticated timestamp.
    assert_eq!(
        check_anchor(&env.anchors[0], &[UC_TS + 1]).unwrap_err(),
        E::ReferenceTimeFuture
    );
    assert!(check_anchor(&env.anchors[0], &[UC_TS]).is_ok());
}

#[test]
fn input_record_opening_rejects_wrong_shape() {
    use unicity_token::cbor::*;
    let ir9 = encode_tag(39002, &encode_array(&[&encode_uint(1)]));
    assert_eq!(parse_input_record(&ir9).unwrap_err(), E::Shape);
    let two = encode_uint(2);
    let ir = encode_tag(39002, &encode_array(&[two.as_slice(); 10]));
    assert_eq!(parse_input_record(&ir).unwrap_err(), E::Version);
    assert_eq!(
        parse_input_record(&vec![0u8; 1025]).unwrap_err(),
        E::InputTooLarge
    );
}

#[test]
fn mixed_anchors_cannot_be_assembled() {
    let w = make_world(20);
    let a = ret(&w);
    let b = build_token(
        &w,
        &spec(1),
        &[tx_step(2, 7, T0 + 10), burn_step(T0 + 20)],
        T0,
        UC_TS + 5,
    );
    let mixed =
        unicity_token::Token::new(a.token.genesis().clone(), b.token.transactions().to_vec());
    // Same leaves, different roots: assembly refuses and asks for a refresh to one root.
    assert!(build_return_proof(&w.bridge, &mixed).is_err());
}

fn fresh_proofs(w: &World, out: &TokenOut, extra: usize, ts: u64) -> Vec<InclusionProof> {
    // A later root containing the same leaves plus unrelated ones.
    let mut leaves = out.leaves.clone();
    for i in 0..extra {
        leaves.push((sha(&[i as u8, 9]), sha(&[i as u8, 10])));
    }
    let (root, _) = tree(&leaves, &leaves[0].0);
    let uc = make_uc(
        &w.agg,
        &UcSpec {
            partition: AGG_PARTITION,
            conf: w.agg_conf.to_vec(),
            epoch_ir: 1,
            root_epoch: 2,
            round: 950,
            timestamp: ts,
            state_hash: root.to_vec(),
            block_hash: None,
            signers: 4,
        },
    );
    let mut proofs = vec![];
    let all: Vec<&InclusionProof> = std::iter::once(out.token.genesis().inclusion_proof())
        .chain(out.token.transactions().iter().map(|t| t.inclusion_proof()))
        .collect();
    for (i, old) in all.iter().enumerate() {
        proofs.push(InclusionProof {
            certification_data: old.certification_data.clone(),
            reference_time: old.reference_time,
            inclusion_certificate: InclusionCertificate::decode(&tree(&leaves, &leaves[i].0).1)
                .unwrap(),
            unicity_certificate: uc.clone(),
        });
    }
    proofs
}

#[test]
fn refresh_to_a_later_anchor_preserves_t_and_j_and_verifies() {
    let w = make_world(20);
    let out = ret(&w);
    let fresh = fresh_proofs(&w, &out, 5, UC_TS + 5000);
    let refreshed = refresh_token(&out.token, &fresh).unwrap();
    assert_eq!(
        refreshed.genesis().transaction().justification(),
        out.token.genesis().transaction().justification()
    );
    assert_eq!(refreshed.genesis().reference_time(), T0);
    let v = w
        .bridge
        .verify_native_token(&refreshed, Expect::Return)
        .unwrap();
    assert_eq!(v.outcome.leaves[1].reference_time, T0 + 10);
    let (env, _) = build_return_proof(&w.bridge, &refreshed).unwrap();
    assert_eq!(
        parse_input_record(&env.anchors[0].input_record)
            .unwrap()
            .timestamp,
        UC_TS + 5000
    );
}

#[test]
fn refresh_that_changes_t_or_certification_data_is_rejected() {
    let w = make_world(20);
    let out = ret(&w);
    let mut fresh = fresh_proofs(&w, &out, 1, UC_TS + 10);
    fresh[1].reference_time += 1;
    assert_eq!(
        refresh_token(&out.token, &fresh).unwrap_err(),
        E::RefreshMismatch
    );
    let mut fresh = fresh_proofs(&w, &out, 1, UC_TS + 10);
    fresh[0].certification_data = fresh[1].certification_data.clone();
    assert_eq!(
        refresh_token(&out.token, &fresh).unwrap_err(),
        E::RefreshMismatch
    );
    assert_eq!(
        refresh_token(&out.token, &fresh[..2]).unwrap_err(),
        E::RefreshMismatch
    );
}

fn agg_err(f: impl FnOnce(&World, &mut UcSpec)) -> E {
    let w = make_world(20);
    let s = spec(1);
    let out = build_token(&w, &s, &[], T0, UC_TS);
    let mut u = UcSpec {
        partition: AGG_PARTITION,
        conf: w.agg_conf.to_vec(),
        epoch_ir: 1,
        root_epoch: 2,
        round: 900,
        timestamp: UC_TS,
        state_hash: out.uc.input_record.hash.clone(),
        block_hash: None,
        signers: 4,
    };
    f(&w, &mut u);
    let uc = make_uc(&w.agg, &u);
    let p = out.token.genesis().inclusion_proof().clone();
    let proof = InclusionProof {
        unicity_certificate: uc,
        ..p
    };
    let g = unicity_token::transaction::CertifiedMintTransaction::new(
        out.token.genesis().transaction().clone(),
        proof,
    );
    w.bridge
        .verify_native_token(&unicity_token::Token::new(g, vec![]), Expect::Receipt)
        .unwrap_err()
}

#[test]
fn aggregator_certificates_are_checked_against_the_pinned_policy() {
    assert_eq!(agg_err(|_, u| u.partition = 9), E::NotAdmitted);
    assert_eq!(agg_err(|_, u| u.conf = vec![9; 32]), E::NotAdmitted);
}

#[test]
fn aggregator_certificates_need_the_sdk_quorum() {
    assert_eq!(agg_err(|_, u| u.signers = 2), E::QuorumNotMet);
}

#[test]
fn aggregator_root_must_contain_the_leaf() {
    assert_eq!(
        agg_err(|_, u| u.state_hash = vec![0x13; 32]),
        E::PathInvalid
    );
}

#[test]
fn deployment_registry_rejects_duplicates_and_ambiguity() {
    use native_bridge_sdk_ext::deployment::DeploymentRegistry;
    let w = make_world(20);
    assert_eq!(
        DeploymentRegistry::new(vec![w.dep.clone(), w.dep.clone()]).unwrap_err(),
        E::AmbiguousDeployment
    );
    assert!(DeploymentRegistry::new(vec![w.dep.clone()]).is_ok());
}
