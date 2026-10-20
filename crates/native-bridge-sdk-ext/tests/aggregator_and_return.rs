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
use native_bridge_sdk_ext::certgroups::measure;
use native_bridge_sdk_ext::envelope::*;
use native_bridge_sdk_ext::gas::{compute_gate, kernel_request_bytes};
use native_bridge_sdk_ext::limits::{MAX_ANCHORS, MAX_LEAVES, TX_GAS_BUDGET};
use native_bridge_sdk_ext::proof::{build_return_proof, preflight_burn, refresh_token};
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
fn return_envelope_round_trips_and_passes_policy_anchor_and_gate_checks() {
    let w = make_world(20);
    let out = ret(&w);
    let (env, v, gate) = build_return_proof(&w.bridge, &out.token).unwrap();
    let bytes = env.encode();
    let back = Envelope::decode(&bytes).unwrap();
    assert_eq!(back, env);
    assert_eq!(env.leaf_proofs.len(), 3);
    assert_eq!(
        env.anchors.len(),
        1,
        "byte-identical certificates are one anchor"
    );
    let sids: Vec<[u8; 32]> = v.outcome.leaves.iter().map(|l| l.sid).collect();
    let pol = check_policy_body(&w.dep.cfg, &back).unwrap();
    let plan = plan_anchors(&pol, &back, &sids).unwrap();
    assert_eq!(plan.leaf_anchor, vec![0, 0, 0]);
    let times: Vec<u64> = v.outcome.leaves.iter().map(|l| l.reference_time).collect();
    let ir = check_anchors(&back, &plan, &times).unwrap();
    assert_eq!(ir[0].timestamp, UC_TS);
    assert!(gate.total <= TX_GAS_BUDGET);
    assert_eq!(gate.grouping.k, 1);
    assert_eq!(
        gate.j,
        17 + 4 + 12 + gate.grouping.items,
        "J: Cfg, policy, one IR opening and the UC occurrences"
    );
    assert_eq!(gate.items, 1000 * gate.j);
    assert_eq!(
        compute_gate(
            &w.dep.cfg.to_bytes(),
            bytes.len(),
            kernel_request_bytes(w.dep.cfg.to_bytes().len() as u64, back.history.len() as u64),
            &back,
            TX_GAS_BUDGET
        )
        .unwrap(),
        gate
    );
}

#[test]
fn envelope_framing_is_canonical() {
    let w = make_world(20);
    let (env, _, _) = build_return_proof(&w.bridge, &ret(&w).token).unwrap();
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
fn policy_and_anchor_table_checks_name_each_mismatch() {
    let w = make_world(20);
    let (env, v, _) = build_return_proof(&w.bridge, &ret(&w).token).unwrap();
    let cfg = &w.dep.cfg;
    let sids: Vec<[u8; 32]> = v.outcome.leaves.iter().map(|l| l.sid).collect();
    let plan = |e: &Envelope, ids: &[[u8; 32]]| {
        let pol = check_policy_body(cfg, e)?;
        plan_anchors(&pol, e, ids)
    };
    let mut e = env.clone();
    e.policy_body[3] ^= 1;
    assert_eq!(check_policy_body(cfg, &e).unwrap_err(), E::PolicyHash);
    let mut e = env.clone();
    e.anchors.clear();
    assert_eq!(check_policy_body(cfg, &e).unwrap_err(), E::PolicyAnchors);
    let mut e = env.clone();
    e.anchors.push(e.anchors[0].clone());
    assert_eq!(
        plan(&e, &sids).unwrap_err(),
        E::PolicyAnchors,
        "identical UC bytes are one anchor, never two"
    );
    let mut e = env.clone();
    e.anchors[0].shard = vec![if sids[0][0] & 0x80 != 0 { 0x40 } else { 0xc0 }];
    assert_eq!(
        plan(&e, &sids).unwrap_err(),
        E::PolicyLeafIndex,
        "a shard whose prefix the leaf does not carry"
    );
    let mut e = env.clone();
    e.anchors[0].shard = vec![0x00];
    assert_eq!(
        plan(&e, &sids).unwrap_err(),
        E::PolicyTuple,
        "a noncanonical shard ID"
    );
    let mut e = env.clone();
    e.anchors[0].partition += 1;
    assert_eq!(plan(&e, &sids).unwrap_err(), E::PolicyTuple);
    let mut e = env.clone();
    e.anchors[0].shard_conf_hash[0] ^= 1;
    assert!(
        plan(&e, &sids).is_ok(),
        "the configuration hash is authenticated by the UC (B1), not pinned by the policy"
    );
    assert_eq!(plan(&env, &sids[..2]).unwrap_err(), E::PolicyLeafCount);
    let mut e = env.clone();
    e.leaf_proofs[1].anchor_index = 1;
    assert_eq!(plan(&e, &sids).unwrap_err(), E::PolicyLeafIndex);
    let mut e = env.clone();
    let mut spare = e.anchors[0].clone();
    spare.uc.push(0);
    e.anchors.push(spare);
    assert_eq!(
        plan(&e, &sids).unwrap_err(),
        E::PolicyAnchors,
        "an anchor no leaf uses"
    );
}

#[test]
fn input_record_opening_is_bound_to_the_anchor() {
    let w = make_world(20);
    let (env, v, _) = build_return_proof(&w.bridge, &ret(&w).token).unwrap();
    let times: Vec<u64> = v.outcome.leaves.iter().map(|l| l.reference_time).collect();
    let one = AnchorPlan {
        leaf_anchor: vec![0, 0, 0],
    };
    let mut e = env.clone();
    e.anchors[0].input_record[10] ^= 1; // false opening: hash no longer equals expectedIRHash
    assert_eq!(check_anchors(&e, &one, &times).unwrap_err(), E::IROpening);
    let mut e = env.clone();
    e.anchors[0].expected_state_root[0] ^= 1;
    assert_eq!(check_anchors(&e, &one, &times).unwrap_err(), E::IRState);
    // A time later than the authenticated timestamp.
    assert_eq!(
        check_anchors(&env, &one, &[UC_TS + 1, UC_TS, UC_TS]).unwrap_err(),
        E::IRTime
    );
    assert!(check_anchors(&env, &one, &[UC_TS, UC_TS, UC_TS]).is_ok());
}

#[test]
fn input_record_opening_rejects_wrong_shape() {
    use unicity_token::cbor::*;
    let ir9 = encode_tag(39002, &encode_array(&[&encode_uint(1)]));
    assert_eq!(parse_input_record(&ir9).unwrap_err(), E::IRShape);
    let two = encode_uint(2);
    let ir = encode_tag(39002, &encode_array(&[two.as_slice(); 10]));
    assert_eq!(parse_input_record(&ir).unwrap_err(), E::IRShape);
    assert_eq!(parse_input_record(&vec![0u8; 513]).unwrap_err(), E::IRShape);
    // the summary value is bounded by the native sublimit the chain enforces (256 bytes)
    let ir_with = |summary: usize| {
        let one = encode_uint(1);
        let null = encode_null();
        let hash = encode_byte_string(&[0u8; 32]);
        let sum = encode_byte_string(&vec![0u8; summary]);
        let zero = encode_uint(0);
        let parts: [&[u8]; 10] = [
            &one, &one, &one, &null, &hash, &sum, &zero, &null, &zero, &null,
        ];
        encode_tag(39002, &encode_array(&parts))
    };
    assert_eq!(
        parse_input_record(&ir_with(256)).unwrap().state_hash,
        [0u8; 32]
    );
    assert_eq!(parse_input_record(&ir_with(257)).unwrap_err(), E::IRShape);
}

#[test]
fn an_over_bound_certificate_is_a_budget_refusal_any_other_shape_failure_is_malformed() {
    let w = make_world(20);
    let env = build_return_proof(&w.bridge, &ret(&w).token).unwrap().0;
    let a = &env.anchors[0];
    // 33 unicity steps (the bound is 32): spliced into the certificate's empty step list
    let at =
        a.uc.windows(4)
            .position(|x| x == [0xd9, 0x98, 0x5c, 0x83])
            .expect("the unicity tree certificate");
    let head = at + 4 + 1 + 1; // tag, array(3), version, partition (both one byte here)
    assert_eq!(a.uc[head], 0x80, "an empty step list");
    let mut over = a.clone();
    over.uc = [&a.uc[..head], &[0x98, 33], &[0xf6u8; 33], &a.uc[head + 1..]].concat();
    assert_eq!(measure(&[over], 0).unwrap_err(), E::TooManyItems);
    // 17 seal signatures (the bound is 16): the scan reads only the map's header, so patch the one map(4) header of the seal
    let seal =
        a.uc.windows(4)
            .position(|x| x == [0xd9, 0x98, 0x5d, 0x88])
            .expect("the seal");
    let mut hit = false;
    for i in seal..a.uc.len() {
        if a.uc[i] != 0xa4 {
            continue;
        }
        let mut sigs = a.clone();
        sigs.uc = [&a.uc[..i], &[0xb1], &a.uc[i + 1..]].concat();
        if measure(&[sigs], 0) == Err(E::TooManyItems) {
            hit = true;
            break;
        }
    }
    assert!(
        hit,
        "a seal signature count over the bound is a budget refusal"
    );
    let mut cut = a.clone();
    cut.uc.truncate(20);
    assert!(matches!(
        measure(&[cut], 0).unwrap_err(),
        E::Truncated | E::Shape | E::NonCanonical | E::Tag
    ));
}

#[test]
fn distinct_certificates_are_distinct_anchors_up_to_the_profile_bound() {
    let w = make_world(20);
    // genesis certified in one round, the transfers in another: two UCs, two anchors, first-use order
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
    let (env, _, _) = build_return_proof(&w.bridge, &mixed).unwrap();
    assert_eq!(env.anchors.len(), 2);
    assert_eq!(
        env.leaf_proofs
            .iter()
            .map(|l| l.anchor_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 1]
    );
    assert_ne!(env.anchors[0].uc, env.anchors[1].uc);
    // one certificate per leaf: up to MAX_ANCHORS distinct UCs are admitted when the gate passes
    assert_eq!(MAX_ANCHORS, 16);
    let per_leaf = |n: usize| {
        let tw = Tweaks {
            uc_round: Some(Box::new(|i| 900 + i as u64)),
            ..Tweaks::default()
        };
        let parts = lock_parts(&w, &spec(1));
        let mut steps: Vec<Step> = (0..n - 1)
            .map(|i| tx_step(i as u8 + 2, 7, T0 + 10 + i as u64))
            .collect();
        steps.push(burn_step(T0 + 20));
        build_token_with(&w, &spec(1), &parts, &tw, &steps, T0, UC_TS)
    };
    for n in [1usize, 2] {
        let out = per_leaf(n);
        assert_eq!(out.ucs.len(), n + 1);
        let (env, _, gate) = build_return_proof(&w.bridge, &out.token).unwrap();
        assert_eq!(env.anchors.len(), n + 1);
        assert!(gate.total <= TX_GAS_BUDGET);
    }
    // every leaf of a full 16-leaf history under its own certificate is MAX_ANCHORS anchors: admitted or priced out by the gate,
    // never truncated
    let full = per_leaf(MAX_LEAVES - 1);
    assert_eq!(full.ucs.len(), MAX_ANCHORS);
    match build_return_proof(&w.bridge, &full.token) {
        Ok((env, _, _)) => assert_eq!(env.anchors.len(), MAX_ANCHORS),
        Err(e) => assert_eq!(e, E::GasBudget),
    }
}

#[test]
fn consolidation_changes_the_seals_never_the_transactions_ids_times_or_the_nullifier() {
    // evidence 1c: before, the genesis and the transfers are certified in two rounds (two UCs); after, one later certificate
    let w = make_world(20);
    let a = ret(&w);
    let b = build_token(
        &w,
        &spec(1),
        &[tx_step(2, 7, T0 + 10), burn_step(T0 + 20)],
        T0,
        UC_TS + 5,
    );
    let before =
        unicity_token::Token::new(a.token.genesis().clone(), b.token.transactions().to_vec());
    let after = refresh_token(&before, &fresh_proofs(&w, &a, 0, UC_TS + 5000)).unwrap();
    let vb = w
        .bridge
        .verify_native_token(&before, Expect::Return)
        .unwrap();
    let va = w
        .bridge
        .verify_native_token(&after, Expect::Return)
        .unwrap();
    let ids = |v: &native_bridge_sdk_ext::token::VerifiedToken| -> Vec<([u8; 32], [u8; 32], u64)> {
        v.outcome
            .leaves
            .iter()
            .map(|l| (l.sid, l.tx_hash, l.reference_time))
            .collect()
    };
    assert_eq!(
        ids(&va),
        ids(&vb),
        "leaf IDs, transaction hashes, reference times"
    );
    assert_eq!(va.outcome.nullifier, vb.outcome.nullifier, "burn nullifier");
    assert_eq!(va.outcome.nonce, vb.outcome.nonce);
    let gb = build_return_proof(&w.bridge, &before).unwrap().2.grouping;
    let ga = build_return_proof(&w.bridge, &after).unwrap().2.grouping;
    assert_eq!((gb.s, ga.s), (2, 1));
    assert!(ga.q < gb.q);
    assert!(ga.e <= gb.e && ga.a < gb.a && ga.k < gb.k);
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
    let (env, _, _) = build_return_proof(&w.bridge, &refreshed).unwrap();
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
    agg_err_with(f, |_| {})
}

/// `agg_err` with a hook on the built certificate.
fn agg_err_with(
    f: impl FnOnce(&World, &mut UcSpec),
    g: impl FnOnce(&mut unicity_token::api::bft::UnicityCertificate),
) -> E {
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
        state_hash: out.uc.input_record.hash.clone().unwrap(),
        block_hash: None,
        signers: 4,
    };
    f(&w, &mut u);
    let mut uc = make_uc(&w.agg, &u);
    g(&mut uc);
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
fn aggregator_certificates_are_checked_against_the_pinned_partition() {
    assert_eq!(agg_err(|_, u| u.partition = 9), E::NotAdmitted);
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

#[test]
fn an_ordinary_proof_with_several_faults_gets_the_oracle_verdict() {
    // an epoch the history does not hold and a false seal root: the epoch decides (retryable)
    assert_eq!(
        agg_err_with(|_, u| u.root_epoch = 3, |uc| uc.unicity_seal.hash[0] ^= 1),
        E::NoEntryForEpoch
    );
}
