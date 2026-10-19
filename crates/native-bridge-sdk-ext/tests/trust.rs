#![allow(clippy::type_complexity, clippy::ptr_arg, unused_imports, dead_code)]
//! The trust input: a release bundle under its genesis EntryID; each seal verified by the SDK
//! under its own epoch's committee (weighted quorum, B1 seal rule, round interval).

mod common;
use common::*;
use native_bridge_sdk_ext::profile::from_hex;
use native_bridge_sdk_ext::trust::{verify_embedded_uc, TrustInput};
use native_bridge_sdk_ext::NativeError as E;
use unicity_token::api::bft::{TrustBaseHistory, UnicityCertificate};
use unicity_token::crypto::signer::Signer;

fn uc_in(root: &Root, signers: usize, root_epoch: u64, round: u64) -> UnicityCertificate {
    make_uc(
        root,
        &UcSpec {
            partition: 1,
            conf: vec![1; 32],
            epoch_ir: 1,
            root_epoch,
            round,
            timestamp: 1_700_000_000,
            state_hash: vec![0; 32],
            block_hash: Some(vec![2; 32]),
            signers,
        },
    )
}

fn uc_with(root: &Root, signers: usize) -> UnicityCertificate {
    uc_in(root, signers, 2, 200)
}

fn input(r: &Root) -> TrustInput {
    trust_input(r)
}

#[test]
fn embedded_uc_rule_is_the_sdk_weighted_quorum() {
    let r = make_root(2, 4, 10);
    verify_embedded_uc(&input(&r), &uc_with(&r, 3)).unwrap();
    assert_eq!(
        verify_embedded_uc(&input(&r), &uc_with(&r, 2)).unwrap_err(),
        E::QuorumNotMet
    );
}

#[test]
fn weighted_committee_threshold_is_two_thirds_of_the_weights() {
    // weights 98, 1, 1 in member order: W = 100, threshold 67
    let r = make_weighted_root(2, 3, 50, Some(&[98, 1, 1]));
    verify_embedded_uc(&input(&r), &uc_with(&r, 1)).unwrap();
    let mut light = uc_with(&r, 0);
    let d = light.unicity_seal.calculate_hash();
    for (id, s) in &r.signers[1..] {
        light
            .unicity_seal
            .signatures
            .push((id.clone(), s.sign(&d).encode().to_vec()));
    }
    assert_eq!(
        verify_embedded_uc(&input(&r), &light).unwrap_err(),
        E::QuorumNotMet
    );
}

#[test]
fn embedded_uc_rejects_wrong_network_root_and_insufficient_valid_count_like_the_sdk() {
    use unicity_token::transaction::Transaction;
    let w = make_world(20);
    let r = &w.agg;
    let ti = input(r);
    let out = build_token(&w, &spec(1), &[], 1_700_000_040, 1_700_000_900);
    let proof = out.token.genesis().inclusion_proof().clone();
    let sid = unicity_token::api::StateId::derive(
        out.token.genesis().transaction().lock_script(),
        out.token.genesis().transaction().source_state_hash(),
    );
    verify_embedded_uc(&ti, &proof.unicity_certificate).unwrap();
    proof
        .verify_for(&sid, proof.reference_time, ti.history())
        .unwrap();
    let sdk_error = |uc: unicity_token::api::bft::UnicityCertificate| {
        let mut p = proof.clone();
        p.unicity_certificate = uc;
        p.verify_for(&sid, p.reference_time, ti.history())
            .unwrap_err()
    };
    // Wrong network.
    let mut uc = proof.unicity_certificate.clone();
    uc.unicity_seal.network_id = unicity_token::api::NetworkId::new(NETWORK + 1).unwrap();
    assert_eq!(verify_embedded_uc(&ti, &uc).unwrap_err(), E::SealNetwork);
    assert_eq!(
        sdk_error(uc),
        unicity_token::verify::VerificationError::SealNetworkMismatch
    );
    // Wrong root: the seal hash no longer matches the recomputed tree.
    let mut uc = proof.unicity_certificate.clone();
    uc.unicity_seal.hash[0] ^= 1;
    assert_eq!(verify_embedded_uc(&ti, &uc).unwrap_err(), E::SealRoot);
    assert_eq!(
        sdk_error(uc),
        unicity_token::verify::VerificationError::SealRootMismatch
    );
    // Two valid, two corrupt: the native rule fails the seal on an invalid signature.
    let mut uc = proof.unicity_certificate.clone();
    uc.unicity_seal.signatures.truncate(2);
    let d = uc.unicity_seal.calculate_hash();
    for k in 2..4 {
        let mut bad = r.signers[k].1.sign(&d).encode().to_vec();
        bad[3] ^= 1;
        uc.unicity_seal
            .signatures
            .push((r.signers[k].0.clone(), bad));
    }
    assert_eq!(verify_embedded_uc(&ti, &uc).unwrap_err(), E::QuorumNotMet);
    assert_eq!(
        sdk_error(uc),
        unicity_token::verify::VerificationError::SealSignerInvalid
    );
}

#[test]
fn unknown_signers_fail_the_seal() {
    let r = make_root(2, 4, 10);
    let mut uc = uc_with(&r, 2);
    let d = uc.unicity_seal.calculate_hash();
    uc.unicity_seal
        .signatures
        .push(("stranger".into(), signer(250).sign(&d).encode().to_vec()));
    uc.unicity_seal
        .signatures
        .push(("dup".into(), r.signers[0].1.sign(&d).encode().to_vec()));
    assert_eq!(
        verify_embedded_uc(&input(&r), &uc).unwrap_err(),
        E::QuorumNotMet
    );
}

#[test]
fn each_seal_is_verified_under_its_own_epoch() {
    let r = make_root(2, 4, 10);
    let r3 = next_epoch(&r, 1000, 4, 30);
    // r holds epoch 2 only: a newer epoch is retryable, an older one invalid
    assert_eq!(
        verify_embedded_uc(&input(&r), &uc_in(&r3, 4, 3, 1500)).unwrap_err(),
        E::NoEntryForEpoch
    );
    assert_eq!(
        verify_embedded_uc(&input(&r), &uc_in(&r, 4, 1, 200)).unwrap_err(),
        E::SealEpoch
    );
    // r3 holds epochs 2 and 3: epoch 2 ends where epoch 3 starts
    let t3 = input(&r3);
    verify_embedded_uc(&t3, &uc_in(&r3, 3, 3, 1500)).unwrap();
    verify_embedded_uc(&t3, &uc_in(&r, 3, 2, 999)).unwrap();
    assert_eq!(
        verify_embedded_uc(&t3, &uc_in(&r, 4, 2, 1000)).unwrap_err(),
        E::SealEpoch
    );
    assert_eq!(
        verify_embedded_uc(&t3, &uc_in(&r3, 4, 3, 999)).unwrap_err(),
        E::SealEpoch
    );
    // epoch 3 is signed by its own committee only
    assert_eq!(
        verify_embedded_uc(&t3, &uc_in(&r, 4, 3, 1500)).unwrap_err(),
        E::QuorumNotMet
    );
}

#[test]
fn installation_requires_the_pinned_genesis_and_an_authenticated_chain() {
    let r = make_root(2, 4, 10);
    assert_eq!(
        TrustInput::from_bundle(&r.bundle, &[0; 32]).unwrap_err(),
        E::TrustBaseDigest
    );
    let mut trailing = r.bundle.clone();
    trailing.push(0);
    assert_eq!(
        TrustInput::from_bundle(&trailing, &r.pin).unwrap_err(),
        E::TrustBase
    );
    let r3 = next_epoch(&r, 1000, 4, 30);
    // a successor witnessed by a committee other than its predecessor's
    let forged = successor_entry(&r, 1000, 4, 31, &r3.signers);
    let bundle = TrustBaseHistory::from_trusted_chain(vec![r.entries[0].clone(), forged])
        .unwrap()
        .to_bundle();
    assert_eq!(
        TrustInput::from_bundle(&bundle, &r.pin).unwrap_err(),
        E::TrustBase
    );
    assert_eq!(input(&r3).history().latest().epoch, 3);
}

#[test]
fn a_foreign_epoch_inside_a_lock_proof_is_retryable_end_to_end() {
    let w = make_world(20);
    let s = spec(1);
    let mut parts = lock_parts(&w, &s);
    parts.uc.unicity_seal.epoch = 9;
    resign(&w.evm_root, &mut parts.uc, 4);
    let out = build_token_with(
        &w,
        &s,
        &parts,
        &Tweaks::default(),
        &[],
        1_700_000_040,
        1_700_000_900,
    );
    assert_eq!(
        w.bridge
            .verify_native_token(&out.token, native_bridge_sdk_ext::token::Expect::Receipt)
            .unwrap_err(),
        E::NoEntryForEpoch
    );
}

#[test]
fn the_shared_dev_trust_base_fixture_installs_under_its_pin() {
    // the same bytes as both SDKs' dev fixture: epochs 1..4, weighted from epoch 2
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/interop/utb-dev");
    let bundle = std::fs::read(dir.join("bft-trustbase.dev.bundle.cbor")).unwrap();
    let pin: [u8; 32] = from_hex(
        std::fs::read_to_string(dir.join("bft-trustbase.dev.genesis.entryid"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let t = TrustInput::from_bundle(&bundle, &pin).unwrap();
    assert_eq!(t.id(), pin);
    assert_eq!(t.network_id().id(), 3);
    assert_eq!(t.history().genesis().epoch, 1);
    assert_eq!(t.history().latest().epoch, 4);
    assert_eq!(t.history().get(2).unwrap().quorum_threshold, 7);
}
