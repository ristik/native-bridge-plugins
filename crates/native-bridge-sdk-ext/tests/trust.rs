#![allow(clippy::type_complexity, clippy::ptr_arg, unused_imports, dead_code)]
//! The fixed-base profile: one pinned SDK trust base, unit weights, SDK count quorum.
//! Weighted, rotating and historical-authority scenarios are DEFERRED (common SDK work, bft-core#421).

mod common;
use common::*;
use native_bridge_sdk_ext::profile::from_hex;
use native_bridge_sdk_ext::trust::{check_fixed_profile, verify_embedded_uc, TrustInput};
use native_bridge_sdk_ext::NativeError as E;
use unicity_token::api::bft::{RootTrustBase, RootTrustBaseNodeInfo};
use unicity_token::crypto::signer::Signer;

fn uc_with(root: &Root, signers: usize) -> unicity_token::api::bft::UnicityCertificate {
    make_uc(
        root,
        &UcSpec {
            partition: 1,
            conf: vec![1; 32],
            epoch_ir: 1,
            root_epoch: 2,
            round: 200,
            timestamp: 1,
            state_hash: vec![0; 32],
            block_hash: None,
            signers,
        },
    )
}

fn input(r: &Root) -> TrustInput {
    trust_input(r)
}

#[test]
fn embedded_uc_rule_is_the_sdk_count_quorum() {
    let r = make_root(2, 4, 10);
    verify_embedded_uc(&input(&r), &uc_with(&r, 3)).unwrap();
    assert_eq!(
        verify_embedded_uc(&input(&r), &uc_with(&r, 2)).unwrap_err(),
        E::QuorumNotMet
    );
}

#[test]
fn embedded_uc_rejects_wrong_network_root_and_insufficient_valid_count_like_the_sdk() {
    use unicity_token::transaction::Transaction;
    let w = make_world(20);
    let r = &w.agg;
    let ti = input(r);
    let out = build_token(&w, &spec(1), &[], 1, 2);
    let proof = out.token.genesis().inclusion_proof().clone();
    let sid = unicity_token::api::StateId::derive(
        out.token.genesis().transaction().lock_script(),
        out.token.genesis().transaction().source_state_hash(),
    );
    verify_embedded_uc(&ti, &proof.unicity_certificate).unwrap();
    proof
        .verify_for(&sid, proof.reference_time, ti.base())
        .unwrap();
    let sdk_error = |uc: unicity_token::api::bft::UnicityCertificate| {
        let mut p = proof.clone();
        p.unicity_certificate = uc;
        p.verify_for(&sid, p.reference_time, ti.base()).unwrap_err()
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
    // Insufficient valid count: two valid, two corrupt.
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
        unicity_token::verify::VerificationError::QuorumNotMet
    );
}

#[test]
fn unknown_and_duplicate_signers_add_nothing() {
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
fn fixed_profile_guards_name_network_epoch_and_start_round() {
    let r = make_root(2, 4, 10);
    let ti = input(&r);
    let mut uc = uc_with(&r, 4);
    uc.unicity_seal.epoch = 3;
    resign(&r, &mut uc, 4);
    assert_eq!(verify_embedded_uc(&ti, &uc).unwrap_err(), E::EpochMismatch);
    let mut uc = uc_with(&r, 4);
    uc.unicity_seal.root_chain_round_number = 0;
    resign(&r, &mut uc, 4);
    assert_eq!(
        verify_embedded_uc(&ti, &uc).unwrap_err(),
        E::RoundBeforeEpochStart
    );
}

fn base(stakes: &[u64], threshold: u64, version: u64) -> RootTrustBase {
    let nodes = stakes
        .iter()
        .enumerate()
        .map(|(i, st)| RootTrustBaseNodeInfo {
            node_id: format!("n{i}"),
            signing_key: signer(40 + i as u8).public_key(),
            stake: *st,
        })
        .collect();
    RootTrustBase::new(
        version,
        unicity_token::api::NetworkId::new(NETWORK).unwrap(),
        2,
        1,
        nodes,
        threshold,
    )
}

#[test]
fn non_unit_or_non_matching_configurations_are_rejected_at_installation() {
    assert!(check_fixed_profile(&base(&[1, 1, 1, 1], 3, 1)).is_ok());
    assert!(check_fixed_profile(&base(&[1], 1, 1)).is_ok());
    assert!(check_fixed_profile(&base(&[1, 1, 1, 1, 1, 1, 1], 5, 1)).is_ok()); // 7 - 6/3 = 5
                                                                               // A heavy validator is never flattened into a unit one.
    assert_eq!(
        check_fixed_profile(&base(&[98, 1, 1], 3, 1)).unwrap_err(),
        E::UnsupportedTrustBase
    );
    assert_eq!(
        check_fixed_profile(&base(&[1, 1, 1, 1], 2, 1)).unwrap_err(),
        E::UnsupportedTrustBase
    );
    assert_eq!(
        check_fixed_profile(&base(&[1, 1, 1, 1], 4, 1)).unwrap_err(),
        E::UnsupportedTrustBase
    );
    assert_eq!(
        check_fixed_profile(&base(&[1, 1, 1, 1], 3, 0)).unwrap_err(),
        E::UnsupportedTrustBase
    );
    assert_eq!(
        check_fixed_profile(&base(&[], 1, 1)).unwrap_err(),
        E::UnsupportedTrustBase
    );
    assert_eq!(
        TrustInput::from_provisioned(base(&[2, 2], 2, 1), [0; 32]).unwrap_err(),
        E::UnsupportedTrustBase
    );
}

#[test]
fn installed_document_must_hash_to_the_pin_and_parse() {
    let r = make_root(2, 4, 10);
    let doc = trust_doc(&r);
    assert!(TrustInput::from_json(&doc, &sha(&doc)).is_ok());
    assert_eq!(
        TrustInput::from_json(&doc, &[0; 32]).unwrap_err(),
        E::TrustBaseDigest
    );
    // A semantically equivalent but differently serialised file has a different identity.
    let mut spaced = doc.clone();
    spaced.extend(b"\n");
    assert_ne!(sha(&spaced), sha(&doc));
    assert_eq!(
        TrustInput::from_json(&spaced, &sha(&doc)).unwrap_err(),
        E::TrustBaseDigest
    );
    let garbage = b"{not json".to_vec();
    assert_eq!(
        TrustInput::from_json(&garbage, &sha(&garbage)).unwrap_err(),
        E::TrustBase
    );
}

#[test]
fn a_weighted_document_cannot_be_installed() {
    let r = make_root(2, 4, 10);
    let doc = String::from_utf8(trust_doc(&r)).unwrap().replacen(
        "\"stake\":\"1\"",
        "\"stake\":\"98\"",
        1,
    );
    assert_eq!(
        TrustInput::from_json(doc.as_bytes(), &sha(doc.as_bytes())).unwrap_err(),
        E::UnsupportedTrustBase
    );
}

#[test]
fn lock_proof_naming_another_base_or_a_foreign_epoch_is_rejected_end_to_end() {
    // Mismatched trustBaseId: LockProofTrust (lock_proof.rs); foreign epoch: EpochMismatch here.
    let w = make_world(20);
    let s = spec(1);
    let mut parts = lock_parts(&w, &s);
    parts.uc.unicity_seal.epoch = 9;
    resign(&w.evm_root, &mut parts.uc, 4);
    let out = build_token_with(&w, &s, &parts, &Tweaks::default(), &[], 1, 2);
    assert_eq!(
        w.bridge
            .verify_native_token(&out.token, native_bridge_sdk_ext::token::Expect::Receipt)
            .unwrap_err(),
        E::EpochMismatch
    );
}

#[test]
#[ignore = "DEFERRED: (98,1,1) weighted acceptance — common SDK trust-base work, unsupported in the current bridge profile"]
fn deferred_weighted_acceptance() {}

#[test]
#[ignore = "DEFERRED: mixed historical/current committees, trust-base append/fetch, interval closure — common SDK work"]
fn deferred_historical_and_current_committees() {}

#[test]
#[ignore = "DEFERRED: old-J validity through rotation and full B1/SDK seal-acceptance parity — common SDK work"]
fn deferred_rotation_and_seal_parity() {}

#[test]
fn the_published_sdk_trust_base_fixture_installs_with_its_digest_as_the_id() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/vectors/config/sdk-root-trust-base.json");
    let bytes = std::fs::read(p).unwrap();
    assert_eq!(bytes.len(), 524);
    let pin: [u8; 32] =
        from_hex("e5454ae4fe566b05dab8c1b15c88a05356b8816b1cd66a2b7adcce184af27fb5")
            .unwrap()
            .try_into()
            .unwrap();
    let t = TrustInput::from_json(&bytes, &pin).unwrap();
    assert_eq!(t.id(), pin);
    assert_eq!(t.base().network_id.id(), 3);
    assert_eq!(t.base().epoch, 1);
    assert_eq!(t.base().epoch_start_round, 0);
    assert_eq!(t.base().root_nodes.len(), 1);
}
