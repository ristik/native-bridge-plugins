#![allow(
    clippy::type_complexity,
    clippy::ptr_arg,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    unused_imports,
    unused_variables,
    dead_code
)]
//! RLP, MPT, header, identifier derivations and the SDK registry adapters.

mod common;
use common::*;
use native_bridge_sdk_ext::mpt;
use native_bridge_sdk_ext::profile::*;
use native_bridge_sdk_ext::rlp;
use native_bridge_sdk_ext::verifier::{
    BridgedTokenIssuancePolicy, NativeLockJustificationVerifier,
};
use native_bridge_sdk_ext::NativeError as E;
use std::rc::Rc;

#[test]
fn rlp_rejects_every_noncanonical_form() {
    for (name, bad) in [
        ("one byte below 0x80 in long form", vec![0x81, 0x05]),
        ("long form for a short string", vec![0xb8, 0x01, 0xaa]),
        ("leading zero in length", vec![0xb9, 0x00, 0x40]),
        ("truncated body", vec![0x82, 0x01]),
        ("trailing bytes", vec![0x01, 0x02]),
        ("truncated list", vec![0xc2, 0x01]),
        ("empty input", vec![]),
    ] {
        assert_eq!(rlp::decode(&bad).unwrap_err(), E::RlpMalformed, "{name}");
    }
    assert!(rlp::decode(&[0x80]).is_ok());
    assert!(rlp::decode(&[0x7f]).is_ok());
    assert_eq!(
        rlp::decode(&[0x82, 0, 1]).unwrap().u64().unwrap_err(),
        E::RlpMalformed
    );
}

#[test]
fn rlp_depth_is_bounded() {
    let mut x = vec![0xc0];
    for _ in 0..40 {
        x = rlp::encode_list(&[&x]);
    }
    assert_eq!(rlp::decode(&x).unwrap_err(), E::RlpMalformed);
}

fn small_trie() -> ([u8; 32], Vec<Vec<u8>>, [u8; 32], Vec<u8>) {
    let entries: Vec<([u8; 32], Vec<u8>)> =
        (0..40u8).map(|i| (sha(&[i]), vec![i + 1; 3])).collect();
    let target = entries[7].0;
    let (root, proof) = trie(&entries, &target);
    (root, proof, target, entries[7].1.clone())
}

#[test]
fn mpt_accepts_the_exact_path_and_nothing_else() {
    let (root, proof, key, value) = small_trie();
    let refs: Vec<&[u8]> = proof.iter().map(Vec::as_slice).collect();
    assert_eq!(mpt::verify_proof(&root, &key, &refs).unwrap(), value);
    // extra, duplicate, missing, reordered, mutated
    let mut extra = refs.clone();
    extra.push(refs[0]);
    assert_eq!(
        mpt::verify_proof(&root, &key, &extra).unwrap_err(),
        E::MptMalformed
    );
    assert_eq!(
        mpt::verify_proof(&root, &key, &refs[..refs.len() - 1]).unwrap_err(),
        E::MptMalformed
    );
    assert_eq!(
        mpt::verify_proof(&root, &key, &[]).unwrap_err(),
        E::MptMalformed
    );
    if refs.len() > 1 {
        let mut rev = refs.clone();
        rev.swap(0, 1);
        assert_eq!(
            mpt::verify_proof(&root, &key, &rev).unwrap_err(),
            E::MptMalformed
        );
    }
    let mut m = proof.clone();
    m[0][5] ^= 1;
    let mr: Vec<&[u8]> = m.iter().map(Vec::as_slice).collect();
    assert_eq!(
        mpt::verify_proof(&root, &key, &mr).unwrap_err(),
        E::MptMalformed
    );
    // another key never verifies against this path, and another root never does either.
    assert!(mpt::verify_proof(&root, &sha(b"absent"), &refs).is_err());
    assert!(mpt::verify_proof(&[1; 32], &key, &refs).is_err());
}

#[test]
fn mpt_rejects_a_leaf_with_an_unused_key_suffix_or_a_short_key() {
    let (root, proof, key, _) = small_trie();
    let refs: Vec<&[u8]> = proof.iter().map(Vec::as_slice).collect();
    // A key one byte longer leaves the walk with unconsumed nibbles at the leaf.
    let mut longer = key.to_vec();
    longer.push(0);
    assert_eq!(
        mpt::verify_proof(&root, &longer, &refs).unwrap_err(),
        E::MptMalformed
    );
    // A key one byte shorter ends the leaf comparison early.
    assert_eq!(
        mpt::verify_proof(&root, &key[..31], &refs).unwrap_err(),
        E::MptMalformed
    );
}

#[test]
fn mpt_embedded_children_and_single_entry_tries() {
    // Small values produce embedded (< 32 byte) nodes deep in a branch; still verifies.
    let entries: Vec<([u8; 32], Vec<u8>)> = vec![
        ([0x10; 32], vec![1]),
        ([0x11; 32], vec![2]),
        ([0x20; 32], vec![3]),
    ];
    for (k, v) in &entries {
        let (root, proof) = trie(&entries, k);
        let refs: Vec<&[u8]> = proof.iter().map(Vec::as_slice).collect();
        assert_eq!(&mpt::verify_proof(&root, k, &refs).unwrap(), v);
    }
    let one = vec![([0x33; 32], vec![9; 40])];
    let (root, proof) = trie(&one, &one[0].0);
    let refs: Vec<&[u8]> = proof.iter().map(Vec::as_slice).collect();
    assert!(mpt::verify_proof(&root, &one[0].0, &refs).is_ok());
}

#[test]
fn hex_prefix_flags_are_validated() {
    // A leaf whose path byte carries flag nibble 4.
    let bad = rlp::encode_list(&[&rlp::encode_bytes(&[0x40]), &rlp::encode_bytes(&[1; 40])]);
    let root = keccak(&[&bad]);
    assert_eq!(
        mpt::verify_proof(&root, &[0u8; 32], &[&bad]).unwrap_err(),
        E::MptMalformed
    );
    // Even-length flag with a nonzero pad nibble.
    let bad = rlp::encode_list(&[&rlp::encode_bytes(&[0x21]), &rlp::encode_bytes(&[1; 40])]);
    let root = keccak(&[&bad]);
    assert_eq!(
        mpt::verify_proof(&root, &[0u8; 32], &[&bad]).unwrap_err(),
        E::MptMalformed
    );
}

#[test]
fn identifier_derivations_follow_the_family_domain_string() {
    let (n, rg, eg, c) = identity();
    let d = format!(
        "{n}:{}:{}:{c}:{}",
        "11".repeat(32),
        "22".repeat(32),
        "0".repeat(40)
    );
    assert_eq!(identity_domain(n, &rg, &eg, c), d);
    assert_eq!(
        derive_type(n, &rg, &eg, c),
        sha(format!("unicity-bridge:unicity-native:{d}").as_bytes())
    );
    assert_eq!(
        derive_asset(n, &rg, &eg, c),
        sha(format!("unicity-bridge-coin:unicity-native:{d}").as_bytes())
    );
    // Network or genesis changes alias nothing; the vault is not part of the type.
    assert_ne!(derive_type(n + 1, &rg, &eg, c), derive_type(n, &rg, &eg, c));
    assert_ne!(
        derive_type(n, &[0x12; 32], &eg, c),
        derive_type(n, &rg, &eg, c)
    );
    assert_ne!(derive_type(n, &rg, &eg, c + 1), derive_type(n, &rg, &eg, c));
    assert_ne!(derive_type(n, &rg, &eg, c), derive_asset(n, &rg, &eg, c));
}

#[test]
fn value_envelope_bytes_are_exact() {
    let aid = [0x5a; 32];
    let mut want = vec![0xd9, 0x98, 0x8a, 0x83, 0x01, 0x81, 0x82, 0x58, 0x20];
    want.extend(aid);
    want.extend([0x42, 0x03, 0xe8, 0xf6]);
    assert_eq!(value_envelope(&aid, &[3, 232]), want);
}

#[test]
fn cfg_and_policy_round_trip_and_reject_noncanonical_input() {
    let w = make_world(20);
    let b = w.dep.cfg.to_bytes();
    assert_eq!(Cfg::from_bytes(&b).unwrap(), w.dep.cfg);
    let mut t = b.clone();
    t.push(0);
    assert_eq!(Cfg::from_bytes(&t).unwrap_err(), E::Trailing);
    assert_eq!(Policy::from_bytes(&w.policy.to_bytes()).unwrap(), w.policy);
    assert_eq!(
        Policy::from_bytes(&[0u8; 513]).unwrap_err(),
        E::InputTooLarge
    );
}

#[test]
fn deployment_construction_rejects_forged_identity_and_policy() {
    use native_bridge_sdk_ext::deployment::Deployment;
    use native_bridge_sdk_ext::header::HeaderProfile;
    let w = make_world(20);
    let hp = HeaderProfile { fields: 20 };
    let mut c = w.dep.cfg.clone();
    c.ty[0] ^= 1;
    assert_eq!(
        Deployment::new(c, [0; 32], [0; 32], hp, w.policy.clone()).unwrap_err(),
        E::CfgMismatch
    );
    let mut c = w.dep.cfg.clone();
    c.aggregator_policy_hash[0] ^= 1;
    assert_eq!(
        Deployment::new(c, [0; 32], [0; 32], hp, w.policy.clone()).unwrap_err(),
        E::PolicyHash
    );
    let p = native_bridge_sdk_ext::profile::Policy::new(EVM_PARTITION, &[w.agg_conf]).unwrap();
    let mut c = w.dep.cfg.clone();
    c.aggregator_policy_hash = p.hash();
    assert_eq!(
        Deployment::new(c, [0; 32], [0; 32], hp, p).unwrap_err(),
        E::PolicyPartition
    );
    assert_eq!(
        Deployment::new(
            w.dep.cfg.clone(),
            [0; 32],
            [0; 32],
            HeaderProfile { fields: 19 },
            w.policy.clone()
        )
        .unwrap_err(),
        E::CfgMismatch
    );
}

#[test]
fn header_fields_are_each_pinned() {
    use native_bridge_sdk_ext::header::{decode, HeaderProfile};
    let p = HeaderProfile { fields: 20 };
    let good = header_rlp(&[7; 32], 5, 20);
    assert_eq!(decode(&good, p).unwrap().number, 5);
    assert_eq!(
        decode(&good, HeaderProfile { fields: 21 }).unwrap_err(),
        E::HeaderProfile
    );
    let list = rlp::decode(&good).unwrap();
    let f = list.list().unwrap();
    let rebuild = |i: usize, v: Vec<u8>| {
        let items: Vec<Vec<u8>> = f
            .iter()
            .enumerate()
            .map(|(j, x)| if j == i { v.clone() } else { x.raw().to_vec() })
            .collect();
        let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
        rlp::encode_list(&refs)
    };
    for (i, v, name) in [
        (1usize, rlp::encode_bytes(&[1; 32]), "uncle hash"),
        (7, rlp::encode_u64(1), "difficulty"),
        (15, rlp::encode_u64(0), "base fee"),
        (16, rlp::encode_bytes(&[1; 32]), "withdrawals root"),
        (17, rlp::encode_u64(1), "blob gas used"),
        (18, rlp::encode_u64(1), "excess blob gas"),
        (12, rlp::encode_bytes(&[0; 33]), "extra data"),
        (3, rlp::encode_bytes(&[1; 31]), "state root width"),
    ] {
        assert_eq!(
            decode(&rebuild(i, v), p).unwrap_err(),
            E::HeaderProfile,
            "{name}"
        );
    }
}

#[test]
fn sdk_registry_adapters_accept_and_reject_through_the_public_hooks() {
    use unicity_token::api::bft::{RootTrustBase, RootTrustBaseNodeInfo};
    use unicity_token::api::NetworkId;
    use unicity_token::verify::{
        verify_token_with_policy, MintJustificationRegistry, VerificationPolicy,
    };
    let w = make_world(20);
    let bridge = Rc::new(w.bridge.clone());
    let mut reg = MintJustificationRegistry::new();
    native_bridge_sdk_ext::verifier::install(bridge.clone(), &mut reg).unwrap();
    // The SDK's own count-based quorum is satisfied by this unit-stake committee.
    let tb = w.bridge.trust.base().clone();
    let pol = VerificationPolicy {
        require_token_data_verifier: true,
        ..Default::default()
    };
    let s = spec(1);
    let ok = build_token(&w, &s, &[], 1_700_000_040, 1_700_000_900);
    verify_token_with_policy(&ok.token, &tb, &reg, pol).unwrap();
    // A bad lock: rejected at the justification hook, exact reason on the owned verifier.
    let mut bad = spec(1);
    bad.evm.stored = Some([9; 32]);
    let out = build_token(&w, &bad, &[], 1_700_000_040, 1_700_000_900);
    assert!(verify_token_with_policy(&out.token, &tb, &reg, pol).is_err());
    let v = NativeLockJustificationVerifier::new(bridge.clone());
    assert_eq!(v.check(out.token.genesis()).unwrap_err(), E::LockDigest);
    v.check(ok.token.genesis()).unwrap();
    // No registry entry for the type: generic hooks refuse the data (the SDK default is fail-closed).
    let empty = MintJustificationRegistry::new();
    assert!(verify_token_with_policy(&ok.token, &tb, &empty, pol).is_err());
}

#[test]
fn issuance_policy_requires_the_exact_reason_and_envelope_and_no_split() {
    use unicity_token::cbor::*;
    let w = make_world(20);
    let bridge = Rc::new(w.bridge.clone());
    let p = BridgedTokenIssuancePolicy::new(bridge, &w.dep.cfg.ty);
    let s = spec(1);
    p.check(build_token(&w, &s, &[], 1, 2).token.genesis())
        .unwrap();
    let no_reason = Tweaks {
        mint_justification: Some(None),
        ..Default::default()
    };
    let g = |tw: &Tweaks| build_token_with(&w, &s, &lock_parts(&w, &s), tw, &[], 1, 2);
    assert_eq!(
        p.check(g(&no_reason).token.genesis()).unwrap_err(),
        E::IssuanceReason
    );
    let split = Tweaks {
        mint_justification: Some(Some(encode_tag(39047, &encode_array(&[&encode_uint(1)])))),
        ..Default::default()
    };
    assert_eq!(
        p.check(g(&split).token.genesis()).unwrap_err(),
        E::IssuanceReason
    );
    let bare = Tweaks {
        mint_data: Some(Some(encode_array(&[
            &encode_byte_string(&w.dep.cfg.aid),
            &encode_byte_string(&[3, 232]),
        ]))),
        ..Default::default()
    };
    assert_eq!(
        p.check(g(&bare).token.genesis()).unwrap_err(),
        E::IssuanceData
    );
    let other_ty = Tweaks {
        mint_ty: Some(vec![4; 32]),
        ..Default::default()
    };
    assert_eq!(
        p.check(g(&other_ty).token.genesis()).unwrap_err(),
        E::MintType
    );
}
