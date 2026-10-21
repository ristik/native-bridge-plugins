#![allow(
    clippy::type_complexity,
    clippy::ptr_arg,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    unused_imports,
    unused_variables,
    dead_code
)]
//! The embedded lock proof: every binding of the offline verification is mutated in isolation and
//! must be rejected with its own named error. Nothing here has any network capability.

mod common;
use common::*;
use native_bridge_sdk_ext::lockproof::parse_justification;
use native_bridge_sdk_ext::profile::*;
use native_bridge_sdk_ext::token::{Expect, NativeBridge, VerifiedToken};
use native_bridge_sdk_ext::NativeError as E;
use unicity_token::crypto::signer::Signer;

const T0: u64 = 1_700_000_040;
const UC_TS: u64 = 1_700_000_900;

fn run(w: &World, s: &MintSpec, parts: &LockParts) -> Result<VerifiedToken, E> {
    let out = build_token_with(w, s, parts, &Tweaks::default(), &[], T0, UC_TS);
    w.bridge.verify_native_token(&out.token, Expect::Receipt)
}

fn mutated(f: impl FnOnce(&World, &mut LockParts, &mut MintSpec)) -> Result<VerifiedToken, E> {
    let w = make_world(20);
    let mut s = spec(1);
    let mut parts = lock_parts(&w, &s);
    f(&w, &mut parts, &mut s);
    run(&w, &s, &parts)
}

/// Mutate the EVM-side facts of the spec, then build the proof from the mutated spec.
fn mutated_spec(f: impl FnOnce(&mut MintSpec)) -> Result<VerifiedToken, E> {
    let w = make_world(20);
    let mut s = spec(1);
    f(&mut s);
    let parts = lock_parts(&w, &s);
    run(&w, &s, &parts)
}

fn flip(b: &mut Vec<u8>, i: usize) {
    let i = i.min(b.len() - 1);
    b[i] ^= 0x01;
}

#[test]
fn baseline_lock_proof_verifies() {
    mutated(|_, _, _| {}).unwrap();
}

#[test]
fn cfg_in_the_proof_must_equal_the_deployment() {
    assert_eq!(
        mutated(|_, p, _| p.cfg[0] ^= 1).unwrap_err(),
        E::LockProofCfg
    );
}

#[test]
fn trust_base_id_must_name_the_installed_trust_base() {
    assert_eq!(
        mutated(|_, p, _| p.trust_base_id[0] ^= 1).unwrap_err(),
        E::LockProofTrust
    );
}

#[test]
fn a_quorum_short_by_one_signature_is_rejected() {
    // Four equal-weight validators need three signatures (> 2/3 of the weight).
    let e = mutated(|w, p, _| resign(&w.evm_root, &mut p.uc, 2)).unwrap_err();
    assert_eq!(e, E::QuorumNotMet);
    // Three is enough.
    mutated(|w, p, _| resign(&w.evm_root, &mut p.uc, 3)).unwrap();
}

#[test]
fn a_signer_unknown_to_the_trust_base_fails_the_seal_as_in_the_sdk() {
    // The native (B1) rule the SDK applies: every signature must be a valid one of a committee
    // member; an extra stranger fails the seal even beside a full quorum.
    let e = mutated(|_, p, _| {
        let intruder = signer(200);
        let digest = p.uc.unicity_seal.calculate_hash();
        p.uc.unicity_seal.signatures.push((
            "intruder".to_string(),
            intruder.sign(&digest).encode().to_vec(),
        ));
    })
    .unwrap_err();
    assert_eq!(e, E::QuorumNotMet);
}

#[test]
#[ignore = "weighted or rotating committees: common SDK trust-base evolution, out of scope until it lands"]
fn weighted_quorum_and_epoch_rotation_are_future_sdk_work() {}

#[test]
fn invalid_signatures_of_known_members_fail_the_seal() {
    // Three genuine signatures plus one corrupt known member: the corrupt one fails the seal (B1).
    let e = mutated(|w, p, _| {
        resign(&w.evm_root, &mut p.uc, 3);
        let (id, sg) = &w.evm_root.signers[3];
        let mut bad = sg
            .sign(&p.uc.unicity_seal.calculate_hash())
            .encode()
            .to_vec();
        bad[10] ^= 1;
        p.uc.unicity_seal.signatures.push((id.clone(), bad));
    })
    .unwrap_err();
    assert_eq!(e, E::QuorumNotMet);
    // Two genuine plus two corrupt: no quorum.
    let e = mutated(|w, p, _| {
        resign(&w.evm_root, &mut p.uc, 2);
        for k in 2..4 {
            let (id, sg) = &w.evm_root.signers[k];
            let mut bad = sg
                .sign(&p.uc.unicity_seal.calculate_hash())
                .encode()
                .to_vec();
            bad[10] ^= 1;
            p.uc.unicity_seal.signatures.push((id.clone(), bad));
        }
    })
    .unwrap_err();
    assert_eq!(e, E::QuorumNotMet);
}

#[test]
fn seal_hash_not_matching_the_unicity_tree_is_rejected() {
    let e = mutated(|_, p, _| p.uc.unicity_seal.hash[0] ^= 1).unwrap_err();
    assert_eq!(e, E::SealRoot);
}

#[test]
fn certificate_of_another_network_is_rejected() {
    let e = mutated(|w, p, _| {
        p.uc.unicity_seal.network_id = unicity_token::api::NetworkId::new(NETWORK + 1).unwrap();
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap_err();
    assert_eq!(e, E::SealNetwork);
}

#[test]
fn certificate_for_the_wrong_partition_is_not_the_evm_partition() {
    let e = mutated(|w, p, _| {
        p.uc.unicity_tree_certificate.partition_identifier = EVM_PARTITION + 1;
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap_err();
    assert_eq!(e, E::EvmPartition);
}

#[test]
fn certificate_for_a_longer_shard_is_not_the_pinned_shard() {
    let e = mutated(|w, p, _| {
        p.uc.shard_tree_certificate.shard =
            unicity_token::api::bft::ShardId::decode(&[0x40]).unwrap();
        p.uc.shard_tree_certificate.sibling_hash_list = vec![vec![0u8; 32]];
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap_err();
    assert_eq!(e, E::EvmShard);
}

#[test]
fn pdr_not_hashing_to_the_certificate_configuration_is_rejected() {
    let e = mutated(|_, p, _| flip(&mut p.pdr, 3)).unwrap_err();
    assert_eq!(e, E::EvmConfigHash);
}

#[test]
fn pdr_changing_a_non_membership_setting_is_rejected_even_when_committed() {
    // A self-consistent certificate over a PDR whose t2 timeout differs from the genesis pin.
    let e = mutated(|w, p, _| {
        p.pdr = pdr_bytes(5, 1);
        p.uc.shard_configuration_hash = sha(&p.pdr).to_vec();
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap_err();
    assert_eq!(e, E::EvmConfigPin);
}

#[test]
fn pdr_changing_only_membership_or_epoch_start_keeps_the_pin() {
    // A later shard epoch whose certificate commits to its own PDR is admitted.
    mutated(|w, p, _| {
        p.pdr = pdr_bytes(6, 0);
        p.uc.shard_configuration_hash = sha(&p.pdr).to_vec();
        p.uc.input_record.epoch = 6;
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap();
}

#[test]
fn certified_shard_epoch_must_be_the_carried_pdrs_epoch() {
    let e = mutated(|w, p, _| {
        p.uc.input_record.epoch = 9;
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap_err();
    assert_eq!(e, E::EvmConfigPin);
}

#[test]
fn non_canonical_pdr_is_rejected() {
    // A non-shortest integer head inside the PDR, committed by the certificate.
    let e = mutated(|w, p, _| {
        let mut pdr = pdr_bytes(5, 0);
        // Replace the version `01` (second byte, after the array head) with the long form `18 01`.
        pdr.splice(1..2, [0x18, 0x01]);
        p.pdr = pdr;
        p.uc.shard_configuration_hash = sha(&p.pdr).to_vec();
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap_err();
    assert_eq!(e, E::EvmConfigPin);
}

#[test]
fn header_not_hashing_to_the_block_hash_is_rejected() {
    let e = mutated(|_, p, _| flip(&mut p.header, 40)).unwrap_err();
    assert_eq!(e, E::HeaderHash);
}

#[test]
fn signature_over_an_unrelated_state_root_is_insufficient() {
    // A genuine header, but the certified input-record state hash is another root.
    let e = mutated(|w, p, _| {
        p.uc.input_record.hash = Some(vec![0x5a; 32]);
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap_err();
    assert_eq!(e, E::HeaderRoot);
}

#[test]
fn missing_block_hash_is_rejected() {
    // a changed state with no block hash is not a native input record: refused by the certificate
    // check, before any header binding
    let e = mutated(|w, p, _| {
        p.uc.input_record.block_hash = None;
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap_err();
    assert_eq!(e, E::CertStructure);
    // a block hash that is not the header's
    let e = mutated(|w, p, _| {
        p.uc.input_record.block_hash = Some(vec![0x5b; 32]);
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap_err();
    assert_eq!(e, E::HeaderHash);
}

#[test]
fn header_outside_the_pinned_profile_is_rejected() {
    // A well-formed 21-field header under a deployment pinned to 20 fields.
    let e = mutated(|w, p, s| {
        let _ = s;
        let acct_root = native_bridge_sdk_ext::rlp::decode(&p.header)
            .unwrap()
            .list()
            .unwrap()[3]
            .bytes()
            .unwrap()
            .to_vec();
        let root: [u8; 32] = acct_root.try_into().unwrap();
        p.header = header_rlp(&root, 1234, 21);
        p.uc.input_record.block_hash = Some(keccak(&[&p.header]).to_vec());
        resign(&w.evm_root, &mut p.uc, 4);
    })
    .unwrap_err();
    assert_eq!(e, E::HeaderProfile);
}

#[test]
fn a_node_of_the_account_proof_changed_is_rejected() {
    let e = mutated(|_, p, _| flip(&mut p.account_nodes[0], 10)).unwrap_err();
    assert_eq!(e, E::AccountProof);
}

#[test]
fn an_extra_account_node_is_rejected() {
    let e = mutated(|_, p, _| {
        let dup = p.account_nodes[0].clone();
        p.account_nodes.push(dup);
    })
    .unwrap_err();
    assert_eq!(e, E::AccountProof);
}

#[test]
fn a_missing_account_node_is_rejected() {
    let e = mutated(|_, p, _| {
        p.account_nodes.pop();
    })
    .unwrap_err();
    assert_eq!(e, E::AccountProof);
}

#[test]
fn an_empty_account_proof_is_rejected() {
    assert_eq!(
        mutated(|_, p, _| p.account_nodes.clear()).unwrap_err(),
        E::LockProofShape
    );
}

#[test]
fn account_with_another_runtime_code_hash_is_rejected() {
    let e = mutated_spec(|s| s.evm.vault_code_hash = [0x77; 32]).unwrap_err();
    assert_eq!(e, E::AccountCode);
}

#[test]
fn a_storage_node_changed_is_rejected() {
    let e = mutated(|_, p, _| flip(&mut p.storage_nodes[0], 12)).unwrap_err();
    assert_eq!(e, E::StorageProof);
}

#[test]
fn an_extra_storage_node_is_rejected() {
    let e = mutated(|_, p, _| {
        let dup = p.storage_nodes[0].clone();
        p.storage_nodes.push(dup);
    })
    .unwrap_err();
    assert_eq!(e, E::StorageProof);
}

#[test]
fn proof_for_another_nonce_slot_is_rejected() {
    // The trie holds slot(99) too, but the mint is nonce 1 and the proof walks slot(5).
    let e = mutated_spec(|s| s.evm.nonce = 99).unwrap_err();
    assert_eq!(e, E::StorageProof);
}

#[test]
fn stored_digest_of_another_lock_is_rejected() {
    let e = mutated_spec(|s| s.evm.stored = Some([0x42; 32])).unwrap_err();
    assert_eq!(e, E::LockDigest);
}

#[test]
fn stored_digest_with_leading_zero_bytes_round_trips() {
    // A digest whose first byte is zero is stored without it and left-padded back.
    let w = make_world(20);
    let mut found = None;
    for n in 1..2000u64 {
        let mut s = spec(1);
        s.nonce = n;
        s.evm.nonce = n;
        if digest_of(&w, &s).0[0] == 0 {
            found = Some(s);
            break;
        }
    }
    let s = found.expect("a leading-zero digest exists in 2000 nonces");
    let parts = lock_parts(&w, &s);
    run(&w, &s, &parts).unwrap();
}

#[test]
fn zero_stored_value_is_rejected() {
    let e = mutated_spec(|s| s.evm.stored = Some([0; 32])).unwrap_err();
    assert_eq!(e, E::StorageValue);
}

#[test]
fn missing_embedded_proof_is_rejection_not_a_fetch() {
    // A pointer-only justification names no proof; verification never goes looking for one.
    use unicity_token::cbor::*;
    let w = make_world(20);
    let s = spec(1);
    let parts = lock_parts(&w, &s);
    let tw = Tweaks {
        mint_justification: Some(Some(encode_tag(
            39049,
            &encode_array(&[
                &encode_uint(2),
                &encode_uint(CHAIN_ID),
                &encode_byte_string(&VAULT),
                &encode_byte_string(&[0; 20]),
                &encode_uint(1),
                &encode_null(),
            ]),
        ))),
        ..Default::default()
    };
    let out = build_token_with(&w, &s, &parts, &tw, &[], T0, UC_TS);
    assert_eq!(
        w.bridge
            .verify_native_token(&out.token, Expect::Receipt)
            .unwrap_err(),
        E::LockProofShape
    );
}

#[test]
fn j_mutated_after_certification_breaks_the_certified_transaction_hash() {
    let w = make_world(20);
    let s = spec(1);
    let good = build_token(&w, &s, &[], T0, UC_TS);
    // Replace J in a copy of the mint: the proof's certification data no longer matches.
    let parts = lock_parts(&w, &s);
    let mut other = parts.clone();
    other.header[40] ^= 1;
    let altered = build_token_with(&w, &s, &other, &Tweaks::default(), &[], T0, UC_TS);
    let mut cert = good.token.genesis().clone();
    let swapped = unicity_token::transaction::CertifiedMintTransaction::new(
        altered.token.genesis().transaction().clone(),
        cert.inclusion_proof().clone(),
    );
    cert = swapped;
    let token = unicity_token::Token::new(cert, vec![]);
    let e = w
        .bridge
        .verify_native_token(&token, Expect::Receipt)
        .unwrap_err();
    // J itself is wrong first (the altered header), and the stale certification data would also
    // fail: either way the substituted justification never verifies.
    assert!(matches!(e, E::HeaderHash | E::CDMismatch), "{e}");
}

// ---- bounds ------------------------------------------------------------------------------------

fn parse_err(f: impl FnOnce(&mut LockParts)) -> E {
    let w = make_world(20);
    let s = spec(1);
    let mut parts = lock_parts(&w, &s);
    f(&mut parts);
    let b = built_from(&w, &s, &parts);
    parse_justification(&b.justification).unwrap_err()
}

fn parse_ok(f: impl FnOnce(&mut LockParts)) {
    let w = make_world(20);
    let s = spec(1);
    let mut parts = lock_parts(&w, &s);
    f(&mut parts);
    let b = built_from(&w, &s, &parts);
    parse_justification(&b.justification).unwrap();
}

#[test]
fn node_count_boundary_is_sixty_five() {
    parse_ok(|p| p.account_nodes = vec![vec![0xc0]; 65]);
    assert_eq!(
        parse_err(|p| p.account_nodes = vec![vec![0xc0]; 66]),
        E::LockProofTooLarge
    );
    parse_ok(|p| p.storage_nodes = vec![vec![0xc0]; 65]);
    assert_eq!(
        parse_err(|p| p.storage_nodes = vec![vec![0xc0]; 66]),
        E::LockProofTooLarge
    );
}

#[test]
fn node_size_boundary_is_one_kibibyte() {
    parse_ok(|p| p.account_nodes = vec![vec![1; 1024]]);
    assert_eq!(
        parse_err(|p| p.account_nodes = vec![vec![1; 1025]]),
        E::LockProofTooLarge
    );
    assert_eq!(
        parse_err(|p| p.storage_nodes = vec![vec![]]),
        E::LockProofShape
    );
}

#[test]
fn combined_node_bytes_boundary_is_twenty_four_kibibytes() {
    // 24 nodes of 1024 bytes are exactly 24 KiB.
    parse_ok(|p| {
        p.account_nodes = vec![vec![1; 1024]; 12];
        p.storage_nodes = vec![vec![1; 1024]; 12];
    });
    assert_eq!(
        parse_err(|p| {
            p.account_nodes = vec![vec![1; 1024]; 12];
            p.storage_nodes = vec![vec![1; 1024]; 12];
            p.storage_nodes.push(vec![1]);
        }),
        E::LockProofTooLarge
    );
}

#[test]
fn certificate_header_and_pdr_boundaries() {
    parse_ok(|p| p.uc_raw = Some(vec![1; 16 * 1024]));
    assert_eq!(
        parse_err(|p| p.uc_raw = Some(vec![1; 16 * 1024 + 1])),
        E::LockProofTooLarge
    );
    parse_ok(|p| p.header = vec![1; 2048]);
    assert_eq!(
        parse_err(|p| p.header = vec![1; 2049]),
        E::LockProofTooLarge
    );
    parse_ok(|p| p.pdr = vec![1; 16 * 1024]);
    assert_eq!(
        parse_err(|p| p.pdr = vec![1; 16 * 1024 + 1]),
        E::LockProofTooLarge
    );
    assert_eq!(parse_err(|p| p.header = vec![]), E::LockProofShape);
}

#[test]
fn over_bound_evidence_never_triggers_online_fallback() {
    let w = make_world(20);
    let s = spec(1);
    let mut parts = lock_parts(&w, &s);
    parts.account_nodes = vec![vec![0xc0]; 66];
    assert_eq!(run(&w, &s, &parts).unwrap_err(), E::ProofTooLarge);
}

#[test]
fn proof_arity_is_exact_and_nodes_must_be_byte_strings() {
    use unicity_token::cbor::*;
    let w = make_world(20);
    let s = spec(1);
    let parts = lock_parts(&w, &s);
    let good = parts.encode();
    // Seven elements instead of eight.
    let seven = {
        let root = native_bridge_sdk_ext::scan::scan_one(&good).unwrap();
        let kids = root.any_array().unwrap();
        let raws: Vec<Vec<u8>> = kids[..7].iter().map(|k| k.raw(&good).to_vec()).collect();
        let refs: Vec<&[u8]> = raws.iter().map(Vec::as_slice).collect();
        encode_array(&refs)
    };
    let j = native_bridge_sdk_ext::lockproof::encode_justification(
        CHAIN_ID, &VAULT, &[0; 20], 1, &seven,
    );
    assert_eq!(parse_justification(&j).unwrap_err(), E::LockProofShape);
    // Proof version 2.
    let mut v2 = good.clone();
    v2[1] = 0x02;
    let j =
        native_bridge_sdk_ext::lockproof::encode_justification(CHAIN_ID, &VAULT, &[0; 20], 1, &v2);
    assert_eq!(parse_justification(&j).unwrap_err(), E::LockProofShape);
}

/// The cfg and trustBaseId slots are the proof's own shape (bft-core decodeLockProof): a 31-byte value is ErrLockProofShape, not the
/// scanner's generic error.
#[test]
fn proof_cfg_and_trust_base_id_of_the_wrong_width_are_the_proofs_shape() {
    use unicity_token::cbor::*;
    let w = make_world(20);
    let good = lock_parts(&w, &spec(1)).encode();
    for slot in [1, 2] {
        let root = native_bridge_sdk_ext::scan::scan_one(&good).unwrap();
        let mut raws: Vec<Vec<u8>> = root
            .any_array()
            .unwrap()
            .iter()
            .map(|k| k.raw(&good).to_vec())
            .collect();
        raws[slot] = encode_byte_string(&[7; 31]);
        let refs: Vec<&[u8]> = raws.iter().map(Vec::as_slice).collect();
        let j = native_bridge_sdk_ext::lockproof::encode_justification(
            CHAIN_ID,
            &VAULT,
            &[0; 20],
            1,
            &encode_array(&refs),
        );
        assert_eq!(
            parse_justification(&j).unwrap_err(),
            E::LockProofShape,
            "slot {slot}"
        );
    }
}

#[test]
fn certificates_outside_the_sdk_decodable_subset_are_unsupported() {
    // Garbage, and a canonical-looking shape the SDK codec would re-encode differently.
    let e = mutated(|_, p, _| p.uc_raw = Some(vec![0xd9, 0x03, 0xe9, 0x80])).unwrap_err();
    assert_eq!(e, E::UnsupportedCertificateEncoding);
    let e = mutated(|_, p, _| {
        let mut raw = p.uc.to_cbor();
        raw.push(0);
        p.uc_raw = Some(raw);
    })
    .unwrap_err();
    assert_eq!(e, E::UnsupportedCertificateEncoding);
}

#[test]
fn an_epoch_change_is_retryable_until_held_then_verified_under_its_own_committee() {
    let w = make_world(20);
    // the root committee changes at round 1000 (epoch 3, witnessed by epoch 2's committee)
    let next = next_epoch(&w.evm_root, 1000, 4, 30);
    let old = make_root(2, 4, 10);
    let s = spec(1);
    let sealed = |root: &Root, epoch: u64, round: u64| {
        let mut parts = lock_parts(&w, &s);
        parts.uc.unicity_seal.epoch = epoch;
        parts.uc.unicity_seal.root_chain_round_number = round;
        resign(root, &mut parts.uc, 4);
        parts
    };
    // the bridge still holds only epoch 2: retryable, never invalid
    assert_eq!(
        run(&w, &s, &sealed(&next, 3, 1500)).unwrap_err(),
        E::NoEntryForEpoch
    );
    let cases = [
        (sealed(&next, 3, 1500), None),
        // before epoch 3's start
        (sealed(&next, 3, 500), Some(E::SealEpoch)),
        // epoch 3 signed by the old committee
        (sealed(&old, 3, 1500), Some(E::QuorumNotMet)),
        // epoch 2 has ended at round 1000
        (sealed(&old, 2, 1500), Some(E::SealEpoch)),
    ];
    // the wallet appended epoch 3
    let held = World {
        bridge: NativeBridge::new(w.bridge.registry.clone(), trust_input(&next)).unwrap(),
        ..w
    };
    for (parts, expected) in cases {
        assert_eq!(run(&held, &s, &parts).err(), expected);
    }
}

#[test]
fn several_faults_get_the_oracle_verdict() {
    // the seal epoch first, then the configuration, then the certificate
    let w = make_world(20);
    let next = next_epoch(&w.evm_root, 1000, 4, 30);
    let s = spec(1);
    // an epoch the history does not hold and a false root: retryable, never the root failure
    let mut parts = lock_parts(&w, &s);
    parts.uc.unicity_seal.epoch = 3;
    parts.uc.unicity_seal.root_chain_round_number = 1500;
    resign(&next, &mut parts.uc, 4);
    parts.uc.unicity_seal.hash[0] ^= 1;
    assert_eq!(run(&w, &s, &parts).unwrap_err(), E::NoEntryForEpoch);
    // an epoch the history does not hold and a configuration that is not the certificate's: the
    // epoch decides (lockproof's own epoch selection, before the PDR checks)
    let mut parts = lock_parts(&w, &s);
    parts.uc.unicity_seal.epoch = 3;
    parts.uc.unicity_seal.root_chain_round_number = 1500;
    resign(&next, &mut parts.uc, 4);
    flip(&mut parts.pdr, 3);
    assert_eq!(run(&w, &s, &parts).unwrap_err(), E::NoEntryForEpoch);
    // a configuration that is not the certificate's and a short quorum: the configuration first
    let e = mutated(|w, p, _| {
        resign(&w.evm_root, &mut p.uc, 2);
        flip(&mut p.pdr, 3);
    })
    .unwrap_err();
    assert_eq!(e, E::EvmConfigHash);
}

#[test]
fn seal_signature_widths_follow_the_b1_profile_rule() {
    // 64 bytes (r||s): accepted by the pre-scan and by the SDK verification, as by B1
    mutated(|w, p, _| {
        resign(&w.evm_root, &mut p.uc, 4);
        for (_, sig) in p.uc.unicity_seal.signatures.iter_mut() {
            sig.truncate(64);
        }
    })
    .unwrap();
    // 65 bytes with the recovery byte swapped between 0 and 1: ignored
    mutated(|w, p, _| {
        resign(&w.evm_root, &mut p.uc, 4);
        for (_, sig) in p.uc.unicity_seal.signatures.iter_mut() {
            sig[64] ^= 1;
        }
    })
    .unwrap();
    // recovery byte 2, and 63 bytes: refused by the pre-scan
    for f in [
        (|s: &mut Vec<u8>| s[64] = 2) as fn(&mut Vec<u8>),
        |s: &mut Vec<u8>| s.truncate(63),
    ] {
        let e = mutated(|w, p, _| {
            resign(&w.evm_root, &mut p.uc, 4);
            for (_, sig) in p.uc.unicity_seal.signatures.iter_mut() {
                f(sig);
            }
        })
        .unwrap_err();
        assert_eq!(e, E::UnsupportedCertificateEncoding);
    }
}
