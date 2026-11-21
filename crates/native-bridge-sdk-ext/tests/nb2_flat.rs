#![cfg(feature = "host")]

use native_bridge_sdk_ext::nb2::config::{decode_config, domain_of, production_params};
use native_bridge_sdk_ext::nb2::crypto::hu;
use native_bridge_sdk_ext::nb2::split::{
    decode_split_justification, decode_sum_proof, encode_split_justification, encode_sum_proof,
    parent_link, split_output_commitment,
};
use native_bridge_sdk_ext::nb2::token::{
    decode_token, encode_certification, encode_mint, encode_token, encode_transfer,
    signature_predicate, state_id, value_data, Token,
};
use native_bridge_sdk_ext::nb2::trust::TrustInput;
use native_bridge_sdk_ext::nb2::util::from_hex;
use native_bridge_sdk_ext::nb2::verify::{verdict_abi, verify_held, verify_return, verify_split};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/vectors/nb2-continuation-v1.1/"
);

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}{name}")).unwrap()
}

#[test]
fn independent_protocol_10_derivations_and_signed_child_bytes() {
    let gamma = read("gamma.bin");
    let cfg = decode_config(&gamma, &production_params()).unwrap();
    let domain = domain_of(&gamma);
    assert_eq!(domain.as_slice(), read("domain.bin"));
    let link = parent_link(
        &domain,
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 32],
        &[0x44; 32],
        &7u8.into(),
    );
    assert_eq!(link.as_slice(), read("parent-link.bin"));
    let mut mint = decode_token(&read("transcripts/one-split/evidence.bin"))
        .unwrap()
        .part
        .mint;
    mint.recipient = signature_predicate(
        &from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap(),
    );
    mint.salt = vec![0; 32];
    mint.deadline = None;
    mint.data = Some(value_data(&cfg.aid, &1u8.into()));
    mint.justification = Some(encode_split_justification(&link));
    let raw = encode_mint(&mint);
    assert_eq!(raw, read("child-mint.bin"));
    assert_eq!(hu(&[&raw]).as_slice(), read("child-mint-hash.bin"));
}

#[test]
fn independent_signed_transcripts() {
    let gamma = read("gamma.bin");
    let params = production_params();
    let cfg = decode_config(&gamma, &params).unwrap();
    let domain = domain_of(&gamma);
    for name in [
        "root",
        "transfers",
        "one-split",
        "depth-20",
        "held-sibling-0",
        "held-sibling-1",
        "held-sibling-2",
        "parent-over-32-pages",
        "transfers-600",
    ] {
        let evidence = read(&format!("transcripts/{name}/evidence.bin"));
        let trust = TrustInput::from_bundle(
            &read(&format!("transcripts/{name}/utb.cbor")),
            &cfg.root_genesis,
        )
        .unwrap();
        let expected = read(&format!("transcripts/{name}/verdict.bin"));
        let part = decode_token(&evidence).unwrap();
        assert_eq!(encode_token(&part), evidence, "{name}");
        for (i, level) in part.levels().enumerate() {
            let request = native_bridge_sdk_ext::nb2::tokenops::mint_request(&level.mint).unwrap();
            assert_eq!(request.tx, level.mint_raw);
            assert_eq!(request.cd, encode_certification(&level.mint_proof.cd));
            assert_eq!(
                hu(&[&level.mint_raw]).as_slice(),
                level.mint_proof.cd.tx_hash
            );
            if i == 0 {
                assert!(level.mint.justification.as_ref().unwrap().len() <= 65_536);
                assert!(level.mint_raw.len() <= 66_048);
            } else {
                assert!(level.mint_raw.len() <= 246);
                assert_eq!(
                    encode_sum_proof(&decode_sum_proof(&level.allocation).unwrap()),
                    level.allocation
                );
            }
            for (j, transfer) in level.transfers.iter().enumerate() {
                assert_eq!(encode_transfer(transfer), level.transfers_raw[j]);
                assert_eq!(
                    hu(&[&level.transfers_raw[j]]).as_slice(),
                    level.proofs[j].cd.tx_hash
                );
            }
        }
        if expected.is_empty() {
            assert!(
                verify_held(&cfg, &domain, &trust, &part)
                    .unwrap()
                    .amount
                    .bits()
                    > 0
            );
        } else {
            let v = verify_return(&gamma, &evidence, &trust, &params)
                .unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(verdict_abi(&v), expected, "{name}");
        }
    }
}

#[test]
fn held_siblings_require_their_allocation_and_their_certified_parent() {
    let gamma = read("gamma.bin");
    let cfg = decode_config(&gamma, &production_params()).unwrap();
    let domain = domain_of(&gamma);
    let trust = TrustInput::from_bundle(
        &read("transcripts/held-sibling-0/utb.cbor"),
        &cfg.root_genesis,
    )
    .unwrap();
    let mut part = decode_token(&read("transcripts/held-sibling-0/evidence.bin")).unwrap();
    let sibling = decode_token(&read("transcripts/held-sibling-1/evidence.bin")).unwrap();
    let parent = Token {
        part: part.ancestors[0].clone(),
        ancestors: Vec::new(),
    };
    let split = verify_split(&cfg, &domain, &trust, &parent).unwrap();
    assert_eq!(
        decode_split_justification(part.mint.justification.as_ref().unwrap()).unwrap(),
        split.link
    );
    let parent_id =
        native_bridge_sdk_ext::nb2::token::token_id_of(&parent.mint.salt, parent.mint.network);
    let mut changed = part.mint.clone();
    changed.deadline = Some(1);
    assert_ne!(
        split_output_commitment(&parent_id, &part.mint),
        split_output_commitment(&parent_id, &changed)
    );
    let parent_burn = &parent.proofs.last().unwrap().cd;
    assert_eq!(
        parent_link(
            &domain,
            &parent_id,
            &state_id(&parent_burn.source, &parent_burn.source_hash),
            &parent_burn.tx_hash,
            &split.manifest,
            &verify_split_amount(&part, &cfg, &domain, &trust)
        ),
        split.link
    );

    let valid = part.part.allocation.clone();
    part.part.allocation = sibling.part.allocation;
    assert!(verify_held(&cfg, &domain, &trust, &part).is_err());
    part.part.allocation = vec![0x80];
    assert!(verify_held(&cfg, &domain, &trust, &part).is_err());
    part.part.allocation = valid;
    part.ancestors.clear();
    assert!(verify_held(&cfg, &domain, &trust, &part).is_err());
}

fn verify_split_amount(
    part: &Token,
    cfg: &native_bridge_sdk_ext::nb2::config::Config,
    domain: &[u8; 32],
    trust: &TrustInput,
) -> num_bigint::BigUint {
    let mut head = part.ancestors[0].clone();
    head.transfers.pop();
    head.transfers_raw.pop();
    head.proofs.pop();
    verify_held(
        cfg,
        domain,
        trust,
        &Token {
            part: head,
            ancestors: Vec::new(),
        },
    )
    .unwrap()
    .amount
}

#[test]
fn framing_and_signed_size_bounds() {
    use native_bridge_sdk_ext::nb2::deposit::{decode_receipt_backing, encode_receipt_backing};
    use native_bridge_sdk_ext::nb2::tokenops::mint_request;

    let valid = read("transcripts/root/evidence.bin");
    let mut root = decode_token(&valid).unwrap().part.mint;
    let mut reason = decode_receipt_backing(root.justification.as_deref().unwrap()).unwrap();
    reason.proof.nodes = vec![vec![0; 1024]; 20];
    reason.proof.nodes.push(vec![0; 40_000]);
    let delta = 65_536 - encode_receipt_backing(&reason).len();
    reason
        .proof
        .nodes
        .last_mut()
        .unwrap()
        .resize(40_000 + delta, 0);
    let capped = encode_receipt_backing(&reason);
    assert_eq!(capped.len(), 65_536);
    root.justification = Some(capped);
    assert!(mint_request(&root).unwrap().tx.len() <= 66_048);
    reason.proof.nodes.last_mut().unwrap().push(0);
    root.justification = Some(encode_receipt_backing(&reason));
    assert!(mint_request(&root).is_err());

    let mut child = decode_token(&read("transcripts/one-split/evidence.bin"))
        .unwrap()
        .part
        .mint;
    let cfg = decode_config(&read("gamma.bin"), &production_params()).unwrap();
    child.network = u16::MAX;
    child.data = Some(value_data(
        &cfg.aid,
        &num_bigint::BigUint::from_bytes_be(&[255; 32]),
    ));
    child.deadline = Some(u64::MAX);
    assert!(mint_request(&child).unwrap().tx.len() <= 246);

    assert!(decode_token(&valid[..valid.len() - 1]).is_err());
    let mut version = valid.clone();
    version[5] = 0;
    assert!(decode_token(&version).is_err());
    let mut count = valid;
    count[6..14].fill(255);
    assert!(decode_token(&count).is_err());
}

#[test]
fn equivalent_external_certificate_preserves_the_return_identity() {
    use native_bridge_sdk_ext::nb2::trust::decode_uc;

    let gamma = read("gamma.bin");
    let params = production_params();
    let cfg = decode_config(&gamma, &params).unwrap();
    let trust = TrustInput::from_bundle(&read("transcripts/one-split/utb.cbor"), &cfg.root_genesis)
        .unwrap();
    let original = read("transcripts/one-split/evidence.bin");
    let mut token = decode_token(&original).unwrap();
    let original_mint = token.mint_raw.clone();
    let proof = token.ancestors[0].proofs.last_mut().unwrap();
    let mut uc = decode_uc(&proof.uc).unwrap();
    // A canonical extra witness for a nonmember contributes zero weight.
    uc.unicity_seal
        .signatures
        .push(("zz-test-nonmember".into(), vec![0; 65]));
    proof.uc = uc.to_cbor();
    let refreshed = encode_token(&token);
    assert_ne!(refreshed, original);
    assert_eq!(decode_token(&refreshed).unwrap().mint_raw, original_mint);
    assert_eq!(
        verify_return(&gamma, &refreshed, &trust, &params).unwrap(),
        verify_return(&gamma, &original, &trust, &params).unwrap(),
    );
}
