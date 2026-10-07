#![allow(
    clippy::type_complexity,
    clippy::ptr_arg,
    unused_imports,
    unused_variables,
    dead_code
)]
mod common;
use common::*;
use native_bridge_sdk_ext::resources::{preflight_token, preflight_uc};
use native_bridge_sdk_ext::token::Expect;
use native_bridge_sdk_ext::NativeError as E;
use unicity_token::api::bft::{HashStep, ShardId, UnicityCertificate};
use unicity_token::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint, Decoder};
use unicity_token::transaction::{CertifiedMintTransaction, CertifiedTransferTransaction, Token};

fn change_uc(token: &Token, mut f: impl FnMut(&mut UnicityCertificate)) -> Token {
    let mut p = token.genesis().inclusion_proof().clone();
    f(&mut p.unicity_certificate);
    let g = CertifiedMintTransaction::new(token.genesis().transaction().clone(), p);
    let txs = token
        .transactions()
        .iter()
        .map(|t| {
            let mut p = t.inclusion_proof().clone();
            f(&mut p.unicity_certificate);
            CertifiedTransferTransaction::new(t.transaction().clone(), p)
        })
        .collect();
    Token::new(g, txs)
}
fn rejects(w: &World, token: &Token, e: E) {
    assert_eq!(
        w.bridge
            .verify_native_token_bytes(&token.to_cbor(), Expect::Receipt)
            .unwrap_err(),
        e
    );
    assert_eq!(
        w.bridge
            .verify_native_token(token, Expect::Receipt)
            .unwrap_err(),
        e
    );
}
fn sized_uc(base: &UnicityCertificate, target: usize) -> UnicityCertificate {
    let mut uc = base.clone();
    let mut shard = vec![0; 33];
    shard[32] = 128;
    uc.shard_tree_certificate.shard = ShardId::decode(&shard).unwrap();
    uc.shard_tree_certificate.sibling_hash_list = vec![vec![0; 32]; 256];
    uc.unicity_tree_certificate.steps = vec![
        HashStep {
            key: 1,
            hash: vec![0; 32]
        };
        32
    ];
    for count in 1..=64 {
        uc.unicity_seal.signatures = (0..count)
            .map(|i| (format!("{:x>128}", i), vec![0; 65]))
            .collect();
        uc.input_record.summary_value.clear();
        let base_len = uc.to_cbor().len();
        if base_len > target {
            continue;
        }
        let gap = target - base_len;
        for adjustment in 0..=2 {
            if gap < adjustment || gap - adjustment > 256 {
                continue;
            }
            uc.input_record.summary_value = vec![0; gap - adjustment];
            if uc.to_cbor().len() == target {
                return uc;
            }
        }
    }
    panic!("cannot size UC")
}
#[test]
fn ordinary_uc_byte_limit_on_bytes_and_decoded_tokens() {
    let w = make_world(20);
    let out = build_token(&w, &spec(1), &[], 1, 2);
    let at = sized_uc(
        &out.token.genesis().inclusion_proof().unicity_certificate,
        16384,
    );
    preflight_uc(&at.to_cbor()).unwrap();
    let token = change_uc(&out.token, |uc| *uc = at.clone());
    preflight_token(&token.to_cbor()).unwrap();
    rejects(&w, &token, E::ShardMismatch);
    for size in [16385, 17473] {
        let over = sized_uc(
            &out.token.genesis().inclusion_proof().unicity_certificate,
            size,
        );
        rejects(
            &w,
            &change_uc(&out.token, |uc| *uc = over.clone()),
            E::ProofTooLarge,
        );
    }
}
#[test]
fn otherwise_valid_receipt_cannot_hide_an_oversized_ordinary_uc_in_unknown_signatures() {
    let w = make_world(20);
    let out = build_token(&w, &spec(1), &[], 1, 2);
    let token = change_uc(&out.token, |uc| {
        uc.unicity_seal
            .signatures
            .push(("x".repeat(17000), vec![0; 65]))
    });
    rejects(&w, &token, E::ProofTooLarge);
}
#[test]
fn native_uc_sublimits_on_ordinary_and_standalone_embedded_certificates() {
    let w = make_world(20);
    let out = build_token(&w, &spec(1), &[], 1, 2);
    let mutations: Vec<Box<dyn Fn(&mut UnicityCertificate)>> = vec![
        Box::new(|uc| uc.input_record.summary_value = vec![0; 257]),
        Box::new(|uc| uc.shard_tree_certificate.shard = ShardId::decode(&[128; 34]).unwrap()),
        Box::new(|uc| uc.shard_tree_certificate.sibling_hash_list = vec![vec![0; 32]; 257]),
        Box::new(|uc| {
            uc.unicity_tree_certificate.steps = vec![
                HashStep {
                    key: 1,
                    hash: vec![0; 32]
                };
                33
            ]
        }),
        Box::new(|uc| uc.unicity_seal.signatures = vec![("x".repeat(129), vec![0; 65])]),
        Box::new(|uc| {
            uc.unicity_seal.signatures = (0..65).map(|i| (i.to_string(), vec![0; 65])).collect()
        }),
    ];
    for mutate in mutations {
        let token = change_uc(&out.token, mutate);
        assert_eq!(
            preflight_uc(
                &token
                    .genesis()
                    .inclusion_proof()
                    .unicity_certificate
                    .to_cbor()
            )
            .unwrap_err(),
            E::ProofTooLarge
        );
        rejects(&w, &token, E::ProofTooLarge);
    }
}
#[test]
fn uc_and_rsmt_paths_share_the_full_token_cumulative_budget() {
    let w = make_world(20);
    let steps: Vec<_> = (0..64)
        .map(|i| tx_step(i + 2, i + 1, (i + 2) as u64))
        .collect();
    let out = build_token(&w, &spec(1), &steps, 1, 100);
    let token = change_uc(&out.token, |uc| {
        uc.unicity_tree_certificate.steps = vec![
            HashStep {
                key: 1,
                hash: vec![0; 32]
            };
            32
        ]
    });
    rejects(&w, &token, E::TooManyPaths);
}
fn nested_payloads(token: &Token, justification: &[u8], data: &[u8]) -> Vec<u8> {
    let bytes = token.to_cbor();
    let root = Decoder::new(&bytes)
        .expect_tag(39040)
        .unwrap()
        .array(Some(3))
        .unwrap();
    let cert = root[1].array(Some(2)).unwrap();
    let mint = cert[0].expect_tag(39041).unwrap().array(Some(8)).unwrap();
    let mut fields: Vec<Vec<u8>> = mint.iter().map(|d| d.bytes().to_vec()).collect();
    fields[5] = encode_byte_string(justification);
    fields[6] = encode_byte_string(data);
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let mint = encode_tag(39041, &encode_array(&refs));
    encode_tag(
        39040,
        &encode_array(&[
            root[0].bytes(),
            &encode_array(&[&mint, cert[1].bytes()]),
            root[2].bytes(),
        ]),
    )
}
#[test]
fn nested_payloads_share_depth_and_item_budgets_with_the_outer_token() {
    let w = make_world(20);
    let out = build_token(&w, &spec(1), &[], 1, 2);
    let zeros = vec![&[0u8][..]; 16400];
    let payload = encode_array(&zeros);
    let bytes = nested_payloads(&out.token, &payload, &payload);
    assert_eq!(
        w.bridge
            .verify_native_token_bytes(&bytes, Expect::Receipt)
            .unwrap_err(),
        E::TooManyItems
    );
    assert_eq!(
        w.bridge
            .verify_native_token(&Token::from_cbor(&bytes).unwrap(), Expect::Receipt)
            .unwrap_err(),
        E::TooManyItems
    );
    let mut payload = encode_uint(0);
    for _ in 0..11 {
        payload = encode_array(&[&payload]);
    }
    let bytes = nested_payloads(&out.token, &payload, &[0xf6]);
    assert_eq!(
        w.bridge
            .verify_native_token_bytes(&bytes, Expect::Receipt)
            .unwrap_err(),
        E::TooDeep
    );
    assert_eq!(
        w.bridge
            .verify_native_token(&Token::from_cbor(&bytes).unwrap(), Expect::Receipt)
            .unwrap_err(),
        E::TooDeep
    );
    let mut payload = encode_array(&[]);
    for _ in 0..10 {
        payload = encode_array(&[&payload]);
    }
    let bytes = nested_payloads(&out.token, &payload, &[0xf6]);
    assert_eq!(
        w.bridge
            .verify_native_token_bytes(&bytes, Expect::Receipt)
            .unwrap_err(),
        E::TooDeep
    );
    assert_eq!(
        w.bridge
            .verify_native_token(&Token::from_cbor(&bytes).unwrap(), Expect::Receipt)
            .unwrap_err(),
        E::TooDeep
    );
}

#[test]
fn cumulative_path_boundary_includes_the_immutable_embedded_certificate() {
    let w = make_world(20);
    let steps: Vec<_> = (0..64)
        .map(|i| tx_step(i + 2, i + 1, (i + 2) as u64))
        .collect();
    let mut parts = lock_parts(&w, &spec(1));
    parts.uc.unicity_tree_certificate.steps = vec![
        HashStep {
            key: 1,
            hash: vec![0; 32]
        };
        32
    ];
    let out = build_token_with(&w, &spec(1), &parts, &Tweaks::default(), &steps, 1, 100);
    let rsmt: usize = std::iter::once(out.token.genesis().inclusion_proof())
        .chain(out.token.transactions().iter().map(|t| t.inclusion_proof()))
        .map(|p| (p.inclusion_certificate.encode().len() - 32) / 32)
        .sum();
    let make = |extra: usize| {
        let mut remaining = 2048 - 32 - rsmt + extra;
        let token = change_uc(&out.token, |uc| {
            let n = remaining.min(32);
            remaining -= n;
            uc.unicity_tree_certificate.steps = vec![
                HashStep {
                    key: 1,
                    hash: vec![0; 32]
                };
                n
            ];
        });
        assert_eq!(remaining, 0);
        token
    };
    preflight_token(&make(0).to_cbor()).unwrap();
    rejects(&w, &make(1), E::TooManyPaths);
}
