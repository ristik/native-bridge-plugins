#![allow(
    clippy::type_complexity,
    clippy::ptr_arg,
    unused_imports,
    unused_variables,
    dead_code
)]
//! Cross-stack replay: every fixture generated with the TypeScript SDK constructors is verified here
//! with the Rust crate and must yield the same sentinel; the positives are also rebuilt with the Rust
//! SDK constructors and must match byte for byte. The fixtures are provisional (not the normative
//! corpus).

mod common;
use common::*;
use native_bridge_sdk_ext::deployment::{Deployment, DeploymentRegistry};
use native_bridge_sdk_ext::header::HeaderProfile;
use native_bridge_sdk_ext::profile::*;
use native_bridge_sdk_ext::token::{Expect, NativeBridge};
use native_bridge_sdk_ext::trust::TrustInput;
use serde_json::Value;

fn fixtures() -> Value {
    let p =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/interop/fixtures.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    from_hex(v.as_str().unwrap()).unwrap()
}

fn bridge(f: &Value) -> NativeBridge {
    let doc = hx(&f["trustDocument"]);
    let trust = TrustInput::from_json(&doc, &sha(&doc)).unwrap();
    let d = &f["deployment"];
    let cfg = Cfg::from_bytes(&hx(&d["cfg"])).unwrap();
    let policy = Policy::from_bytes(&hx(&d["policy"])).unwrap();
    let dep = Deployment::new(
        cfg,
        hx(&d["vaultCodeHash"]).try_into().unwrap(),
        hx(&d["evmConfigHash"]).try_into().unwrap(),
        HeaderProfile {
            fields: d["headerFields"].as_u64().unwrap() as u8,
        },
        policy,
    )
    .unwrap();
    NativeBridge::new(DeploymentRegistry::new(vec![dep]).unwrap(), trust).unwrap()
}

#[test]
fn every_typescript_fixture_has_the_same_verdict_in_rust() {
    let f = fixtures();
    let b = bridge(&f);
    let mut n = 0;
    for c in f["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let expect = if c["expect"] == "return" {
            Expect::Return
        } else {
            Expect::Receipt
        };
        let got = match b.verify_native_token_bytes(&hx(&c["token"]), expect) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.name().to_string(),
        };
        assert_eq!(got, c["result"].as_str().unwrap(), "{name}");
        n += 1;
    }
    assert!(n >= 17);
}

#[test]
fn rust_world_matches_the_typescript_world() {
    let f = fixtures();
    let w = make_world(20);
    let d = &f["deployment"];
    assert_eq!(w.dep.cfg.to_bytes(), hx(&d["cfg"]));
    assert_eq!(w.policy.to_bytes(), hx(&d["policy"]));
    assert_eq!(trust_doc(&w.agg), hx(&f["trustDocument"]));
    assert_eq!(w.dep.evm_config_hash.to_vec(), hx(&d["evmConfigHash"]));
}

fn token_hex(f: &Value, name: &str) -> Vec<u8> {
    let c = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap();
    hx(&c["token"])
}

#[test]
fn rust_constructors_reproduce_the_typescript_positives_byte_for_byte() {
    let f = fixtures();
    let w = make_world(20);
    let (t0, ts) = (1_700_000_040u64, 1_700_000_900u64);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "receipt_genesis",
            build_token(&w, &spec(1), &[], t0, ts).token.to_cbor(),
        ),
        (
            "receipt_two_transfers",
            build_token(
                &w,
                &spec(1),
                &[tx_step(2, 7, t0 + 10), tx_step(3, 8, t0 + 20)],
                t0,
                ts,
            )
            .token
            .to_cbor(),
        ),
        (
            "return_burn",
            build_token(
                &w,
                &spec(1),
                &[tx_step(2, 7, t0 + 10), burn_step(t0 + 20)],
                t0,
                ts,
            )
            .token
            .to_cbor(),
        ),
        ("receipt_explicit_deadlines", {
            let mut s = spec(1);
            s.mint_deadline = Some(t0 + 1);
            build_token(
                &w,
                &s,
                &[Step::Transfer {
                    to: signer(2),
                    mask: 7,
                    deadline: Some(t0 + 11),
                    t: t0 + 10,
                }],
                t0,
                ts,
            )
            .token
            .to_cbor()
        }),
    ];
    for (name, bytes) in cases {
        assert_eq!(bytes, token_hex(&f, name), "{name}");
    }
}

#[test]
fn native_go_pdr_encoding_and_both_hash_preimages_match_independent_construction() {
    let f: Value =
        serde_json::from_str(include_str!("../../../tests/interop/native-pdr.json")).unwrap();
    let native = hx(&f["native"]);
    assert_eq!(pdr_bytes(5, 0), native);
    assert_eq!(sha(&native).as_slice(), hx(&f["fullHash"]));
    assert_eq!(sha(&hx(&f["neutralized"])).as_slice(), hx(&f["configHash"]));
    assert_eq!(pdr_config_hash().as_slice(), hx(&f["configHash"]));
    assert_eq!(
        native_bridge_sdk_ext::lockproof::config_hash_of_pdr(&native)
            .unwrap()
            .as_slice(),
        hx(&f["configHash"])
    );
    assert_eq!(
        native_bridge_sdk_ext::scan::pdr_elements(&native[3..]).unwrap_err(),
        native_bridge_sdk_ext::NativeError::Shape
    );
    let mut wrong_tag = native.clone();
    wrong_tag[2] ^= 1;
    assert_eq!(
        native_bridge_sdk_ext::scan::pdr_elements(&wrong_tag).unwrap_err(),
        native_bridge_sdk_ext::NativeError::Tag
    );
}
