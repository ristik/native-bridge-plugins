#![allow(
    clippy::type_complexity,
    clippy::ptr_arg,
    unused_imports,
    unused_variables,
    dead_code
)]
mod common;
use common::*;
use native_bridge_sdk_ext::manifest;
use native_bridge_sdk_ext::profile::*;
use native_bridge_sdk_ext::token::Expect;
use native_bridge_sdk_ext::NativeError as E;
use serde_json::{json, Value};

fn exec_profile() -> Vec<u8> {
    br#"{"headerFields":20}"#.to_vec()
}

fn artifacts(hash: &[u8; 32]) -> Option<Vec<u8>> {
    let pdr = pdr_bytes(5, 0);
    [exec_profile(), pdr].into_iter().find(|b| &sha(b) == hash)
}

fn art(b: &[u8]) -> Value {
    json!({ "sha256": hex_lower(&sha(b)) })
}

fn rec(w: &World) -> Value {
    let c = &w.dep.cfg;
    json!({
      "vaultAddress": hex_lower(&c.vault),
      "vaultRuntimeHash": hex_lower(&sha(b"vault runtime")),
      "cfgHex": hex_lower(&c.to_bytes()),
      "cfgHash": hex_lower(&w.dep.cfg_hash),
      "tokenVerifierAddress": hex_lower(&c.token_verifier_address),
      "tokenVerifierRuntimeHash": hex_lower(&c.token_verifier_code_hash),
      "semanticProfile": { "sha256": hex_lower(&c.semantic_profile_hash) },
      "b1": {
        "profile": { "sha256": hex_lower(&c.b1_profile_hash) },
        "registryAddress": hex_lower(&[0x0b; 20]),
        "registryRuntimeHash": hex_lower(&sha(b"registry")),
        "registryLayout": art(b"layout"),
        "genesis": art(b"b1 genesis"),
      },
      "lockLayoutVersion": 1,
      "aggregatorPolicy": {
        "bodyHex": hex_lower(&w.policy.to_bytes()), "sha256": hex_lower(&w.policy.hash()),
        "partition": w.policy.partition, "shardHex": "80", "configurationHash": hex_lower(&w.policy.shard_conf),
      },
      "evmBackingPolicy": {
        "partition": c.evm_partition, "shardHex": hex_lower(&c.evm_shard),
        "configurationHash": hex_lower(&w.dep.evm_config_hash),
        "pdr": art(&pdr_bytes(5, 0)), "executionProfile": art(&exec_profile()),
      },
    })
}

fn entry(w: &World) -> Value {
    let (n, rg, eg, c) = identity();
    json!({
      "schemaVersion": 1, "protocolVersion": 2, "family": "unicity-native", "sdkVersion": "3.0.1",
      "tokenTypeHex": hex_lower(&derive_type(n, &rg, &eg, c)),
      "coinIdHex": hex_lower(&derive_asset(n, &rg, &eg, c)),
      "symbol": "UCT", "decimals": 18,
      "plugin": {
        "npm": { "name": "@unicitylabs/native-bridge-plugin", "version": "0.1.0", "integrity": format!("sha512-{}==", "A".repeat(86)) },
        "rust": { "crate": "native-bridge-sdk-ext", "version": "0.1.0", "revision": "1".repeat(40) },
        "protocolCommit": "2".repeat(40), "vectorManifestSha256": "3".repeat(64),
      },
      "networkId": n, "rootGenesisHash": hex_lower(&rg), "executionGenesisHash": hex_lower(&eg),
      "evmChainId": c.to_string(), "chainRef": format!("eip155:{c}"), "asset": "0".repeat(40),
      "activeDeployment": rec(w), "replacedDeployments": [],
      "trustBase": {
        "networkId": n, "rootGenesisHash": hex_lower(&rg), "format": "sdk-root-trust-base-json-v1",
        "document": { "sha256": hex_lower(&w.bridge.trust.id()), "location": "file:///etc/native/trust-base.json" },
      },
      "proofEndpoints": ["https://aggregator.invalid"], "rpcUrls": [],
    })
}

fn registry(e: &Value) -> String {
    json!({ e["tokenTypeHex"].as_str().unwrap(): e }).to_string()
}

fn load_with(f: impl FnOnce(&mut Value)) -> Result<usize, E> {
    let w = make_world(20);
    let mut e = entry(&w);
    f(&mut e);
    manifest::load(&registry(&e), Some(&artifacts)).map(|l| l.registry.deployments().len())
}

#[test]
fn a_schema_shaped_manifest_loads_and_installs_under_the_pinned_document() {
    let w = make_world(20);
    let loaded = manifest::load(&registry(&entry(&w)), Some(&artifacts)).unwrap();
    assert_eq!(loaded.registry.deployments().len(), 1);
    assert_eq!(loaded.registry.deployments()[0].cfg, w.dep.cfg);
    loaded.install(w.bridge.trust.clone()).unwrap();
}

#[test]
fn every_identity_and_profile_field_is_recomputed_or_rejected() {
    let zero = hex_lower(&[1u8; 32]);
    let cases: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        ("schema", Box::new(|d| d["schemaVersion"] = 2.into())),
        ("protocol", Box::new(|d| d["protocolVersion"] = 1.into())),
        ("family", Box::new(|d| d["family"] = "eip155".into())),
        ("sdk", Box::new(|d| d["sdkVersion"] = "3.0.0".into())),
        (
            "type",
            Box::new({
                let z = zero.clone();
                move |d| d["tokenTypeHex"] = z.clone().into()
            }),
        ),
        (
            "coin",
            Box::new({
                let z = zero.clone();
                move |d| d["coinIdHex"] = z.clone().into()
            }),
        ),
        ("chain ref", Box::new(|d| d["chainRef"] = "eip155:1".into())),
        (
            "chain id leading zero",
            Box::new(|d| d["evmChainId"] = "07777".into()),
        ),
        ("chain id zero", Box::new(|d| d["evmChainId"] = "0".into())),
        (
            "asset with 0x",
            Box::new(|d| d["asset"] = format!("0x{}", "0".repeat(40)).into()),
        ),
        (
            "asset nonzero",
            Box::new(|d| d["asset"] = format!("{}1", "0".repeat(39)).into()),
        ),
        (
            "vault",
            Box::new(|d| d["activeDeployment"]["vaultAddress"] = hex_lower(&[1u8; 20]).into()),
        ),
        (
            "zero vault",
            Box::new(|d| d["activeDeployment"]["vaultAddress"] = "0".repeat(40).into()),
        ),
        (
            "cfg hash",
            Box::new({
                let z = zero.clone();
                move |d| d["activeDeployment"]["cfgHash"] = z.clone().into()
            }),
        ),
        (
            "semantic profile",
            Box::new({
                let z = zero.clone();
                move |d| d["activeDeployment"]["semanticProfile"]["sha256"] = z.clone().into()
            }),
        ),
        (
            "b1 profile",
            Box::new({
                let z = zero.clone();
                move |d| d["activeDeployment"]["b1"]["profile"]["sha256"] = z.clone().into()
            }),
        ),
        (
            "policy partition",
            Box::new(|d| d["activeDeployment"]["aggregatorPolicy"]["partition"] = 99.into()),
        ),
        (
            "policy shard",
            Box::new(|d| d["activeDeployment"]["aggregatorPolicy"]["shardHex"] = "00".into()),
        ),
        (
            "policy configuration",
            Box::new({
                let z = zero.clone();
                move |d| {
                    d["activeDeployment"]["aggregatorPolicy"]["configurationHash"] =
                        z.clone().into()
                }
            }),
        ),
        (
            "evm partition",
            Box::new(|d| d["activeDeployment"]["evmBackingPolicy"]["partition"] = 99.into()),
        ),
        (
            "evm configuration pin",
            Box::new({
                let z = zero.clone();
                move |d| {
                    d["activeDeployment"]["evmBackingPolicy"]["configurationHash"] =
                        z.clone().into()
                }
            }),
        ),
        (
            "execution profile missing",
            Box::new({
                let z = hex_lower(&[2u8; 32]);
                move |d| {
                    d["activeDeployment"]["evmBackingPolicy"]["executionProfile"]["sha256"] =
                        z.clone().into()
                }
            }),
        ),
        (
            "uppercase hex",
            Box::new(|d| d["rootGenesisHash"] = "AA".repeat(32).into()),
        ),
        ("unknown field", Box::new(|d| d["extra"] = 1.into())),
        (
            "bundle-style trust base",
            Box::new(|d| d["trustBase"] = json!({ "bundleDigest": "x", "epochs": [] })),
        ),
        (
            "trust format",
            Box::new(|d| d["trustBase"]["format"] = "epoch-bundle".into()),
        ),
        (
            "trust network",
            Box::new(|d| d["trustBase"]["networkId"] = 4.into()),
        ),
        (
            "npm version",
            Box::new(|d| d["plugin"]["npm"]["version"] = "9.9.9".into()),
        ),
        (
            "replaced missing",
            Box::new(|d| {
                d.as_object_mut().unwrap().remove("replacedDeployments");
            }),
        ),
    ];
    for (name, f) in cases {
        assert!(load_with(f).is_err(), "{name} must be rejected");
    }
}

#[test]
fn symbol_is_not_identity() {
    assert_eq!(
        load_with(|d| d["symbol"] = "SOMETHING-ELSE".into()).unwrap(),
        1
    );
}

#[test]
fn installed_artifacts_must_match_their_pins_and_the_genesis_pdr_must_yield_the_pin() {
    let w = make_world(20);
    let e = entry(&w);
    let pdr_hash = sha(&pdr_bytes(5, 0));
    let wrong = |h: &[u8; 32]| {
        if h == &pdr_hash {
            Some(b"not the pdr".to_vec())
        } else {
            artifacts(h)
        }
    };
    assert_eq!(
        manifest::load(&registry(&e), Some(&wrong)).unwrap_err(),
        E::Manifest
    );
    let other = pdr_bytes(5, 1);
    let mut e2 = entry(&w);
    e2["activeDeployment"]["evmBackingPolicy"]["pdr"]["sha256"] = hex_lower(&sha(&other)).into();
    let with_other = |h: &[u8; 32]| {
        if h == &sha(&other) {
            Some(other.clone())
        } else {
            artifacts(h)
        }
    };
    assert_eq!(
        manifest::load(&registry(&e2), Some(&with_other)).unwrap_err(),
        E::Manifest
    );
    assert_eq!(
        manifest::load(&registry(&e), None).unwrap_err(),
        E::Manifest,
        "the execution profile is required"
    );
}

#[test]
fn the_registry_key_must_be_the_token_type_and_vaults_must_be_distinct() {
    let w = make_world(20);
    let e = entry(&w);
    let bad_key = json!({ hex_lower(&[0u8; 32]): e }).to_string();
    assert_eq!(
        manifest::load(&bad_key, Some(&artifacts)).unwrap_err(),
        E::Manifest
    );
    let mut dup = entry(&w);
    dup["replacedDeployments"] = json!([rec(&w)]);
    assert_eq!(
        manifest::load(&registry(&dup), Some(&artifacts)).unwrap_err(),
        E::AmbiguousDeployment
    );
    assert_eq!(
        manifest::load("{}", Some(&artifacts)).unwrap_err(),
        E::Manifest
    );
}

#[test]
fn the_pinned_document_digest_must_be_the_installed_trust_input() {
    let w = make_world(20);
    let mut e = entry(&w);
    e["trustBase"]["document"]["sha256"] = hex_lower(&[9u8; 32]).into();
    let loaded = manifest::load(&registry(&e), Some(&artifacts)).unwrap();
    assert_eq!(
        loaded.install(w.bridge.trust.clone()).unwrap_err(),
        E::TrustBaseDigest
    );
}

#[test]
fn endpoints_and_locations_are_installation_metadata_never_verification_inputs() {
    assert_eq!(
        load_with(|d| {
            d["proofEndpoints"] = json!(["https://unreachable.invalid"]);
            d["trustBase"]["document"]["location"] = "https://unreachable.invalid/B.json".into();
        })
        .unwrap(),
        1
    );
}

// ---- no network capability ---------------------------------------------------------------------

#[test]
fn verifier_sources_contain_no_network_or_filesystem_capability() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let banned = [
        "std::net",
        "TcpStream",
        "UdpSocket",
        "ureq",
        "reqwest",
        "hyper",
        "std::fs",
        "std::process",
        "std::env",
        "http://",
        "https://",
    ];
    for entry in std::fs::read_dir(src).unwrap() {
        let p = entry.unwrap().path();
        let text = std::fs::read_to_string(&p).unwrap();
        for b in banned {
            assert!(!text.contains(b), "{} mentions {b}", p.display());
        }
    }
}

#[test]
fn receipt_verification_succeeds_with_the_network_disabled() {
    // Re-run this very test under an OS sandbox that denies all networking, when one is available.
    if std::env::var("NBP_NO_NET_CHILD").is_ok() {
        let w = make_world(20);
        let out = build_token(
            &w,
            &spec(1),
            &[tx_step(2, 7, 1_700_000_050)],
            1_700_000_040,
            1_700_000_900,
        );
        w.bridge
            .verify_native_token_bytes(&out.token.to_cbor(), Expect::Receipt)
            .unwrap();
        assert!(
            std::net::TcpStream::connect("127.0.0.1:9").is_err(),
            "sandbox must deny networking"
        );
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let mut cmd =
        if cfg!(target_os = "macos") && std::path::Path::new("/usr/bin/sandbox-exec").exists() {
            let mut c = std::process::Command::new("/usr/bin/sandbox-exec");
            c.args(["-p", "(version 1)(allow default)(deny network*)"])
                .arg(&exe);
            c
        } else if cfg!(target_os = "linux")
            && std::process::Command::new("unshare")
                .arg("-rn")
                .arg("true")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        {
            let mut c = std::process::Command::new("unshare");
            c.args(["-rn"]).arg(&exe);
            c
        } else {
            eprintln!("no network sandbox available; the source-scan test covers this platform");
            return;
        };
    let status = cmd
        .args([
            "receipt_verification_succeeds_with_the_network_disabled",
            "--exact",
            "--nocapture",
        ])
        .env("NBP_NO_NET_CHILD", "1")
        .status()
        .unwrap();
    assert!(status.success(), "sandboxed run failed");
}
