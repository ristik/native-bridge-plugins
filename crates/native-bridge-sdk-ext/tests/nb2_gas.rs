#![cfg(feature = "host")]

use native_bridge_sdk_ext::nb2::bridge::lineage_of;
use native_bridge_sdk_ext::nb2::gas::{
    batch_gas, calibrated_deployment, cbor_count, cbor_items, create_address, memory_gas,
    redeem_features, redeem_gas_terms, CborCount, Claim, DeploymentCode, GasModel,
    MeasuredGasModel, RedeemShape, NATIVE_GAS_SCHEDULE,
};
use native_bridge_sdk_ext::nb2::token::LineageLevel;
use native_bridge_sdk_ext::nb2::util::from_hex;
use native_bridge_sdk_ext::nb2::verify::decode_evidence;
use serde_json::Value;

const EVIDENCE: &[u8] = include_bytes!(
    "../../../protocol/vectors/nb2-continuation-v1.1/transcripts/one-split/evidence.bin"
);

#[test]
fn flat_evidence_is_priced_by_its_bounded_signed_records() {
    let token = decode_evidence(EVIDENCE).unwrap();
    let lineage = lineage_of(&token);
    let shape = RedeemShape {
        evidence_bytes: EVIDENCE.len(),
        lineage: &lineage,
        pending_transactions: 0,
        proofs: 0,
        k: 64,
    };
    let f = redeem_features(&shape).unwrap();
    assert_eq!(f.tokens, 2);
    assert_eq!(f.edges, 1);
    assert_eq!(
        f.steps,
        lineage
            .iter()
            .map(|level| 1 + level.transfers.len())
            .sum::<usize>()
    );
    let base = redeem_gas_terms(&shape).unwrap().limit;
    assert!(
        redeem_gas_terms(&RedeemShape { proofs: 1, ..shape })
            .unwrap()
            .limit
            > base
    );

    let mut held = lineage.clone();
    let last = held.last_mut().unwrap();
    last.transfers.pop();
    last.transfers_raw.pop();
    last.proofs.pop();
    let pending = RedeemShape {
        lineage: &held,
        pending_transactions: 1,
        ..shape
    };
    assert!(redeem_gas_terms(&pending).unwrap().limit >= base);
}

#[test]
fn native_schedules_and_items() {
    let claim = Claim {
        bytes: 1_000,
        signatures: 4,
        path: 2,
        epoch: Some(1),
    };
    assert_eq!(
        batch_gas(core::slice::from_ref(&claim)).0,
        61_100 + 16 * 1_004 + 29_900 + 28_800 + 2_000 + 500
    );
    let (gas, calls, _) = batch_gas(&vec![claim.clone(); 17]);
    assert_eq!(calls, 2);
    let call = |k: u64| {
        61_100
            + 16 * (4 + 1_000 * k)
            + 500 * k * (k - 1)
            + 29_900
            + 7_200 * 4 * k
            + 2_000 * k
            + 500 * k
    };
    assert_eq!(gas, call(9) + call(8));
    let big = Claim {
        bytes: 24_717,
        signatures: 16,
        path: 288,
        epoch: None,
    };
    assert_eq!(batch_gas(&vec![big; 11]).1, 2);
    let unknown = Claim {
        epoch: None,
        ..claim.clone()
    };
    assert_eq!(
        batch_gas(&[claim.clone(), unknown]).0 - batch_gas(&[claim.clone(), claim]).0,
        29_900
    );
    assert_eq!(memory_gas(1024), 3 * 1024 + 2048);
    assert_eq!(memory_gas(50_000), 150_000 + 4_882_812);
    assert_eq!(cbor_items(&[0x82, 0x01, 0x43, 0xaa, 0xbb, 0xcc]), 3);
    assert_eq!(
        cbor_items(&[0xd9, 0x98, 0x58, 0x81, 0x59, 0x00, 0x02, 0x01, 0x02]),
        3
    );
}

#[test]
fn fail_closed() {
    let part = decode_evidence(EVIDENCE).unwrap();
    let lineage = lineage_of(&part);
    let s = |l: &[LineageLevel], pending: usize| {
        redeem_gas_terms(&RedeemShape {
            evidence_bytes: 10_000,
            lineage: l,
            pending_transactions: pending,
            proofs: 0,
            k: 4,
        })
    };
    assert!(s(&lineage, 0).is_some());
    assert!(s(&[], 0).is_none());
    assert!(s(&lineage, 2).is_none());
    let mut bad = lineage.clone();
    let last = bad.len() - 1;
    let uc = &mut bad[last].proofs[0].uc;
    uc.pop();
    assert!(s(&bad, 0).is_none());
}

struct Dep {
    gamma: Vec<u8>,
    verifier: Vec<u8>,
    helper: String,
    k: u64,
    b: u64,
    qmax: Vec<u8>,
    verifier_code: Vec<u8>,
    helper_code: Vec<u8>,
    vault_code: Vec<u8>,
}

fn deployment(build: &str) -> Dep {
    let d: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/nb2-gas/deployment.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let h = |v: &Value| from_hex(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
    let qmax: u128 = d[build]["Qmax"].as_str().unwrap().parse().unwrap();
    let qb: Vec<u8> = qmax
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|&x| x == 0)
        .collect();
    Dep {
        gamma: h(&d[build]["gamma"]),
        verifier: h(&d[build]["verifier"]),
        helper: d[build]["helper"].as_str().unwrap().to_lowercase(),
        k: d[build]["K"].as_u64().unwrap(),
        b: d[build]["B"].as_u64().unwrap(),
        qmax: qb,
        verifier_code: h(&d[build]["verifierCode"]),
        helper_code: h(&d["helperCode"]),
        vault_code: h(&d[build]["vaultCode"]),
    }
}

fn code_of<'a>(d: &'a Dep, schedule: Option<&'a str>) -> DeploymentCode<'a> {
    DeploymentCode {
        gamma: &d.gamma,
        verifier: &d.verifier,
        k: d.k,
        b: d.b,
        qmax: &d.qmax,
        verifier_code: &d.verifier_code,
        helper_code: &d.helper_code,
        vault_code: &d.vault_code,
        native_gas_schedule: schedule,
    }
}

fn flip(b: &[u8], at: usize) -> Vec<u8> {
    let mut c = b.to_vec();
    c[at] ^= 1;
    c
}

#[test]
fn the_default_estimate_applies_to_the_calibrated_deployment_only() {
    for build in ["test", "production"] {
        let d = deployment(build);
        let ok = code_of(&d, Some(NATIVE_GAS_SCHEDULE));
        assert!(calibrated_deployment(&ok), "{build}");
        assert_eq!(MeasuredGasModel.supports_deployment(&ok), Some(true));
        let helper = create_address(&d.verifier, 1);
        let hex: String = helper.iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(format!("0x{hex}"), d.helper);
        // one occurrence of an immutable changed alone (the helper address at its last use, admitsTestSet, the helper hash)
        for at in [15_504 + 31, 325 + 31, 12_187 + 31, 368 + 31, 1_000] {
            let v = flip(&d.verifier_code, at);
            assert!(
                !calibrated_deployment(&DeploymentCode {
                    verifier_code: &v,
                    ..code_of(&d, Some(NATIVE_GAS_SCHEDULE))
                }),
                "{build} verifier {at}"
            );
        }
        let mut moved = d.verifier_code.clone();
        for at in [325, 3_071, 8_473, 15_504] {
            moved[at + 31] ^= 1;
        }
        assert!(!calibrated_deployment(&DeploymentCode {
            verifier_code: &moved,
            ..code_of(&d, Some(NATIVE_GAS_SCHEDULE))
        }));
        assert!(!calibrated_deployment(&DeploymentCode {
            verifier_code: &d.verifier_code[1..],
            ..code_of(&d, Some(NATIVE_GAS_SCHEDULE))
        }));
        let hc = flip(&d.helper_code, 100);
        assert!(!calibrated_deployment(&DeploymentCode {
            helper_code: &hc,
            ..code_of(&d, Some(NATIVE_GAS_SCHEDULE))
        }));
        for at in [103 + 31, 4_057 + 31, 641 + 31, 1_218 + 31, 3_000] {
            let v = flip(&d.vault_code, at);
            assert!(
                !calibrated_deployment(&DeploymentCode {
                    vault_code: &v,
                    ..code_of(&d, Some(NATIVE_GAS_SCHEDULE))
                }),
                "{build} vault {at}"
            );
        }
        let g = flip(&d.gamma, d.gamma.len() - 1);
        assert!(!calibrated_deployment(&DeploymentCode {
            gamma: &g,
            ..code_of(&d, Some(NATIVE_GAS_SCHEDULE))
        }));
        assert!(!calibrated_deployment(&code_of(&d, None)));
        assert!(!calibrated_deployment(&code_of(&d, Some("another"))));
    }
}

#[test]
fn cbor_walk_counts() {
    assert_eq!(
        cbor_count(&[0xd9, 0x98, 0x58, 0x81, 0x59, 0x00, 0x02, 0x01, 0x02]),
        CborCount {
            items: 3,
            long: 2,
            nodes: 2
        }
    );
    assert_eq!(
        cbor_count(&[0x80, 0xa0, 0xc1, 0x00, 0x18, 0x20]),
        CborCount {
            items: 5,
            long: 1,
            nodes: 1
        }
    );
}
