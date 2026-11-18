//! The redeem gas estimate (`nb2::gas`, estimate-nb2-1179) against the shared vectors (`tests/nb2-gas/gas-vectors.json`, real evidence of
//! the bft-core#1179 measurement lane, written by the TypeScript plug-in's `scripts/gen-nb2-gas-vectors.ts`): every feature and term,
//! exactly as the TypeScript plug-in computes them (`test/nb2/gas.test.ts`).
#![cfg(feature = "host")]

use native_bridge_sdk_ext::nb2::bridge::lineage_of;
use native_bridge_sdk_ext::nb2::gas::{
    batch_gas, calibrated_deployment, cbor_count, cbor_items, create_address, memory_gas,
    price_features, redeem_features, redeem_gas_terms, CborCount, Claim, DeploymentCode, GasModel,
    GasTerms, MeasuredGasModel, RedeemFeatures, RedeemShape, UcCost, NATIVE_GAS_SCHEDULE,
};
use native_bridge_sdk_ext::nb2::token::Token;
use native_bridge_sdk_ext::nb2::util::from_hex;
use native_bridge_sdk_ext::nb2::verify::decode_evidence;
use serde_json::{json, Value};

const FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/nb2-gas/gas-vectors.json"
);

fn before_burn(t: &Token) -> Token {
    let mut p = t.clone();
    p.transfers.pop();
    p.proofs.pop();
    p.transfers_raw.pop();
    p
}

fn uc(c: &UcCost) -> Value {
    json!({"bytes": c.bytes, "ir": c.ir, "signatures": c.signatures, "stc": c.stc, "utc": c.utc, "slow": c.slow})
}

fn walk(c: &CborCount) -> Value {
    json!({"items": c.items, "long": c.long, "nodes": c.nodes})
}

/// The features as the TypeScript plug-in writes them (camelCase, bigints as strings).
fn features_json(f: &RedeemFeatures) -> Value {
    let claims: Vec<Value> = f
        .claims
        .iter()
        .map(|c| json!({"bytes": c.bytes, "signatures": c.signatures, "path": c.path, "epoch": c.epoch.map(|e| e.to_string())}))
        .collect();
    json!({
        "tokens": f.tokens, "edges": f.edges, "allocSteps": f.alloc_steps, "steps": f.steps, "parentSteps": f.parent_steps, "txWords": f.tx_words, "maxTx": f.max_tx,
        "siblings": f.siblings, "ucParses": f.uc_parses, "ucBytes": f.uc_bytes, "ucIr": f.uc_ir, "ucSignatures": f.uc_signatures, "ucStc": f.uc_stc,
        "ucUtc": f.uc_utc, "ucSlow": f.uc_slow, "helperMemory": f.helper_memory.to_string(), "evmUc": uc(&f.evm_uc), "rcptItems": f.rcpt_items, "rcptLong": f.rcpt_long, "rcptLists": f.rcpt_lists, "rcptHeads": f.rcpt_heads, "rcptLongHeads": f.rcpt_long_heads, "rcptKids": f.rcpt_kids, "rcptWords": f.rcpt_words, "ucCosts": f.uc_costs.iter().map(uc).collect::<Vec<_>>(),
        "pathWords": f.path_words, "maxUc": f.max_uc, "scratch": f.scratch, "scan": walk(&f.scan), "skip": walk(&f.skip), "jBytes": f.j_bytes, "keyLookups": f.key_lookups,
        "decompressions": f.decompressions, "probes": f.probes, "claims": claims,
    })
}

fn terms_json(t: &GasTerms) -> Value {
    json!({
        "transaction": t.transaction.to_string(), "vault": t.vault.to_string(), "batch": t.batch.to_string(),
        "membership": t.membership.to_string(), "sha256": t.sha256.to_string(), "execution": t.execution.to_string(),
        "memory": t.memory.to_string(), "forwarding": t.forwarding.to_string(), "safety": t.safety.to_string(), "reserve": t.reserve.to_string(),
        "limit": t.limit.to_string(), "memoryWords": t.memory_words,
    })
}

/// Every vector's cases: (the case, its lineage, its evidence bytes, pending, proofs, K).
fn cases(v: &Value) -> Vec<(Value, Vec<Token>, usize, usize, u64, u64)> {
    let part = decode_evidence(&from_hex(v["evidence"].as_str().unwrap()).unwrap()).unwrap();
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let pending = c["pendingTransactions"].as_u64().unwrap() as usize;
            let lineage = lineage_of(&if pending == 1 {
                before_burn(&part)
            } else {
                part.clone()
            })
            .unwrap();
            (
                c.clone(),
                lineage,
                c["evidenceBytes"].as_u64().unwrap() as usize,
                pending,
                c["proofs"].as_str().unwrap().parse().unwrap(),
                c["K"].as_str().unwrap().parse().unwrap(),
            )
        })
        .collect()
}

fn shape(l: &[Token], e: usize, pending: usize, proofs: u64, k: u64) -> RedeemShape<'_> {
    RedeemShape {
        evidence_bytes: e,
        lineage: l,
        pending_transactions: pending,
        proofs,
        k,
    }
}

#[test]
fn shared_vectors_reproduce_exactly() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    assert_eq!(v["model"], MeasuredGasModel.name());
    let vectors = v["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 18);
    let mut nulls = 0;
    for vec in vectors {
        let name = vec["name"].as_str().unwrap();
        for (c, l, e, pending, proofs, k) in cases(vec) {
            let s = shape(&l, e, pending, proofs, k);
            let at = format!("{name} {} P {} K {k}", c["input"], c["proofs"]);
            let f = redeem_features(&s);
            assert_eq!(
                f.as_ref().map(features_json).unwrap_or(Value::Null),
                c["features"],
                "{at}: features"
            );
            let t = redeem_gas_terms(&s);
            assert_eq!(
                t.as_ref().map(terms_json).unwrap_or(Value::Null),
                c["terms"],
                "{at}: terms"
            );
            assert_eq!(MeasuredGasModel.redeem_gas_limit(&s), t.map(|t| t.limit));
            if t.is_none() {
                nulls += 1;
            }
        }
    }
    // the 17-signature seal and the non-text signature key, every case
    assert_eq!(nulls, 2 * 5);
}

#[test]
fn every_vector_measured_in_the_lab_is_covered() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    let mut measured = 0;
    for vec in v["vectors"].as_array().unwrap() {
        let Some(lab) = vec["labGas"].as_str() else {
            continue;
        };
        measured += 1;
        let lab: u64 = lab.parse().unwrap();
        let (_, l, e, pending, proofs, k) = cases(vec).remove(0);
        let t = redeem_gas_terms(&shape(&l, e, pending, proofs, k)).unwrap();
        assert!(
            t.execution + t.memory + t.sha256 >= lab,
            "{}: {} < {lab}",
            vec["name"],
            t.execution + t.memory + t.sha256
        );
    }
    assert!(measured >= 14);
}

#[test]
fn preflight_dominates_redemption_and_more_never_costs_less() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    for vec in v["vectors"].as_array().unwrap() {
        let name = vec["name"].as_str().unwrap();
        let all = cases(vec);
        for k in [4u64, 64] {
            let red = all
                .iter()
                .find(|c| c.3 == 0 && c.5 == k && c.4 == 17)
                .unwrap();
            let pre = all.iter().find(|c| c.3 == 1 && c.5 == k).unwrap();
            let fr = redeem_features(&shape(&red.1, red.2, 0, 17, k));
            let fp = redeem_features(&shape(&pre.1, pre.2, 1, 17, k));
            let (Some(fr), Some(fp)) = (fr, fp) else {
                assert!(
                    redeem_features(&shape(&red.1, red.2, 0, 17, k)).is_none()
                        && redeem_features(&shape(&pre.1, pre.2, 1, 17, k)).is_none()
                );
                continue;
            };
            let lr = redeem_gas_terms(&shape(&red.1, red.2, 0, 17, k))
                .unwrap()
                .limit;
            let lp = redeem_gas_terms(&shape(&pre.1, pre.2, 1, 17, k))
                .unwrap()
                .limit;
            assert!(lp >= lr, "{name} K {k}");
            for (a, b, what) in [
                (fp.steps, fr.steps, "steps"),
                (fp.scan.items, fr.scan.items, "scan.items"),
                (fp.scan.long, fr.scan.long, "scan.long"),
                (fp.scan.nodes, fr.scan.nodes, "scan.nodes"),
                (fp.skip.items, fr.skip.items, "skip.items"),
                (fp.skip.long, fr.skip.long, "skip.long"),
                (fp.tx_words, fr.tx_words, "txWords"),
                (fp.siblings, fr.siblings, "siblings"),
                (fp.uc_bytes, fr.uc_bytes, "ucBytes"),
                (fp.uc_signatures, fr.uc_signatures, "ucSignatures"),
                (fp.uc_stc, fr.uc_stc, "ucStc"),
                (fp.uc_utc, fr.uc_utc, "ucUtc"),
                (fp.uc_slow, fr.uc_slow, "ucSlow"),
                (fp.probes, fr.probes, "probes"),
                (fp.key_lookups, fr.key_lookups, "keyLookups"),
                (fp.claims.len(), fr.claims.len(), "claims"),
            ] {
                assert!(a >= b, "{name} K {k}: {what} {a} < {b}");
            }
            // one more of any counted unit never lowers the bound
            let base = price_features(&fr, red.2, 0, 4).limit;
            type Bump = fn(&mut RedeemFeatures);
            let bumps: [(&str, Bump); 22] = [
                ("steps", |f| f.steps += 1),
                ("scan.items", |f| f.scan.items += 1),
                ("scan.long", |f| f.scan.long += 1),
                ("skip.items", |f| f.skip.items += 1),
                ("skip.long", |f| f.skip.long += 1),
                ("rcptItems", |f| f.rcpt_items += 1),
                ("rcptLong", |f| f.rcpt_long += 1),
                ("rcptLists", |f| f.rcpt_lists += 1),
                ("rcptHeads", |f| f.rcpt_heads += 1),
                ("rcptLongHeads", |f| f.rcpt_long_heads += 1),
                ("siblings", |f| f.siblings += 1),
                ("ucBytes", |f| f.uc_bytes += 1),
                ("ucIr", |f| f.uc_ir += 1),
                ("ucSignatures", |f| f.uc_signatures += 1),
                ("ucStc", |f| f.uc_stc += 1),
                ("ucUtc", |f| f.uc_utc += 1),
                ("ucSlow", |f| f.uc_slow += 1),
                ("probes", |f| f.probes += 1),
                ("decompressions", |f| f.decompressions += 1),
                ("txWords", |f| f.tx_words += 1),
                ("edges", |f| f.edges += 1),
                ("jBytes", |f| f.j_bytes += 1),
            ];
            for (what, bump) in bumps {
                let mut more = fr.clone();
                bump(&mut more);
                assert!(
                    price_features(&more, red.2, 0, 4).limit > base,
                    "{name}: {what}"
                );
            }
        }
    }
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
    let v: Value = serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    let part =
        decode_evidence(&from_hex(v["vectors"][0]["evidence"].as_str().unwrap()).unwrap()).unwrap();
    let lineage = lineage_of(&part).unwrap();
    let s = |l: &[Token], pending: usize| {
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
