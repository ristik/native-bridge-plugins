//! The redeem gas bound (`nb2::gas`, bound-nb2-1179) against the shared vectors (`tests/nb2-gas/gas-vectors.json`, real evidence of
//! the bft-core#1179 measurement lane, written by the TypeScript plug-in's `scripts/gen-nb2-gas-vectors.ts`): every feature and term,
//! exactly as the TypeScript plug-in computes them (`test/nb2/gas.test.ts`).
#![cfg(feature = "host")]

use native_bridge_sdk_ext::nb2::bridge::lineage_of;
use native_bridge_sdk_ext::nb2::gas::{
    batch_gas, cbor_items, memory_gas, redeem_features, redeem_gas_terms, Claim, GasModel,
    MeasuredGasModel, RedeemFeatures, RedeemShape,
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
        "ucUtc": f.uc_utc, "ucSlow": f.uc_slow, "helperMemory": f.helper_memory.to_string(),
        "pathWords": f.path_words, "maxUc": f.max_uc, "scratch": f.scratch, "items": f.items, "jBytes": f.j_bytes, "keyLookups": f.key_lookups,
        "decompressions": f.decompressions, "probes": f.probes, "claims": claims,
    })
}

#[test]
fn shared_vectors_reproduce_exactly() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    assert_eq!(v["model"], MeasuredGasModel.name());
    let vectors = v["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 5);
    for vec in vectors {
        let name = vec["name"].as_str().unwrap();
        let part = decode_evidence(&from_hex(vec["evidence"].as_str().unwrap()).unwrap()).unwrap();
        for c in vec["cases"].as_array().unwrap() {
            let pending = c["pendingTransactions"].as_u64().unwrap() as usize;
            let lineage = lineage_of(&if pending == 1 {
                before_burn(&part)
            } else {
                part.clone()
            })
            .unwrap();
            let s = RedeemShape {
                evidence_bytes: c["evidenceBytes"].as_u64().unwrap() as usize,
                lineage: &lineage,
                pending_transactions: pending,
                proofs: c["proofs"].as_str().unwrap().parse().unwrap(),
                k: c["K"].as_str().unwrap().parse().unwrap(),
            };
            let at = format!("{name} {} P {}", c["input"], c["proofs"]);
            let f = redeem_features(&s).unwrap_or_else(|| panic!("{at}: no features"));
            assert_eq!(features_json(&f), c["features"], "{at}: features");
            let t = redeem_gas_terms(&s).unwrap();
            let terms = json!({
                "transaction": t.transaction.to_string(), "vault": t.vault.to_string(), "batch": t.batch.to_string(),
                "membership": t.membership.to_string(), "sha256": t.sha256.to_string(), "execution": t.execution.to_string(),
                "memory": t.memory.to_string(), "forwarding": t.forwarding.to_string(), "reserve": t.reserve.to_string(),
                "limit": t.limit.to_string(), "memoryWords": t.memory_words,
            });
            assert_eq!(terms, c["terms"], "{at}: terms");
            assert_eq!(MeasuredGasModel.redeem_gas_limit(&s), Some(t.limit));
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
