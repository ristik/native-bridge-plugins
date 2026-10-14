//! The token-level vectors of bft-core's b1ref/tokenvec through this projection (acceptance matrix 1b/1c/7e): bft-core's
//! `bridgeprofile/testdata/tokenvec-envelopes.json`, pinned in `tests/tokenvec/pin.json`. Each run is a real lock-backed return
//! token whose leaves are certified by the scenario's anchors (several epochs, a topology change, eight shards before and after
//! consolidation); Go's Compose accepted it and b1ref accepted its batch on the TokenWorld registry. From the kernel's leaves this
//! projection must plan the same anchor table, open every anchor within its leaves' times, and build the same CERT_BATCH_V2
//! request, grouping and gate. Split semantics are not executed: the kernel refuses a split (bft-core
//! TestTokenvecSplitIsUnsupportedByTheKernel), so the split-* runs are multi-epoch and topology-change histories at the anchor level.

use native_bridge_sdk_ext::certgroups::{batch_request, measure};
use native_bridge_sdk_ext::envelope::{check_anchors, check_policy_body, plan_anchors, Envelope};
use native_bridge_sdk_ext::gas::{compute_gate, kernel_request_bytes};
use native_bridge_sdk_ext::profile::{from_hex, Cfg};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn dir() -> String {
    format!("{}/../../tests/tokenvec", env!("CARGO_MANIFEST_DIR"))
}

fn runs() -> Vec<Value> {
    let pin: Value =
        serde_json::from_slice(&std::fs::read(format!("{}/pin.json", dir())).unwrap()).unwrap();
    let raw = std::fs::read(format!("{}/tokenvec-envelopes.json", dir())).unwrap();
    let digest: String = Sha256::digest(&raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest,
        pin["sha256"].as_str().unwrap(),
        "the fixture is the pinned file"
    );
    let f: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(f["format"], "bridgeprofile/tokenvec-envelopes-v1");
    f["envelopes"].as_array().unwrap().clone()
}

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bytes(v: &Value) -> Vec<u8> {
    from_hex(v.as_str().unwrap()).unwrap()
}

fn sids(r: &Value) -> Vec<[u8; 32]> {
    r["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| bytes(&l["sid"]).try_into().unwrap())
        .collect()
}

fn times(r: &Value) -> Vec<u64> {
    r["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["referenceTime"].as_u64().unwrap())
        .collect()
}

#[test]
fn every_token_level_run_is_planned_opened_batched_grouped_and_gated_as_the_go_projection_did() {
    let rs = runs();
    let names: Vec<&str> = rs.iter().map(|r| r["scenario"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "split-three-epochs",
            "split-across-topology-change",
            "consolidated-eight-shards",
            "unconsolidated-eight-seals",
            "paired/unconsolidated-eight-seals",
            "paired/consolidated-eight-shards"
        ]
    );
    for r in &rs {
        let id = r["scenario"].as_str().unwrap();
        let cfg_raw = bytes(&r["cfg"]);
        let cfg = Cfg::from_bytes(&cfg_raw).unwrap();
        let encoded = bytes(&r["envelope"]);
        let env = Envelope::decode(&encoded).unwrap();
        let pol = check_policy_body(&cfg, &env).unwrap();
        let plan = plan_anchors(&pol, &env, &sids(r)).unwrap();
        assert_eq!(
            plan.leaf_anchor,
            (0..env.anchors.len()).collect::<Vec<_>>(),
            "{id}: leaf i is certified by anchor i"
        );
        check_anchors(&env, &plan, &times(r)).unwrap();
        assert_eq!(
            hx(&batch_request(&env.anchors).unwrap()),
            r["request"].as_str().unwrap(),
            "{id}: request"
        );
        let n = measure(&env.anchors, 0).unwrap();
        let g = &r["grouping"];
        for (k, v) in [
            ("C", n.c),
            ("K", n.k),
            ("E", n.e),
            ("S", n.s),
            ("Q", n.q),
            ("A", n.a),
            ("P", n.p),
        ] {
            assert_eq!(g[k].as_u64().unwrap(), v, "{id}: grouping {k}");
        }
        let gate = compute_gate(
            &cfg_raw,
            encoded.len(),
            kernel_request_bytes(cfg_raw.len() as u64, env.history.len() as u64),
            &env,
            7_000_000,
        )
        .unwrap();
        let want = &r["gate"];
        for (k, v) in [
            ("b2", gate.b2),
            ("batch", gate.batch),
            ("intrinsic", gate.intrinsic),
            ("items", gate.items),
            ("j", gate.j),
            ("rsmt", gate.rsmt),
            ("steps", gate.steps),
            ("total", gate.total),
        ] {
            assert_eq!(want[k].as_u64().unwrap(), v, "{id}: gate {k}");
        }
    }
}

#[test]
fn consolidation_changes_the_anchors_and_the_price_never_the_token() {
    let rs = runs();
    let find = |s: &str| rs.iter().find(|r| r["scenario"] == s).unwrap().clone();
    let (before, after) = (
        find("paired/unconsolidated-eight-seals"),
        find("paired/consolidated-eight-shards"),
    );
    let hb = Envelope::decode(&bytes(&before["envelope"]))
        .unwrap()
        .history;
    let ha = Envelope::decode(&bytes(&after["envelope"]))
        .unwrap()
        .history;
    assert_eq!(hb, ha, "the same token bytes");
    assert_eq!(
        before["leaves"], after["leaves"],
        "the same state IDs, values and reference times"
    );
    assert_ne!(before["request"], after["request"]);
    let esa = |r: &Value| ["E", "S", "A"].map(|k| r["grouping"][k].as_u64().unwrap());
    assert_eq!(esa(&before), [3, 8, 8]);
    assert_eq!(esa(&after), [1, 1, 8]);
    assert!(after["gate"]["total"].as_u64() < before["gate"]["total"].as_u64());
}

#[test]
fn a_leaf_moved_past_its_anchors_time_or_out_of_its_shard_is_refused_by_this_projection_too() {
    let r = &runs()[0];
    let cfg = Cfg::from_bytes(&bytes(&r["cfg"])).unwrap();
    let env = Envelope::decode(&bytes(&r["envelope"])).unwrap();
    let pol = check_policy_body(&cfg, &env).unwrap();
    let s = sids(r);
    let plan = plan_anchors(&pol, &env, &s).unwrap();
    let mut late = times(r);
    late[1] += 2; // one past its anchor's IR time (Go: reference time = IR time - 1)
    assert_eq!(
        check_anchors(&env, &plan, &late).unwrap_err().name(),
        "ErrIRTime"
    );
    let swapped = [s[1], s[0], s[2]];
    assert_eq!(
        plan_anchors(&pol, &env, &swapped).unwrap_err().name(),
        "ErrPolicyLeafIndex"
    );
}
