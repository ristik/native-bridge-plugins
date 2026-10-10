#![allow(clippy::type_complexity, unused_imports, unused_variables, dead_code)]
//! The named profile-v3 bounds against `protocol/profile-v3.json`, the shared gas gate at the worst
//! admitted bundle, the DN-B depth-1 topology and the burn-time preflight.

mod common;
use common::*;
use native_bridge_sdk_ext::envelope::*;
use native_bridge_sdk_ext::gas::*;
use native_bridge_sdk_ext::limits::*;
use native_bridge_sdk_ext::proof::{build_return_proof, preflight_burn};
use native_bridge_sdk_ext::NativeError as E;

const T0: u64 = 1_700_000_040;
const UC_TS: u64 = 1_700_000_900;

#[test]
fn the_named_bounds_are_the_limits_of_profile_v3_the_one_source() {
    let p: serde_json::Value = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/profile-v3.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let l = &p["limits"];
    let n = |k: &str| l[k].as_u64().unwrap_or_else(|| panic!("limit {k}"));
    assert_eq!(MAX_ANCHORS as u64, n("aggregatorAnchors"));
    assert_eq!(MAX_LEAVES as u64, n("leaves"));
    assert_eq!(MAX_TRANSFERS as u64, n("transfers"));
    assert_eq!(MAX_SEMANTIC_BYTES as u64, n("semanticBytes"));
    assert_eq!(MAX_ENVELOPE_BYTES as u64, n("envelopeBytes"));
    assert_eq!(MAX_ANCHOR_UC_BYTES as u64, n("anchorUcBytes"));
    assert_eq!(MAX_RSMT_SIBLINGS as u64, n("rsmtSiblingsPerLeaf"));
    assert_eq!(MAX_PATH_STEPS as u64, n("pathSteps"));
    assert_eq!(MAX_POLICY_BYTES as u64, n("policyBytes"));
    assert_eq!(MAX_UNICITY_STEPS as u64, n("unicityStepsPerUc"));
    assert_eq!(MAX_INPUT_RECORD_BYTES as u64, n("irBytes"));
    assert_eq!(TX_GAS_BUDGET, n("txGasBudget"));
    assert_eq!(GAS_RESERVE, n("gasReserve"));
    assert_eq!(MAX_JUSTIFICATION_BYTES as u64, n("justificationBytes"));
}

#[test]
fn the_shared_gate_prices_the_worst_admitted_bundle_as_the_oracle_and_the_contract_do() {
    // The numbers of bft-core `TestWorstAdmittedBundleFitsBudget` and the contract's `BridgeBounds`.
    let uc = uc_gas(
        1,
        MAX_ANCHOR_UC_BYTES as u64,
        MAX_SIGNATURES as u64,
        1 + MAX_UNICITY_STEPS as u64,
    );
    assert_eq!(uc, 1_768_798);
    assert_eq!(rsmt_gas(MAX_RSMT_SIBLINGS as u64), 28_810);
    assert_eq!(intrinsic_gas(MAX_ENVELOPE_BYTES as u64), 1_069_576);
    let b2 = b2_gas(
        kernel_request_bytes(MAX_SEMANTIC_BYTES as u64, MAX_SEMANTIC_BYTES as u64),
        MAX_LEAVES as u64,
    );
    assert_eq!(b2, 908_560);
    let worst = intrinsic_gas(MAX_ENVELOPE_BYTES as u64)
        + b2
        + MAX_ANCHORS as u64 * uc
        + MAX_LEAVES as u64 * rsmt_gas(MAX_RSMT_SIBLINGS as u64)
        + GAS_RESERVE;
    assert_eq!(worst, 6_976_692);
    assert!(worst <= TX_GAS_BUDGET);
}

/// The cumulative step bound cannot bind: the anchor, leaf and sibling bounds already imply it.
const _: () = assert!(
    MAX_ANCHORS * (1 + MAX_UNICITY_STEPS) + MAX_LEAVES * MAX_RSMT_SIBLINGS <= MAX_PATH_STEPS
);

/// A return whose leaves occupy both shards of the depth-1 world (the owner key moves the state IDs).
fn two_shard_return(w: &World) -> TokenOut {
    for k in 2u8..60 {
        let out = build_token(
            w,
            &spec(1),
            &[tx_step(k, 7, T0 + 10), burn_step(T0 + 20)],
            T0,
            UC_TS,
        );
        let rows: std::collections::BTreeSet<usize> = out
            .leaves
            .iter()
            .map(|(sid, _)| w.policy.shard_row(sid))
            .collect();
        if rows.len() == 2 {
            return out;
        }
    }
    panic!("no two-shard fixture");
}

#[test]
fn depth_one_one_anchor_per_distinct_uc_in_first_use_order_each_leaf_under_its_own_shard() {
    let w = make_world_depth(20, 1);
    let out = two_shard_return(&w);
    assert_eq!(out.ucs.len(), 2);
    let (env, v, gate) = build_return_proof(&w.bridge, &out.token).unwrap();
    assert_eq!(env.anchors.len(), 2);
    let sids: Vec<[u8; 32]> = v.outcome.leaves.iter().map(|l| l.sid).collect();
    let rows: Vec<usize> = sids.iter().map(|s| w.policy.shard_row(s)).collect();
    let mut order: Vec<usize> = Vec::new();
    for r in &rows {
        if !order.contains(r) {
            order.push(*r);
        }
    }
    for (j, r) in order.iter().enumerate() {
        assert_eq!(env.anchors[j].shard, w.policy.shard_id(*r));
        assert_eq!(env.anchors[j].shard_conf_hash, w.agg_confs[*r]);
    }
    let want: Vec<u16> = rows
        .iter()
        .map(|r| order.iter().position(|x| x == r).unwrap() as u16)
        .collect();
    assert_eq!(
        env.leaf_proofs
            .iter()
            .map(|l| l.anchor_index)
            .collect::<Vec<_>>(),
        want
    );
    let pol = check_policy_body(&w.dep.cfg, &env).unwrap();
    let plan = plan_anchors(&pol, &env, &sids).unwrap();
    let times: Vec<u64> = v.outcome.leaves.iter().map(|l| l.reference_time).collect();
    check_anchors(&env, &plan, &times).unwrap();
    // the shard-tree sibling of the depth-1 certificate is a path step of the gate
    assert_eq!(scan_anchor(&env.anchors[0], 1).unwrap().steps, 1);
    assert_eq!(scan_anchor(&env.anchors[0], 0).unwrap_err(), E::AnchorAuth);
    assert!(gate.total <= TX_GAS_BUDGET);
    assert_eq!(Envelope::decode(&env.encode()).unwrap(), env);
    // a leaf under the other shard's anchor is refused
    let mut swapped = env.clone();
    for l in &mut swapped.leaf_proofs {
        l.anchor_index = 1 - l.anchor_index;
    }
    assert_eq!(
        plan_anchors(&pol, &swapped, &sids).unwrap_err(),
        E::PolicyLeafIndex
    );
}

#[test]
fn burn_time_preflight_admits_a_redeemable_history_and_refuses_one_leaf_more_than_the_bound() {
    let w = make_world(20);
    let steps = |n: usize| -> Vec<Step> {
        (0..n)
            .map(|i| tx_step(i as u8 + 2, i as u8 + 1, T0 + 1 + i as u64))
            .collect()
    };
    let fits = build_token(&w, &spec(1), &steps(MAX_LEAVES - 2), T0, UC_TS);
    let gate = preflight_burn(&w.bridge, &fits.token).unwrap();
    assert!(gate.total <= TX_GAS_BUDGET, "{}", gate.total);
    let too_long = build_token(&w, &spec(1), &steps(MAX_LEAVES - 1), T0, UC_TS);
    assert_eq!(
        preflight_burn(&w.bridge, &too_long.token).unwrap_err(),
        E::TooManyTx
    );
}
