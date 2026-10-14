#![allow(clippy::type_complexity, unused_imports, unused_variables, dead_code)]
//! The named profile-v4 bounds against `protocol/profile-v4.json`, the shared gas gate at the worst
//! admitted bundle, the DN-B depth-1 topology and the burn-time preflight.

mod common;
use common::*;
use native_bridge_sdk_ext::certgroups::{batch_gas, measure, Counts};
use native_bridge_sdk_ext::envelope::*;
use native_bridge_sdk_ext::gas::*;
use native_bridge_sdk_ext::limits::*;
use native_bridge_sdk_ext::proof::{
    build_return_proof, check_burn_projection, leaf_state_ids, preflight_burn, BURN_HISTORY_BYTES,
};
use native_bridge_sdk_ext::NativeError as E;

const T0: u64 = 1_700_000_040;
const UC_TS: u64 = 1_700_000_900;

#[test]
fn the_named_bounds_are_the_limits_of_profile_v3_the_one_source() {
    let p: serde_json::Value = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/profile-v4.json"
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
    assert_eq!(native_bridge_sdk_ext::NATIVE_BRIDGE_PROTO_VERSION, 4);
    assert_eq!(BRIDGE_CBOR_ITEMS as u64, n("bridgeCborItems"));
    assert_eq!(BRIDGE_ITEM_GAS, n("bridgeItemGas"));
    assert_eq!(MAX_SHARD_DEPTH as u64, n("shardDepthMax"));
    assert_eq!(MAX_CBOR_ITEMS as u64, n("cborItems"));
}

#[test]
fn the_shared_gate_prices_its_components_as_the_oracle_and_the_contract_do() {
    assert_eq!(rsmt_gas(MAX_RSMT_SIBLINGS as u64), 28_810);
    // 21000 + 16*D_max + 80*B_env with D_max = 4 + 128 + pad32(B_cfg) + pad32(B_env)
    assert_eq!(
        intrinsic_gas(512, MAX_ENVELOPE_BYTES as u64),
        21_000 + 16 * (132 + 512 + 65_536) + 80 * 65_536
    );
    assert_eq!(
        intrinsic_gas(513, 100),
        21_000 + 16 * (132 + 544 + 128) + 80 * 100,
        "both lengths are padded to words"
    );
    assert_eq!(
        b2_gas(
            kernel_request_bytes(MAX_SEMANTIC_BYTES as u64, MAX_SEMANTIC_BYTES as u64),
            MAX_LEAVES as u64
        ),
        908_560
    );
    assert_eq!(item_gas(BRIDGE_CBOR_ITEMS as u64), 4_096_000);
    // G_batch = 60000 + 16*C + 500*K*(K-1) + 1100 + 29900*E + 6000*Q + 2000*A + 250*P
    let n = Counts {
        k: 3,
        c: 1000,
        e: 2,
        s: 2,
        q: 8,
        a: 3,
        p: 7,
        items: 0,
    };
    assert_eq!(
        batch_gas(&n),
        60_000 + 16_000 + 500 * 6 + 1_100 + 2 * 29_900 + 8 * 6_000 + 3 * 2_000 + 7 * 250
    );
}

#[test]
fn the_best_case_projection_fits_at_the_bounds_with_one_anchor() {
    let (gate, envelope) = projected_gate(300, 150, MAX_LEAVES as u64, MAX_SEMANTIC_BYTES as u64);
    assert!(gate.total <= TX_GAS_BUDGET, "{}", gate.total);
    assert!(envelope <= MAX_ENVELOPE_BYTES as u64, "{envelope}");
    assert_eq!(
        gate.grouping.k, 1,
        "a single certificate may serve every leaf: the best case is never one anchor per shard"
    );
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
        let rows: std::collections::BTreeSet<usize> =
            out.leaves.iter().map(|(sid, _)| row_of(w, sid)).collect();
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
    let rows: Vec<usize> = sids.iter().map(|s| row_of(&w, s)).collect();
    let mut order: Vec<usize> = Vec::new();
    for r in &rows {
        if !order.contains(r) {
            order.push(*r);
        }
    }
    for (j, r) in order.iter().enumerate() {
        assert_eq!(env.anchors[j].shard, shard_of(&w, *r));
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
    // the depth of each anchor comes from its own shard ID, and its shard-tree sibling is a path step of the gate
    assert_eq!(measure(&env.anchors[0..1], 0).unwrap().p, 1);
    let mut wrong = env.anchors[0].clone();
    wrong.shard = vec![0x80];
    assert_eq!(measure(&[wrong], 0).unwrap_err(), E::ShardMismatch);
    assert!(gate.total <= TX_GAS_BUDGET);
    assert_eq!(Envelope::decode(&env.encode()).unwrap(), env);
    // routing: the state ID of every leaf is what the host asks its aggregator for; the anchors carry the shards the certificates name
    assert_eq!(leaf_state_ids(&out.token), sids);
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

#[test]
fn a_real_burn_leaf_adds_no_more_history_than_the_bound_and_the_best_case_is_a_lower_bound() {
    use native_bridge_sdk_ext::error::Family;
    use native_bridge_sdk_ext::history::project;
    use native_bridge_sdk_ext::proof::BURN_HISTORY_BYTES;
    let w = make_world(20);
    let held = build_token(&w, &spec(1), &[tx_step(2, 7, T0 + 10)], T0, UC_TS);
    let burned = build_token(
        &w,
        &spec(1),
        &[tx_step(2, 7, T0 + 10), burn_step(T0 + 20)],
        T0,
        UC_TS,
    );
    let added = project(&burned.token).len() - project(&held.token).len();
    assert!(added > 0 && added <= BURN_HISTORY_BYTES, "{added}");
    for uc in &burned.ucs {
        assert!(uc.to_cbor().len() as u64 >= BEST_UC_BYTES);
    }
    // the retryable unavailability is its own family; the bound and relation failures keep theirs
    assert_eq!(E::ProofUnavailable.family(), Family::Unavailable);
    assert_eq!(E::PolicyAnchors.family(), Family::Invalid);
    assert_eq!(E::TooManyPaths.family(), Family::Budget);
}

#[test]
fn the_burn_preflight_refuses_a_history_near_the_bound_and_a_best_case_the_gate_cannot_pass() {
    let edge = MAX_SEMANTIC_BYTES - BURN_HISTORY_BYTES;
    let ok = check_burn_projection(200, 300, MAX_LEAVES as u64, edge).unwrap();
    assert!(ok.total <= TX_GAS_BUDGET, "exactly at the margin passes");
    assert_eq!(
        check_burn_projection(200, 300, MAX_LEAVES as u64, edge + 1).unwrap_err(),
        E::InputTooLarge
    );
    assert!(check_burn_projection(200, 300, 8, 500).unwrap().total <= TX_GAS_BUDGET);
}

#[test]
fn preflight_burn_on_a_held_token_refuses_a_history_within_the_burn_margin_of_the_bound() {
    use native_bridge_sdk_ext::history::project;
    let w = make_world(20);
    let held = |n: usize| {
        let tw = Tweaks {
            mint_data: Some(Some(vec![7u8; n])),
            ..Tweaks::default()
        };
        let parts = lock_parts(&w, &spec(1));
        build_token_with(
            &w,
            &spec(1),
            &parts,
            &tw,
            &[tx_step(2, 7, T0 + 10)],
            T0,
            UC_TS,
        )
    };
    let edge = MAX_SEMANTIC_BYTES - BURN_HISTORY_BYTES;
    // the projection grows one byte per data byte once the byte-string header width is fixed
    let probe = 4096usize;
    let base = project(&held(probe).token).len();
    let n = probe + (edge - base);
    let fits = held(n);
    assert_eq!(project(&fits.token).len(), edge, "exactly at the margin");
    assert!(preflight_burn(&w.bridge, &fits.token).unwrap().total <= TX_GAS_BUDGET);
    assert_eq!(
        preflight_burn(&w.bridge, &held(n + 1).token).unwrap_err(),
        E::InputTooLarge
    );
}

#[test]
fn preflight_burn_prices_a_held_token_exactly() {
    let w = make_world(20);
    let held = build_token(&w, &spec(1), &[tx_step(2, 7, T0 + 10)], T0, UC_TS);
    let gate = preflight_burn(&w.bridge, &held.token).unwrap();
    // best case: ONE 445-byte one-signature certificate (39 items, depth 0, no shard sibling), an empty input record (12 items), the
    // known history only
    assert_eq!(
        [
            gate.total,
            gate.batch,
            gate.items,
            gate.b2,
            gate.intrinsic,
            gate.rsmt
        ],
        [1_722_174, 107_896, 72_000, 124_960, 404_040, 13_278]
    );
}

#[test]
fn plan_anchors_itself_refuses_more_than_the_ceiling_with_too_many_paths() {
    let w = make_world(20);
    let out = build_token(
        &w,
        &spec(1),
        &[tx_step(2, 7, T0 + 10), burn_step(T0 + 20)],
        T0,
        UC_TS,
    );
    let (env, v, _) = build_return_proof(&w.bridge, &out.token).unwrap();
    let pol = check_policy_body(&w.dep.cfg, &env).unwrap();
    let mut over = env.clone();
    while over.anchors.len() <= MAX_ANCHORS {
        over.anchors.push(over.anchors[0].clone());
    }
    let sids: Vec<[u8; 32]> = v.outcome.leaves.iter().map(|l| l.sid).collect();
    assert_eq!(
        plan_anchors(&pol, &over, &sids).unwrap_err(),
        E::TooManyPaths
    );
}
