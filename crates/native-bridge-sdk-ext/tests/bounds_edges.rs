#![allow(clippy::type_complexity, unused_imports, dead_code)]
//! Exact edges of the per-object bounds the estimate and the composition keep (rev's nbp#35/#36 review nits): RSMT siblings per
//! leaf, the per-UC item budget of the batch scan, the per-object item bound of the gate, and the output status word.

mod common;
use common::*;
use native_bridge_sdk_ext::certgroups::{count_items, measure};
use native_bridge_sdk_ext::compose::{compose_output_status, COMPOSE_MARKER, COMPOSE_OUTPUT_BYTES};
use native_bridge_sdk_ext::envelope::*;
use native_bridge_sdk_ext::gas::*;
use native_bridge_sdk_ext::history::{project, History};
use native_bridge_sdk_ext::limits::*;
use native_bridge_sdk_ext::proof::{build_return_proof, preflight_burn};
use native_bridge_sdk_ext::NativeError as E;

const T0: u64 = 1_700_000_040;
const UC_TS: u64 = 1_700_000_900;

/// A canonical array of `n` zeros: `n + 1` items.
fn zeros(n: usize) -> Vec<u8> {
    let mut b = match n {
        0..=23 => vec![0x80 | n as u8],
        24..=0xff => vec![0x98, n as u8],
        0x100..=0xffff => vec![0x99, (n >> 8) as u8, n as u8],
        _ => vec![
            0x9a,
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        ],
    };
    b.resize(b.len() + n, 0);
    b
}

fn ret(w: &World) -> TokenOut {
    build_token(
        w,
        &spec(1),
        &[tx_step(2, 7, T0 + 10), burn_step(T0 + 20)],
        T0,
        UC_TS,
    )
}

fn proof_env() -> Envelope {
    let w = make_world(20);
    build_return_proof(&w.bridge, &ret(&w).token).unwrap().0
}

#[test]
fn a_leaf_path_of_max_rsmt_siblings_is_priced_and_one_more_is_too_many_paths() {
    let path = |n: usize| {
        let mut bitmap = [0u8; 32];
        for i in 0..n {
            bitmap[i / 8] |= 0x80 >> (i % 8);
        }
        LeafProof {
            anchor_index: 0,
            bitmap,
            siblings: vec![[7; 32]; n],
        }
    };
    assert_eq!(MAX_RSMT_SIBLINGS, 32);
    assert_eq!(
        leaf_path_gas(&path(MAX_RSMT_SIBLINGS)).unwrap(),
        (rsmt_gas(MAX_RSMT_SIBLINGS as u64), MAX_RSMT_SIBLINGS as u64)
    );
    assert_eq!(
        leaf_path_gas(&path(MAX_RSMT_SIBLINGS + 1)).unwrap_err(),
        E::TooManyPaths
    );
}

/// The anchor's UC with its embedded input record (scanned generically by the batch scan) replaced by `ir`.
fn with_ir(a: &Anchor, ir: &[u8]) -> Anchor {
    // tag(39001) array(7) version: the input record follows at byte 5
    assert_eq!(&a.uc[..5], &[0xd9, 0x98, 0x59, 0x87, 0x01]);
    assert_eq!(&a.uc[5..5 + a.input_record.len()], &a.input_record[..]);
    let mut b = a.clone();
    b.uc = [&a.uc[..5], ir, &a.uc[5 + a.input_record.len()..]].concat();
    b
}

#[test]
fn every_uc_has_its_own_item_budget_up_to_exactly_max_cbor_items() {
    let env = proof_env();
    let a = &env.anchors[0];
    let total = measure(core::slice::from_ref(a)).unwrap().items as usize;
    let ir = count_items(&a.input_record, MAX_CBOR_ITEMS).unwrap();
    // an input record of n zeros adds n + 1 items in place of `ir`
    let n = MAX_CBOR_ITEMS - (total - ir) - 1;
    let full = with_ir(a, &zeros(n));
    assert_eq!(
        measure(core::slice::from_ref(&full)).unwrap().items as usize,
        MAX_CBOR_ITEMS
    );
    let over = with_ir(a, &zeros(n + 1));
    assert_eq!(
        measure(core::slice::from_ref(&over)).unwrap_err(),
        E::TooManyItems
    );
    // two full UCs: 2 * MAX_CBOR_ITEMS in sum, each within its own budget (no shared budget)
    let two = measure(&[full.clone(), full]).unwrap();
    assert_eq!(two.items as usize, 2 * MAX_CBOR_ITEMS);
}

#[test]
fn the_gate_bounds_each_object_by_its_own_item_scan_up_to_exactly_max_cbor_items() {
    let w = make_world(20);
    let env = build_return_proof(&w.bridge, &ret(&w).token).unwrap().0;
    let cfg = w.dep.cfg.to_bytes();
    let gate = |ir: Vec<u8>| {
        let mut e = env.clone();
        e.anchors[0].input_record = ir;
        let kr = kernel_request_bytes(cfg.len() as u64, e.history.len() as u64);
        compute_gate(&cfg, 4096, kr, &e)
    };
    let base = gate(env.anchors[0].input_record.clone()).unwrap();
    // an IR opening of exactly MAX_CBOR_ITEMS items, after the Cfg and the policy body have spent theirs: within its own bound
    let at = gate(zeros(MAX_CBOR_ITEMS - 1)).unwrap();
    let ir = count_items(&env.anchors[0].input_record, MAX_CBOR_ITEMS).unwrap() as u64;
    assert_eq!(at.j, base.j - ir + MAX_CBOR_ITEMS as u64);
    assert_eq!(gate(zeros(MAX_CBOR_ITEMS)).unwrap_err(), E::TooManyItems);
}

#[test]
fn an_output_status_above_64_bits_is_not_an_output() {
    let mut out = vec![0u8; COMPOSE_OUTPUT_BYTES];
    out[..32].copy_from_slice(&COMPOSE_MARKER);
    out[63] = 61;
    assert_eq!(compose_output_status(&out), Some(61));
    out[56] = 1;
    assert_eq!(compose_output_status(&out), Some((1 << 56) | 61));
    for i in [32, 40, 55] {
        let mut high = out.clone();
        high[i] = 1;
        assert_eq!(compose_output_status(&high), None, "status byte {i}");
    }
    let mut marker = out.clone();
    marker[31] = 1;
    assert_eq!(compose_output_status(&marker), None);
    assert_eq!(
        compose_output_status(&out[..COMPOSE_OUTPUT_BYTES - 1]),
        None
    );
}

#[test]
fn a_composed_history_above_the_kernels_128_kib_decodes_and_is_estimated_while_the_kernel_refuses_it(
) {
    let w = make_world(20);
    let parts = lock_parts(&w, &spec(1));
    let tw = Tweaks {
        mint_data: Some(Some(vec![7u8; 140_000])),
        ..Tweaks::default()
    };
    let held = build_token_with(
        &w,
        &spec(1),
        &parts,
        &tw,
        &[tx_step(2, 7, T0 + 10)],
        T0,
        UC_TS,
    );
    let bytes = project(&held.token);
    assert!(bytes.len() > MAX_SEMANTIC_BYTES, "{}", bytes.len());
    assert_eq!(History::decode(&bytes).unwrap_err(), E::InputTooLarge);
    assert_eq!(History::decode_composed(&bytes).unwrap().transfers.len(), 1);
    assert!(preflight_burn(&w.bridge, &held.token).unwrap().native > 0);
}
