//! The cross-language journal round trip (bft-core#1104), the same two stages as the TypeScript
//! `test/nb2/journal-interop.ts`: stage A plans and half-finishes deposits, a split and two returns; stage B continues them from
//! the journal alone. Each plug-in writes a snapshot of the whole offline world after stage A (`tests/nb2-journal/`), and each
//! continues the other's.
//!
//! `NB2_WRITE_FIXTURE=1 cargo test --test nb2_journal_interop write_the_rust_fixture` rewrites `rust-written.json`.
#![cfg(feature = "host")]

mod nb2_world;

use std::sync::Arc;

use native_bridge_sdk_ext::nb2::bridge::NativeBridgeV2;
use native_bridge_sdk_ext::nb2::evm::EvmSigner;
use native_bridge_sdk_ext::nb2::journal::{unhex_n, MemoryJournalStore};
use native_bridge_sdk_ext::nb2::tokenops::{local_owner, OwnerSigner};
use nb2_world::*;
use num_bigint::BigUint;
use serde_json::Value;

const WALLET: &str = "interop wallet";
const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/nb2-journal/");

fn big(v: u64) -> BigUint {
    BigUint::from(v)
}

/// Stage A in a fresh world; the snapshot after it.
fn stage_a() -> Value {
    let w = setup();
    let store = World::store();
    let b = NativeBridgeV2::open(w.options(WALLET, store.clone())).unwrap();
    let payer = w.evm_account("interop");
    let alice = local_owner(&key("interop alice"));
    let bob = local_owner(&key("interop bob"));
    let p = b.plan_deposit(&big(100), &alice.public_key()).unwrap();
    b.submit_deposit(&p, &payer).unwrap();
    b.collect_deposit_proof(p.intent).unwrap();
    let t100 = b.mint(p.intent).unwrap();
    let parts = b
        .split(
            &t100,
            &alice,
            &[
                (bob.public_key().to_vec(), big(60)),
                (bob.public_key().to_vec(), big(40)),
            ],
            None,
        )
        .unwrap();
    let r60 = b
        .plan_return(&parts[0], &recipient("interop r1"), &payer.address(), None)
        .unwrap();
    b.burn(&r60.return_id, &bob).unwrap();
    b.plan_return(&parts[1], &recipient("interop r2"), &payer.address(), None)
        .unwrap();
    let p7 = b.plan_deposit(&big(7), &alice.public_key()).unwrap();
    b.submit_deposit(&p7, &payer).unwrap();
    b.collect_deposit_proof(p7.intent).unwrap();
    b.plan_deposit(&big(5), &alice.public_key()).unwrap();
    w.snapshot(&store)
}

/// Stage B over a snapshot written by either plug-in.
fn stage_b(snap: &Value) {
    let (w, journal): (World, Arc<MemoryJournalStore>) = World::restore(snap);
    let b = NativeBridgeV2::open(w.options(WALLET, journal)).unwrap();
    let payer = w.evm_account("interop");
    let alice = local_owner(&key("interop alice"));
    let bob = local_owner(&key("interop bob"));
    assert_eq!(
        b.journal
            .deposits()
            .unwrap()
            .iter()
            .map(|d| d.status.as_str())
            .collect::<Vec<_>>(),
        ["minted", "proven", "planned"]
    );
    let rets = b.journal.returns().unwrap();
    let r60 = rets.iter().find(|r| r.amount == "60").unwrap();
    let r40 = rets.iter().find(|r| r.amount == "40").unwrap();
    assert_eq!(r60.status, "burned");
    assert_eq!(r40.status, "planned");
    // the proven deposit mints; the planned one is sent, proven and minted
    let t7 = b.mint(1).unwrap();
    let v7 = b.verify_token(&t7).unwrap();
    assert_eq!(v7.amount, big(7));
    assert_eq!(v7.owner, Some(alice.public_key().to_vec()));
    b.submit_deposit(2u64, &payer).unwrap();
    b.collect_deposit_proof(2).unwrap();
    assert_eq!(b.verify_token(&b.mint(2).unwrap()).unwrap().amount, big(5));
    // the planned return burns and both redeem
    let id60: [u8; 32] = unhex_n(&r60.return_id).unwrap();
    let id40: [u8; 32] = unhex_n(&r40.return_id).unwrap();
    b.burn(&id40, &bob).unwrap();
    assert_eq!(b.submit_redeem(&id60, &payer).unwrap().state(), "paid");
    assert_eq!(b.submit_redeem(&id40, &payer).unwrap().state(), "paid");
    assert_eq!(w.chain.balance_of(&recipient("interop r1")), big(60));
    assert_eq!(w.chain.balance_of(&recipient("interop r2")), big(40));
    assert_eq!(w.chain.with(|s| s.vault.state().outstanding), big(12));
    // the intent counter continues past the other plug-in's mark
    assert_eq!(
        b.plan_deposit(&big(1), &alice.public_key()).unwrap().intent,
        3
    );
    assert_eq!(
        b.status()
            .unwrap()
            .iter()
            .filter(|x| x.ends_with(": paid"))
            .count(),
        2
    );
}

fn read(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{DIR}{name}")).unwrap()).unwrap()
}

#[test]
fn a_journal_written_by_the_typescript_plugin_continues_in_the_rust_plugin() {
    stage_b(&read("ts-written.json"));
}

#[test]
fn the_committed_rust_written_snapshot_continues_here_too() {
    stage_b(&read("rust-written.json"));
}

#[test]
fn stage_a_then_stage_b_in_this_plugin_through_a_json_round_trip_of_the_snapshot() {
    let s = stage_a();
    stage_b(&serde_json::from_str(&s.to_string()).unwrap());
}

#[test]
fn write_the_rust_fixture() {
    if std::env::var("NB2_WRITE_FIXTURE").is_err() {
        return;
    }
    let s = stage_a();
    std::fs::write(
        format!("{DIR}rust-written.json"),
        format!("{}\n", serde_json::to_string_pretty(&s).unwrap()),
    )
    .unwrap();
}
