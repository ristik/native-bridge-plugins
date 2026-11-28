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
use std::sync::atomic::Ordering;

use native_bridge_sdk_ext::nb2::abi::deposit_calldata;
use native_bridge_sdk_ext::nb2::deposit::{
    decode_receipt_backing, encode_receipt_backing, first_owner_of, limits::RECEIPT_LEAF_NODE_BYTES,
};
use native_bridge_sdk_ext::nb2::errors::{Rule, WalletReason};
use native_bridge_sdk_ext::nb2::evm::{sign_tx, EvmSigner, TxRequest};
use native_bridge_sdk_ext::nb2::journal::{unhex, unhex_n, MemoryJournalStore};
use native_bridge_sdk_ext::nb2::tokenops::{local_owner, OwnerSigner};
use native_bridge_sdk_ext::nb2::util::hex0x;
use nb2_world::*;
use num_bigint::BigUint;
use serde_json::json;
use serde_json::Value;

const WALLET: &str = "interop wallet";
const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/nb2-journal/");

fn big(v: u64) -> BigUint {
    BigUint::from(v)
}

#[test]
fn an_older_proven_deposit_reports_its_oversized_receipt() {
    let w = setup();
    let b = NativeBridgeV2::open(w.options(WALLET, World::store())).unwrap();
    let payer = w.evm_account("cached deposit payer");
    let owner = local_owner(&key("cached deposit owner"));
    let plan = b.plan_deposit(&big(7), &owner.public_key()).unwrap();
    b.submit_deposit(&plan, &payer).unwrap();
    b.collect_deposit_proof(plan.intent).unwrap();
    let mut saved = b.journal.deposit(plan.intent).unwrap().unwrap();
    let mut j = decode_receipt_backing(&unhex(saved.reason.as_ref().unwrap()).unwrap()).unwrap();
    j.proof
        .nodes
        .last_mut()
        .unwrap()
        .resize(RECEIPT_LEAF_NODE_BYTES + 1, 0);
    saved.reason = Some(hex0x(&encode_receipt_backing(&j)));
    b.journal.put_deposit(&saved).unwrap();
    let calls = w.agg.st.lock().unwrap().calls;
    for err in [
        b.collect_deposit_proof(plan.intent).unwrap_err(),
        b.mint(plan.intent).unwrap_err(),
    ] {
        let err = err.rule().unwrap();
        assert_eq!(err.rule, Rule::InputTooLarge);
        assert!(err
            .detail
            .as_deref()
            .unwrap()
            .contains("deposit receipt exceeds the offline proof limits"));
    }
    assert_eq!(
        b.journal.deposit(plan.intent).unwrap().unwrap().status,
        "proven"
    );
    assert_eq!(w.agg.st.lock().unwrap().calls, calls);
}

/// Stage A in a fresh world; the snapshot after it. Every intermediate state the journal can hold is left for stage B:
/// minted, proven, deposited (with a second deposit of its rho in `seenDeposits`), submitted with a replaced send
/// (`nonceUsedAt`), planned; a split with one child minted; returns burned, planned, burn-requested and submitted (in the pool);
/// and unknown fields in two records.
fn stage_a() -> Value {
    let w = setup();
    let store = World::store();
    let b = NativeBridgeV2::open(w.options(WALLET, store.clone())).unwrap();
    let payer = w.evm_account("interop");
    let alice = local_owner(&key("interop alice"));
    let bob = local_owner(&key("interop bob"));
    let minted = |v: u64| {
        let p = b.plan_deposit(&big(v), &alice.public_key()).unwrap();
        b.submit_deposit(&p, &payer).unwrap();
        b.collect_deposit_proof(p.intent).unwrap();
        b.mint(p.intent).unwrap()
    };
    // intent 0: 100, split 60 + 40; the 60 burned, the 40 planned
    let t100 = minted(100);
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
    // intent 1: proven
    let p7 = b.plan_deposit(&big(7), &alice.public_key()).unwrap();
    b.submit_deposit(&p7, &payer).unwrap();
    b.collect_deposit_proof(p7.intent).unwrap();
    // intent 2: 30, split into 10 + 20, interrupted after the burn and the first child
    let t30 = minted(30);
    *w.agg.fail_after.lock().unwrap() = Some(2);
    assert!(b
        .split(
            &t30,
            &alice,
            &[
                (bob.public_key().to_vec(), big(10)),
                (bob.public_key().to_vec(), big(20))
            ],
            None
        )
        .is_err());
    *w.agg.fail_after.lock().unwrap() = None;
    // intent 3: 9, its return burn-requested (the aggregator down at the burn)
    let t9 = minted(9);
    let r9 = b
        .plan_return(&t9, &recipient("interop r9"), &payer.address(), None)
        .unwrap();
    w.agg.down.store(true, Ordering::SeqCst);
    assert!(b.burn(&r9.return_id, &alice).is_err());
    w.agg.down.store(false, Ordering::SeqCst);
    // intent 4: 3, deposited; a second deposit of its rho (to bob) is in seenDeposits
    let p3 = b.plan_deposit(&big(3), &alice.public_key()).unwrap();
    b.submit_deposit(&p3, &payer).unwrap();
    let nonce = |tag: &str| {
        u64::from_str_radix(
            &w.chain
                .real(
                    "eth_getTransactionCount",
                    json!([hex0x(&payer.address()), tag]),
                )
                .unwrap()
                .as_str()
                .unwrap()[2..],
            16,
        )
        .unwrap()
    };
    let tx = |nonce: u64, to: [u8; 20], value: u64, data: Vec<u8>| {
        sign_tx(
            &payer,
            &TxRequest {
                chain_id: CHAIN_ID,
                nonce,
                max_priority_fee_per_gas: big(1),
                max_fee_per_gas: big(15),
                gas: 200_000,
                to,
                value: big(value),
                data,
            },
        )
        .unwrap()
    };
    let extra = tx(
        nonce("pending"),
        VAULT,
        3,
        deposit_calldata(&first_owner_of(&bob.public_key()), &p3.rho),
    );
    w.chain
        .real("eth_sendRawTransaction", json!([hex0x(&extra.raw)]))
        .unwrap();
    b.recover_deposits(5).unwrap();
    // intent 5: 6, submitted, its send replaced by another transaction of the same nonce (nonceUsedAt journaled)
    let p6 = b.plan_deposit(&big(6), &alice.public_key()).unwrap();
    w.chain.with(|s| s.auto_mine = false);
    assert_eq!(
        b.submit_deposit(&p6, &payer).err().and_then(|e| e.reason()),
        Some(WalletReason::Unconfirmed)
    );
    w.chain.drop_pool();
    let other = tx(nonce("latest"), recipient("interop z"), 1, vec![]);
    w.chain
        .real("eth_sendRawTransaction", json!([hex0x(&other.raw)]))
        .unwrap();
    w.chain.flush();
    w.chain.with(|s| s.auto_mine = true);
    assert_eq!(
        b.submit_deposit(p6.intent, &payer)
            .err()
            .and_then(|e| e.reason()),
        Some(WalletReason::Unconfirmed)
    );
    // intent 6: 8, its redeem submitted and still in the pool
    let t8 = minted(8);
    let r8 = b
        .plan_return(&t8, &recipient("interop r8"), &payer.address(), None)
        .unwrap();
    b.burn(&r8.return_id, &alice).unwrap();
    w.chain.with(|s| s.auto_mine = false);
    assert_eq!(
        b.submit_redeem(&r8.return_id, &payer).unwrap().state(),
        "pending"
    );
    // intent 7: planned
    b.plan_deposit(&big(5), &alice.public_key()).unwrap();
    // unknown fields in the intents record and in the planned return
    let mut m = store.dump();
    for (k, v) in m.iter_mut() {
        if k.ends_with("/intents") || (k.contains("/return/") && v.contains("\"amount\":\"40\"")) {
            let mut x: Value = serde_json::from_str(v).unwrap();
            x["futureField"] = json!({"from": "stage A"});
            *v = x.to_string();
        }
    }
    w.snapshot(&MemoryJournalStore::from_map(m))
}

/// Stage B over a snapshot written by either plug-in.
fn stage_b(snap: &Value) {
    let (w, journal): (World, Arc<MemoryJournalStore>) = World::restore(snap);
    let b = NativeBridgeV2::open(w.options(WALLET, journal.clone())).unwrap();
    let payer = w.evm_account("interop");
    let alice = local_owner(&key("interop alice"));
    let bob = local_owner(&key("interop bob"));
    let statuses: Vec<String> = b
        .journal
        .deposits()
        .unwrap()
        .iter()
        .map(|d| d.status.clone())
        .collect();
    assert_eq!(
        statuses,
        [
            "minted",
            "proven",
            "minted",
            "minted",
            "deposited",
            "submitted",
            "minted",
            "planned"
        ]
    );
    let rets = b.journal.returns().unwrap();
    let by = |amount: &str| rets.iter().find(|r| r.amount == amount).unwrap().clone();
    let (r60, r40, r9, r8) = (by("60"), by("40"), by("9"), by("8"));
    assert_eq!(
        [&r60.status, &r40.status, &r9.status, &r8.status],
        ["burned", "planned", "burn-requested", "submitted"]
    );
    let id = |r: &native_bridge_sdk_ext::nb2::journal::ReturnRecord| -> [u8; 32] {
        unhex_n(&r.return_id).unwrap()
    };
    // the submitted redeem lands and reconciles
    w.chain.flush();
    assert_eq!(b.reconcile(&id(&r8)).unwrap().state(), "paid");
    // proven mints; planned is sent, proven and minted
    let v7 = b.verify_token(&b.mint(1).unwrap()).unwrap();
    assert_eq!(
        (v7.amount, v7.owner),
        (big(7), Some(alice.public_key().to_vec()))
    );
    b.submit_deposit(7u64, &payer).unwrap();
    b.collect_deposit_proof(7).unwrap();
    assert_eq!(b.verify_token(&b.mint(7).unwrap()).unwrap().amount, big(5));
    // the replaced send is dead after depth on a certified block: one new send
    for _ in 0..6 {
        w.chain.mine_empty();
    }
    b.submit_deposit(5u64, &payer).unwrap();
    b.collect_deposit_proof(5).unwrap();
    assert_eq!(b.verify_token(&b.mint(5).unwrap()).unwrap().amount, big(6));
    // both deposits of intent 4's rho mint, each to its own first owner
    b.collect_deposit_proof(4).unwrap();
    assert_eq!(b.verify_token(&b.mint(4).unwrap()).unwrap().amount, big(3));
    let seen = b
        .journal
        .deposit(4)
        .unwrap()
        .unwrap()
        .seen_deposits
        .unwrap();
    assert_eq!(seen.len(), 2);
    let extra = b
        .mint_extra_deposit(4, seen[1].deposit_number.parse().unwrap())
        .unwrap();
    assert_eq!(
        b.verify_token(&extra).unwrap().owner,
        Some(bob.public_key().to_vec())
    );
    // the interrupted split resumes from its record
    let sp: Vec<String> = journal
        .dump()
        .into_iter()
        .filter(|(k, _)| k.contains("/split/"))
        .map(|(_, v)| v)
        .collect();
    let rec = sp
        .iter()
        .map(|v| serde_json::from_str::<Value>(v).unwrap())
        .find(|v| v["status"] == "burned")
        .unwrap();
    assert_eq!(
        rec["outputs"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| !o["token"].is_null())
            .count(),
        1
    );
    let src = native_bridge_sdk_ext::nb2::journal::unhex(rec["source"].as_str().unwrap()).unwrap();
    let kids = b
        .split(
            &src,
            &alice,
            &[],
            Some(unhex_n(rec["splitId"].as_str().unwrap()).unwrap()),
        )
        .unwrap();
    assert_eq!(
        kids.iter()
            .map(|t| b.verify_token(t).unwrap().amount)
            .collect::<Vec<_>>(),
        [big(10), big(20)]
    );
    // the burn-requested return finishes its burn; every return redeems
    b.burn(&id(&r9), &alice).unwrap();
    b.burn(&id(&r40), &bob).unwrap();
    for r in [&r9, &r60, &r40] {
        assert_eq!(b.submit_redeem(&id(r), &payer).unwrap().state(), "paid");
    }
    let paid: Vec<BigUint> = ["interop r1", "interop r2", "interop r9", "interop r8"]
        .iter()
        .map(|s| w.chain.balance_of(&recipient(s)))
        .collect();
    assert_eq!(paid, [big(60), big(40), big(9), big(8)]);
    assert_eq!(
        w.chain.with(|s| s.vault.state().outstanding),
        big(171 - 117)
    );
    // unknown fields survive the rewrites; the intent counter continues past the other plug-in's mark
    assert_eq!(
        b.plan_deposit(&big(1), &alice.public_key()).unwrap().intent,
        8
    );
    let m = journal.dump();
    for (k, v) in &m {
        if k.ends_with("/intents") || (k.contains("/return/") && v.contains("\"amount\":\"40\"")) {
            assert_eq!(
                serde_json::from_str::<Value>(v).unwrap()["futureField"],
                json!({"from": "stage A"}),
                "{k}"
            );
        }
    }
    assert_eq!(
        b.status()
            .unwrap()
            .iter()
            .filter(|x| x.ends_with(": paid"))
            .count(),
        4
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
