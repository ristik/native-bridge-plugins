//! The bridge API against the offline simulator, the ports of the TypeScript `test/nb2` suites: the persistence rules
//! (journal.test.ts), the reference scenario (scenario.test.ts), the witness builder (witness.test.ts), the preflight refusals
//! (preflight.test.ts) and the custody fixes of the nbp#76 review (review.test.ts).
#![cfg(feature = "host")]

mod nb2_world;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use native_bridge_sdk_ext::nb2::abi::{
    classify_redeem_error, decode_revert, deposit_calldata, revert_data, ErrArg, RedeemAction,
};
use native_bridge_sdk_ext::nb2::bridge::{NativeBridgeV2, ReconcileResult};
use native_bridge_sdk_ext::nb2::crypto::{he, public_key, sign_unlock, verify_unlock};
use native_bridge_sdk_ext::nb2::deposit::{first_owner_of, topic};
use native_bridge_sdk_ext::nb2::errors::{Error, Nb2Error, Result, Rule, WalletReason};
use native_bridge_sdk_ext::nb2::evm::{sign_tx, EvmSigner, LocalKeySigner, TxRequest};
use native_bridge_sdk_ext::nb2::gas::{GasModel, RedeemShape};
use native_bridge_sdk_ext::nb2::journal::{hex, MemoryJournalStore, JOURNAL_FORMAT};
use native_bridge_sdk_ext::nb2::rpc::{Estimate, EvmReader, JsonRpc, RpcError};
use native_bridge_sdk_ext::nb2::rules::topic_index;
use native_bridge_sdk_ext::nb2::segment::{build_history, check_segment_log};
use native_bridge_sdk_ext::nb2::tokenops::{local_owner, LocalOwner, OwnerSigner};
use native_bridge_sdk_ext::nb2::util::{arr, from_hex, hex0x};
use native_bridge_sdk_ext::nb2::vaultmodel::RecipientBehaviour;
use nb2_world::*;
use num_bigint::BigUint;
use serde_json::{json, Value};

fn big(v: u64) -> BigUint {
    BigUint::from(v)
}

fn reason<T>(r: Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.name(),
    }
}

fn open(w: &World, seed: &str, store: Arc<MemoryJournalStore>) -> NativeBridgeV2 {
    NativeBridgeV2::open(w.options(seed, store)).unwrap()
}

fn sim(w: &World, from: &[u8], data: &[u8]) -> Estimate {
    EvmReader::new(w.chain.clone() as Arc<dyn JsonRpc>)
        .estimate_gas(from, &VAULT, data, 0)
        .unwrap()
}

fn sim_rule(w: &World, from: &[u8], data: &[u8]) -> Option<Rule> {
    match sim(w, from, data) {
        Estimate::Revert { data, .. } => {
            decode_revert(data.as_deref().unwrap_or(&[])).map(|d| d.rule)
        }
        Estimate::Gas(_) => None,
    }
}

/// deposit, collect, mint.
fn minted(b: &NativeBridgeV2, payer: &LocalKeySigner, owner: &LocalOwner, v: u64) -> Vec<u8> {
    let p = b.plan_deposit(&big(v), &owner.public_key()).unwrap();
    b.submit_deposit(&p, payer).unwrap();
    b.collect_deposit_proof(p.intent).unwrap();
    b.mint(p.intent).unwrap()
}

// ---- journal.test.ts ----

#[test]
fn secret_before_value_no_deposit_without_a_persisted_backed_up_plan() {
    let w = setup();
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o")).public_key();
    // no backup and no explicit opt-out: refused at construction
    let mut o = w.options("w", World::store());
    o.backup = None;
    assert_eq!(reason(NativeBridgeV2::open(o)), "BadInput");
    // a plan whose journal entry is gone (another store) is refused before anything is signed
    let b = open(&w, "w", World::store());
    let plan = b.plan_deposit(&big(5), &owner).unwrap();
    let other = open(&w, "w", World::store());
    assert_eq!(
        reason(other.submit_deposit(&plan, &payer)),
        "JournalNotPersisted"
    );
    // a plan not backed up is refused while require_backup holds
    let backups = Arc::new(AtomicUsize::new(0));
    let mut o = w.options("x", World::store());
    let bk = backups.clone();
    o.backup = Some(Box::new(move |_| {
        bk.fetch_add(1, Ordering::SeqCst);
        Err(Error::Other("backup offline".into()))
    }));
    let failing = NativeBridgeV2::open(o).unwrap();
    assert!(failing.plan_deposit(&big(5), &owner).is_err());
    assert_eq!(backups.load(Ordering::SeqCst), 1);
    assert!(!failing.journal.deposit(0).unwrap().unwrap().backed_up);
    assert_eq!(
        reason(failing.submit_deposit(0u64, &payer)),
        "JournalNotPersisted"
    );
    assert_eq!(w.chain.with(|s| s.vault.state().deposits), 0);
    // the journal record is the documented version 1 shape
    let r = b.journal.deposit(plan.intent).unwrap().unwrap();
    assert_eq!(r.base.format, JOURNAL_FORMAT);
    let v: Value = serde_json::to_value(&r).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "amount",
            "backedUp",
            "domain",
            "firstOwner",
            "format",
            "intent",
            "keyScheme",
            "kind",
            "ownerKey",
            "plannedBlock",
            "rho",
            "sends",
            "status",
            "version"
        ]
    );
}

#[test]
fn crash_between_send_and_receipt_the_retry_reconciles_and_never_deposits_twice() {
    let w = setup();
    let payer = w.evm_account("p");
    let store = World::store();
    let b = open(&w, "w", store.clone());
    let plan = b
        .plan_deposit(&big(7), &local_owner(&key("o")).public_key())
        .unwrap();
    w.chain.with(|s| s.auto_mine = false);
    assert_eq!(reason(b.submit_deposit(&plan, &payer)), "Unconfirmed");
    // "restart": a fresh instance over the same journal, while the transaction is still in the pool
    let again = open(&w, "w", store);
    assert_eq!(
        reason(again.submit_deposit(plan.intent, &payer)),
        "Unconfirmed"
    );
    w.chain.flush();
    w.chain.with(|s| s.auto_mine = true);
    let d = again.submit_deposit(plan.intent, &payer).unwrap();
    assert_eq!(d.deposit_number, 1);
    assert_eq!(w.chain.with(|s| s.vault.state().deposits), 1);
    assert_eq!(
        again
            .journal
            .deposit(plan.intent)
            .unwrap()
            .unwrap()
            .sends
            .len(),
        1
    );
    again.collect_deposit_proof(plan.intent).unwrap();
    assert_eq!(
        again
            .verify_token(&again.mint(plan.intent).unwrap())
            .unwrap()
            .amount,
        big(7)
    );
}

#[test]
fn a_deposited_event_with_another_deployments_domain_is_not_this_deposit() {
    // the same address and rho under another vault configuration (a reset network that redeployed at the same nonce): the receipt's
    // Deposited log names another D, and the record must not become deposited
    let w = setup();
    let payer = w.evm_account("p");
    let b = open(&w, "w", World::store());
    let plan = b
        .plan_deposit(&big(7), &local_owner(&key("o")).public_key())
        .unwrap();
    w.chain.with(|s| s.faults.deposit_domain = Some([0x5a; 32]));
    assert_eq!(reason(b.submit_deposit(&plan, &payer)), "ProviderFault");
    assert_eq!(
        b.journal.deposit(plan.intent).unwrap().unwrap().status,
        "submitted"
    );
}

#[test]
fn crash_between_burn_request_and_certification_and_between_burn_and_redeem() {
    let w = setup();
    let payer = w.evm_account("p");
    let store = World::store();
    let owner = local_owner(&key("o"));
    let b = open(&w, "w", store.clone());
    let t = minted(&b, &payer, &owner, 9);
    let rp = b
        .plan_return(&t, &recipient("r"), &payer.address(), None)
        .unwrap();
    // the aggregator is down at the burn: the request is journaled, nothing else
    w.agg.down.store(true, Ordering::SeqCst);
    assert!(b.burn(&rp.return_id, &owner).is_err());
    let rec = b.journal.ret(&rp.record.return_id).unwrap().unwrap();
    assert_eq!(rec.status, "burn-requested");
    w.agg.down.store(false, Ordering::SeqCst);
    // a restart resumes the same request: the same burn, never a second one
    let b2 = open(&w, "w", store.clone());
    let burned = b2.burn(&rp.return_id, &owner).unwrap();
    assert_eq!(
        b2.journal
            .ret(&rp.record.return_id)
            .unwrap()
            .unwrap()
            .burn_request,
        rec.burn_request
    );
    // between burn and redeem: another restart redeems from the journal alone
    let b3 = open(&w, "w", store);
    assert_eq!(
        b3.submit_redeem(&rp.return_id, &payer).unwrap().state(),
        "paid"
    );
    assert_eq!(w.chain.balance_of(&recipient("r")), big(9));
    assert_eq!(burned.verdict.amount, big(9));
}

#[test]
fn recovery_from_the_seed_and_the_intent_high_water_mark() {
    let w = setup();
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o")).public_key();
    let lost = open(&w, "seed", World::store());
    for v in [3, 4, 5] {
        lost.plan_deposit(&big(v), &owner).unwrap(); // intents 0..2; only 0 and 2 are sent
    }
    lost.submit_deposit(0u64, &payer).unwrap();
    lost.submit_deposit(2u64, &payer).unwrap();
    // a new device: the same seed (k_w) and the backed-up mark, an empty journal
    let restored = open(&w, "seed", World::store());
    assert_eq!(restored.recover_deposits(3).unwrap(), vec![0, 2]);
    restored.collect_deposit_proof(2).unwrap();
    assert_eq!(
        restored
            .verify_token(&restored.mint(2).unwrap())
            .unwrap()
            .amount,
        big(5)
    );
    // the counter continues past the mark: intent 1 is never reused
    assert_eq!(restored.plan_deposit(&big(1), &owner).unwrap().intent, 3);
}

// ---- scenario.test.ts ----

#[test]
fn reference_scenario_100_to_60_40_to_60_15_25_all_returned() {
    let w = setup();
    let store = World::store();
    let b = open(&w, "alice wallet", store.clone());
    let other = open(&w, "dave wallet", World::store());
    let payer = w.evm_account("alice");
    let dave_payer = w.evm_account("dave");
    let (alice, bob, carol, dave) = (
        local_owner(&key("alice")),
        local_owner(&key("bob")),
        local_owner(&key("carol")),
        local_owner(&key("dave")),
    );
    let (r1, r2, r3, rd) = (
        recipient("r1"),
        recipient("r2"),
        recipient("r3"),
        recipient("rd"),
    );
    // a second wallet's small deposits and returns rotate segments (K = 4)
    let rotate = |segments: usize| {
        for _ in 0..4 * segments {
            let t = minted(&other, &dave_payer, &dave, 1);
            let plan = other
                .plan_return(&t, &rd, &dave_payer.address(), None)
                .unwrap();
            other.burn(&plan.return_id, &dave).unwrap();
            assert_eq!(
                other
                    .submit_redeem(&plan.return_id, &dave_payer)
                    .unwrap()
                    .state(),
                "paid"
            );
        }
    };

    // deposit 100, mint
    let plan = b.plan_deposit(&big(100), &alice.public_key()).unwrap();
    assert_eq!(b.submit_deposit(&plan, &payer).unwrap().deposit_number, 1);
    b.collect_deposit_proof(plan.intent).unwrap();
    let t100 = b.mint(plan.intent).unwrap();
    assert_eq!(b.verify_token(&t100).unwrap().amount, big(100));

    // transfer, split 60 + 40, split 40 into 15 + 25, transfer again
    let tb = b.transfer(&t100, &alice, &bob.public_key()).unwrap();
    let parts = b
        .split(
            &tb,
            &bob,
            &[
                (bob.public_key().to_vec(), big(60)),
                (bob.public_key().to_vec(), big(40)),
            ],
            None,
        )
        .unwrap();
    let parts2 = b
        .split(
            &parts[1],
            &bob,
            &[
                (carol.public_key().to_vec(), big(15)),
                (bob.public_key().to_vec(), big(25)),
            ],
            None,
        )
        .unwrap();
    let (t15, t25) = (&parts2[0], &parts2[1]);
    let t60c = b.transfer(&parts[0], &bob, &carol.public_key()).unwrap();
    assert_eq!(
        b.verify_token(t15).unwrap().owner,
        Some(carol.public_key().to_vec())
    );

    rotate(1);
    // return 60: burned at its index, redeemed after two rotations with historical gap proofs
    let p60 = b.plan_return(&t60c, &r1, &payer.address(), None).unwrap();
    assert_eq!(p60.a, 1);
    assert!(p60.margin_segments > 0);
    b.burn(&p60.return_id, &carol).unwrap();
    rotate(2);
    let rtx60 = b.build_redeem(&p60.return_id).unwrap();
    assert_eq!(rtx60.p, 2);
    assert_eq!(
        b.submit_redeem(&p60.return_id, &payer).unwrap().state(),
        "paid"
    );

    // a replay of the paid part is refused while it is in the recent buffers
    assert_eq!(
        sim_rule(&w, &payer.address(), &rtx60.calldata),
        Some(Rule::AlreadyPaid)
    );

    // return 15 through an ambiguous broadcast: the receipt of the locally computed hash decides
    let p15 = b.plan_return(t15, &r2, &payer.address(), None).unwrap();
    b.burn(&p15.return_id, &carol).unwrap();
    w.chain.with(|s| s.faults.ambiguous_sends = 1);
    assert_eq!(
        b.submit_redeem(&p15.return_id, &payer).unwrap().state(),
        "paid"
    );

    // return 25 with a witness made stale by two rotations, finished by a fresh instance over the same journal
    let p25 = b.plan_return(t25, &r3, &payer.address(), None).unwrap();
    b.burn(&p25.return_id, &bob).unwrap();
    let stale = b.build_redeem(&p25.return_id).unwrap();
    rotate(2);
    assert_eq!(
        sim_rule(&w, &payer.address(), &stale.calldata),
        Some(Rule::StaleEndpoint)
    );
    let cold = open(&w, "alice wallet", store);
    assert_eq!(
        cold.submit_redeem(&p25.return_id, &payer).unwrap().state(),
        "paid"
    );

    // exactly 100 paid; nothing left outstanding (the second wallet's returns net to zero)
    assert_eq!(
        [
            w.chain.balance_of(&r1),
            w.chain.balance_of(&r2),
            w.chain.balance_of(&r3)
        ],
        [big(60), big(15), big(25)]
    );
    assert_eq!(w.chain.with(|s| s.vault.state().outstanding), big(0));

    // after eviction (two more rotations) the replay's recent check is gone, and its history shows it paid
    rotate(2);
    assert_eq!(
        sim_rule(&w, &payer.address(), &rtx60.calldata),
        Some(Rule::StaleEndpoint)
    );
    assert_eq!(b.reconcile(&p60.return_id).unwrap().state(), "paid");
    let rec = b.journal.ret(&p60.record.return_id).unwrap().unwrap();
    let evm = EvmReader::new(w.chain.clone() as Arc<dyn JsonRpc>);
    let st = evm.vault_state(&VAULT).unwrap();
    let a: u64 = rec.a.parse().unwrap();
    let mut segs = vec![];
    let mut before = from_hex(&rec.start_head[2..]).unwrap();
    for l in evm
        .segment_logs(&VAULT, rec.from_block.parse().unwrap(), a, st.segment)
        .unwrap()
    {
        let sg =
            check_segment_log(&b.domain, 4, topic_index(&l.topics[1]), &before, &l.data).unwrap();
        before = sg.after.to_vec();
        segs.push(sg);
    }
    let eta: [u8; 32] = arr(&from_hex(&rec.eta.unwrap()[2..]).unwrap());
    assert!(build_history(
        &segs,
        &eta,
        a,
        st.segment,
        &from_hex(&rec.start_head[2..]).unwrap()
    )
    .unwrap()
    .paid
    .is_some());
    assert_eq!(
        b.status()
            .unwrap()
            .iter()
            .filter(|x| x.contains("paid"))
            .count(),
        3
    );
}

// ---- witness.test.ts ----

struct WitnessWorld {
    w: World,
    b: NativeBridgeV2,
    payer: LocalKeySigner,
    owner: LocalOwner,
}

impl WitnessWorld {
    fn new() -> Self {
        let w = setup();
        let payer = w.evm_account("p");
        let b = open(&w, "w", World::store());
        WitnessWorld {
            w,
            b,
            payer,
            owner: local_owner(&key("o")),
        }
    }

    fn pay(&self, n: usize) {
        for _ in 0..n {
            let t = minted(&self.b, &self.payer, &self.owner, 1);
            let rp = self
                .b
                .plan_return(&t, &recipient("x"), &self.payer.address(), None)
                .unwrap();
            self.b.burn(&rp.return_id, &self.owner).unwrap();
            assert_eq!(
                self.b
                    .submit_redeem(&rp.return_id, &self.payer)
                    .unwrap()
                    .state(),
                "paid"
            );
        }
    }

    fn burned(&self) -> [u8; 32] {
        let t = minted(&self.b, &self.payer, &self.owner, 2);
        let rp = self
            .b
            .plan_return(&t, &recipient("y"), &self.payer.address(), None)
            .unwrap();
        self.b.burn(&rp.return_id, &self.owner).unwrap();
        rp.return_id
    }
}

#[test]
fn history_of_zero_one_and_several_segments_one_rollover_in_flight_is_tolerated() {
    let x = WitnessWorld::new();
    let id = x.burned();
    assert_eq!(x.b.build_redeem(&id).unwrap().p, 0);
    x.pay(4);
    assert_eq!(x.b.build_redeem(&id).unwrap().p, 1);
    x.pay(8);
    let built = x.b.build_redeem(&id).unwrap();
    assert_eq!(built.p, 3);
    // one more seal between build and submit: the old witness ends at c - 1, still accepted
    x.pay(4);
    assert!(matches!(
        sim(&x.w, &x.payer.address(), &built.calldata),
        Estimate::Gas(_)
    ));
    assert_eq!(x.b.submit_redeem(&id, &x.payer).unwrap().state(), "paid");
}

#[test]
fn deployed_quorum_refusal_is_retryable_until_seal_import() {
    let x = WitnessWorld::new();
    let id = x.burned();
    let refusal = revert_data(
        Rule::VerifierRefused,
        &[ErrArg::Word(revert_data(Rule::QuorumNotMet, &[]))],
    );
    assert_eq!(
        classify_redeem_error(decode_revert(&refusal).as_ref()),
        RedeemAction::RetryLater
    );
    let sends = Arc::new(AtomicUsize::new(0));
    let observed_sends = sends.clone();
    x.w.chain
        .set_pre(Some(Box::new(move |method, _| match method {
            "eth_estimateGas" => Some(Err(RpcError {
                status: 200,
                code: 3,
                message: "execution reverted".into(),
                data: Some(json!(hex0x(&refusal))),
            })),
            "eth_sendRawTransaction" => {
                observed_sends.fetch_add(1, Ordering::Relaxed);
                None
            }
            _ => None,
        })));
    let refusal = x.b.submit_redeem(&id, &x.payer).unwrap_err();
    assert!(refusal.retryable());
    let outer = refusal.rule().unwrap();
    assert_eq!(outer.rule, Rule::VerifierRefused);
    assert_eq!(outer.innermost(), Rule::QuorumNotMet);
    assert!(!Nb2Error::new(Rule::QuorumNotMet).retryable());
    assert_eq!(sends.load(Ordering::Relaxed), 0);

    x.w.chain.set_pre(None);
    assert_eq!(x.b.submit_redeem(&id, &x.payer).unwrap().state(), "paid");
}

#[test]
fn mined_final_refusal_preserves_the_decoded_inner_rule() {
    let x = WitnessWorld::new();
    let id = x.burned();
    let inner = revert_data(Rule::SealRoot, &[]);
    let refusal = revert_data(Rule::VerifierRefused, &[ErrArg::Word(inner.clone())]);
    x.w.chain.with(|s| {
        s.faults
            .recipients
            .insert(recipient("y"), RecipientBehaviour::Reverts)
    });
    let estimates = Arc::new(AtomicUsize::new(0));
    let sends = Arc::new(AtomicUsize::new(0));
    let seen_estimates = estimates.clone();
    let seen_sends = sends.clone();
    x.w.chain
        .set_pre(Some(Box::new(move |method, params| match method {
            "eth_estimateGas" if seen_estimates.fetch_add(1, Ordering::Relaxed) == 0 => {
                Some(Ok(json!("0x1d4c0")))
            }
            "eth_estimateGas" => Some(Err(RpcError {
                status: 200,
                code: 3,
                message: "execution reverted".into(),
                data: Some(json!(hex0x(&refusal))),
            })),
            "eth_call" if params[1].is_object() => Some(Ok(json!("0x"))),
            "eth_sendRawTransaction" => {
                seen_sends.fetch_add(1, Ordering::Relaxed);
                None
            }
            _ => None,
        })));

    let error = x.b.submit_redeem(&id, &x.payer).unwrap_err();
    let rule = error.rule().unwrap();
    assert_eq!(rule.rule, Rule::VerifierRefused);
    assert_eq!(rule.innermost(), Rule::SealRoot);
    assert_eq!(rule.args, vec![hex(&inner)]);
    assert!(!error.retryable());
    assert_eq!(estimates.load(Ordering::Relaxed), 2);
    assert_eq!(sends.load(Ordering::Relaxed), 1);
}

#[test]
fn a_missing_or_substituted_segment_log_is_missing_evidence_never_absence() {
    let x = WitnessWorld::new();
    let id = x.burned();
    x.pay(8);
    x.w.chain.with(|s| s.faults.hide_segments.insert(1));
    assert_eq!(
        x.b.build_redeem(&id).err().and_then(|e| e.reason()),
        Some(WalletReason::EvidenceMissing)
    );
    x.w.chain.with(|s| s.faults.hide_segments.clear());
    // a provider that serves segment 1's log in place of segment 0's: the chain link refuses it
    x.w.chain.set_post(Some(Box::new(|m, p, mut r| {
        if m == "eth_getLogs" {
            let t0 = p[0]["topics"][0].clone();
            let idx: Vec<usize> = r
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .filter(|(_, l)| l["topics"].as_array().unwrap().len() == 2 && l["topics"][0] == t0)
                .map(|(i, _)| i)
                .collect();
            if idx.len() >= 2 {
                let a = r[idx[0]]["data"].clone();
                r[idx[0]]["data"] = r[idx[1]]["data"].clone();
                r[idx[1]]["data"] = a;
            }
        }
        r
    })));
    assert_eq!(
        x.b.build_redeem(&id)
            .err()
            .and_then(|e| e.rule().map(|n| n.rule)),
        Some(Rule::SegmentLog)
    );
}

// ---- preflight.test.ts ----

fn minted_world(
    pins: impl FnOnce(&mut native_bridge_sdk_ext::nb2::bridge::DeploymentPins),
    gas: Option<Box<dyn GasModel>>,
) -> (World, NativeBridgeV2, LocalKeySigner, LocalOwner, Vec<u8>) {
    let mut w = setup();
    pins(&mut w.pins);
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o"));
    let mut o = w.options("w", World::store());
    if gas.is_some() {
        o.gas = gas;
    }
    let b = NativeBridgeV2::open(o).unwrap();
    let t = minted(&b, &payer, &owner, 3);
    (w, b, payer, owner, t)
}

struct Blind;
impl GasModel for Blind {
    fn name(&self) -> &str {
        "blind"
    }
    fn redeem_gas_limit(&self, _: &RedeemShape<'_>) -> Option<u64> {
        None
    }
    fn deposit_gas_limit(&self) -> u64 {
        200_000
    }
}

#[test]
fn preflight_an_oversized_token_unfundable_gas_and_an_unboundable_gas_cost_refuse_before_the_burn()
{
    let r = recipient("recipient");
    let (_, small, payer, _, t) = minted_world(|p| p.max_encoded_tx_bytes = 40_000, None);
    assert_eq!(
        reason(small.plan_return(&t, &r, &payer.address(), None)),
        "CapacityPreflight"
    );
    let (_, tight, payer, _, t) = minted_world(|p| p.user_gas_limit = 1_000_000, None);
    assert_eq!(
        reason(tight.plan_return(&t, &r, &payer.address(), None)),
        "CapacityPreflight"
    );
    let (_, unbounded, payer, _, t) = minted_world(|_| {}, Some(Box::new(Blind)));
    assert_eq!(
        reason(unbounded.plan_return(&t, &r, &payer.address(), None)),
        "CapacityPreflight"
    );
    let (w, ok, payer, _, t) = minted_world(|_| {}, None);
    let poor = w.evm_account("poor");
    w.chain.set_balance(&poor.address(), big(1000));
    assert_eq!(
        reason(ok.plan_return(&t, &r, &poor.address(), None)),
        "InsufficientFunds"
    );
    // nothing was burned or journaled as burned
    assert_eq!(ok.journal.returns().unwrap().len(), 0);
    let plan = ok.plan_return(&t, &r, &payer.address(), None).unwrap();
    assert!(plan.gas_limit > 500_000 && plan.gas_limit < 60_000_000);
}

#[test]
fn the_default_gas_bound_is_refused_for_a_verifier_it_is_not_calibrated_for() {
    // the world's verifier is a stand-in whose code is not Γ's: the default model is never applied to it
    let w = setup();
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o"));
    let t = minted(&open(&w, "prefund", World::store()), &payer, &owner, 3);
    let mut o = w.options("w", World::store());
    o.gas = None;
    let b = NativeBridgeV2::open(o).unwrap();
    assert_eq!(b.gas.name(), "estimate-nb2-1179");
    assert_eq!(
        reason(b.plan_return(&t, &recipient("recipient"), &payer.address(), None)),
        "BadDeployment"
    );
}

#[test]
fn recipient_rule_zero_and_vault_refused_a_contract_warned() {
    let r = recipient("recipient");
    let (w, b, payer, _, t) = minted_world(|_| {}, None);
    assert_eq!(
        reason(b.plan_return(&t, &[0u8; 20], &payer.address(), None)),
        "RecipientRefused"
    );
    assert_eq!(
        reason(b.plan_return(&t, &VAULT, &payer.address(), None)),
        "RecipientRefused"
    );
    w.chain.with(|s| s.code.insert(r, vec![0x60, 0x00]));
    assert_eq!(
        b.plan_return(&t, &r, &payer.address(), None)
            .unwrap()
            .warnings
            .len(),
        1
    );
}

#[test]
fn index_rule_a_plain_state_read_is_not_evidence_outside_state_read_only_an_implausible_jump_is_refused(
) {
    let r = recipient("recipient");
    let (_, b, payer, _, t) = minted_world(|_| {}, None);
    assert_eq!(
        reason(b.plan_return(&t, &r, &payer.address(), Some(0))),
        "StateReadNotAdmitted"
    );
    let (w, b, payer, _, t) = minted_world(
        |p| {
            p.state_read_only = true;
            p.max_jump = Some(0);
        },
        None,
    );
    // a provider claims segment 5 while the wallet verified 0
    w.chain.set_post(Some(Box::new(|m, p, r| {
        if m == "eth_call" && p[0]["data"] == "0xc19d93fb" {
            let s = r.as_str().unwrap();
            return json!(format!("{}{}05{}", &s[..66], "00".repeat(31), &s[130..]));
        }
        r
    })));
    assert_eq!(
        reason(b.plan_return(&t, &r, &payer.address(), Some(0))),
        "ImplausibleIndex"
    );
    // a provider that hides every seal only anchors the burn lower (a = 0), never higher
    let (w, b, payer, _, t) = minted_world(|_| {}, None);
    w.chain.with(|s| s.faults.hide_all_seals = true);
    assert_eq!(b.plan_return(&t, &r, &payer.address(), None).unwrap().a, 0);
}

#[test]
fn unlock_recovery_ids_2_and_3_are_refused() {
    let k = key("u");
    let src = he(&[&key("s")]);
    let tx = he(&[&key("t")]);
    let sig = sign_unlock(&k, &src, &tx);
    verify_unlock(&public_key(&k), &src, &tx, &sig).unwrap();
    for id in [2u8, 3] {
        let mut bad = sig;
        bad[64] = id;
        assert_eq!(
            verify_unlock(&public_key(&k), &src, &tx, &bad)
                .err()
                .and_then(|e| e.rule().map(|n| n.rule)),
            Some(Rule::UnlockRecovery)
        );
    }
}

// ---- review.test.ts ----

fn lag_receipts(w: &World) -> Arc<AtomicUsize> {
    let left = Arc::new(AtomicUsize::new(0));
    let l = left.clone();
    w.chain.set_pre(Some(Box::new(move |m, _| {
        if m == "eth_getTransactionReceipt" && l.load(Ordering::SeqCst) > 0 {
            l.fetch_sub(1, Ordering::SeqCst);
            return Some(Ok(Value::Null));
        }
        None
    })));
    left
}

#[test]
fn send_race_a_send_mined_between_reads_behind_a_lagging_backend_is_never_doubled() {
    let w = setup();
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o"));
    let b = open(&w, "w", World::store());
    let plan = b.plan_deposit(&big(5), &owner.public_key()).unwrap();
    w.chain.with(|s| s.auto_mine = false);
    assert_eq!(reason(b.submit_deposit(&plan, &payer)), "Unconfirmed");
    w.chain.flush(); // mined now; the nonce moved past it
    w.chain.with(|s| s.auto_mine = true);
    // every receipt read misses: the mined nonce alone must not make the send look dead
    let lag = lag_receipts(&w);
    lag.store(1000, Ordering::SeqCst);
    assert_eq!(reason(b.submit_deposit(plan.intent, &payer)), "Unconfirmed");
    assert_eq!(reason(b.submit_deposit(plan.intent, &payer)), "Unconfirmed");
    assert_eq!(w.chain.with(|s| s.vault.state().deposits), 1);
    // the backend catches up: the success receipt is the answer, whenever it is seen
    lag.store(0, Ordering::SeqCst);
    assert_eq!(
        b.submit_deposit(plan.intent, &payer)
            .unwrap()
            .deposit_number,
        1
    );
    assert_eq!(w.chain.with(|s| s.vault.state().deposits), 1);
}

#[test]
fn send_race_windows_lagging_receipt_then_caught_up_a_replaced_send_is_dead_only_after_depth() {
    let w = setup();
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o"));
    let lag = Arc::new(AtomicUsize::new(0));
    let companion_down = Arc::new(AtomicBool::new(false));
    let (l, c) = (lag.clone(), companion_down.clone());
    w.chain.set_pre(Some(Box::new(move |m, _| {
        if m == "unicity_getSealCompanionV1" && c.load(Ordering::SeqCst) {
            return Some(Ok(json!({"status": "unknown"})));
        }
        if m == "eth_getTransactionReceipt" && l.load(Ordering::SeqCst) > 0 {
            l.fetch_sub(1, Ordering::SeqCst);
            return Some(Ok(Value::Null));
        }
        None
    })));
    let mut o = w.options("w", World::store());
    o.dead_after_blocks = Some(3);
    let b = NativeBridgeV2::open(o).unwrap();
    // window 1: the send is mined between the broadcast's receipt read and the next call's reads
    let p1 = b.plan_deposit(&big(5), &owner.public_key()).unwrap();
    w.chain.with(|s| s.auto_mine = false);
    assert_eq!(reason(b.submit_deposit(&p1, &payer)), "Unconfirmed");
    w.chain.flush();
    w.chain.with(|s| s.auto_mine = true);
    lag.store(1, Ordering::SeqCst); // the first receipt read misses, the nonce read (taken first) already shows it mined
    assert_eq!(reason(b.submit_deposit(p1.intent, &payer)), "Unconfirmed");
    assert_eq!(
        b.submit_deposit(p1.intent, &payer).unwrap().deposit_number,
        1
    );
    assert_eq!(w.chain.with(|s| s.vault.state().deposits), 1);
    // window 2: a send replaced by another transaction of the same nonce is dead, but only after the head advanced dead_after_blocks
    let p2 = b.plan_deposit(&big(6), &owner.public_key()).unwrap();
    w.chain.with(|s| s.auto_mine = false);
    assert_eq!(reason(b.submit_deposit(&p2, &payer)), "Unconfirmed");
    w.chain.drop_pool();
    let nonce = u64::from_str_radix(
        &w.chain
            .real(
                "eth_getTransactionCount",
                json!([hex0x(&payer.address()), "latest"]),
            )
            .unwrap()
            .as_str()
            .unwrap()[2..],
        16,
    )
    .unwrap();
    let other = sign_tx(
        &payer,
        &TxRequest {
            chain_id: CHAIN_ID,
            nonce,
            max_priority_fee_per_gas: big(1),
            max_fee_per_gas: big(15),
            gas: 21_000,
            to: recipient("z"),
            value: big(1),
            data: vec![],
        },
    )
    .unwrap();
    w.chain
        .real("eth_sendRawTransaction", json!([hex0x(&other.raw)]))
        .unwrap();
    w.chain.flush();
    w.chain.with(|s| s.auto_mine = true);
    assert_eq!(reason(b.submit_deposit(p2.intent, &payer)), "Unconfirmed"); // first seen used: pending
    assert_eq!(reason(b.submit_deposit(p2.intent, &payer)), "Unconfirmed"); // not deep enough yet
    for _ in 0..3 {
        w.chain.mine_empty();
    }
    // deep enough, but the block at nonceUsedAt has no certificate served: still not dead
    companion_down.store(true, Ordering::SeqCst);
    assert_eq!(reason(b.submit_deposit(p2.intent, &payer)), "Unconfirmed");
    companion_down.store(false, Ordering::SeqCst);
    assert_eq!(
        b.submit_deposit(p2.intent, &payer).unwrap().deposit_number,
        2
    ); // certified and deep: dead, one new send
    assert_eq!(w.chain.with(|s| s.vault.state().deposits), 2);
}

struct Lying(LocalKeySigner);
impl EvmSigner for Lying {
    fn address(&self) -> [u8; 20] {
        self.0.address()
    }
    fn sign_transaction(&self, t: &TxRequest) -> core::result::Result<Vec<u8>, String> {
        let mut t = t.clone();
        t.value += 1u8;
        self.0.sign_transaction(&t)
    }
}

struct Impostor(LocalKeySigner);
impl EvmSigner for Impostor {
    fn address(&self) -> [u8; 20] {
        recipient("i")
    }
    fn sign_transaction(&self, t: &TxRequest) -> core::result::Result<Vec<u8>, String> {
        self.0.sign_transaction(t)
    }
}

#[test]
fn an_external_signer_must_return_exactly_the_requested_transaction_from_its_own_address() {
    let w = setup();
    let b = open(&w, "w", World::store());
    let owner = local_owner(&key("o"));
    let honest = w.evm_account("x");
    let plan = b.plan_deposit(&big(5), &owner.public_key()).unwrap();
    assert!(reason(b.submit_deposit(&plan, &Lying(honest.clone()))).contains("another transaction"));
    assert!(reason(b.submit_deposit(&plan, &Impostor(honest))).contains("not from the signer"));
    assert_eq!(w.chain.with(|s| s.vault.state().deposits), 0);
    assert_eq!(
        b.journal.deposit(plan.intent).unwrap().unwrap().sends.len(),
        0
    );
}

#[test]
fn serialization_concurrent_plans_never_share_an_intent_a_second_writer_loses_the_compare_and_swap()
{
    let w = setup();
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o"));
    let store = World::store();
    let b = Arc::new(open(&w, "w", store.clone()));
    let mut intents: Vec<u64> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..6)
            .map(|_| s.spawn(|| b.plan_deposit(&big(1), &owner.public_key()).unwrap().intent))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    intents.sort();
    assert_eq!(intents, vec![0, 1, 2, 3, 4, 5]);
    // two instances on one store race one burn: one wins, the other is refused before certifying anything else
    b.submit_deposit(0u64, &payer).unwrap();
    b.collect_deposit_proof(0).unwrap();
    let t = b.mint(0).unwrap();
    let rp = b
        .plan_return(&t, &recipient("r"), &payer.address(), None)
        .unwrap();
    let b2 = open(&w, "w", store);
    b2.journal.ret(&rp.record.return_id).unwrap(); // both have read the planned record
    b.journal.ret(&rp.record.return_id).unwrap();
    let outs: Vec<Result<_>> = std::thread::scope(|s| {
        let h1 = s.spawn(|| b.burn(&rp.return_id, &owner));
        let h2 = s.spawn(|| b2.burn(&rp.return_id, &owner));
        vec![h1.join().unwrap(), h2.join().unwrap()]
    });
    let ok: Vec<_> = outs.iter().filter_map(|o| o.as_ref().ok()).collect();
    assert!(!ok.is_empty());
    for o in &outs {
        if let Err(e) = o {
            assert_eq!(e.reason(), Some(WalletReason::JournalConflict), "{e}");
        }
    }
    let fin = b2.journal.ret(&rp.record.return_id).unwrap().unwrap();
    assert_eq!(fin.status, "burned");
    for o in ok {
        assert_eq!(Some(hex(&o.eta)), fin.eta);
    }
}

#[test]
fn recovery_a_stale_planned_record_is_upgraded_the_pre_send_scan_finds_a_deposit_every_deposit_number_is_kept(
) {
    let w = setup();
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o"));
    let store = World::store();
    let b = open(&w, "w", store.clone());
    let plan = b.plan_deposit(&big(5), &owner.public_key()).unwrap();
    let copy = Arc::new(MemoryJournalStore::from_map(store.dump())); // a second device restored before the send
                                                                     // both devices send the same intent before either sees the other's deposit (a faulty wallet reusing r)
    w.chain.with(|s| s.auto_mine = false);
    assert_eq!(reason(b.submit_deposit(&plan, &payer)), "Unconfirmed");
    let dev_b = open(&w, "w", copy.clone());
    let payer2 = w.evm_account("p2");
    assert_eq!(
        reason(dev_b.submit_deposit(plan.intent, &payer2)),
        "Unconfirmed"
    );
    w.chain.flush();
    w.chain.with(|s| s.auto_mine = true);
    assert_eq!(w.chain.with(|s| s.vault.state().deposits), 2);
    assert_eq!(
        b.submit_deposit(plan.intent, &payer)
            .unwrap()
            .deposit_number,
        1
    );
    // the record's own deposit is merged with a rho scan: both numbers are journaled at once
    let numbers = |r: &native_bridge_sdk_ext::nb2::journal::DepositRecord| {
        r.seen_deposits
            .as_ref()
            .unwrap()
            .iter()
            .map(|x| x.deposit_number.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        numbers(&b.journal.deposit(plan.intent).unwrap().unwrap()),
        ["1", "2"]
    );
    // device b's own deposit is number 2: its mint tags that entry, not entry 0
    assert_eq!(
        dev_b
            .submit_deposit(plan.intent, &payer2)
            .unwrap()
            .deposit_number,
        2
    );
    dev_b.collect_deposit_proof(plan.intent).unwrap();
    dev_b.mint(plan.intent).unwrap();
    let bs = dev_b
        .journal
        .deposit(plan.intent)
        .unwrap()
        .unwrap()
        .seen_deposits
        .unwrap();
    assert_eq!(
        bs.iter().map(|x| x.token.is_some()).collect::<Vec<_>>(),
        [false, true]
    );
    // a third device with the stale planned record: the pre-send scan adopts the deposits, and sends nothing
    let mut third = copy.dump();
    let dkey = third
        .keys()
        .find(|k| k.contains("/deposit/"))
        .unwrap()
        .clone();
    let orig = store.dump()[&dkey].clone();
    let mut v: Value = serde_json::from_str(&orig).unwrap();
    v["status"] = json!("planned");
    v["sends"] = json!([]);
    third.insert(dkey, serde_json::to_string(&v).unwrap());
    let c = open(&w, "w", Arc::new(MemoryJournalStore::from_map(third)));
    c.submit_deposit(plan.intent, &payer).unwrap();
    assert_eq!(w.chain.with(|s| s.vault.state().deposits), 2);
    // recovery journals both deposit numbers; the second mints as its own root token
    b.recover_deposits(1).unwrap();
    assert_eq!(
        numbers(&b.journal.deposit(plan.intent).unwrap().unwrap()),
        ["1", "2"]
    );
    b.collect_deposit_proof(plan.intent).unwrap();
    b.mint(plan.intent).unwrap();
    let extra = b.mint_extra_deposit(plan.intent, 2).unwrap();
    assert_eq!(b.verify_token(&extra).unwrap().amount, big(5));
    // a deposit of the same rho to another first owner: its entry keeps that owner and its mint goes to it
    let other = local_owner(&key("other owner"));
    let nonce = u64::from_str_radix(
        &w.chain
            .real(
                "eth_getTransactionCount",
                json!([hex0x(&payer.address()), "pending"]),
            )
            .unwrap()
            .as_str()
            .unwrap()[2..],
        16,
    )
    .unwrap();
    let raw = sign_tx(
        &payer,
        &TxRequest {
            chain_id: CHAIN_ID,
            nonce,
            max_priority_fee_per_gas: big(1),
            max_fee_per_gas: big(15),
            gas: 200_000,
            to: VAULT,
            value: big(3),
            data: deposit_calldata(&first_owner_of(&other.public_key()), &plan.rho),
        },
    )
    .unwrap();
    w.chain
        .real("eth_sendRawTransaction", json!([hex0x(&raw.raw)]))
        .unwrap();
    b.recover_deposits(1).unwrap();
    let rec = b.journal.deposit(plan.intent).unwrap().unwrap();
    let third3 = rec
        .seen_deposits
        .unwrap()
        .into_iter()
        .find(|x| x.deposit_number == "3")
        .unwrap();
    assert_eq!(
        third3.first_owner,
        hex(&first_owner_of(&other.public_key()))
    );
    let t3 = b.mint_extra_deposit(plan.intent, 3).unwrap();
    assert_eq!(
        b.verify_token(&t3).unwrap().owner,
        Some(other.public_key().to_vec())
    );
}

#[test]
fn paid_counts_only_from_the_vault_and_only_with_a_certified_receipt() {
    let w = setup();
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o"));
    let b = open(&w, "w", World::store());
    let t = minted(&b, &payer, &owner, 4);
    let rp = b
        .plan_return(&t, &recipient("r"), &payer.address(), None)
        .unwrap();
    let eta = b.burn(&rp.return_id, &owner).unwrap().eta;
    // the provider invents Paid(eta) logs: one from another address, one from the vault in a transaction that never paid
    let block2 = hex0x(&w.chain.with(|s| s.blocks[2].hash));
    let fake = move |address: [u8; 20]| json!({"address": hex0x(&address), "topics": [hex0x(&topic::paid()), hex0x(&eta), hex0x(&[0u8; 32])], "data": hex0x(&[0u8; 32]), "blockNumber": "0x2", "blockHash": block2, "transactionHash": hex0x(&he(&[&key("fake")])), "logIndex": "0x0", "removed": false});
    w.chain.set_post(Some(Box::new(move |m, p, r| {
        if m == "eth_getLogs" && p[0]["topics"][0] == json!(hex0x(&topic::paid())) {
            let mut out = vec![fake(recipient("other")), fake(VAULT)];
            out.extend(r.as_array().unwrap().iter().cloned());
            return json!(out);
        }
        r
    })));
    assert_eq!(b.reconcile(&rp.return_id).unwrap().state(), "not-paid");
    assert_eq!(
        b.submit_redeem(&rp.return_id, &payer).unwrap().state(),
        "paid"
    );
    assert_eq!(w.chain.balance_of(&recipient("r")), big(4));
}

struct Odd(LocalOwner);
impl OwnerSigner for Odd {
    fn public_key(&self) -> [u8; 33] {
        self.0.public_key()
    }
    fn sign_unlock(&self, m: &[u8; 32]) -> core::result::Result<[u8; 65], String> {
        let mut s = self.0.sign_unlock(m)?;
        s[64] = 2;
        Ok(s)
    }
}

#[test]
fn the_burn_re_runs_the_preflight_and_checks_the_owner_signature_before_anything_irreversible_is_journaled(
) {
    let w = setup();
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o"));
    let b = open(&w, "w", World::store());
    let t = minted(&b, &payer, &owner, 4);
    let poor = w.evm_account("poor");
    let rp = b
        .plan_return(&t, &recipient("r"), &poor.address(), None)
        .unwrap();
    w.chain.set_balance(&poor.address(), big(0)); // the payer was drained after planning
    assert_eq!(reason(b.burn(&rp.return_id, &owner)), "InsufficientFunds");
    assert_eq!(
        b.journal.ret(&rp.record.return_id).unwrap().unwrap().status,
        "planned"
    );
    w.chain.fund(&poor.address(), BigUint::from(10u8).pow(24));
    // an owner key whose signer returns recovery ID 2: refused (UnlockRecovery) before the burn request is journaled
    assert_eq!(
        reason(b.burn(&rp.return_id, &Odd(owner.clone()))),
        "UnlockRecovery"
    );
    assert_eq!(
        b.journal.ret(&rp.record.return_id).unwrap().unwrap().status,
        "planned"
    );
    assert_eq!(
        b.burn(&rp.return_id, &owner).unwrap().verdict.amount,
        big(4)
    );
}

#[test]
fn options_an_old_seal_warns_and_a_record_keeps_unknown_fields() {
    let w = setup();
    let mut o = w.options("w", World::store());
    o.max_seal_age_blocks = Some(0);
    let b = NativeBridgeV2::open(o).unwrap();
    // a seal exists after four payments; with a zero age bound the plan carries the freshness warning
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o"));
    for _ in 0..4 {
        let t = minted(&b, &payer, &owner, 1);
        let rp = b
            .plan_return(&t, &recipient("r"), &payer.address(), None)
            .unwrap();
        b.burn(&rp.return_id, &owner).unwrap();
        b.submit_redeem(&rp.return_id, &payer).unwrap();
    }
    let t = minted(&b, &payer, &owner, 1);
    w.chain.mine_empty();
    let plan = b
        .plan_return(&t, &recipient("r"), &payer.address(), None)
        .unwrap();
    assert_eq!(plan.a, 1);
    assert!(plan.warnings.iter().any(|x| x.contains("blocks old")));
    // the journal format: a version 1 reader keeps unknown fields on rewrite
    let store = World::store();
    let b = open(&w, "w", store.clone());
    let p = b.plan_deposit(&big(2), &owner.public_key()).unwrap();
    let mut m = store.dump();
    let k = m.keys().find(|k| k.contains("/deposit/")).unwrap().clone();
    let mut v: Value = serde_json::from_str(&m[&k]).unwrap();
    v["futureField"] = json!({"x": 1});
    m.insert(k.clone(), v.to_string());
    let store2 = Arc::new(MemoryJournalStore::from_map(m));
    let b2 = open(&w, "w", store2.clone());
    b2.mark_backed_up(p.intent).unwrap();
    b2.submit_deposit(p.intent, &payer).unwrap();
    let after: Value = serde_json::from_str(&store2.dump()[&k]).unwrap();
    assert_eq!(after["futureField"], json!({"x": 1}));
    assert_eq!(after["status"], "deposited");
    let _ = ReconcileResult::NotPaid { last_failure: None };
    let _: Option<RpcError> = None;
}

// ---- the fixes found by the port (port-fixes.test.ts) ----

/// A store whose compare-and-swap of a paid return record loses while `lose` is set.
#[derive(Default)]
struct LosingStore {
    inner: MemoryJournalStore,
    lose: AtomicBool,
}

impl native_bridge_sdk_ext::nb2::journal::JournalStore for LosingStore {
    fn get(&self, key: &str) -> Result<Option<String>> {
        self.inner.get(key)
    }
    fn put_if(&self, key: &str, expected: Option<&str>, value: &str) -> Result<bool> {
        if self.lose.load(Ordering::SeqCst)
            && key.contains("/return/")
            && value.contains("\"status\":\"paid\"")
        {
            return Ok(false);
        }
        self.inner.put_if(key, expected, value)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix)
    }
}

#[test]
fn a_lost_compare_and_swap_while_journaling_paid_propagates_never_not_paid_or_pending() {
    let w = setup();
    let payer = w.evm_account("p");
    let owner = local_owner(&key("o"));
    let store = Arc::new(LosingStore::default());
    let b = NativeBridgeV2::open(w.options("w", store.clone())).unwrap();
    let t = minted(&b, &payer, &owner, 4);
    let rp = b
        .plan_return(&t, &recipient("r"), &payer.address(), None)
        .unwrap();
    b.burn(&rp.return_id, &owner).unwrap();
    store.lose.store(true, Ordering::SeqCst);
    assert_eq!(
        reason(b.submit_redeem(&rp.return_id, &payer)),
        "JournalConflict"
    );
    assert_eq!(w.chain.balance_of(&recipient("r")), big(4)); // it was paid on chain
    assert_eq!(reason(b.reconcile(&rp.return_id)), "JournalConflict");
    store.lose.store(false, Ordering::SeqCst);
    let fresh = NativeBridgeV2::open(w.options("w", store)).unwrap();
    assert_eq!(fresh.reconcile(&rp.return_id).unwrap().state(), "paid");
}

#[test]
fn plan_deposit_and_recover_deposits_keep_the_unknown_fields_of_the_intents_record() {
    let w = setup();
    let store = World::store();
    let owner = local_owner(&key("o")).public_key();
    open(&w, "w", store.clone())
        .plan_deposit(&big(1), &owner)
        .unwrap();
    let mut m = store.dump();
    let k = m.keys().find(|x| x.ends_with("/intents")).unwrap().clone();
    let mut v: Value = serde_json::from_str(&m[&k]).unwrap();
    v["futureField"] = json!({"x": 1});
    m.insert(k.clone(), v.to_string());
    let store = Arc::new(MemoryJournalStore::from_map(m));
    let b = open(&w, "w", store.clone());
    b.plan_deposit(&big(1), &owner).unwrap();
    let r: Value = serde_json::from_str(&store.dump()[&k]).unwrap();
    assert_eq!(
        (r["futureField"].clone(), r["next"].clone()),
        (json!({"x": 1}), json!("2"))
    );
    b.recover_deposits(5).unwrap();
    let r: Value = serde_json::from_str(&store.dump()[&k]).unwrap();
    assert_eq!(
        (r["futureField"].clone(), r["next"].clone()),
        (json!({"x": 1}), json!("5"))
    );
}

// ---- review fixes of nbp#77 ----

#[test]
fn an_unlocked_read_never_moves_a_locked_compare_and_swap_past_another_writer() {
    use native_bridge_sdk_ext::nb2::journal::{dec, IntentsRecord, Journal};
    let store = World::store();
    let j1 = Journal::new(store.clone(), [7; 32]);
    let j2 = Journal::new(store.clone(), [7; 32]);
    let rec = IntentsRecord {
        base: j1.base("intents"),
        key_scheme: "nb2-hmac-sha256-v1".into(),
        next: dec(1),
        extra: Default::default(),
    };
    j1.put_intents(&rec).unwrap();
    let mut r1 = j1.intents_for_update().unwrap().unwrap();
    let mut r2 = j2.intents_for_update().unwrap().unwrap();
    r2.next = dec(5);
    j2.put_intents(&r2).unwrap(); // another process advances the record
    let _ = j1.intents().unwrap(); // an unlocked reader of the first instance (status, a listing)
    r1.next = dec(2);
    assert_eq!(
        j1.put_intents(&r1).err().and_then(|e| e.reason()),
        Some(WalletReason::JournalConflict)
    );
    assert_eq!(j2.intents().unwrap().unwrap().next, "5");
}

#[test]
fn the_memory_store_meets_the_journal_store_contract() {
    native_bridge_sdk_ext::nb2::journal::check_journal_store(
        MemoryJournalStore::new,
        |s| MemoryJournalStore::from_map(s.dump()),
        16,
    )
    .unwrap();
    // a store that loses its writes on reopen, and one whose compare-and-swap is not atomic, are refused
    assert!(native_bridge_sdk_ext::nb2::journal::check_journal_store(
        MemoryJournalStore::new,
        |_| MemoryJournalStore::new(),
        4
    )
    .is_err());
    #[derive(Default)]
    struct Racy(MemoryJournalStore);
    impl native_bridge_sdk_ext::nb2::journal::JournalStore for Racy {
        fn get(&self, k: &str) -> Result<Option<String>> {
            self.0.get(k)
        }
        fn put_if(&self, k: &str, e: Option<&str>, v: &str) -> Result<bool> {
            // compares, then writes unconditionally: not atomic
            let ok = self.0.get(k)?.as_deref() == e;
            if ok {
                std::thread::sleep(std::time::Duration::from_millis(5));
                self.0.map.lock().unwrap().insert(k.into(), v.into());
            }
            Ok(ok)
        }
        fn list(&self, p: &str) -> Result<Vec<String>> {
            self.0.list(p)
        }
    }
    assert!(native_bridge_sdk_ext::nb2::journal::check_journal_store(
        Racy::default,
        |s| Racy(MemoryJournalStore::from_map(s.0.dump())),
        8
    )
    .is_err());
}

mod sdk_aggregator {
    use super::*;
    use native_bridge_sdk_ext::nb2::aggregator::SdkAggregator;
    use native_bridge_sdk_ext::nb2::token::{signature_predicate, MintTx};
    use native_bridge_sdk_ext::nb2::tokenops::{mint_request, Aggregator};
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use unicity_token::api::{CertificationData, InclusionProof, StateId};
    use unicity_token::cbor::Decoder;
    use unicity_token::client::AggregatorClient;

    #[derive(Debug, Clone, PartialEq)]
    enum E {
        /// STATE_ID_EXISTS, or a queued duplicate
        Duplicate,
        NotYet,
        Unknown,
    }

    struct Client {
        submit: Option<E>,
        proofs: Mutex<VecDeque<core::result::Result<Vec<u8>, E>>>,
    }

    impl AggregatorClient for Client {
        type Error = E;
        fn submit_certification_request(
            &self,
            _: &CertificationData,
        ) -> core::result::Result<(), E> {
            self.submit.clone().map_or(Ok(()), Err)
        }
        fn get_inclusion_proof(&self, _: &StateId) -> core::result::Result<InclusionProof, E> {
            let next = self
                .proofs
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(E::NotYet));
            next.map(|b| InclusionProof::from_cbor(Decoder::new(&b)).unwrap())
        }
    }

    fn request(seed: u8) -> Vec<u8> {
        let m = MintTx {
            network: NETWORK,
            recipient: signature_predicate(&local_owner(&key("o")).public_key()),
            salt: vec![seed; 32],
            ty: vec![2; 32],
            justification: Some(
                native_bridge_sdk_ext::nb2::split::encode_split_justification(&[0; 32]),
            ),
            data: None,
            deadline: None,
        };
        mint_request(&m).unwrap().cd
    }

    fn adapter(
        submit: Option<E>,
        proofs: Vec<core::result::Result<Vec<u8>, E>>,
    ) -> SdkAggregator<Client> {
        let mut a = SdkAggregator::new(
            Client {
                submit,
                proofs: Mutex::new(proofs.into()),
            },
            Box::new(|e| *e == E::NotYet),
        );
        a.sleep = Box::new(|_| {});
        a.timeout = std::time::Duration::from_millis(200);
        a
    }

    #[test]
    fn a_resubmitted_or_queued_request_is_accepted_when_its_proof_certifies_it() {
        let w = setup();
        let req = request(1);
        let proof = w.agg.certify(&req).unwrap();
        // the aggregator already holds the request (a resumed burn, a retried mint): its proof is the answer
        assert_eq!(
            adapter(Some(E::Duplicate), vec![Ok(proof.clone())])
                .certify(&req)
                .unwrap(),
            proof
        );
        // not yet certified, then certified
        assert_eq!(
            adapter(
                None,
                vec![Err(E::NotYet), Err(E::NotYet), Ok(proof.clone())]
            )
            .certify(&req)
            .unwrap(),
            proof
        );
        assert_eq!(
            adapter(Some(E::Duplicate), vec![Err(E::NotYet), Ok(proof.clone())])
                .certify(&req)
                .unwrap(),
            proof
        );
    }

    #[test]
    fn other_proof_read_errors_pass_through_and_a_proof_of_other_data_is_refused() {
        let w = setup();
        let req = request(2);
        let other = w.agg.certify(&request(3)).unwrap();
        // StateUnknown (or expired, auth, config) is passed through at once, not waited out into Unconfirmed
        let e = adapter(None, vec![Err(E::Unknown)])
            .certify(&req)
            .unwrap_err();
        assert!(
            matches!(&e, Error::Other(m) if m.contains("Unknown")),
            "{e}"
        );
        // a refused submission is the submission's error only when a read says no proof exists; a wait that times out is
        // Unconfirmed (the duplicate may still land)
        assert_eq!(
            adapter(Some(E::Duplicate), vec![Err(E::Unknown)])
                .certify(&req)
                .err()
                .and_then(|e| e.reason()),
            Some(WalletReason::Reverted)
        );
        assert_eq!(
            adapter(Some(E::Duplicate), vec![])
                .certify(&req)
                .err()
                .and_then(|e| e.reason()),
            Some(WalletReason::Unconfirmed)
        );
        assert_eq!(
            adapter(None, vec![Ok(other)])
                .certify(&req)
                .err()
                .and_then(|e| e.reason()),
            Some(WalletReason::ProviderFault)
        );
        assert_eq!(
            adapter(None, vec![])
                .certify(&req)
                .err()
                .and_then(|e| e.reason()),
            Some(WalletReason::Unconfirmed)
        );
    }
}

#[test]
fn deposit_estimates_the_pinned_protocol_10_deployment_and_checks_the_user_limit() {
    let mut w = setup();
    let code = b"verifier code";
    w.cfg.verifier_code_hash = he(&[code]);
    w.chain = FakeChain::create(w.root.clone(), w.cfg.clone());
    w.pins = pins_of(&w.chain);
    let payer = w.evm_account("estimate payer");
    let owner = local_owner(&key("estimate owner"));
    w.chain
        .with(|s| s.code.insert(w.cfg.verifier, b"verifier code".to_vec()));
    let mut opts = w.options("estimated deposit", World::store());
    opts.gas = None;
    let bridge = NativeBridgeV2::open(opts).unwrap();
    let plan = bridge.plan_deposit(&big(3), &owner.public_key()).unwrap();
    bridge.submit_deposit(&plan, &payer).unwrap();
    assert_eq!(
        bridge.journal.deposit(plan.intent).unwrap().unwrap().sends[0].gas,
        "144000"
    );

    let mut opts = w.options("limited deposit", World::store());
    opts.gas = None;
    opts.pins.user_gas_limit = 143_999;
    let bridge = NativeBridgeV2::open(opts).unwrap();
    let plan = bridge.plan_deposit(&big(3), &owner.public_key()).unwrap();
    assert_eq!(
        reason(bridge.submit_deposit(&plan, &payer)),
        "CapacityExceeded"
    );
    assert!(bridge
        .journal
        .deposit(plan.intent)
        .unwrap()
        .unwrap()
        .sends
        .is_empty());
}

#[test]
fn split_retries_the_exact_request_after_an_unusable_parent_proof_and_restart() {
    use native_bridge_sdk_ext::nb2::cbor::{
        array, c_arr, c_tag, c_uint, raw, scan_native, tag_content,
    };
    use native_bridge_sdk_ext::nb2::config::tag;
    use native_bridge_sdk_ext::nb2::tokenops::Aggregator;
    use std::sync::Mutex;

    struct OnceCorrupt {
        inner: Arc<FakeAggregator>,
        requests: Mutex<Vec<Vec<u8>>>,
    }
    impl Aggregator for OnceCorrupt {
        fn certify(&self, cd: &[u8]) -> Result<Vec<u8>> {
            let proof = self.inner.certify(cd)?;
            let mut requests = self.requests.lock().unwrap();
            requests.push(cd.to_vec());
            if requests.len() != 1 {
                return Ok(proof);
            }
            let item = scan_native(&proof)?;
            let p = array(tag_content(&item, tag::INCLUSION)?, 5)?;
            Ok(c_tag(
                tag::INCLUSION,
                &c_arr(&[
                    raw(&proof, &p[0]),
                    raw(&proof, &p[1]),
                    &c_uint(p[2].arg + 1),
                    raw(&proof, &p[3]),
                    raw(&proof, &p[4]),
                ]),
            ))
        }
    }
    struct CountSigner(LocalOwner, AtomicUsize);
    impl OwnerSigner for CountSigner {
        fn public_key(&self) -> [u8; 33] {
            self.0.public_key()
        }
        fn sign_unlock(&self, digest: &[u8; 32]) -> core::result::Result<[u8; 65], String> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.sign_unlock(digest)
        }
    }
    let w = setup();
    let store = World::store();
    let payer = w.evm_account("split retry payer");
    let owner = CountSigner(local_owner(&key("split retry owner")), AtomicUsize::new(0));
    let root = minted(&open(&w, "split retry", store.clone()), &payer, &owner.0, 3);
    let aggregator = Arc::new(OnceCorrupt {
        inner: w.agg.clone(),
        requests: Mutex::new(Vec::new()),
    });
    let options = || {
        let mut o = w.options("split retry", store.clone());
        o.aggregator = aggregator.clone();
        o
    };
    let split_id = key("split retry id");
    let outputs = [(owner.public_key().to_vec(), big(3))];
    let bridge = NativeBridgeV2::open(options()).unwrap();
    assert_eq!(
        reason(bridge.split(&root, &owner, &outputs, Some(split_id))),
        "InclusionProof"
    );
    let pending = bridge.journal.split(&hex(&split_id)).unwrap().unwrap();
    assert_eq!(pending.status, "burn-requested");
    assert!(pending.burned.is_none());

    let restarted = NativeBridgeV2::open(options()).unwrap();
    let children = restarted
        .split(&root, &owner, &outputs, Some(split_id))
        .unwrap();
    assert_eq!(restarted.verify_token(&children[0]).unwrap().amount, big(3));
    let requests = aggregator.requests.lock().unwrap();
    assert_eq!(requests[0], requests[1]);
    assert_eq!(owner.1.load(Ordering::SeqCst), 1);
}

#[test]
fn history_refresh_extends_the_installed_pin() {
    use native_bridge_sdk_ext::nb2::config::Build;
    use native_bridge_sdk_ext::nb2::trust::TrustInput;
    use unicity_token::api::bft::TrustBaseHistory;

    const CORPUS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/vectors/nb2-continuation-v1.1/"
    );
    let read = |file: &str| std::fs::read(format!("{CORPUS}{file}")).unwrap();
    let gamma = read("gamma.bin");
    let cfg = native_bridge_sdk_ext::nb2::config::decode_config(
        &gamma,
        &native_bridge_sdk_ext::nb2::config::production_params(),
    )
    .unwrap();
    let pin = cfg.root_genesis;
    let bundle = read("transcripts/held-sibling-0/utb.cbor");
    let extended = TrustInput::from_bundle(&bundle, &pin).unwrap();
    let lagging = TrustBaseHistory::from_trusted_chain(vec![extended.history().genesis().clone()])
        .unwrap()
        .to_bundle();
    let held = read("transcripts/held-sibling-0/evidence.bin");
    {
        let world = setup();
        let foreign = world.root.trust.clone();
        let mut opts = world.options("authenticated refresh", World::store());
        opts.pins.gamma = gamma.clone();
        opts.pins.build = Build::Production;
        opts.trust = TrustInput::from_bundle(&lagging, &pin).unwrap();
        opts.trust_freshness_ms = Some(60_000);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let bundle = bundle.clone();
        opts.refresh_trust = Some(Box::new(move |current| {
            assert_eq!(current.id(), pin);
            assert_eq!(current.history().latest().epoch, 1);
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok(foreign.clone());
            }
            let fresh = TrustInput::from_bundle(&bundle, &pin).unwrap();
            Ok(fresh)
        }));
        let bridge = NativeBridgeV2::open_checked(opts, false).unwrap();
        assert_eq!(reason(bridge.verify_token(&held)), "TrustInput");
        assert!(bridge.verify_token(&held).is_ok());
        assert!(bridge.verify_token(&held).is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    // The same genesis and valid bundle structure are insufficient if a refresh
    // would remove an already held successor.
    let world = setup();
    let mut opts = world.options("trust rollback", World::store());
    opts.pins.gamma = gamma;
    opts.pins.build = Build::Production;
    opts.trust = extended;
    opts.trust_freshness_ms = Some(60_000);
    let rollback = TrustInput::from_bundle(&lagging, &pin).unwrap();
    opts.refresh_trust = Some(Box::new(move |_| Ok(rollback.clone())));
    let bridge = NativeBridgeV2::open_checked(opts, false).unwrap();
    assert_eq!(reason(bridge.verify_token(&held)), "TrustInput");
}
