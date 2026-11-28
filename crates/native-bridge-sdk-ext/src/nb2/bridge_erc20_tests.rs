use super::*;
use crate::nb2::recovery_cost::{erc20_signing_reserve, preflight_recovery, quote_erc20_recovery};
use crate::nb2::{
    recovery::{RecoveryAuthority, RecoverySession},
    recovery_cost::{RecoveryCalibrationRange, RecoveryEntry, RecoveryShape},
    rpc::RpcError,
    token::token_id_of,
    tokenops::local_owner,
    util::{from_hex, hex0x, to_hex},
};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../protocol/vectors/");

struct Chain {
    recovery: [u8; 20],
    blocked: AtomicBool,
    probes: AtomicUsize,
    balance: AtomicU64,
    bad_dependency: AtomicUsize,
    finalized_nonce: AtomicU64,
    pending_reads: AtomicUsize,
    refuse_nonce_at: AtomicUsize,
}

const RECEIPT_HELPER: [u8; 20] = [0x76; 20];
const LINEAGE_HELPER: [u8; 20] = [0x77; 20];
const REGISTRY_HELPER: [u8; 20] = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

impl JsonRpc for Chain {
    fn call(&self, method: &str, params: Value) -> core::result::Result<Value, RpcError> {
        Ok(match method {
            "eth_getCode" => {
                let helper = [RECEIPT_HELPER, LINEAGE_HELPER, REGISTRY_HELPER]
                    .iter()
                    .position(|a| params[0] == hex0x(a));
                match helper {
                    Some(i) if self.bad_dependency.load(Ordering::SeqCst) == i + 1 => {
                        json!("0x600f")
                    }
                    Some(i) => json!(hex0x(&[0x60, i as u8])),
                    None if params[0] == hex0x(&self.recovery) => json!("0x6000"),
                    None => json!("0x"),
                }
            }
            "eth_getBlockByNumber" => json!({"baseFeePerGas": "0x3"}),
            "eth_getBalance" => json!(format!("0x{:x}", self.balance.load(Ordering::SeqCst))),
            "eth_getTransactionCount" if params[1] == "finalized" => json!(format!(
                "0x{:x}",
                self.finalized_nonce.load(Ordering::SeqCst)
            )),
            "eth_getTransactionCount" => {
                let read = self.pending_reads.fetch_add(1, Ordering::SeqCst) + 1;
                json!(if self.refuse_nonce_at.load(Ordering::SeqCst) == read {
                    "0x100"
                } else {
                    "0x1"
                })
            }
            "eth_maxPriorityFeePerGas" => json!("0x1"),
            "eth_call" if params[0]["data"] == hex0x(&sel("state()")) => json!(hex0x(&[0; 192])),
            "eth_call" if params[0]["to"] == hex0x(&self.recovery) => {
                let data = &params[0]["data"];
                if data == &hex0x(&sel("RECEIPTS()")) {
                    json!(hex0x(&address_word(&RECEIPT_HELPER)))
                } else if data == &hex0x(&sel("LINEAGE()")) {
                    json!(hex0x(&address_word(&LINEAGE_HELPER)))
                } else {
                    let index = ["RECEIPTS_HASH()", "LINEAGE_HASH()", "REGISTRY_HASH()"]
                        .iter()
                        .position(|getter| data == &hex0x(&sel(getter)))
                        .unwrap();
                    json!(hex0x(&he(&[&[0x60, index as u8]])))
                }
            }
            "eth_call" => {
                assert!(params[0]["data"]
                    .as_str()
                    .unwrap()
                    .starts_with(&hex0x(&sel("previewPayout(address,uint256)"))));
                assert_eq!(params[0]["gas"], "0x55730");
                self.probes.fetch_add(1, Ordering::SeqCst);
                let marker = if self.blocked.load(Ordering::SeqCst) {
                    "TokenCallFailed()"
                } else {
                    "PayoutPreviewPassed()"
                };
                return Err(RpcError {
                    status: 200,
                    code: 3,
                    message: "execution reverted".into(),
                    data: Some(json!(hex0x(&sel(marker)))),
                });
            }
            _ => panic!("unexpected RPC {method}"),
        })
    }
}

struct NeverSign;
impl OwnerSigner for NeverSign {
    fn public_key(&self) -> [u8; 33] {
        panic!("the burn must stop before inspecting the owner")
    }
    fn sign_unlock(&self, _: &[u8; 32]) -> core::result::Result<[u8; 65], String> {
        panic!("the burn must not be signed")
    }
}
impl Aggregator for NeverSign {
    fn certify(&self, _: &[u8]) -> Result<Vec<u8>> {
        panic!("the burn must not be certified")
    }
}

struct OrdinaryGas(u64);
impl GasModel for OrdinaryGas {
    fn name(&self) -> &str {
        "ordinary fixture"
    }
    fn redeem_gas_limit(&self, _: &RedeemShape<'_>) -> Option<u64> {
        Some(self.0)
    }
    fn deposit_gas_limit(&self) -> u64 {
        400_000
    }
}

struct Calibration([u8; 32], Vec<RecoveryCalibrationRange>);
impl RecoveryCalibration for Calibration {
    fn pins(&self) -> [u8; 32] {
        self.0
    }
    fn runtime_hash(&self) -> [u8; 32] {
        he(&[&[0x60, 0]])
    }
    fn vault_runtime_hash(&self) -> Option<[u8; 32]> {
        Some([1; 32])
    }
    fn ranges(&self) -> &[RecoveryCalibrationRange] {
        &self.1
    }
}

fn vector() -> (Value, Vec<u8>, TrustInput) {
    let doc: Value =
        serde_json::from_slice(&std::fs::read(format!("{VECTORS}erc20-nb2/vectors.json")).unwrap())
            .unwrap();
    let gamma = bytes(&doc["Assets"][0]["Gamma"]);
    let cfg = decode_config(&gamma, &build_params(Build::Production)).unwrap();
    let bundle = std::fs::read(format!(
        "{VECTORS}nb2-continuation-v1.1/transcripts/root/utb.cbor"
    ))
    .unwrap();
    let trust = TrustInput::from_bundle(&bundle, &cfg.root_genesis).unwrap();
    (doc, gamma, trust)
}

fn bytes(v: &Value) -> Vec<u8> {
    from_hex(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn continuation(cfg: &Config, recovery: [u8; 20], fee_budget: u64) -> Erc20ReturnRecovery {
    let erc20 = cfg.erc20.as_ref().unwrap();
    let range = |entry, operations, gaps| RecoveryCalibrationRange {
        min_receipt_bytes: usize::from(entry != RecoveryEntry::Run),
        max: RecoveryShape {
            entry,
            operations,
            gaps,
            receipt_bytes: 65_536,
            calldata_bytes: 393_216,
            pages: 32,
            opening_bytes: 393_216,
        },
        execution: 1_000_000,
    };
    let ranges = (1..=16)
        .map(|n| range(RecoveryEntry::Run, n, 0))
        .chain((1..=128).map(|n| range(RecoveryEntry::AdvanceGaps, 0, n)))
        .chain((0..128).map(|n| range(RecoveryEntry::RedeemRecovered, 0, n)))
        .collect();
    let calibration = Box::new(Calibration(erc20.pins, ranges));
    Erc20ReturnRecovery {
        deployment: RecoveryDeployment {
            salt: erc20.generation,
            recovery,
            runtime_hash: calibration.runtime_hash(),
            pins: erc20.pins,
            vault_runtime_hash: calibration.vault_runtime_hash(),
        },
        calibration,
        signing_bounds: Erc20SigningBounds {
            fee_window_ms: 400_000,
            progress_window_ms: 100_000,
            max_run_calls: 16,
            advance_window_ms: 2_000,
        },
        ordinary_attempts: Some((1, 1_000)),
        backlog: RecoveryBacklog {
            signed_start: 0,
            observed: 0,
            during_progress: 3,
            peak_seals: 1,
            elapsed_ms: 1_000,
            receipt_p99_ms: 1_000,
            advance_peak_seals: 1,
            final_inclusion_ms: 25,
            final_peak_seals: 1,
            qualified_for_ms: 200_000,
        },
        limits: RecoveryLimits {
            signed_bytes: 524_288,
            calldata_bytes: 393_216,
            gas: 24_000_000,
            chain_id: cfg.chain_id,
            max_nonce: 255,
            max_fee_per_gas: 10u8.into(),
            max_priority_fee_per_gas: 1u8.into(),
            max_transaction_fee: None,
            balance: 1_000_000_000_000u64.into(),
            fee_budget: fee_budget.into(),
        },
    }
}

fn return_bridge(
    ordinary_gas: u64,
    balance: u64,
    fee_budget: u64,
    aggregator: Arc<dyn Aggregator + Send + Sync>,
) -> (NativeBridgeV2, Arc<Chain>, Vec<u8>) {
    let (doc, gamma, trust) = vector();
    let cfg = decode_config(&gamma, &build_params(Build::Production)).unwrap();
    let recovery = arr(&bytes(&doc["Assets"][0]["Recovery"]));
    let rpc = Arc::new(Chain {
        recovery,
        blocked: AtomicBool::new(false),
        probes: AtomicUsize::new(0),
        balance: AtomicU64::new(balance),
        bad_dependency: AtomicUsize::new(0),
        finalized_nonce: AtomicU64::new(1),
        pending_reads: AtomicUsize::new(0),
        refuse_nonce_at: AtomicUsize::new(0),
    });
    let pins = DeploymentPins {
        gamma,
        build: Build::Production,
        vault_runtime_code_hash: [1; 32],
        max_encoded_tx_bytes: 524_288,
        user_gas_limit: 24_000_000,
        gas_reserve: 500_000,
        return_reserve_segments: 64,
        deployment_block: 1,
        state_read_only: true,
        max_jump: None,
        native_gas_schedule: None,
        erc20: Some(Erc20ActivationPins {
            factory: arr(&bytes(&doc["Factory"])),
            factory_runtime_hash: [0; 32],
            vault_initcode_hash: arr(&bytes(&doc["VaultTemplate"])),
            recovery_initcode_hash: arr(&bytes(&doc["RecoveryTemplate"])),
            activation_tx: [0; 32],
            funding_qualified: true,
        }),
    };
    let mut options = BridgeOptions::new(
        pins,
        trust,
        rpc.clone(),
        aggregator,
        Arc::new(MemoryJournalStore::default()),
        &[1; 32],
    );
    options.require_backup = Some(false);
    options.gas = Some(Box::new(OrdinaryGas(ordinary_gas)));
    options.unsafe_test_trust = true;
    options.erc20_return_recovery = Some(continuation(&cfg, recovery, fee_budget));
    let bridge = NativeBridgeV2::construct(options).unwrap();
    let held = bytes(&doc["Assets"][0]["Held"]);
    (bridge, rpc, held)
}

#[test]
fn return_requires_affordable_continuation_and_reprobes_before_signing() {
    let (mut bridge, rpc, held) =
        return_bridge(1_000_000, 1_000_000_000_000, 8_000_000, Arc::new(NeverSign));
    let recipient = [0xab; 20];
    let payer = [0xcd; 20];
    assert!(bridge
        .preflight(&held, &40u8.into(), &recipient, 0, &payer)
        .is_ok());
    let err = bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .err()
        .unwrap();
    assert_eq!(err.rule().unwrap().rule, Rule::CapacityPreflight);
    assert!(
        err.to_string()
            .contains("insufficient authorized fee budget"),
        "{err}"
    );

    bridge
        .erc20_return_recovery
        .as_mut()
        .unwrap()
        .limits
        .fee_budget = 1_000_000_000_000u64.into();
    let plan = bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap();
    assert!(!plan.continuation_only);
    rpc.blocked.store(true, Ordering::SeqCst);
    let err = bridge.burn(&plan.return_id, &NeverSign).err().unwrap();
    assert_eq!(err.reason(), Some(WalletReason::RecipientRefused));
    assert_eq!(rpc.probes.load(Ordering::SeqCst), 3);
    assert_eq!(
        bridge.return_record(&plan.return_id).unwrap().status,
        "planned"
    );
}

const CERTIFICATION_PAUSED: &str = "fixture paused certification";

struct PauseCertification;
impl Aggregator for PauseCertification {
    fn certify(&self, _: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Other(CERTIFICATION_PAUSED.into()))
    }
}

#[test]
fn continuation_only_admits_planning_and_signing_after_capacity_or_funds_refusal() {
    let recipient = [0xab; 20];
    let payer = [0xcd; 20];
    for (gas, balance, ordinary_refusal) in [
        (24_000_001, 1_000_000_000_000, "CapacityPreflight"),
        (24_000_000, 167_000_000, "InsufficientFunds"),
    ] {
        let (bridge, rpc, held) = return_bridge(
            gas,
            balance,
            1_000_000_000_000,
            Arc::new(PauseCertification),
        );
        let error = bridge
            .preflight(&held, &40u8.into(), &recipient, 0, &payer)
            .unwrap_err();
        assert_eq!(error.name(), ordinary_refusal);
        let plan = bridge
            .plan_return(&held, &recipient, &payer, Some(0))
            .unwrap();
        assert!(plan.continuation_only);
        assert_eq!(plan.gas_limit, 0);

        rpc.balance.store(1, Ordering::SeqCst);
        let error = bridge.burn(&plan.return_id, &NeverSign).unwrap_err();
        assert_eq!(error.rule().unwrap().rule, Rule::CapacityPreflight);
        assert!(
            error
                .to_string()
                .contains("insufficient free payer balance"),
            "{error}"
        );
        assert_eq!(
            bridge.return_record(&plan.return_id).unwrap().status,
            "planned"
        );

        rpc.balance.store(balance, Ordering::SeqCst);
        rpc.blocked.store(true, Ordering::SeqCst);
        let error = bridge.burn(&plan.return_id, &NeverSign).unwrap_err();
        assert_eq!(error.reason(), Some(WalletReason::RecipientRefused));

        rpc.blocked.store(false, Ordering::SeqCst);
        let token = decode_token(&held).unwrap();
        let parent = &token.ancestors[0].mint;
        let parent_id = token_id_of(&parent.salt, parent.network);
        // Same fixture key derivation as Go's flatFixtureSplit.
        let seed = format!("nb2-key:flat-child-0-{}", to_hex(&parent_id[..4]));
        let owner = local_owner(&hu(&[seed.as_bytes(), &[0]]));
        let error = bridge.burn(&plan.return_id, &owner).unwrap_err();
        assert!(matches!(error, Error::Other(detail) if detail == CERTIFICATION_PAUSED));
        let record = bridge.return_record(&plan.return_id).unwrap();
        assert_eq!(record.status, "burn-requested");
        assert!(record.burn_request.is_some());
        assert_eq!(rpc.probes.load(Ordering::SeqCst), 3);
    }
}

#[test]
fn continuation_only_refuses_an_unaffordable_or_unqualified_plan() {
    let (mut bridge, _, held) =
        return_bridge(24_000_001, 1_000_000_000_000, 1, Arc::new(NeverSign));
    let recipient = [0xab; 20];
    let payer = [0xcd; 20];
    let error = bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap_err();
    assert_eq!(error.rule().unwrap().rule, Rule::CapacityPreflight);
    assert!(
        error
            .to_string()
            .contains("insufficient authorized fee budget"),
        "{error}"
    );
    assert!(bridge
        .journal
        .ret_for_update(&hex(&hu(&[&held])))
        .unwrap()
        .is_none());

    bridge.unsafe_test_trust = false;
    bridge.pins.erc20.as_mut().unwrap().funding_qualified = false;
    let error = bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("awaiting real-value qualification"),
        "{error}"
    );
}

#[test]
fn recovery_session_and_quote_reject_one_mismatched_config_field() {
    let (doc, gamma, trust) = vector();
    let params = build_params(Build::Production);
    let cfg = decode_config(&gamma, &params).unwrap();
    let evidence = bytes(&doc["Assets"][0]["Evidence"]);
    let held = bytes(&doc["Assets"][0]["Held"]);
    let recovery = arr(&bytes(&doc["Assets"][0]["Recovery"]));
    for wrong_salt in [true, false] {
        let mut quote = continuation(&cfg, recovery, 1_000_000_000_000);
        if wrong_salt {
            quote.deployment.salt[0] ^= 1;
        } else {
            quote.deployment.pins[0] ^= 1;
            quote.calibration = Box::new(Calibration(quote.deployment.pins, vec![]));
        }
        let err = preflight_recovery(
            &AdmissionContext {
                gamma: &gamma,
                trust: &trust,
                params: &params,
                deployment: &quote.deployment,
                calibration: &*quote.calibration,
                limits: &quote.limits,
            },
            &held,
            &quote.backlog,
            None,
        )
        .err()
        .unwrap();
        assert_eq!(err.rule().unwrap().rule, Rule::CapacityPreflight);
        assert!(
            err.to_string().contains("unqualified recovery deployment"),
            "{err}"
        );
        let session = RecoverySession::create(
            &gamma,
            &evidence,
            RecoveryAuthority::new(trust.clone(), |_| Ok(())),
            &params,
            quote.deployment,
        );
        assert_eq!(
            session.err().unwrap().rule().unwrap().rule,
            Rule::ConfigShape
        );
    }
}

#[test]
fn erc20_caps_and_funding_limits_are_inclusive() {
    let (_, gamma, _) = vector();
    let cfg = decode_config(&gamma, &build_params(Build::Production)).unwrap();
    let model = continuation(&cfg, [0x22; 20], 100_000_000);
    let limits = &model.limits;
    let resume = RecoveryShape {
        entry: RecoveryEntry::Run,
        operations: 8,
        pages: 32,
        gaps: 0,
        receipt_bytes: 65_536,
        calldata_bytes: 333_060,
        opening_bytes: 131_856,
    };
    let quoted = quote_erc20_recovery(resume, &*model.calibration, limits).unwrap();
    let mut boundary = limits.clone();
    boundary.gas = quoted.gas;
    boundary.signed_bytes = quoted.signed_bytes;
    boundary.calldata_bytes = resume.calldata_bytes;
    assert!(quote_erc20_recovery(resume, &*model.calibration, &boundary).is_some());
    for larger in [
        RecoveryShape {
            operations: 9,
            ..resume
        },
        RecoveryShape {
            pages: 33,
            ..resume
        },
        RecoveryShape {
            receipt_bytes: 65_537,
            ..resume
        },
        RecoveryShape {
            calldata_bytes: 333_092,
            ..resume
        },
    ] {
        assert!(quote_erc20_recovery(larger, &*model.calibration, &boundary).is_none());
    }
    boundary.signed_bytes -= 1;
    assert!(quote_erc20_recovery(resume, &*model.calibration, &boundary).is_none());

    let ordinary = Erc20OrdinaryBound {
        gas: 1_500_000,
        calldata_bytes: 120_004,
        attempts_before_fallback: 2,
        inclusion_ms: 2_000,
    };
    let reserve = |limits: &RecoveryLimits,
                   bounds: &Erc20SigningBounds,
                   ordinary: Option<&Erc20OrdinaryBound>| {
        erc20_signing_reserve(
            12_000_000u64.into(),
            2,
            2,
            &model.backlog,
            limits,
            bounds,
            ordinary,
        )
    };
    let mut bounds = Erc20SigningBounds {
        fee_window_ms: 14_025,
        progress_window_ms: 10_000,
        max_run_calls: 2,
        advance_window_ms: 2_000,
    };
    let mut payer = limits.clone();
    payer.balance = 45_000_000u64.into();
    payer.fee_budget = payer.balance.clone();
    assert_eq!(
        reserve(&payer, &bounds, Some(&ordinary)).unwrap(),
        (45_000_000u64.into(), 2)
    );
    bounds.max_run_calls = 1;
    assert!(reserve(&payer, &bounds, Some(&ordinary))
        .unwrap_err()
        .to_string()
        .contains("Run schedule exceeds"));
    bounds.max_run_calls = 2;
    payer.balance -= 1u8;
    assert!(reserve(&payer, &bounds, Some(&ordinary))
        .unwrap_err()
        .to_string()
        .contains("free payer balance"));
    payer.balance += 1u8;
    payer.fee_budget -= 1u8;
    assert!(reserve(&payer, &bounds, Some(&ordinary))
        .unwrap_err()
        .to_string()
        .contains("authorized fee budget"));
    bounds.fee_window_ms -= 1;
    assert!(reserve(&payer, &bounds, None)
        .unwrap_err()
        .to_string()
        .contains("signing horizon"));
    bounds.advance_window_ms = 999;
    assert!(reserve(&payer, &bounds, None)
        .unwrap_err()
        .to_string()
        .contains("fee or inclusion windows"));
}

#[test]
fn shared_erc20_payer_limits_match_the_typescript_routes() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../tests/erc20-admission/payer-limits.json"
    ))
    .unwrap();
    let n = |row: &Value, field: &str| row[field].as_u64().unwrap();
    let mut limits = RecoveryLimits {
        chain_id: n(&vector, "chainId"),
        max_nonce: n(&vector, "maxNonce"),
        max_fee_per_gas: n(&vector, "maxFeePerGas").into(),
        max_priority_fee_per_gas: n(&vector, "maxPriorityFeePerGas").into(),
        gas: 24_000_000,
        signed_bytes: 524_288,
        calldata_bytes: 393_216,
        max_transaction_fee: None,
        balance: 1_000_000_000u64.into(),
        fee_budget: 1_000_000_000u64.into(),
    };
    let quote = |call: &Value, limits: &RecoveryLimits| {
        quote_erc20_call(n(call, "calldataBytes") as usize, n(call, "gas"), limits)
    };
    let ordinary = &vector["ordinary"];
    let recovery = &vector["recovery"];
    assert_eq!(
        quote(ordinary, &limits).unwrap().0 as u64,
        n(ordinary, "signedBytes")
    );
    for row in vector["cases"].as_array().unwrap() {
        limits.gas = n(row, "gas");
        limits.signed_bytes = n(row, "signedBytes") as usize;
        let route = if quote(recovery, &limits).is_none() {
            "refused"
        } else if quote(ordinary, &limits).is_some() {
            "ordinary"
        } else {
            "continuation"
        };
        assert_eq!(row["route"], route);
    }
}

#[test]
fn ordinary_quote_above_the_payer_gas_limit_selects_continuation() {
    let (mut bridge, _, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let recipient = [0xab; 20];
    let payer = [0xcd; 20];
    assert!(
        !bridge
            .plan_return(&held, &recipient, &payer, Some(0))
            .unwrap()
            .continuation_only
    );
    bridge.erc20_return_recovery.as_mut().unwrap().limits.gas = 4_000_000;
    let plan = bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap();
    assert!(plan.continuation_only);
    assert!(plan.record.extra["recovery"].get("ordinary").is_none());
}

#[test]
fn separate_rust_journals_cannot_reserve_the_same_payer_concurrently() {
    use std::sync::Barrier;
    struct RacingStore(MemoryJournalStore, Barrier);
    impl JournalStore for RacingStore {
        fn get(&self, key: &str) -> Result<Option<String>> {
            self.0.get(key)
        }
        fn list(&self, prefix: &str) -> Result<Vec<String>> {
            self.0.list(prefix)
        }
        fn put_if(&self, key: &str, prior: Option<&str>, value: &str) -> Result<bool> {
            if key.starts_with("nb2/payer/v1/") && prior.is_none() {
                self.1.wait();
            }
            self.0.put_if(key, prior, value)
        }
    }
    let store = Arc::new(RacingStore(MemoryJournalStore::new(), Barrier::new(2)));
    let outcomes = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            Journal::new(store.clone(), [1; 32]).check_return_payer(
                31337,
                &[3; 20],
                &hex(&[1; 32]),
                true,
            )
        });
        let b = scope.spawn(|| {
            Journal::new(store.clone(), [2; 32]).check_return_payer(
                31337,
                &[3; 20],
                &hex(&[2; 32]),
                true,
            )
        });
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .into_iter()
            .find_map(Result::err)
            .unwrap()
            .rule()
            .unwrap()
            .rule,
        Rule::CapacityPreflight
    );
}

#[test]
fn mismatched_dependencies_keep_the_holder_signer_untouched() {
    let (bridge, rpc, held) = return_bridge(
        24_000_001,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let plan = bridge
        .plan_return(&held, &[0xab; 20], &[0xcd; 20], Some(0))
        .unwrap();
    for i in 1..=3 {
        rpc.bad_dependency.store(i, Ordering::SeqCst);
        assert!(bridge
            .burn(&plan.return_id, &NeverSign)
            .unwrap_err()
            .to_string()
            .contains("pinned hash"));
    }
    assert_eq!(
        bridge.return_record(&plan.return_id).unwrap().status,
        "planned"
    );
}

#[test]
fn peer_paid_holds_the_payer_until_the_local_recovery_nonce_is_finalized() {
    use super::super::evm::LocalKeySigner;
    let (bridge, rpc, held) = return_bridge(
        24_000_001,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let signer = LocalKeySigner::new(&[0x35; 32]);
    let payer = signer.address();
    let recipient = [0xab; 20];
    let planned = bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap();
    let mut paid = planned.record;
    paid.return_id = hex(&[0xec; 32]);
    bridge.journal.put_return(&paid).unwrap();
    bridge
        .journal
        .check_return_payer(bridge.cfg.chain_id, &payer, &paid.return_id, true)
        .unwrap();
    let packet = sign_tx(
        &signer,
        &TxRequest {
            chain_id: bridge.cfg.chain_id,
            nonce: 7,
            max_priority_fee_per_gas: 1u8.into(),
            max_fee_per_gas: 10u8.into(),
            gas: 2_000_000,
            to: rpc.recovery,
            value: BigUint::default(),
            data: vec![0x11],
        },
    )
    .unwrap();
    bridge
        .journal
        .index_payer_sends(&paid, &[&packet.raw])
        .unwrap();
    paid.status = "paid".into();
    paid.paid = Some(PaidRecord {
        tx_hash: hex(&[0xdd; 32]),
        block_number: "9".into(),
        extra: Default::default(),
    });
    bridge.journal.put_return(&paid).unwrap();
    rpc.finalized_nonce.store(7, Ordering::SeqCst);
    assert!(bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap_err()
        .to_string()
        .contains("signed nonce awaiting finalization"));
    rpc.finalized_nonce.store(8, Ordering::SeqCst);
    bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap();
}

fn fixture_owner(held: &[u8]) -> super::super::tokenops::LocalOwner {
    let token = decode_token(held).unwrap();
    let parent = &token.ancestors[0].mint;
    let parent_id = token_id_of(&parent.salt, parent.network);
    let seed = format!("nb2-key:flat-child-0-{}", to_hex(&parent_id[..4]));
    local_owner(&hu(&[seed.as_bytes(), &[0]]))
}

#[test]
fn declined_signing_cancels_but_an_ambiguous_signer_keeps_the_payer() {
    struct DecliningOwner([u8; 33], bool);
    impl OwnerSigner for DecliningOwner {
        fn public_key(&self) -> [u8; 33] {
            self.0
        }
        fn sign_unlock(&self, _: &[u8; 32]) -> core::result::Result<[u8; 65], String> {
            unreachable!()
        }
        fn sign_unlock_for_burn(&self, _: &[u8; 32]) -> Result<[u8; 65]> {
            if self.1 {
                refuse(WalletReason::SigningDeclined, "owner declined")
            } else {
                Err(Error::Other("signer disconnected".into()))
            }
        }
    }
    let (bridge, rpc, held) = return_bridge(
        24_000_001,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let payer = [0xcd; 20];
    let plan = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap();
    let other = hex(&[0xfd; 32]);
    rpc.refuse_nonce_at.store(
        rpc.pending_reads.load(Ordering::SeqCst) + 2,
        Ordering::SeqCst,
    );
    assert!(bridge
        .burn(&plan.return_id, &NeverSign)
        .unwrap_err()
        .to_string()
        .contains("declared nonce horizon"));
    bridge
        .journal
        .check_return_payer(bridge.cfg.chain_id, &payer, &other, false)
        .unwrap();
    let candidate = fixture_owner(&held).public_key();
    assert_eq!(
        bridge
            .burn(&plan.return_id, &DecliningOwner(candidate, true))
            .unwrap_err()
            .reason(),
        Some(WalletReason::SigningDeclined)
    );
    bridge
        .journal
        .check_return_payer(bridge.cfg.chain_id, &payer, &other, false)
        .unwrap();
    assert!(bridge
        .burn(&plan.return_id, &DecliningOwner(candidate, false))
        .unwrap_err()
        .to_string()
        .contains("signer disconnected"));
    assert!(bridge
        .journal
        .check_return_payer(bridge.cfg.chain_id, &payer, &other, false)
        .unwrap_err()
        .to_string()
        .contains("outstanding ERC20 return"));
}

#[test]
fn legacy_domains_drain_in_sequence_with_cross_domain_fee_and_nonce_reserves() {
    let (bridge, _, held) = return_bridge(
        24_000_001,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let chain_id = bridge.cfg.chain_id;
    let payer = [0xcd; 20];
    let recipient = [0xab; 20];
    let plan = bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap();
    let old_a = Journal::new(bridge.journal.store.clone(), [0x01; 32]);
    let old_b = Journal::new(bridge.journal.store.clone(), [0x02; 32]);
    let off_chain = Journal::new(bridge.journal.store.clone(), [0x03; 32]);
    let old = |journal: &Journal, id: u8, calls: &str, fee: &str| {
        let mut record = plan.record.clone();
        record.base = journal.base("return");
        record.return_id = hex(&[id; 32]);
        record.status = "burned".into();
        record.extra["recovery"]["calls"] = json!(calls);
        record.extra["recovery"]["totalFee"] = json!(fee);
        record
    };
    let mut a = old(&old_a, 1, "6", "60");
    let mut b = old(&old_b, 2, "7", "70");
    let c = old(&off_chain, 3, "80", "800");
    off_chain
        .check_return_payer(chain_id + 1, &payer, &c.return_id, false)
        .unwrap();
    off_chain.put_return(&c).unwrap();
    old_a.put_return(&a).unwrap();
    old_b.put_return(&b).unwrap();
    assert!(bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap_err()
        .to_string()
        .contains("outstanding ERC20 return"));
    let drain = PayerCheck {
        drain: true,
        ..Default::default()
    };
    let commitment = old_a
        .check_payer(chain_id, &payer, &a.return_id, true, &drain)
        .unwrap();
    assert_eq!(commitment.fees, 70u8.into());
    assert_eq!(commitment.calls, 7);
    assert_eq!(commitment.nonce_limit(255), Some(248));
    assert_eq!(commitment.nonce_limit(245), Some(245));
    assert!(old_b
        .check_payer(chain_id, &payer, &b.return_id, true, &drain)
        .is_err());
    a.status = "paid".into();
    a.paid = Some(PaidRecord {
        tx_hash: hex(&[1; 32]),
        block_number: "21".into(),
        extra: Default::default(),
    });
    old_a.put_return(&a).unwrap();
    assert_eq!(
        old_b
            .check_payer(chain_id, &payer, &b.return_id, true, &drain)
            .unwrap()
            .calls,
        0
    );
    b.status = "paid".into();
    b.paid = Some(PaidRecord {
        tx_hash: hex(&[2; 32]),
        block_number: "22".into(),
        extra: Default::default(),
    });
    old_b.put_return(&b).unwrap();
    bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap();
}

#[test]
fn stale_cancellation_cannot_release_a_retry_claim() {
    let (bridge, _, held) = return_bridge(
        24_000_001,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let payer = [0xcd; 20];
    let plan = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap();
    let chain = bridge.cfg.chain_id;
    let id = &plan.record.return_id;
    let mut claimed = bridge
        .journal
        .check_payer(
            chain,
            &payer,
            id,
            true,
            &PayerCheck {
                fence: Some("initial"),
                ..Default::default()
            },
        )
        .unwrap();
    let retry = Journal::new(bridge.journal.store.clone(), bridge.domain);
    assert!(retry
        .check_payer(
            chain,
            &payer,
            id,
            true,
            &PayerCheck {
                fence: Some("retry"),
                ..Default::default()
            }
        )
        .unwrap()
        .fence
        .is_none());
    bridge
        .journal
        .cancel_unsigned_return(id, claimed.fence.take().unwrap())
        .unwrap();
    assert!(retry
        .check_return_payer(chain, &payer, &hex(&[0xde; 32]), true)
        .is_err());
}
