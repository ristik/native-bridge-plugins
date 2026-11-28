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
    vector_runtime: AtomicBool,
    finalized_nonce: AtomicU64,
    pending_reads: AtomicUsize,
    refuse_nonce_at: AtomicUsize,
}

const RECEIPT_HELPER: [u8; 20] = [0x76; 20];
const LINEAGE_HELPER: [u8; 20] = [0x77; 20];
const REGISTRY_HELPER: [u8; 20] = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn finalized_header() -> Value {
    let zero = hex0x(&[0; 32]);
    json!({
        "number": "0x14", "parentHash": zero, "sha3Uncles": zero, "miner": hex0x(&[0; 20]),
        "stateRoot": zero, "transactionsRoot": zero, "receiptsRoot": zero, "logsBloom": hex0x(&[0; 256]),
        "difficulty": "0x0", "gasLimit": "0x2000000", "gasUsed": "0x0", "timestamp": "0x1",
        "extraData": "0x", "mixHash": zero, "nonce": hex0x(&[0; 8]), "baseFeePerGas": "0x3",
        "withdrawalsRoot": zero, "blobGasUsed": "0x0", "excessBlobGas": "0x0", "parentBeaconBlockRoot": zero,
    })
}

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
                    None if params[0] == hex0x(&self.recovery) => {
                        if self.vector_runtime.load(Ordering::SeqCst) {
                            json!(hex0x(b"erc20-recovery-runtime"))
                        } else {
                            json!("0x6000")
                        }
                    }
                    None => json!("0x"),
                }
            }
            "eth_getBlockByNumber" if params[0] == "finalized" || params[0] == "0x14" => {
                finalized_header()
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
            "eth_blockNumber" => json!("0x14"),
            "eth_getLogs" => json!([]),
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

struct Calibration([u8; 32], Vec<RecoveryCalibrationRange>, [u8; 32], [u8; 32]);
impl RecoveryCalibration for Calibration {
    fn pins(&self) -> [u8; 32] {
        self.0
    }
    fn runtime_hash(&self) -> [u8; 32] {
        self.2
    }
    fn vault_runtime_hash(&self) -> Option<[u8; 32]> {
        Some(self.3)
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
    let calibration = Box::new(Calibration(erc20.pins, ranges, he(&[&[0x60, 0]]), [1; 32]));
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
        vector_runtime: AtomicBool::new(false),
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
            quote.calibration = Box::new(Calibration(
                quote.deployment.pins,
                vec![],
                he(&[&[0x60, 0]]),
                [1; 32],
            ));
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
        .prepare_payer_signing(&paid, bridge.cfg.chain_id, &payer)
        .unwrap();
    bridge
        .journal
        .retain_payer_send(&paid, &packet.raw)
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

#[test]
fn peer_paid_while_the_evm_signer_is_outstanding_keeps_the_payer_reserved() {
    use super::super::evm::LocalKeySigner;

    struct AmbiguousSigner<F>([u8; 20], F);
    impl<F: Fn()> EvmSigner for AmbiguousSigner<F> {
        fn address(&self) -> [u8; 20] {
            self.0
        }
        fn sign_transaction(&self, _: &TxRequest) -> core::result::Result<Vec<u8>, String> {
            (self.1)();
            Err("signer disconnected".into())
        }
    }
    let (bridge, rpc, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let payer = LocalKeySigner::new(&[0x35; 32]).address();
    let recipient = [0xab; 20];
    let mut active = bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap()
        .record;
    active.return_id = hex(&[0xec; 32]);
    active.status = "burned".into();
    bridge.journal.put_return(&active).unwrap();
    bridge
        .journal
        .check_return_payer(bridge.cfg.chain_id, &payer, &active.return_id, true)
        .unwrap();
    let peer = Journal::new(bridge.journal.store.clone(), bridge.domain);
    let tx = TxRequest {
        chain_id: bridge.cfg.chain_id,
        nonce: 7,
        max_priority_fee_per_gas: 1u8.into(),
        max_fee_per_gas: 10u8.into(),
        gas: undec64(
            active.extra["recovery"]["ordinary"]["gas"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
        to: bridge.cfg.vault,
        value: BigUint::default(),
        data: vec![0x11; 68],
    };
    rpc.finalized_nonce.store(tx.nonce, Ordering::SeqCst);
    let assert_reserved = || {
        assert!(bridge
            .plan_return(&held, &recipient, &payer, Some(0))
            .unwrap_err()
            .to_string()
            .contains("signing nonce awaiting finalization"));
    };
    let signer = AmbiguousSigner(payer, || {
        let mut paid = peer.ret_for_update(&active.return_id).unwrap().unwrap();
        paid.status = "paid".into();
        paid.paid = Some(PaidRecord {
            tx_hash: hex(&[0xdd; 32]),
            block_number: "9".into(),
            extra: Default::default(),
        });
        peer.put_return(&paid).unwrap();
        assert_reserved();
    });
    let error = bridge.sign_redeem_tx(&active, &signer, &tx).unwrap_err();
    assert!(error.to_string().contains("signer disconnected"), "{error}");
    assert_reserved();
    rpc.finalized_nonce.store(tx.nonce + 1, Ordering::SeqCst);
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
fn funded_domains_drain_in_sequence_with_cross_domain_fee_and_nonce_reserves() {
    let (bridge, rpc, held) = return_bridge(
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
    old_a.register_payer_chain(chain_id).unwrap();
    old_b.register_payer_chain(chain_id).unwrap();
    old_a.put_return(&a).unwrap();
    old_b.put_return(&b).unwrap();
    assert!(bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap_err()
        .to_string()
        .contains("outstanding ERC20 return"));
    let drain = PayerCheck {
        drain: true,
        signing_nonce: Some(0),
        finalized_nonce: Some(&|| Ok(2)),
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
    let drain = PayerCheck {
        signing_nonce: Some(2),
        ..drain
    };
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
    rpc.finalized_nonce.store(3, Ordering::SeqCst);
    bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap();
}

#[test]
fn erc20_startup_signing_and_rebroadcast_refuse_pre_release_records_without_indexing_them() {
    use super::super::evm::LocalKeySigner;
    let (bridge, rpc, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let signer = LocalKeySigner::new(&[0x35; 32]);
    let payer = signer.address();
    let chain = bridge.cfg.chain_id;
    let journal = &bridge.journal;
    let mut record = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap()
        .record;
    let id = unhex_n::<32>(&record.return_id).unwrap();
    journal.open_erc20_payer_journal(chain).unwrap();
    record.extra.remove("erc20PayerState");
    record.extra.remove("recovery");
    journal.put_return(&record).unwrap();
    let assert_refused = |error: Error| {
        assert!(
            error
                .to_string()
                .contains("unsupported pre-release ERC20 record: start a fresh wallet"),
            "{error}"
        );
    };
    assert_refused(journal.open_erc20_payer_journal(chain).unwrap_err());
    assert_refused(bridge.burn(&id, &NeverSign).unwrap_err());
    let mut unreserved = record.clone();
    unreserved.extra.insert("erc20PayerState".into(), json!(1));
    unreserved.status = "burn-requested".into();
    unreserved.burn_request = Some(hex(&[0x37; 32]));
    journal.put_return(&unreserved).unwrap();
    assert_refused(journal.open_erc20_payer_journal(chain).unwrap_err());
    let request = TxRequest {
        chain_id: chain,
        nonce: 7,
        max_priority_fee_per_gas: 1u8.into(),
        max_fee_per_gas: 10u8.into(),
        gas: 100_000,
        to: bridge.cfg.vault,
        value: BigUint::default(),
        data: vec![],
    };
    let packet = sign_tx(&signer, &request).unwrap();
    record.status = "submitted".into();
    record
        .extra
        .insert("executionPayer".into(), json!(hex(&payer)));
    record.sends.push(bridge.send_record(&packet));
    let scope = format!(
        "{chain}/{}/{}/{}",
        to_hex(&payer),
        &record.base.domain[2..],
        &record.return_id[2..]
    );
    let watermark = format!("nb2/payer-sends/v1/{scope}");
    journal.store.put_if(&watermark, None, "2").unwrap();
    journal.put_return(&record).unwrap();
    for _ in 0..2 {
        assert_refused(journal.open_erc20_payer_journal(chain).unwrap_err());
        assert_refused(bridge.submit_redeem(&id, &signer).unwrap_err());
        assert_refused(
            journal
                .prepare_payer_broadcast(&record, chain, &packet.raw)
                .unwrap_err(),
        );
        assert_eq!(journal.store.get(&watermark).unwrap().as_deref(), Some("2"));
        assert!(journal
            .store
            .get(&format!("nb2/payer-fee-index/v2/{scope}"))
            .unwrap()
            .is_none());
        assert!(journal
            .store
            .list(&format!("nb2/payer-fees/v1/{scope}/"))
            .unwrap()
            .is_empty());
    }
    record.status = "paid".into();
    record.paid = Some(PaidRecord {
        tx_hash: hex(&packet.hash),
        block_number: "21".into(),
        extra: Default::default(),
    });
    journal.put_return(&record).unwrap();
    rpc.finalized_nonce.store(8, Ordering::SeqCst);
    assert_refused(journal.open_erc20_payer_journal(chain).unwrap_err());
    assert_refused(
        journal
            .check_return_payer(chain, &payer, &hex(&[0x38; 32]), false)
            .unwrap_err(),
    );
}

#[test]
fn erc20_open_refuses_an_unregistered_foreign_pending_send_on_any_chain() {
    use super::super::evm::LocalKeySigner;
    let (bridge, _, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let signer = LocalKeySigner::new(&[0x35; 32]);
    let payer = signer.address();
    let chain = bridge.cfg.chain_id;
    let journal = &bridge.journal;
    let record = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap()
        .record;
    let native: Value = serde_json::from_str(include_str!(
        "../../../../tests/nb2-journal/ts-written.json"
    ))
    .unwrap();
    for (key, value) in native["journal"].as_object().unwrap() {
        if key.contains("/return/") {
            journal
                .store
                .put_if(key, None, value.as_str().unwrap())
                .unwrap();
        }
    }
    journal.open_erc20_payer_journal(chain).unwrap();
    let (vectors, _, _) = vector();
    let asset = &vectors["Assets"][1];
    let domain = domain_of(&bytes(&asset["Gamma"]));
    assert_ne!(domain, bridge.domain);
    let foreign = Journal::new(journal.store.clone(), domain);
    let mut pending = record.clone();
    pending.base = foreign.base("return");
    pending.return_id = hex(&[0x27; 32]);
    pending.status = "submitted".into();
    pending.source = hex(&bytes(&asset["Held"]));
    pending.extra.remove("erc20PayerState");
    pending.extra.remove("recovery");
    pending
        .extra
        .insert("executionPayer".into(), json!(hex(&payer)));
    for chain_id in [chain, chain + 1] {
        let request = TxRequest {
            chain_id,
            nonce: 7,
            gas: 100_000,
            max_fee_per_gas: 10u8.into(),
            max_priority_fee_per_gas: 1u8.into(),
            to: arr(&bytes(&asset["Vault"])),
            value: BigUint::default(),
            data: vec![],
        };
        pending.sends = vec![bridge.send_record(&sign_tx(&signer, &request).unwrap())];
        foreign.put_return(&pending).unwrap();
        let keys = journal.store.list("").unwrap();
        let before = keys
            .iter()
            .map(|key| journal.store.get(key).unwrap())
            .collect::<Vec<_>>();
        for error in [
            journal.open_erc20_payer_journal(chain).unwrap_err(),
            journal
                .check_return_payer(chain, &payer, &record.return_id, true)
                .unwrap_err(),
        ] {
            assert!(
                error
                    .to_string()
                    .contains("unsupported pre-release ERC20 record: start a fresh wallet"),
                "{error}"
            );
        }
        assert_eq!(journal.store.list("").unwrap(), keys);
        assert_eq!(
            keys.iter()
                .map(|key| journal.store.get(key).unwrap())
                .collect::<Vec<_>>(),
            before
        );
    }
    foreign.register_payer_chain(chain + 1).unwrap();
    let error = journal.open_erc20_payer_journal(chain).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported pre-release ERC20 record: start a fresh wallet"),
        "{error}"
    );
}

#[test]
fn an_evm_nonce_fence_requires_its_existing_scoped_fee_index() {
    let (bridge, _, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let payer = [0xcd; 20];
    let chain = bridge.cfg.chain_id;
    let journal = &bridge.journal;
    let mut record = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap()
        .record;
    record.status = "burned".into();
    record.burn_request = Some(hex(&[0x32; 32]));
    journal.put_return(&record).unwrap();
    let scope = format!("{chain}/{}", to_hex(&payer));
    let slot = format!("nb2/payer/v1/{scope}");
    let owner = format!(
        "nb2/v1/{}/return/{}",
        &record.base.domain[2..],
        &record.return_id[2..]
    );
    let index = format!(
        "nb2/payer-fee-index/v2/{scope}/{}/{}",
        &record.base.domain[2..],
        &record.return_id[2..]
    );
    let fence = format!("{owner}#nonce:7");
    journal.store.put_if(&slot, None, &fence).unwrap();
    let claim = || {
        journal.check_payer(
            chain,
            &payer,
            &record.return_id,
            true,
            &PayerCheck {
                signing_nonce: Some(7),
                ..Default::default()
            },
        )
    };
    for error in [
        journal.open_erc20_payer_journal(chain).unwrap_err(),
        journal
            .prepare_payer_signing(&record, chain, &payer)
            .unwrap_err(),
        claim().err().expect("the incomplete fence must refuse"),
    ] {
        assert!(
            error
                .to_string()
                .contains("unsupported pre-release ERC20 record: start a fresh wallet"),
            "{error}"
        );
    }
    assert!(journal.store.get(&index).unwrap().is_none());
    assert_eq!(
        journal.store.get(&slot).unwrap().as_deref(),
        Some(fence.as_str())
    );
    journal.store.put_if(&slot, Some(&fence), &owner).unwrap();
    journal.open_erc20_payer_journal(chain).unwrap();
    assert!(journal.store.get(&index).unwrap().is_none());
    claim().unwrap();
    assert_eq!(journal.store.get(&index).unwrap().as_deref(), Some("1"));
    assert_eq!(
        journal.store.get(&slot).unwrap().as_deref(),
        Some(fence.as_str())
    );
    journal.open_erc20_payer_journal(chain).unwrap();
}

#[test]
fn a_claim_checks_all_remaining_calls_before_granting_exclusivity() {
    let (bridge, _, held) = return_bridge(
        24_000_001,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let chain = bridge.cfg.chain_id;
    let payer = [0xcd; 20];
    let template = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap()
        .record;
    let a = Journal::new(bridge.journal.store.clone(), [0xa1; 32]);
    let b = Journal::new(bridge.journal.store.clone(), [0xb1; 32]);
    let legacy = |journal: &Journal, id: u8, cap: &str| {
        let mut record = template.clone();
        record.base = journal.base("return");
        record.return_id = hex(&[id; 32]);
        record.status = "burned".into();
        record.extra["recovery"]["calls"] = json!("8");
        record.extra["recovery"]["envelope"]["maxNonce"] = json!(cap);
        journal.register_payer_chain(chain).unwrap();
        journal.put_return(&record).unwrap();
        record
    };
    let later = legacy(&a, 1, "15");
    let mut earlier = legacy(&b, 2, "8");
    let claim = |journal: &Journal, record: &ReturnRecord, nonce| {
        journal.check_payer(
            chain,
            &payer,
            &record.return_id,
            true,
            &PayerCheck {
                drain: true,
                signing_nonce: Some(nonce),
                finalized_nonce: Some(&|| Ok(8)),
                ..Default::default()
            },
        )
    };
    assert!(claim(&a, &later, 0)
        .err()
        .unwrap()
        .to_string()
        .contains("remaining continuation schedule"));
    for nonce in 0..8 {
        claim(&b, &earlier, nonce).unwrap();
    }
    earlier.status = "paid".into();
    earlier.paid = Some(PaidRecord {
        tx_hash: hex(&[2; 32]),
        block_number: "21".into(),
        extra: Default::default(),
    });
    b.put_return(&earlier).unwrap();
    for nonce in 8..16 {
        claim(&a, &later, nonce).unwrap();
    }
}

#[test]
fn finalized_runs_free_exact_nonce_and_balance_windows_for_both_funded_returns() {
    use super::super::evm::LocalKeySigner;
    use super::super::recovery::RecoveryReceipt;
    let (bridge, rpc, held) = return_bridge(
        24_000_001,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let chain_id = bridge.cfg.chain_id;
    let signer = LocalKeySigner::new(&[0x35; 32]);
    let payer = signer.address();
    let template = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap()
        .record;
    let a = Journal::new(bridge.journal.store.clone(), [0xa1; 32]);
    let b = Journal::new(bridge.journal.store.clone(), [0xb1; 32]);
    let legacy = |journal: &Journal, id: u8, cap: &str, nonce| {
        let mut record = template.clone();
        record.base = journal.base("return");
        record.return_id = hex(&[id; 32]);
        record.status = "burned".into();
        record
            .extra
            .insert("executionPayer".into(), json!(hex(&payer)));
        record.extra["recovery"]["calls"] = json!("8");
        record.extra["recovery"]["totalFee"] = json!("100");
        record.extra["recovery"]["envelope"]["maxNonce"] = json!(cap);
        record.extra["recovery"]["envelope"]["maxFeePerGas"] = json!("1");
        let packet = sign_tx(
            &signer,
            &TxRequest {
                chain_id,
                nonce,
                gas: 100_000,
                max_priority_fee_per_gas: 1u8.into(),
                max_fee_per_gas: 10u8.into(),
                to: rpc.recovery,
                value: BigUint::default(),
                data: vec![],
            },
        )
        .unwrap();
        journal.register_payer_chain(chain_id).unwrap();
        let mut unsigned = record.clone();
        unsigned.extra.remove("executionPayer");
        journal
            .prepare_payer_signing(&unsigned, chain_id, &payer)
            .unwrap();
        journal.retain_payer_send(&record, &packet.raw).unwrap();
        journal.put_return(&record).unwrap();
        journal
            .index_recovery_progress(
                chain_id,
                &record,
                1,
                &RecoveryReceipt {
                    encoded: vec![],
                    block_number: 20 + nonce,
                    block_hash: [id; 32],
                    tx_index: 0,
                    log_index: 0,
                },
                Some(80u64.into()),
            )
            .unwrap();
        record
    };
    let later = legacy(&a, 1, "15", 0);
    let mut earlier = legacy(&b, 2, "8", 1);
    let finalized = AtomicU64::new(19);
    rpc.finalized_nonce.store(2, Ordering::SeqCst);
    rpc.balance.store(159, Ordering::SeqCst);
    let claim = |journal: &Journal, record: &ReturnRecord, nonce| {
        journal.check_payer(
            chain_id,
            &payer,
            &record.return_id,
            true,
            &PayerCheck {
                drain: true,
                signing_nonce: Some(nonce),
                finalized_nonce: Some(&|| bridge.evm.nonce(&payer, "finalized")),
                finalized_block: Some(&|number, hash| {
                    Ok(finalized.load(Ordering::SeqCst) >= number
                        && *hash == [(number - 19) as u8; 32])
                }),
                before_signing: Some(&|other| {
                    if bridge.erc20_free_balance(&payer, other)? < 80u64.into() {
                        return fail_d(Rule::CapacityPreflight, "insufficient free balance");
                    }
                    Ok(())
                }),
                ..Default::default()
            },
        )
    };
    assert!(claim(&b, &earlier, 2)
        .err()
        .unwrap()
        .to_string()
        .contains("remaining continuation schedule"));
    finalized.store(21, Ordering::SeqCst);
    assert!(claim(&a, &later, 2)
        .err()
        .unwrap()
        .to_string()
        .contains("remaining continuation schedule"));
    rpc.finalized_nonce.store(0, Ordering::SeqCst);
    assert!(claim(&b, &earlier, 2)
        .err()
        .unwrap()
        .to_string()
        .contains("signed nonce awaiting finalization"));
    rpc.finalized_nonce.store(2, Ordering::SeqCst);
    assert!(claim(&b, &earlier, 2)
        .err()
        .unwrap()
        .to_string()
        .contains("insufficient free balance"));
    rpc.balance.store(160, Ordering::SeqCst);
    let competing = claim(&b, &earlier, 2).unwrap();
    assert_eq!(competing.calls, 7);
    assert_eq!(competing.fees, 80u64.into());
    for nonce in 3..=8 {
        claim(&b, &earlier, nonce).unwrap();
    }
    earlier.status = "paid".into();
    earlier.paid = Some(PaidRecord {
        tx_hash: hex(&[2; 32]),
        block_number: "22".into(),
        extra: Default::default(),
    });
    b.put_return(&earlier).unwrap();
    rpc.finalized_nonce.store(9, Ordering::SeqCst);
    for nonce in 9..=15 {
        claim(&a, &later, nonce).unwrap();
    }
}

#[test]
fn the_sdk_publishes_only_authenticated_recovery_checkpoints() {
    let (mut bridge, rpc, held) = return_bridge(
        24_000_001,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let (doc, _, _) = vector();
    let asset = &doc["Assets"][0];
    let mut plan = bridge
        .plan_return(&held, &[0xab; 20], &[0xcd; 20], Some(0))
        .unwrap();
    plan.record.status = "burned".into();
    plan.record.burned = Some(asset["Evidence"].as_str().unwrap().into());
    plan.record.eta = Some(hex(&bytes(&asset["Verdict"])[32..64]));
    plan.record.extra["recovery"]["calls"] = json!("8");
    bridge.journal.put_return(&plan.record).unwrap();
    rpc.vector_runtime.store(true, Ordering::SeqCst);
    bridge
        .erc20_return_recovery
        .as_mut()
        .unwrap()
        .deployment
        .runtime_hash = he(&[b"erc20-recovery-runtime"]);
    // The vector's recovered Redeem carries the exact Complete receipt.
    let calldata = bytes(&asset["ReturnProof"]);
    let receipt_start = 68 + 42 + 1 + 4;
    let width = u32::from_be_bytes(arr(&calldata[receipt_start - 4..receipt_start])) as usize;
    let receipt = &calldata[receipt_start..receipt_start + width];
    let publish = |bridge: &NativeBridgeV2, proof| {
        bridge.index_erc20_recovery_progress(
            &plan.return_id,
            &[Erc20RecoveryCheckpoint {
                receipt: proof,
                gaps: &[],
            }],
        )
    };
    let error = publish(&bridge, receipt).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unqualified recovery deployment"),
        "{error}"
    );
    let policy = bridge.erc20_return_recovery.as_mut().unwrap();
    let deployed = &policy.deployment;
    let vault_hash = deployed.vault_runtime_hash.unwrap();
    let ranges = policy.calibration.ranges().to_vec();
    for (pins, vault) in [([0xff; 32], vault_hash), (deployed.pins, [0xff; 32])] {
        bridge.erc20_return_recovery.as_mut().unwrap().calibration = Box::new(Calibration(
            pins,
            ranges.clone(),
            he(&[b"erc20-recovery-runtime"]),
            vault,
        ));
        let error = publish(&bridge, receipt).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unqualified recovery deployment"),
            "{error}"
        );
    }
    let policy = bridge.erc20_return_recovery.as_mut().unwrap();
    policy.calibration = Box::new(Calibration(
        policy.deployment.pins,
        ranges,
        policy.deployment.runtime_hash,
        vault_hash,
    ));
    assert!(publish(&bridge, &receipt[..receipt.len() - 1]).is_err());
    assert!(bridge
        .journal
        .store
        .list("nb2/payer-progress/v2/")
        .unwrap()
        .is_empty());
    publish(&bridge, receipt).unwrap();
    let keys = bridge.journal.store.list("nb2/payer-progress/v2/").unwrap();
    assert_eq!(keys.len(), 1);
    let progress: Value =
        serde_json::from_str(&bridge.journal.store.get(&keys[0]).unwrap().unwrap()).unwrap();
    assert_eq!(progress["completed"], "1");
    assert!(undec(progress["continuationGas"].as_str().unwrap()).unwrap() > BigUint::default());
}

#[test]
fn contested_ordinary_signing_requires_the_remaining_fee_budget_and_free_balance() {
    use super::super::evm::LocalKeySigner;
    let (mut bridge, rpc, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let signer = LocalKeySigner::new(&[0x35; 32]);
    let payer = signer.address();
    let mut first = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap()
        .record;
    first.status = "burned".into();
    let mut second = first.clone();
    second.return_id = hex(&[0x33; 32]);
    bridge.journal.put_return(&first).unwrap();
    bridge.journal.put_return(&second).unwrap();
    let request = TxRequest {
        chain_id: bridge.cfg.chain_id,
        nonce: 1,
        gas: 100_000,
        max_fee_per_gas: 10u8.into(),
        max_priority_fee_per_gas: 1u8.into(),
        to: bridge.cfg.vault,
        value: BigUint::default(),
        data: vec![0x11; 68],
    };
    let packet_fee = 1_000_000;
    let total = undec64(first.extra["recovery"]["totalFee"].as_str().unwrap()).unwrap();
    bridge
        .erc20_return_recovery
        .as_mut()
        .unwrap()
        .limits
        .fee_budget = packet_fee.into();
    let err = bridge
        .sign_redeem_tx(&first, &signer, &request)
        .unwrap_err();
    assert!(
        err.to_string().contains("authorized payer fee budget"),
        "{err}"
    );
    bridge
        .erc20_return_recovery
        .as_mut()
        .unwrap()
        .limits
        .fee_budget = total.into();
    rpc.balance.store(total + packet_fee, Ordering::SeqCst);
    let err = bridge
        .sign_redeem_tx(&first, &signer, &request)
        .unwrap_err();
    assert!(err.to_string().contains("free payer balance"), "{err}");
    rpc.balance.store(total * 3, Ordering::SeqCst);
    bridge
        .erc20_return_recovery
        .as_mut()
        .unwrap()
        .limits
        .max_fee_per_gas = 20u8.into();
    let err = bridge
        .sign_redeem_tx(&first, &signer, &request)
        .unwrap_err();
    assert!(
        err.to_string().contains("authorized payer fee budget"),
        "{err}"
    );
    bridge
        .erc20_return_recovery
        .as_mut()
        .unwrap()
        .limits
        .fee_budget = (total * 2).into();
    bridge.sign_redeem_tx(&second, &signer, &request).unwrap();
    assert!(bridge
        .check_erc20_payer(&first, &payer, false, None)
        .err()
        .unwrap()
        .to_string()
        .contains("outstanding ERC20 return"));
}

#[test]
fn contested_ordinary_signing_checks_fallback_signed_bytes_and_per_packet_fee() {
    use super::super::evm::LocalKeySigner;
    let (mut bridge, _, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let signer = LocalKeySigner::new(&[0x35; 32]);
    let payer = signer.address();
    let mut first = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap()
        .record;
    first.status = "burned".into();
    let mut second = first.clone();
    second.return_id = hex(&[0x34; 32]);
    bridge.journal.put_return(&first).unwrap();
    bridge.journal.put_return(&second).unwrap();
    let plan = &first.extra["recovery"];
    let cuts = recovery_run_cuts(plan).unwrap();
    let batch = plan["advanceGaps"].as_u64().unwrap() as usize;
    let advances = recovery_advance_calls(plan, cuts.len(), 1).unwrap();
    let saved = bridge.erc20_return_recovery.as_ref().unwrap();
    let mut limits = saved.limits.clone();
    limits.max_fee_per_gas = 127u8.into();
    let fits = |signed_bytes| {
        admitted_recovery_gas(
            &held,
            RecoverySuffix {
                cuts: &cuts,
                completed_runs: 0,
                batch,
                advances,
            },
            bridge.cfg.k,
            &*saved.calibration,
            &RecoveryLimits {
                signed_bytes,
                ..limits.clone()
            },
        )
        .is_ok()
    };
    let (mut low, mut high) = (0, limits.signed_bytes);
    assert!(fits(high));
    while high - low > 1 {
        let mid = (low + high) / 2;
        if fits(mid) {
            high = mid;
        } else {
            low = mid;
        }
    }
    let tx = TxRequest {
        chain_id: bridge.cfg.chain_id,
        nonce: 1,
        gas: 100_000,
        max_fee_per_gas: 10u8.into(),
        max_priority_fee_per_gas: 1u8.into(),
        to: bridge.cfg.vault,
        value: BigUint::default(),
        data: vec![0x11; 68],
    };
    limits.max_transaction_fee = Some(2_000_000u64.into());
    limits.max_fee_per_gas = tx.max_fee_per_gas.clone();
    assert!(quote_erc20_call(tx.data.len(), tx.gas, &limits).is_some());
    bridge.erc20_return_recovery.as_mut().unwrap().limits = limits.clone();
    let error = bridge.sign_redeem_tx(&first, &signer, &tx).unwrap_err();
    assert!(
        error.to_string().contains("outside the release limits"),
        "{error}"
    );
    limits.max_transaction_fee = None;
    limits.max_fee_per_gas = 254u8.into();
    limits.signed_bytes = high;
    bridge.erc20_return_recovery.as_mut().unwrap().limits = limits.clone();
    let error = bridge.sign_redeem_tx(&first, &signer, &tx).unwrap_err();
    assert!(
        error.to_string().contains("outside the release limits"),
        "{error}"
    );
    limits.signed_bytes += 1;
    bridge.erc20_return_recovery.as_mut().unwrap().limits = limits;
    bridge.sign_redeem_tx(&second, &signer, &tx).unwrap();
}

#[test]
fn ordinary_takeover_counts_indexed_run_fees_and_preserves_the_higher_replacement_fee() {
    use super::super::evm::LocalKeySigner;
    use super::super::recovery::RecoveryReceipt;
    let (mut bridge, rpc, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let signer = LocalKeySigner::new(&[0x35; 32]);
    let payer = signer.address();
    let chain = bridge.cfg.chain_id;
    let mut first = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap()
        .record;
    first.status = "burned".into();
    let mut other = first.clone();
    other.return_id = hex(&[0x33; 32]);
    bridge.journal.put_return(&other).unwrap();
    let tx = TxRequest {
        chain_id: chain,
        nonce: 1,
        gas: 100_000,
        max_fee_per_gas: 7u8.into(),
        max_priority_fee_per_gas: 1u8.into(),
        to: bridge.cfg.vault,
        value: BigUint::default(),
        data: vec![0x11; 68],
    };
    let raw = |signer: &LocalKeySigner, gas, chain_id, nonce| {
        sign_tx(
            signer,
            &TxRequest {
                gas,
                chain_id,
                nonce,
                max_fee_per_gas: 10u8.into(),
                to: rpc.recovery,
                ..tx.clone()
            },
        )
        .unwrap()
        .raw
    };
    bridge
        .journal
        .prepare_payer_signing(&first, chain, &payer)
        .unwrap();
    for packet in [
        raw(&signer, 2, chain, 0),
        raw(&signer, 1, chain, 0),
        raw(&signer, 200, chain, tx.nonce),
    ] {
        bridge.journal.retain_payer_send(&first, &packet).unwrap();
    }
    first
        .extra
        .insert("executionPayer".into(), json!(hex(&payer)));
    bridge.journal.put_return(&first).unwrap();
    let hash = he(&[&super::super::header::encode_header(
        &super::super::rpc::header_of_json(&finalized_header()).unwrap(),
    )]);
    bridge
        .journal
        .index_recovery_progress(
            chain,
            &first,
            1,
            &RecoveryReceipt {
                encoded: vec![],
                block_number: 20,
                block_hash: hash,
                tx_index: 0,
                log_index: 0,
            },
            None,
        )
        .unwrap();
    let plan = &first.extra["recovery"];
    let ordinary = &plan["ordinary"];
    let attempts = undec64(ordinary["attemptsBeforeFallback"].as_str().unwrap()).unwrap();
    let ordinary_gas = undec(ordinary["gas"].as_str().unwrap()).unwrap();
    let cuts = recovery_run_cuts(plan).unwrap();
    let advances = recovery_advance_calls(plan, cuts.len(), attempts).unwrap();
    let batch = plan["advanceGaps"].as_u64().unwrap() as usize;
    let saved = bridge.erc20_return_recovery.as_ref().unwrap();
    let limits = RecoveryLimits {
        max_fee_per_gas: 7u8.into(),
        ..saved.limits.clone()
    };
    let suffix = admitted_recovery_gas(
        &held,
        RecoverySuffix {
            cuts: &cuts,
            completed_runs: 1,
            batch,
            advances,
        },
        bridge.cfg.k,
        &*saved.calibration,
        &limits,
    )
    .unwrap();
    let gas: BigUint = suffix.run.into_iter().fold(
        BigUint::from(advances) * suffix.advance + suffix.settle,
        |sum, gas| sum + gas,
    );
    let allowance = &ordinary_gas * &limits.max_fee_per_gas;
    let needed =
        (gas.max(ordinary_gas.clone()) + &ordinary_gas * attempts) * &limits.max_fee_per_gas;
    rpc.finalized_nonce.store(1, Ordering::SeqCst);
    bridge.erc20_return_recovery.as_mut().unwrap().limits = RecoveryLimits {
        fee_budget: needed.clone(),
        ..limits
    };
    let fees = bridge
        .journal
        .payer_fees(&first, chain, &payer, tx.nonce)
        .unwrap();
    assert_eq!(fees.prior, 20u8.into());
    assert_eq!(fees.at_nonce, 2000u16.into());
    bridge
        .erc20_return_recovery
        .as_mut()
        .unwrap()
        .limits
        .fee_budget = &needed + 19u8;
    let error = bridge.sign_redeem_tx(&first, &signer, &tx).unwrap_err();
    assert!(
        error.to_string().contains("authorized payer fee budget"),
        "{error}"
    );
    let old_gas = undec64(ordinary["gas"].as_str().unwrap()).unwrap();
    let old = raw(&signer, old_gas, chain, tx.nonce);
    bridge.journal.retain_payer_send(&first, &old).unwrap();
    let old_fee = BigUint::from(old_gas) * 10u8;
    let required = &needed - allowance + &old_fee;
    bridge
        .erc20_return_recovery
        .as_mut()
        .unwrap()
        .limits
        .fee_budget = needed + 20u8;
    let error = bridge.sign_redeem_tx(&first, &signer, &tx).unwrap_err();
    assert!(
        error.to_string().contains("authorized payer fee budget"),
        "{error}"
    );
    bridge
        .erc20_return_recovery
        .as_mut()
        .unwrap()
        .limits
        .fee_budget = &required + 19u8;
    let error = bridge.sign_redeem_tx(&first, &signer, &tx).unwrap_err();
    assert!(
        error.to_string().contains("authorized payer fee budget"),
        "{error}"
    );
    bridge
        .erc20_return_recovery
        .as_mut()
        .unwrap()
        .limits
        .fee_budget = required + 20u8;
    bridge.sign_redeem_tx(&first, &signer, &tx).unwrap();
    let fees = bridge
        .journal
        .payer_fees(&first, chain, &payer, tx.nonce)
        .unwrap();
    assert_eq!(fees.prior, 20u8.into());
    assert_eq!(fees.at_nonce, old_fee);
}

#[test]
fn finalized_runs_keep_ordinary_retries_reserved_until_their_nonces_are_used() {
    use super::super::evm::LocalKeySigner;
    use super::super::recovery::RecoveryReceipt;
    let (bridge, rpc, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let signer = LocalKeySigner::new(&[0x35; 32]);
    let payer = signer.address();
    let chain_id = bridge.cfg.chain_id;
    let mut a = bridge
        .plan_return(&held, &[0xab; 20], &payer, Some(0))
        .unwrap()
        .record;
    a.status = "burned".into();
    a.extra["recovery"]["calls"] = json!("10");
    a.extra["recovery"]["totalFee"] = json!("120");
    a.extra["recovery"]["envelope"]["maxFeePerGas"] = json!("1");
    a.extra["recovery"]["ordinary"]["attemptsBeforeFallback"] = json!("2");
    a.extra["recovery"]["ordinary"]["maxFeePerGas"] = json!("1");
    a.extra["recovery"]["ordinary"]["gas"] = json!("10");
    let mut b = a.clone();
    b.return_id = hex(&[0xab; 32]);
    let journal = &bridge.journal;
    journal.put_return(&a).unwrap();
    journal.put_return(&b).unwrap();
    journal
        .index_recovery_progress(
            chain_id,
            &b,
            1,
            &RecoveryReceipt {
                encoded: vec![],
                block_number: 20,
                block_hash: [0xfe; 32],
                tx_index: 0,
                log_index: 0,
            },
            Some(80u64.into()),
        )
        .unwrap();
    let commitments = || {
        journal
            .check_payer(
                chain_id,
                &payer,
                &a.return_id,
                false,
                &PayerCheck {
                    drain: true,
                    finalized_nonce: Some(&|| bridge.evm.nonce(&payer, "finalized")),
                    finalized_block: Some(&|n, hash| Ok(n == 20 && *hash == [0xfe; 32])),
                    ..Default::default()
                },
            )
            .unwrap()
    };
    assert_eq!(commitments().calls, 9);
    assert_eq!(commitments().fees, 100u64.into());
    let tx = sign_tx(
        &signer,
        &TxRequest {
            chain_id,
            nonce: 1,
            gas: 10,
            max_fee_per_gas: 1u8.into(),
            max_priority_fee_per_gas: 0u8.into(),
            to: bridge.cfg.vault,
            value: BigUint::default(),
            data: vec![0x11; 68],
        },
    )
    .unwrap();
    journal.prepare_payer_signing(&b, chain_id, &payer).unwrap();
    journal.retain_payer_send(&b, &tx.raw).unwrap();
    b.sends.push(bridge.send_record(&tx));
    journal.put_return(&b).unwrap();
    rpc.finalized_nonce.store(2, Ordering::SeqCst);
    assert_eq!(commitments().calls, 8);
    assert_eq!(commitments().fees, 90u64.into());
}

#[test]
fn a_second_ordinary_payer_cannot_sign_or_rebroadcast_an_already_bound_return() {
    use super::super::evm::LocalKeySigner;
    struct MustNotSign([u8; 20]);
    impl EvmSigner for MustNotSign {
        fn address(&self) -> [u8; 20] {
            self.0
        }
        fn sign_transaction(&self, _: &TxRequest) -> core::result::Result<Vec<u8>, String> {
            panic!("a second payer must never reach its signer");
        }
    }

    let (bridge, rpc, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let first = LocalKeySigner::new(&[0x35; 32]);
    let other = LocalKeySigner::new(&[0x36; 32]);
    let signer = MustNotSign(other.address());
    let chain = bridge.cfg.chain_id;
    let mut record = bridge
        .plan_return(&held, &[0xab; 20], &first.address(), Some(0))
        .unwrap()
        .record;
    record.status = "burned".into();
    record.eta = Some(hex(&[0x37; 32]));
    record
        .extra
        .insert("executionPayer".into(), json!(hex(&first.address())));
    let request = TxRequest {
        chain_id: chain,
        nonce: 0,
        gas: 100_000,
        max_fee_per_gas: 10u8.into(),
        max_priority_fee_per_gas: 1u8.into(),
        to: rpc.recovery,
        value: BigUint::default(),
        data: vec![0x11; 68],
    };
    let recovery = sign_tx(&first, &request).unwrap();
    let mut unsigned = record.clone();
    unsigned.extra.remove("executionPayer");
    bridge
        .journal
        .prepare_payer_signing(&unsigned, chain, &first.address())
        .unwrap();
    bridge
        .journal
        .retain_payer_send(&record, &recovery.raw)
        .unwrap();
    rpc.finalized_nonce.store(1, Ordering::SeqCst);
    assert_eq!(
        bridge
            .journal
            .payer_fees(&record, chain, &first.address(), 1)
            .unwrap()
            .prior,
        1_000_000u64.into()
    );
    let second_packet = sign_tx(&other, &request).unwrap();
    let return_id = unhex_n::<32>(&record.return_id).unwrap();
    let next = TxRequest {
        nonce: 1,
        to: bridge.cfg.vault,
        ..request.clone()
    };

    for recorded in [true, false] {
        if !recorded {
            record.extra.remove("executionPayer");
            let ordinary = sign_tx(&first, &next).unwrap();
            bridge
                .journal
                .retain_payer_send(&record, &ordinary.raw)
                .unwrap();
            record.sends.push(bridge.send_record(&ordinary));
        }
        bridge.journal.put_return(&record).unwrap();
        let mut before_binding = record.clone();
        before_binding.extra.remove("executionPayer");
        before_binding.sends.clear();
        for error in [
            bridge
                .journal
                .prepare_payer_signing(&before_binding, chain, &other.address())
                .unwrap_err(),
            bridge.submit_redeem(&return_id, &signer).unwrap_err(),
            bridge.sign_redeem_tx(&record, &signer, &next).unwrap_err(),
            bridge
                .journal
                .prepare_payer_broadcast(&record, chain, &second_packet.raw)
                .unwrap_err(),
        ] {
            assert!(
                error.to_string().contains("bound to execution payer"),
                "{error}"
            );
        }
    }
    assert!(bridge
        .journal
        .store
        .get(&format!(
            "nb2/payer/v1/{chain}/{}",
            to_hex(&other.address())
        ))
        .unwrap()
        .is_none());
}

#[test]
fn ordinary_signer_cannot_return_altered_nonce_or_bid_after_the_fence() {
    use super::super::evm::LocalKeySigner;
    struct AlteringSigner<'a> {
        key: &'a LocalKeySigner,
        journal: &'a Journal,
    }
    impl EvmSigner for AlteringSigner<'_> {
        fn address(&self) -> [u8; 20] {
            self.key.address()
        }
        fn sign_transaction(&self, request: &TxRequest) -> core::result::Result<Vec<u8>, String> {
            let slot = format!(
                "nb2/payer/v1/{}/{}",
                request.chain_id,
                to_hex(&self.address())
            );
            assert_eq!(request.nonce, 1);
            assert_eq!(request.max_fee_per_gas, 10u8.into());
            assert!(self
                .journal
                .store
                .get(&slot)
                .unwrap()
                .unwrap()
                .ends_with("#nonce:1"));
            let mut altered = request.clone();
            altered.nonce += 1;
            altered.max_fee_per_gas *= 2u8;
            self.key.sign_transaction(&altered)
        }
    }
    let (bridge, _, held) = return_bridge(
        6_000_000,
        1_000_000_000_000,
        1_000_000_000_000,
        Arc::new(NeverSign),
    );
    let key = LocalKeySigner::new(&[0x35; 32]);
    let mut rec = bridge
        .plan_return(&held, &[0xab; 20], &key.address(), Some(0))
        .unwrap()
        .record;
    rec.status = "burned".into();
    bridge.journal.put_return(&rec).unwrap();
    let request = TxRequest {
        chain_id: bridge.cfg.chain_id,
        nonce: 1,
        gas: 100_000,
        max_fee_per_gas: 10u8.into(),
        max_priority_fee_per_gas: 1u8.into(),
        to: bridge.cfg.vault,
        value: BigUint::default(),
        data: vec![0x11; 68],
    };
    let signer = AlteringSigner {
        key: &key,
        journal: &bridge.journal,
    };
    let error = bridge.sign_redeem_tx(&rec, &signer, &request).unwrap_err();
    assert!(error.to_string().contains("another transaction"), "{error}");
    assert!(bridge
        .journal
        .store
        .list("nb2/payer-sends/v1/")
        .unwrap()
        .is_empty());
    let exact = bridge.sign_redeem_tx(&rec, &key, &request).unwrap();
    assert_eq!(exact.request, request);
}

#[test]
fn two_refusals_release_the_claim_only_after_both_attempts_finish() {
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
    let retry_fence = retry
        .check_payer(
            chain,
            &payer,
            id,
            true,
            &PayerCheck {
                fence: Some("retry"),
                ..Default::default()
            },
        )
        .unwrap()
        .fence
        .unwrap();
    bridge
        .journal
        .cancel_unsigned_return(id, claimed.fence.take().unwrap())
        .unwrap();
    assert!(retry
        .check_return_payer(chain, &payer, &hex(&[0xde; 32]), true)
        .is_err());
    retry.cancel_unsigned_return(id, retry_fence).unwrap();
    assert_eq!(retry.ret(id).unwrap().unwrap().status, "planned");
    retry
        .check_return_payer(chain, &payer, &hex(&[0xde; 32]), true)
        .unwrap();
}
