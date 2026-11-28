use super::*;
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
}

impl JsonRpc for Chain {
    fn call(&self, method: &str, params: Value) -> core::result::Result<Value, RpcError> {
        Ok(match method {
            "eth_getCode" => json!(if params[0] == hex0x(&self.recovery) {
                "0x6000"
            } else {
                "0x"
            }),
            "eth_getBlockByNumber" => json!({"baseFeePerGas": "0x3"}),
            "eth_getBalance" => json!(format!("0x{:x}", self.balance.load(Ordering::SeqCst))),
            "eth_getTransactionCount" => json!("0x1"),
            "eth_maxPriorityFeePerGas" => json!("0x1"),
            "eth_call" if params[0]["data"] == hex0x(&sel("state()")) => json!(hex0x(&[0; 192])),
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
        err.to_string().contains("insufficient recovery fee budget"),
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
        (24_000_000, 150_000_000, "InsufficientFunds"),
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
                .contains("insufficient recovery fee budget"),
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
            .contains("insufficient recovery fee budget"),
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
