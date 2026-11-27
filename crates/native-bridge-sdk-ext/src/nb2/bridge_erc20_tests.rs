use super::*;
use crate::nb2::{
    recovery::{RecoveryAuthority, RecoverySession},
    recovery_cost::{RecoveryCalibrationRange, RecoveryEntry, RecoveryShape},
    rpc::RpcError,
    util::{from_hex, hex0x},
};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../protocol/vectors/");

struct Chain {
    recovery: [u8; 20],
    blocked: AtomicBool,
    probes: AtomicUsize,
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
            "eth_getBalance" => json!("0x100000000000"),
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

struct OrdinaryGas;
impl GasModel for OrdinaryGas {
    fn name(&self) -> &str {
        "ordinary fixture"
    }
    fn redeem_gas_limit(&self, _: &RedeemShape<'_>) -> Option<u64> {
        Some(1_000_000)
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

#[test]
fn return_requires_affordable_continuation_and_reprobes_before_signing() {
    let (doc, gamma, trust) = vector();
    let cfg = decode_config(&gamma, &build_params(Build::Production)).unwrap();
    let recovery = arr(&bytes(&doc["Assets"][0]["Recovery"]));
    let rpc = Arc::new(Chain {
        recovery,
        blocked: AtomicBool::new(false),
        probes: AtomicUsize::new(0),
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
        Arc::new(NeverSign),
        Arc::new(MemoryJournalStore::default()),
        &[1; 32],
    );
    options.require_backup = Some(false);
    options.gas = Some(Box::new(OrdinaryGas));
    options.unsafe_test_trust = true;
    options.erc20_return_recovery = Some(continuation(&cfg, recovery, 8_000_000));
    let mut bridge = NativeBridgeV2::construct(options).unwrap();
    let held = bytes(&doc["Assets"][0]["Held"]);
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

    bridge.erc20_return_recovery = Some(continuation(&cfg, recovery, 1_000_000_000_000));
    let plan = bridge
        .plan_return(&held, &recipient, &payer, Some(0))
        .unwrap();
    rpc.blocked.store(true, Ordering::SeqCst);
    let err = bridge.burn(&plan.return_id, &NeverSign).err().unwrap();
    assert_eq!(err.reason(), Some(WalletReason::RecipientRefused));
    assert_eq!(rpc.probes.load(Ordering::SeqCst), 3);
    assert_eq!(
        bridge.return_record(&plan.return_id).unwrap().status,
        "planned"
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
