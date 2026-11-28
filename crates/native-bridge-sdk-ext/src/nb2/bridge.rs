//! The native bridge v2 wallet API (`bridge.ts`, NB2-07 bft-core#1103; this port NB2-08 bft-core#1104). A wallet bridges
//! native UCT with these calls and does not handle segments, gap proofs or receipt tries itself:
//!
//! ```text
//!   EVM -> Unicity   plan_deposit, submit_deposit, collect_deposit_proof, mint
//!   circulation      transfer, split (ordinary token operations; nothing touches the EVM)
//!   Unicity -> EVM   plan_return, burn, build_redeem, submit_redeem, reconcile
//! ```
//!
//! Network adapters fetch bytes; pure functions verify them offline. Every step is journaled BEFORE the step it enables, so a
//! crash at any point resumes by calling the same function again with the same identifier:
//! - the deposit secret's intent and its backed-up high-water mark exist before value is sent (`submit_deposit` refuses
//!   otherwise);
//! - every signed EVM transaction is journaled before it is broadcast, and an earlier send is reconciled before any new one;
//! - a burn's exact request is journaled before it is certified, and the certified burn before success is reported;
//! - the burn index comes from a verified SegmentSealed receipt (or is zero), never from a plain RPC number outside test
//!   deployments.
//!
//! The calls are synchronous; calls on the same journal record are serialized within the process, and the store's
//! compare-and-swap serializes them across processes.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use num_bigint::BigUint;
use serde_json::json;

use super::abi::{
    address_word, classify_redeem_error, decode_asset_deposit, decode_paid, decode_revert,
    deposit_calldata, deposit_erc20_calldata, redeem_calldata, redeem_calldata_length, sel,
    DecodedError, ErrArg, RedeemAction,
};
use super::cbor::{c_arr, c_bytes};
use super::config::{build_params, config_identities, decode_config, domain_of, Build, Config};
use super::crypto::{he, hmac_sha256, hu, parse_key};
use super::deposit::{
    decode_receipt_backing, deposit_intent_secret, deposit_salt, encode_receipt_backing,
    first_owner_of, rho_of, topic, verify_deposit_evidence, verify_receipt_log, ReceiptBacking,
};
use super::errors::{fail_d, refuse, Error, Nb2Error, Result, Rule, WalletReason};
use super::evm::{decode_signed_tx, sign_tx, DecodedTx, EvmSigner, SignedTx, TxRequest};
use super::gas::{
    create_address, redeem_tx_framing, DeploymentCode, GasModel, MeasuredGasModel, RedeemShape,
};
use super::journal::*;
use super::recovery::RecoveryDeployment;
use super::recovery_cost::{
    preflight_recovery_with_signing_bounds, quote_erc20_call, AdmissionContext, Erc20OrdinaryBound,
    Erc20SigningBounds, RecoveryBacklog, RecoveryCalibration, RecoveryLimits,
};
use super::rpc::{Estimate, EvmReader, JsonRpc, ReceiptJson, SendError};
use super::rules::{
    burn_index, capacity_exceeded, capacity_preflight, check_state_read, topic_index,
    verify_seal_receipt, Preflight, PreflightResult, SealReceipt,
};
use super::segment::{build_history, check_segment_log, genesis_head, Segment};
use super::token::{
    burn_predicate, decode_token, signature_predicate, value_data, LineageLevel, MintTx, Token,
    TransferTx, PRED_SIGNATURE,
};
use super::tokenops::{
    append_transfer, certify_checked, child_mint, fresh_mask, mint_request, split_plan,
    token_of_child, token_of_mint, transfer_request, Aggregator, OwnerSigner, SplitOutput,
};
use super::trust::{bind_trust, TrustInput};
use super::util::{arr, be_int, cat, u256, u256_64};
use super::verify::{
    decode_evidence, encode_return_data, evidence_of, verify_held, verify_part, verify_split,
    ReturnData, Verdict,
};

/// The deployment manifest pins outside D (section 4.3).
#[derive(Debug, Clone)]
pub struct DeploymentPins {
    pub gamma: Vec<u8>,
    pub build: Build,
    pub vault_runtime_code_hash: [u8; 32],
    pub max_encoded_tx_bytes: u64,
    pub user_gas_limit: u64,
    pub gas_reserve: u64,
    pub return_reserve_segments: u64,
    pub deployment_block: u64,
    pub state_read_only: bool,
    /// The plausibility bound of a stateReadOnly index read (default 64).
    pub max_jump: Option<u64>,
    /// The chain's native gas schedules (CERT_BATCH_V2, the RSMT membership, SHA-256), as the default gas model names them.
    pub native_gas_schedule: Option<String>,
    pub erc20: Option<Erc20ActivationPins>,
}

/// Factory, CREATE2 templates and the certified activation locator.
#[derive(Debug, Clone)]
pub struct Erc20ActivationPins {
    pub factory: [u8; 20],
    pub factory_runtime_hash: [u8; 32],
    pub vault_initcode_hash: [u8; 32],
    pub recovery_initcode_hash: [u8; 32],
    pub activation_tx: [u8; 32],
    pub funding_qualified: bool,
}

fn erc20_create2(factory: &[u8; 20], salt: &[u8; 32], initcode: &[u8; 32]) -> [u8; 20] {
    arr(&he(&[&[0xff], factory, salt, initcode])[12..])
}

type Callback<A, R> = Box<dyn Fn(A) -> R + Send + Sync>;

/// Authenticated continuation calibration, qualified backlog bounds and payer policy.
pub struct Erc20ReturnRecovery {
    pub deployment: RecoveryDeployment,
    pub calibration: Box<dyn RecoveryCalibration + Send + Sync>,
    /// The bridge reads the signed start and the current segment for each quote.
    pub backlog: RecoveryBacklog,
    /// Upper limits for the payer. The bridge further caps them by the deployment and live balance.
    pub limits: RecoveryLimits,
    pub signing_bounds: Erc20SigningBounds,
    /// Maximum mined ordinary attempts before fallback and maximum time per attempt in milliseconds.
    pub ordinary_attempts: Option<(u64, u64)>,
}

/// The bridge's inputs.
const IMPORTED_TIP_PROFILE_HASH: &str =
    "0x63158aeb61ee273e6c319c19f1663ec3910d6b5403b7affc90dec31813514e7e";
const ERC20_PROFILE_HASH: &str =
    "0xf05dd5c3563165d73c1cf91a5af79ec7afcaa77edc90061c6e7666bf53a8b0b6";
pub const TESTNET_TRUST_FRESHNESS_MS: u64 = 15 * 60 * 1000;
pub const PRODUCTION_TRUST_FRESHNESS_MS: u64 = 7 * 24 * 60 * 60 * 1000;

pub struct BridgeOptions {
    pub pins: DeploymentPins,
    pub trust: TrustInput,
    pub rpc: Arc<dyn JsonRpc>,
    pub aggregator: Arc<dyn Aggregator + Send + Sync>,
    pub journal: Arc<dyn JournalStore>,
    /// k_w: the 32-byte wallet bridge key, derived from the wallet seed (see [`derive_bridge_key`]).
    pub bridge_key: Zeroizing<Vec<u8>>,
    /// The wallet-versioned name of the k_w derivation, recorded in the journal.
    pub key_scheme: Option<String>,
    /// Back up the intent high-water mark with the seed (section 12.1). Required unless `require_backup` is false.
    pub backup: Option<Callback<IntentsRecord, Result<()>>>,
    /// Default true: a deposit is not sent before its intent's high-water mark is backed up.
    pub require_backup: Option<bool>,
    pub gas: Option<Box<dyn GasModel>>,
    pub erc20_return_recovery: Option<Erc20ReturnRecovery>,
    /// Blocks the head must advance, after a send's nonce is seen used without its success receipt, before the send counts as dead.
    pub dead_after_blocks: Option<u64>,
    /// A seal receipt older than this many blocks gives a warning (default 7,200).
    pub max_seal_age_blocks: Option<u64>,
    /// Extend the trust-base history when a certificate's epoch is not held yet: given the current input, return the extended
    /// one. A seal receipt or a token refused with the retryable NoEntryForEpoch is retried once after it.
    pub refresh_trust: Option<Callback<TrustInput, Result<TrustInput>>>,
    /// Required successful UTB sync interval for wallet integrations.
    pub trust_freshness_ms: Option<u64>,
    /// Only for local fixtures that use an old verifier or have no live UTB source.
    pub unsafe_test_trust: bool,
    /// Receipt polling.
    pub receipt_timeout_ms: Option<u64>,
    pub poll_ms: Option<u64>,
    pub sleep: Option<Callback<u64, ()>>,
    pub now: Option<Box<dyn Fn() -> u64 + Send + Sync>>,
}

impl BridgeOptions {
    /// Options with every optional field unset.
    pub fn new(
        pins: DeploymentPins,
        trust: TrustInput,
        rpc: Arc<dyn JsonRpc>,
        aggregator: Arc<dyn Aggregator + Send + Sync>,
        journal: Arc<dyn JournalStore>,
        bridge_key: &[u8],
    ) -> Self {
        BridgeOptions {
            pins,
            trust,
            rpc,
            aggregator,
            journal,
            bridge_key: Zeroizing::new(bridge_key.to_vec()),
            key_scheme: None,
            backup: None,
            require_backup: None,
            gas: None,
            erc20_return_recovery: None,
            dead_after_blocks: None,
            max_seal_age_blocks: None,
            refresh_trust: None,
            trust_freshness_ms: None,
            unsafe_test_trust: false,
            receipt_timeout_ms: None,
            poll_ms: None,
            sleep: None,
            now: None,
        }
    }
}

fn redeem_refusal(e: DecodedError, detail: Option<String>) -> Nb2Error {
    Nb2Error {
        detail,
        args: e
            .args
            .into_iter()
            .map(|arg| match arg {
                ErrArg::Int(v) => v.to_string(),
                ErrArg::Word(w) => hex(&w),
            })
            .collect(),
        inner: e.inner.map(|inner| Box::new(redeem_refusal(*inner, None))),
        ..Nb2Error::new(e.rule)
    }
}

pub const DEFAULT_KEY_SCHEME: &str = "nb2-hmac-sha256-v1";

/// k_w = HMAC-SHA256(key = seed, "unicity-nb2/wallet-bridge-key/v1"): the [`DEFAULT_KEY_SCHEME`] derivation.
pub fn derive_bridge_key(seed: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hmac_sha256(seed, b"unicity-nb2/wallet-bridge-key/v1"))
}

#[derive(Debug, Clone)]
pub struct DepositPlan {
    pub intent: u64,
    pub amount: BigUint,
    pub rho: [u8; 32],
    pub first_owner: Vec<u8>,
    pub calldata: Vec<u8>,
    pub record: DepositRecord,
}

/// Either a plan or its intent number.
pub enum PlanRef<'a> {
    Plan(&'a DepositPlan),
    Intent(u64),
}

impl<'a> From<&'a DepositPlan> for PlanRef<'a> {
    fn from(p: &'a DepositPlan) -> Self {
        PlanRef::Plan(p)
    }
}

impl From<u64> for PlanRef<'_> {
    fn from(i: u64) -> Self {
        PlanRef::Intent(i)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deposited {
    pub tx_hash: Vec<u8>,
    pub deposit_number: u64,
    pub block_number: u64,
}

#[derive(Debug, Clone)]
pub struct ReturnPlan {
    pub return_id: [u8; 32],
    pub amount: BigUint,
    pub recipient: [u8; 20],
    pub a: u64,
    /// The endpoint estimate and the history already owed from a.
    pub c_obs: u64,
    pub p_now: u64,
    /// Ordinary proof capacity and margin. Both are zero on a continuation-only plan.
    pub p_max: u64,
    pub margin_segments: i128,
    /// The ordinary gas quote, or zero when continuation is the only admitted route.
    pub gas_limit: u64,
    /// The bounded continuation is the available route at the observed state.
    pub continuation_only: bool,
    pub warnings: Vec<String>,
    pub record: ReturnRecord,
}

#[derive(Debug, Clone)]
pub struct Burned {
    pub burned: Vec<u8>,
    pub eta: [u8; 32],
    pub verdict: Verdict,
}

#[derive(Debug, Clone)]
pub struct RedeemTx {
    pub return_id: [u8; 32],
    pub calldata: Vec<u8>,
    pub gas_limit: u64,
    pub p: u64,
    pub endpoint: u64,
    pub history: Vec<u8>,
    pub eta: [u8; 32],
    pub claimed_start: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileResult {
    Paid {
        tx_hash: Vec<u8>,
        block_number: u64,
    },
    Pending {
        tx_hash: Vec<u8>,
    },
    NotPaid {
        last_failure: Option<(Vec<u8>, RedeemAction, Option<DecodedError>)>,
    },
}

impl ReconcileResult {
    pub fn state(&self) -> &'static str {
        match self {
            ReconcileResult::Paid { .. } => "paid",
            ReconcileResult::Pending { .. } => "pending",
            ReconcileResult::NotPaid { .. } => "not-paid",
        }
    }
}

/// A held token's verified facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldToken {
    pub token_id: [u8; 32],
    pub amount: BigUint,
    pub owner: Option<Vec<u8>>,
    pub state: [u8; 32],
}

#[derive(Debug, Clone)]
struct SeenLog {
    tx: Vec<u8>,
    block_number: u64,
    n: u64,
    amount: BigUint,
    first_owner: Vec<u8>,
}

enum Landed {
    Replace(Box<DecodedTx>, bool),
    Receipt(Box<ReceiptJson>),
    Pending,
    None,
}

fn status_is_ok(r: &ReceiptJson) -> bool {
    r.success()
}

/// The bridge for one pinned deployment.
pub struct NativeBridgeV2 {
    pub cfg: Config,
    pub domain: [u8; 32],
    pub journal: Journal,
    pub evm: EvmReader<dyn JsonRpc>,
    pub gas: Box<dyn GasModel>,
    key_scheme: String,
    /// k_w, kept out of the options.
    kw: Zeroizing<[u8; 32]>,
    pins: DeploymentPins,
    trust: RwLock<TrustInput>,
    aggregator: Arc<dyn Aggregator + Send + Sync>,
    backup: Option<Callback<IntentsRecord, Result<()>>>,
    require_backup: bool,
    dead_after_blocks: u64,
    max_seal_age_blocks: u64,
    refresh_trust: Option<Callback<TrustInput, Result<TrustInput>>>,
    trust_freshness_ms: Option<u64>,
    trust_sync: Mutex<Option<Instant>>,
    receipt_timeout_ms: u64,
    poll_ms: u64,
    sleep: Option<Callback<u64, ()>>,
    now: Option<Box<dyn Fn() -> u64 + Send + Sync>>,
    /// In-process serialization per journal key (with the store's compare-and-swap across processes).
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Whether the gas model applies to this deployment's verifier (checked once, from its runtime code).
    gas_fits: Mutex<Option<bool>>,
    erc20_return_recovery: Option<Erc20ReturnRecovery>,
    unsafe_test_trust: bool,
}

impl NativeBridgeV2 {
    fn construct(o: BridgeOptions) -> Result<Self> {
        let cfg = decode_config(&o.pins.gamma, &build_params(o.pins.build))?;
        let domain = domain_of(&o.pins.gamma);
        bind_trust(&o.trust, &cfg)?;
        let profile = if cfg.erc20.is_some() {
            ERC20_PROFILE_HASH
        } else {
            IMPORTED_TIP_PROFILE_HASH
        };
        if !o.unsafe_test_trust && hex(&cfg.semantic_profile_hash) != profile {
            return refuse(
                WalletReason::BadDeployment,
                "the wallet requires the paired imported-tip NB2 semantic profile",
            );
        }
        if o.trust_freshness_ms == Some(0) {
            return refuse(
                WalletReason::BadInput,
                "the UTB freshness window must be positive",
            );
        }
        if o.bridge_key.len() != 32 {
            return refuse(WalletReason::BadInput, "k_w is 32 bytes");
        }
        let require_backup = o.require_backup != Some(false);
        if require_backup && o.backup.is_none() {
            return refuse(WalletReason::BadInput, "a backup of the intent high-water mark is required (or require_backup: false on a test deployment)");
        }
        Ok(NativeBridgeV2 {
            journal: Journal::new(o.journal, domain),
            evm: EvmReader::new(o.rpc),
            gas: o.gas.unwrap_or_else(|| Box::new(MeasuredGasModel)),
            key_scheme: o.key_scheme.unwrap_or_else(|| DEFAULT_KEY_SCHEME.into()),
            kw: Zeroizing::new(arr(&o.bridge_key)),
            trust: RwLock::new(o.trust),
            aggregator: o.aggregator,
            backup: o.backup,
            require_backup,
            dead_after_blocks: o.dead_after_blocks.unwrap_or(6),
            max_seal_age_blocks: o.max_seal_age_blocks.unwrap_or(7_200),
            refresh_trust: o.refresh_trust,
            trust_freshness_ms: o
                .trust_freshness_ms
                .or((!o.unsafe_test_trust).then_some(PRODUCTION_TRUST_FRESHNESS_MS)),
            trust_sync: Mutex::new(None),
            receipt_timeout_ms: o.receipt_timeout_ms.unwrap_or(60_000),
            poll_ms: o.poll_ms.unwrap_or(1_000),
            sleep: o.sleep,
            now: o.now,
            locks: Mutex::new(HashMap::new()),
            gas_fits: Mutex::new(None),
            erc20_return_recovery: o.erc20_return_recovery,
            unsafe_test_trust: o.unsafe_test_trust,
            pins: o.pins,
            cfg,
            domain,
        })
    }

    /// Open the bridge for one pinned deployment. The installation check (section 4.3): the chain ID, the vault's exact Γ through
    /// config() and its runtime code hash. These come from the RPC, which the wallet trusts here exactly as far as its manifest source.
    pub fn open(o: BridgeOptions) -> Result<Self> {
        Self::open_checked(o, true)
    }

    pub fn open_checked(o: BridgeOptions, check: bool) -> Result<Self> {
        let b = Self::construct(o)?;
        if check || b.cfg.erc20.is_some() {
            if b.evm.chain_id()? != b.cfg.chain_id {
                return refuse(WalletReason::BadDeployment, "the RPC serves another chain");
            }
            if b.evm.vault_config(&b.cfg.vault)? != b.pins.gamma {
                return refuse(
                    WalletReason::BadDeployment,
                    "the vault's config() is not the pinned Γ",
                );
            }
            if he(&[&b.evm.code(&b.cfg.vault)?]) != b.pins.vault_runtime_code_hash {
                return refuse(
                    WalletReason::BadDeployment,
                    "the vault runtime code hash is not the pinned one",
                );
            }
        }
        if b.cfg.erc20.is_some() {
            b.verify_erc20_activation()?;
        }
        Ok(b)
    }

    fn verify_erc20_activation(&self) -> Result<()> {
        let (Some(e), Some(pins)) = (&self.cfg.erc20, &self.pins.erc20) else {
            return refuse(
                WalletReason::BadDeployment,
                "the ERC20 activation pins are missing",
            );
        };
        let (asset, ty, aid) = config_identities(&self.cfg);
        let token = address_word(&e.token);
        let vault = erc20_create2(&pins.factory, &token, &pins.vault_initcode_hash);
        let recovery = erc20_create2(&pins.factory, &he(&[&token]), &pins.recovery_initcode_hash);
        let Some((_, genesis)) = self.evm.header_by_number(0)? else {
            return refuse(
                WalletReason::BadDeployment,
                "the execution genesis is unavailable",
            );
        };
        let rc = self.evm.code(&recovery)?;
        let call = |sig| self.evm.call(&pins.factory, &sel(sig), None);
        let gamma = self.evm.call(
            &pins.factory,
            &cat(&[&sel("config(address)"), &token]),
            None,
        )?;
        if (asset, ty, aid) != (self.cfg.asset, self.cfg.ty, self.cfg.aid)
            || vault != self.cfg.vault
            || genesis != self.cfg.execution_genesis
            || rc.is_empty()
            || he(&[&self.evm.code(&pins.factory)?]) != pins.factory_runtime_hash
            || he(&[&self.evm.code(&self.cfg.verifier)?]) != self.cfg.verifier_code_hash
            || super::abi::decode_bytes_return(&gamma).as_deref()
                != Some(self.pins.gamma.as_slice())
            || call("VAULT_INITCODE_HASH()")? != pins.vault_initcode_hash
            || call("RECOVERY_INITCODE_HASH()")? != pins.recovery_initcode_hash
            || call("GENERATION()")? != e.generation
            || call("PINS()")? != e.pins
        {
            return refuse(
                WalletReason::BadDeployment,
                "the ERC20 chain or factory graph differs from the release",
            );
        }
        let topics = [
            topic::erc20_activated(),
            token,
            address_word(&vault),
            address_word(&recovery),
        ];
        let data = cat(&[
            &self.domain,
            &self.pins.vault_runtime_code_hash,
            &he(&[&rc]),
        ]);
        let proof = self.evm.matching_mint_receipt_proof(
            &pins.activation_tx,
            &pins.factory,
            &topics,
            Some(&data),
            true,
        )?;
        let log = self.retrying_trust(|t| {
            super::deposit::verify_receipt_log_at(&self.cfg, t, &proof.proof, &pins.factory)
        })?;
        if log.header.number_u64() != self.pins.deployment_block
            || !log
                .topics
                .iter()
                .map(Vec::as_slice)
                .eq(topics.iter().map(|t| t.as_slice()))
            || log.data != data
        {
            return refuse(
                WalletReason::BadDeployment,
                "the certified ERC20 activation differs from the deployment",
            );
        }
        Ok(())
    }

    pub fn pins(&self) -> &DeploymentPins {
        &self.pins
    }

    fn sleep_ms(&self, ms: u64) {
        match &self.sleep {
            Some(f) => f(ms),
            None => std::thread::sleep(std::time::Duration::from_millis(ms)),
        }
    }

    fn now_ms(&self) -> u64 {
        match &self.now {
            Some(f) => f(),
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
        }
    }

    /// Run `f` after every earlier call holding `key` in this instance has finished.
    fn locked<T>(&self, key: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let m = self
            .locks
            .lock()
            .expect("locks")
            .entry(key.to_string())
            .or_default()
            .clone();
        let _g = m.lock().unwrap_or_else(|p| p.into_inner());
        f()
    }

    fn trust(&self) -> TrustInput {
        self.trust.read().expect("trust").clone()
    }

    fn trust_stale(&self, sync: Option<Instant>) -> bool {
        self.trust_freshness_ms.is_some_and(|window| {
            !sync.is_some_and(|start| start.elapsed() < Duration::from_millis(window))
        })
    }

    fn sync_trust(&self, seen: Option<&TrustInput>) -> Result<()> {
        let mut sync = self.trust_sync.lock().expect("trust sync");
        let held = self.trust();
        if let Some(snapshot) = seen {
            if snapshot != &held {
                return Ok(());
            }
        } else if !self.trust_stale(*sync) {
            return Ok(());
        }
        let Some(refresh) = &self.refresh_trust else {
            return refuse(
                WalletReason::TrustInput,
                "a successful UTB sync is required",
            );
        };
        // Failure may leave a verified prefix persisted by the source. Suspend until it can install.
        *sync = None;
        let start = Instant::now();
        let offered = refresh(held.clone())?;
        bind_trust(&offered, &self.cfg)?;
        let old = held.history().entries();
        let incoming = offered.history().entries();
        if incoming.len() < old.len()
            || old
                .iter()
                .zip(incoming)
                .any(|(a, b)| a.entry_id() != b.entry_id())
        {
            return refuse(
                WalletReason::TrustInput,
                "authority refresh does not extend the installed history",
            );
        }
        let key = format!("{}trust-sync", self.journal.prefix);
        let previous = self.journal.store.get(&key)?;
        if let Some(text) = &previous {
            let saved: serde_json::Value = serde_json::from_str(text).map_err(|_| {
                super::errors::wallet_err(
                    WalletReason::TrustInput,
                    "invalid durable UTB checkpoint",
                )
            })?;
            let entry = saved["tipEpoch"]
                .as_str()
                .and_then(|epoch| epoch.parse::<u64>().ok())
                .and_then(|epoch| offered.history().get(epoch));
            if saved["domain"] != hex(&self.domain)
                || saved["genesis"] != hex(&offered.id())
                || !entry.is_some_and(|entry| saved["tipId"] == hex(&entry.entry_id()))
            {
                return refuse(
                    WalletReason::TrustInput,
                    "authority refresh does not extend the durable history",
                );
            }
        }
        if self.trust_freshness_ms.is_some() || previous.is_some() {
            let end = offered.history().latest();
            let Ok(time) = SystemTime::now().duration_since(UNIX_EPOCH) else {
                return refuse(WalletReason::TrustInput, "the UTB sync clock is uncertain");
            };
            let record = json!({
                "domain": hex(&self.domain), "genesis": hex(&offered.id()),
                "tipEpoch": end.epoch.to_string(), "tipId": hex(&end.entry_id()),
                "syncedAt": time.as_millis() as u64,
            });
            if !self
                .journal
                .store
                .put_if(&key, previous.as_deref(), &record.to_string())?
            {
                return refuse(WalletReason::JournalConflict, "the UTB sync record changed");
            }
            *sync = Some(start);
        }
        *self.trust.write().expect("trust") = offered;
        Ok(())
    }

    fn retrying_trust<T>(&self, f: impl Fn(&TrustInput) -> Result<T>) -> Result<T> {
        self.sync_trust(None)?;
        let mut refreshed = false;
        loop {
            let held = {
                let sync = self.trust_sync.lock().expect("trust sync");
                if self.trust_stale(*sync) {
                    return refuse(
                        WalletReason::TrustSyncRequired,
                        "the UTB freshness window elapsed before verification",
                    );
                }
                self.trust()
            };
            let result = f(&held);
            {
                let sync = self.trust_sync.lock().expect("trust sync");
                if self.trust() != held {
                    continue;
                }
                if result.is_ok() && self.trust_stale(*sync) {
                    return refuse(
                        WalletReason::TrustSyncRequired,
                        "the UTB freshness window elapsed before publication",
                    );
                }
            }
            if !refreshed
                && self.refresh_trust.is_some()
                && result
                    .as_ref()
                    .is_err_and(|e| e.rule().is_some_and(|rule| rule.retryable()))
            {
                self.sync_trust(Some(&held))?;
                refreshed = true;
                continue;
            }
            return result;
        }
    }

    // ==== EVM -> Unicity ==================================================================================================

    /// r for intent i (never stored unless the wallet asks: it is derivable from k_w and i).
    pub fn secret_of(&self, i: u64) -> [u8; 32] {
        deposit_intent_secret(&self.kw[..], &self.domain, i)
    }

    fn intents_record(&self, next: u64) -> IntentsRecord {
        IntentsRecord {
            base: self.journal.base("intents"),
            key_scheme: self.key_scheme.clone(),
            next: dec(next),
            extra: Default::default(),
        }
    }

    /// Plan a deposit of `amount` to the Unicity owner `owner_key` (compressed key): allocate a never-used intent i, derive r and
    /// rho, and journal the plan with the new high-water mark, which is handed to the backup. Serialized: two plans never share
    /// an intent.
    pub fn plan_deposit(&self, amount: &BigUint, owner_key: &[u8]) -> Result<DepositPlan> {
        self.plan_asset_deposit(amount, owner_key, None)
    }

    pub fn plan_erc20_deposit(
        &self,
        amount: &BigUint,
        min_credit: &BigUint,
        owner_key: &[u8],
    ) -> Result<DepositPlan> {
        self.plan_asset_deposit(amount, owner_key, Some(min_credit))
    }

    fn plan_asset_deposit(
        &self,
        amount: &BigUint,
        owner_key: &[u8],
        min_credit: Option<&BigUint>,
    ) -> Result<DepositPlan> {
        if amount.bits() == 0 || amount.bits() > 256 {
            return refuse(
                WalletReason::BadInput,
                "a deposit amount is a positive uint256",
            );
        }
        if match (&self.cfg.erc20, min_credit) {
            (Some(_), Some(min)) => min.bits() == 0 || min > amount,
            (None, None) => false,
            _ => true,
        } {
            return refuse(
                WalletReason::BadInput,
                "ERC20 deposits require 0 < minCredit <= requested",
            );
        }
        parse_key(owner_key)?;
        self.locked("intents", || {
            let cur = self.journal.intents_for_update()?;
            if let Some(c) = &cur {
                if c.key_scheme != self.key_scheme {
                    return refuse(
                        WalletReason::BadInput,
                        format!("the journal's intents use key scheme {}", c.key_scheme),
                    );
                }
            }
            let i = match &cur {
                None => 0,
                Some(c) => undec64(&c.next)?,
            };
            let mut intents = cur.unwrap_or_else(|| self.intents_record(0));
            let Some(next) = i.checked_add(1) else {
                return refuse(WalletReason::BadInput, "the intent counter is exhausted");
            };
            intents.next = dec(next);
            intents.key_scheme = self.key_scheme.clone();
            // the counter moves first, by compare-and-swap: a crash wastes intent i, another writer makes this one fail; i is never reused
            self.journal.put_intents(&intents)?;
            let r = self.secret_of(i);
            let rho = rho_of(&self.domain, &r);
            let first_owner = first_owner_of(owner_key);
            let mut rec = DepositRecord {
                base: self.journal.base("deposit"),
                key_scheme: self.key_scheme.clone(),
                intent: dec(i),
                amount: dec(amount),
                erc20_token: self.cfg.erc20.as_ref().map(|e| hex(&e.token)),
                requested: min_credit.map(|_| dec(amount)),
                min_credit: min_credit.map(dec),
                approval_sends: Vec::new(),
                owner_key: hex(owner_key),
                first_owner: hex(&first_owner),
                rho: hex(&rho),
                status: "planned".into(),
                backed_up: false,
                sends: Vec::new(),
                deposit_tx: None,
                block_number: None,
                deposit_number: None,
                receipt_proof: None,
                reason: None,
                token: None,
                secret: None,
                planned_block: Some(dec(self.evm.block_number()?)),
                seen_deposits: None,
                extra: Default::default(),
            };
            self.journal.put_deposit(&rec)?;
            if let Some(b) = &self.backup {
                b(intents.clone())?;
                rec.backed_up = true;
                self.journal.put_deposit(&rec)?;
            }
            Ok(DepositPlan {
                intent: i,
                amount: amount.clone(),
                rho,
                calldata: self.deposit_data(&rec)?,
                first_owner,
                record: rec,
            })
        })
    }

    /// Record that the wallet backed up the high-water mark covering this intent by other means.
    pub fn mark_backed_up(&self, intent: u64) -> Result<()> {
        self.locked(&format!("deposit/{intent}"), || {
            let mut rec = self.deposit_record(intent)?;
            rec.backed_up = true;
            self.journal.put_deposit(&rec)
        })
    }

    fn deposit_record(&self, i: u64) -> Result<DepositRecord> {
        match self.journal.deposit_for_update(i)? {
            Some(r) => Ok(r),
            None => refuse(
                WalletReason::JournalNotPersisted,
                format!("no journal entry for intent {i}"),
            ),
        }
    }

    /// Every Deposited event of the vault carrying `rho`, from block `from`, in chain order.
    fn deposits_with_rho(&self, rho: &[u8], from: u64) -> Result<Vec<SeenLog>> {
        let mut out = Vec::new();
        let top = self.evm.block_number()?;
        for l in self.evm.logs(
            &self.cfg.vault,
            &json!([hex(&self.deposit_topic())]),
            from,
            top,
        )? {
            if let Some(d) = decode_asset_deposit(&l.topics, &l.data, self.erc20_token()) {
                if l.address == self.cfg.vault && d.domain == self.domain && d.rho == rho {
                    out.push(SeenLog {
                        tx: l.transaction_hash.clone(),
                        block_number: l.block_number,
                        n: d.n,
                        amount: d.amount,
                        first_owner: d.first_owner,
                    });
                }
            }
        }
        Ok(out)
    }

    fn planned_from(&self, rec: &DepositRecord) -> Result<u64> {
        match &rec.planned_block {
            None => Ok(self.pins.deployment_block),
            Some(b) => undec64(b),
        }
    }

    /// Send the deposit. Refuses a plan whose journal entry is not persisted exactly as planned, or whose high-water mark is not
    /// backed up. Earlier sends of the intent are reconciled first, and before the first send the vault's events are searched for
    /// a deposit that already carries this rho (another device on the same backup), so a retry never deposits twice.
    pub fn submit_deposit<'a>(
        &self,
        plan: impl Into<PlanRef<'a>>,
        signer: &dyn EvmSigner,
    ) -> Result<Deposited> {
        let plan = plan.into();
        let i = match &plan {
            PlanRef::Plan(p) => p.intent,
            PlanRef::Intent(i) => *i,
        };
        let submit = || {
            self.locked(&format!("deposit/{i}"), || {
            let Some(mut rec) = self.journal.deposit_for_update(i)? else {
                return refuse(WalletReason::JournalNotPersisted, format!("intent {i} is not in the journal: plan it first"));
            };
            if let PlanRef::Plan(p) = &plan {
                if rec.rho != hex(&p.rho) || rec.requested.as_ref().unwrap_or(&rec.amount) != &dec(&p.amount) {
                    return refuse(WalletReason::JournalNotPersisted, "the journal entry is not this plan");
                }
            }
            if rho_of(&self.domain, &self.secret_of(i)).as_slice() != unhex(&rec.rho)? {
                return refuse(WalletReason::JournalNotPersisted, "the journal entry does not derive from this wallet key");
            }
            let hw = self.journal.intents_for_update()?;
            match &hw {
                Some(h) if undec64(&h.next)? > i => {}
                _ => return refuse(WalletReason::JournalNotPersisted, "the intent high-water mark does not cover this intent"),
            }
            if self.require_backup && !rec.backed_up {
                return refuse(WalletReason::JournalNotPersisted, "the high-water mark covering this intent is not backed up");
            }
            if rec.status != "planned" && rec.status != "submitted" {
                return Ok(Deposited {
                    tx_hash: unhex(rec.deposit_tx.as_deref().unwrap_or(""))?,
                    deposit_number: undec64(rec.deposit_number.as_deref().unwrap_or(""))?,
                    block_number: undec64(rec.block_number.as_deref().unwrap_or(""))?,
                });
            }
            let mut sends = rec.sends.clone();
            let landed = self.landed_send(&mut sends, None)?;
            if sends != rec.sends {
                rec.sends = sends;
                self.journal.put_deposit(&rec)?;
            }
            match landed {
                Landed::Pending | Landed::Replace(..) => return refuse(WalletReason::Unconfirmed, "an earlier deposit transaction may still be pending: wait or reconcile, never resend blindly"),
                Landed::Receipt(r) => return self.record_deposit(&mut rec, &r),
                Landed::None => {}
            }
            if rec.sends.is_empty() {
                let seen = self.deposits_with_rho(&unhex(&rec.rho)?, self.planned_from(&rec)?)?;
                if !seen.is_empty() {
                    return self.adopt_deposits(&mut rec, &seen);
                }
            }
            let data = self.deposit_data(&rec)?;
            let value = if let Some(erc20) = &self.cfg.erc20 {
                self.require_erc20_qualification()?;
                self.approve_deposit(&mut rec, signer, &erc20.token)?;
                BigUint::default()
            } else {
                undec(&rec.amount)?
            };
            let gas_limit = if self.gas_applies()? {
                self.gas.deposit_gas_limit()
            } else {
                match self.evm.estimate_gas(&signer.address(), &self.cfg.vault, &data, &value)? {
                    Estimate::Gas(gas) => gas.checked_add(gas.div_ceil(5)).unwrap_or_default(),
                    Estimate::Revert { message, .. } => return refuse(WalletReason::Reverted, format!("deposit simulation refused: {message}")),
                }
            };
            if gas_limit == 0 || gas_limit > self.pins.user_gas_limit {
                return fail_d(Rule::CapacityExceeded, "deposit gas exceeds the user limit");
            }
            let tx = self.signed(signer, &self.cfg.vault, &data, value, gas_limit)?;
            rec.sends.push(self.send_record(&tx));
            rec.status = "submitted".into();
            self.journal.put_deposit(&rec)?;
            let Some(r) = self.broadcast_and_wait(&tx)? else {
                return refuse(WalletReason::Unconfirmed, format!("deposit {} has no receipt yet: call submit_deposit again to reconcile", hex(&tx.hash)));
            };
            if !status_is_ok(&r) {
                return refuse(WalletReason::Reverted, format!("deposit {} reverted", hex(&tx.hash)));
            }
            self.record_deposit(&mut rec, &r)
        })
        };
        if self.cfg.erc20.is_some() {
            self.locked(
                &format!("erc20-approval/{}", hex(&signer.address())),
                submit,
            )
        } else {
            submit()
        }
    }

    fn require_erc20_qualification(&self) -> Result<()> {
        if self.cfg.erc20.is_some()
            && !self.unsafe_test_trust
            && (!self
                .pins
                .erc20
                .as_ref()
                .is_some_and(|e| e.funding_qualified)
                || self.pins.return_reserve_segments < 64)
        {
            return fail_d(
                Rule::CapacityPreflight,
                "the ERC20 deployment is awaiting real-value qualification",
            );
        }
        Ok(())
    }

    fn erc20_token(&self) -> Option<&[u8; 20]> {
        self.cfg.erc20.as_ref().map(|e| &e.token)
    }

    fn deposit_topic(&self) -> [u8; 32] {
        super::deposit::deposit_topic(self.erc20_token())
    }

    fn credit_bounds(&self, rec: &DepositRecord) -> Result<(BigUint, BigUint)> {
        let (Some(requested), Some(min), Some(token)) =
            (&rec.requested, &rec.min_credit, self.erc20_token())
        else {
            return refuse(
                WalletReason::JournalNotPersisted,
                "the ERC20 intent is missing its token or credit bounds",
            );
        };
        let (requested, min) = (undec(requested)?, undec(min)?);
        if rec.erc20_token.as_deref() != Some(hex(token).as_str())
            || requested.bits() > 256
            || min.bits() == 0
            || min > requested
        {
            return refuse(
                WalletReason::JournalNotPersisted,
                "the ERC20 intent has invalid credit bounds",
            );
        }
        Ok((requested, min))
    }

    fn deposit_data(&self, rec: &DepositRecord) -> Result<Vec<u8>> {
        let owner = unhex(&rec.first_owner)?;
        let rho = unhex(&rec.rho)?;
        if self.cfg.erc20.is_some() {
            let (requested, min) = self.credit_bounds(rec)?;
            Ok(deposit_erc20_calldata(&requested, &min, &owner, &rho))
        } else {
            Ok(deposit_calldata(&owner, &rho))
        }
    }

    fn approve_deposit(
        &self,
        rec: &mut DepositRecord,
        signer: &dyn EvmSigner,
        token: &[u8; 20],
    ) -> Result<()> {
        let (requested, _) = self.credit_bounds(rec)?;
        let address = signer.address();
        let spender = address_word(&self.cfg.vault);
        let allowance = || -> Result<BigUint> {
            let raw = self.evm.call(
                token,
                &cat(&[
                    &sel("allowance(address,address)"),
                    &address_word(&address),
                    &spender,
                ]),
                None,
            )?;
            if raw.len() != 32 {
                return refuse(
                    WalletReason::ProviderFault,
                    "invalid ERC20 allowance response",
                );
            }
            Ok(be_int(&raw))
        };
        if !rec.approval_sends.is_empty() {
            let mut sends = rec.approval_sends.clone();
            let landed = self.landed_send(&mut sends, None)?;
            if matches!(landed, Landed::Pending | Landed::Replace(..)) {
                rec.approval_sends = sends;
                self.journal.put_deposit(rec)?;
                return refuse(
                    WalletReason::Unconfirmed,
                    "an earlier token approval is pending",
                );
            }
            rec.approval_sends.clear();
            self.journal.put_deposit(rec)?;
        }
        let current = allowance()?;
        if current == requested {
            return Ok(());
        }
        let zero = BigUint::default();
        let targets = [&zero, &requested];
        for target in &targets[usize::from(current == zero)..] {
            let data = cat(&[
                &sel("approve(address,uint256)"),
                &spender,
                &super::util::u256(target),
            ]);
            let gas = match self.evm.estimate_gas(&address, token, &data, &zero)? {
                Estimate::Gas(value) => value.checked_add(value.div_ceil(5)).unwrap_or_default(),
                Estimate::Revert { message, .. } => {
                    return refuse(
                        WalletReason::Reverted,
                        format!("token approval simulation refused: {message}"),
                    )
                }
            };
            if gas == 0 || gas > self.pins.user_gas_limit {
                return fail_d(
                    Rule::CapacityExceeded,
                    "approval gas exceeds the user limit",
                );
            }
            let tx = self.signed(signer, token, &data, zero.clone(), gas)?;
            rec.approval_sends = vec![self.send_record(&tx)];
            self.journal.put_deposit(rec)?;
            let Some(receipt) = self.broadcast_and_wait(&tx)? else {
                return refuse(
                    WalletReason::Unconfirmed,
                    "token approval has no receipt yet",
                );
            };
            if !status_is_ok(&receipt) || &allowance()? != *target {
                return refuse(
                    WalletReason::Reverted,
                    "token approval did not set the exact allowance",
                );
            }
            rec.approval_sends.clear();
            self.journal.put_deposit(rec)?;
        }
        Ok(())
    }

    fn record_deposit(&self, rec: &mut DepositRecord, r: &ReceiptJson) -> Result<Deposited> {
        let want_topic = hex(&self.deposit_topic());
        let l = r.logs.iter().find(|x| {
            unhex(&x.address.to_lowercase()).is_ok_and(|a| a == self.cfg.vault)
                && x.topics
                    .first()
                    .is_some_and(|topic| topic.to_lowercase() == want_topic)
        });
        let Some(l) = l else {
            return refuse(
                WalletReason::ProviderFault,
                "the deposit receipt has no Deposited log",
            );
        };
        let topics = l
            .topics
            .iter()
            .map(|x| unhex(&x.to_lowercase()))
            .collect::<Result<Vec<_>>>()?;
        let d = decode_asset_deposit(&topics, &unhex(&l.data.to_lowercase())?, self.erc20_token());
        let Some(d) = d.filter(|d| unhex(&rec.rho).is_ok_and(|rho| d.rho == rho)) else {
            return refuse(
                WalletReason::ProviderFault,
                "the Deposited log is not this intent's",
            );
        };
        // the event's D is this deployment's: the same rho under another vault configuration at this address is not this deposit
        if d.domain != self.domain {
            return refuse(
                WalletReason::ProviderFault,
                "the Deposited log carries another deployment's domain D",
            );
        }
        if self.cfg.erc20.is_some() {
            let (requested, min) = self.credit_bounds(rec)?;
            if d.amount < min || d.amount > requested || hex(&d.first_owner) != rec.first_owner {
                return refuse(
                    WalletReason::ProviderFault,
                    "the ERC20 lock differs from the journaled credit bounds",
                );
            }
            rec.amount = dec(&d.amount);
        }
        let block = super::rpc::qty64(&json!(r.block_number), "blockNumber")?;
        rec.deposit_tx = Some(r.transaction_hash.to_lowercase());
        rec.block_number = Some(dec(block));
        rec.deposit_number = Some(dec(d.n));
        rec.status = "deposited".into();
        // merge, never replace: the record's own deposit, what was journaled before, and every deposit carrying this rho on chain
        let mut entries = vec![SeenDeposit {
            tx: rec.deposit_tx.clone().expect("set"),
            deposit_number: dec(d.n),
            block_number: dec(block),
            amount: dec(&d.amount),
            first_owner: hex(&d.first_owner),
            token: None,
            extra: Default::default(),
        }];
        for x in self.deposits_with_rho(&unhex(&rec.rho)?, self.planned_from(rec)?)? {
            entries.push(seen_entry(&x));
        }
        merge_seen(rec, entries)?;
        self.journal.put_deposit(rec)?;
        Ok(Deposited {
            tx_hash: unhex(rec.deposit_tx.as_deref().expect("set"))?,
            deposit_number: d.n,
            block_number: block,
        })
    }

    /// Journal the deposits found for a record's rho: the first becomes its own, every one is listed (each is a separate root token).
    fn adopt_deposits(&self, rec: &mut DepositRecord, seen: &[SeenLog]) -> Result<Deposited> {
        merge_seen(rec, seen.iter().map(seen_entry).collect())?;
        if rec.status == "planned" || rec.status == "submitted" {
            let first = if self.cfg.erc20.is_some() && rec.requested.is_some() {
                let (requested, min) = self.credit_bounds(rec)?;
                let Some(lock) = seen.iter().find(|s| {
                    s.amount >= min
                        && s.amount <= requested
                        && hex(&s.first_owner) == rec.first_owner
                }) else {
                    return refuse(
                        WalletReason::ProviderFault,
                        "no ERC20 lock matches the journaled credit bounds and owner",
                    );
                };
                lock
            } else {
                &seen[0]
            };
            rec.deposit_tx = Some(hex(&first.tx));
            rec.block_number = Some(dec(first.block_number));
            rec.deposit_number = Some(dec(first.n));
            rec.amount = dec(&first.amount);
            rec.first_owner = hex(&first.first_owner);
            rec.owner_key = hex(&first.first_owner[9..]);
            rec.status = "deposited".into();
        }
        self.journal.put_deposit(rec)?;
        Ok(Deposited {
            tx_hash: unhex(rec.deposit_tx.as_deref().unwrap_or(""))?,
            deposit_number: undec64(rec.deposit_number.as_deref().unwrap_or(""))?,
            block_number: undec64(rec.block_number.as_deref().unwrap_or(""))?,
        })
    }

    /// The receipt proof and J of deposit number `n` of intent `i`, verified offline.
    fn prove_deposit(
        &self,
        i: u64,
        tx: &[u8],
        n: u64,
        amount: &BigUint,
        first_owner: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut topics = vec![self.deposit_topic(), u256_64(n)];
        if let Some(e) = &self.cfg.erc20 {
            topics.push(address_word(&e.token));
        }
        let rp = self.evm.matching_mint_receipt_proof(
            tx,
            &self.cfg.vault,
            &topics,
            None,
            self.cfg.erc20.is_some()
                || hex(&self.cfg.semantic_profile_hash) == IMPORTED_TIP_PROFILE_HASH,
        )?;
        let j = ReceiptBacking {
            d: self.domain,
            n,
            r: self.secret_of(i),
            proof: rp.proof,
        };
        let ev =
            self.retrying_trust(|t| verify_deposit_evidence(&self.cfg, &self.domain, t, &j))?;
        if ev.v != *amount || ev.first_owner != first_owner {
            return refuse(
                WalletReason::ProviderFault,
                "the certified deposit is not the planned one",
            );
        }
        Ok((rp.encoded, encode_receipt_backing(&j)))
    }

    /// The ordinary mint with reason J, certified by the aggregator and verified offline.
    fn mint_with(&self, reason: &[u8], owner_key: &[u8], amount: &BigUint) -> Result<Vec<u8>> {
        let j = decode_receipt_backing(reason)?;
        let m = MintTx {
            network: self.cfg.network,
            recipient: signature_predicate(owner_key),
            salt: deposit_salt(&self.domain, j.n, &j.r).to_vec(),
            ty: self.cfg.ty.to_vec(),
            justification: Some(reason.to_vec()),
            data: Some(value_data(&self.cfg.aid, amount)),
            deadline: None,
        };
        let req = mint_request(&m)?;
        let token = token_of_mint(&req.tx, &certify_checked(&*self.aggregator, &req.cd)?);
        let decoded = decode_token(&token)?;
        let held = self.retrying_trust(|t| verify_held(&self.cfg, &self.domain, t, &decoded))?;
        if held.amount != *amount {
            return refuse(WalletReason::ProviderFault, "the minted amount differs");
        }
        Ok(token)
    }

    /// Fetch the certified header evidence and the block's receipts, build the receipt proof and verify it offline (section 6.2
    /// steps 1 to 7), then journal J. Retry `CompanionUnknown` after a round.
    pub fn collect_deposit_proof(&self, intent: u64) -> Result<(Vec<u8>, u64)> {
        self.locked(&format!("deposit/{intent}"), || {
            let mut rec = self.deposit_record(intent)?;
            if rec.status == "proven" || rec.status == "minted" {
                return Ok((
                    unhex(rec.reason.as_deref().unwrap_or(""))?,
                    undec64(rec.deposit_number.as_deref().unwrap_or(""))?,
                ));
            }
            if rec.status != "deposited" {
                return refuse(
                    WalletReason::NotPending,
                    format!(
                        "intent {intent} is {}: submit the deposit first",
                        rec.status
                    ),
                );
            }
            let n = undec64(rec.deposit_number.as_deref().unwrap_or(""))?;
            let (proof, reason) = self.prove_deposit(
                intent,
                &unhex(rec.deposit_tx.as_deref().unwrap_or(""))?,
                n,
                &undec(&rec.amount)?,
                &unhex(&rec.first_owner)?,
            )?;
            rec.receipt_proof = Some(hex(&proof));
            rec.reason = Some(hex(&reason));
            rec.status = "proven".into();
            self.journal.put_deposit(&rec)?;
            Ok((reason, n))
        })
    }

    /// The ordinary SDK mint with the receipt-backed reason J, certified by the aggregator and verified offline.
    pub fn mint(&self, intent: u64) -> Result<Vec<u8>> {
        self.locked(&format!("deposit/{intent}"), || {
            let mut rec = self.deposit_record(intent)?;
            if rec.status == "minted" {
                let token = unhex(rec.token.as_deref().unwrap_or(""))?;
                self.verify_token(&token)?;
                return Ok(token);
            }
            if rec.status != "proven" {
                return refuse(
                    WalletReason::NotPending,
                    format!(
                        "intent {intent} is {}: collect the deposit proof first",
                        rec.status
                    ),
                );
            }
            let token = self.mint_with(
                &unhex(rec.reason.as_deref().unwrap_or(""))?,
                &unhex(&rec.owner_key)?,
                &undec(&rec.amount)?,
            )?;
            rec.token = Some(hex(&token));
            rec.status = "minted".into();
            let own = rec.deposit_number.clone();
            if let Some(mine) = rec.seen_deposits.as_mut().and_then(|s| {
                s.iter_mut()
                    .find(|x| Some(&x.deposit_number) == own.as_ref())
            }) {
                mine.token = rec.token.clone();
            }
            self.journal.put_deposit(&rec)?;
            self.verify_token(&token)?;
            Ok(token)
        })
    }

    /// Mint a further deposit that carries this intent's rho (`seenDeposits`): a reused secret, or a second device. Its value is
    /// a separate root token with its own deposit number; nothing is lost.
    pub fn mint_extra_deposit(&self, intent: u64, deposit_number: u64) -> Result<Vec<u8>> {
        self.locked(&format!("deposit/{intent}"), || {
            let mut rec = self.deposit_record(intent)?;
            let want = dec(deposit_number);
            let Some(x) = rec
                .seen_deposits
                .as_ref()
                .and_then(|s| s.iter().find(|s| s.deposit_number == want))
                .cloned()
            else {
                return refuse(
                    WalletReason::NotPending,
                    format!("no deposit number {deposit_number} is journaled for intent {intent}"),
                );
            };
            if let Some(t) = &x.token {
                let token = unhex(t)?;
                self.verify_token(&token)?;
                return Ok(token);
            }
            // the entry's own first owner: another device may have deposited this rho to another key
            let first_owner = unhex(&x.first_owner)?;
            let amount = undec(&x.amount)?;
            let (_, reason) = self.prove_deposit(
                intent,
                &unhex(&x.tx)?,
                deposit_number,
                &amount,
                &first_owner,
            )?;
            let token = self.mint_with(&reason, &first_owner[9..], &amount)?;
            if let Some(e) = rec
                .seen_deposits
                .as_mut()
                .and_then(|s| s.iter_mut().find(|s| s.deposit_number == want))
            {
                e.token = Some(hex(&token));
            }
            self.journal.put_deposit(&rec)?;
            self.verify_token(&token)?;
            Ok(token)
        })
    }

    /// Recover deposits from the seed (k_w) and a backed-up high-water mark (section 5.1): every intent below `next` is matched by
    /// its rho against the vault's Deposited events. A match upgrades a planned or submitted record (or creates the record) to
    /// deposited; every deposit number seen for a rho is journaled. A look-ahead past the mark does not replace it.
    pub fn recover_deposits(&self, next: u64) -> Result<Vec<u64>> {
        self.locked("intents", || {
            let cur = self.journal.intents_for_update()?;
            let behind = match &cur {
                None => true,
                Some(c) => undec64(&c.next)? < next,
            };
            if behind {
                let mut r = cur.unwrap_or_else(|| self.intents_record(next));
                r.next = dec(next);
                r.key_scheme = self.key_scheme.clone();
                self.journal.put_intents(&r)?;
            }
            Ok(())
        })?;
        let mut want: HashMap<[u8; 32], u64> = HashMap::new();
        for i in 0..next {
            want.insert(rho_of(&self.domain, &self.secret_of(i)), i);
        }
        let mut by_intent: BTreeMap<u64, Vec<SeenLog>> = BTreeMap::new();
        let top = self.evm.block_number()?;
        for l in self.evm.logs(
            &self.cfg.vault,
            &json!([hex(&self.deposit_topic())]),
            self.pins.deployment_block,
            top,
        )? {
            let Some(d) = decode_asset_deposit(&l.topics, &l.data, self.erc20_token()) else {
                continue;
            };
            if l.address != self.cfg.vault || d.domain != self.domain {
                continue;
            }
            let Some(&i) = want.get(d.rho.as_slice()) else {
                continue;
            };
            by_intent.entry(i).or_default().push(SeenLog {
                tx: l.transaction_hash.clone(),
                block_number: l.block_number,
                n: d.n,
                amount: d.amount,
                first_owner: d.first_owner,
            });
        }
        let mut found = Vec::new();
        for (i, seen) in by_intent {
            self.locked(&format!("deposit/{i}"), || {
                let mut rec = match self.journal.deposit_for_update(i)? {
                    Some(r) => r,
                    None => DepositRecord {
                        base: self.journal.base("deposit"),
                        key_scheme: self.key_scheme.clone(),
                        intent: dec(i),
                        amount: dec(&seen[0].amount),
                        erc20_token: self.erc20_token().map(|token| hex(token)),
                        requested: None,
                        min_credit: None,
                        approval_sends: Vec::new(),
                        owner_key: hex(&seen[0].first_owner[9..]),
                        first_owner: hex(&seen[0].first_owner),
                        rho: hex(&rho_of(&self.domain, &self.secret_of(i))),
                        status: "planned".into(),
                        backed_up: true,
                        sends: Vec::new(),
                        deposit_tx: None,
                        block_number: None,
                        deposit_number: None,
                        receipt_proof: None,
                        reason: None,
                        token: None,
                        secret: None,
                        planned_block: None,
                        seen_deposits: None,
                        extra: Default::default(),
                    },
                };
                self.adopt_deposits(&mut rec, &seen).map(|_| ())
            })?;
            found.push(i);
        }
        Ok(found)
    }

    // ==== circulation =====================================================================================================

    /// Verify a held token fully offline (receipt origin, lineage, every certificate): its ID, amount, owner and spendable state.
    pub fn verify_token(&self, token: &[u8]) -> Result<HeldToken> {
        let t = decode_token(token)?;
        let h = self.retrying_trust(|tr| verify_held(&self.cfg, &self.domain, tr, &t))?;
        Ok(HeldToken {
            token_id: h.token_id,
            amount: h.amount,
            owner: (h.owner.ty == PRED_SIGNATURE).then_some(h.owner.params),
            state: h.state,
        })
    }

    /// Verify incoming lineage and bind its receipt to the paired RPC's canonical child.
    pub fn verify_received_token(&self, token: &[u8]) -> Result<HeldToken> {
        if self.cfg.erc20.is_none()
            && hex(&self.cfg.semantic_profile_hash) != IMPORTED_TIP_PROFILE_HASH
        {
            return self.verify_token(token);
        }
        let part = decode_token(token)?;
        let mint = &part.levels().next().expect("nonempty lineage").mint;
        let backing = decode_receipt_backing(mint.justification.as_deref().unwrap_or(&[]))?;
        self.retrying_trust(|trust| {
            let held = verify_held(&self.cfg, &self.domain, trust, &part)?;
            self.evm.check_mint_receipt(&backing.proof)?;
            Ok(HeldToken {
                token_id: held.token_id,
                amount: held.amount,
                owner: (held.owner.ty == PRED_SIGNATURE).then_some(held.owner.params),
                state: held.state,
            })
        })
    }

    /// An ordinary transfer to `to_key`; the result is verified before it is returned.
    pub fn transfer(
        &self,
        token: &[u8],
        owner: &dyn OwnerSigner,
        to_key: &[u8],
    ) -> Result<Vec<u8>> {
        self.verify_token(token)?;
        parse_key(to_key)?;
        let req = transfer_request(
            token,
            owner,
            &TransferTx {
                recipient: signature_predicate(to_key),
                mask: fresh_mask().to_vec(),
                data: None,
                deadline: None,
            },
        )?;
        let out = append_transfer(
            token,
            &req.tx,
            &certify_checked(&*self.aggregator, &req.cd)?,
        )?;
        self.verify_token(&out)?;
        Ok(out)
    }

    /// The default split ID: H_U(C(b("UNICITY_NB2_WALLET_SPLIT"), b(source))).
    pub fn default_split_id(token: &[u8]) -> [u8; 32] {
        hu(&[&c_arr(&[
            &c_bytes(b"UNICITY_NB2_WALLET_SPLIT"),
            &c_bytes(token),
        ])])
    }

    /// Split a held token into whole parts. The plan is journaled first, then
    /// the burn's exact request, the burned parent and each child as it is minted; a call with the same `split_id` resumes.
    pub fn split(
        &self,
        token: &[u8],
        owner: &dyn OwnerSigner,
        outputs: &[(Vec<u8>, BigUint)],
        split_id: Option<[u8; 32]>,
    ) -> Result<Vec<Vec<u8>>> {
        let id = split_id.unwrap_or_else(|| Self::default_split_id(token));
        self.locked(&format!("split/{}", hex(&id)), || {
            self.split_inner(token, owner, outputs, &id)
        })
    }

    fn split_inner(
        &self,
        token: &[u8],
        owner: &dyn OwnerSigner,
        outputs: &[(Vec<u8>, BigUint)],
        id: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>> {
        let mut rec = match self.journal.split_for_update(&hex(id))? {
            Some(r) => r,
            None => {
                let held = self.verify_token(token)?;
                if outputs.is_empty() {
                    return refuse(WalletReason::BadInput, "a split requires an output");
                }
                let mut sum = BigUint::default();
                for (k, a) in outputs {
                    if a.bits() == 0 {
                        return refuse(WalletReason::BadInput, "every output amount is positive");
                    }
                    parse_key(k)?;
                    sum += a;
                }
                if sum != held.amount {
                    return refuse(
                        WalletReason::BadInput,
                        format!("the outputs sum to {sum}, the token holds {}", held.amount),
                    );
                }
                let r = SplitRecord {
                    base: self.journal.base("split"),
                    split_id: hex(id),
                    source: hex(token),
                    outputs: outputs
                        .iter()
                        .map(|(k, a)| SplitOutputRecord {
                            owner_key: hex(k),
                            amount: dec(a),
                            salt: hex(&fresh_mask()),
                            token: None,
                            extra: Default::default(),
                        })
                        .collect(),
                    mask: hex(&fresh_mask()),
                    status: "planned".into(),
                    burn_tx: None,
                    burn_request: None,
                    burned: None,
                    extra: Default::default(),
                };
                self.journal.put_split(&r)?;
                r
            }
        };
        let parent = decode_token(&unhex(&rec.source)?)?;
        let outs = rec
            .outputs
            .iter()
            .map(|o| {
                Ok(SplitOutput {
                    owner_key: unhex(&o.owner_key)?,
                    amount: undec(&o.amount)?,
                    salt: unhex(&o.salt)?,
                    deadline: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let plan = split_plan(
            &parent,
            &outs,
            &self.cfg.ty,
            &self.cfg.aid,
            &unhex(&rec.mask)?,
            None,
        )?;
        if rec.status == "planned" {
            let req = transfer_request(&unhex(&rec.source)?, owner, &plan.burn)?;
            rec.burn_tx = Some(hex(&req.tx));
            rec.burn_request = Some(hex(&req.cd));
            rec.status = "burn-requested".into();
            self.journal.put_split(&rec)?;
        }
        let verify_burn = |burned: Vec<u8>| {
            let part = decode_token(&burned)?;
            let split = self.retrying_trust(|t| verify_split(&self.cfg, &self.domain, t, &part))?;
            if split.manifest != plan.tree.root() {
                return refuse(
                    WalletReason::ProviderFault,
                    "certified split manifest differs from the plan",
                );
            }
            Ok((burned, split))
        };
        let refresh_burn = |rec: &mut SplitRecord| -> Result<_> {
            let proof = certify_checked(
                &*self.aggregator,
                &unhex(rec.burn_request.as_deref().unwrap_or(""))?,
            )?;
            let verified = verify_burn(append_transfer(
                &unhex(&rec.source)?,
                &unhex(rec.burn_tx.as_deref().unwrap_or(""))?,
                &proof,
            )?)?;
            rec.burned = Some(hex(&verified.0));
            rec.status = "burned".into();
            self.journal.put_split(rec)?;
            Ok(verified)
        };
        let (burned, split) = if rec.status == "burn-requested" {
            refresh_burn(&mut rec)?
        } else {
            match verify_burn(unhex(rec.burned.as_deref().unwrap_or(""))?) {
                Ok(verified) => verified,
                // A journal from the previous verifier may have recorded an unchecked proof.
                Err(_)
                    if rec.status == "burned"
                        && rec.outputs.iter().all(|output| output.token.is_none()) =>
                {
                    refresh_burn(&mut rec)?
                }
                Err(error) => return Err(error),
            }
        };
        for k in 0..rec.outputs.len() {
            if rec.outputs[k].token.is_some() {
                continue;
            }
            let (m, allocation) = child_mint(&split.link, &plan.tree, &plan.children[k])?;
            let req = mint_request(&m)?;
            let child = token_of_child(
                &burned,
                &allocation,
                &req.tx,
                &certify_checked(&*self.aggregator, &req.cd)?,
            )?;
            let v = self.verify_token(&child)?;
            if v.amount != undec(&rec.outputs[k].amount)? {
                return refuse(
                    WalletReason::ProviderFault,
                    "a split child has another amount",
                );
            }
            rec.outputs[k].token = Some(hex(&child));
            self.journal.put_split(&rec)?;
        }
        rec.status = "minted".into();
        self.journal.put_split(&rec)?;
        rec.outputs
            .iter()
            .map(|o| {
                let token = unhex(o.token.as_deref().unwrap_or(""))?;
                self.verify_token(&token)?;
                Ok(token)
            })
            .collect()
    }

    // ==== Unicity -> EVM ==================================================================================================

    /// The newest verified seal receipt (section 12.2) and its container, or None when the vault has never sealed.
    pub fn newest_seal_receipt(&self) -> Result<Option<(SealReceipt, Vec<u8>)>> {
        let Some(log) = self
            .evm
            .newest_seal(&self.cfg.vault, self.pins.deployment_block)?
        else {
            return Ok(None);
        };
        let rp = self.evm.receipt_proof(
            &log.transaction_hash,
            &self.cfg.vault,
            &topic::segment_sealed(),
        )?;
        let receipt =
            self.retrying_trust(|t| verify_seal_receipt(&self.cfg, &self.domain, t, &rp.encoded))?;
        Ok(Some((receipt, rp.encoded)))
    }

    /// Plan the return of a whole held part to `recipient` on the EVM: verify its full provenance, pick the index from a verified
    /// seal receipt, and price the history owed from `a` plus the reserve under the transaction and payer limits.
    /// ERC20 requires a bounded continuation quote and can use it when ordinary capacity or funding is insufficient.
    /// Journals the plan. `state_read` is the stateReadOnly substitute (Some(verified index)).
    pub fn plan_return(
        &self,
        token: &[u8],
        recipient: &[u8],
        payer: &[u8],
        state_read: Option<u64>,
    ) -> Result<ReturnPlan> {
        let return_id = hu(&[token]);
        self.locked(&format!("return/{}", hex(&return_id)), || {
            let part = decode_token(token)?;
            let held = self.retrying_trust(|t| verify_held(&self.cfg, &self.domain, t, &part))?;
            if recipient.len() != 20 {
                return refuse(WalletReason::BadInput, "an EVM recipient is 20 bytes");
            }
            let recipient: [u8; 20] = arr(recipient);
            if recipient.iter().all(|&x| x == 0) || recipient == self.cfg.vault {
                return refuse(WalletReason::RecipientRefused, "the zero address and the vault are refused");
            }
            let mut warnings = Vec::new();
            if self.cfg.erc20.is_some() {
                self.preview_erc20_recipient(&recipient, &held.amount)?;
                warnings.push("The burn fixes this recipient. Permanent blocking or an outbound tax can strand the claim.".to_string());
            }
            if !self.evm.code(&recipient)?.is_empty() {
                warnings.push("the recipient is a contract: a payout it refuses strands the burn (simulation is not a guarantee)".to_string());
            }
            // the index
            let (a, start_head);
            let mut from_block = self.pins.deployment_block;
            let mut seal_receipt = None;
            if let Some(verified) = state_read {
                let st = self.evm.vault_state(&self.cfg.vault)?;
                check_state_read(self.pins.state_read_only, st.segment, verified, self.pins.max_jump.unwrap_or(64))?;
                a = st.segment;
                start_head = if a == 0 { genesis_head(&self.domain, self.cfg.k) } else { st.head };
            } else {
                let sr = self.newest_seal_receipt()?;
                (a, start_head) = burn_index(&self.cfg, &self.domain, sr.as_ref().map(|x| &x.0));
                if let Some((r, encoded)) = &sr {
                    from_block = r.block_number;
                    seal_receipt = Some(hex(encoded));
                    // availability, not safety: an old receipt anchors the burn low (more history to prove), never in the future
                    let age = self.evm.block_number()?.saturating_sub(r.block_number);
                    if age > self.max_seal_age_blocks {
                        warnings.push(format!("the newest seal receipt served is {age} blocks old: the provider may be hiding newer seals; the burn then owes more history"));
                    }
                }
            }
            let mut record = ReturnRecord {
                base: self.journal.base("return"),
                return_id: hex(&return_id),
                source: hex(token),
                amount: dec(&held.amount),
                recipient: hex(&recipient),
                a: dec(a),
                start_head: hex(&start_head),
                from_block: dec(from_block),
                seal_receipt,
                status: "planned".into(),
                burn_tx: None,
                burn_request: None,
                burned: None,
                eta: None,
                sends: Vec::new(),
                payer: Some(hex(payer)),
                first_send_block: None,
                paid: None,
                extra: Default::default(),
            };
            let (c_obs, ordinary) = self.admit_return(&mut record, token, &held.amount, &recipient, a, payer)?;
            if let Some(existing) = self.journal.ret_for_update(&hex(&return_id))? {
                if existing.status != "planned" {
                    return refuse(WalletReason::NotPending, format!("this part's return is already {}", existing.status));
                }
            }
            self.journal.put_return(&record)?;
            Ok(ReturnPlan {
                return_id,
                amount: held.amount,
                recipient,
                a,
                c_obs,
                p_now: c_obs - a,
                p_max: ordinary.map_or(0, |pf| pf.p_max),
                margin_segments: ordinary.map_or(0, |pf| pf.p_max as i128 - pf.need as i128),
                gas_limit: ordinary.map_or(0, |pf| pf.gas),
                continuation_only: ordinary.is_none(),
                warnings,
                record,
            })
        })
    }

    /// The section 12.5 preflight for burning `token` at index `a` to `recipient`, with a fresh endpoint estimate
    /// (c_obs = max(c, a); the state read is an availability assumption, not evidence) and the payer's funds for the worst-case
    /// gas limit.
    /// Whether the gas model applies to the deployment (`bridge.ts` gasApplies): a model that says which deployments it is calibrated
    /// for (the default does) is shown the verifier's runtime code (whose hash must be Γ's), the vault's (whose hash must be the
    /// manifest's), the code at the verifier's first CREATE address (its helper) and the manifest's native gas schedule; a model that
    /// does not say is used as supplied.
    fn gas_applies(&self) -> Result<bool> {
        if let Some(f) = *self.gas_fits.lock().unwrap() {
            return Ok(f);
        }
        let empty = DeploymentCode {
            gamma: &[],
            verifier: &[],
            k: 0,
            b: 0,
            qmax: &[],
            verifier_code: &[],
            helper_code: &[],
            vault_code: &[],
            native_gas_schedule: None,
        };
        if self.gas.supports_deployment(&empty).is_none() {
            return Ok(true);
        }
        let verifier_code = self.evm.code(&self.cfg.verifier)?;
        if he(&[&verifier_code]) != self.cfg.verifier_code_hash {
            return refuse(
                WalletReason::BadDeployment,
                "the verifier's runtime code is not the one Γ pins",
            );
        }
        let vault_code = self.evm.code(&self.cfg.vault)?;
        if he(&[&vault_code]) != self.pins.vault_runtime_code_hash {
            return refuse(
                WalletReason::BadDeployment,
                "the vault runtime code hash is not the pinned one",
            );
        }
        let helper_code = if self.cfg.erc20.is_some() {
            let address = self.evm.call(&self.cfg.verifier, &sel("LINEAGE()"), None)?;
            if address.len() != 32 || address[..12] != [0; 12] {
                return refuse(
                    WalletReason::BadDeployment,
                    "the ERC20 ordinary verifier returned an invalid lineage address",
                );
            }
            let code = self.evm.code(&address[12..])?;
            let expected = self
                .evm
                .call(&self.cfg.verifier, &sel("LINEAGE_HASH()"), None)?;
            if code.is_empty() || he(&[&code]).as_slice() != expected {
                return refuse(
                    WalletReason::BadDeployment,
                    "the ERC20 lineage helper runtime differs from the verifier binding",
                );
            }
            code
        } else {
            self.evm.code(&create_address(&self.cfg.verifier, 1))?
        };
        let qmax = self.cfg.qmax.to_bytes_be();
        let fits = self
            .gas
            .supports_deployment(&DeploymentCode {
                gamma: &self.pins.gamma,
                verifier: &self.cfg.verifier,
                k: self.cfg.k,
                b: self.cfg.b,
                qmax: &qmax,
                verifier_code: &verifier_code,
                helper_code: &helper_code,
                vault_code: &vault_code,
                native_gas_schedule: self.pins.native_gas_schedule.as_deref(),
            })
            .unwrap_or(true);
        *self.gas_fits.lock().unwrap() = Some(fits);
        Ok(fits)
    }

    fn preflight(
        &self,
        token: &[u8],
        amount: &BigUint,
        recipient: &[u8; 20],
        a: u64,
        payer: &[u8],
    ) -> Result<(u64, PreflightResult)> {
        if !self.gas_applies()? {
            return fail_d(
                Rule::CapacityPreflight,
                format!("the gas model {} is not calibrated for this deployment (its verifier, helper and vault code, its native gas schedule): supply a GasModel for it", self.gas.name()),
            );
        }
        let st = self.evm.vault_state(&self.cfg.vault)?;
        let c_obs = st.segment.max(a);
        let r = encode_return_data(&ReturnData {
            d: self.domain,
            asset: self.cfg.asset,
            recipient: *recipient,
            amount: amount.clone(),
            min_index: a,
        });
        let l_t = (evidence_of(token).len() + burn_pair_bound(r.len())) as u64;
        let l_o = other_bytes(l_t as usize) as u64;
        let lineage = lineage_of(&decode_token(token)?);
        let gas_at = |p: u64| {
            self.gas.redeem_gas_limit(&RedeemShape {
                evidence_bytes: l_t as usize,
                lineage: &lineage,
                pending_transactions: 1,
                proofs: p,
                k: self.cfg.k,
            })
        };
        let pins = &self.pins;
        let pf = capacity_preflight(&Preflight {
            l_max: pins.max_encoded_tx_bytes,
            l_t,
            l_o,
            k: self.cfg.k,
            a,
            c_obs,
            reserve: pins.return_reserve_segments,
            gas_at: &gas_at,
            user_gas_limit: pins.user_gas_limit,
        })?;
        // the payer must fund the worst-case gas limit at the current fee level (twice the base fee plus the priority fee)
        let (base_fee, priority) = self.evm.fees()?;
        let cost = BigUint::from(pf.gas) * (BigUint::from(2u8) * base_fee + priority);
        let bal = self.evm.balance(payer)?;
        if bal < cost {
            return refuse(
                WalletReason::InsufficientFunds,
                format!(
                    "the payer holds {bal} wei, the worst-case gas limit {} needs {cost}",
                    pf.gas
                ),
            );
        }
        Ok((c_obs, pf))
    }

    fn admit_return(
        &self,
        record: &mut ReturnRecord,
        source: &[u8],
        amount: &BigUint,
        recipient: &[u8; 20],
        a: u64,
        payer: &[u8],
    ) -> Result<(u64, Option<PreflightResult>)> {
        self.require_erc20_qualification()?;
        let (observed, ordinary) = match self.preflight(source, amount, recipient, a, payer) {
            Ok((observed, preflight)) => (observed, Some(preflight)),
            Err(error)
                if self.cfg.erc20.is_some()
                    && (error
                        .rule()
                        .is_some_and(|e| e.rule == Rule::CapacityPreflight)
                        || error.reason() == Some(WalletReason::InsufficientFunds)) =>
            {
                (self.evm.vault_state(&self.cfg.vault)?.segment.max(a), None)
            }
            Err(error) => return Err(error),
        };
        self.quote_erc20_continuation(record, source, a, observed, payer, ordinary)?;
        Ok((observed, ordinary))
    }

    fn return_record(&self, id: &[u8; 32]) -> Result<ReturnRecord> {
        match self.journal.ret_for_update(&hex(id))? {
            Some(r) => Ok(r),
            None => refuse(
                WalletReason::JournalNotPersisted,
                format!("no journal entry for return {}", hex(id)),
            ),
        }
    }

    fn quote_erc20_continuation(
        &self,
        record: &mut ReturnRecord,
        source: &[u8],
        a: u64,
        observed: u64,
        payer: &[u8],
        ordinary: Option<PreflightResult>,
    ) -> Result<()> {
        let Some(erc20) = &self.cfg.erc20 else {
            return Ok(());
        };
        let (Some(quote), Some(pins)) = (&self.erc20_return_recovery, &self.pins.erc20) else {
            return fail_d(
                Rule::CapacityPreflight,
                "a bounded ERC20 continuation quote is required",
            );
        };
        let recovery = erc20_create2(
            &pins.factory,
            &he(&[&address_word(&erc20.token)]),
            &pins.recovery_initcode_hash,
        );
        if quote.deployment.recovery != recovery
            || quote.deployment.vault_runtime_hash != Some(self.pins.vault_runtime_code_hash)
            || he(&[&self.evm.code(&recovery)?]) != quote.deployment.runtime_hash
        {
            return fail_d(
                Rule::CapacityPreflight,
                "continuation calibration differs from the deployed graph",
            );
        }
        let mut limits = quote.limits.clone();
        let (base_fee, priority) = self.evm.fees()?;
        if priority > limits.max_priority_fee_per_gas
            || BigUint::from(2u8) * base_fee + priority > limits.max_fee_per_gas
        {
            return fail_d(
                Rule::CapacityPreflight,
                "current fees exceed the continuation bid limits",
            );
        }
        limits.signed_bytes = limits
            .signed_bytes
            .min(self.pins.max_encoded_tx_bytes as usize);
        limits.gas = limits.gas.min(self.pins.user_gas_limit);
        limits.balance = limits.balance.min(self.evm.balance(payer)?);
        let ordinary = ordinary
            .map(|pf| {
                let return_data = encode_return_data(&ReturnData {
                    d: self.domain,
                    asset: self.cfg.asset,
                    recipient: unhex_n(&record.recipient)?,
                    amount: undec(&record.amount)?,
                    min_index: a,
                });
                let evidence = evidence_of(source).len() + burn_pair_bound(return_data.len());
                let history = if pf.need == 0 {
                    0
                } else {
                    32 + pf.need as usize * super::segment::gap_proof_len(self.cfg.k)
                };
                let (attempts_before_fallback, inclusion_ms) =
                    quote.ordinary_attempts.unwrap_or_default();
                Ok::<_, Error>(Erc20OrdinaryBound {
                    gas: pf.gas,
                    calldata_bytes: super::abi::redeem_calldata_length(evidence, history),
                    attempts_before_fallback,
                    inclusion_ms,
                })
            })
            .transpose()?;
        let backlog = RecoveryBacklog {
            signed_start: a,
            observed,
            ..quote.backlog.clone()
        };
        let seal = record.seal_receipt.as_deref().map(unhex).transpose()?;
        let admission = self.retrying_trust(|trust| {
            preflight_recovery_with_signing_bounds(
                &AdmissionContext {
                    gamma: &self.pins.gamma,
                    trust,
                    params: &build_params(self.pins.build),
                    deployment: &quote.deployment,
                    calibration: &*quote.calibration,
                    limits: &limits,
                },
                source,
                &backlog,
                seal.as_deref(),
                Some(&quote.signing_bounds),
                ordinary.as_ref(),
            )
        })?;
        let calls = admission.run.len() as u64 + admission.advance_calls + 1;
        let nonce = self.evm.nonce(payer, "pending")?;
        if nonce
            .checked_add(calls - 1)
            .and_then(|last| last.checked_add(admission.prior_attempts))
            .map_or(true, |last| last > limits.max_nonce)
        {
            return fail_d(
                Rule::CapacityPreflight,
                "continuation schedule exceeds the declared nonce horizon",
            );
        }
        let mut schedule = serde_json::json!({
            "generation": hex(&super::recovery::recovery_generation(&quote.deployment.salt, &self.domain)),
            "calls": (u128::from(calls) + u128::from(admission.prior_attempts)).to_string(),
            "totalFee": dec(&admission.total_fee),
            "runCuts": admission.run.iter().map(|call| call.shape.operations).collect::<Vec<_>>(),
            "advanceGaps": admission.advance.shape.gaps,
            "observed": dec(observed),
            "receiptP99Ms": dec(backlog.receipt_p99_ms),
            "finalInclusionMs": dec(backlog.final_inclusion_ms),
            "qualifiedForMs": dec(backlog.qualified_for_ms),
        });
        if let Some(ordinary) = ordinary {
            schedule["ordinary"] = serde_json::json!({
                "gas": dec(ordinary.gas), "calldataBytes": ordinary.calldata_bytes,
                "maxFeePerGas": dec(&limits.max_fee_per_gas), "attemptsBeforeFallback": dec(ordinary.attempts_before_fallback),
            });
        }
        record.extra.insert("recovery".into(), schedule);
        Ok(())
    }

    fn preview_erc20_recipient(&self, recipient: &[u8; 20], amount: &BigUint) -> Result<()> {
        if self.cfg.erc20.is_none() {
            return Ok(());
        }
        let data = cat(&[
            &sel("previewPayout(address,uint256)"),
            &address_word(recipient),
            &u256(amount),
        ]);
        if !self.evm.call_reverts_with(
            &self.cfg.vault,
            &data,
            350_000,
            &sel("PayoutPreviewPassed()"),
        ) {
            return refuse(
                WalletReason::RecipientRefused,
                "the ERC20 payout simulation did not confirm an exact transfer",
            );
        }
        Ok(())
    }

    /// Certify the terminal burn of a planned return: R signs the recipient, the amount and the index. The exact request is
    /// journaled before certification, the certified burn before this returns; a second call resumes the same burn and never
    /// makes another.
    pub fn burn(&self, return_id: &[u8; 32], owner: &dyn OwnerSigner) -> Result<Burned> {
        self.locked(&format!("return/{}", hex(return_id)), || {
            self.burn_inner(return_id, owner)
        })
    }

    fn burn_inner(&self, return_id: &[u8; 32], owner: &dyn OwnerSigner) -> Result<Burned> {
        let mut rec = self.return_record(return_id)?;
        let recipient: [u8; 20] = unhex_n(&rec.recipient)?;
        let amount = undec(&rec.amount)?;
        let a = undec64(&rec.a)?;
        if rec.status == "planned" {
            if self.cfg.erc20.is_some() {
                if recipient == [0; 20] || recipient == self.cfg.vault {
                    return refuse(
                        WalletReason::RecipientRefused,
                        "the zero address and the vault are refused",
                    );
                }
                let source = unhex(&rec.source)?;
                let held = self.verify_token(&source)?;
                if hu(&[&source]) != *return_id || held.amount != amount {
                    return refuse(
                        WalletReason::BadInput,
                        "planned return differs from the verified source and amount",
                    );
                }
            }
            // the last check before the irreversible step: the preflight again, at the journaled index, against a fresh state
            let payer = match &rec.payer {
                None => recipient.to_vec(),
                Some(p) => unhex(p)?,
            };
            let source = unhex(&rec.source)?;
            self.admit_return(&mut rec, &source, &amount, &recipient, a, &payer)?;
            self.preview_erc20_recipient(&recipient, &amount)?;
            let r = encode_return_data(&ReturnData {
                d: self.domain,
                asset: self.cfg.asset,
                recipient,
                amount: amount.clone(),
                min_index: a,
            });
            let req = transfer_request(
                &source,
                owner,
                &TransferTx {
                    recipient: burn_predicate(&hu(&[&r])),
                    mask: fresh_mask().to_vec(),
                    data: Some(r),
                    deadline: None,
                },
            )?;
            rec.burn_tx = Some(hex(&req.tx));
            rec.burn_request = Some(hex(&req.cd));
            rec.status = "burn-requested".into();
            self.journal.put_return(&rec)?;
        }
        if rec.status == "burn-requested" {
            let proof = certify_checked(
                &*self.aggregator,
                &unhex(rec.burn_request.as_deref().unwrap_or(""))?,
            )?;
            let burned = append_transfer(
                &unhex(&rec.source)?,
                &unhex(rec.burn_tx.as_deref().unwrap_or(""))?,
                &proof,
            )?;
            let part = decode_evidence(&evidence_of(&burned))?;
            let v =
                self.retrying_trust(|trust| verify_part(&self.cfg, &self.domain, trust, &part))?;
            if v.min_segment != a || v.amount != amount || v.recipient != recipient {
                return refuse(
                    WalletReason::ProviderFault,
                    "the certified burn is not the planned one",
                );
            }
            rec.burned = Some(hex(&burned));
            rec.eta = Some(hex(&v.eta));
            rec.status = "burned".into();
            self.journal.put_return(&rec)?;
        }
        let burned = unhex(rec.burned.as_deref().unwrap_or(""))?;
        let part = decode_evidence(&evidence_of(&burned))?;
        let verdict =
            self.retrying_trust(|trust| verify_part(&self.cfg, &self.domain, trust, &part))?;
        Ok(Burned {
            burned,
            eta: verdict.eta,
            verdict,
        })
    }

    /// Build the redeem transaction of a burned return: one SegmentSealed log per segment a .. c-1 from any provider, each checked
    /// (length, order, M_j, head link from the journaled start head), the gap proofs, and the gas limit (expected cost plus
    /// gasReserve). A missing or reordered log is missing evidence, never absence. Refuses with `CapacityExceeded` when the claim
    /// does not fit.
    pub fn build_redeem(&self, return_id: &[u8; 32]) -> Result<RedeemTx> {
        self.locked(&format!("return/{}", hex(return_id)), || {
            self.build_redeem_inner(return_id)
        })
    }

    fn build_redeem_inner(&self, return_id: &[u8; 32]) -> Result<RedeemTx> {
        let rec = self.return_record(return_id)?;
        if rec.status != "burned" && rec.status != "submitted" {
            return refuse(
                WalletReason::NotPending,
                format!("return {} is {}", hex(return_id), rec.status),
            );
        }
        let a = undec64(&rec.a)?;
        let eta: [u8; 32] = unhex_n(rec.eta.as_deref().unwrap_or(""))?;
        let burned = unhex(rec.burned.as_deref().unwrap_or(""))?;
        let evidence = evidence_of(&burned);
        let start_head = unhex(&rec.start_head)?;
        let mut attempt = 0;
        loop {
            let st = self.evm.vault_state(&self.cfg.vault)?;
            if st.segment < a {
                return refuse(
                    WalletReason::NotPending,
                    format!(
                        "the vault is at segment {}, below the burn index {a}: wait (FutureIndex)",
                        st.segment
                    ),
                );
            }
            let logs =
                self.evm
                    .segment_logs(&self.cfg.vault, undec64(&rec.from_block)?, a, st.segment)?;
            let mut segs: Vec<Segment> = Vec::new();
            let mut before = start_head.clone();
            for l in &logs {
                let s = check_segment_log(
                    &self.domain,
                    self.cfg.k,
                    topic_index(&l.topics[1]),
                    &before,
                    &l.data,
                )?;
                before = s.after.to_vec();
                segs.push(s);
            }
            if before != st.head {
                // the chain moved between the reads, or the provider is inconsistent: read again once
                if attempt < 2 {
                    attempt += 1;
                    continue;
                }
                return refuse(
                    WalletReason::ProviderFault,
                    "the served segment logs do not fold to the vault's current head",
                );
            }
            let h = build_history(&segs, &eta, a, st.segment, &start_head)?;
            if let Some(j) = h.paid {
                return refuse(
                    WalletReason::AlreadyPaid,
                    format!("the redemption ID is in sealed segment {j}: reconcile"),
                );
            }
            let p = st.segment - a;
            let calldata = redeem_calldata(&evidence, &eta, a, &h.history);
            let l_o = other_bytes(evidence.len()) as u64;
            let lineage = lineage_of(&decode_token(&burned)?);
            // the model only where it applies; the simulation, when the RPC has one, sets the limit
            let mut gas_limit = if self.gas_applies()? {
                self.gas.redeem_gas_limit(&RedeemShape {
                    evidence_bytes: evidence.len(),
                    lineage: &lineage,
                    pending_transactions: 0,
                    proofs: p,
                    k: self.cfg.k,
                })
            } else {
                None
            };
            match self
                .evm
                .estimate_gas(&rec.recipient_bytes()?, &self.cfg.vault, &calldata, 0)?
            {
                Estimate::Gas(g) => {
                    // fail closed: a limit that overflows is not bounded
                    let Some(l) = g.checked_add(self.pins.gas_reserve) else {
                        return fail_d(Rule::CapacityExceeded, "the gas cannot be bounded");
                    };
                    gas_limit = Some(l);
                }
                Estimate::Revert { data, .. } => {
                    let e = decode_revert(data.as_deref().unwrap_or(&[]));
                    let action = classify_redeem_error(e.as_ref());
                    if action == RedeemAction::RebuildHistory && attempt < 2 {
                        attempt += 1;
                        continue;
                    }
                    if action == RedeemAction::Reconcile {
                        return refuse(
                            WalletReason::AlreadyPaid,
                            "the vault reports AlreadyPaid: reconcile",
                        );
                    }
                    if let Some(e) = e {
                        return Err(redeem_refusal(
                            e,
                            Some(format!("simulation refused ({})", action.name())),
                        )
                        .into());
                    }
                    // no rule: an RPC without simulation; the model's bound stands
                }
            }
            let Some(gas_limit) = gas_limit else {
                return fail_d(Rule::CapacityExceeded, "the gas cannot be bounded");
            };
            capacity_exceeded(
                self.pins.max_encoded_tx_bytes,
                evidence.len() as u64,
                l_o,
                self.cfg.k,
                p,
                gas_limit,
                self.pins.user_gas_limit,
            )?;
            return Ok(RedeemTx {
                return_id: *return_id,
                calldata,
                gas_limit,
                p,
                endpoint: st.segment,
                history: h.history,
                eta,
                claimed_start: a,
            });
        }
    }

    /// Send the redeem. Earlier sends are reconciled first (a pending one is never doubled; a landed one is the answer). Every
    /// signed transaction is journaled before broadcast; an ambiguous broadcast is resolved by its receipt. A stale endpoint is
    /// rebuilt, never the burn; failures are classified by error selector.
    pub fn submit_redeem(
        &self,
        return_id: &[u8; 32],
        signer: &dyn EvmSigner,
    ) -> Result<ReconcileResult> {
        self.locked(&format!("return/{}", hex(return_id)), || {
            self.submit_redeem_inner(return_id, signer)
        })
    }

    fn check_ordinary_import(&self, rec: &ReturnRecord, raw: Option<&[u8]>) -> Result<()> {
        let part = decode_token(&unhex(rec.burned.as_deref().unwrap_or(""))?)?;
        let tx = raw
            .map(decode_signed_tx)
            .transpose()
            .map_err(Error::Other)?;
        self.retrying_trust(|trust| {
            use super::trust::decode_uc;
            super::verify::verify_part(&self.cfg, &self.domain, trust, &part)?;
            let root = part.levels().next().expect("nonempty lineage");
            let receipt =
                decode_receipt_backing(root.mint.justification.as_deref().unwrap_or(&[]))?;
            let mut epoch = decode_uc(&receipt.proof.uc)?.unicity_seal.epoch;
            for level in part.levels() {
                for proof in std::iter::once(&level.mint_proof).chain(&level.proofs) {
                    epoch = epoch.max(decode_uc(&proof.uc)?.unicity_seal.epoch);
                }
            }
            self.evm.check_return_import(&self.cfg, epoch, tx.as_ref())
        })
    }

    fn submit_redeem_inner(
        &self,
        return_id: &[u8; 32],
        signer: &dyn EvmSigner,
    ) -> Result<ReconcileResult> {
        let mut expired = None;
        let prior = self.reconcile_inner_with_expiry(return_id, &mut expired)?;
        if !matches!(prior, ReconcileResult::NotPaid { .. })
            && !expired
                .as_ref()
                .is_some_and(|(tx, _)| tx.from == signer.address())
        {
            return Ok(prior);
        }
        let mut gas_bump = 1u64;
        for _ in 0..4 {
            let mut fresh = self.return_record(return_id)?;
            let rtx = match self.build_redeem_inner(return_id) {
                Err(e) if e.rule().is_some_and(|r| r.rule == Rule::VerifierRefused) => {
                    self.check_ordinary_import(&fresh, None)?;
                    return Err(e);
                }
                other => other?,
            };
            let gas = (rtx.gas_limit.saturating_mul(gas_bump)).min(self.pins.user_gas_limit);
            let replacement = if let Some((old, underpriced)) = &expired {
                let mut bid = old.request.clone();
                let nonce = dec(bid.nonce);
                for send in fresh.sends.iter().filter(|send| send.nonce == nonce) {
                    let candidate = decode_signed_tx(&unhex(&send.raw)?).map_err(Error::Other)?;
                    bid.max_fee_per_gas =
                        bid.max_fee_per_gas.max(candidate.request.max_fee_per_gas);
                    bid.max_priority_fee_per_gas = bid
                        .max_priority_fee_per_gas
                        .max(candidate.request.max_priority_fee_per_gas);
                }
                Some((bid, *underpriced))
            } else {
                None
            };
            let request = self.transaction_request(
                &signer.address(),
                &self.cfg.vault,
                &rtx.calldata,
                BigUint::default(),
                gas,
                replacement.as_ref(),
            )?;
            self.check_erc20_ordinary_attempt(&fresh, &signer.address(), &request)?;
            let tx = sign_tx(signer, &request)?;
            self.check_ordinary_import(&fresh, Some(&tx.raw))?;
            if let Some((old, _)) = &expired {
                if self.evm.nonce(&old.from, "latest")? != old.request.nonce {
                    return Ok(ReconcileResult::Pending {
                        tx_hash: old.hash.to_vec(),
                    });
                }
            }
            fresh.sends.push(self.send_record(&tx));
            fresh.status = "submitted".into();
            if fresh.first_send_block.is_none() {
                fresh.first_send_block = Some(dec(self.evm.block_number()?));
            }
            self.journal.put_return(&fresh)?;
            expired = None;
            let Some(r) = self.broadcast_and_wait(&tx)? else {
                return Ok(ReconcileResult::Pending {
                    tx_hash: tx.hash.to_vec(),
                });
            };
            if status_is_ok(&r) {
                let rec = self.return_record(return_id)?;
                return Ok(self.verified_paid(rec, &tx.hash)?.unwrap_or(
                    ReconcileResult::Pending {
                        tx_hash: tx.hash.to_vec(),
                    },
                ));
            }
            // reverted: classify by simulating the same call at the current state
            let (action, e) =
                match self
                    .evm
                    .estimate_gas(&signer.address(), &self.cfg.vault, &rtx.calldata, 0)?
                {
                    Estimate::Gas(_) => (RedeemAction::RetryLater, None),
                    Estimate::Revert { data, .. } => {
                        let e = decode_revert(data.as_deref().unwrap_or(&[]));
                        (classify_redeem_error(e.as_ref()), e)
                    }
                };
            match action {
                RedeemAction::Reconcile => return self.reconcile_inner(return_id),
                RedeemAction::RebuildHistory | RedeemAction::RepairProof => continue,
                RedeemAction::RetryLater => {
                    if let Some(e) = e.filter(|e| {
                        e.rule == Rule::VerifierRefused
                            && e.inner
                                .as_ref()
                                .is_some_and(|i| i.rule == Rule::QuorumNotMet)
                    }) {
                        return Err(redeem_refusal(
                            e,
                            Some("simulation after reverted redeem refused (retry-later)".into()),
                        )
                        .into());
                    }
                    // an out-of-gas or a transient payout failure: one retry with more gas
                    gas_bump = 2;
                    continue;
                }
                _ => {
                    let detail =
                        format!("redeem {} reverted: stop and tell the user", hex(&tx.hash));
                    let error = match e {
                        Some(e) => redeem_refusal(e, Some(detail)),
                        None => Nb2Error::with_detail(Rule::PayoutFailed, detail),
                    };
                    return Err(error.into());
                }
            }
        }
        Ok(ReconcileResult::NotPaid { last_failure: None })
    }

    /// Look for Paid(eta) and the receipts of every journaled send; never changes the burn. A Paid log counts only from the vault
    /// and only once its receipt is verified under the block's EVM UC (section 6.2 steps 2 to 5): a provider that invents or
    /// withholds Paid can delay the wallet, never stop its redemption.
    pub fn reconcile(&self, return_id: &[u8; 32]) -> Result<ReconcileResult> {
        self.locked(&format!("return/{}", hex(return_id)), || {
            self.reconcile_inner(return_id)
        })
    }

    fn reconcile_inner(&self, return_id: &[u8; 32]) -> Result<ReconcileResult> {
        self.reconcile_inner_with_expiry(return_id, &mut None)
    }

    fn reconcile_inner_with_expiry(
        &self,
        return_id: &[u8; 32],
        expired: &mut Option<(DecodedTx, bool)>,
    ) -> Result<ReconcileResult> {
        let mut rec = self.return_record(return_id)?;
        if rec.status == "paid" {
            let p = rec.paid.as_ref().expect("a paid record has paid");
            return Ok(ReconcileResult::Paid {
                tx_hash: unhex(&p.tx_hash)?,
                block_number: undec64(&p.block_number)?,
            });
        }
        let Some(eta_hex) = rec.eta.clone() else {
            return Ok(ReconcileResult::NotPaid { last_failure: None });
        };
        let eta = unhex(&eta_hex)?;
        for l in self
            .evm
            .paid(&self.cfg.vault, &eta, undec64(&rec.from_block)?)?
        {
            let Some(p) = decode_paid(&l) else { continue };
            if l.address != self.cfg.vault || p.eta != eta {
                continue;
            }
            if let Some(v) = self.verified_paid(rec.clone(), &l.transaction_hash)? {
                return Ok(v);
            }
        }
        let mut sends = rec.sends.clone();
        let landed = self.landed_send(&mut sends, Some(&rec))?;
        if sends != rec.sends {
            rec.sends = sends;
            self.journal.put_return(&rec)?;
        }
        match landed {
            Landed::Replace(tx, pooled) => {
                let tx_hash = tx.hash.to_vec();
                *expired = Some((*tx, pooled));
                Ok(ReconcileResult::Pending { tx_hash })
            }
            Landed::Pending => Ok(ReconcileResult::Pending {
                tx_hash: unhex(&rec.sends.last().expect("a send").hash)?,
            }),
            Landed::Receipt(r) => {
                let tx = unhex(&r.transaction_hash.to_lowercase())?;
                Ok(self
                    .verified_paid(rec, &tx)?
                    .unwrap_or(ReconcileResult::Pending { tx_hash: tx }))
            }
            Landed::None => Ok(ReconcileResult::NotPaid { last_failure: None }),
        }
    }

    /// Verify that transaction `tx` paid this return: its Paid log, from the vault, with topics [Paid, eta, recipient] and data the
    /// amount, in a receipt verified under the block's certificate. Journals `paid` and returns it; Pending while the block is not
    /// certified yet; None when the claim does not verify (it is ignored).
    fn verified_paid(&self, mut rec: ReturnRecord, tx: &[u8]) -> Result<Option<ReconcileResult>> {
        let r = (|| -> Result<Option<ReconcileResult>> {
            let eta = unhex(rec.eta.as_deref().unwrap_or(""))?;
            let rp = self
                .evm
                .receipt_proof(tx, &self.cfg.vault, &topic::paid())?;
            let log = self.retrying_trust(|t| verify_receipt_log(&self.cfg, t, &rp.proof))?;
            let recipient_word = cat(&[&[0u8; 12], &unhex(&rec.recipient)?]);
            if log.topics.len() != 3
                || log.topics[0] != topic::paid()
                || log.topics[1] != eta
                || log.topics[2] != recipient_word
                || log.data.len() != 32
                || be_int(&log.data) != undec(&rec.amount)?
            {
                return Ok(None);
            }
            rec.paid = Some(PaidRecord {
                tx_hash: hex(tx),
                block_number: dec(rp.block_number),
                extra: Default::default(),
            });
            rec.status = "paid".into();
            self.journal.put_return(&rec)?;
            Ok(Some(ReconcileResult::Paid {
                tx_hash: tx.to_vec(),
                block_number: rp.block_number,
            }))
        })();
        match r {
            Err(Error::Wallet(w)) if w.reason == WalletReason::CompanionUnknown => {
                Ok(Some(ReconcileResult::Pending {
                    tx_hash: tx.to_vec(),
                }))
            }
            // a lost compare-and-swap of the journal is never read as an unverified claim
            Err(Error::Wallet(w))
                if w.reason == WalletReason::JournalConflict
                    || w.reason == WalletReason::JournalNotPersisted =>
            {
                Err(Error::Wallet(w))
            }
            Err(Error::Rule(_)) | Err(Error::Wallet(_)) => Ok(None),
            r => r,
        }
    }

    // ==== status ==========================================================================================================

    /// Where every journaled deposit and return stands, in words.
    pub fn status(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for d in self.journal.deposits()? {
            let say = match d.status.as_str() {
                "planned" => "planned: the secret is journaled; send the deposit",
                "submitted" => "sent: waiting for the receipt (submit_deposit again reconciles)",
                "deposited" => {
                    "deposited: waiting for the block certificate (collect_deposit_proof)"
                }
                "proven" => "proven: J is journaled; mint",
                "minted" => "minted",
                _ => "unknown",
            };
            out.push(format!(
                "deposit intent {} of {}: {say}",
                d.intent, d.amount
            ));
        }
        for r in self.journal.returns()? {
            let say = match r.status.as_str() {
                "planned" => "planned: preflight passed; burn",
                "burn-requested" => "burn requested: call burn again to finish certification",
                "burned" => "burned: build and submit the redeem",
                "submitted" => "redeem sent: reconcile",
                "paid" => "paid",
                _ => "unknown",
            };
            out.push(format!(
                "return {} of {} to {} (a = {}): {say}",
                r.return_id.chars().take(18).collect::<String>(),
                r.amount,
                r.recipient,
                r.a
            ));
        }
        Ok(out)
    }

    // ==== EVM plumbing ====================================================================================================

    fn signed(
        &self,
        signer: &dyn EvmSigner,
        to: &[u8; 20],
        data: &[u8],
        value: BigUint,
        gas: u64,
    ) -> Result<SignedTx> {
        sign_tx(
            signer,
            &self.transaction_request(&signer.address(), to, data, value, gas, None)?,
        )
    }

    fn check_erc20_ordinary_attempt(
        &self,
        record: &ReturnRecord,
        payer: &[u8; 20],
        request: &TxRequest,
    ) -> Result<()> {
        if self.cfg.erc20.is_none() {
            return Ok(());
        }
        let Some(ordinary) = record
            .extra
            .get("recovery")
            .and_then(|plan| plan.get("ordinary"))
        else {
            return fail_d(
                Rule::CapacityPreflight,
                "ordinary route lacks a signing reserve",
            );
        };
        let Some(policy) = &self.erc20_return_recovery else {
            return fail_d(Rule::CapacityPreflight, "ordinary route lacks payer limits");
        };
        let field = |name| {
            ordinary
                .get(name)
                .and_then(|value| value.as_str())
                .unwrap_or("")
        };
        let prior = record
            .sends
            .iter()
            .map(|sent| sent.nonce.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let mut limits = policy.limits.clone();
        limits.gas = limits
            .gas
            .min(undec64(field("gas"))?)
            .min(self.pins.user_gas_limit);
        limits.calldata_bytes = limits
            .calldata_bytes
            .min(ordinary["calldataBytes"].as_u64().unwrap_or(0) as usize);
        limits.signed_bytes = limits
            .signed_bytes
            .min(self.pins.max_encoded_tx_bytes as usize);
        limits.max_fee_per_gas = limits.max_fee_per_gas.min(undec(field("maxFeePerGas"))?);
        limits.max_priority_fee_per_gas = limits
            .max_priority_fee_per_gas
            .min(limits.max_fee_per_gas.clone());
        let Some((_, fee)) = quote_erc20_call(request.data.len(), request.gas, &limits) else {
            return fail_d(
                Rule::CapacityPreflight,
                "ordinary call is outside the ERC20 admission limits",
            );
        };
        if (!prior.contains(dec(request.nonce).as_str())
            && prior.len() as u64 >= undec64(field("attemptsBeforeFallback"))?)
            || request.nonce > limits.max_nonce
            || request.max_fee_per_gas > limits.max_fee_per_gas
            || request.max_priority_fee_per_gas > limits.max_priority_fee_per_gas
            || fee > limits.fee_budget
            || fee > limits.balance
            || fee > self.evm.balance(payer)?
        {
            return fail_d(
                Rule::CapacityPreflight,
                "ordinary attempt exceeds its signing reserve",
            );
        }
        Ok(())
    }

    fn transaction_request(
        &self,
        payer: &[u8; 20],
        to: &[u8; 20],
        data: &[u8],
        value: BigUint,
        gas: u64,
        replace: Option<&(TxRequest, bool)>,
    ) -> Result<TxRequest> {
        let (base_fee, mut priority) = self.evm.fees()?;
        let mut max_fee = BigUint::from(2u8) * base_fee + &priority;
        let nonce = if let Some((prior, pooled)) = replace {
            if self.evm.nonce(payer, "latest")? != prior.nonce {
                return refuse(
                    WalletReason::NotPending,
                    "payout nonce changed during replacement",
                );
            }
            if *pooled || self.evm.nonce(payer, "pending")? > prior.nonce {
                let bump = |bid: &BigUint| bid + bid / 10u8 + 1u8;
                max_fee = max_fee.max(bump(&prior.max_fee_per_gas));
                priority = priority.max(bump(&prior.max_priority_fee_per_gas));
            }
            prior.nonce
        } else {
            self.evm.nonce(payer, "pending")?
        };
        Ok(TxRequest {
            chain_id: self.cfg.chain_id,
            nonce,
            max_priority_fee_per_gas: priority,
            max_fee_per_gas: max_fee,
            gas,
            to: *to,
            value,
            data: data.to_vec(),
        })
    }

    fn send_record(&self, tx: &SignedTx) -> SendRecord {
        SendRecord {
            hash: hex(&tx.hash),
            raw: hex(&tx.raw),
            nonce: dec(tx.request.nonce),
            gas: dec(tx.request.gas),
            at: dec(self.now_ms()),
            nonce_used_at: None,
            extra: Default::default(),
        }
    }

    fn send_raw_tolerant(&self, raw: &[u8]) -> Result<()> {
        match self.evm.send_raw(raw) {
            Ok(_) | Err(SendError::Ambiguous { .. }) => Ok(()),
            Err(SendError::Failed(e)) => Err(e),
        }
    }

    /// Broadcast and poll the receipt of the locally computed hash; None when none arrived in time (the send stays journaled).
    fn broadcast_and_wait(&self, tx: &SignedTx) -> Result<Option<ReceiptJson>> {
        self.send_raw_tolerant(&tx.raw)?;
        let deadline = self.now_ms() + self.receipt_timeout_ms;
        loop {
            if let Some(r) = self.evm.receipt(&tx.hash)? {
                return Ok(Some(r));
            }
            if self.now_ms() >= deadline {
                return Ok(None);
            }
            self.sleep_ms(self.poll_ms);
        }
    }

    /// The outcome of a record's earlier sends: a success receipt (the answer), Pending, or None (none is alive: a new send is
    /// safe). The account's MINED nonce is read first, then every send's receipt; a success receipt is the answer whenever it is
    /// seen. A send whose nonce is used without a success receipt is dead only after the head has advanced `dead_after_blocks`
    /// since that was first seen (journaled in `nonceUsedAt`; the caller persists `sends` when this changes them), the block at
    /// `nonceUsedAt` has a certificate (a found companion), and every receipt is read again; until then it is pending. A send
    /// still in a pool is broadcast again (same bytes).
    fn landed_send(
        &self,
        sends: &mut [SendRecord],
        return_record: Option<&ReturnRecord>,
    ) -> Result<Landed> {
        let Some(last) = sends.last() else {
            return Ok(Landed::None);
        };
        let raw = unhex(&last.raw)?;
        let tx = decode_signed_tx(&raw).map_err(Error::Other)?;
        let last_nonce = undec64(&last.nonce)?;
        let mined = self.evm.nonce(&tx.from, "latest")?;
        let mut seen = false;
        for s in sends.iter() {
            if let Some(r) = self.evm.receipt(&unhex(&s.hash)?)? {
                if status_is_ok(&r) {
                    return Ok(Landed::Receipt(Box::new(r)));
                }
                seen |= s.nonce == last.nonce;
            }
        }
        if mined <= last_nonce {
            if let Some(rec) = return_record {
                if let Err(error) = self.check_ordinary_import(rec, Some(&raw)) {
                    if error
                        .rule()
                        .is_some_and(|rule| rule.rule == Rule::StaleEndpoint)
                    {
                        return Ok(
                            if !seen
                                && mined == tx.request.nonce
                                && mined == last_nonce
                                && self.evm.nonce(&tx.from, "latest")? == last_nonce
                            {
                                Landed::Replace(Box::new(tx), false)
                            } else {
                                Landed::Pending
                            },
                        );
                    }
                    return Err(error);
                }
            }
            if let Err(error) = self.send_raw_tolerant(&raw) {
                if return_record.is_some()
                    && !seen
                    && matches!(&error, Error::Other(message) if message.to_ascii_lowercase().contains("replacement transaction underpriced"))
                    && self.evm.nonce(&tx.from, "latest")? == tx.request.nonce
                {
                    return Ok(Landed::Replace(Box::new(tx), true));
                }
                return Err(error);
            }
            return Ok(Landed::Pending);
        }
        // a mined transaction used the nonce, and no success receipt is visible: wait for depth before calling it dead
        let head = self.evm.block_number()?;
        let last = sends.last_mut().expect("a send");
        let Some(used_at) = last.nonce_used_at.clone() else {
            last.nonce_used_at = Some(dec(head));
            return Ok(Landed::Pending);
        };
        let used_at = undec64(&used_at)?;
        if head < used_at.saturating_add(self.dead_after_blocks) {
            return Ok(Landed::Pending);
        }
        // and the block at which the nonce was seen used is certified (a found companion, section 12.7): depth alone is not finality
        let Some((header, hash)) = self.evm.header_by_number(used_at)? else {
            return Ok(Landed::Pending);
        };
        match self.evm.certificate_of(&header, &hash) {
            Ok(_) => {}
            Err(Error::Wallet(_)) | Err(Error::Rule(_)) => return Ok(Landed::Pending),
            Err(e) => return Err(e),
        }
        for s in sends.iter() {
            if let Some(r) = self.evm.receipt(&unhex(&s.hash)?)? {
                if status_is_ok(&r) {
                    return Ok(Landed::Receipt(Box::new(r)));
                }
            }
        }
        Ok(Landed::None)
    }
}

impl ReturnRecord {
    fn recipient_bytes(&self) -> Result<Vec<u8>> {
        unhex(&self.recipient)
    }
}

fn seen_entry(s: &SeenLog) -> SeenDeposit {
    SeenDeposit {
        tx: hex(&s.tx),
        deposit_number: dec(s.n),
        block_number: dec(s.block_number),
        amount: dec(&s.amount),
        first_owner: hex(&s.first_owner),
        token: None,
        extra: Default::default(),
    }
}

/// Merge deposit entries into `seenDeposits` by deposit number, keeping journaled tokens, in number order.
fn merge_seen(rec: &mut DepositRecord, entries: Vec<SeenDeposit>) -> Result<()> {
    let mut known: Vec<SeenDeposit> = rec.seen_deposits.take().unwrap_or_default();
    for e in entries {
        if !known.iter().any(|k| k.deposit_number == e.deposit_number) {
            known.push(e);
        }
    }
    let mut keyed = Vec::new();
    for k in known {
        keyed.push((undec(&k.deposit_number)?, k));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    rec.seen_deposits = Some(keyed.into_iter().map(|x| x.1).collect());
    Ok(())
}

/// The lineage of a part, root first.
pub fn lineage_of(part: &Token) -> Vec<LineageLevel> {
    part.levels().cloned().collect()
}

/// An upper bound of the encoded [burn transfer, inclusion proof] pair with return data of `r_len` bytes: the transfer, the
/// certification data, the reference time, an RSMT path of at most 256 siblings and an aggregator UC at its decoder bound.
pub fn burn_pair_bound(r_len: usize) -> usize {
    let transfer = 3 + 1 + 45 + 34 + 3 + r_len + 9;
    let cd = 3 + 1 + 45 + 34 + 34 + 9 + 67;
    4 + 1 + transfer + 3 + 1 + cd + 9 + 3 + 32 + 32 * 256 + (24 << 10)
}

/// Everything of the redeem transaction besides the evidence and the gap proofs: ABI heads and padding, the start head, the envelope.
pub fn other_bytes(evidence: usize) -> usize {
    // the start head, and the history's padding at most 31 bytes
    let calldata = redeem_calldata_length(evidence, 32) + 31;
    calldata - evidence + redeem_tx_framing(calldata)
}

#[cfg(test)]
#[path = "bridge_erc20_tests.rs"]
mod erc20_tests;
