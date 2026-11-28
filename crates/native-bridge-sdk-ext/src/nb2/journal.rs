//! The wallet journal (format `unicity-nb2-journal`, version 1; `journal.ts`), documented byte for byte in
//! `docs/nb2-journal.md`, so this plug-in and the TypeScript plug-in read and write the same records. A journal is a
//! key-value store of JSON records, one per key:
//!
//! ```text
//!   nb2/v1/<D>/intents          the intent counter: the next unused intent i (its high-water mark is next - 1)
//!   nb2/v1/<D>/deposit/<i>      one deposit, from its plan to the minted token
//!   nb2/v1/<D>/split/<id>       one split, from its plan to the minted children
//!   nb2/v1/<D>/return/<id>      one return, from its plan to the Paid event
//! ```
//!
//! `<D>` is the deployment domain in lowercase hex without 0x. Byte strings are 0x-prefixed lowercase hex; integers are decimal
//! strings. A record is written whole, by compare-and-swap against the exact text last read or written, and read back. Unknown
//! fields are kept on rewrite.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use num_bigint::BigUint;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::errors::{fail_d, refuse, Error, Result, Rule, WalletReason};
use super::evm::decode_signed_tx;
use super::util::{from_hex, to_hex};

pub const JOURNAL_FORMAT: &str = "unicity-nb2-journal";
pub const JOURNAL_VERSION: u64 = 1;

/// Durable key-value storage. `put_if` is a compare-and-swap: it writes `value` only when the stored value is exactly
/// `expected` (None: absent) and reports whether it did; it must be atomic and must not return before the value survives a
/// crash. Two wallets (or two processes) sharing a store therefore never both advance the same record.
pub trait JournalStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn put_if(&self, key: &str, expected: Option<&str>, value: &str) -> Result<bool>;
    /// The keys with this prefix, sorted.
    fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// An in-memory store (tests, and the export/import of a whole journal).
#[derive(Debug, Default)]
pub struct MemoryJournalStore {
    pub map: Mutex<BTreeMap<String, String>>,
}

impl MemoryJournalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every record.
    pub fn dump(&self) -> BTreeMap<String, String> {
        self.map.lock().expect("store").clone()
    }

    /// A store holding exactly these records.
    pub fn from_map(m: BTreeMap<String, String>) -> Self {
        MemoryJournalStore { map: Mutex::new(m) }
    }
}

impl JournalStore for MemoryJournalStore {
    fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.map.lock().expect("store").get(key).cloned())
    }

    fn put_if(&self, key: &str, expected: Option<&str>, value: &str) -> Result<bool> {
        let mut m = self.map.lock().expect("store");
        if m.get(key).map(|s| s.as_str()) != expected {
            return Ok(false);
        }
        m.insert(key.to_string(), value.to_string());
        Ok(true)
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .map
            .lock()
            .expect("store")
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

/// `0x`-prefixed lowercase hex.
pub type Hex = String;
/// A decimal string.
pub type Dec = String;

pub fn hex(b: &[u8]) -> Hex {
    format!("0x{}", to_hex(b))
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    let ok = s.starts_with("0x")
        && s.len() % 2 == 0
        && s[2..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    if !ok {
        return refuse(
            WalletReason::BadInput,
            format!(
                "journal field {} is not lowercase 0x hex",
                s.chars().take(20).collect::<String>()
            ),
        );
    }
    Ok(from_hex(&s[2..]).expect("checked"))
}

pub fn unhex_n<const N: usize>(s: &str) -> Result<[u8; N]> {
    let b = unhex(s)?;
    if b.len() != N {
        return refuse(
            WalletReason::BadInput,
            format!(
                "journal field {} is not {N} bytes",
                s.chars().take(20).collect::<String>()
            ),
        );
    }
    Ok(super::util::arr(&b))
}

pub fn dec(v: impl core::fmt::Display) -> Dec {
    v.to_string()
}

fn dec_ok(s: &str) -> bool {
    s == "0" || (!s.is_empty() && s.as_bytes()[0] != b'0' && s.bytes().all(|c| c.is_ascii_digit()))
}

pub fn undec(s: &str) -> Result<BigUint> {
    if !dec_ok(s) {
        return refuse(
            WalletReason::BadInput,
            format!("journal field {s} is not a decimal"),
        );
    }
    Ok(s.parse().expect("checked"))
}

pub fn undec64(s: &str) -> Result<u64> {
    if !dec_ok(s) {
        return refuse(
            WalletReason::BadInput,
            format!("journal field {s} is not a decimal"),
        );
    }
    match s.parse() {
        Ok(v) => Ok(v),
        Err(_) => refuse(
            WalletReason::BadInput,
            format!("journal field {s} exceeds 64 bits"),
        ),
    }
}

/// A signed EVM transaction the wallet broadcast (or is about to).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRecord {
    pub hash: Hex,
    pub raw: Hex,
    pub nonce: Dec,
    pub gas: Dec,
    pub at: Dec,
    /// The head block when a mined transaction of the account was first seen past this nonce without this send's success receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_used_at: Option<Dec>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The fields every record carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Base {
    pub format: String,
    pub version: u64,
    pub domain: Hex,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentsRecord {
    #[serde(flatten)]
    pub base: Base,
    /// The wallet-versioned derivation of k_w from the seed, e.g. "nb2-hmac-sha256-v1".
    pub key_scheme: String,
    pub next: Dec,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One Deposited event seen with a record's rho.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeenDeposit {
    pub tx: Hex,
    pub deposit_number: Dec,
    pub block_number: Dec,
    pub amount: Dec,
    pub first_owner: Hex,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<Hex>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositRecord {
    #[serde(flatten)]
    pub base: Base,
    pub key_scheme: String,
    pub intent: Dec,
    pub amount: Dec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erc20_token: Option<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<Dec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_credit: Option<Dec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_sends: Vec<SendRecord>,
    /// The first owner's compressed key and its 42-byte predicate.
    pub owner_key: Hex,
    pub first_owner: Hex,
    pub rho: Hex,
    /// planned, submitted, deposited, proven or minted.
    pub status: String,
    /// The intent's high-water mark has been handed to the wallet's backup (section 12.1).
    pub backed_up: bool,
    pub sends: Vec<SendRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit_tx: Option<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<Dec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit_number: Option<Dec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_proof: Option<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<Hex>,
    /// Optional: r itself, when the wallet backs up secrets rather than the high-water mark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Hex>,
    /// The head block when the plan was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planned_block: Option<Dec>,
    /// Every Deposited event seen with this rho; the first is the record's own deposit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_deposits: Option<Vec<SeenDeposit>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitOutputRecord {
    pub owner_key: Hex,
    pub amount: Dec,
    pub salt: Hex,
    /// The certified child, or null.
    pub token: Option<Hex>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitRecord {
    #[serde(flatten)]
    pub base: Base,
    pub split_id: Hex,
    pub source: Hex,
    pub outputs: Vec<SplitOutputRecord>,
    pub mask: Hex,
    /// planned, burn-requested, burned or minted.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burn_tx: Option<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burn_request: Option<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burned: Option<Hex>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The transaction that emitted Paid(eta).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaidRecord {
    pub tx_hash: Hex,
    pub block_number: Dec,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReturnRecord {
    #[serde(flatten)]
    pub base: Base,
    pub return_id: Hex,
    /// The held part before its burn.
    pub source: Hex,
    pub amount: Dec,
    pub recipient: Hex,
    /// The signed minimum segment index and the start head it came with.
    pub a: Dec,
    pub start_head: Hex,
    /// The block of the seal receipt that gave `a` (the deployment block when there was none).
    pub from_block: Dec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_receipt: Option<Hex>,
    /// planned, burn-requested, burned, submitted or paid.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burn_tx: Option<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burn_request: Option<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burned: Option<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eta: Option<Hex>,
    pub sends: Vec<SendRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_send_block: Option<Dec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paid: Option<PaidRecord>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A record kind with its `kind` string.
pub trait Record: Serialize + DeserializeOwned {
    const KIND: &'static str;
    fn base(&self) -> &Base;
}

macro_rules! record {
    ($t:ty, $k:literal) => {
        impl Record for $t {
            const KIND: &'static str = $k;
            fn base(&self) -> &Base {
                &self.base
            }
        }
    };
}

record!(IntentsRecord, "intents");
record!(DepositRecord, "deposit");
record!(SplitRecord, "split");
record!(ReturnRecord, "return");

/// The typed journal over a store, keyed by deployment.
pub struct Journal {
    pub store: Arc<dyn JournalStore>,
    pub domain: [u8; 32],
    pub prefix: String,
    /// The stored text of every record this instance last read or wrote: the `expected` of its next compare-and-swap.
    seen: Mutex<HashMap<String, Option<String>>>,
}

#[derive(Default)]
pub struct PayerCheck<'a> {
    pub drain: bool,
    pub finalized_nonce: Option<&'a dyn Fn() -> Result<u64>>,
    pub finalized_block: Option<&'a PayerFinalityCheck<'a>>,
    pub fence: Option<&'a str>,
    /// Exact nonce to fence before invoking an EVM signer.
    pub signing_nonce: Option<u64>,
    /// Calls still to execute, including the packet about to be signed.
    pub remaining_calls: Option<u64>,
    pub max_nonce: Option<u64>,
    pub before_signing: Option<&'a PayerSigningCheck<'a>>,
}

pub type PayerSigningCheck<'a> = dyn Fn(&PayerCommitments) -> Result<()> + 'a;
pub type PayerFinalityCheck<'a> = dyn Fn(u64, &[u8; 32]) -> Result<bool> + 'a;

#[derive(Default)]
pub struct PayerCommitments {
    pub fees: BigUint,
    pub calls: u128,
    nonce_windows: Vec<(u64, Option<u64>)>,
    pub finalized_nonce: Option<u64>,
    pub contested_drain: bool,
    pub fence: Option<PayerFence>,
}

pub(crate) fn remaining_recovery_calls(
    plan: &Value,
    completed: u64,
    ordinary_used: u64,
) -> Result<u64> {
    let calls = undec64(plan["calls"].as_str().unwrap_or(""))?;
    let prior = undec64(
        plan["ordinary"]["attemptsBeforeFallback"]
            .as_str()
            .unwrap_or("0"),
    )?;
    let attempts = prior.saturating_sub(ordinary_used);
    let continuation = calls.saturating_sub(prior).saturating_sub(completed).max(1);
    continuation
        .checked_add(attempts)
        .ok_or_else(|| Error::Other("invalid recovery call count".into()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredRecoveryProgress {
    completed: Dec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continuation_gas: Option<Dec>,
}

pub(crate) struct RecoveryProgress {
    pub completed: u64,
    pub continuation_gas: Option<BigUint>,
}

impl RecoveryProgress {
    fn decode(value: &str) -> Result<Self> {
        let saved: StoredRecoveryProgress =
            serde_json::from_str(value).map_err(|e| Error::Other(e.to_string()))?;
        Ok(Self {
            completed: undec64(&saved.completed)?,
            continuation_gas: saved.continuation_gas.as_deref().map(undec).transpose()?,
        })
    }

    fn preferred_to(&self, previous: &Self) -> bool {
        self.completed > previous.completed
            || (self.completed == previous.completed
                && self.continuation_gas > previous.continuation_gas)
    }
}

pub(crate) fn remaining_recovery_fee(
    plan: &Value,
    progress: Option<&RecoveryProgress>,
    ordinary_used: u64,
    ceiling: Option<&BigUint>,
) -> Result<BigUint> {
    let total = undec(plan["totalFee"].as_str().unwrap_or(""))?;
    let ordinary = &plan["ordinary"];
    let Some(bid) = plan["envelope"]["maxFeePerGas"]
        .as_str()
        .or_else(|| ordinary["maxFeePerGas"].as_str())
    else {
        return Ok(total);
    };
    let admitted = undec(bid)?;
    let price = ceiling.unwrap_or(&admitted);
    if admitted == BigUint::default() || *price == BigUint::default() {
        return fail_d(Rule::CapacityPreflight, "invalid continuation fee ceiling");
    }
    let ordinary_gas = undec(ordinary["gas"].as_str().unwrap_or("0"))?;
    let prior = undec64(ordinary["attemptsBeforeFallback"].as_str().unwrap_or("0"))?;
    let spent = prior.min(ordinary_used);
    let attempts = prior - spent;
    if let Some(gas) = progress.and_then(|p| p.continuation_gas.as_ref()) {
        let route = if attempts > 0 {
            gas.max(&ordinary_gas)
        } else {
            gas
        };
        return Ok((route + BigUint::from(attempts) * &ordinary_gas) * price);
    }
    let consumed = BigUint::from(spent) * ordinary_gas * &admitted;
    if total <= consumed {
        return Ok(BigUint::default());
    }
    Ok(((total - consumed) * price + &admitted - 1u8) / admitted)
}

impl PayerCommitments {
    /// Last nonce this return may use while leaving feasible windows for the older returns.
    pub fn nonce_limit(&self, max_nonce: u64) -> Option<u64> {
        let mut windows = self
            .nonce_windows
            .iter()
            .map(|(calls, cap)| (cap.unwrap_or(max_nonce), *calls))
            .collect::<Vec<_>>();
        windows.sort_unstable();
        let mut used = 0u128;
        let mut limit = u128::from(max_nonce);
        for (cap, calls) in windows {
            used += u128::from(calls);
            limit = limit.min(u128::from(cap).checked_sub(used)?);
        }
        Some(limit as u64)
    }
}

pub struct PayerFence {
    key: String,
    attempt: String,
}

fn return_path(key: &str) -> Option<(&str, &str)> {
    let (domain, id) = key.strip_prefix("nb2/v1/")?.split_once("/return/")?;
    [domain, id]
        .into_iter()
        .all(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
        .then_some((domain, id))
}

impl Journal {
    pub fn new(store: Arc<dyn JournalStore>, domain: [u8; 32]) -> Self {
        Journal {
            prefix: format!("nb2/v1/{}/", to_hex(&domain)),
            store,
            domain,
            seen: Mutex::new(HashMap::new()),
        }
    }

    fn key(&self, kind: &str, id: Option<&str>) -> String {
        match id {
            None => format!("{}{kind}", self.prefix),
            Some(id) => format!("{}{kind}/{id}", self.prefix),
        }
    }

    /// Read a record. Only a read `for_update` (taken under the key's lock, by the operation that then writes the record)
    /// sets the `expected` of the next compare-and-swap; any other read leaves it alone, so an unlocked reader (`status`, a
    /// listing, a wallet's own look) can never move a locked operation's comparison past another process's write.
    fn read<T: Record>(&self, key: &str, for_update: bool) -> Result<Option<T>> {
        let s = self.store.get(key)?;
        if for_update {
            self.seen
                .lock()
                .expect("journal")
                .insert(key.to_string(), s.clone());
        }
        let Some(s) = s else { return Ok(None) };
        let bad = || {
            refuse(WalletReason::BadInput, format!("journal record {key} is not a version {JOURNAL_VERSION} {} record of this deployment", T::KIND))
        };
        let r: T = match serde_json::from_str(&s) {
            Ok(r) => r,
            Err(_) => return bad(),
        };
        let b = r.base();
        if b.format != JOURNAL_FORMAT
            || b.version != JOURNAL_VERSION
            || b.kind != T::KIND
            || b.domain != hex(&self.domain)
        {
            return bad();
        }
        Ok(Some(r))
    }

    /// Write a record and read it back: the plug-in proceeds only on a record that is in the store.
    fn write<T: Record>(&self, key: &str, r: &T) -> Result<()> {
        let s = serde_json::to_string(r).expect("a journal record serializes");
        let known = self.seen.lock().expect("journal").get(key).cloned();
        let expected = match known {
            Some(e) => e,
            None => self.store.get(key)?,
        };
        if expected.as_deref() == Some(s.as_str()) {
            return Ok(());
        }
        if !self.store.put_if(key, expected.as_deref(), &s)? {
            self.seen.lock().expect("journal").remove(key);
            return refuse(WalletReason::JournalConflict, format!("journal record {key} changed under this wallet (another process?): reload and retry"));
        }
        if self.store.get(key)?.as_deref() != Some(s.as_str()) {
            return refuse(
                WalletReason::JournalNotPersisted,
                format!("journal record {key} did not read back"),
            );
        }
        self.seen
            .lock()
            .expect("journal")
            .insert(key.to_string(), Some(s));
        Ok(())
    }

    pub fn base(&self, kind: &str) -> Base {
        Base {
            format: JOURNAL_FORMAT.into(),
            version: JOURNAL_VERSION,
            domain: hex(&self.domain),
            kind: kind.into(),
        }
    }

    pub fn intents(&self) -> Result<Option<IntentsRecord>> {
        self.read(&self.key("intents", None), false)
    }

    /// The intents record, read for the write that follows (under its lock).
    pub fn intents_for_update(&self) -> Result<Option<IntentsRecord>> {
        self.read(&self.key("intents", None), true)
    }

    pub fn put_intents(&self, r: &IntentsRecord) -> Result<()> {
        self.write(&self.key("intents", None), r)
    }

    pub fn deposit(&self, i: u64) -> Result<Option<DepositRecord>> {
        self.read(&self.key("deposit", Some(&dec(i))), false)
    }

    pub fn deposit_for_update(&self, i: u64) -> Result<Option<DepositRecord>> {
        self.read(&self.key("deposit", Some(&dec(i))), true)
    }

    pub fn put_deposit(&self, r: &DepositRecord) -> Result<()> {
        self.write(&self.key("deposit", Some(&r.intent)), r)
    }

    pub fn deposits(&self) -> Result<Vec<DepositRecord>> {
        let mut out = Vec::new();
        for k in self.store.list(&self.key("deposit/", None))? {
            if let Some(r) = self.read::<DepositRecord>(&k, false)? {
                out.push(r);
            }
        }
        let mut keyed = Vec::new();
        for r in out {
            keyed.push((undec(&r.intent)?, r));
        }
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(keyed.into_iter().map(|x| x.1).collect())
    }

    pub fn split(&self, id: &str) -> Result<Option<SplitRecord>> {
        self.read(&self.key("split", Some(id.get(2..).unwrap_or(""))), false)
    }

    pub fn split_for_update(&self, id: &str) -> Result<Option<SplitRecord>> {
        self.read(&self.key("split", Some(id.get(2..).unwrap_or(""))), true)
    }

    pub fn put_split(&self, r: &SplitRecord) -> Result<()> {
        self.write(
            &self.key("split", Some(r.split_id.get(2..).unwrap_or(""))),
            r,
        )
    }

    pub fn ret(&self, id: &str) -> Result<Option<ReturnRecord>> {
        self.read(&self.key("return", Some(id.get(2..).unwrap_or(""))), false)
    }

    pub fn ret_for_update(&self, id: &str) -> Result<Option<ReturnRecord>> {
        self.read(&self.key("return", Some(id.get(2..).unwrap_or(""))), true)
    }

    pub fn put_return(&self, r: &ReturnRecord) -> Result<()> {
        self.write(
            &self.key("return", Some(r.return_id.get(2..).unwrap_or(""))),
            r,
        )
    }

    pub fn returns(&self) -> Result<Vec<ReturnRecord>> {
        let mut out = Vec::new();
        for k in self.store.list(&self.key("return/", None))? {
            if let Some(r) = self.read::<ReturnRecord>(&k, false)? {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// Record the highest signed nonce before offering an exact transaction to any RPC.
    pub fn retain_payer_send(&self, record: &ReturnRecord, raw: &[u8]) -> Result<()> {
        let tx = decode_signed_tx(raw).map_err(Error::Other)?;
        let key = format!(
            "nb2/payer-sends/v1/{}/{}/{}/{}",
            tx.request.chain_id,
            to_hex(&tx.from),
            &record.base.domain[2..],
            &record.return_id[2..]
        );
        self.retain_payer_nonce(&key, tx.request.nonce)
    }

    fn retain_payer_nonce(&self, key: &str, nonce: u64) -> Result<()> {
        loop {
            let previous = self.store.get(key)?;
            if previous
                .as_deref()
                .map(undec64)
                .transpose()?
                .is_some_and(|n| n >= nonce)
                || self.store.put_if(key, previous.as_deref(), &dec(nonce))?
            {
                return Ok(());
            }
        }
    }

    /// Register separately retained signed packets before an upgraded wallet can reuse a payer.
    pub fn index_payer_sends(&self, record: &ReturnRecord, signed: &[&[u8]]) -> Result<()> {
        for raw in signed {
            self.retain_payer_send(record, raw)?;
        }
        self.store.put_if(
            &format!(
                "nb2/payer-index/v1/{}/{}",
                &record.base.domain[2..],
                &record.return_id[2..]
            ),
            None,
            "1",
        )?;
        Ok(())
    }

    /// Publish a replayed checkpoint. Readers check the exact block's execution finality before crediting it.
    pub(crate) fn index_recovery_progress(
        &self,
        chain_id: u64,
        record: &ReturnRecord,
        completed: u64,
        receipt: &super::recovery::RecoveryReceipt,
        continuation_gas: Option<BigUint>,
    ) -> Result<()> {
        let path = self.recovery_progress_path(chain_id, record)?;
        let key = format!(
            "{path}{}/{}",
            receipt.block_number,
            to_hex(&receipt.block_hash)
        );
        let progress = RecoveryProgress {
            completed,
            continuation_gas,
        };
        let value = serde_json::to_string(&StoredRecoveryProgress {
            completed: dec(completed),
            continuation_gas: progress.continuation_gas.as_ref().map(dec),
        })
        .expect("recovery progress encodes");
        loop {
            let previous = self.store.get(&key)?;
            if previous
                .as_deref()
                .map(RecoveryProgress::decode)
                .transpose()?
                .is_some_and(|saved| !progress.preferred_to(&saved))
                || self.store.put_if(&key, previous.as_deref(), &value)?
            {
                return Ok(());
            }
        }
    }

    fn recovery_progress_path(&self, chain_id: u64, record: &ReturnRecord) -> Result<String> {
        let plan = &record.extra["recovery"];
        let generation = plan["generation"].as_str().unwrap_or("");
        unhex_n::<32>(generation)?;
        let cuts = plan["runCuts"]
            .as_array()
            .ok_or_else(|| Error::Other("missing admitted Run cuts".into()))?;
        let cuts = cuts
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join(",");
        Ok(format!(
            "nb2/payer-progress/v2/{chain_id}/{}/{}/{}/{}/{}/{}/{cuts}/",
            &record.base.domain[2..],
            &record.return_id[2..],
            &generation[2..],
            plan["calls"].as_str().unwrap_or(""),
            plan["ordinary"]["attemptsBeforeFallback"]
                .as_str()
                .unwrap_or("0"),
            plan["advanceGaps"]
        ))
    }

    pub(crate) fn finalized_recovery_progress(
        &self,
        chain_id: u64,
        record: &ReturnRecord,
        finalized: Option<&PayerFinalityCheck<'_>>,
    ) -> Result<Option<RecoveryProgress>> {
        let mut progress = None;
        let Some(finalized) = finalized else {
            return Ok(None);
        };
        let path = self.recovery_progress_path(chain_id, record)?;
        for key in self.store.list(&path)? {
            let Some(value) = self.store.get(&key)? else {
                return refuse(
                    WalletReason::JournalNotPersisted,
                    "recovery checkpoint disappeared during payer reconciliation",
                );
            };
            let candidate = RecoveryProgress::decode(&value)?;
            if progress
                .as_ref()
                .is_some_and(|previous| !candidate.preferred_to(previous))
            {
                continue;
            }
            let (number, hash) = key[path.len()..]
                .split_once('/')
                .ok_or_else(|| Error::Other("invalid recovery checkpoint key".into()))?;
            if finalized(undec64(number)?, &unhex_n(&format!("0x{hash}"))?)? {
                progress = Some(candidate);
            }
        }
        Ok(progress)
    }

    fn other_payer_resources(
        &self,
        chain_id: u64,
        payer: &[u8],
        target: &str,
        owns_slot: bool,
        check: &PayerCheck<'_>,
    ) -> Result<PayerCommitments> {
        let address = hex(payer);
        let sends = format!("nb2/payer-sends/v1/{chain_id}/{}/", to_hex(payer));
        let (own_domain, own_id) = return_path(target).expect("validated journal key");
        let own_sends = format!("{sends}{own_domain}/{own_id}");
        let mut highest = None;
        let mut out = PayerCommitments::default();
        let mut draining = false;
        let mut include_nonce =
            |nonce| highest = Some(highest.map_or(nonce, |previous: u64| previous.max(nonce)));
        for key in self.store.list("nb2/v1/")? {
            let Some((domain, id)) = return_path(&key) else {
                continue;
            };
            let Some(raw) = self.store.get(&key)? else {
                return refuse(
                    WalletReason::JournalNotPersisted,
                    "return disappeared during payer reconciliation",
                );
            };
            let rec: ReturnRecord =
                serde_json::from_str(&raw).map_err(|err| Error::Other(err.to_string()))?;
            if rec.base.domain != format!("0x{domain}")
                || rec.return_id != format!("0x{id}")
                || rec.base.kind != "return"
                || rec.base.version != JOURNAL_VERSION
                || rec.base.format != JOURNAL_FORMAT
            {
                return refuse(WalletReason::BadInput, "invalid return in shared journal");
            }
            let executing =
                rec.extra.get("executionPayer").and_then(Value::as_str) == Some(&address);
            let active = rec.status != "planned"
                && rec.status != "paid"
                && rec.extra.contains_key("recovery")
                && (rec.payer.as_deref().unwrap_or(&rec.recipient) == address || executing);
            if key == target {
                draining = active;
                continue;
            }
            let mut ordinary = std::collections::BTreeSet::new();
            for send in &rec.sends {
                let tx = decode_signed_tx(&unhex(&send.raw)?).map_err(Error::Other)?;
                if tx.request.chain_id == chain_id && tx.from.as_slice() == payer {
                    include_nonce(tx.request.nonce);
                    ordinary.insert(tx.request.nonce);
                }
            }
            if self
                .store
                .get(&format!("nb2/domain-chain/v1/{domain}"))?
                .as_deref()
                .map(undec64)
                .transpose()?
                .is_some_and(|known| known != chain_id)
            {
                continue;
            }
            if rec.status != "planned"
                && executing
                && self
                    .store
                    .get(&format!("nb2/payer-index/v1/{domain}/{id}"))?
                    .as_deref()
                    != Some("1")
            {
                return fail_d(
                    Rule::CapacityPreflight,
                    "another return needs its local signed sends indexed",
                );
            }
            if active {
                let recovery = &rec.extra["recovery"];
                let progress =
                    self.finalized_recovery_progress(chain_id, &rec, check.finalized_block)?;
                let used = ordinary.len() as u64;
                out.fees += remaining_recovery_fee(recovery, progress.as_ref(), used, None)?;
                // The signed-nonce check below must pass before ordinary nonces count as used.
                let calls =
                    remaining_recovery_calls(recovery, progress.map_or(0, |p| p.completed), used)?;
                out.calls += u128::from(calls);
                let cap = recovery["envelope"]["maxNonce"]
                    .as_str()
                    .map(undec64)
                    .transpose()?;
                out.nonce_windows.push((calls, cap));
            }
        }
        for key in self.store.list(&sends)? {
            if key == own_sends {
                continue;
            }
            let Some(value) = self.store.get(&key)? else {
                return refuse(
                    WalletReason::JournalNotPersisted,
                    "signed nonce disappeared during payer reconciliation",
                );
            };
            include_nonce(undec64(&value)?);
        }
        if let Some(nonce) = highest {
            let finalized = check.finalized_nonce.map(|read| read()).transpose()?;
            if finalized.map_or(true, |finalized| finalized <= nonce) {
                return fail_d(
                    Rule::CapacityPreflight,
                    "payer has a local signed nonce awaiting finalization",
                );
            }
            out.finalized_nonce = finalized;
        }
        if out.calls != 0 && (!check.drain || (!draining && !owns_slot)) {
            return fail_d(
                Rule::CapacityPreflight,
                "payer already has an outstanding ERC20 return",
            );
        }
        Ok(out)
    }

    pub fn check_return_payer(
        &self,
        chain_id: u64,
        payer: &[u8],
        id: &str,
        reserve: bool,
    ) -> Result<()> {
        self.check_payer(chain_id, payer, id, reserve, &PayerCheck::default())
            .map(|_| ())
    }

    /// Admit one new return per payer. Existing funded returns can drain in sequence.
    pub fn check_payer(
        &self,
        chain_id: u64,
        payer: &[u8],
        id: &str,
        reserve: bool,
        check: &PayerCheck<'_>,
    ) -> Result<PayerCommitments> {
        if payer.len() != 20 {
            return refuse(WalletReason::BadInput, "invalid ERC20 payer");
        }
        if check.fence.is_some() && check.signing_nonce.is_some() {
            return refuse(
                WalletReason::BadInput,
                "payer claim cannot sign both a burn and an EVM packet",
            );
        }
        unhex_n::<32>(id)?;
        let domain_key = format!("nb2/domain-chain/v1/{}", to_hex(&self.domain));
        self.store.put_if(&domain_key, None, &dec(chain_id))?;
        if self.store.get(&domain_key)?.as_deref() != Some(&dec(chain_id)) {
            return refuse(
                WalletReason::BadInput,
                "journal domain has another chain ID",
            );
        }
        let key = format!("nb2/payer/v1/{chain_id}/{}", to_hex(payer));
        let target = self.key("return", Some(&id[2..]));
        loop {
            let held = self.store.get(&key)?;
            let held_text = held.as_deref().unwrap_or_default();
            let (owner, state) = held_text.split_once('#').unwrap_or((held_text, ""));
            let owns_slot = owner == target;
            let held_nonce = state.strip_prefix("nonce:").map(undec64).transpose()?;
            if !owns_slot && !owner.is_empty() {
                if return_path(owner).is_none() {
                    return refuse(WalletReason::BadInput, "invalid ERC20 payer reservation");
                }
                if !self
                    .store
                    .get(owner)?
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<ReturnRecord>(s).ok())
                    .is_some_and(|r| r.status == "paid" && r.paid.is_some())
                {
                    return fail_d(
                        Rule::CapacityPreflight,
                        "payer already has an outstanding ERC20 return",
                    );
                }
            }
            let mut out = self.other_payer_resources(chain_id, payer, &target, owns_slot, check)?;
            if let Some(nonce) = held_nonce.filter(|_| !owns_slot) {
                let finalized = match out.finalized_nonce {
                    Some(nonce) => Some(nonce),
                    None => check.finalized_nonce.map(|read| read()).transpose()?,
                };
                if finalized.map_or(true, |finalized| finalized <= nonce) {
                    return fail_d(
                        Rule::CapacityPreflight,
                        "payer has a local signing nonce awaiting finalization",
                    );
                }
                out.finalized_nonce = finalized;
                if reserve {
                    let (domain, id) = return_path(owner).expect("validated payer slot");
                    self.retain_payer_nonce(
                        &format!(
                            "nb2/payer-sends/v1/{chain_id}/{}/{domain}/{id}",
                            to_hex(payer)
                        ),
                        nonce,
                    )?;
                }
            }
            if !reserve {
                return Ok(out);
            }
            let mut claim = if owns_slot { held_text } else { &target }.to_owned();
            let contested_drain = !owns_slot && check.drain && out.calls > 0;
            out.contested_drain = contested_drain;
            if check.signing_nonce.is_some() || contested_drain {
                let Some(current) = self
                    .ret(id)?
                    .filter(|r| r.status != "paid" && r.status != "planned")
                else {
                    return fail_d(
                        Rule::CapacityPreflight,
                        "return is no longer eligible for payer signing",
                    );
                };
                let recovery = &current.extra["recovery"];
                let cap = recovery["envelope"]["maxNonce"]
                    .as_str()
                    .map(undec64)
                    .transpose()?
                    .unwrap_or(u64::MAX)
                    .min(check.max_nonce.unwrap_or(u64::MAX));
                let calls = if contested_drain {
                    match check.remaining_calls {
                        Some(calls) => calls,
                        None => {
                            let progress = self.finalized_recovery_progress(
                                chain_id,
                                &current,
                                check.finalized_block,
                            )?;
                            remaining_recovery_calls(
                                recovery,
                                progress.map_or(0, |p| p.completed),
                                0,
                            )?
                        }
                    }
                } else {
                    1
                };
                let Some(nonce) = check.signing_nonce.filter(|&nonce| {
                    calls > 0
                        && nonce >= out.finalized_nonce.unwrap_or(0)
                        && out.nonce_limit(cap).is_some_and(|limit| {
                            u128::from(nonce) + u128::from(calls) - 1 <= u128::from(limit)
                        })
                }) else {
                    return fail_d(
                        Rule::CapacityPreflight,
                        "remaining continuation schedule exceeds the payer nonce horizon",
                    );
                };
                if let Some(validate) = check.before_signing {
                    validate(&out)?;
                }
                let highest = held_nonce
                    .filter(|_| owns_slot)
                    .map_or(nonce, |n| n.max(nonce));
                claim = format!("{target}#nonce:{highest}");
            }
            let attempts = state.strip_prefix("burn:");
            if let Some(fence) = check.fence.filter(|_| !owns_slot || attempts.is_some()) {
                claim = match attempts.filter(|_| owns_slot) {
                    Some(attempts) => format!("{target}#burn:{attempts},{fence}"),
                    None => format!("{target}#burn:{fence}"),
                };
                out.fence = Some(PayerFence {
                    key: key.clone(),
                    attempt: fence.to_owned(),
                });
            }
            if claim == held_text && check.signing_nonce.is_none() {
                return Ok(out);
            }
            if !self.store.put_if(&key, held.as_deref(), &claim)? {
                continue;
            }
            return Ok(out);
        }
    }

    pub fn cancel_unsigned_return(&self, id: &str, fence: PayerFence) -> Result<()> {
        self.finish_return_attempt(id, fence, true)
    }

    pub fn retain_return_attempt(&self, id: &str, fence: PayerFence) -> Result<()> {
        self.finish_return_attempt(id, fence, false)
    }

    fn finish_return_attempt(&self, id: &str, fence: PayerFence, unsigned: bool) -> Result<()> {
        let target = self.key("return", Some(&id[2..]));
        let prefix = format!("{target}#burn:");
        loop {
            let Some(held) = self.store.get(&fence.key)? else {
                return Ok(());
            };
            let Some(attempts) = held.strip_prefix(&prefix) else {
                return Ok(());
            };
            let attempts = attempts.split(',').collect::<Vec<_>>();
            if !attempts.contains(&fence.attempt.as_str()) {
                return Ok(());
            }
            let next = if unsigned
                && self
                    .ret(id)?
                    .is_some_and(|r| r.status == "planned" && r.burn_request.is_none())
            {
                let remaining = attempts
                    .into_iter()
                    .filter(|attempt| *attempt != fence.attempt)
                    .collect::<Vec<_>>();
                if remaining.is_empty() {
                    String::new()
                } else {
                    format!("{prefix}{}", remaining.join(","))
                }
            } else {
                target.clone()
            };
            if self.store.put_if(&fence.key, Some(&held), &next)? {
                return Ok(());
            }
        }
    }
}

/// The `put_if` contract every wallet journal store must meet, as a check any store can run (its own tests, or a wallet's
/// start-up self-test against a scratch location). `fresh` opens an empty store; `reopen` opens the same storage again (a new
/// process after a crash would). It checks:
///
/// - compare-and-swap: a write against absence succeeds once; a second write against absence, or against any text but the
///   stored one, loses and changes nothing; a write against the stored text succeeds;
/// - atomicity: of `writers` concurrent writes against the same expected text exactly one wins, and the stored value is the
///   winner's;
/// - persistence: every value a winning `put_if` returned for is read back by a reopened store;
/// - `list`: the keys with a prefix, sorted.
///
/// This crate has no filesystem capability and ships no durable store: the wallet supplies one (for a file, write a temporary
/// file, fsync it, rename it over the record, fsync the directory, all under a lock that makes the comparison and the rename
/// one step) and runs this check against it.
pub fn check_journal_store<S: JournalStore + 'static>(
    fresh: impl Fn() -> S,
    reopen: impl Fn(&S) -> S,
    writers: usize,
) -> core::result::Result<(), String> {
    let fail = |m: &str| Err(format!("journal store: {m}"));
    let s = fresh();
    let (k, k2) = ("nb2/v1/conformance/a", "nb2/v1/conformance/b");
    let ok = |r: Result<bool>| r.map_err(|e| format!("journal store: {e}"));
    if s.get(k).map_err(|e| e.to_string())?.is_some() {
        return fail("a fresh store is not empty");
    }
    if !ok(s.put_if(k, None, "v1"))? {
        return fail("a write against absence lost on an empty key");
    }
    if ok(s.put_if(k, None, "v1b"))? {
        return fail("a second write against absence won");
    }
    if ok(s.put_if(k, Some("other"), "v1c"))? {
        return fail("a write against a stale text won");
    }
    if s.get(k).map_err(|e| e.to_string())?.as_deref() != Some("v1") {
        return fail("a lost write changed the record");
    }
    if !ok(s.put_if(k, Some("v1"), "v2"))? {
        return fail("a write against the stored text lost");
    }
    if !ok(s.put_if(k2, None, "w1"))? {
        return fail("a write of a second key lost");
    }
    let s = Arc::new(s);
    let wins: Vec<bool> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..writers)
            .map(|i| {
                let s = s.clone();
                sc.spawn(move || {
                    s.put_if(k, Some("v2"), &format!("race-{i}"))
                        .unwrap_or(false)
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap_or(false)).collect()
    });
    let winners: Vec<usize> = wins
        .iter()
        .enumerate()
        .filter(|(_, w)| **w)
        .map(|(i, _)| i)
        .collect();
    if winners.len() != 1 {
        return fail(&format!(
            "{} of {writers} concurrent writes against one text won",
            winners.len()
        ));
    }
    let want = format!("race-{}", winners[0]);
    if s.get(k).map_err(|e| e.to_string())?.as_deref() != Some(want.as_str()) {
        return fail("the stored value is not the winner's");
    }
    let s = Arc::try_unwrap(s).map_err(|_| "journal store: still shared".to_string())?;
    let again = reopen(&s);
    if again.get(k).map_err(|e| e.to_string())?.as_deref() != Some(want.as_str())
        || again.get(k2).map_err(|e| e.to_string())?.as_deref() != Some("w1")
    {
        return fail("a reopened store does not hold every won write");
    }
    if again
        .list("nb2/v1/conformance/")
        .map_err(|e| e.to_string())?
        != [k.to_string(), k2.to_string()]
    {
        return fail("list is not the sorted keys of the prefix");
    }
    Ok(())
}
