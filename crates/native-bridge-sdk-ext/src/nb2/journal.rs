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

use super::errors::{refuse, Result, WalletReason};
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
