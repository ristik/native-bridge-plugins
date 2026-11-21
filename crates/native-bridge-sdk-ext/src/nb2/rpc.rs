//! Wallet evidence from the ordinary execution RPC behind the deployment's public gateway (section 12.7, NB2-06 #1102;
//! `rpc.ts`): one URL, JSON-RPC 2.0 POST, one request per call. Nothing read here is trusted: the adapters only fetch bytes,
//! and every piece of evidence is verified offline by the pure functions of this module tree. A provider that withholds or
//! falsifies data can only delay the wallet.
//!
//! Gateway rules honoured here: `eth_getLogs` names one address and an explicit window of at most 10,000 blocks (a result-count
//! error or the 8 MiB answer cap, HTTP 413, halves the window); 429 and a busy 503 are waited out; an HTTP 503 from
//! `eth_sendRawTransaction` is ambiguous (the transaction may still land, #1121), so it is reported as such and the caller
//! polls for the receipt of the locally computed hash.
//!
//! This crate has no network capability: the wallet supplies the HTTP transport ([`HttpPost`]) or a whole [`JsonRpc`].

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::{json, Value};

use super::abi::{decode_bytes_return, decode_state_return, selector, RawLog, VaultState};
use super::crypto::he;
use super::deposit::{encode_deposit_proof, topic, DepositProof};
use super::errors::{fail_d, refuse, Error, Result, Rule, WalletReason};
use super::header::{encode_header, Header};
use super::mpt::build_trie;
use super::rlp::{rlp_bytes, rlp_index_key, rlp_list, rlp_uint_enc};
use super::rules::check_companion;
use super::util::{from_hex, hex0x, to_hex, to_u64};

pub const LOG_BLOCK_RANGE: u64 = 10_000;

/// A JSON-RPC error object (`code != 0`), a gateway refusal (an HTTP status and its error text, `code == 0`), or a transport
/// failure (`status == 0`, `code == 0`).
#[derive(Debug, Clone, PartialEq)]
pub struct RpcError {
    pub status: u16,
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl core::fmt::Display for RpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.code != 0 {
            write!(f, "rpc error {}: {}", self.code, self.message)
        } else {
            write!(f, "gateway HTTP {}: {}", self.status, self.message)
        }
    }
}

impl From<RpcError> for Error {
    fn from(e: RpcError) -> Self {
        Error::Other(e.to_string())
    }
}

/// A JSON-RPC transport: one method call.
pub trait JsonRpc: Send + Sync {
    fn call(&self, method: &str, params: Value) -> core::result::Result<Value, RpcError>;
}

/// An HTTP POST of a JSON body: the response status and text, or a transport failure.
pub trait HttpPost: Send + Sync {
    fn post(
        &self,
        url: &str,
        body: &str,
        timeout_ms: u64,
    ) -> core::result::Result<(u16, String), String>;
}

/// The gateway client over a wallet-supplied HTTP transport.
pub struct HttpJsonRpc<P: HttpPost> {
    url: String,
    http: P,
    id: AtomicU64,
    /// Retries of a 429 or busy 503 (not of a send); default 10.
    pub retries: u32,
    pub timeout_ms: u64,
    pub sleep: Box<dyn Fn(u64) + Send + Sync>,
}

impl<P: HttpPost> HttpJsonRpc<P> {
    pub fn new(url: &str, http: P) -> Self {
        HttpJsonRpc {
            url: url.into(),
            http,
            id: AtomicU64::new(0),
            retries: 10,
            timeout_ms: 45_000,
            sleep: Box::new(|ms| std::thread::sleep(std::time::Duration::from_millis(ms))),
        }
    }

    fn once(&self, method: &str, params: &Value) -> core::result::Result<Value, RpcError> {
        let id = self.id.fetch_add(1, Ordering::Relaxed) + 1;
        let body =
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
        let (status, text) = self
            .http
            .post(&self.url, &body, self.timeout_ms)
            .map_err(|e| RpcError {
                status: 0,
                code: 0,
                message: e,
                data: None,
            })?;
        if status != 200 {
            let mut msg: String = text.chars().take(200).collect();
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
                    msg = e.into();
                }
            }
            return Err(RpcError {
                status,
                code: 0,
                message: msg,
                data: None,
            });
        }
        let env: Value = serde_json::from_str(&text).map_err(|e| RpcError {
            status: 200,
            code: 0,
            message: format!("not JSON: {e}"),
            data: None,
        })?;
        if let Some(e) = env.get("error").filter(|e| !e.is_null()) {
            return Err(RpcError {
                status: 200,
                code: e.get("code").and_then(|c| c.as_i64()).unwrap_or(-1),
                message: e
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .into(),
                data: e.get("data").cloned(),
            });
        }
        Ok(env.get("result").cloned().unwrap_or(Value::Null))
    }
}

impl<P: HttpPost> JsonRpc for HttpJsonRpc<P> {
    fn call(&self, method: &str, params: Value) -> core::result::Result<Value, RpcError> {
        let mut attempt = 0u32;
        loop {
            match self.once(method, &params) {
                Ok(v) => return Ok(v),
                Err(e) => {
                    let retryable =
                        e.status == 429 || (e.status == 503 && method != "eth_sendRawTransaction");
                    if !retryable || attempt >= self.retries {
                        return Err(e);
                    }
                    (self.sleep)((attempt as u64 + 1) * 500);
                    attempt += 1;
                }
            }
        }
    }
}

// ---- typed reads --------------------------------------------------------------------------------

pub fn qty(v: u64) -> String {
    format!("0x{v:x}")
}

pub fn bytes_of(s: &Value, what: &str) -> Result<Vec<u8>> {
    match s
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .and_then(from_hex)
    {
        Some(b) => Ok(b),
        None => refuse(WalletReason::ProviderFault, format!("{what} is not hex")),
    }
}

pub fn qty_of(s: &Value, what: &str) -> Result<BigUint> {
    let ok = s
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .filter(|h| !h.is_empty() && h.bytes().all(|c| c.is_ascii_hexdigit()));
    match ok.and_then(|h| BigUint::parse_bytes(h.as_bytes(), 16)) {
        Some(v) => Ok(v),
        None => refuse(
            WalletReason::ProviderFault,
            format!("{what} is not a quantity"),
        ),
    }
}

pub fn qty64(s: &Value, what: &str) -> Result<u64> {
    match to_u64(&qty_of(s, what)?) {
        Some(v) => Ok(v),
        None => refuse(
            WalletReason::ProviderFault,
            format!("{what} exceeds 64 bits"),
        ),
    }
}

fn fixed_of(s: &Value, n: usize, what: &str) -> Result<Vec<u8>> {
    let b = bytes_of(s, what)?;
    if b.len() != n {
        return refuse(
            WalletReason::ProviderFault,
            format!("{what} is not {n} bytes"),
        );
    }
    Ok(b)
}

/// The header fields of an `eth_getBlockBy*` answer, as the 20-field Cancun header.
pub fn header_of_json(j: &Value) -> Result<Header> {
    Ok(Header {
        parent_hash: fixed_of(&j["parentHash"], 32, "parentHash")?,
        ommers_hash: fixed_of(&j["sha3Uncles"], 32, "sha3Uncles")?,
        beneficiary: fixed_of(&j["miner"], 20, "miner")?,
        state_root: fixed_of(&j["stateRoot"], 32, "stateRoot")?,
        transactions_root: fixed_of(&j["transactionsRoot"], 32, "transactionsRoot")?,
        receipts_root: fixed_of(&j["receiptsRoot"], 32, "receiptsRoot")?,
        logs_bloom: fixed_of(&j["logsBloom"], 256, "logsBloom")?,
        difficulty: qty_of(&j["difficulty"], "difficulty")?,
        number: qty_of(&j["number"], "number")?,
        gas_limit: qty64(&j["gasLimit"], "gasLimit")?,
        gas_used: qty64(&j["gasUsed"], "gasUsed")?,
        timestamp: qty64(&j["timestamp"], "timestamp")?,
        extra_data: bytes_of(&j["extraData"], "extraData")?,
        mix_hash: fixed_of(&j["mixHash"], 32, "mixHash")?,
        nonce: fixed_of(&j["nonce"], 8, "nonce")?,
        base_fee_per_gas: qty_of(&j["baseFeePerGas"], "baseFeePerGas")?,
        withdrawals_root: fixed_of(&j["withdrawalsRoot"], 32, "withdrawalsRoot")?,
        blob_gas_used: qty64(&j["blobGasUsed"], "blobGasUsed")?,
        excess_blob_gas: qty64(&j["excessBlobGas"], "excessBlobGas")?,
        parent_beacon_block_root: fixed_of(
            &j["parentBeaconBlockRoot"],
            32,
            "parentBeaconBlockRoot",
        )?,
    })
}

/// A log of a receipt answer.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptLogJson {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    #[serde(default)]
    pub log_index: Option<String>,
}

/// An `eth_getTransactionReceipt` answer.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptJson {
    #[serde(default, rename = "type")]
    pub ty: Option<String>,
    pub status: String,
    pub cumulative_gas_used: String,
    pub logs_bloom: String,
    pub logs: Vec<ReceiptLogJson>,
    pub block_hash: String,
    pub block_number: String,
    pub transaction_index: String,
    pub transaction_hash: String,
}

impl ReceiptJson {
    pub fn parse(v: Value) -> Result<Self> {
        serde_json::from_value(v).map_err(|e| {
            super::errors::wallet_err(WalletReason::ProviderFault, format!("not a receipt: {e}"))
        })
    }

    /// status == 1.
    pub fn success(&self) -> bool {
        qty_of(&json!(self.status), "status").is_ok_and(|s| s == BigUint::from(1u8))
    }
}

/// The consensus encoding of a receipt: a legacy RLP list, or type || RLP(...) for types 1..3.
pub fn encode_receipt_json(r: &ReceiptJson) -> Result<Vec<u8>> {
    let mut logs = Vec::new();
    for l in &r.logs {
        let mut topics = Vec::new();
        for t in &l.topics {
            topics.push(rlp_bytes(&fixed_of(&json!(t), 32, "topic")?));
        }
        logs.push(rlp_list(&[
            rlp_bytes(&fixed_of(&json!(l.address), 20, "log address")?),
            rlp_list(&topics),
            rlp_bytes(&bytes_of(&json!(l.data), "log data")?),
        ]));
    }
    let body = rlp_list(&[
        rlp_uint_enc(&qty_of(&json!(r.status), "status")?),
        rlp_uint_enc(&qty_of(&json!(r.cumulative_gas_used), "cumulativeGasUsed")?),
        rlp_bytes(&fixed_of(&json!(r.logs_bloom), 256, "logsBloom")?),
        rlp_list(&logs),
    ]);
    let ty = match &r.ty {
        None => 0u64,
        Some(t) => qty64(&json!(t), "type")?,
    };
    Ok(if ty == 0 {
        body
    } else {
        super::util::cat(&[&[ty as u8], &body])
    })
}

pub fn raw_log_of(l: &Value) -> Result<RawLog> {
    let topics = match l["topics"].as_array() {
        Some(t) => t
            .iter()
            .map(|t| fixed_of(t, 32, "topic"))
            .collect::<Result<Vec<_>>>()?,
        None => return refuse(WalletReason::ProviderFault, "log topics"),
    };
    Ok(RawLog {
        address: fixed_of(&l["address"], 20, "address")?,
        topics,
        data: bytes_of(&l["data"], "data")?,
        block_number: qty64(&l["blockNumber"], "blockNumber")?,
        block_hash: fixed_of(&l["blockHash"], 32, "blockHash")?,
        transaction_hash: fixed_of(&l["transactionHash"], 32, "transactionHash")?,
        log_index: qty64(&l["logIndex"], "logIndex")?,
        removed: l["removed"] == json!(true),
    })
}

/// A built receipt proof and the facts it was built from.
#[derive(Debug, Clone)]
pub struct ReceiptProof {
    pub proof: DepositProof,
    pub encoded: Vec<u8>,
    pub block_number: u64,
    pub block_hash: Vec<u8>,
    pub log: RawLog,
    pub receipt_log_index: usize,
}

/// The outcome of `eth_estimateGas`: the gas, or the revert (its data when the RPC carried it) and message.
#[derive(Debug, Clone, PartialEq)]
pub enum Estimate {
    Gas(u64),
    Revert {
        data: Option<Vec<u8>>,
        message: String,
    },
}

/// An `eth_sendRawTransaction` failure.
#[derive(Debug, Clone, PartialEq)]
pub enum SendError {
    /// HTTP 503 ("broadcast may be partial"): the transaction may still be included; poll its receipt before any resubmission.
    Ambiguous {
        tx_hash: [u8; 32],
        detail: String,
    },
    Failed(Error),
}

/// The typed RPC reads the wallet uses.
pub struct EvmReader<R: JsonRpc + ?Sized> {
    pub rpc: std::sync::Arc<R>,
}

fn call<R: JsonRpc + ?Sized>(rpc: &R, method: &str, params: Value) -> Result<Value> {
    rpc.call(method, params).map_err(Error::from)
}

impl<R: JsonRpc + ?Sized> EvmReader<R> {
    pub fn new(rpc: std::sync::Arc<R>) -> Self {
        EvmReader { rpc }
    }

    pub fn block_number(&self) -> Result<u64> {
        qty64(
            &call(&*self.rpc, "eth_blockNumber", json!([]))?,
            "eth_blockNumber",
        )
    }

    pub fn chain_id(&self) -> Result<u64> {
        qty64(&call(&*self.rpc, "eth_chainId", json!([]))?, "eth_chainId")
    }

    pub fn receipt(&self, tx_hash: &[u8]) -> Result<Option<ReceiptJson>> {
        let v = call(
            &*self.rpc,
            "eth_getTransactionReceipt",
            json!([hex0x(tx_hash)]),
        )?;
        if v.is_null() {
            return Ok(None);
        }
        Ok(Some(ReceiptJson::parse(v)?))
    }

    /// The header of a block by hash, as its exact RLP, which must hash to the requested hash.
    pub fn header_by_hash(&self, hash: &[u8]) -> Result<(Header, Vec<u8>)> {
        let j = call(
            &*self.rpc,
            "eth_getBlockByHash",
            json!([hex0x(hash), false]),
        )?;
        if j.is_null() {
            return fail_d(
                Rule::EvidencePruned,
                format!("block 0x{} is not held by this node", to_hex(hash)),
            );
        }
        let header = header_of_json(&j)?;
        let raw = encode_header(&header);
        if he(&[&raw]) != hash {
            return refuse(
                WalletReason::ProviderFault,
                format!(
                    "the header served for 0x{} does not re-encode to its hash",
                    to_hex(hash)
                ),
            );
        }
        Ok((header, raw))
    }

    /// The header of a block by number and its hash (the hash of its exact re-encoding); None when the node does not hold it.
    pub fn header_by_number(&self, n: u64) -> Result<Option<(Header, [u8; 32])>> {
        let j = call(&*self.rpc, "eth_getBlockByNumber", json!([qty(n), false]))?;
        if j.is_null() {
            return Ok(None);
        }
        let header = header_of_json(&j)?;
        let hash = he(&[&encode_header(&header)]);
        Ok(Some((header, hash)))
    }

    /// The certificate of block N: witness 0 of the companion of its child N+1 (section 12.7). Not yet served while the child
    /// does not exist (`CompanionUnknown`, retry after a round); `EvidencePruned` below the node's horizon.
    pub fn certificate_of(&self, header: &Header, hash: &[u8]) -> Result<Vec<u8>> {
        let n = header.number_u64();
        let child = call(
            &*self.rpc,
            "eth_getBlockByNumber",
            json!([
                qty(n.checked_add(1).ok_or_else(|| super::errors::wallet_err(
                    WalletReason::ProviderFault,
                    "a block number at the u64 bound"
                ))?),
                false
            ]),
        )?;
        if child.is_null() {
            return refuse(WalletReason::CompanionUnknown, format!("block {n} has no child yet: its certificate is not served; retry after a round"));
        }
        let child_header = header_of_json(&child)?;
        if child_header.parent_hash != hash {
            return refuse(
                WalletReason::CompanionUnknown,
                format!("block {n} is not on this node's canonical chain"),
            );
        }
        let child_hash = he(&[&encode_header(&child_header)]);
        let l = call(
            &*self.rpc,
            "unicity_getSealCompanionV1",
            json!([hex0x(&child_hash)]),
        )?;
        let empty = Vec::new();
        let witnesses = l["companion"]["witnesses"]
            .as_array()
            .or_else(|| l["witnesses"].as_array())
            .unwrap_or(&empty);
        check_companion(l["status"].as_str().unwrap_or(""), witnesses.len())?;
        bytes_of(&witnesses[0], "companion witness 0")
    }

    /// The root-to-leaf receipt-trie path of RLP(txIndex), from the block's receipts, whose trie must hash to the header's root.
    pub fn receipt_path(
        &self,
        header: &Header,
        hash: &[u8],
        tx_index: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let n = header.number_u64();
        let receipts = match self.rpc.call("eth_getBlockReceipts", json!([hex0x(hash)])) {
            Ok(v) => v,
            // an answer over the gateway's 8 MiB cap is not served by this gateway: use another provider for this block
            Err(e) if e.status == 413 => return refuse(WalletReason::ProviderFault, format!("the receipts of block {n} exceed this gateway's answer cap: use another provider")),
            Err(e) => return Err(e.into()),
        };
        if receipts.is_null() {
            return fail_d(
                Rule::EvidencePruned,
                format!("the receipts of block {n} are not served"),
            );
        }
        let Some(list) = receipts.as_array() else {
            return refuse(
                WalletReason::ProviderFault,
                "eth_getBlockReceipts is not a list",
            );
        };
        if tx_index >= list.len() as u64 {
            return refuse(
                WalletReason::ProviderFault,
                format!("block {n} has {} receipts, no index {tx_index}", list.len()),
            );
        }
        let mut entries = Vec::with_capacity(list.len());
        for (i, r) in list.iter().enumerate() {
            entries.push((
                rlp_index_key(i as u64),
                encode_receipt_json(&ReceiptJson::parse(r.clone())?)?,
            ));
        }
        let (root, path) = build_trie(&entries, Some(&rlp_index_key(tx_index)));
        if root.as_slice() != header.receipts_root.as_slice() {
            return refuse(
                WalletReason::ProviderFault,
                format!("the receipts served for block {n} do not hash to its receiptsRoot"),
            );
        }
        Ok(path)
    }

    /// The DepositProof container for the first log of `tx_hash` emitted by `emitter` with `topic0`.
    pub fn receipt_proof(
        &self,
        tx_hash: &[u8],
        emitter: &[u8],
        topic0: &[u8],
    ) -> Result<ReceiptProof> {
        let Some(r) = self.receipt(tx_hash)? else {
            return refuse(
                WalletReason::EvidenceMissing,
                format!(
                    "transaction 0x{} has no receipt on this node (pending, unknown or pruned)",
                    to_hex(tx_hash)
                ),
            );
        };
        if !r.success() {
            return refuse(
                WalletReason::Reverted,
                format!(
                    "transaction 0x{} failed: its logs never count",
                    to_hex(tx_hash)
                ),
            );
        }
        let mut idx = None;
        for (i, l) in r.logs.iter().enumerate() {
            let addr = bytes_of(&json!(l.address), "address")?;
            if addr == emitter
                && !l.topics.is_empty()
                && bytes_of(&json!(l.topics[0]), "topic")? == topic0
            {
                idx = Some(i);
                break;
            }
        }
        let Some(idx) = idx else {
            return refuse(
                WalletReason::EvidenceMissing,
                format!(
                    "transaction 0x{} emitted no such log from 0x{}",
                    to_hex(tx_hash),
                    to_hex(emitter)
                ),
            );
        };
        let block_hash = fixed_of(&json!(r.block_hash), 32, "blockHash")?;
        let (header, raw) = self.header_by_hash(&block_hash)?;
        let uc = self.certificate_of(&header, &block_hash)?;
        let tx_index = qty64(&json!(r.transaction_index), "transactionIndex")?;
        let nodes = self.receipt_path(&header, &block_hash, tx_index)?;
        let proof = DepositProof {
            uc,
            header: raw,
            tx_index,
            log_index: idx as u64,
            nodes,
        };
        let l = &r.logs[idx];
        let log = RawLog {
            address: emitter.to_vec(),
            topics: l
                .topics
                .iter()
                .map(|x| fixed_of(&json!(x), 32, "topic"))
                .collect::<Result<Vec<_>>>()?,
            data: bytes_of(&json!(l.data), "data")?,
            block_number: header.number_u64(),
            block_hash: block_hash.clone(),
            transaction_hash: tx_hash.to_vec(),
            log_index: match &l.log_index {
                None => idx as u64,
                Some(x) => qty64(&json!(x), "logIndex")?,
            },
            removed: false,
        };
        Ok(ReceiptProof {
            encoded: encode_deposit_proof(&proof),
            block_number: header.number_u64(),
            proof,
            block_hash,
            log,
            receipt_log_index: idx,
        })
    }

    /// `eth_getLogs` of `address` and `topics` over [from, to], in gateway windows, in order; a result-count error halves the window.
    pub fn logs(&self, address: &[u8], topics: &Value, from: u64, to: u64) -> Result<Vec<RawLog>> {
        let mut out = Vec::new();
        let mut lo = from;
        while lo <= to {
            let mut hi = if lo.saturating_add(LOG_BLOCK_RANGE - 1) < to {
                lo.saturating_add(LOG_BLOCK_RANGE - 1)
            } else {
                to
            };
            loop {
                let params = json!([{"address": hex0x(address), "topics": topics, "fromBlock": qty(lo), "toBlock": qty(hi)}]);
                match self.rpc.call("eth_getLogs", params) {
                    Ok(page) => {
                        let Some(page) = page.as_array() else {
                            return refuse(
                                WalletReason::ProviderFault,
                                "eth_getLogs is not a list",
                            );
                        };
                        for l in page {
                            if l["removed"] != json!(true) {
                                out.push(raw_log_of(l)?);
                            }
                        }
                        break;
                    }
                    Err(e) => {
                        // the node's result-count error, or the gateway's 8 MiB answer cap (HTTP 413): ask for less
                        let m = e.message.to_lowercase();
                        if (e.status == 413
                            || m.contains("max results")
                            || m.contains("too many")
                            || m.contains("exceed"))
                            && hi > lo
                        {
                            hi = lo + (hi - lo) / 2;
                            continue;
                        }
                        return Err(e.into());
                    }
                }
            }
            match hi.checked_add(1) {
                Some(x) => lo = x,
                None => break,
            }
        }
        Ok(out)
    }

    /// The newest SegmentSealed log of the vault at or after `from`, paging backwards from the head; None when it never sealed.
    pub fn newest_seal(&self, vault: &[u8], from: u64) -> Result<Option<RawLog>> {
        let top = self.block_number()?;
        let mut hi = top;
        while hi >= from {
            let lo = if hi >= from.saturating_add(LOG_BLOCK_RANGE) {
                hi - LOG_BLOCK_RANGE + 1
            } else {
                from
            };
            let mut page = self.logs(vault, &json!([hex0x(&topic::segment_sealed())]), lo, hi)?;
            if let Some(l) = page.pop() {
                return Ok(Some(l));
            }
            if lo == from || lo == 0 {
                break;
            }
            hi = lo - 1;
        }
        Ok(None)
    }

    /// The SegmentSealed logs of segments [start, end) in order, paging forwards from `from` (a block at or before segment
    /// `start`'s seal).
    pub fn segment_logs(
        &self,
        vault: &[u8],
        from: u64,
        start: u64,
        end: u64,
    ) -> Result<Vec<RawLog>> {
        if end <= start {
            return Ok(Vec::new());
        }
        let top = self.block_number()?;
        let mut want: BTreeMap<u64, RawLog> = BTreeMap::new();
        let mut lo = from;
        while lo <= top && (want.len() as u64) < end - start {
            let hi = if lo.saturating_add(LOG_BLOCK_RANGE - 1) < top {
                lo.saturating_add(LOG_BLOCK_RANGE - 1)
            } else {
                top
            };
            for l in self.logs(vault, &json!([hex0x(&topic::segment_sealed())]), lo, hi)? {
                if l.topics.len() != 2 {
                    continue;
                }
                let j = super::util::be_int(&l.topics[1]);
                // a second log for one index is a provider fault: the chain link check refuses whichever is wrong
                if let Some(j) = to_u64(&j) {
                    if j >= start && j < end {
                        want.entry(j).or_insert(l);
                    }
                }
            }
            match lo.checked_add(LOG_BLOCK_RANGE) {
                Some(x) => lo = x,
                None => break,
            }
        }
        let mut out = Vec::new();
        for j in start..end {
            // a missing log is missing evidence, never absence
            match want.remove(&j) {
                Some(l) => out.push(l),
                None => {
                    return refuse(
                        WalletReason::EvidenceMissing,
                        format!("no SegmentSealed log of segment {j} was served"),
                    )
                }
            }
        }
        Ok(out)
    }

    /// `Paid(eta)` logs of the vault from block `from`.
    pub fn paid(&self, vault: &[u8], eta: &[u8], from: u64) -> Result<Vec<RawLog>> {
        let top = self.block_number()?;
        if top < from {
            return Ok(Vec::new());
        }
        self.logs(
            vault,
            &json!([hex0x(&topic::paid()), hex0x(eta)]),
            from,
            top,
        )
    }

    pub fn call(&self, to: &[u8], data: &[u8], from: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut tx = json!({"to": hex0x(to), "data": hex0x(data)});
        if let Some(f) = from {
            tx["from"] = json!(hex0x(f));
        }
        bytes_of(
            &call(&*self.rpc, "eth_call", json!([tx, "latest"]))?,
            "eth_call",
        )
    }

    pub fn vault_state(&self, vault: &[u8]) -> Result<VaultState> {
        match decode_state_return(&self.call(vault, &selector::state(), None)?) {
            Some(s) => Ok(s),
            None => Err(Error::Other(
                "nb2: state() returned other than 192 bytes".into(),
            )),
        }
    }

    pub fn vault_config(&self, vault: &[u8]) -> Result<Vec<u8>> {
        match decode_bytes_return(&self.call(vault, &selector::config(), None)?) {
            Some(b) => Ok(b),
            None => Err(Error::Other("nb2: not an ABI bytes return".into())),
        }
    }

    pub fn code(&self, address: &[u8]) -> Result<Vec<u8>> {
        bytes_of(
            &call(&*self.rpc, "eth_getCode", json!([hex0x(address), "latest"]))?,
            "eth_getCode",
        )
    }

    pub fn balance(&self, address: &[u8]) -> Result<BigUint> {
        qty_of(
            &call(
                &*self.rpc,
                "eth_getBalance",
                json!([hex0x(address), "latest"]),
            )?,
            "eth_getBalance",
        )
    }

    /// The account nonce: "pending" counts the pool (for signing), "latest" only mined transactions (for deciding a send is dead).
    pub fn nonce(&self, address: &[u8], tag: &str) -> Result<u64> {
        qty64(
            &call(
                &*self.rpc,
                "eth_getTransactionCount",
                json!([hex0x(address), tag]),
            )?,
            "eth_getTransactionCount",
        )
    }

    /// The base fee of the latest block and a priority fee.
    pub fn fees(&self) -> Result<(BigUint, BigUint)> {
        let latest = call(&*self.rpc, "eth_getBlockByNumber", json!(["latest", false]))?;
        let base_fee = qty_of(&latest["baseFeePerGas"], "baseFeePerGas")?;
        let mut priority = BigUint::from(1_000_000_000u64);
        // optional on the gateway
        if let Ok(v) = self.rpc.call("eth_maxPriorityFeePerGas", json!([])) {
            if let Ok(p) = qty_of(&v, "eth_maxPriorityFeePerGas") {
                priority = p;
            }
        }
        Ok((base_fee, priority))
    }

    /// `eth_estimateGas`; a revert is returned as its data (for classification), never as success.
    pub fn estimate_gas(
        &self,
        from: &[u8],
        to: &[u8],
        data: &[u8],
        value: impl core::fmt::LowerHex,
    ) -> Result<Estimate> {
        let params = json!([{"from": hex0x(from), "to": hex0x(to), "data": hex0x(data), "value": format!("0x{value:x}")}]);
        match self.rpc.call("eth_estimateGas", params) {
            Ok(g) => Ok(Estimate::Gas(qty64(&g, "eth_estimateGas")?)),
            Err(e) if e.code != 0 => Ok(Estimate::Revert {
                data: revert_data_of(&e),
                message: e.message,
            }),
            Err(e) => Err(e.into()),
        }
    }

    /// Submit a signed raw transaction; an HTTP 503 is [`SendError::Ambiguous`].
    pub fn send_raw(&self, raw: &[u8]) -> core::result::Result<[u8; 32], SendError> {
        let hash = he(&[raw]);
        match self.rpc.call("eth_sendRawTransaction", json!([hex0x(raw)])) {
            Ok(_) => Ok(hash),
            Err(e) if e.status == 503 => Err(SendError::Ambiguous {
                tx_hash: hash,
                detail: e.message,
            }),
            Err(e) => {
                let m = e.message.to_lowercase();
                if m.contains("already known") || m.contains("nonce too low") {
                    Ok(hash)
                } else {
                    Err(SendError::Failed(e.into()))
                }
            }
        }
    }
}

/// The revert data an RPC error carries (`data` of the error object is not kept by every client; the message may embed it).
pub fn revert_data_of(e: &RpcError) -> Option<Vec<u8>> {
    if let Some(d) = e
        .data
        .as_ref()
        .and_then(|d| d.as_str())
        .and_then(|d| d.strip_prefix("0x"))
    {
        return from_hex(d);
    }
    // the first 0x followed by at least 8 hex digits; byte-wise, so any message text is safe
    let b = e.message.as_bytes();
    let mut i = 0;
    while i + 2 <= b.len() {
        if &b[i..i + 2] == b"0x" {
            let run = b[i + 2..]
                .iter()
                .take_while(|c| c.is_ascii_hexdigit())
                .count();
            if run >= 8 {
                // an odd-length run is not hex: None, as the TypeScript fromHex
                return core::str::from_utf8(&b[i + 2..i + 2 + run])
                    .ok()
                    .and_then(from_hex);
            }
        }
        i += 1;
    }
    None
}
