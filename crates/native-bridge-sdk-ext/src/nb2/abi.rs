//! The vault ABI (section 13; `abi.ts`): calldata of its functions, its views and events, and the custom errors with their exact
//! revert data. A failed simulation or transaction is classified by selector into what the wallet does next (section 13.3).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use num_bigint::BigUint;

use super::crypto::he;
use super::deposit::topic;
use super::errors::Rule;
use super::util::{arr, be_int, cat, to_u64, u256, u256_64};

fn sel(sig: &str) -> [u8; 4] {
    arr(&he(&[sig.as_bytes()])[..4])
}

/// The function selectors.
pub mod selector {
    pub fn deposit() -> [u8; 4] {
        super::sel("deposit(bytes,bytes32)")
    }
    pub fn redeem() -> [u8; 4] {
        super::sel("redeem(bytes,bytes32,uint64,bytes)")
    }
    pub fn domain() -> [u8; 4] {
        super::sel("domain()")
    }
    pub fn config() -> [u8; 4] {
        super::sel("config()")
    }
    pub fn state() -> [u8; 4] {
        super::sel("state()")
    }
    pub fn verify_return() -> [u8; 4] {
        super::sel("verifyReturn(bytes,bytes)")
    }
}

/// The vault errors with arguments (section 13.3); every other rule is `<Name>()`.
pub fn error_signature(r: Rule) -> Option<&'static str> {
    Some(match r {
        Rule::LiabilityCap => "LiabilityCap(uint256,uint256,uint256)",
        Rule::BadHistoryLength => "BadHistoryLength(uint256)",
        Rule::FutureIndex => "FutureIndex(uint64,uint64)",
        Rule::StaleEndpoint => "StaleEndpoint(uint64,uint64)",
        Rule::BadGapProof => "BadGapProof(uint256)",
        Rule::AlreadyPaid => "AlreadyPaid(bytes32)",
        Rule::VerifierRefused => "VerifierRefused(bytes)",
        Rule::LiabilityUnderflow => "LiabilityUnderflow(uint256,uint256)",
        Rule::BadConfig => "BadConfig(uint256)",
        _ => return None,
    })
}

pub fn signature_of(r: Rule) -> String {
    match error_signature(r) {
        Some(s) => String::from(s),
        None => alloc::format!("{}()", r.name()),
    }
}

pub fn selector_of(r: Rule) -> [u8; 4] {
    sel(&signature_of(r))
}

fn arg_types(r: Rule) -> Vec<String> {
    let sig = signature_of(r);
    let open = sig.find('(').expect("a signature");
    sig[open + 1..sig.len() - 1]
        .split(',')
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect()
}

fn pad32(b: &[u8]) -> Vec<u8> {
    let mut out = b.to_vec();
    out.resize(b.len() + (32 - b.len() % 32) % 32, 0);
    out
}

/// One ABI argument: a static word or dynamic bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiArg {
    Word([u8; 32]),
    Bytes(Vec<u8>),
}

/// Standard ABI of (static words..., dynamic bytes...) arguments given in order.
pub fn abi_encode(args: &[AbiArg]) -> Vec<u8> {
    let mut heads = Vec::new();
    let mut tails = Vec::new();
    for a in args {
        match a {
            AbiArg::Word(w) => heads.extend_from_slice(w),
            AbiArg::Bytes(b) => {
                heads.extend_from_slice(&u256_64((32 * args.len() + tails.len()) as u64));
                tails.extend_from_slice(&u256_64(b.len() as u64));
                tails.extend_from_slice(&pad32(b));
            }
        }
    }
    cat(&[&heads, &tails])
}

/// A value of a vault error's argument: an integer, a 32-byte word or bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrArg {
    Int(BigUint),
    Word(Vec<u8>),
}

/// The exact revert data of a vault or verifier rule with its arguments (`bytes` arguments as `Word` of any length).
pub fn revert_data(r: Rule, vals: &[ErrArg]) -> Vec<u8> {
    let types = arg_types(r);
    if vals.is_empty() || types.is_empty() {
        return selector_of(r).to_vec();
    }
    let args: Vec<AbiArg> = vals
        .iter()
        .enumerate()
        .map(|(i, v)| match (types[i].as_str(), v) {
            ("bytes", ErrArg::Word(b)) => AbiArg::Bytes(b.clone()),
            (_, ErrArg::Int(x)) => AbiArg::Word(u256(x)),
            (_, ErrArg::Word(w)) => AbiArg::Word(arr(w)),
        })
        .collect();
    cat(&[&selector_of(r), &abi_encode(&args)])
}

pub fn deposit_calldata(first_owner: &[u8], rho: &[u8]) -> Vec<u8> {
    cat(&[
        &selector::deposit(),
        &abi_encode(&[AbiArg::Bytes(first_owner.to_vec()), AbiArg::Word(arr(rho))]),
    ])
}

pub fn redeem_calldata(
    evidence: &[u8],
    claimed_eta: &[u8],
    claimed_start: u64,
    history: &[u8],
) -> Vec<u8> {
    cat(&[
        &selector::redeem(),
        &abi_encode(&[
            AbiArg::Bytes(evidence.to_vec()),
            AbiArg::Word(arr(claimed_eta)),
            AbiArg::Word(u256_64(claimed_start)),
            AbiArg::Bytes(history.to_vec()),
        ]),
    ])
}

/// The calldata length of a redeem with `evidence` bytes and `history` bytes (selector, four heads, two length words, padding).
pub fn redeem_calldata_length(evidence: usize, history: usize) -> usize {
    4 + 4 * 32 + 32 + evidence.div_ceil(32) * 32 + 32 + history.div_ceil(32) * 32
}

/// The state() view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultState {
    pub deposits: u64,
    pub segment: u64,
    pub population: u64,
    pub outstanding: BigUint,
    pub head: [u8; 32],
    pub previous_head: [u8; 32],
}

pub fn decode_state_return(b: &[u8]) -> Option<VaultState> {
    if b.len() != 192 {
        return None;
    }
    let w = |i: usize| &b[32 * i..32 * i + 32];
    Some(VaultState {
        deposits: to_u64(&be_int(w(0)))?,
        segment: to_u64(&be_int(w(1)))?,
        population: to_u64(&be_int(w(2)))?,
        outstanding: be_int(w(3)),
        head: arr(w(4)),
        previous_head: arr(w(5)),
    })
}

/// A `bytes` return (config()).
pub fn decode_bytes_return(b: &[u8]) -> Option<Vec<u8>> {
    if b.len() < 64 || be_int(&b[..32]) != BigUint::from(32u8) {
        return None;
    }
    let n = to_u64(&be_int(&b[32..64]))? as usize;
    if b.len() != 64 + n.div_ceil(32) * 32 {
        return None;
    }
    Some(b[64..64 + n].to_vec())
}

/// A decoded vault or verifier error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedError {
    pub rule: Rule,
    pub args: Vec<ErrArg>,
    pub raw: Vec<u8>,
    pub inner: Option<Box<DecodedError>>,
}

/// Decode revert data by selector; None for data that names no rule (an out-of-gas or a plain revert).
pub fn decode_revert(data: &[u8]) -> Option<DecodedError> {
    if data.len() < 4 {
        return None;
    }
    let rule = *Rule::ALL.iter().find(|r| selector_of(**r) == data[..4])?;
    let types = arg_types(rule);
    let body = &data[4..];
    let parse = || -> Option<(Vec<ErrArg>, Option<Box<DecodedError>>)> {
        let mut args = Vec::new();
        let mut inner = None;
        for (i, t) in types.iter().enumerate() {
            let w = body.get(32 * i..32 * i + 32)?;
            if t == "bytes" {
                let off = to_u64(&be_int(w))? as usize;
                let n = to_u64(&be_int(body.get(off..off.checked_add(32)?)?))? as usize;
                let v = body.get(off + 32..(off + 32).checked_add(n)?)?.to_vec();
                if rule == Rule::VerifierRefused {
                    inner = decode_revert(&v).map(Box::new);
                }
                args.push(ErrArg::Word(v));
            } else if t == "bytes32" {
                args.push(ErrArg::Word(w.to_vec()));
            } else {
                args.push(ErrArg::Int(be_int(w)));
            }
        }
        Some((args, inner))
    };
    Some(match parse() {
        Some((args, inner)) => DecodedError {
            rule,
            args,
            raw: data.to_vec(),
            inner,
        },
        None => DecodedError {
            rule,
            args: Vec::new(),
            raw: data.to_vec(),
            inner: None,
        },
    })
}

/// What the wallet does about a failed redeem (section 13.3 and the guide's failure table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemAction {
    /// AlreadyPaid: look for Paid(eta); the burn is (probably) paid.
    Reconcile,
    /// StaleEndpoint: two rollovers since the history was built; rebuild it, never change the burn.
    RebuildHistory,
    /// FutureIndex: the vault has not reached a (cannot arise from section 12.2).
    Wait,
    /// BadGapProof, ChainMismatch, BadHistoryLength: a wrong proof or start head, repairable without a new burn.
    RepairProof,
    /// NoEntryForEpoch inside VerifierRefused, Reentrancy, PayoutFailed, an out-of-gas: retry with more gas or later.
    RetryLater,
    /// The evidence or the deployment is refused: tell the user, do not resend.
    Stop,
}

impl RedeemAction {
    pub fn name(self) -> &'static str {
        match self {
            RedeemAction::Reconcile => "reconcile",
            RedeemAction::RebuildHistory => "rebuild-history",
            RedeemAction::Wait => "wait",
            RedeemAction::RepairProof => "repair-proof",
            RedeemAction::RetryLater => "retry-later",
            RedeemAction::Stop => "stop",
        }
    }
}

pub fn classify_redeem_error(e: Option<&DecodedError>) -> RedeemAction {
    let Some(e) = e else {
        return RedeemAction::RetryLater;
    };
    match e.rule {
        Rule::AlreadyPaid => RedeemAction::Reconcile,
        Rule::StaleEndpoint => RedeemAction::RebuildHistory,
        Rule::FutureIndex => RedeemAction::Wait,
        Rule::BadGapProof | Rule::ChainMismatch | Rule::BadHistoryLength => {
            RedeemAction::RepairProof
        }
        Rule::PayoutFailed | Rule::Reentrancy => RedeemAction::RetryLater,
        Rule::VerifierRefused => {
            if e.inner
                .as_ref()
                .is_some_and(|i| i.rule == Rule::NoEntryForEpoch)
            {
                RedeemAction::RetryLater
            } else {
                RedeemAction::Stop
            }
        }
        _ => RedeemAction::Stop,
    }
}

/// A log as an RPC returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLog {
    pub address: Vec<u8>,
    pub topics: Vec<Vec<u8>>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub block_hash: Vec<u8>,
    pub transaction_hash: Vec<u8>,
    pub log_index: u64,
    pub removed: bool,
}

/// A decoded Deposited log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositedLog {
    pub n: u64,
    pub domain: Vec<u8>,
    pub amount: BigUint,
    pub rho: Vec<u8>,
    pub first_owner: Vec<u8>,
}

pub fn decode_deposited(topics: &[Vec<u8>], data: &[u8]) -> Option<DepositedLog> {
    if topics.len() != 2 || topics[0] != topic::deposited() || data.len() != 224 {
        return None;
    }
    Some(DepositedLog {
        n: to_u64(&be_int(&topics[1]))?,
        domain: data[..32].to_vec(),
        amount: be_int(&data[32..64]),
        rho: data[64..96].to_vec(),
        first_owner: data[160..202].to_vec(),
    })
}

/// A decoded Paid log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidLog {
    pub eta: Vec<u8>,
    pub recipient: Vec<u8>,
    pub amount: BigUint,
}

pub fn decode_paid(l: &RawLog) -> Option<PaidLog> {
    if l.topics.len() != 3 || l.topics[0] != topic::paid() || l.data.len() != 32 {
        return None;
    }
    Some(PaidLog {
        eta: l.topics[1].clone(),
        recipient: l.topics[2][12..].to_vec(),
        amount: be_int(&l.data),
    })
}
