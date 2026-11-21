//! Cold admission using complete signed envelopes and a deployment-pinned execution bound.
use alloc::vec;
use alloc::vec::Vec;

use num_bigint::BigUint;

use super::config::{decode_config, domain_of, Params, MAX_SEGMENT};
use super::errors::{fail_d, Result, Rule};
use super::recovery::RecoveryDeployment;
use super::rlp::{rlp_bytes, rlp_list, rlp_u64_enc, rlp_uint_enc};
use super::rules::{burn_index, verify_seal_receipt};
use super::segment::gap_proof_len;
use super::token::{decode_token, MAX_TRANSFER_PAIR};
use super::trust::TrustInput;
use super::verify::verify_held;

const TX_BYTES: usize = 524_288;
const CALLDATA_BYTES: usize = 393_216;
const RECEIPT_BYTES: usize = 65_536;
const SPARSE: usize = 8_224;
const SEAL_RESERVE: u64 = 500_000;
const GAS_LIMIT: u64 = 24_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEntry {
    Run,
    AdvanceGaps,
    RedeemRecovered,
}

#[derive(Debug, Clone, Copy)]
pub struct RecoveryShape {
    pub entry: RecoveryEntry,
    pub calldata_bytes: usize,
    pub operations: usize,
    pub pages: usize,
    pub gaps: usize,
    pub receipt_bytes: usize,
    pub opening_bytes: usize,
}

/// A bound from the authenticated release, including execution, forwarding and memory.
pub trait RecoveryCalibration {
    fn pins(&self) -> [u8; 32];
    fn runtime_hash(&self) -> [u8; 32];
    fn vault_runtime_hash(&self) -> Option<[u8; 32]> {
        None
    }
    fn execution_bound(&self, shape: &RecoveryShape) -> Option<u64>;
}

/// Effective minima over authenticated deployment, node/relay, chain and payer. Empty access lists, zero value.
pub struct RecoveryLimits {
    pub signed_bytes: usize,
    pub calldata_bytes: usize,
    pub gas: u64,
    pub chain_id: u64,
    pub max_nonce: u64,
    pub max_fee_per_gas: BigUint,
    pub max_priority_fee_per_gas: BigUint,
    pub balance: BigUint,
    pub fee_budget: BigUint,
}

pub struct RecoveryQuote {
    pub shape: RecoveryShape,
    pub gas: u64,
    pub signed_bytes: usize,
    pub fee: BigUint,
}

pub fn quote_recovery(
    shape: RecoveryShape,
    calibration: &dyn RecoveryCalibration,
    limits: &RecoveryLimits,
) -> Option<RecoveryQuote> {
    let n = shape.calldata_bytes;
    if !(68..=CALLDATA_BYTES.min(limits.calldata_bytes)).contains(&n) {
        return None;
    }
    let execution = calibration.execution_bound(&shape)?;
    if execution == 0 {
        return None;
    }
    let reserve = if shape.entry == RecoveryEntry::RedeemRecovered {
        SEAL_RESERVE
    } else {
        0
    };
    let gas =
        (21_000 + 16 * n as u64 + reserve).checked_add(execution.checked_mul(6)?.div_ceil(5))?;
    if gas > GAS_LIMIT.min(limits.gas)
        || limits.chain_id == 0
        || limits.max_fee_per_gas.bits() == 0
        || limits.max_fee_per_gas.bits() > 256
        || limits.max_priority_fee_per_gas > limits.max_fee_per_gas
    {
        return None;
    }
    let signed_bytes = 1 + rlp_list(&[
        rlp_u64_enc(limits.chain_id),
        rlp_u64_enc(limits.max_nonce),
        rlp_uint_enc(&limits.max_priority_fee_per_gas),
        rlp_uint_enc(&limits.max_fee_per_gas),
        rlp_u64_enc(gas),
        rlp_bytes(&[0; 20]),
        rlp_u64_enc(0),
        rlp_bytes(&vec![0; n]),
        rlp_list(&[]),
        rlp_u64_enc(1),
        rlp_bytes(&[0; 32]),
        rlp_bytes(&[0; 32]),
    ])
    .len();
    if signed_bytes > TX_BYTES.min(limits.signed_bytes) {
        return None;
    }
    Some(RecoveryQuote {
        shape,
        gas,
        signed_bytes,
        fee: &limits.max_fee_per_gas * gas,
    })
}

#[derive(Clone, Copy)]
struct Span {
    pub start: usize,
    pub end: usize,
    claims: usize,
}
fn calldata_size(payload: usize) -> usize {
    68 + payload.div_ceil(32) * 32
}

fn run_shape(
    spans: &[Span],
    from: usize,
    end: usize,
    n: usize,
    receipt_bytes: usize,
    opening_bytes: usize,
) -> Option<RecoveryShape> {
    if end <= from || end - from > 16 {
        return None;
    }
    let first = if from == 0 {
        0
    } else {
        spans[from].start / 4096
    };
    let last = (spans[end - 1].end - 1) / 4096;
    let pages = last - first + 1;
    if pages > 32 {
        return None;
    }
    let depth = n.div_ceil(4096).next_power_of_two().trailing_zeros() as usize;
    let page_bytes = ((last + 1) * 4096).min(n) - first * 4096 + pages * (8 + 32 * depth);
    let prefix = if from == 0 {
        0
    } else {
        290 + 4 + receipt_bytes
    };
    Some(RecoveryShape {
        entry: RecoveryEntry::Run,
        operations: end - from,
        pages,
        gaps: 0,
        receipt_bytes,
        opening_bytes,
        calldata_bytes: calldata_size(
            42 + 1 + prefix + 1 + page_bytes + 1 + end - from + opening_bytes,
        ),
    })
}

fn gap_shape(entry: RecoveryEntry, gaps: usize, width: usize) -> RecoveryShape {
    RecoveryShape {
        entry,
        operations: 0,
        pages: 0,
        gaps,
        receipt_bytes: RECEIPT_BYTES,
        opening_bytes: 0,
        calldata_bytes: calldata_size(
            42 + 1 + 4 + RECEIPT_BYTES + 2 + if gaps == 0 { 0 } else { 32 } + gaps * width,
        ),
    }
}

pub struct RecoveryBacklog {
    pub signed_start: u64,
    pub observed: u64,
    pub during_progress: u64,
    pub peak_seals: u64,
    pub elapsed_ms: u64,
    pub receipt_p99_ms: u64,
}
pub struct RecoveryAdmission {
    pub run: Vec<RecoveryQuote>,
    pub advance: RecoveryQuote,
    pub advance_calls: u64,
    pub advance_tail: Option<RecoveryQuote>,
    pub settle: RecoveryQuote,
    pub total_fee: BigUint,
}
pub struct AdmissionContext<'a> {
    pub gamma: &'a [u8],
    pub trust: &'a TrustInput,
    pub params: &'a Params,
    pub deployment: &'a RecoveryDeployment,
    pub calibration: &'a dyn RecoveryCalibration,
    pub limits: &'a RecoveryLimits,
}

/// Price the hypothetical terminal pair at its decoder cap and worst future predecessor and map openings.
pub fn preflight_recovery(
    ctx: &AdmissionContext<'_>,
    held: &[u8],
    backlog: &RecoveryBacklog,
    starting_seal: Option<&[u8]>,
) -> Result<RecoveryAdmission> {
    let cfg = decode_config(ctx.gamma, ctx.params)?;
    if ctx.deployment.pins != ctx.calibration.pins()
        || ctx.deployment.runtime_hash != ctx.calibration.runtime_hash()
        || ctx.deployment.vault_runtime_hash.is_none()
        || ctx.deployment.vault_runtime_hash != ctx.calibration.vault_runtime_hash()
        || cfg.chain_id != ctx.limits.chain_id
    {
        return fail_d(Rule::CapacityPreflight, "unqualified recovery deployment");
    }
    let domain = domain_of(ctx.gamma);
    let token = decode_token(held)?;
    verify_held(&cfg, &domain, ctx.trust, &token)?;
    let seal = starting_seal
        .map(|r| verify_seal_receipt(&cfg, &domain, ctx.trust, r))
        .transpose()?;
    if burn_index(&cfg, &domain, seal.as_ref()).0 != backlog.signed_start {
        return fail_d(Rule::CapacityPreflight, "unauthenticated signed start");
    }
    let mut spans = Vec::new();
    let mut pos = 14;
    let skip = |pos: &mut usize| {
        let len = u32::from_be_bytes(held[*pos..*pos + 4].try_into().unwrap()) as usize;
        *pos += 4 + len;
    };
    for (index, level) in token.levels().enumerate() {
        let start = pos;
        for _ in 0..3 {
            skip(&mut pos);
        }
        pos += 8;
        spans.push(Span {
            start,
            end: pos,
            claims: if index == 0 { 2 } else { 1 },
        });
        for _ in &level.transfers {
            let start = pos;
            skip(&mut pos);
            spans.push(Span {
                start,
                end: pos,
                claims: 1,
            });
        }
    }
    let n = pos + MAX_TRANSFER_PAIR + 4;
    spans.push(Span {
        start: pos,
        end: n,
        claims: 1,
    });
    let quoted = |from: usize, end: usize| {
        let opening = spans[from..end]
            .iter()
            .map(|op| SPARSE + op.claims * (34 + SPARSE))
            .sum();
        let shape = run_shape(
            &spans,
            from,
            end,
            n,
            if from == 0 { 0 } else { RECEIPT_BYTES },
            opening,
        )?;
        quote_recovery(shape, ctx.calibration, ctx.limits)
    };
    if (0..spans.len()).any(|i| quoted(i, i + 1).is_none()) {
        return fail_d(Rule::CapacityPreflight, "indivisible run operation");
    }
    let mut run = Vec::new();
    let mut from = 0;
    while from < spans.len() {
        let (end, quote) = ((from + 1)..=(from + 16).min(spans.len()))
            .rev()
            .find_map(|end| quoted(from, end).map(|quote| (end, quote)))
            .unwrap();
        run.push(quote);
        from = end;
    }
    let Some(last) = backlog
        .observed
        .checked_add(backlog.during_progress)
        .and_then(|x| x.checked_add(64))
    else {
        return fail_d(Rule::CapacityPreflight, "unqualified backlog");
    };
    if backlog.observed < backlog.signed_start
        || last > MAX_SEGMENT
        || backlog.elapsed_ms == 0
        || backlog.receipt_p99_ms == 0
    {
        return fail_d(Rule::CapacityPreflight, "unqualified backlog");
    }
    let need = last - backlog.signed_start;
    let width = gap_proof_len(cfg.k);
    let gap = |q| {
        quote_recovery(
            gap_shape(RecoveryEntry::AdvanceGaps, q, width),
            ctx.calibration,
            ctx.limits,
        )
    };
    let Some((q, advance)) = (1..=need.min(1024) as usize)
        .rev()
        .find_map(|q| gap(q).map(|quote| (q as u64, quote)))
    else {
        return fail_d(
            Rule::CapacityPreflight,
            "insufficient certified catch-up rate",
        );
    };
    if BigUint::from(q) * backlog.elapsed_ms
        < BigUint::from(2u8) * backlog.peak_seals * backlog.receipt_p99_ms
    {
        return fail_d(
            Rule::CapacityPreflight,
            "insufficient certified catch-up rate",
        );
    }
    let Some(settle) = quote_recovery(
        gap_shape(RecoveryEntry::RedeemRecovered, 0, width),
        ctx.calibration,
        ctx.limits,
    ) else {
        return fail_d(Rule::CapacityPreflight, "indivisible settlement");
    };
    let advance_calls = need / q;
    let advance_tail = if need % q == 0 {
        None
    } else {
        let Some(tail) = gap((need % q) as usize) else {
            return fail_d(Rule::CapacityPreflight, "unqualified gap remainder");
        };
        Some(tail)
    };
    let mut total_fee = &settle.fee + &advance.fee * advance_calls;
    for quote in run.iter().chain(advance_tail.iter()) {
        total_fee += &quote.fee;
    }
    if total_fee > ctx.limits.fee_budget || total_fee > ctx.limits.balance {
        return fail_d(Rule::CapacityPreflight, "insufficient recovery fee budget");
    }
    Ok(RecoveryAdmission {
        run,
        advance,
        advance_calls,
        advance_tail,
        settle,
        total_fee,
    })
}
