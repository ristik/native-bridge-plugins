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
/// ERC20 release admission cap. The continuation wire still accepts 16 Resume operations.
pub const ERC20_RESUME_OPERATIONS: usize = 8;

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
    fn ranges(&self) -> &[RecoveryCalibrationRange];
}

/// A qualified envelope for the same entry, operation count and gap count.
/// Covers the inclusive receipt interval and all smaller calldata, page and opening sizes.
#[derive(Clone, Copy)]
pub struct RecoveryCalibrationRange {
    pub min_receipt_bytes: usize,
    pub max: RecoveryShape,
    pub execution: u64,
}

/// Effective minima over authenticated deployment, node/relay, chain and payer. Empty access lists, zero value.
#[derive(Clone)]
pub struct RecoveryLimits {
    pub signed_bytes: usize,
    pub calldata_bytes: usize,
    pub gas: u64,
    pub chain_id: u64,
    pub max_nonce: u64,
    pub max_fee_per_gas: BigUint,
    pub max_priority_fee_per_gas: BigUint,
    pub max_transaction_fee: Option<BigUint>,
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
    quote_range(shape, shape.receipt_bytes, calibration, limits, false)
}

pub fn quote_erc20_recovery(
    shape: RecoveryShape,
    calibration: &dyn RecoveryCalibration,
    limits: &RecoveryLimits,
) -> Option<RecoveryQuote> {
    quote_range(shape, shape.receipt_bytes, calibration, limits, true)
}

fn quote_range(
    shape: RecoveryShape,
    min_receipt_bytes: usize,
    calibration: &dyn RecoveryCalibration,
    limits: &RecoveryLimits,
    erc20: bool,
) -> Option<RecoveryQuote> {
    let n = shape.calldata_bytes;
    if !(68..=CALLDATA_BYTES.min(limits.calldata_bytes)).contains(&n)
        || shape.operations > 16
        || shape.pages > 32
        || shape.gaps > 1024
        || shape.receipt_bytes > RECEIPT_BYTES
        || (erc20
            && shape.entry == RecoveryEntry::Run
            && shape.receipt_bytes != 0
            && shape.operations > ERC20_RESUME_OPERATIONS)
    {
        return None;
    }
    let execution = calibration
        .ranges()
        .iter()
        .filter(|range| {
            let max = range.max;
            max.entry == shape.entry
                && max.operations == shape.operations
                && max.gaps == shape.gaps
                && range.min_receipt_bytes <= min_receipt_bytes
                && max.receipt_bytes >= shape.receipt_bytes
                && max.calldata_bytes >= n
                && max.pages >= shape.pages
                && max.opening_bytes >= shape.opening_bytes
                && range.execution > 0
        })
        .map(|range| range.execution)
        .min()?;
    let reserve = if shape.entry == RecoveryEntry::RedeemRecovered {
        SEAL_RESERVE
    } else {
        0
    };
    let gas =
        (21_000 + 16 * n as u64 + reserve).checked_add(execution.checked_mul(6)?.div_ceil(5))?;
    let (signed_bytes, fee) = quote_erc20_call(n, gas, limits)?;
    Some(RecoveryQuote {
        shape,
        gas,
        signed_bytes,
        fee,
    })
}

/// Bound a zero-value Type 2 call with an empty access list and full-width signature.
pub fn quote_erc20_call(n: usize, gas: u64, limits: &RecoveryLimits) -> Option<(usize, BigUint)> {
    if !(68..=CALLDATA_BYTES.min(limits.calldata_bytes)).contains(&n)
        || gas == 0
        || gas > GAS_LIMIT.min(limits.gas)
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
    let fee = &limits.max_fee_per_gas * gas;
    if limits
        .max_transaction_fee
        .as_ref()
        .is_some_and(|cap| fee > *cap)
    {
        return None;
    }
    Some((signed_bytes, fee))
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

#[derive(Clone)]
pub struct RecoveryBacklog {
    pub signed_start: u64,
    pub observed: u64,
    pub during_progress: u64,
    /// Sustained peak count over elapsed_ms, for the throughput check.
    pub peak_seals: u64,
    pub elapsed_ms: u64,
    pub receipt_p99_ms: u64,
    /// Qualified maximum arrivals, including bursts, in any receipt_p99_ms window.
    pub advance_peak_seals: u64,
    /// Qualified time from sealing the final endpoint, including proof retrieval, through settlement inclusion.
    pub final_inclusion_ms: u64,
    /// Qualified maximum arrivals, including bursts, in any final_inclusion_ms window.
    pub final_peak_seals: u64,
    /// Horizon for which the peak-rate and timing bounds are qualified after lineage progress.
    pub qualified_for_ms: u64,
}
pub struct RecoveryAdmission {
    pub run: Vec<RecoveryQuote>,
    pub advance: RecoveryQuote,
    pub advance_calls: u64,
    pub settlement_max_gaps: usize,
    pub settle: RecoveryQuote,
    pub total_fee: BigUint,
    pub prior_attempts: u64,
}

/// Qualified upper time bounds, in milliseconds, through inclusion and usable proof.
pub struct Erc20SigningBounds {
    pub fee_window_ms: u64,
    /// Includes burn and Run certification, covered restores and any delay before fallback.
    pub progress_window_ms: u64,
    /// Worst time to a usable advance proof, over which advance_peak_seals is bounded.
    pub advance_window_ms: u64,
}

pub struct Erc20OrdinaryBound {
    pub gas: u64,
    pub calldata_bytes: usize,
    pub attempts_before_fallback: u64,
    pub inclusion_ms: u64,
}

pub fn erc20_signing_reserve(
    recovery_fee: BigUint,
    calls: u64,
    backlog: &RecoveryBacklog,
    limits: &RecoveryLimits,
    bounds: &Erc20SigningBounds,
    ordinary: Option<&Erc20OrdinaryBound>,
) -> Result<(BigUint, u64)> {
    if bounds.fee_window_ms == 0
        || bounds.progress_window_ms == 0
        || bounds.advance_window_ms < backlog.receipt_p99_ms
        || bounds.advance_window_ms == 0
    {
        return fail_d(
            Rule::CapacityPreflight,
            "unqualified ERC20 fee or inclusion windows",
        );
    }
    let continuation_ms = u128::from(calls) * u128::from(bounds.advance_window_ms)
        + u128::from(backlog.final_inclusion_ms);
    if continuation_ms > u128::from(backlog.qualified_for_ms)
        || u128::from(bounds.progress_window_ms) + continuation_ms
            > u128::from(bounds.fee_window_ms)
    {
        return fail_d(Rule::CapacityPreflight, "unqualified ERC20 signing horizon");
    }
    let (total_fee, prior_attempts) = if let Some(ordinary) = ordinary {
        let attempts = ordinary.attempts_before_fallback;
        if attempts == 0
            || ordinary.inclusion_ms == 0
            || u128::from(attempts) * u128::from(ordinary.inclusion_ms)
                > u128::from(bounds.progress_window_ms)
        {
            return fail_d(Rule::CapacityPreflight, "unqualified ordinary retry window");
        }
        let Some((_, fee)) = quote_erc20_call(ordinary.calldata_bytes, ordinary.gas, limits) else {
            return fail_d(
                Rule::CapacityPreflight,
                "ordinary call is outside the ERC20 admission limits",
            );
        };
        let retries = &fee * attempts;
        (recovery_fee.max(fee) + retries, attempts)
    } else {
        (recovery_fee, 0)
    };
    if total_fee > limits.fee_budget {
        return fail_d(
            Rule::CapacityPreflight,
            "insufficient authorized fee budget",
        );
    }
    if total_fee > limits.balance {
        return fail_d(Rule::CapacityPreflight, "insufficient free payer balance");
    }
    Ok((total_fee, prior_attempts))
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
    preflight_recovery_with_signing_bounds(ctx, held, backlog, starting_seal, None, None)
}

pub fn preflight_recovery_with_signing_bounds(
    ctx: &AdmissionContext<'_>,
    held: &[u8],
    backlog: &RecoveryBacklog,
    starting_seal: Option<&[u8]>,
    bounds: Option<&Erc20SigningBounds>,
    ordinary: Option<&Erc20OrdinaryBound>,
) -> Result<RecoveryAdmission> {
    let cfg = decode_config(ctx.gamma, ctx.params)?;
    let erc20 = cfg.erc20.is_some();
    if !ctx.deployment.matches_config(&cfg)
        || ctx.deployment.pins != ctx.calibration.pins()
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
        quote_range(
            shape,
            usize::from(from != 0),
            ctx.calibration,
            ctx.limits,
            erc20,
        )
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
        .max(backlog.signed_start)
        .checked_add(backlog.during_progress)
        .and_then(|x| x.checked_add(64))
    else {
        return fail_d(Rule::CapacityPreflight, "unqualified backlog");
    };
    if last > MAX_SEGMENT
        || backlog.elapsed_ms == 0
        || backlog.receipt_p99_ms == 0
        || backlog.final_inclusion_ms == 0
    {
        return fail_d(Rule::CapacityPreflight, "unqualified backlog");
    }
    let per_advance = u128::from(backlog.advance_peak_seals);
    let final_growth = u128::from(backlog.final_peak_seals);
    if final_growth > 1 {
        return fail_d(
            Rule::CapacityPreflight,
            "unqualified final inclusion window",
        );
    }
    let need = last - backlog.signed_start;
    let width = gap_proof_len(cfg.k);
    let gap = |count| {
        quote_range(
            gap_shape(RecoveryEntry::AdvanceGaps, count, width),
            1,
            ctx.calibration,
            ctx.limits,
            erc20,
        )
    };
    if gap(1).is_none() {
        return fail_d(Rule::CapacityPreflight, "indivisible gap operation");
    }
    let Some((q, advance)) = (1..=need.min(1024) as usize)
        .rev()
        .find_map(|q| gap(q).map(|quote| (q, quote)))
    else {
        return fail_d(
            Rule::CapacityPreflight,
            "insufficient certified catch-up rate",
        );
    };
    if q as u128 <= per_advance
        || (q as u128) * u128::from(backlog.elapsed_ms) / 2
            < u128::from(backlog.peak_seals) * u128::from(backlog.receipt_p99_ms)
    {
        return fail_d(
            Rule::CapacityPreflight,
            "insufficient certified catch-up rate",
        );
    }
    // Fund full advances against net progress while the archive is growing.
    let advance_calls = need.div_ceil(q as u64 - per_advance as u64);
    if u128::from(last) + u128::from(advance_calls) * per_advance + final_growth
        > u128::from(MAX_SEGMENT)
        || u128::from(advance_calls) * u128::from(backlog.receipt_p99_ms)
            + u128::from(backlog.final_inclusion_ms)
            > u128::from(backlog.qualified_for_ms)
    {
        return fail_d(Rule::CapacityPreflight, "unqualified catch-up horizon");
    }
    // Every suffix smaller than the advance batch may be needed at settlement.
    let mut settle: Option<RecoveryQuote> = None;
    for count in 0..q {
        let Some(quote) = quote_range(
            gap_shape(RecoveryEntry::RedeemRecovered, count, width),
            1,
            ctx.calibration,
            ctx.limits,
            erc20,
        ) else {
            return fail_d(Rule::CapacityPreflight, "unqualified settlement suffix");
        };
        if settle.as_ref().map_or(true, |best| quote.fee > best.fee) {
            settle = Some(quote);
        }
    }
    let settle = settle.expect("positive gap batch");
    let mut total_fee = &settle.fee + &advance.fee * advance_calls;
    for quote in &run {
        total_fee += &quote.fee;
    }
    let (total_fee, prior_attempts) = if erc20 {
        let Some(bounds) = bounds else {
            return fail_d(
                Rule::CapacityPreflight,
                "unqualified ERC20 fee or inclusion windows",
            );
        };
        erc20_signing_reserve(
            total_fee,
            advance_calls,
            backlog,
            ctx.limits,
            bounds,
            ordinary,
        )?
    } else {
        (total_fee, 0)
    };
    if total_fee > ctx.limits.fee_budget || total_fee > ctx.limits.balance {
        return fail_d(Rule::CapacityPreflight, "insufficient recovery fee budget");
    }
    Ok(RecoveryAdmission {
        run,
        advance,
        advance_calls,
        settlement_max_gaps: q - 1,
        settle,
        total_fee,
        prior_attempts,
    })
}
