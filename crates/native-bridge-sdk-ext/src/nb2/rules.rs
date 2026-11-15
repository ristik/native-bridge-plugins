//! Wallet rules that affect safety (section 12) and the wallet refusals of section 14.6 (`rules.ts`; bft-core `nb2ref/wallet.go`).

use alloc::format;

use super::config::{log2, Config};
use super::deposit::{decode_deposit_proof, topic, verify_receipt_log, DepositProof};
use super::errors::{fail, fail_d, refuse, refuse0, wrap, Result, Rule, WalletReason};
use super::segment::{check_segment_log, genesis_head, Segment};
use super::trust::{bind_trust, TrustInput};
use super::util::arr;

/// A verified SegmentSealed(j) receipt.
#[derive(Debug, Clone)]
pub struct SealReceipt {
    pub segment: Segment,
    pub proof: DepositProof,
    pub block_number: u64,
}

/// A seal receipt proof (a DepositProof container whose log is SegmentSealed), verified exactly as section 6.2 steps 2 to 5 for
/// that event: the same EVM UC rule, header, receipt path, type, status, log index and emitter, topics
/// [topic0(SegmentSealed), u256(j)] with j < 2^48, and the log's own check. Every failure is `SealReceipt` carrying the inner rule.
pub fn verify_seal_receipt(
    c: &Config,
    domain: &[u8; 32],
    t: &TrustInput,
    receipt: &[u8],
) -> Result<SealReceipt> {
    bind_trust(t, c)?;
    let f = || -> Result<SealReceipt> {
        let p = decode_deposit_proof(receipt)?;
        let log = verify_receipt_log(c, t, &p)?;
        if log.topics.len() != 2 || log.topics[0] != topic::segment_sealed() {
            return fail(Rule::LogTopics);
        }
        let jw = &log.topics[1];
        if jw[..26].iter().any(|&x| x != 0) {
            return fail(Rule::LogTopics);
        }
        let j = jw[26..].iter().fold(0u64, |a, &x| a << 8 | x as u64);
        if log.data.len() as u64 != 128 + 32 * c.k {
            return fail(Rule::LogData);
        }
        let segment = check_segment_log(domain, c.k, j, &log.data[..32], &log.data)?;
        Ok(SealReceipt {
            segment,
            proof: p,
            block_number: log.header.number_u64(),
        })
    };
    f().map_err(|e| wrap(Rule::SealReceipt, e))
}

/// Section 12.2: with the newest verified seal receipt of segment j, sign a = j + 1 and keep H_{j+1}; with none, a = 0 and H_0.
pub fn burn_index(c: &Config, domain: &[u8; 32], newest: Option<&SealReceipt>) -> (u64, [u8; 32]) {
    match newest {
        None => (0, genesis_head(domain, c.k)),
        Some(s) => (s.segment.index + 1, s.segment.after),
    }
}

/// P_max = floor((L_max - L_T - L_O) / (65 + 32h)) and whether the return without history fits at all (L_T <= L_max and
/// L_O <= L_max - L_T); P_max is zero when it does not.
pub fn max_proofs(l_max: u64, l_t: u64, l_o: u64, k: u64) -> (u64, bool) {
    if l_t > l_max || l_o > l_max - l_t {
        return (0, false);
    }
    ((l_max - l_t - l_o) / (65 + 32 * log2(k) as u64), true)
}

fn fits_proofs(l_max: u64, l_t: u64, l_o: u64, k: u64, p: u64) -> bool {
    let (p_max, base_fits) = max_proofs(l_max, l_t, l_o, k);
    base_fits && p <= p_max
}

/// The before-burn capacity input (section 12.5 as amended by astra's review, finding 1).
pub struct Preflight<'a> {
    pub l_max: u64,
    /// The encoded evidence, including the burn and its certification.
    pub l_t: u64,
    /// All other framing of the redeem transaction (ABI padding, transaction envelope, start head).
    pub l_o: u64,
    pub k: u64,
    pub a: u64,
    /// A current endpoint estimate, c_obs >= a.
    pub c_obs: u64,
    pub reserve: u64,
    /// The gas limit (expected cost plus gasReserve) with P proofs, estimated conservatively; None when it cannot be bounded.
    pub gas_at: &'a dyn Fn(u64) -> Option<u64>,
    pub user_gas_limit: u64,
}

/// The preflight's figures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreflightResult {
    pub p_now: u64,
    pub need: u64,
    pub p_max: u64,
    pub gas: u64,
}

/// Refuse the burn (`CapacityPreflight`) unless the return fits L_max and userGasLimit with P_now + returnReserveSegments proofs.
pub fn capacity_preflight(p: &Preflight<'_>) -> Result<PreflightResult> {
    if p.c_obs < p.a {
        return fail_d(
            Rule::CapacityPreflight,
            "the endpoint estimate is below the index",
        );
    }
    // no wrap: an owed history beyond u64 never fits
    let Some(need) = (p.c_obs - p.a).checked_add(p.reserve) else {
        return fail_d(Rule::CapacityPreflight, "the owed history overflows");
    };
    let (p_max, _) = max_proofs(p.l_max, p.l_t, p.l_o, p.k);
    if !fits_proofs(p.l_max, p.l_t, p.l_o, p.k, need) {
        return fail_d(
            Rule::CapacityPreflight,
            format!("{need} proofs needed, {p_max} fit {} bytes", p.l_max),
        );
    }
    let Some(gas) = (p.gas_at)(need) else {
        return fail_d(Rule::CapacityPreflight, "the gas cannot be bounded");
    };
    if gas > p.user_gas_limit {
        return fail_d(
            Rule::CapacityPreflight,
            format!("gas {gas} above userGasLimit {}", p.user_gas_limit),
        );
    }
    Ok(PreflightResult {
        p_now: p.c_obs - p.a,
        need,
        p_max,
        gas,
    })
}

/// The at-redemption refusal: P > P_max, or the gas limit above userGasLimit.
#[allow(clippy::too_many_arguments)]
pub fn capacity_exceeded(
    l_max: u64,
    l_t: u64,
    l_o: u64,
    k: u64,
    p: u64,
    gas_limit: u64,
    user_gas_limit: u64,
) -> Result<()> {
    if !fits_proofs(l_max, l_t, l_o, k, p) || gas_limit > user_gas_limit {
        return fail(Rule::CapacityExceeded);
    }
    Ok(())
}

/// The stateReadOnly substitute for a seal receipt (section 12.2, test deployments only): the read index must lie in
/// [verified, verified + maxJump] (`ImplausibleIndex`); without stateReadOnly a state() read is not evidence at all.
pub fn check_state_read(
    state_read_only: bool,
    read: u64,
    verified: u64,
    max_jump: u64,
) -> Result<()> {
    if !state_read_only {
        return refuse(
            WalletReason::StateReadNotAdmitted,
            "a plain state() read is not evidence on this deployment",
        );
    }
    if read < verified || read - verified > max_jump {
        return fail(Rule::ImplausibleIndex);
    }
    Ok(())
}

/// A seal companion answer (section 12.7): "found" with exactly two witnesses is usable; "unavailable" is EvidencePruned;
/// "unknown" is retried after a round; anything else is the provider's fault.
pub fn check_companion(status: &str, witnesses: usize) -> Result<()> {
    if status == "found" && witnesses == 2 {
        return Ok(());
    }
    if status == "unavailable" {
        return fail(Rule::EvidencePruned);
    }
    if status == "unknown" {
        return refuse0(WalletReason::CompanionUnknown);
    }
    refuse0(WalletReason::CompanionProvider)
}

/// The segment index of a SegmentSealed topic word.
pub fn topic_index(w: &[u8]) -> u64 {
    let b: [u8; 8] = arr(&w[24..32]);
    u64::from_be_bytes(b)
}
