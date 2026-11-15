//! Size and gas bounds of a redemption (sections 12.4 and 12.5; `gas.ts`). The preflight needs a CONSERVATIVE bound of the
//! complete redeem transaction before the burn exists: its encoded size and its gas limit (expected cost plus `gasReserve`).
//! The verifier part is a named, replaceable component: [`GasModel`]. The default [`ProvisionalGasModel`] over-estimates by
//! construction and fails closed (returns None, which the preflight reports as `CapacityPreflight`) for anything it cannot bound.

use unicity_token::api::bft::UnicityCertificate;
use unicity_token::cbor::{DecodeLimits, Decoder};

use super::abi::redeem_calldata_length;
use super::cbor::head_tag;
use super::config::tag;
use super::deposit::decode_receipt_backing;
use super::segment::gap_proof_len;
use super::token::Token;

/// What the gas model sees of a prospective redemption.
pub struct RedeemShape<'a> {
    /// The evidence bytes (`C(1, Token)`), or an upper bound of their length when the burn does not exist yet.
    pub evidence_bytes: usize,
    /// The decoded token of the lineage walk, root first, when known (counts certificates, signatures and paths).
    pub lineage: &'a [Token],
    /// Transactions the evidence will hold that are not in `lineage` yet (the burn about to be made).
    pub pending_transactions: usize,
    /// Historical gap proofs.
    pub proofs: u64,
    pub k: u64,
}

/// A gas model: the gas limit of a redeem (expected cost plus gasReserve), or None when it cannot be bounded.
pub trait GasModel: Send + Sync {
    fn name(&self) -> &str;
    fn redeem_gas_limit(&self, s: &RedeemShape<'_>) -> Option<u64>;
    /// The gas limit of a deposit call.
    fn deposit_gas_limit(&self) -> u64;
}

/// Measured by #1098 (K = 64, B = 16, optimizer runs 200): replay and settlement only.
pub mod measured {
    pub const GAS_RESERVE: u64 = 500_000;
    /// The more expensive of the P = 0 endpoints.
    pub const PREVIOUS_ENDPOINT: u64 = 78_083;
    pub const PER_SEGMENT: u64 = 5_950;
    pub const DEPOSIT_FIRST: u64 = 48_758;
}

const TX_BASE: u64 = 21_000;
const CALLDATA_NONZERO: u64 = 16;

/// Upper-bound guesses for the unmeasured verifier, from the B1 price schedule (bft-core `b1ref/limits.go`, profile 7) charged
/// for EVERY certificate occurrence as its own call, plus a per-byte charge for parsing and hashing the evidence in Solidity.
pub mod provisional {
    pub const PER_EVIDENCE_BYTE: u64 = 128;
    pub const PER_CERTIFICATE: u64 = 60_000 + 1_100 + 29_900 + 2_000;
    pub const PER_CERTIFICATE_BYTE: u64 = 16;
    pub const PER_SIGNATURE: u64 = 7_200;
    pub const MAX_SIGNATURES: usize = 16;
    pub const PER_PATH_STEP: u64 = 250;
    pub const PER_TRANSACTION: u64 = 3_000 + 2_000 + 256 * 250;
    pub const RECEIPT_PROOF: u64 = 200_000;
    /// A pending transaction's own certificate.
    pub const PENDING_CERTIFICATE_BYTES: u64 = 24_576;
}

/// The provisional model of NB2-07.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProvisionalGasModel;

impl GasModel for ProvisionalGasModel {
    fn name(&self) -> &str {
        "provisional-nb2-07"
    }

    fn redeem_gas_limit(&self, s: &RedeemShape<'_>) -> Option<u64> {
        use provisional as p;
        let mut verifier = p::RECEIPT_PROOF + p::PER_EVIDENCE_BYTE * s.evidence_bytes as u64;
        let mut transactions = 0u64;
        for tok in s.lineage {
            let proofs = core::iter::once(&tok.mint_proof).chain(tok.proofs.iter());
            for pr in proofs {
                transactions += 1;
                let sigs = count_signatures(&pr.uc)?;
                if sigs > p::MAX_SIGNATURES {
                    return None;
                }
                verifier += p::PER_CERTIFICATE
                    + p::PER_CERTIFICATE_BYTE * pr.uc.len() as u64
                    + p::PER_SIGNATURE * sigs as u64
                    + p::PER_PATH_STEP * (pr.siblings.len() as u64 + 32);
            }
        }
        // the root's EVM UC (inside J) and every pending transaction's future certificate, at the bounds
        let pending = s.pending_transactions as u64;
        verifier += (pending + 1)
            * (p::PER_CERTIFICATE
                + p::PER_CERTIFICATE_BYTE * p::PENDING_CERTIFICATE_BYTES
                + p::PER_SIGNATURE * p::MAX_SIGNATURES as u64
                + p::PER_PATH_STEP * 288);
        verifier += (transactions + pending) * p::PER_TRANSACTION;
        let history_bytes = if s.proofs == 0 {
            0
        } else {
            32 + s.proofs as usize * gap_proof_len(s.k)
        };
        let calldata =
            CALLDATA_NONZERO * redeem_calldata_length(s.evidence_bytes, history_bytes) as u64;
        let settlement = measured::PREVIOUS_ENDPOINT + measured::PER_SEGMENT * s.proofs;
        Some(TX_BASE + calldata + settlement + verifier + measured::GAS_RESERVE)
    }

    fn deposit_gas_limit(&self) -> u64 {
        2 * measured::DEPOSIT_FIRST + 50_000
    }
}

/// The measured schedule: NB2-05's verifier (unicity-pos-contracts#82 `docs/nb2-verifier.md`: solc 0.8.37, via-IR, Cancun,
/// native 0x0100/0x0102 schedules, calldata included) and the vault's replay and settlement (#1098 bake-off and #81 snapshots),
/// each term rounded up so the model stays above every measured token:
///
/// ```text
///   verifier = 800,000 + 190,000 per further transfer + 760,000 per nested split level
///              + 136 per evidence byte beyond the measured shape (4,242 + 1,026 per transfer + 3,238 per level)
///              + 7,500 per seal signature beyond the measured 3
///   vault    = 487,339 (the worst measured call: previous endpoint, one bucket, sealing) + 6,000 per historical segment
///   limit    = verifier + vault + history calldata + gasReserve (500,000)
/// ```
///
/// It fails closed: a certificate whose signatures cannot be counted, or more than 16 of them, gives None (`CapacityPreflight`).
pub mod measured_verifier {
    pub const BASE: u64 = 800_000;
    pub const PER_TRANSFER: u64 = 190_000;
    pub const PER_SPLIT_LEVEL: u64 = 760_000;
    pub const BASE_BYTES: u64 = 4_242;
    pub const BYTES_PER_TRANSFER: u64 = 1_026;
    pub const BYTES_PER_SPLIT_LEVEL: u64 = 3_238;
    pub const PER_EXCESS_BYTE: u64 = 136;
    pub const MEASURED_SIGNATURES: usize = 3;
    pub const PER_EXTRA_SIGNATURE: u64 = 7_500;
    pub const MAX_SIGNATURES: usize = 16;
    pub const VAULT_WORST_CALL: u64 = 487_339;
    pub const PER_SEGMENT: u64 = 6_000;
}

/// The default model: [`measured_verifier`].
#[derive(Debug, Clone, Copy, Default)]
pub struct MeasuredGasModel;

impl GasModel for MeasuredGasModel {
    fn name(&self) -> &str {
        "measured-nb2-05"
    }

    fn redeem_gas_limit(&self, s: &RedeemShape<'_>) -> Option<u64> {
        use measured_verifier as m;
        let levels = s.lineage.len().saturating_sub(1) as u64;
        // every token of the walk ends in a burn (its split burn, or the return burn, pending or not); further transfers are hops
        let transfers =
            s.lineage.iter().map(|t| t.transfers.len()).sum::<usize>() + s.pending_transactions;
        let hops = transfers.saturating_sub(s.lineage.len()) as u64;
        let mut extra_sigs = 0u64;
        let count = |uc: &[u8], extra: &mut u64| -> Option<()> {
            let n = count_signatures(uc)?;
            if n > m::MAX_SIGNATURES {
                return None;
            }
            *extra += n.saturating_sub(m::MEASURED_SIGNATURES) as u64;
            Some(())
        };
        for (i, tok) in s.lineage.iter().enumerate() {
            for pr in core::iter::once(&tok.mint_proof).chain(tok.proofs.iter()) {
                count(&pr.uc, &mut extra_sigs)?;
            }
            // the root's EVM UC inside J
            if i == 0 {
                if let Some(evm) = evm_uc_of(tok)? {
                    count(&evm, &mut extra_sigs)?;
                }
            }
        }
        // a future certificate at the signature bound
        extra_sigs +=
            (s.pending_transactions * (m::MAX_SIGNATURES - m::MEASURED_SIGNATURES)) as u64;
        let shaped =
            m::BASE_BYTES + m::BYTES_PER_TRANSFER * hops + m::BYTES_PER_SPLIT_LEVEL * levels;
        let excess = (s.evidence_bytes as u64).saturating_sub(shaped);
        let verifier = m::BASE
            + m::PER_TRANSFER * hops
            + m::PER_SPLIT_LEVEL * levels
            + m::PER_EXCESS_BYTE * excess
            + m::PER_EXTRA_SIGNATURE * extra_sigs;
        let history_calldata = if s.proofs == 0 {
            0
        } else {
            CALLDATA_NONZERO * (32 + s.proofs * gap_proof_len(s.k) as u64)
        };
        Some(
            verifier
                + m::VAULT_WORST_CALL
                + m::PER_SEGMENT * s.proofs
                + history_calldata
                + measured::GAS_RESERVE,
        )
    }

    fn deposit_gas_limit(&self) -> u64 {
        2 * measured::DEPOSIT_FIRST + 50_000
    }
}

/// The EVM UC inside a root token's J: Some(None) for a token whose reason is not J (not a root), None when J does not decode.
fn evm_uc_of(t: &Token) -> Option<Option<alloc::vec::Vec<u8>>> {
    match t.mint.justification.as_deref() {
        Some(j) if head_tag(j) == Some(tag::RECEIPT_BACKING) => {
            decode_receipt_backing(j).ok().map(|b| Some(b.proof.uc))
        }
        _ => Some(None),
    }
}

/// The signature count of a UC's seal, from its full canonical decode; None (fail closed) when the UC does not decode.
fn count_signatures(uc: &[u8]) -> Option<usize> {
    UnicityCertificate::from_cbor(Decoder::with_limits(uc, DecodeLimits::DEFAULT))
        .ok()
        .map(|u| u.unicity_seal.signatures.len())
}

/// The encoded size of a signed EIP-1559 redeem transaction around `calldata` bytes: the envelope, nine scalar fields at their
/// widest, the 20-byte target, an empty access list and a 65-byte signature, plus the RLP heads of the data string and the list.
pub fn redeem_tx_framing(calldata: usize) -> usize {
    1 + 9 + 9 * 9 + 21 + 1 + 3 * 33 + if calldata >= 56 { 5 } else { 1 } + 5
}
