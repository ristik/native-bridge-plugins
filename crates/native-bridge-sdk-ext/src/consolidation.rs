//! The redemption's proof path (interop.md, Assembly and refresh). Consolidation is the default: the host runs the SDK's
//! uc-consolidation flow (`unicity_token::client::ProofClient::consolidate`, over its own routing and transport) once, and a
//! consolidated token is an ordinary token whose outer proofs share one seal, so [`crate::proof::build_return_proof`] gives it one
//! anchor per shard the leaves touch. Only an `Unavailable` outcome falls back to the per-SID path (the host refreshes the held
//! token per leaf, as before). A `ConsolidationError` stays the SDK's error: it is never turned into a fallback.

use unicity_token::client::{ConsolidationOutcome, UnavailableReason};
use unicity_token::transaction::Token;

/// Where the redemption bundle's proofs come from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum RedeemProofs {
    /// The consolidated token: assemble it as is (no refetch) and persist it with the pending redemption.
    Consolidated(Token),
    /// Consolidation is unavailable: assemble from per-SID proofs of the held token. `retryable` is the SDK's: whether a later
    /// consolidation attempt may succeed.
    PerSid {
        unavailable: UnavailableReason,
        retryable: bool,
    },
}

/// The path an explicit consolidation outcome selects.
pub fn redeem_proofs(outcome: ConsolidationOutcome) -> RedeemProofs {
    match outcome {
        ConsolidationOutcome::Consolidated { token, .. } => RedeemProofs::Consolidated(token),
        ConsolidationOutcome::Unavailable { reason, retryable } => RedeemProofs::PerSid {
            unavailable: reason,
            retryable,
        },
    }
}
