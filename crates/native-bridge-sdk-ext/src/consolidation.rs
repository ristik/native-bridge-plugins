//! The redemption's proof path (interop.md, Assembly and refresh). Consolidation is the default: the host runs the SDK's
//! uc-consolidation flow (`unicity_token::client::ProofClient::consolidate`, over its own routing and transport) once, and a
//! consolidated token is an ordinary token whose outer proofs share one seal, so [`crate::proof::build_return_proof`] gives it one
//! anchor per shard the leaves touch. Only an `Unavailable` outcome falls back to the per-SID path (the host refreshes the held
//! token per leaf, as before). A `ConsolidationError` stays the SDK's error: it is never turned into a fallback. A partition with
//! more shards than the view admits is not consolidated at all ([`consolidation_applies`]): the SDK would refuse its topology as
//! an integrity error, not report it unavailable.

use unicity_token::client::{ConsolidationOutcome, UnavailableReason};
use unicity_token::transaction::Token;

/// The partition view's V1 shard limit (`MaxPartitionViewLeaves`).
pub const MAX_VIEW_SHARDS: usize = 8;

/// Whether the host calls consolidation for an aggregation partition of `partition_shards` shards (its routing): only up to
/// [`MAX_VIEW_SHARDS`]; a larger partition is assembled per SID without calling it.
pub fn consolidation_applies(partition_shards: usize) -> bool {
    partition_shards <= MAX_VIEW_SHARDS
}

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
