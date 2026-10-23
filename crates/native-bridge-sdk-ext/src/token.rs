//! Full-history verification of a native bridge token.
//!
//! The standard SDK token carries its complete immutable lock evidence in the genesis justification
//! and its aggregator inclusion proofs in the certified transactions. Verification reads nothing
//! else: the deployment allow-list and the SDK trust base are installed beforehand, and no function
//! here has any network capability.
//!
//! A bare SDK registration only sees genesis. [`NativeBridge::verify_native_token`] is the gate every
//! import, credit, transfer, burn and export must call.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use unicity_token::api::{InclusionProof, StateId};
use unicity_token::transaction::Transaction;
use unicity_token::Token;

use crate::deployment::{Deployment, DeploymentRegistry};
use crate::error::{NativeError as E, Result};
use crate::history::{self, History, Leaf, Outcome};
use crate::lineage::{verify_lineage, LineageOutcome};
use crate::lockproof::{self, parse_justification, VerifiedLock};
use crate::splitpart::{is_split_reason, root_justification, split_chain};
use crate::trust::TrustInput;
use alloc::rc::Rc;
use unicity_token::verify::{
    verify_token_with_policy, MintJustificationRegistry, VerificationError, VerificationPolicy,
};

/// What the verifier must establish about the token's terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Zero or more signature transfers; a burn is rejected.
    Receipt,
    /// The history ends in the exact return burn.
    Return,
}

/// The result of a successful full-history verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    /// For a split part, the lineage's root identity and every leaf of the lineage, root first (`lineage` below).
    pub outcome: Outcome,
    pub lock: VerifiedLock,
    /// Index of the allow-listed deployment the token was verified under.
    pub deployment: usize,
    /// A split part's lineage (protocol 6): the part, the depth and the walk's charge; `None` for a lock-backed token.
    pub lineage: Option<LineageOutcome>,
}

/// The installed trust: allow-listed deployments and the SDK trust base, used as is.
#[derive(Debug, Clone)]
pub struct NativeBridge {
    pub registry: DeploymentRegistry,
    pub trust: TrustInput,
}

impl NativeBridge {
    /// Install the deployments and the one fixed trust input. Every deployment must belong to the
    /// base's network.
    pub fn new(registry: DeploymentRegistry, trust: TrustInput) -> Result<Self> {
        for d in registry.deployments() {
            if d.cfg.network != trust.network_id().id() {
                return Err(E::NetworkMismatch);
            }
        }
        Ok(NativeBridge { registry, trust })
    }

    /// Decode canonical token bytes (bounded, re-encoding equal) and verify them.
    pub fn verify_native_token_bytes(&self, bytes: &[u8], expect: Expect) -> Result<VerifiedToken> {
        crate::resources::preflight_token(bytes)?;
        let token = Token::from_cbor(bytes).map_err(|_| E::SdkDecode)?;
        if token.to_cbor() != bytes {
            return Err(E::NonCanonical);
        }
        self.verify_native_token(&token, expect)
    }

    /// Verify a return as completion of the exact held-token burn request. Proof refresh is allowed;
    /// genesis, prior transactions, certification data and reference times must stay identical.
    pub fn verify_burn_request_bytes(
        &self,
        held: &[u8],
        burned: &[u8],
        reason: &[u8],
    ) -> Result<VerifiedToken> {
        self.verify_native_token_bytes(held, Expect::Receipt)?;
        let verified = self.verify_native_token_bytes(burned, Expect::Return)?;
        let before = Token::from_cbor(held).map_err(|_| E::SdkDecode)?;
        let after = Token::from_cbor(burned).map_err(|_| E::SdkDecode)?;
        if after.transactions().len() != before.transactions().len() + 1 {
            return Err(E::BurnReason);
        }
        let same = |a: &InclusionProof, b: &InclusionProof| {
            a.certification_data.to_cbor() == b.certification_data.to_cbor()
                && a.reference_time == b.reference_time
        };
        if before.genesis().transaction().to_cbor() != after.genesis().transaction().to_cbor()
            || !same(
                before.genesis().inclusion_proof(),
                after.genesis().inclusion_proof(),
            )
        {
            return Err(E::BurnReason);
        }
        for (a, b) in before.transactions().iter().zip(after.transactions()) {
            if a.transaction().to_cbor() != b.transaction().to_cbor()
                || !same(a.inclusion_proof(), b.inclusion_proof())
            {
                return Err(E::BurnReason);
            }
        }
        if after
            .transactions()
            .last()
            .ok_or(E::BurnReason)?
            .transaction()
            .data()
            != Some(reason)
        {
            return Err(E::BurnReason);
        }
        Ok(verified)
    }

    /// Verify a decoded token over its whole history.
    pub fn verify_native_token(&self, token: &Token, expect: Expect) -> Result<VerifiedToken> {
        crate::resources::preflight_token(&token.to_cbor())?;
        let mint = token.genesis().transaction();
        // The generic data hook skips null data, so missing genesis data and justification are
        // rejected here before anything else runs.
        let j = mint.justification().ok_or(E::MintJustif)?;
        if mint.data().is_none() {
            return Err(E::MintData);
        }
        if is_split_reason(Some(j)) {
            return self.verify_split_part(token, expect);
        }
        // J's errors are already the oracle's (bft-core ParseJustification), so they pass through unchanged.
        let parsed = parse_justification(j)?;
        let index = self
            .registry
            .deployments()
            .iter()
            .position(|d| {
                d.cfg.network == mint.network_id().id()
                    && d.cfg.chain_id == parsed.chain_id
                    && d.cfg.vault == parsed.vault
            })
            .ok_or(E::UnknownDeployment)?;
        let dep = &self.registry.deployments()[index];

        let hist_bytes = history::project(token);
        let hist = History::decode_composed(&hist_bytes)?;
        let outcome = history::verify_history_as(dep, &hist, expect == Expect::Return)?;
        if expect == Expect::Receipt
            && hist
                .transfers
                .last()
                .is_some_and(|t| t.recipient.typ == crate::limits::PRED_BURN)
        {
            return Err(E::UnexpectedBurn);
        }

        // Positive, permanent, offline evidence of the lock.
        let lock = lockproof::verify(dep, &self.trust, &parsed, &outcome.lock_digest)?;

        // Bridge-specific checks per certified leaf: fixed-profile guards, aggregator admission and the
        // `t <= IR.timestamp` bound the Rust SDK lacks (no cumulative path budget, owner section 36).
        let mut leaves = outcome.leaves.iter();
        let g = token.genesis();
        check_leaf(
            dep,
            &self.trust,
            g.inclusion_proof(),
            g.transaction(),
            leaves.next().ok_or(E::Shape)?,
        )?;
        for t in token.transactions() {
            check_leaf(
                dep,
                &self.trust,
                t.inclusion_proof(),
                t.transaction(),
                leaves.next().ok_or(E::Shape)?,
            )?;
        }

        // The SDK's own ordinary token verification against the held history (each certificate
        // under its own epoch's committee), with the justification/data registries.
        let mut registry = MintJustificationRegistry::new();
        crate::verifier::install(Rc::new(self.clone()), &mut registry).map_err(|_| E::TrustBase)?;
        let policy = VerificationPolicy {
            require_token_data_verifier: true,
            ..Default::default()
        };
        verify_token_with_policy(token, self.trust.history(), &registry, policy)
            .map_err(|e| map_sdk(&e))?;
        Ok(VerifiedToken {
            outcome,
            lock,
            deployment: index,
            lineage: None,
        })
    }

    /// A split part (protocol 6): the lineage relation over the part's projection (its ancestry read from the exact reason bytes),
    /// the root's lock proof against the root's lock digest, every leaf of the lineage (root first) admitted under the deployment's
    /// policy, then the SDK's own verification (the split verifier walks the same ancestry).
    fn verify_split_part(&self, token: &Token, expect: Expect) -> Result<VerifiedToken> {
        let mint = token.genesis().transaction();
        let root_j = root_justification(mint.justification())?;
        let parsed = parse_justification(&root_j)?;
        let index = self
            .registry
            .deployments()
            .iter()
            .position(|d| {
                d.cfg.network == mint.network_id().id()
                    && d.cfg.chain_id == parsed.chain_id
                    && d.cfg.vault == parsed.vault
            })
            .ok_or(E::UnknownDeployment)?;
        let dep = &self.registry.deployments()[index];

        let hist = History::decode_composed(&history::project(token))?;
        let lineage = verify_lineage(dep, hist, expect == Expect::Return)?;
        let lock = lockproof::verify(dep, &self.trust, &parsed, &lineage.outcome.lock_digest)?;

        let chain = split_chain(token)?;
        let mut leaves = lineage.outcome.leaves.iter();
        for t in &chain {
            let g = t.genesis();
            check_leaf(
                dep,
                &self.trust,
                g.inclusion_proof(),
                g.transaction(),
                leaves.next().ok_or(E::CDMismatch)?,
            )?;
            for c in t.transactions() {
                check_leaf(
                    dep,
                    &self.trust,
                    c.inclusion_proof(),
                    c.transaction(),
                    leaves.next().ok_or(E::CDMismatch)?,
                )?;
            }
        }
        if leaves.next().is_some() {
            return Err(E::CDMismatch);
        }

        let mut registry = MintJustificationRegistry::new();
        crate::verifier::install(Rc::new(self.clone()), &mut registry).map_err(|_| E::TrustBase)?;
        let policy = VerificationPolicy {
            require_token_data_verifier: true,
            ..Default::default()
        };
        verify_token_with_policy(token, self.trust.history(), &registry, policy)
            .map_err(|e| map_sdk(&e))?;
        Ok(VerifiedToken {
            outcome: lineage.outcome.clone(),
            lock,
            deployment: index,
            lineage: Some(lineage),
        })
    }
}

/// Bridge-specific checks of one certified leaf; certification data equality was established by
/// the relation. Everything the SDK defines (network, seal fold, quorum, path, shard, predicate)
/// stays the SDK's.
pub fn check_leaf(
    dep: &Deployment,
    trust: &TrustInput,
    proof: &InclusionProof,
    tx: &impl Transaction,
    leaf: &Leaf,
) -> Result<()> {
    let uc = &proof.unicity_certificate;
    if proof.reference_time != leaf.reference_time {
        return Err(E::CDMismatch);
    }
    let sid = StateId::derive(tx.lock_script(), tx.source_state_hash());
    if sid.bytes() != &leaf.sid
        || proof.certification_data.transaction_hash().data() != leaf.tx_hash.as_slice()
    {
        return Err(E::CDMismatch);
    }
    // The seal epoch's committee first (protocol/trust-base.md order; the SDK token verification
    // below checks the tree root before the epoch), so several faults get the oracle's verdict.
    crate::trust::select_epoch(trust, uc)?;
    // Aggregator admission: the pinned policy names the partition only. The certificate authenticates its own historical shard and
    // configuration; the shard must be a canonical native ID whose prefix the leaf's state ID carries (the first `d` bits, `d` its
    // own depth).
    if uc.unicity_tree_certificate.partition_identifier != dep.policy.partition {
        return Err(E::NotAdmitted);
    }
    let shard = uc.shard_tree_certificate.shard.encode();
    if crate::profile::shard_depth(&shard).is_err()
        || !crate::profile::shard_covers(&shard, &leaf.sid)
    {
        return Err(E::ShardMismatch);
    }
    // The leaf cannot have been created after the round whose root authenticates it.
    if leaf.reference_time > uc.input_record.timestamp {
        return Err(E::ReferenceTimeFuture);
    }
    Ok(())
}

/// Reject a token whose state ids repeat, as a cheap standalone guard.
pub fn distinct_state_ids(token: &Token) -> bool {
    let mut seen = BTreeSet::new();
    let g = token.genesis().transaction();
    let mut ids: Vec<[u8; 32]> = Vec::new();
    ids.push(*StateId::derive(g.lock_script(), g.source_state_hash()).bytes());
    for t in token.transactions() {
        let tx = t.transaction();
        ids.push(*StateId::derive(tx.lock_script(), tx.source_state_hash()).bytes());
    }
    ids.into_iter().all(|i| seen.insert(i))
}

/// Name an SDK verification failure with the shared sentinel vocabulary.
pub fn map_sdk(e: &VerificationError) -> E {
    // certificate failures are named as for the embedded certificate
    if let Some(c) = crate::trust::certificate_failure(e) {
        return c;
    }
    match e {
        VerificationError::Genesis(inner) => map_sdk(inner),
        VerificationError::Transfer { source, .. } => map_sdk(source),
        VerificationError::PathInvalid => E::PathInvalid,
        VerificationError::NetworkMismatch => E::SealNetwork,
        VerificationError::ShardMismatch => E::ShardMismatch,
        VerificationError::RequestExpired => E::DeadlineExpired,
        VerificationError::CertificationDataMismatch
        | VerificationError::TransactionHashMismatch
        | VerificationError::ReferenceTimeMismatch => E::CDMismatch,
        _ => E::SdkVerification,
    }
}
