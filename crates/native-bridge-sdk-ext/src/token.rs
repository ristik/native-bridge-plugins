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
use crate::limits::*;
use crate::lockproof::{self, parse_justification, VerifiedLock};
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
    pub outcome: Outcome,
    pub lock: VerifiedLock,
    /// Index of the allow-listed deployment the token was verified under.
    pub deployment: usize,
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
            if d.cfg.network != trust.base().network_id.id() {
                return Err(E::NetworkMismatch);
            }
        }
        Ok(NativeBridge { registry, trust })
    }

    /// Decode canonical token bytes (bounded, re-encoding equal) and verify them.
    pub fn verify_native_token_bytes(&self, bytes: &[u8], expect: Expect) -> Result<VerifiedToken> {
        if bytes.len() > MAX_TOKEN_BYTES {
            return Err(E::InputTooLarge);
        }
        let token = Token::from_cbor(bytes).map_err(|_| E::SdkDecode)?;
        if token.to_cbor() != bytes {
            return Err(E::NonCanonical);
        }
        self.verify_native_token(&token, expect)
    }

    /// Verify a decoded token over its whole history.
    pub fn verify_native_token(&self, token: &Token, expect: Expect) -> Result<VerifiedToken> {
        if token.transactions().len() > MAX_TRANSFERS {
            return Err(E::TooManyTx);
        }
        let mint = token.genesis().transaction();
        // The generic data hook skips null data, so missing genesis data and justification are
        // rejected here before anything else runs.
        let j = mint.justification().ok_or(E::MintJustif)?;
        if mint.data().is_none() {
            return Err(E::MintData);
        }
        let parsed = parse_justification(j).map_err(|e| match e {
            E::InputTooLarge | E::ProofTooLarge | E::TooDeep | E::TooManyItems => e,
            _ => E::MintJustif,
        })?;
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
        let hist = History::decode(&hist_bytes)?;
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

        // Bridge-specific checks per certified leaf: fixed-profile guards, aggregator admission,
        // path budget and the `t <= IR.timestamp` bound the Rust SDK lacks.
        let mut steps = 0usize;
        let mut leaves = outcome.leaves.iter();
        let g = token.genesis();
        check_leaf(
            dep,
            &self.trust,
            g.inclusion_proof(),
            g.transaction(),
            leaves.next().ok_or(E::Shape)?,
            &mut steps,
        )?;
        for t in token.transactions() {
            check_leaf(
                dep,
                &self.trust,
                t.inclusion_proof(),
                t.transaction(),
                leaves.next().ok_or(E::Shape)?,
                &mut steps,
            )?;
        }

        // The SDK's own ordinary token verification, with the same base throughout and the
        // existing justification/data registries; it keeps its count-quorum behaviour.
        let mut registry = MintJustificationRegistry::new();
        crate::verifier::install(Rc::new(self.clone()), &mut registry).map_err(|_| E::TrustBase)?;
        let policy = VerificationPolicy {
            require_token_data_verifier: true,
            ..Default::default()
        };
        verify_token_with_policy(token, self.trust.base(), &registry, policy)
            .map_err(|e| map_sdk(&e))?;
        Ok(VerifiedToken {
            outcome,
            lock,
            deployment: index,
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
    steps: &mut usize,
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
    trust.check_guards(uc)?;
    // Aggregator admission against the pinned one-shard policy, never the certificate's own tuple.
    if uc.unicity_tree_certificate.partition_identifier != dep.policy.partition
        || uc.shard_configuration_hash.as_slice() != dep.policy.shard_conf.as_slice()
    {
        return Err(E::NotAdmitted);
    }
    if uc.shard_tree_certificate.shard.length() != 0 {
        return Err(E::ShardMismatch);
    }
    let encoded = proof.inclusion_certificate.encode();
    *steps += (encoded.len() - 32) / 32;
    if *steps > MAX_PATH_STEPS {
        return Err(E::TooManyPaths);
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
    match e {
        VerificationError::Genesis(inner) => map_sdk(inner),
        VerificationError::Transfer { source, .. } => map_sdk(source),
        VerificationError::PathInvalid => E::PathInvalid,
        VerificationError::QuorumNotMet => E::QuorumNotMet,
        VerificationError::SealRootMismatch => E::SealRoot,
        VerificationError::SealNetworkMismatch | VerificationError::NetworkMismatch => {
            E::SealNetwork
        }
        VerificationError::ShardMismatch => E::ShardMismatch,
        VerificationError::RequestExpired => E::DeadlineExpired,
        VerificationError::CertificationDataMismatch
        | VerificationError::TransactionHashMismatch
        | VerificationError::ReferenceTimeMismatch => E::CDMismatch,
        VerificationError::InvalidTrustBase(_) => E::TrustBase,
        _ => E::SdkVerification,
    }
}
