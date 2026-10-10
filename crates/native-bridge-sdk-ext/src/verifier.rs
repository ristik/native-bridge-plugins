//! SDK-registry adapters: `NativeLockJustificationVerifier` (tag 39049, v2 with the embedded lock
//! proof) and `BridgedTokenIssuancePolicy` (the exact lock reason plus the exact value envelope).
//!
//! Installing these in a registry is an application trust decision; manifests never authorise
//! executable code merely by arriving with a token. The registry hooks see genesis only, so they
//! cannot enforce the full-history profile: [`crate::token::NativeBridge::verify_native_token`]
//! is the gate for whole tokens.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::Cell;

use unicity_token::transaction::{CertifiedMintTransaction, TokenType, Transaction};
use unicity_token::verify::{
    MintJustificationRegistry, MintJustificationVerifier, TokenDataVerifier, VerificationContext,
    VerificationError,
};

use crate::error::{Family, NativeError as E, Result};
use crate::history::{check_justification, check_mint_data};
use crate::limits::TAG_MINT_LOCK;
use crate::lockproof::{self, parse_justification};
use crate::profile::{derive_salt, derive_token_id, h, lock_digest, lock_record};
use crate::token::NativeBridge;

fn map_error(e: E, malformed: VerificationError) -> VerificationError {
    match e.family() {
        Family::Malformed => malformed,
        Family::Budget => VerificationError::VerificationLimitExceeded("native lock proof"),
        Family::Invalid | Family::Unavailable => VerificationError::UnsupportedMintJustification,
    }
}

/// Verifies the native lock justification of a genesis fully offline.
pub struct NativeLockJustificationVerifier {
    bridge: Rc<NativeBridge>,
    last: Cell<Option<E>>,
}

impl NativeLockJustificationVerifier {
    pub fn new(bridge: Rc<NativeBridge>) -> Self {
        Self {
            bridge,
            last: Cell::new(None),
        }
    }

    /// The exact native reason of the most recent failure, for identity-level diagnostics.
    pub fn last_error(&self) -> Option<E> {
        self.last.get()
    }

    /// Verify the genesis binding to the certified permanent lock.
    pub fn check(&self, genesis: &CertifiedMintTransaction) -> Result<()> {
        let mint = genesis.transaction();
        let j = mint.justification().ok_or(E::MintJustif)?;
        let parsed = parse_justification(j).map_err(|e| match e {
            E::InputTooLarge | E::ProofTooLarge | E::TooDeep | E::TooManyItems => e,
            _ => E::MintJustif,
        })?;
        let dep =
            self.bridge
                .registry
                .find(mint.network_id().id(), parsed.chain_id, &parsed.vault)?;
        if mint.token_type().bytes() != dep.cfg.ty {
            return Err(E::MintType);
        }
        let data = mint.data().ok_or(E::MintData)?;
        let amount = check_mint_data(dep, Some(data))?;
        let nonce = check_justification(dep, Some(j))?;
        let salt = derive_salt(&dep.cfg_hash, nonce);
        if mint.salt().bytes() != &salt {
            return Err(E::MintSalt);
        }
        let id = derive_token_id(&salt, dep.cfg.network);
        let first = h(&mint.recipient().to_cbor());
        let digest = lock_digest(
            &dep.cfg_hash,
            nonce,
            &lock_record(
                &dep.cfg.zero_address,
                &dep.cfg.ty,
                &dep.cfg.aid,
                &amount,
                &id,
                &first,
            ),
        );
        lockproof::verify(dep, &self.bridge.trust, &parsed, &digest)?;
        Ok(())
    }
}

impl MintJustificationVerifier for NativeLockJustificationVerifier {
    fn tag(&self) -> u64 {
        TAG_MINT_LOCK
    }

    fn verify(
        &self,
        genesis: &CertifiedMintTransaction,
        context: &mut VerificationContext<'_>,
    ) -> core::result::Result<(), VerificationError> {
        self.last.set(None);
        // One fixed base throughout: a caller-supplied different base is outside the profile.
        if context.trust_base() != self.bridge.trust.base() {
            self.last.set(Some(E::TrustBase));
            return Err(VerificationError::UnsupportedMintJustification);
        }
        self.check(genesis).map_err(|e| {
            self.last.set(Some(e));
            map_error(e, VerificationError::MalformedMintJustification)
        })
    }
}

/// Claims exactly the native asset for one token type. It requires the exact native lock reason and
/// the exact value envelope, and rejects null, unknown and split reasons: no split exception.
pub struct BridgedTokenIssuancePolicy {
    bridge: Rc<NativeBridge>,
    token_type: TokenType,
    last: Cell<Option<E>>,
}

impl BridgedTokenIssuancePolicy {
    pub fn new(bridge: Rc<NativeBridge>, token_type: &[u8; 32]) -> Self {
        Self {
            bridge,
            token_type: TokenType::new(*token_type),
            last: Cell::new(None),
        }
    }

    pub fn last_error(&self) -> Option<E> {
        self.last.get()
    }

    pub fn check(&self, genesis: &CertifiedMintTransaction) -> Result<()> {
        let mint = genesis.transaction();
        let j = mint.justification().ok_or(E::IssuanceReason)?;
        let parsed = parse_justification(j).map_err(|_| E::IssuanceReason)?;
        let dep = self
            .bridge
            .registry
            .find(mint.network_id().id(), parsed.chain_id, &parsed.vault)
            .map_err(|_| E::IssuanceReason)?;
        if mint.token_type().bytes() != self.token_type.bytes()
            || dep.cfg.ty.as_slice() != self.token_type.bytes()
        {
            return Err(E::MintType);
        }
        check_justification(dep, Some(j)).map_err(|_| E::IssuanceReason)?;
        check_mint_data(dep, mint.data()).map_err(|_| E::IssuanceData)?;
        Ok(())
    }
}

impl TokenDataVerifier for BridgedTokenIssuancePolicy {
    fn token_type(&self) -> &TokenType {
        &self.token_type
    }

    fn verify(
        &self,
        genesis: &CertifiedMintTransaction,
        _context: &mut VerificationContext<'_>,
    ) -> core::result::Result<(), VerificationError> {
        self.last.set(None);
        self.check(genesis).map_err(|e| {
            self.last.set(Some(e));
            VerificationError::PaymentIssuanceRejected
        })
    }
}

/// Install the native verifier and one issuance policy per distinct deployed token type.
pub fn install(
    bridge: Rc<NativeBridge>,
    registry: &mut MintJustificationRegistry,
) -> unicity_token::Result<()> {
    registry.register(Box::new(NativeLockJustificationVerifier::new(
        bridge.clone(),
    )))?;
    let mut types: Vec<[u8; 32]> = Vec::new();
    for d in bridge.registry.deployments() {
        if !types.contains(&d.cfg.ty) {
            types.push(d.cfg.ty);
        }
    }
    for ty in types {
        registry.register_token_data(Box::new(BridgedTokenIssuancePolicy::new(
            bridge.clone(),
            &ty,
        )))?;
    }
    Ok(())
}
