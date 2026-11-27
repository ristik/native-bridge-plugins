//! The rejection rules of the native bridge v2 specification (bft-core `docs/design/native-bridge-v2.md` section 14), one name
//! each, and the wallet's own refusals (`errors.ts`). The Go reference uses `Err<Name>`; the on-chain verifier reverts with
//! `<Name>()`; the vault's names and selectors are those of section 13.3.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

macro_rules! rules {
    (erc20 = [$($erc20:ident),*]; $($sec:literal => [$($name:ident),* $(,)?]),* $(,)?) => {
        /// A section 14 rule.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[allow(missing_docs)]
        pub enum Rule { $($($name,)*)* $($erc20,)* }

        impl Rule {
            /// Every rule, in section 14 order.
            pub const ALL: &'static [Rule] = &[$($(Rule::$name),*),*];

            /// ERC20 profile rule extensions.
            pub const ERC20: &'static [Rule] = &[$(Rule::$erc20),*];

            /// The rule's name (`AlreadyPaid`).
            pub fn name(self) -> &'static str {
                match self { $($(Rule::$name => stringify!($name),)*)* $(Rule::$erc20 => stringify!($erc20),)* }
            }

            /// Its section (`14.5`).
            pub fn section(self) -> &'static str {
                match self { $($(Rule::$name => $sec,)*)* $(Rule::$erc20 => "ERC20",)* }
            }

            /// The rule of a name.
            pub fn from_name(s: &str) -> Option<Rule> {
                match s { $($(stringify!($name) => Some(Rule::$name),)*)* $(stringify!($erc20) => Some(Rule::$erc20),)* _ => None }
            }
        }
    };
}

rules! {
    erc20 = [BadCredit, ExcessDebit, InsufficientBacking, TokenCallFailed];
    "14.1" => [Truncated, Trailing, NonCanonical, Shape, Tag, Version, Length, IntRange, InputTooLarge, ConfigShape, EvidenceShape],
    "14.2" => [MintDomain, DepositUC, DepositHeader, ReceiptPath, ReceiptType, ReceiptStatus, LogIndex, LogEmitter, LogTopics,
        LogData, SecretOpening, MintSalt, MintType, MintOwner, MintData, MintReason],
    "14.3" => [NotBurn, BurnNotFinal, BurnReason, ReturnData, ReturnDomain, ReturnAsset, ReturnAmount, ReturnRecipient, ReturnIndex],
    "14.4" => [Predicate, MintShape, TransferData, CDMismatch, UnlockLength, UnlockScalars, UnlockRecovery, UnlockKey, RepeatedSID,
        NoTransfers, DeadlineMismatch, DeadlineExpired, InclusionProof, ReferenceTime, SealNetwork, SealEpoch, NoEntryForEpoch,
        CertStructure, SealRoot, QuorumNotMet, UnsupportedCertificateEncoding, SplitJustif, SplitProofCount, SplitProofShape,
        SplitManifest, SplitBurn, SplitProof, SplitSum],
    "14.5" => [BadHistoryLength, FutureIndex, StaleEndpoint, BadGapProof, ChainMismatch, AlreadyPaid, VerifierRefused, VerifierBadReturn,
        DomainMismatch, AssetMismatch, ClaimMismatch, BadRecipient, ZeroAmount, LiabilityUnderflow, SegmentCounterExhausted, PayoutFailed,
        Reentrancy, ZeroValue, BadFirstOwner, LiabilityCap, DepositCounterExhausted, BadConfig],
    "14.6" => [SealReceipt, SegmentLog, CapacityPreflight, CapacityExceeded, ImplausibleIndex, EvidencePruned],
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Offline verification can retry once the trust history holds the seal's epoch.
pub const RETRYABLE_RULES: &[Rule] = &[Rule::NoEntryForEpoch];

/// The deployed verifier cannot distinguish a pending seal import from an invalid quorum.
pub(crate) fn is_retryable_verifier_refusal(inner: Rule) -> bool {
    matches!(inner, Rule::NoEntryForEpoch | Rule::QuorumNotMet)
}

/// A section 14 refusal. `args` are a vault error's arguments as the vectors write them (decimal or `0x` hex); `inner` is the
/// rule a wrapper (`SealReceipt`, `SegmentLog`) carries. `config_field` is set on a Γ failure (`ConfigShape`): the first
/// failing field, 19 for the array itself (the TypeScript `ConfigError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nb2Error {
    pub rule: Rule,
    pub detail: Option<String>,
    pub args: Vec<String>,
    pub inner: Option<Box<Nb2Error>>,
    pub config_field: Option<usize>,
}

impl Nb2Error {
    pub fn new(rule: Rule) -> Self {
        Nb2Error {
            rule,
            detail: None,
            args: Vec::new(),
            inner: None,
            config_field: None,
        }
    }

    pub fn with_detail(rule: Rule, detail: impl Into<String>) -> Self {
        Nb2Error {
            detail: Some(detail.into()),
            ..Nb2Error::new(rule)
        }
    }

    pub fn with_args(rule: Rule, args: Vec<String>) -> Self {
        Nb2Error {
            args,
            ..Nb2Error::new(rule)
        }
    }

    /// `outer` carrying `inner`.
    pub fn wrapping(outer: Rule, inner: Nb2Error) -> Self {
        Nb2Error {
            inner: Some(Box::new(inner)),
            ..Nb2Error::new(outer)
        }
    }

    /// Retry after trust-history refresh or, for an ambiguous on-chain refusal, after seal import.
    pub fn retryable(&self) -> bool {
        RETRYABLE_RULES.contains(&self.rule)
            || self.inner.as_ref().is_some_and(|i| {
                i.retryable()
                    || (self.rule == Rule::VerifierRefused && is_retryable_verifier_refusal(i.rule))
            })
    }

    /// The innermost rule of a wrapper chain.
    pub fn innermost(&self) -> Rule {
        match &self.inner {
            Some(i) => i.innermost(),
            None => self.rule,
        }
    }
}

impl fmt::Display for Nb2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nb2: {}", self.rule)?;
        if !self.args.is_empty() {
            write!(f, "({})", self.args.join(","))?;
        }
        if let Some(i) = &self.inner {
            write!(f, ": {i}")?;
        }
        if let Some(d) = &self.detail {
            write!(f, ": {d}")?;
        }
        Ok(())
    }
}

/// Non-rule outcomes the plug-in reports, and the plug-in's own safety refusals of NB2-07.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletReason {
    /// A plain state() read on a deployment without stateReadOnly: not evidence (section 12.2).
    StateReadNotAdmitted,
    /// The node does not hold the block on its canonical chain: re-resolve and retry (section 12.7).
    CompanionUnknown,
    /// A companion whose witnesses are not [certificate, technical record]: use another provider.
    CompanionProvider,
    /// The trust-base history is not the one Γ names.
    TrustInput,
    TrustSyncRequired,
    ImportLag,
    /// A step on a plan whose journal entry was not durably written first.
    JournalNotPersisted,
    /// A compare-and-swap of a journal record lost to another writer.
    JournalConflict,
    /// Zero or vault recipient (wallet policy; the verifier's rule is ReturnRecipient).
    RecipientRefused,
    /// The requested step does not apply to the journal entry's state.
    NotPending,
    /// A log or receipt the witness needs was not served: never treated as absence.
    EvidenceMissing,
    /// An RPC answer that is inconsistent with itself (wrong hash, wrong root).
    ProviderFault,
    /// Reconcile found Paid(eta): the burn has been redeemed.
    AlreadyPaid,
    /// A submission whose outcome is not known yet: reconcile, never resend blindly.
    Unconfirmed,
    /// The transaction was mined and reverted.
    Reverted,
    /// The paying EVM account cannot fund the worst-case gas limit of the return.
    InsufficientFunds,
    /// The vault's config(), chain ID or runtime code is not the pinned deployment.
    BadDeployment,
    /// A caller argument outside the API's contract.
    BadInput,
}

impl WalletReason {
    pub fn name(self) -> &'static str {
        match self {
            WalletReason::StateReadNotAdmitted => "StateReadNotAdmitted",
            WalletReason::CompanionUnknown => "CompanionUnknown",
            WalletReason::CompanionProvider => "CompanionProvider",
            WalletReason::TrustInput => "TrustInput",
            WalletReason::TrustSyncRequired => "TrustSyncRequired",
            WalletReason::ImportLag => "ImportLag",
            WalletReason::JournalNotPersisted => "JournalNotPersisted",
            WalletReason::JournalConflict => "JournalConflict",
            WalletReason::RecipientRefused => "RecipientRefused",
            WalletReason::NotPending => "NotPending",
            WalletReason::EvidenceMissing => "EvidenceMissing",
            WalletReason::ProviderFault => "ProviderFault",
            WalletReason::AlreadyPaid => "AlreadyPaid",
            WalletReason::Unconfirmed => "Unconfirmed",
            WalletReason::Reverted => "Reverted",
            WalletReason::InsufficientFunds => "InsufficientFunds",
            WalletReason::BadDeployment => "BadDeployment",
            WalletReason::BadInput => "BadInput",
        }
    }
}

/// A wallet refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletError {
    pub reason: WalletReason,
    pub detail: Option<String>,
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nb2 wallet: {}", self.reason.name())?;
        if let Some(d) = &self.detail {
            write!(f, ": {d}")?;
        }
        Ok(())
    }
}

/// Every failure of the plug-in: a rule, a wallet refusal, or anything else (a transport, store or signer failure; the
/// TypeScript plug-in's plain `Error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Rule(Nb2Error),
    Wallet(WalletError),
    Other(String),
}

impl Error {
    /// The rule (or wallet reason) the error names, for vector comparisons and logs (`nameOf`).
    pub fn name(&self) -> String {
        match self {
            Error::Rule(e) => e.rule.name().to_string(),
            Error::Wallet(w) => w.reason.name().to_string(),
            Error::Other(s) => alloc::format!("?{s}"),
        }
    }

    pub fn rule(&self) -> Option<&Nb2Error> {
        match self {
            Error::Rule(e) => Some(e),
            _ => None,
        }
    }

    pub fn reason(&self) -> Option<WalletReason> {
        match self {
            Error::Wallet(w) => Some(w.reason),
            _ => None,
        }
    }

    /// Whether this refusal is eligible for a retry.
    pub fn retryable(&self) -> bool {
        matches!(self, Error::Rule(e) if e.retryable())
            || matches!(
                self.reason(),
                Some(WalletReason::ImportLag | WalletReason::TrustSyncRequired)
            )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rule(e) => e.fmt(f),
            Error::Wallet(w) => w.fmt(f),
            Error::Other(s) => f.write_str(s),
        }
    }
}

#[cfg(feature = "host")]
impl std::error::Error for Error {}

impl From<Nb2Error> for Error {
    fn from(e: Nb2Error) -> Self {
        Error::Rule(e)
    }
}

impl From<WalletError> for Error {
    fn from(e: WalletError) -> Self {
        Error::Wallet(e)
    }
}

/// Result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Refuse with `rule`.
pub fn fail<T>(rule: Rule) -> Result<T> {
    Err(Error::Rule(Nb2Error::new(rule)))
}

/// Refuse with `rule` and a detail.
pub fn fail_d<T>(rule: Rule, detail: impl Into<String>) -> Result<T> {
    Err(Error::Rule(Nb2Error::with_detail(rule, detail)))
}

/// A rule error with arguments (decimal or `0x` hex strings).
pub fn fail_args<T>(rule: Rule, args: Vec<String>) -> Result<T> {
    Err(Error::Rule(Nb2Error::with_args(rule, args)))
}

/// `outer` carrying `e` when it is a rule; any other error passes through (`wrap`).
pub fn wrap(outer: Rule, e: Error) -> Error {
    match e {
        Error::Rule(inner) => Error::Rule(Nb2Error::wrapping(outer, inner)),
        other => other,
    }
}

/// A wallet refusal.
pub fn refuse<T>(reason: WalletReason, detail: impl Into<String>) -> Result<T> {
    Err(Error::Wallet(WalletError {
        reason,
        detail: Some(detail.into()),
    }))
}

/// A wallet refusal without detail.
pub fn refuse0<T>(reason: WalletReason) -> Result<T> {
    Err(Error::Wallet(WalletError {
        reason,
        detail: None,
    }))
}

/// The same refusal as a value.
pub fn wallet_err(reason: WalletReason, detail: impl Into<String>) -> Error {
    Error::Wallet(WalletError {
        reason,
        detail: Some(detail.into()),
    })
}

/// A rule error as a value.
pub fn rule_err(rule: Rule) -> Error {
    Error::Rule(Nb2Error::new(rule))
}

/// Convenience: map any error of a sub-step into the given rule (TypeScript `catch { fail(rule) }`).
pub fn or_rule<T>(r: Result<T>, rule: Rule) -> Result<T> {
    r.map_err(|_| rule_err(rule))
}
