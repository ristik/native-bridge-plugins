//! Error taxonomy. Variant names are the sentinel names shared with the Go oracle and the
//! TypeScript plug-in (`Err` + variant), so vectors and tests can name the exact reason.

/// Failure family: malformed encoding, relation outside the profile or wrong, or a budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Malformed,
    Invalid,
    Budget,
}

macro_rules! errors {
    ($($name:ident => $fam:ident),* $(,)?) => {
        /// A profile failure; the variant name is the shared sentinel name.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[allow(missing_docs)]
        pub enum NativeError { $($name),* }

        impl NativeError {
            /// The sentinel name used by vectors and the TypeScript plug-in.
            pub fn name(&self) -> &'static str {
                match self { $(NativeError::$name => concat!("Err", stringify!($name))),* }
            }
            /// The failure family.
            pub fn family(&self) -> Family {
                match self { $(NativeError::$name => Family::$fam),* }
            }
        }
    };
}

errors! {
    // framing and encoding
    Truncated => Malformed, Trailing => Malformed, NonCanonical => Malformed,
    ForbiddenCBOR => Malformed, Shape => Malformed, Tag => Malformed, Version => Malformed,
    Length => Malformed, IntRange => Malformed, ABIFraming => Malformed, BadOperation => Malformed,
    RlpMalformed => Malformed, MptMalformed => Malformed, SdkDecode => Malformed,
    // budgets
    InputTooLarge => Budget, TooManyTx => Budget, TooManyItems => Budget, TooDeep => Budget,
    TooManyPaths => Budget, ProofTooLarge => Budget, GasBudget => Budget,
    // profile relation
    CfgMismatch => Invalid, PolicyHash => Invalid, PolicyTuple => Invalid, PolicyAnchors => Invalid,
    PolicyLeafIndex => Invalid, PolicyLeafCount => Invalid, PolicyPartition => Invalid,
    PathBitmap => Invalid, AnchorAuth => Invalid, ProofUnavailable => Invalid,
    Predicate => Invalid, MintShape => Invalid, MintJustif => Invalid, MintSalt => Invalid,
    MintType => Invalid, MintData => Invalid, TransferData => Invalid, CDMismatch => Invalid,
    Unlock => Invalid, UnlockLength => Invalid, UnlockScalars => Invalid, UnlockRecovery => Invalid,
    UnlockKey => Invalid, MinterKey => Invalid, RepeatedSID => Invalid, NoTransfers => Invalid,
    HasTransfers => Invalid, BurnNotFinal => Invalid, NotBurn => Invalid, BurnReason => Invalid,
    ReturnData => Invalid, ReturnAmount => Invalid, ReturnRecip => Invalid, LockInput => Invalid,
    ZeroDigest => Invalid, DeadlineExpired => Invalid, ReferenceTimeFuture => Invalid,
    InputRecordMismatch => Invalid, UnexpectedBurn => Invalid, RefreshMismatch => Invalid,
    // issuance policy and deployments
    IssuanceReason => Invalid, IssuanceData => Invalid, IssuanceSplit => Invalid,
    UnknownDeployment => Invalid, AmbiguousDeployment => Invalid, NetworkMismatch => Invalid,
    // trust
    TrustBase => Invalid, SdkVerification => Invalid, EpochMismatch => Invalid,
    RoundBeforeEpochStart => Invalid, UnsupportedTrustBase => Invalid, TrustBaseDigest => Invalid,
    UnsupportedCertificateEncoding => Invalid,
    SealNetwork => Invalid, SealRoot => Invalid, QuorumNotMet => Invalid,
    NotAdmitted => Invalid, ShardMismatch => Invalid, PathInvalid => Invalid,
    // embedded lock proof
    MissingBacking => Invalid, LockProofCfg => Invalid, LockProofTrust => Invalid,
    EvmPartition => Invalid, EvmShard => Invalid, EvmConfigHash => Invalid, EvmConfigPin => Invalid,
    HeaderHash => Invalid, HeaderRoot => Invalid, HeaderProfile => Invalid,
    AccountProof => Invalid, AccountCode => Invalid, StorageProof => Invalid, StorageValue => Invalid,
    LockDigest => Invalid,
    // manifests
    Manifest => Invalid,
}

impl core::fmt::Display for NativeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(feature = "host")]
impl std::error::Error for NativeError {}

/// Result alias.
pub type Result<T> = core::result::Result<T, NativeError>;
