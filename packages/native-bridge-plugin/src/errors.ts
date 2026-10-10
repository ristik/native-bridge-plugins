/** Failure family: malformed encoding, relation outside the profile or wrong, or a budget. */
export type NativeFamily = 'malformed' | 'invalid' | 'budget';

const M = 'malformed' as const;
const B = 'budget' as const;
const I = 'invalid' as const;

/**
 * Sentinel names shared with the Rust crate and the Go oracle (`Err` + name). Every identity a test
 * asserts is one of these.
 */
const FAMILY = {
  ErrTruncated: M, ErrTrailing: M, ErrNonCanonical: M, ErrForbiddenCBOR: M, ErrShape: M, ErrTag: M,
  ErrVersion: M, ErrLength: M, ErrIntRange: M, ErrABIFraming: M, ErrBadOperation: M, ErrRlpMalformed: M,
  ErrMptMalformed: M, ErrSdkDecode: M,
  ErrInputTooLarge: B, ErrTooManyTx: B, ErrTooManyItems: B, ErrTooDeep: B, ErrTooManyPaths: B, ErrProofTooLarge: B, ErrGasBudget: B,
  ErrCfgMismatch: I, ErrPolicyHash: I, ErrPolicyTuple: I, ErrPolicyAnchors: I, ErrPolicyLeafIndex: I,
  ErrPolicyLeafCount: I, ErrPolicyPartition: I, ErrPathBitmap: I, ErrAnchorAuth: I, ErrPredicate: I, ErrMintShape: I, ErrMintJustif: I,
  ErrMintSalt: I, ErrMintType: I, ErrMintData: I, ErrTransferData: I, ErrCDMismatch: I, ErrUnlock: I,
  ErrUnlockLength: I, ErrUnlockScalars: I, ErrUnlockRecovery: I, ErrUnlockKey: I, ErrMinterKey: I,
  ErrRepeatedSID: I, ErrNoTransfers: I, ErrHasTransfers: I, ErrBurnNotFinal: I, ErrNotBurn: I,
  ErrBurnReason: I, ErrReturnData: I, ErrReturnAmount: I, ErrReturnRecip: I, ErrLockInput: I,
  ErrZeroDigest: I, ErrDeadlineExpired: I, ErrReferenceTimeFuture: I, ErrInputRecordMismatch: I,
  ErrUnexpectedBurn: I, ErrRefreshMismatch: I, ErrProofUnavailable: I,
  ErrIssuanceReason: I, ErrIssuanceData: I, ErrIssuanceSplit: I, ErrUnknownDeployment: I,
  ErrAmbiguousDeployment: I, ErrNetworkMismatch: I,
  ErrTrustBase: I, ErrSdkVerification: I, ErrEpochMismatch: I, ErrRoundBeforeEpochStart: I,
  ErrUnsupportedTrustBase: I, ErrTrustBaseDigest: I, ErrUnsupportedCertificateEncoding: I,
  ErrSealNetwork: I, ErrSealRoot: I, ErrQuorumNotMet: I, ErrNotAdmitted: I, ErrShardMismatch: I,
  ErrPathInvalid: I,
  ErrMissingBacking: I, ErrLockProofCfg: I, ErrLockProofTrust: I, ErrEvmPartition: I, ErrEvmShard: I,
  ErrEvmConfigHash: I, ErrEvmConfigPin: I, ErrHeaderHash: I, ErrHeaderRoot: I, ErrHeaderProfile: I,
  ErrAccountProof: I, ErrAccountCode: I, ErrStorageProof: I, ErrStorageValue: I, ErrLockDigest: I,
  ErrManifest: I,
} as const;

export type NativeReason = keyof typeof FAMILY;

/** A native profile failure; `reason` is the shared sentinel name. */
/**
 * Failures a host may retry later: a racing or mismatched (path, UC) pair that survived the bounded
 * retries, never a failure of the token or of the profile bounds.
 */
export const RETRYABLE: readonly NativeReason[] = ['ErrProofUnavailable'];

export class NativeError extends Error {
  public readonly family: NativeFamily;

  public constructor(public readonly reason: NativeReason) {
    super(reason);
    this.name = 'NativeError';
    this.family = FAMILY[reason];
  }
}

/** Throw a profile error. */
export function fail(reason: NativeReason): never {
  throw new NativeError(reason);
}
