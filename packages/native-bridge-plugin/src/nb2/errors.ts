/**
 * The rejection rules of the native bridge v2 specification (bft-core `docs/design/native-bridge-v2.md` section 14), one name each.
 * The Go reference (bft-core `nb2ref`, NB2-03) uses `Err<Name>`; the on-chain verifier reverts with `<Name>()`; the vault's names and
 * selectors are those of section 13.3. The plug-in's own refusals that are not section 14 rules (a journal that is not persisted, a
 * plain RPC index on a production deployment, a recipient refused by wallet policy) are {@link WalletError}s.
 */

export const RULES = {
  '14.1': ['Truncated', 'Trailing', 'NonCanonical', 'Shape', 'Tag', 'Version', 'Length', 'IntRange', 'InputTooLarge', 'ConfigShape', 'EvidenceShape'],
  '14.2': ['MintDomain', 'DepositUC', 'DepositHeader', 'ReceiptPath', 'ReceiptType', 'ReceiptStatus', 'LogIndex', 'LogEmitter', 'LogTopics',
    'LogData', 'SecretOpening', 'MintSalt', 'MintType', 'MintOwner', 'MintData', 'MintReason'],
  '14.3': ['NotBurn', 'BurnNotFinal', 'BurnReason', 'ReturnData', 'ReturnDomain', 'ReturnAsset', 'ReturnAmount', 'ReturnRecipient', 'ReturnIndex'],
  '14.4': ['Predicate', 'MintShape', 'TransferData', 'CDMismatch', 'UnlockLength', 'UnlockScalars', 'UnlockRecovery', 'UnlockKey', 'RepeatedSID',
    'NoTransfers', 'DeadlineMismatch', 'DeadlineExpired', 'InclusionProof', 'ReferenceTime', 'SealNetwork', 'SealEpoch', 'NoEntryForEpoch',
    'CertStructure', 'SealRoot', 'QuorumNotMet', 'UnsupportedCertificateEncoding', 'SplitJustif', 'SplitProofCount', 'SplitProofShape',
    'SplitManifest', 'SplitBurn', 'SplitProof', 'SplitSum'],
  '14.5': ['BadHistoryLength', 'FutureIndex', 'StaleEndpoint', 'BadGapProof', 'ChainMismatch', 'AlreadyPaid', 'VerifierRefused', 'VerifierBadReturn',
    'DomainMismatch', 'AssetMismatch', 'ClaimMismatch', 'BadRecipient', 'ZeroAmount', 'LiabilityUnderflow', 'SegmentCounterExhausted', 'PayoutFailed',
    'Reentrancy', 'ZeroValue', 'BadFirstOwner', 'LiabilityCap', 'DepositCounterExhausted', 'BadConfig'],
  '14.6': ['SealReceipt', 'SegmentLog', 'CapacityPreflight', 'CapacityExceeded', 'ImplausibleIndex', 'EvidencePruned'],
} as const;

export const ERC20_RULES = ['BadCredit', 'ExcessDebit', 'InsufficientBacking', 'TokenCallFailed'] as const;
export type Rule = (typeof RULES)[keyof typeof RULES][number] | typeof ERC20_RULES[number];

/** Every rule, in section 14 order. */
export const ALL_RULES: readonly Rule[] = Object.values(RULES).flat() as Rule[];

/** Offline verification can retry once the trust history holds the seal's epoch. */
export const RETRYABLE_RULES: readonly Rule[] = ['NoEntryForEpoch'];

/** The deployed verifier cannot distinguish a pending seal import from an invalid quorum. */
export function isRetryableVerifierRefusal(inner: Rule | undefined): boolean {
  return inner === 'QuorumNotMet' || inner === 'NoEntryForEpoch';
}

/**
 * A section 14 refusal. `args` are a vault error's arguments as the vectors write them (decimal or `0x` hex); `inner` is the rule a
 * wrapper (`SealReceipt`, `SegmentLog`) carries.
 */
export class Nb2Error extends Error {
  public constructor(
    public readonly rule: Rule,
    public readonly detail?: string,
    public readonly args?: string[],
    public readonly inner?: Nb2Error,
  ) {
    super(`nb2: ${rule}${args?.length ? `(${args.join(',')})` : ''}${inner ? `: ${inner.message}` : ''}${detail ? `: ${detail}` : ''}`);
    this.name = 'Nb2Error';
  }

  /** Retry after trust-history refresh or, for an ambiguous on-chain refusal, after seal import. */
  public get retryable(): boolean {
    return RETRYABLE_RULES.includes(this.rule) || (this.inner?.retryable ?? false) ||
      (this.rule === 'VerifierRefused' && isRetryableVerifierRefusal(this.inner?.rule));
  }

  /** The innermost rule of a wrapper chain. */
  public get innermost(): Rule {
    return this.inner ? this.inner.innermost : this.rule;
  }
}

export function fail(rule: Rule, detail?: string): never {
  throw new Nb2Error(rule, detail);
}

export function failArgs(rule: Rule, ...args: (bigint | number | string)[]): never {
  throw new Nb2Error(rule, undefined, args.map(String));
}

/** `outer` carrying `inner` (a {@link Nb2Error}) as its cause; any other throw passes through. */
export function wrap(outer: Rule, e: unknown): never {
  if (e instanceof Nb2Error) throw new Nb2Error(outer, undefined, undefined, e);
  throw e;
}

/**
 * Non-rule outcomes the plug-in reports (section 14.6 names a few of them without a rule: a `state()` read without `stateReadOnly`,
 * an unknown or malformed seal companion), and the plug-in's own safety refusals of NB2-07.
 */
export type WalletReason =
  | 'SigningDeclined' // a signer guarantees it produced no signature
  | 'StateReadNotAdmitted' // a plain state() read on a deployment without stateReadOnly: not evidence (section 12.2)
  | 'CompanionUnknown' // the node does not hold the block on its canonical chain: re-resolve and retry (section 12.7)
  | 'CompanionProvider' // a companion whose witnesses are not [certificate, technical record]: use another provider
  | 'TrustSyncRequired' // retry after a fresh successful UTB sync
  | 'ImportLag' // the finalized destination is still missing the required signer epoch
  | 'TrustInput' // the trust-base history is not the one Γ names
  | 'JournalNotPersisted' // submitDeposit on a plan whose journal entry was not durably written first
  | 'JournalConflict' // a compare-and-swap of a journal record lost to another writer
  | 'RecipientRefused' // zero or vault recipient (wallet policy; the verifier's rule is ReturnRecipient)
  | 'NotPending' // the requested step does not apply to the journal entry's state
  | 'EvidenceMissing' // a log or receipt the witness needs was not served: never treated as absence
  | 'ProviderFault' // an RPC answer that is inconsistent with itself (wrong hash, wrong root)
  | 'AlreadyPaid' // reconcile found Paid(eta): the burn has been redeemed
  | 'Unconfirmed' // a submission whose outcome is not known yet: reconcile, never resend blindly
  | 'Reverted' // the transaction was mined and reverted (the classification says what to do)
  | 'InsufficientFunds' // the paying EVM account cannot fund the worst-case gas limit of the return
  | 'BadDeployment' // the vault's config(), chain ID or runtime code is not the pinned deployment
  | 'PolicyRequired' // the wallet has no payer policy (explicit limits) but the route needs one: enter it; nothing was read or signed
  | 'BadInput'; // a caller argument outside the API's contract

export class WalletError extends Error {
  public constructor(public readonly reason: WalletReason, detail?: string, public readonly cause?: unknown) {
    super(`nb2 wallet: ${reason}${detail ? `: ${detail}` : ''}`);
    this.name = 'WalletError';
  }

  public get retryable(): boolean {
    return this.reason === 'ImportLag' || this.reason === 'TrustSyncRequired';
  }
}

export function refuse(reason: WalletReason, detail?: string, cause?: unknown): never {
  throw new WalletError(reason, detail, cause);
}

/** The rule (or wallet reason) an error names, for vector comparisons and logs. */
export function nameOf(e: unknown): string {
  if (e instanceof Nb2Error) return e.rule;
  if (e instanceof WalletError) return e.reason;
  return `?${String((e as Error)?.message ?? e)}`;
}
