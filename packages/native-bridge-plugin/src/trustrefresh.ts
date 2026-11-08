/**
 * The wallet's side of trust evolution (#430 row 2): the plug-in never fetches (trust.ts), so when a verification needs an epoch newer than the
 * held history, the wallet fetches the missing contiguous entries from its untrusted source through the SDK's own update path, appends them to the
 * history it already holds and retries the same verification.
 *
 * - The fetch is the SDK's `fetchTrustBaseEntries` (the response decoded under the page limits, each entry appended through
 *   `TrustBaseHistory.append`, which authenticates it from its predecessor): the pin and every held entry stay, an entry that does not authenticate,
 *   of another network or conflicting with a held epoch is refused (`TrustBaseUpdateError`, propagated), and nothing is ever replaced.
 * - Only "no entry for epoch" is retried: the plug-in's `ErrNoEntryForEpoch`, or an SDK consolidation `integrity` error whose verification trace
 *   names the missing epoch. Every other failure propagates unchanged on the first attempt.
 * - `persist` receives the whole held history after every fetch that appended entries (`exportBundle`), so a durable wallet keeps what it learnt.
 */
import type { ITrustBaseSource } from '@unicitylabs/state-transition-sdk/lib/api/ITrustBaseSource.js';
import { CertificateVerificationResult } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/CertificateVerdict.js';
import { ConsolidationError } from '@unicitylabs/state-transition-sdk/lib/consolidation/ConsolidationError.js';
import { fetchTrustBaseEntries } from '@unicitylabs/state-transition-sdk/lib/util/TrustBaseUtils.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';

import { NativeError } from './errors.js';
import type { TrustInput } from './trust.js';

export interface TrustRefreshOptions {
  /** Entries asked for per fetch, 1..64 (the SDK's bound). Defaults to 64; 1 forces one-entry pages. */
  readonly maxEntries?: number;
  /** Verifications at most, the first included. Defaults to 8. */
  readonly attempts?: number;
  /** Pause after a fetch that brought nothing new (the source does not have the epoch yet), in milliseconds. Defaults to 2000. */
  readonly intervalMs?: number;
  /** Called with the whole held history (tag 39015) after a fetch appended entries. */
  readonly persist?: (bundle: Uint8Array) => Promise<void> | void;
  /** Called once per fetch: the held tip before and after, and the entries appended. */
  readonly onFetch?: (event: TrustRefreshEvent) => void;
}

export interface TrustRefreshEvent {
  readonly attempt: number;
  readonly fromEpoch: bigint;
  readonly tipBefore: bigint;
  readonly tipAfter: bigint;
  readonly appended: number;
}

/** True when `e` is a verification that failed only for want of a newer trust-base entry. */
export function needsNewerEntry(e: unknown): boolean {
  if (e instanceof NativeError) return e.reason === 'ErrNoEntryForEpoch';
  if (e instanceof ConsolidationError && e.kind === 'integrity' && e.cause instanceof VerificationResult) {
    return CertificateVerificationResult.findMissingEpoch(e.cause) !== null;
  }
  return false;
}

/**
 * Run `verify`; while it fails for want of a newer entry, fetch the entries after the held tip from `source` into `trust.history` and run it
 * again. The last failure is rethrown when `attempts` run out; a refused fetch (`TrustBaseUpdateError`) is thrown at once.
 */
export async function withTrustRefresh<T>(trust: TrustInput, source: ITrustBaseSource, verify: () => Promise<T>, options: TrustRefreshOptions = {}): Promise<T> {
  const attempts = options.attempts ?? 8;
  const maxEntries = options.maxEntries ?? 64;
  const intervalMs = options.intervalMs ?? 2000;
  for (let attempt = 1; ; attempt++) {
    try {
      return await verify();
    } catch (e) {
      if (!needsNewerEntry(e) || attempt >= attempts) throw e;
    }
    const tipBefore = trust.history.tipEpoch;
    const appended = await fetchTrustBaseEntries(trust.history, source, { maxEntries });
    const tipAfter = trust.history.tipEpoch;
    options.onFetch?.({ attempt, fromEpoch: tipBefore + 1n, tipBefore, tipAfter, appended });
    if (appended > 0) await options.persist?.(await trust.history.exportBundle());
    else await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}
