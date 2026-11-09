/**
 * The wallet's side of trust evolution (#430 row 2): the plug-in never fetches (trust.ts), so when a verification needs an epoch newer than the
 * held history, the wallet fetches the missing contiguous entries from its untrusted source through the SDK's own update path, appends them to the
 * history it already holds and retries the same verification.
 *
 * - The fetch is the SDK's `TrustBaseUpdater.update` (the response decoded under the page limits, each entry appended through
 *   `TrustBaseHistory.append`, which authenticates it from its predecessor; `TrustBaseUpdater.update`): the pin and every held entry stay, an entry that does not authenticate,
 *   of another network or conflicting with a held epoch is refused (`TrustBaseUpdateError`, propagated), and nothing is ever replaced.
 * - Only "no entry for epoch" is retried: the plug-in's `ErrNoEntryForEpoch`, or an SDK consolidation `integrity` error whose verification trace
 *   names a missing epoch. Every other failure propagates unchanged on the first attempt. A consolidation trace can hold a missing epoch AND another
 *   failure; the retry is then bounded, not narrowed: each attempt runs the complete verification again from the start, so once the epoch is held
 *   the other failure is what fails (not retried), and if the source never has the epoch the last failure propagates after `attempts`. It fails
 *   closed either way. `verify` must be a pure verification: it never submits a transaction, so a retry never replays one.
 * - `persist` receives the whole held history after every fetch that appended entries (`toBundle`), so a durable wallet keeps what it learnt;
 *   it is called before `onFetch`, so a reporting failure cannot prevent the write.
 * - A refused page keeps its authenticated prefix: the SDK appends a page entry by entry and stops at the first refusal, leaving the entries before
 *   it held. When the held tip advanced, that prefix is persisted, then the original refusal propagates (no retry of the verification). If the
 *   write itself fails the operation stops with the write's error, the refusal as its `cause`.
 */
import type { ITrustBaseSource } from '@unicitylabs/state-transition-sdk/lib/api/ITrustBaseSource.js';
import { TRUST_BASE_PAGE_LIMITS } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseRange.js';
import { TrustBaseUpdater } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseUpdater.js';
import { findNoTrustBaseEntry } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/TrustBaseEntryResult.js';
import { ConsolidationError } from '@unicitylabs/state-transition-sdk/lib/consolidation/ConsolidationError.js';
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

/** The epoch of the held tip (0 when nothing is held, which a history installed from a bundle never is). */
function tipOf(trust: TrustInput): bigint {
  return trust.history.tip?.epoch ?? 0n;
}

/** Persist the held history; a failed write stops the operation (with `refused`, the fetch's own refusal, as its cause when there is one). */
async function persistOrStop(trust: TrustInput, options: TrustRefreshOptions, refused?: unknown): Promise<void> {
  if (!options.persist) return;
  try {
    await options.persist(await trust.history.toBundle());
  } catch (e) {
    throw new TrustPersistError(`the held trust-base history (tip ${tipOf(trust)}) could not be persisted: ${e instanceof Error ? e.message : String(e)}`,
      refused === undefined ? e : new AggregateError([e, refused], 'the write failed after the fetch was refused'));
  }
}

/** A failed write of the held history: the operation stops. `cause` is the write's error, or both it and the fetch's refusal. */
export class TrustPersistError extends Error {
  public constructor(message: string, cause: unknown) {
    super(message, { cause });
    this.name = 'TrustPersistError';
  }
}

/** True when `e` is a verification that failed only for want of a newer trust-base entry. */
export function needsNewerEntry(e: unknown): boolean {
  if (e instanceof NativeError) return e.reason === 'ErrNoEntryForEpoch';
  if (e instanceof ConsolidationError && e.kind === 'integrity' && e.cause instanceof VerificationResult) {
    return findNoTrustBaseEntry(e.cause) !== null;
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
    const tipBefore = tipOf(trust);
    let appended: number;
    try {
      appended = await TrustBaseUpdater.update(trust.history, [source], { limits: { ...TRUST_BASE_PAGE_LIMITS, maxEntries } });
    } catch (refused) {
      // the authenticated prefix before the refused entry stays held: keep it durable, then report the refusal itself
      if (tipOf(trust) > tipBefore) await persistOrStop(trust, options, refused);
      throw refused;
    }
    const tipAfter = tipOf(trust);
    if (appended > 0) await persistOrStop(trust, options);
    options.onFetch?.({ attempt, fromEpoch: tipBefore + 1n, tipBefore, tipAfter, appended });
    if (appended === 0) await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}
