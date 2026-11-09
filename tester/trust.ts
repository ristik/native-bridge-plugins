/**
 * The tester wallet's held trust (bridge-tester.ts): the operator's shipped bundle under its pin, or the wallet's own durable history when it has one,
 * and the one way that history is written. One process per wallet: the write is a temporary file renamed over the old one, which suits the serial
 * tester; it is not the public SDK session's concurrent-writer behaviour, nor evidence of power-loss durability.
 */
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';

import type { ITrustBaseSource } from '@unicitylabs/state-transition-sdk/lib/api/ITrustBaseSource.js';
import { fetchTrustBaseEntries } from '@unicitylabs/state-transition-sdk/lib/util/TrustBaseUtils.js';

import { TrustInput } from '../packages/native-bridge-plugin/src/trust.js';
import { TrustPersistError } from '../packages/native-bridge-plugin/src/trustrefresh.js';

/** BRIDGE_TRUST_MAX_ENTRIES (1..64, default 64): the page size asked for. */
export function maxEntriesOf(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.BRIDGE_TRUST_MAX_ENTRIES ?? '64');
  if (!Number.isInteger(n) || n < 1 || n > 64) throw new Error('BRIDGE_TRUST_MAX_ENTRIES must be 1 to 64');
  return n;
}

/**
 * The held trust: the shipped bundle (`bundleFile`) under the pin (`pinFile`), or the durable history at `historyFile` when it exists, verified under
 * the same pin. Every shipped entry is then appended to it through the SDK: a held epoch with the same EntryID is a replay (another valid witness set
 * of the same entry included), a shipped epoch it lacks is appended, and a conflicting one is refused — the history is never replaced.
 */
export async function loadHeldTrust(bundleFile: string, pinFile: string, historyFile: string): Promise<TrustInput> {
  const pin = Uint8Array.from(Buffer.from(readFileSync(pinFile, 'utf8').trim().replace(/^0x/, ''), 'hex'));
  const shipped = await TrustInput.fromBundle(Uint8Array.from(readFileSync(bundleFile)), pin);
  if (!existsSync(historyFile)) return shipped;
  const held = await TrustInput.fromBundle(Uint8Array.from(readFileSync(historyFile)), pin);
  for (let e = shipped.history.genesisEpoch; e <= shipped.history.tipEpoch; e++) {
    try {
      await held.history.append(shipped.history.bytes(e)!);
    } catch (cause) {
      throw new Error(`${historyFile} does not extend the shipped trust bundle at epoch ${e}`, { cause });
    }
  }
  return held;
}

/** Write the held history (tag 39015): a temporary file renamed over the old one. */
export function persistTrustFile(historyFile: string, bundle: Uint8Array): void {
  writeFileSync(`${historyFile}.tmp`, bundle);
  renameSync(`${historyFile}.tmp`, historyFile);
}

/**
 * Fetch every entry after the held tip, page by page, persisting after each page that appended. A refused page keeps its authenticated prefix: when the
 * tip advanced it is persisted, then the refusal propagates; a failed write stops with TrustPersistError (the refusal its cause, when there is one).
 * Returns the entries appended.
 */
export async function refreshAll(trust: TrustInput, source: ITrustBaseSource, maxEntries: number, persist: (bundle: Uint8Array) => void): Promise<number> {
  let total = 0;
  const write = async (refused?: unknown) => {
    try {
      persist(await trust.history.exportBundle());
    } catch (e) {
      throw new TrustPersistError(`the held trust-base history (tip ${trust.history.tipEpoch}) could not be persisted: ${e instanceof Error ? e.message : String(e)}`,
        refused === undefined ? e : new AggregateError([e, refused], 'the write failed after the fetch was refused'));
    }
  };
  for (;;) {
    const before = trust.history.tipEpoch;
    let n: number;
    try {
      n = await fetchTrustBaseEntries(trust.history, source, { maxEntries });
    } catch (refused) {
      if (trust.history.tipEpoch > before) await write(refused);
      throw refused;
    }
    if (n === 0) return total;
    total += n;
    await write();
  }
}
