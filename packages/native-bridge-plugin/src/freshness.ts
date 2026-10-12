/**
 * The host freshness contract for return proofs (`protocol/interop.md` "Assembly and refresh").
 *
 * B1 accepts an anchor with seal round `r` only if `r <= O` and `O - r <= W_cert`, `O` being the registry
 * `clock.rootRound` at the redemption's EXECUTION block, not the shard round, the original time `t` or a
 * wall clock. The executing block imports its own origin, so a read of the latest block is advisory and an
 * execution margin `M` is kept: a proof is only sent when `max(r) <= O` and `O - min(r) <= W_cert - M`.
 * `M` is a host-measured inclusion margin, not a protocol constant.
 *
 * Everything here consumes host transports (the chain reader, the proof source, the transaction sender) and
 * never decides admission: a wrongly judged proof is refused on chain. Freshness is repaired by refreshing
 * the proofs of the SAME burned token (exact M/T/CD/t/J preserved), never by rebuilding or re-burning, and
 * never to obtain matching certificates or fewer anchors. Exhausted freshness is `ErrProofUnavailable`
 * with a cause (the unavailable family, retryable); a bound overflow (anchors, gas, size) stays a budget
 * refusal and is never retried.
 */
import { NativeError, fail } from './errors.js';
import { buildReturnProof, refreshToken } from './proof.js';
import { preflightToken } from './resources.js';
import { PAIR_RACE, type NativeBridgePlugin, type ProofSource } from './wallet.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { eq, toHex } from './bytes.js';
import { MAX_ANCHORS } from './limits.js';

/** What the chain says about the window, read by the host from the registry and the pinned profile (`b1.wCert`). */
export interface ChainReader {
  /** The registry's `clock.rootRound` as of the latest block. */
  origin(): Promise<bigint>;
  /** The committed B1 window `W_cert`, in root rounds. */
  wCert(): Promise<bigint>;
}

/** How the bundle's anchors stand against the window. */
export type Freshness = 'ok' | 'future' | 'stale' | 'spread';

/**
 * Classify the seal rounds of a bundle's distinct anchors. `spread`: even the best origin cannot admit them
 * together under the margin (`max - min > wCert - margin`), so waiting never helps and only newer proofs can.
 * `future`: the newest anchor is beyond the origin, so the registry cannot know it yet (waiting helps).
 * `stale`: the oldest is too old for the origin (only newer proofs help).
 */
export function classifyFreshness(rounds: readonly bigint[], origin: bigint, wCert: bigint, margin: bigint): Freshness {
  if (rounds.length === 0) throw new TypeError('no anchor rounds');
  if (margin < 0n || margin >= wCert) throw new RangeError('the execution margin must be in [0, W_cert)');
  let min = rounds[0];
  let max = rounds[0];
  for (const r of rounds) {
    if (r < min) min = r;
    if (r > max) max = r;
  }
  if (max - min > wCert - margin) return 'spread';
  if (max > origin) return 'future';
  if (origin - min > wCert - margin) return 'stale';
  return 'ok';
}

export interface FreshnessPolicy {
  /** The execution margin M in root rounds. */
  margin: bigint;
  /** Fetch-and-assemble attempts (each re-fetches every leaf's proof) before the proof is reported unavailable. */
  maxAttempts: number;
  /** The longest the origin is awaited, per attempt, when an anchor is newer than it. */
  maxOriginWaitMs: number;
  pollMs: number;
  /** Test seams. */
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

/** M=6 is the lane's heuristic (about 2.7 s at the fast cadence), to be replaced by a measured value. */
export const DEFAULT_FRESHNESS: FreshnessPolicy = { margin: 10n, maxAttempts: 3, maxOriginWaitMs: 10_000, pollMs: 250 };

/** Reject a policy that cannot work before anything is fetched or sent. */
function checkPolicy(policy: FreshnessPolicy, wCert: bigint, sends?: number): void {
  if (!Number.isInteger(policy.maxAttempts) || policy.maxAttempts < 1) throw new RangeError('maxAttempts must be an integer >= 1');
  if (sends !== undefined && (!Number.isInteger(sends) || sends < 1)) throw new RangeError('maxSends must be an integer >= 1');
  if (policy.margin < 0n || policy.margin >= wCert) throw new RangeError('the execution margin must be in [0, W_cert)');
}

const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** The distinct seal rounds of a token's anchors (byte-identical certificates counted once). */
export function anchorRounds(token: Token): bigint[] {
  const seen = new Map<string, bigint>();
  for (const c of [token.genesis, ...token.transactions]) {
    const uc = c.inclusionProof.unicityCertificate;
    seen.set(toHex(uc.toCBOR()), BigInt(uc.unicitySeal.rootChainRoundNumber));
  }
  return [...seen.values()];
}

export interface FreshReturnProof {
  encoded: Uint8Array;
  nullifier: Uint8Array;
  /** The anchors' seal rounds, the origin they were last judged against and W_cert (for the host's records). */
  rounds: bigint[];
  origin: bigint;
  wCert: bigint;
  /** Fetch rounds used (1 = the first fetch was fresh enough). */
  attempts: number;
}

/**
 * Fetch every leaf's current proof, assemble the envelope and send it nowhere: return it once it is inside
 * the window. Every attempt re-fetches all leaves for the same burned token. An anchor newer than the origin
 * is awaited for at most `maxOriginWaitMs` and then judged again, oldest anchor included.
 */
export async function buildFreshReturnProof(
  plugin: NativeBridgePlugin,
  tokenBytes: Uint8Array,
  source: ProofSource,
  chain: ChainReader,
  policy: FreshnessPolicy = DEFAULT_FRESHNESS,
  sends?: number,
): Promise<FreshReturnProof> {
  preflightToken(tokenBytes);
  const sleep = policy.sleep ?? realSleep;
  const now = policy.now ?? Date.now;
  const held = await Token.fromCBOR(tokenBytes);
  const wCert = await chain.wCert();
  checkPolicy(policy, wCert, sends);
  let cause = 'no attempt';
  for (let attempt = 1; attempt <= policy.maxAttempts; attempt++) {
    let token: Token;
    let built: Awaited<ReturnType<typeof buildReturnProof>>;
    let fetched: Awaited<ReturnType<ProofSource>>;
    try {
      fetched = await source(held);
    } catch (e) {
      // the proof service did not answer: temporary witness unavailability, bounded by the attempts (a NativeError from the host's own source is its verdict)
      if (e instanceof NativeError) throw e;
      cause = `witness unavailable (${String((e as Error)?.message ?? e).slice(0, 120)})`;
      continue;
    }
    try {
      token = await refreshToken(held, fetched);
      try {
        built = await buildReturnProof(plugin.bridge, token);
      } catch (e) {
        // A bundle over the anchor, gas or size bound is a budget refusal, never retried (a refetch must not be used to make certificates converge or
        // to obtain fewer anchors): report the measured count so the host can see how far over it was.
        if (e instanceof NativeError && e.family === 'budget') {
          const n = anchorRounds(token).length;
          throw new NativeError(e.reason, e.reason === 'ErrTooManyPaths' ? `${n} distinct anchors fetched, ceiling ${MAX_ANCHORS}; not retried` : `over the gas or size bound with ${n} distinct anchors fetched; not retried`);
        }
        throw e;
      }
    } catch (e) {
      // a (path, UC) pair that raced a certificate: another fetch; any other failure (budget, invalid, mismatch) is the caller's
      if (e instanceof NativeError && PAIR_RACE.includes(e.reason)) {
        cause = `pair-race (${e.reason})`;
        continue;
      }
      throw e;
    }
    const rounds = anchorRounds(token);
    const deadline = now() + policy.maxOriginWaitMs;
    // only the host's own read is guarded: the classification is pure code, and a bug or a bad policy there must not read as an unavailable origin
    const readOrigin = async (): Promise<bigint | undefined> => {
      try {
        return await chain.origin();
      } catch (e) {
        if (e instanceof NativeError) throw e;
        cause = `origin unavailable (${String((e as Error)?.message ?? e).slice(0, 120)})`;
        return undefined;
      }
    };
    let origin = await readOrigin();
    if (origin === undefined) continue;
    let verdict = classifyFreshness(rounds, origin, wCert, policy.margin);
    let lost = false;
    while (verdict === 'future' && now() < deadline) {
      await sleep(policy.pollMs);
      const again = await readOrigin();
      if (again === undefined) { lost = true; break; }
      origin = again;
      verdict = classifyFreshness(rounds, origin, wCert, policy.margin);
    }
    if (lost) continue;
    if (verdict === 'ok') return { encoded: built.encoded, nullifier: built.verified.outcome.nullifier, rounds, origin, wCert, attempts: attempt };
    cause = `${verdict} (rounds ${rounds.join(',')}, origin ${origin}, W_cert ${wCert}, margin ${policy.margin})`;
    if (verdict === 'future') break; // the registry has not imported the newest anchor within the wait: refetching cannot make it older
  }
  return fail('ErrProofUnavailable', cause);
}

/** The transaction transport and the vault's state, supplied by the host. */
export interface RedeemTransport {
  /** Broadcast `redeem(bytes)` and return the transaction hash. It may throw on a timeout after the transaction was in fact accepted. */
  send(data: Uint8Array): Promise<string>;
  /** The receipt of a sent transaction: undefined while it is not mined. */
  receipt(txHash: string): Promise<'success' | 'reverted' | undefined>;
  /**
   * The vault's spent state for a lock nonce: `spentNullifier(nonce)`, the burn nullifier the vault stored when it credited that nonce. The
   * vault keys spent state by NONCE and keeps the nullifier as the stored value (and as an indexed topic of `RedemptionCredited`); it has no
   * nullifier-keyed lookup. `undefined` or an all-zero word: not redeemed. A host that only has the logs may answer from `RedemptionCredited`.
   */
  spentNullifier(nonce: bigint): Promise<Uint8Array | undefined>;
}

/** What `redeemReturn` tells the host's journal, in order: before every send, and with its hash (undefined when the send failed without one). */
export interface RedeemObserver {
  beforeSend?(): Promise<void>;
  sent?(txHash: string | undefined): Promise<void>;
}

export interface RedeemPolicy extends FreshnessPolicy {
  /** Sends before giving up. Each re-fetches every proof for the same burned token. */
  maxSends: number;
  receiptTimeoutMs: number;
}

export const DEFAULT_REDEEM: RedeemPolicy = { ...DEFAULT_FRESHNESS, maxSends: 3, receiptTimeoutMs: 30_000 };

export type RedeemResult =
  | { status: 'redeemed'; txHash?: string; nullifier: Uint8Array; sends: number }
  | { status: 'already-redeemed'; nullifier: Uint8Array; sends: number };

/**
 * A redemption whose outcome is unknown: no receipt and no vault change within `receiptTimeoutMs`. It is still an
 * `ErrProofUnavailable` (retryable), but `txHash` is the sent transaction (absent when the send itself failed without a hash) and
 * the caller keeps it: pass it back in `pending` so the next call checks its receipt before any new send.
 */
export class RedemptionUnconfirmed extends NativeError {
  public constructor(public readonly txHash: string | undefined) {
    super('ErrProofUnavailable', `redemption unconfirmed (${txHash ?? 'send failed'}); check the transaction before any resend`);
  }
}

/** The identity the vault knows a return token by: its lock nonce (the spent-state key) and its burn nullifier (the stored value). Needs no aggregator proof. */
export async function returnIdentity(plugin: NativeBridgePlugin, tokenBytes: Uint8Array): Promise<{ nonce: bigint; nullifier: Uint8Array }> {
  preflightToken(tokenBytes);
  const v = await plugin.bridge.verifyNativeToken(await Token.fromCBOR(tokenBytes), 'return');
  return { nonce: v.outcome.nonce, nullifier: v.outcome.nullifier };
}

/** Whether the vault has already credited this token's lock nonce. A nonce credited to ANOTHER burn can never be redeemed by this token: `ErrUnexpectedBurn`. */
async function isRedeemed(transport: RedeemTransport, id: { nonce: bigint; nullifier: Uint8Array }): Promise<boolean> {
  const stored = await transport.spentNullifier(id.nonce);
  if (stored === undefined || stored.every((b) => b === 0)) return false;
  if (!eq(stored, id.nullifier)) fail('ErrUnexpectedBurn', `lock nonce ${id.nonce} is already redeemed by a different burn`);
  return true;
}

/**
 * Redeem a burned token. The vault is asked FIRST (after the receipts of the hashes in `pending`), before any proof is fetched and before the freshness window is judged: an already executed
 * redemption (a third party's, or an earlier send of ours whose hash was lost) is reported as such even when the proof service is down or the
 * window cannot be met. Then every hash in `pending` (an earlier unconfirmed send) is checked: a success ends the call, a transaction still
 * pending, with the vault still not showing the nonce credited, leaves the call unconfirmed again with no new send, a revert is dropped. Before every send the vault's state is read again. After a send
 * the receipt and the vault state, never the RPC's answer alone, decide the next step: an RPC timeout is not a revert. A revert refetches every
 * proof for the same token and sends again, within `maxSends`, whatever its cause: a deterministic refusal (a closed authority interval, bad
 * backing) therefore costs `maxSends` transactions. A send whose outcome is unknown is never repeated while it may still be pending (see
 * `RedemptionUnconfirmed`). The wallet burn is never repeated. `observer` lets the host journal each step (`beforeSend`, `sent`).
 */
export async function redeemReturn(
  plugin: NativeBridgePlugin,
  tokenBytes: Uint8Array,
  source: ProofSource,
  chain: ChainReader,
  transport: RedeemTransport,
  policy: RedeemPolicy = DEFAULT_REDEEM,
  pending: readonly string[] = [],
  observer: RedeemObserver = {},
): Promise<RedeemResult> {
  const sleep = policy.sleep ?? realSleep;
  const now = policy.now ?? Date.now;
  checkPolicy(policy, await chain.wCert(), policy.maxSends);
  const id = await returnIdentity(plugin, tokenBytes);
  const nullifier = id.nullifier;
  // a pending hash that succeeded ends the call; one without a receipt does not end it yet: the vault is asked before it is believed (a dropped
  // transaction never gets a receipt, and someone else's redemption of the same nonce must still settle this call)
  let unconfirmed: string | undefined;
  for (const h of pending) {
    const r = await transport.receipt(h);
    if (r === 'success') return { status: 'redeemed', txHash: h, nullifier, sends: 0 };
    if (r === undefined) unconfirmed ??= h;
  }
  if (await isRedeemed(transport, id)) return { status: 'already-redeemed', nullifier, sends: 0 };
  if (unconfirmed !== undefined) throw new RedemptionUnconfirmed(unconfirmed);
  for (let sends = 0; sends < policy.maxSends; ) {
    const proof = await buildFreshReturnProof(plugin, tokenBytes, source, chain, policy, policy.maxSends);
    if (await isRedeemed(transport, id)) return { status: 'already-redeemed', nullifier, sends };
    sends++;
    await observer.beforeSend?.();
    let txHash: string | undefined;
    try {
      txHash = await transport.send(proof.encoded);
    } catch {
      txHash = undefined; // unknown: it may have been accepted
    }
    await observer.sent?.(txHash);
    const deadline = now() + policy.receiptTimeoutMs;
    let outcome: 'success' | 'reverted' | undefined;
    for (;;) {
      if (txHash !== undefined) outcome = await transport.receipt(txHash);
      if (outcome !== undefined) break;
      if (await isRedeemed(transport, id)) { outcome = 'success'; break; }
      if (now() >= deadline) break;
      await sleep(policy.pollMs);
    }
    if (outcome === 'success') return { status: 'redeemed', txHash, nullifier, sends };
    if (outcome === undefined) throw new RedemptionUnconfirmed(txHash); // it may still be pending: not sent again
    // reverted: someone else (or an earlier transaction of ours) may have redeemed it, otherwise the proofs were refused: refetch and send again
    if (await isRedeemed(transport, id)) return { status: 'already-redeemed', nullifier, sends };
  }
  return fail('ErrProofUnavailable', `redemption reverted ${policy.maxSends} times`);
}
