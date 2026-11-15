/** Wallet rules that affect safety (section 12) and the wallet refusals of section 14.6; bft-core `nb2ref/wallet.go`. */
import { eq } from '../bytes.js';
import { log2, type Config } from './config.js';
import { TOPIC, decodeDepositProof, verifyReceiptLog, type DepositProof } from './deposit.js';
import { Nb2Error, WalletError, fail, refuse, wrap } from './errors.js';
import { checkSegmentLog, genesisHead, type Segment } from './segment.js';
import { bindTrust, type TrustInput } from './trust.js';

/** A verified SegmentSealed(j) receipt. */
export interface SealReceipt { segment: Segment; proof: DepositProof; blockNumber: bigint }

/**
 * A seal receipt proof (a DepositProof container whose log is SegmentSealed), verified exactly as section 6.2 steps 2 to 5 for that
 * event: the same EVM UC rule, header, receipt path, type, status, log index and emitter, topics [topic0(SegmentSealed), u256(j)] with
 * j < 2^48, and the log's own check. Every failure is `SealReceipt` carrying the inner rule.
 */
export async function verifySealReceipt(c: Config, domain: Uint8Array, t: TrustInput, receipt: Uint8Array): Promise<SealReceipt> {
  bindTrust(t, c);
  try {
    const p = decodeDepositProof(receipt);
    const log = await verifyReceiptLog(c, t, p);
    if (log.topics.length !== 2 || !eq(log.topics[0], TOPIC.SegmentSealed)) fail('LogTopics');
    const jw = log.topics[1];
    if (jw.subarray(0, 26).some((x) => x !== 0)) fail('LogTopics');
    const j = jw.subarray(26).reduce((a, x) => (a << 8n) | BigInt(x), 0n);
    if (BigInt(log.data.length) !== 128n + 32n * c.K) fail('LogData');
    const segment = checkSegmentLog(domain, c.K, j, log.data.subarray(0, 32), log.data);
    return { segment, proof: p, blockNumber: log.header.number };
  } catch (e) {
    return wrap('SealReceipt', e);
  }
}

/** Section 12.2: with the newest verified seal receipt of segment j, sign a = j + 1 and keep H_{j+1}; with none, a = 0 and H_0. */
export function burnIndex(c: Config, domain: Uint8Array, newest: SealReceipt | null): { a: bigint; startHead: Uint8Array } {
  if (newest === null) return { a: 0n, startHead: genesisHead(domain, c.K) };
  return { a: newest.segment.index + 1n, startHead: newest.segment.after };
}

/**
 * P_max = floor((L_max - L_T - L_O) / (65 + 32h)) and whether the return without history fits at all (L_T <= L_max and
 * L_O <= L_max - L_T); P_max is zero when it does not.
 */
export function maxProofs(lMax: bigint, lT: bigint, lO: bigint, K: bigint): { pMax: bigint; baseFits: boolean } {
  if (lT > lMax || lO > lMax - lT) return { pMax: 0n, baseFits: false };
  return { pMax: (lMax - lT - lO) / BigInt(65 + 32 * log2(K)), baseFits: true };
}

const fitsProofs = (lMax: bigint, lT: bigint, lO: bigint, K: bigint, P: bigint): boolean => {
  const m = maxProofs(lMax, lT, lO, K);
  return m.baseFits && P <= m.pMax;
};

/** The before-burn capacity input (section 12.5 as amended by astra's review, finding 1). */
export interface Preflight {
  lMax: bigint;
  /** The encoded evidence, including the burn and its certification. */
  lT: bigint;
  /** All other framing of the redeem transaction (ABI padding, transaction envelope, start head). */
  lO: bigint;
  K: bigint;
  a: bigint;
  /** A current endpoint estimate, cObs >= a. */
  cObs: bigint;
  reserve: bigint;
  /** The gas limit (expected cost plus gasReserve) with P proofs, estimated conservatively; null when it cannot be bounded. */
  gasAt: (p: bigint) => bigint | null;
  userGasLimit: bigint;
}

/** Refuse the burn (`CapacityPreflight`) unless the return fits L_max and userGasLimit with P_now + returnReserveSegments proofs. */
export function capacityPreflight(p: Preflight): { pNow: bigint; need: bigint; pMax: bigint; gas: bigint } {
  if (p.cObs < p.a) fail('CapacityPreflight', 'the endpoint estimate is below the index');
  const need = p.cObs - p.a + p.reserve;
  const { pMax } = maxProofs(p.lMax, p.lT, p.lO, p.K);
  if (!fitsProofs(p.lMax, p.lT, p.lO, p.K, need)) fail('CapacityPreflight', `${need} proofs needed, ${pMax} fit ${p.lMax} bytes`);
  const gas = p.gasAt(need);
  if (gas === null) fail('CapacityPreflight', 'the gas cannot be bounded');
  if (gas! > p.userGasLimit) fail('CapacityPreflight', `gas ${gas} above userGasLimit ${p.userGasLimit}`);
  return { pNow: p.cObs - p.a, need, pMax, gas: gas! };
}

/** The at-redemption refusal: P > P_max, or the gas limit above userGasLimit. */
export function capacityExceeded(lMax: bigint, lT: bigint, lO: bigint, K: bigint, P: bigint, gasLimit: bigint, userGasLimit: bigint): void {
  if (!fitsProofs(lMax, lT, lO, K, P) || gasLimit > userGasLimit) fail('CapacityExceeded');
}

/**
 * The stateReadOnly substitute for a seal receipt (section 12.2, test deployments only): the read index must lie in
 * [verified, verified + maxJump] (`ImplausibleIndex`); without stateReadOnly a state() read is not evidence at all.
 */
export function checkStateRead(stateReadOnly: boolean, read: bigint, verified: bigint, maxJump: bigint): void {
  if (!stateReadOnly) refuse('StateReadNotAdmitted', 'a plain state() read is not evidence on this deployment');
  if (read < verified || read - verified > maxJump) fail('ImplausibleIndex');
}

/** A seal companion answer (section 12.7): "found" with exactly two witnesses is usable; "unavailable" is EvidencePruned; anything else ("ok" included) is a provider fault. */
export function checkCompanion(status: string, witnesses: number): void {
  if (status === 'found' && witnesses === 2) return;
  if (status === 'unavailable') fail('EvidencePruned');
  if (status === 'unknown') refuse('CompanionUnknown');
  refuse('CompanionProvider');
}

export { Nb2Error, WalletError };
