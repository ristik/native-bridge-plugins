/**
 * The vault ABI (section 13): calldata of its functions, its views and events, and the custom errors with their exact revert data.
 * A failed simulation or transaction is classified by selector into what the wallet does next (section 13.3).
 */
import { concat, eq, toHex } from '../bytes.js';
import { ascii, beInt, u256 } from './cbor.js';
import { HE } from './crypto.js';
import { TOPIC } from './deposit.js';
import { ALL_RULES, isRetryableVerifierRefusal, type Rule } from './errors.js';

const sel = (sig: string): Uint8Array => HE(ascii(sig)).subarray(0, 4);

export const SELECTOR = {
  deposit: sel('deposit(bytes,bytes32)'),
  redeem: sel('redeem(bytes,bytes32,uint64,bytes)'),
  domain: sel('domain()'),
  config: sel('config()'),
  state: sel('state()'),
  verifyReturn: sel('verifyReturn(bytes,bytes)'),
} as const;

/** The vault errors with arguments (section 13.3); every other rule is `<Name>()`. */
export const ERROR_SIGNATURES: Partial<Record<Rule, string>> = {
  LiabilityCap: 'LiabilityCap(uint256,uint256,uint256)',
  BadHistoryLength: 'BadHistoryLength(uint256)',
  FutureIndex: 'FutureIndex(uint64,uint64)',
  StaleEndpoint: 'StaleEndpoint(uint64,uint64)',
  BadGapProof: 'BadGapProof(uint256)',
  AlreadyPaid: 'AlreadyPaid(bytes32)',
  VerifierRefused: 'VerifierRefused(bytes)',
  LiabilityUnderflow: 'LiabilityUnderflow(uint256,uint256)',
  BadConfig: 'BadConfig(uint256)',
};

export const signatureOf = (r: Rule): string => ERROR_SIGNATURES[r] ?? `${r}()`;
export const selectorOf = (r: Rule): Uint8Array => sel(signatureOf(r));

const BY_SELECTOR = new Map<string, Rule>(ALL_RULES.map((r) => [toHex(selectorOf(r)), r]));

const pad32 = (b: Uint8Array): Uint8Array => concat(b, new Uint8Array((32 - (b.length % 32)) % 32));

/** Standard ABI of (static words..., dynamic bytes...) arguments given in order, each a word or bytes. */
function abiEncode(args: ({ word: Uint8Array } | { bytes: Uint8Array })[]): Uint8Array {
  const heads: Uint8Array[] = [];
  const tails: Uint8Array[] = [];
  let tailLen = 0;
  for (const a of args) {
    if ('word' in a) heads.push(a.word);
    else {
      heads.push(u256(32 * args.length + tailLen));
      const t = concat(u256(a.bytes.length), pad32(a.bytes));
      tails.push(t);
      tailLen += t.length;
    }
  }
  return concat(...heads, ...tails);
}

/** The exact revert data of a vault or verifier rule with its arguments (words as bigint or 32 bytes, `bytes` as Uint8Array). */
export function revertData(r: Rule, ...vals: (bigint | Uint8Array)[]): Uint8Array {
  const sig = signatureOf(r);
  const types = sig.slice(sig.indexOf('(') + 1, -1).split(',').filter((x) => x !== '');
  if (vals.length === 0 || types.length === 0) return selectorOf(r);
  return concat(selectorOf(r), abiEncode(vals.map((v, i) => (types[i] === 'bytes' ? { bytes: v as Uint8Array } : { word: typeof v === 'bigint' ? u256(v) : (v as Uint8Array) }))));
}

export const depositCalldata = (firstOwner: Uint8Array, rho: Uint8Array): Uint8Array =>
  concat(SELECTOR.deposit, abiEncode([{ bytes: firstOwner }, { word: rho }]));

export const redeemCalldata = (evidence: Uint8Array, claimedEta: Uint8Array, claimedStart: bigint, history: Uint8Array): Uint8Array =>
  concat(SELECTOR.redeem, abiEncode([{ bytes: evidence }, { word: claimedEta }, { word: u256(claimedStart) }, { bytes: history }]));

/** The calldata length of a redeem with `evidence` bytes and `history` bytes (selector, four heads, two length words, padding). */
export const redeemCalldataLength = (evidence: number, history: number): number =>
  4 + 4 * 32 + 32 + Math.ceil(evidence / 32) * 32 + 32 + Math.ceil(history / 32) * 32;

export interface VaultState { deposits: bigint; segment: bigint; population: bigint; outstanding: bigint; head: Uint8Array; previousHead: Uint8Array }

export function decodeStateReturn(b: Uint8Array): VaultState {
  if (b.length !== 192) throw new Error('nb2: state() returned other than 192 bytes');
  const w = (i: number): Uint8Array => b.subarray(32 * i, 32 * i + 32);
  return { deposits: beInt(w(0)), segment: beInt(w(1)), population: beInt(w(2)), outstanding: beInt(w(3)), head: w(4).slice(), previousHead: w(5).slice() };
}

/** A `bytes` return (config()). */
export function decodeBytesReturn(b: Uint8Array): Uint8Array {
  if (b.length < 64 || beInt(b.subarray(0, 32)) !== 32n) throw new Error('nb2: not an ABI bytes return');
  const n = Number(beInt(b.subarray(32, 64)));
  if (b.length !== 64 + Math.ceil(n / 32) * 32) throw new Error('nb2: not an ABI bytes return');
  return b.slice(64, 64 + n);
}

/** A decoded vault or verifier error. */
export interface DecodedError { rule: Rule; args: (bigint | Uint8Array)[]; raw: Uint8Array; inner?: DecodedError }

/** Decode revert data by selector; null for data that names no rule (an out-of-gas or a plain revert). */
export function decodeRevert(data: Uint8Array): DecodedError | null {
  if (data.length < 4) return null;
  const rule = BY_SELECTOR.get(toHex(data.subarray(0, 4)));
  if (rule === undefined) return null;
  const sig = signatureOf(rule);
  const types = sig.slice(sig.indexOf('(') + 1, -1).split(',').filter((x) => x !== '');
  const body = data.subarray(4);
  const args: (bigint | Uint8Array)[] = [];
  let inner: DecodedError | undefined;
  try {
    types.forEach((t, i) => {
      const w = body.subarray(32 * i, 32 * i + 32);
      if (w.length !== 32) throw new Error('short');
      if (t === 'bytes') {
        const off = Number(beInt(w));
        const n = Number(beInt(body.subarray(off, off + 32)));
        const v = body.slice(off + 32, off + 32 + n);
        if (v.length !== n) throw new Error('short');
        args.push(v);
        if (rule === 'VerifierRefused') inner = decodeRevert(v) ?? undefined;
      } else if (t === 'bytes32') args.push(w.slice());
      else args.push(beInt(w));
    });
  } catch {
    return { rule, args: [], raw: data };
  }
  return { rule, args, raw: data, inner };
}

/** What the wallet does about a failed redeem (section 13.3 and the guide's failure table). */
export type RedeemAction =
  | 'reconcile' // AlreadyPaid: look for Paid(eta); the burn is (probably) paid
  | 'rebuild-history' // StaleEndpoint: two rollovers since the history was built; rebuild it, never change the burn
  | 'wait' // FutureIndex: the vault has not reached a (cannot arise from section 12.2)
  | 'repair-proof' // BadGapProof, ChainMismatch, BadHistoryLength: a wrong proof or start head, repairable without a new burn
  | 'retry-later' // a potentially transient verifier or payout refusal, or an out-of-gas
  | 'stop'; // the evidence or the deployment is refused: tell the user, do not resend

export function classifyRedeemError(e: DecodedError | null): RedeemAction {
  if (e === null) return 'retry-later';
  switch (e.rule) {
    case 'AlreadyPaid': return 'reconcile';
    case 'StaleEndpoint': return 'rebuild-history';
    case 'FutureIndex': return 'wait';
    case 'BadGapProof': case 'ChainMismatch': case 'BadHistoryLength': return 'repair-proof';
    case 'PayoutFailed': case 'Reentrancy': return 'retry-later';
    case 'VerifierRefused': return isRetryableVerifierRefusal(e.inner?.rule) ? 'retry-later' : 'stop';
    default: return 'stop';
  }
}

/** A log as an RPC returns it. */
export interface RawLog { address: Uint8Array; topics: Uint8Array[]; data: Uint8Array; blockNumber: bigint; blockHash: Uint8Array; transactionHash: Uint8Array; logIndex: bigint; removed?: boolean }

export function decodeDeposited(l: RawLog): { n: bigint; domain: Uint8Array; amount: bigint; rho: Uint8Array; firstOwner: Uint8Array } | null {
  if (l.topics.length !== 2 || !eq(l.topics[0], TOPIC.Deposited) || l.data.length !== 224) return null;
  return { n: beInt(l.topics[1]), domain: l.data.slice(0, 32), amount: beInt(l.data.subarray(32, 64)), rho: l.data.slice(64, 96), firstOwner: l.data.slice(160, 202) };
}

export function decodePaid(l: RawLog): { eta: Uint8Array; recipient: Uint8Array; amount: bigint } | null {
  if (l.topics.length !== 3 || !eq(l.topics[0], TOPIC.Paid) || l.data.length !== 32) return null;
  return { eta: l.topics[1].slice(), recipient: l.topics[2].slice(12), amount: beInt(l.data) };
}
