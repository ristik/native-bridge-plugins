/**
 * Size and gas bounds of a redemption (sections 12.4 and 12.5). The preflight needs a CONSERVATIVE bound of the complete redeem
 * transaction before the burn exists: its encoded size and its gas limit (expected cost plus `gasReserve`). The gas part is a named,
 * replaceable component: {@link GasModel}. The default {@link MeasuredGasModel} (bound-nb2-1179, docs/nb2-gas-model.md) bounds the redeem
 * term by term from the deployed verifier's cost structure and fails closed (null, which the preflight reports as `CapacityPreflight`) for
 * anything it cannot bound. {@link ProvisionalGasModel} is NB2-07's earlier over-estimate, kept for comparison.
 */

import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';

import { concat, fromHex, toHex } from '../bytes.js';
import { gapProofLen } from './segment.js';
import { array, bstr, bytesN, headTag, isUint, raw, scanNative, tagContent, u16 } from './cbor.js';
import { TAG } from './config.js';
import { HE, HU } from './crypto.js';
import { decodeReceiptBacking } from './deposit.js';
import { redeemCalldataLength } from './abi.js';
import { decodeSplitJustification } from './split.js';
import { PRED_SIGNATURE, encodeProof, encodeToken, mintSourceHash, resultState, stateId, tokenIdOf, type Predicate, type Token } from './token.js';

/** What the gas model sees of a prospective redemption. */
export interface RedeemShape {
  /** The evidence bytes (`C(1, Token)`), or an upper bound of their length when the burn does not exist yet. */
  evidenceBytes: number;
  /** The decoded token of the lineage walk, root first, when known (counts certificates, signatures and paths). */
  lineage: Token[];
  /** Transactions the evidence will hold that are not in `lineage` yet (the burn about to be made). */
  pendingTransactions: number;
  /** Historical gap proofs. */
  proofs: bigint;
  K: bigint;
}

/** A gas model: the gas limit of a redeem (expected cost plus gasReserve), or null when it cannot be bounded. */
export interface GasModel {
  readonly name: string;
  redeemGasLimit(s: RedeemShape): bigint | null;
  /**
   * Whether the model is calibrated for the deployment, given its runtime codes (the verifier's hash checked against Γ, the vault's against
   * the manifest) and the manifest's native gas schedule. A model without this method is the wallet's own choice and is used as supplied.
   */
  supportsDeployment?(d: DeploymentCode): boolean;
  /** The gas limit of a deposit call. */
  depositGasLimit(): bigint;
}

/** Measured by #1098 (K = 64, B = 16, optimizer runs 200): replay and settlement only. */
export const MEASURED = {
  gasReserve: 500_000n,
  previousEndpoint: 78_083n, // the more expensive of the P = 0 endpoints
  perSegment: 5_950n,
  depositFirst: 48_758n,
} as const;

const TX_BASE = 21_000n;
const CALLDATA_NONZERO = 16n;

/**
 * Upper-bound guesses for the unmeasured verifier, from the B1 price schedule (bft-core `b1ref/limits.go`, profile 7) charged for
 * EVERY certificate occurrence as its own call, plus a per-byte charge for parsing and hashing the evidence in Solidity. Each term is
 * chosen above any plausible cost; it is not a measurement.
 */
export const PROVISIONAL = {
  perEvidenceByte: 128n, // CBOR scanning, SHA-256 and keccak over every byte, memory expansion
  perCertificate: 60_000n + 1_100n + 29_900n + 2_000n, // one B1 call per UC: base, common reads, one epoch, one claim
  perCertificateByte: 16n,
  perSignature: 7_200n,
  maxSignatures: 16, // the B1 bound per seal; a UC claiming more cannot be bounded here
  perPathStep: 250n,
  perTransaction: 3_000n + 2_000n + 256n * 250n, // ecrecover, the RSMT membership call, a full-depth path
  receiptProof: 200_000n, // the deposit's EVM UC is counted as a certificate; this covers header, trie and log checks
  /** A pending transaction's own certificate. */
  pendingCertificateBytes: 24_576,
} as const;

export class ProvisionalGasModel implements GasModel {
  public readonly name = 'provisional-nb2-07';

  public redeemGasLimit(s: RedeemShape): bigint | null {
    const p = PROVISIONAL;
    let verifier = p.receiptProof + p.perEvidenceByte * BigInt(s.evidenceBytes);
    let transactions = 0;
    for (const tok of s.lineage) {
      const proofs = [tok.mintProof, ...tok.proofs];
      transactions += proofs.length;
      for (const pr of proofs) {
        const sigs = countSignatures(pr.uc);
        if (sigs === null || sigs > p.maxSignatures) return null;
        verifier += p.perCertificate + p.perCertificateByte * BigInt(pr.uc.length) + p.perSignature * BigInt(sigs) + p.perPathStep * BigInt(pr.siblings.length + 32);
      }
    }
    // the root's EVM UC (inside J) and every pending transaction's future certificate, at the bounds
    const pending = BigInt(s.pendingTransactions);
    verifier += (pending + 1n) * (p.perCertificate + p.perCertificateByte * BigInt(p.pendingCertificateBytes) + p.perSignature * BigInt(p.maxSignatures) + p.perPathStep * 288n);
    verifier += BigInt(transactions + s.pendingTransactions) * p.perTransaction;
    const historyBytes = s.proofs === 0n ? 0 : 32 + Number(s.proofs) * gapProofLen(s.K);
    const calldata = CALLDATA_NONZERO * BigInt(redeemCalldataLength(s.evidenceBytes, historyBytes));
    const settlement = MEASURED.previousEndpoint + MEASURED.perSegment * s.proofs;
    return TX_BASE + calldata + settlement + verifier + MEASURED.gasReserve;
  }

  public depositGasLimit(): bigint {
    return 2n * MEASURED.depositFirst + 50_000n;
  }
}

/**
 * The redeem gas bound (bft-core#1179, docs/nb2-gas-model.md, where the calibration and the soundness argument are): an upper bound of the vault redeem's gas limit, term by term from the deployed
 * verifier's cost structure (unicity-pos-contracts `NativeBridgeVerifierV2`, its receipt helper `Nb2ReceiptVerifier`, the vault), not a fit to
 * the token's length:
 *
 *   limit = transaction + vault + batch + membership + sha256 + execution + memory + forwarding + gasReserve
 *
 *   transaction  21,000 + 16 per calldata byte (every byte priced as nonzero)
 *   vault        the worst measured vault call (#1098: previous endpoint, one bucket, sealing, K = 64, B = 16) + 6,000 per historical segment
 *                + its copy of the evidence into the verifier call: 3 a word and the vault frame's memory expansion
 *   batch        CERT_BATCH_V2 (0x0100) exactly as charged, over the distinct claims in the verifier's batching (_flush)
 *   membership   the RSMT membership (0x0102) exactly as charged, per inclusion proof
 *   sha256       SHA-256 (0x02) of every hashed transaction, exactly (a mint's includes its justification, so nesting is counted)
 *   execution    the verifier's and the helper's own execution, each loop priced per iteration at its measured cost rounded up: per token, split
 *                edge, allocation step and inclusion proof; per transaction word copied; per RSMT sibling; per CBOR item scanned; per UC
 *                parsed (base, byte, signature, shard tree sibling, unicity tree step, non-ASCII node ID byte) and its helper frame's memory;
 *                per key lookup, key decompression and hash-table probe (the verifier's three open-addressing tables replayed on the token's
 *                own keys, state IDs and claims; an unknown claim at every occupied slot); per byte of the root's J
 *   memory       the verifier frame's memory expansion, 3 M + M^2 / 512, over a bound M (words) of its high-water: what it allocates for
 *                the token plus the largest scratch beyond its free pointer
 *   forwarding   EIP-150: the vault keeps 1/64 of the gas it forwards to the verifier, the verifier 1/64 of its largest call
 *
 * The token's own proofs are counted exactly. The pending burn of a preflight is counted at the decoder bounds: a 24 KiB UC with 16
 * signatures of 128-byte non-ASCII node IDs, 256 shard tree siblings and 32 unicity tree steps, 256 RSMT siblings, a new claim and a new
 * epoch. A UC that does not parse, or has more than 16 signatures, gives null (`CapacityPreflight`).
 */
export const REDEEM_GAS = {
  txBase: 21_000n,
  calldataByte: 16n,
  // the vault: NB2VaultBase at unicity-pos-contracts 884c4829 (both builds, {@link CALIBRATED_DEPLOYMENT}), its worst call measured over every
  // phase (segments 0, 1 and steady; the previous endpoint, m = K-1, every identifier in one bucket in sort-adversarial order, then the seal)
  // for a never-used recipient (G_newaccount): 525,551 at K = 64, segment 1, the whole transaction with the echo verifier; rounded up
  vaultWorstCall: 530_000n,
  perSegment: 6_000n, // measured 5,898 a historical segment at K = 64, its calldata included
  copyWord: 3n,
  // CERT_BATCH_V2 (ureth crates/unicity/b1 batch.rs): 60,000 + 16 C + 500 k(k-1) + 1,100 + 29,900 E + 7,200 Q + 2,000 A + 250 P
  batchCall: 61_100n,
  batchByte: 16n,
  batchPair: 500n,
  batchEpoch: 29_900n,
  batchSignature: 7_200n,
  batchClaim: 2_000n,
  batchPath: 250n,
  batchClaims: 16,
  batchBytes: 262_144,
  // the RSMT membership (rsmt.rs): 2,000 + 16 per request byte + 250 (1 + siblings), a request of 104 + 32 (1 + siblings) bytes
  memberCall: 2_000n,
  memberByte: 16n,
  memberStep: 250n,
  // SHA-256 (0x02): 60 + 12 a word
  sha256Call: 60n,
  sha256Word: 12n,
  // the verifier's and the helper's own execution (measured, rounded up)
  verifierBase: 159_000n,
  perToken: 0n,
  perEdge: 16_407n,
  perAllocStep: 2_000n,
  perStep: 21_226n,
  perParentStep: 0n,
  perTxWord: 3n,
  perSibling: 3n,
  // the verifier's CBOR walks (Nb2Cbor.scan and skip), per item visited by each walk (bft-core#1179 round 2: measured per item form under the
  // verifier's own compiler settings, the largest form of each class raised 5%): an item, its head's argument bytes (ai 24 to 27), a nested
  // array, map or tag (scan's depth push and pop)
  scanItem: 410n, // measured: 389 an unsigned integer or null, 348 a byte string, 371 a text string
  scanLong: 230n, // measured: 219 the most an argument adds (a 2-byte argument)
  scanNode: 185n, // measured: 474 an array, 527 a map, 503 a tag, 657 a long array, 706 a long map, 782 a long tag (all with their head)
  skipItem: 260n, // measured: 231 an integer or null, 173 a byte string, 219 an array, 236 a map, 249 a tag
  skipLong: 90n, // measured: 80 the most an argument adds (329 a long tag)
  perUcParse: 19_100n,
  perUcByte: 7n,
  perUcIrByte: 27n,
  perUcSignature: 1_784n,
  perUcStc: 1_798n, // the helper's 1,548 and the verifier's _inShard, 250 a shard bit (measured 170)
  perUcUtc: 2_146n,
  perUcSlowByte: 315n,
  perKeyLookup: 0n,
  perDecompress: 2_100n,
  perProbe: 270n,
  perClaim: 0n,
  jByte: 10n, // J's copies and Keccak (code: at most 20 gas a word)
  // the receipt helper's RLP walk (Nb2Evm: check, head, kids), per item form (round 2: measured on lists of each form, raised 5%)
  perRlpItem: 320n, // check() of every item of the header, each trie node and the receipt (measured: 182 a byte, 304 a short string)
  perRlpLong: 190n, // its long form (0xb8 to 0xbf, 0xf8 to 0xff; measured: 482 a long string, 618 a long list)
  perRlpList: 250n, // a list (measured: 483 a short list, 541 an empty one)
  perRlpHead: 1_070n, // head() with its Item: each preceding log, the selected log's topics, every kids() child (measured at most 1,019)
  perRlpLongHead: 450n, // its long form (measured at most 1,371 in kids(), about 1,440 in receiptLog's walk of the logs)
  perRlpKids: 2_000n, // a kids() call's array of max Items
  coldAccess: 5_200n, // the verifier's EXTCODEHASH of its helper and the helper's code, cold on chain (2 x 2,600)
  // the verifier frame's memory high-water beyond its hash tables: words, and hundredths of a word per unit (measured, rounded up)
  memBase: 320,
  memPerStep100: 6_744,
  memPerParentStep100: 0,
  memPerClaimWord100: 103,
  memPerUcWord100: 306,
  memPerPathWord100: 123,
  memPerToken100: 28_523,
  memPerEdge100: 0,
  memPerAllocStep100: 600, // _sumVerify's 130-byte encoding a step
  memPerJWord100: 200, // J's receipt nodes, sliced and passed to the helper
  // the pending burn at the decoder bounds (unicity-pos-contracts Nb2Cert, the verifier's MAX_PROOF_UC, the RSMT's 256 levels)
  pendingTxBytes: 256,
  pendingUcBytes: 24_576,
  pendingSignatures: 16,
  pendingIdBytes: 128,
  pendingIrBytes: 448, // tag and head, version, round, epoch, timestamp and fees at 9 bytes, five 33-byte hashes, a 259-byte summary
  pendingStc: 256,
  pendingUtc: 32,
  pendingShardBytes: 33,
  pendingSiblings: 256,
  pendingUcItems: 40 + 256 + 3 * 32 + 2 * 16, // Nb2Cert's fixed items, one a shard tree sibling, three a step, two a signature
  pendingPairItems: 32, // the burn transfer, its certification data and path
  pendingDataItems: 16, // the burn's return data (_returnData: d, asset, recipient, amount, minIndex)
  maxSignatures: 16,
  keyCache: 128,
  // the explicit safety margin: 1/32 of the measured terms (about 3%)
  safetyDivisor: 32n,
} as const;

/** One UC as the verifier, its helper and the batch see it. */
interface UcShape {
  bytes: number;
  ir: number; // its input record's bytes (hashed and parsed field by field)
  signatures: number;
  stc: number; // shard tree siblings (= the shard's depth)
  utc: number; // unicity tree steps
  slow: number; // bytes of node IDs with a non-ASCII byte (the helper's byte-wise UTF-8 check)
  epoch: bigint | null; // null: unknown (the pending burn's)
  claimBytes: number; // 4 + 2 + shard + 96 + 4 + bytes
  claimKey: string | null; // keccak of the claim; null: unknown
}

/** A UC's shape as the helper's parse prices it. */
export interface UcCost { bytes: number; ir: number; signatures: number; stc: number; utc: number; slow: number }

/** The helper's certificate() on one UC, at the bound's coefficients (its execution and its frame's memory). */
export function helperGas(c: UcCost): bigint {
  const g = REDEEM_GAS;
  const B = (n: number): bigint => BigInt(n);
  return g.perUcParse + g.perUcByte * B(c.bytes) + g.perUcIrByte * B(c.ir) + g.perUcSignature * B(c.signatures) + g.perUcStc * B(c.stc) + g.perUcUtc * B(c.utc)
    + g.perUcSlowByte * B(c.slow) + helperMemory(c.bytes);
}

/** What the bound counts, extracted from the lineage. */
export interface RedeemFeatures {
  tokens: number;
  edges: number;
  allocSteps: number;
  steps: number; // inclusion proofs (mints and transfers, the pending burn's included)
  parentSteps: number; // the steps of the tokens above the part (the walk decodes each parent twice over: its justification's scan and parse)
  txWords: number; // SHA-256 words of every hashed transaction
  maxTx: number;
  siblings: number; // RSMT siblings
  ucParses: number; // UCs parsed: every proof's and J's
  ucBytes: number;
  ucIr: number;
  ucSignatures: number;
  ucStc: number;
  ucUtc: number;
  ucSlow: number;
  helperMemory: bigint; // the helper frames' memory expansion
  evmUc: UcCost; // J's EVM UC (the helper's receiptLog parses it)
  rcptItems: number; // RLP items check() visits: the header, every trie node, the receipt
  rcptLong: number; // of which in long form
  rcptLists: number; // of which lists
  rcptHeads: number; // head() calls: every preceding log and the selected one, its topics, every child a kids() call walks
  rcptLongHeads: number; // of which of a long-form item
  rcptKids: number; // kids() calls
  rcptWords: number; // the receipt helper frame's allocations beyond its UC parse (words)
  ucCosts: UcCost[]; // the distinct UC shapes the helper parses (each a call of its own: the forwarding term takes the largest)
  pathWords: number; // the membership requests (words)
  maxUc: number;
  scratch: number; // the largest scratch use beyond the free pointer that the allocations after it do not cover (words)
  scan: CborCount; // items the strict and loose scans visit: the evidence, every split justification, J, every transaction's data
  skip: CborCount; // items skip() visits: each parent token (skip(k0)), each token's genesis, each proof's UC, each predicate's three fields
  jBytes: number;
  keyLookups: number;
  decompressions: number;
  probes: number; // key cache, state-ID set and claim set
  claims: { bytes: number; signatures: number; path: number; epoch: bigint | null }[]; // distinct, in check order
}

const ceil32 = (n: number): number => Math.ceil(n / 32);

/** What a walk of the verifier's CBOR reader visits: items, heads with argument bytes, and nested items (a non-empty array or map, a tag). */
export interface CborCount { items: number; long: number; nodes: number }

/** The items of a CBOR item sequence as Nb2Cbor's scan and skip visit them (definite lengths, string payloads skipped). */
export function cborCount(b: Uint8Array): CborCount {
  const c = { items: 0, long: 0, nodes: 0 };
  for (let p = 0; p < b.length;) {
    const ib = b[p++];
    const major = ib >> 5;
    const ai = ib & 0x1f;
    let arg = ai;
    if (ai >= 24 && ai <= 27) {
      const w = 1 << (ai - 24);
      arg = 0;
      for (let k = 0; k < w; k++) arg = arg * 256 + (b[p + k] ?? 0);
      p += w;
      c.long++;
    }
    if (major === 2 || major === 3) p += arg;
    if (major === 6 || ((major === 4 || major === 5) && arg > 0)) c.nodes++;
    c.items++;
  }
  return c;
}

const addCount = (a: CborCount, b: CborCount, times = 1): void => {
  a.items += times * b.items;
  a.long += times * b.long;
  a.nodes += times * b.nodes;
};

/** The heads of a CBOR item sequence (definite lengths, string payloads skipped): the items the verifier's scanner visits. */
export function cborItems(b: Uint8Array): number {
  return cborCount(b).items;
}

/** An RLP item as Nb2Evm.head reads it. */
interface Rlp { list: boolean; at: number; pos: number; len: number; end: number }

function rlpHead(b: Uint8Array, p: number, end: number): Rlp | null {
  if (p >= end) return null;
  const x = b[p];
  const be = (q: number, n: number): number | null => {
    if (n > 4 || q + n > end || b[q] === 0) return null;
    let v = 0;
    for (let k = 0; k < n; k++) v = v * 256 + b[q + k];
    return v;
  };
  let hdr = 1;
  let len: number;
  let list = false;
  if (x < 0x80) return { list: false, at: p, pos: p, len: 1, end: p + 1 };
  if (x <= 0xb7) len = x - 0x80;
  else if (x <= 0xbf) {
    const n = be(p + 1, x - 0xb7);
    if (n === null) return null;
    hdr += x - 0xb7;
    len = n;
  } else if (x <= 0xf7) {
    list = true;
    len = x - 0xc0;
  } else {
    const n = be(p + 1, x - 0xf7);
    if (n === null) return null;
    list = true;
    hdr += x - 0xf7;
    len = n;
  }
  if (p + hdr + len > end) return null;
  return { list, at: p, pos: p + hdr, len, end: p + hdr + len };
}

/** Whether the item at P is in long form (a length of length: 0xb8 to 0xbf, 0xf8 to 0xff). */
const rlpLongAt = (b: Uint8Array, p: number): boolean => (b[p] >= 0xb8 && b[p] <= 0xbf) || b[p] >= 0xf8;

interface RlpCount { items: number; long: number; lists: number }

/** Every RLP item in [p, end) (check()'s visits) into C, or false when it is not RLP. */
function rlpItems(b: Uint8Array, p: number, end: number, c: RlpCount, depth = 0): boolean {
  while (p < end) {
    const it = rlpHead(b, p, end);
    if (it === null || depth > 16) return false;
    c.items++;
    if (rlpLongAt(b, p)) c.long++;
    if (it.list) {
      c.lists++;
      if (!rlpItems(b, it.pos, it.end, c, depth + 1)) return false;
    }
    p = it.end;
  }
  return true;
}

function rlpKids(b: Uint8Array, it: Rlp): Rlp[] | null {
  const out: Rlp[] = [];
  for (let q = it.pos; q < it.end;) {
    const k = rlpHead(b, q, it.end);
    if (k === null) return null;
    out.push(k);
    q = k.end;
  }
  return out;
}

/**
 * The receipt helper's walk of J's deposit proof (Nb2ReceiptVerifier.receiptLog, Nb2Evm): check() of the header, every trie node and the
 * receipt; kids() of the header (20), each node (17), the receipt (4) and the log (3), each walking every child; head() of every log up to
 * the selected one and of its topics; the allocations of those calls (an Item is 4 words, a kids() array 1 + 5 max) and the log's data.
 */
function receiptShape(header: Uint8Array, nodes: Uint8Array[], logIndex: bigint): { items: number; long: number; lists: number; heads: number; longHeads: number; kids: number; words: number } | null {
  const c: RlpCount = { items: 0, long: 0, lists: 0 };
  let heads = 0;
  let longHeads = 0;
  let kids = 0;
  // fixed: the frame's own words, the nodes' position and length arrays, the key nibbles (18), the header widths (20); scratch: the largest
  // node or header copied for its Keccak beyond the free pointer
  let words = 128 + 2 * nodes.length + 18 + 20 + ceil32(Math.max(header.length, ...nodes.map((x) => x.length)));
  const kidsOf = (b: Uint8Array, it: Rlp, max: number): Rlp[] | null => {
    const k = rlpKids(b, it);
    if (k === null) return null;
    kids++;
    heads += k.length;
    for (const x of k) if (rlpLongAt(b, x.at)) longHeads++;
    words += 1 + 5 * max + 4 * k.length;
    return k;
  };
  const top = (b: Uint8Array): Rlp | null => {
    const it = rlpHead(b, 0, b.length);
    if (!rlpItems(b, 0, b.length, c) || it === null || it.end !== b.length) return null;
    return it;
  };
  const h = top(header);
  if (h === null || !h.list || kidsOf(header, h, 20) === null) return null;
  let value: Uint8Array | null = null;
  for (let i = 0; i < nodes.length; i++) {
    const it = top(nodes[i]);
    if (it === null || !it.list) return null;
    const k = kidsOf(nodes[i], it, 17);
    if (k === null) return null;
    if (i === nodes.length - 1) {
      const v = k.length === 17 ? k[16] : k.length === 2 ? k[1] : null;
      if (v === null || v.list) return null;
      value = nodes[i].subarray(v.pos, v.end);
    }
  }
  if (value === null || value.length === 0) return null;
  const r = value[0] < 0xc0 ? value.subarray(1) : value;
  const rt = top(r);
  if (rt === null || !rt.list) return null;
  const f = kidsOf(r, rt, 4);
  if (f === null || f.length !== 4 || !f[3].list) return null;
  let q = f[3].pos;
  let sel: Rlp | null = null;
  for (let i = 0n; q < f[3].end; i++) {
    const it = rlpHead(r, q, f[3].end);
    if (it === null) return null;
    heads++;
    if (rlpLongAt(r, q)) longHeads++;
    words += 4;
    if (i === logIndex) {
      sel = it;
      break;
    }
    q = it.end;
  }
  if (sel === null || !sel.list) return null;
  const lk = kidsOf(r, sel, 3);
  if (lk === null || lk.length !== 3 || !lk[1].list) return null;
  const topics = rlpKids(r, lk[1]);
  if (topics === null) return null;
  heads += topics.length;
  for (const x of topics) if (rlpLongAt(r, x.at)) longHeads++;
  words += 4 * topics.length + 1 + topics.length + 1 + ceil32(lk[2].len);
  return { items: c.items, long: c.long, lists: c.lists, heads, longHeads, kids, words };
}

const u32 = (v: number): Uint8Array => Uint8Array.of(v >>> 24, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);

/** A UC in Nb2Cert.parse's shape: tag 39001 [1, IR, trHash, scHash, STC, UTC, seal]; null when it is not that shape. */
function ucShape(uc: Uint8Array): UcShape | null {
  try {
    const it = scanNative(uc);
    const c = array(tagContent(it, 39001n), 7);
    const ir = c[1];
    const irc = array(tagContent(ir, 39002n), 10);
    const sch = bytesN(c[3], 32);
    const stc = array(tagContent(c[4], 39003n), 3);
    const shard = bstr(stc[1]);
    const utc = array(tagContent(c[5], 39004n), 3);
    const seal = array(tagContent(c[6], 39005n), 8);
    const sigs = seal[7];
    if (stc[2].major !== 4 || !isUint(utc[1]) || utc[2].major !== 4 || !isUint(seal[3]) || sigs.major !== 5) return null;
    if (utc[1].arg > 0xffffffffn || shard.length > 0xffff) return null;
    let slow = 0;
    for (let k = 0; k < sigs.kids.length; k += 2) {
      const id = sigs.kids[k].data;
      if (sigs.kids[k].major !== 3 || id === undefined) return null;
      if (id.some((x) => x >= 0x80)) slow += id.length;
    }
    const claim = concat(u32(Number(utc[1].arg)), u16(shard.length), shard, sch, bytesN(irc[4], 32), HU(raw(uc, ir)), u32(uc.length), uc);
    return {
      bytes: uc.length, ir: ir.end - ir.start, signatures: sigs.kids.length / 2, stc: stc[2].kids.length, utc: utc[2].kids.length, slow, epoch: seal[3].arg,
      claimBytes: claim.length, claimKey: toHex(HE(claim)),
    };
  } catch {
    return null;
  }
}

/** One open-addressing table of the verifier (linear probing from the key's low bits), counting its probes and its misses. */
class ProbeTable {
  private readonly slots: (string | null)[];
  public probes = 0;
  public misses = 0;
  public constructor(size: number) {
    this.slots = new Array<string | null>(size).fill(null);
  }
  /** Look up or insert KEY (a 32-byte digest in hex); a full table answers a miss without storing (the key cache). */
  public lookup(key: string): void {
    const mask = this.slots.length - 1;
    let i = Number(BigInt(`0x${key.slice(-8)}`) & BigInt(mask));
    for (let probe = 0; probe <= mask; probe++) {
      this.probes++;
      const s = this.slots[i];
      if (s === key) return;
      if (s === null) {
        this.slots[i] = key;
        this.misses++;
        return;
      }
      i = (i + 1) & mask;
    }
    this.misses++;
  }
}

/** The part's current owner and state (tokenops headOf, repeated here to keep this module free of the signing code). */
function headOf(t: Token): { owner: Predicate; state: Uint8Array } {
  const id = tokenIdOf(t.mint.salt, t.mint.network);
  let state = resultState(mintSourceHash(id), id);
  let owner = t.mint.recipient;
  for (const tr of t.transfers) {
    state = resultState(state, tr.mask);
    owner = tr.recipient;
  }
  return { owner, state };
}

/** The verifier's table size for N entries (_pow2: at least 16). */
const pow2At = (n: number): number => {
  let p = 16;
  while (p < n) p <<= 1;
  return p;
};

interface Step { tx: number; siblings: number; uc: UcShape; sid: Uint8Array }

/** The features of a prospective redemption; null when a UC does not parse or has more signatures than the bound. */
export function redeemFeatures(s: RedeemShape): RedeemFeatures | null {
  const g = REDEEM_GAS;
  const L = s.lineage;
  if (L.length === 0 || (s.pendingTransactions !== 0 && s.pendingTransactions !== 1)) return null;
  const pending = s.pendingTransactions === 1;
  const cache = new Map<string, UcShape | null>();
  const shapeOf = (uc: Uint8Array): UcShape | null => {
    const k = toHex(HU(uc));
    if (!cache.has(k)) cache.set(k, ucShape(uc));
    const u = cache.get(k)!;
    return u === null || u.signatures > g.maxSignatures ? null : u;
  };
  // the steps in check order (the verifier's _level loop): root first, each token's mint then its transfers, the pending burn last
  const steps: Step[] = [];
  for (const t of L) {
    const proofs = [t.mintProof, ...t.proofs];
    const raws = [t.mintRaw, ...t.transfersRaw];
    for (let k = 0; k < proofs.length; k++) {
      const uc = shapeOf(proofs[k].uc);
      if (uc === null) return null;
      steps.push({ tx: raws[k].length, siblings: proofs[k].siblings.length, uc, sid: stateId(proofs[k].cd.source, proofs[k].cd.sourceHash) });
    }
  }
  const part = L[L.length - 1];
  const head = headOf(part);
  if (pending) {
    const uc: UcShape = {
      bytes: g.pendingUcBytes, ir: g.pendingIrBytes, signatures: g.pendingSignatures, stc: g.pendingStc, utc: g.pendingUtc, slow: g.pendingSignatures * g.pendingIdBytes, epoch: null,
      claimBytes: 4 + 2 + g.pendingShardBytes + 96 + 4 + g.pendingUcBytes, claimKey: null,
    };
    steps.push({ tx: g.pendingTxBytes, siblings: g.pendingSiblings, uc, sid: stateId(head.owner, head.state) });
  }
  const n = steps.length;
  // J and its EVM UC (the receipt helper parses it like an aggregator UC)
  const j = L[0].mint.justification;
  if (j === null || headTag(j) !== TAG.receiptBacking) return null;
  let evm: UcShape | null;
  let rcpt: ReturnType<typeof receiptShape>;
  try {
    const dp = decodeReceiptBacking(j).proof;
    evm = shapeOf(dp.uc);
    rcpt = receiptShape(dp.header, dp.nodes, dp.logIndex);
  } catch {
    return null;
  }
  if (evm === null || rcpt === null) return null;
  // the CBOR walks (NativeBridgeVerifierV2): a byte string's content is walked only by the check that opens it.
  // scan (strict or loose, one price): the evidence [1, part] (_evidence), every split justification, so each parent token once
  // (_splitJustification), J (_rootMint), every transaction's data (_mintAmount, _returnData, _splitBurn: each at most once)
  // skip: every parent token (_splitJustification's skip(k0)), every token's genesis [mint, proof] (_token's skip(g)), every proof's UC
  // (_proof), every predicate's three fields (_pred)
  const scan: CborCount = { items: 2, long: 0, nodes: 1 };
  const skip: CborCount = { items: 0, long: 0, nodes: 0 };
  addCount(scan, cborCount(encodeToken(part)));
  addCount(scan, cborCount(j));
  let allocSteps = 0;
  for (let i = 0; i < L.length; i++) {
    const t = L[i];
    if (i > 0) {
      const sj = t.mint.justification;
      if (sj === null) return null;
      addCount(scan, cborCount(sj));
      try {
        allocSteps += decodeSplitJustification(sj).proof.length;
      } catch {
        return null;
      }
    }
    if (i < L.length - 1) addCount(skip, cborCount(encodeToken(t)));
    // the genesis array's head and its two items
    skip.items += 1;
    skip.nodes += 1;
    addCount(skip, cborCount(t.mintRaw));
    addCount(skip, cborCount(encodeProof(t.mintProof)));
    for (const pr of [t.mintProof, ...t.proofs]) addCount(skip, cborCount(pr.uc));
    for (const d of [t.mint.data, ...t.transfers.map((tr) => tr.data)]) if (d !== null) addCount(scan, cborCount(d));
    // a predicate's fields: a 1-item integer, a 1-byte code string, a 33- or 32-byte parameter string (an argument byte)
    const predicates = 2 * (1 + t.transfers.length);
    skip.items += 3 * predicates;
    skip.long += predicates;
  }
  if (pending) {
    // the burn and its proof at the decoder bounds, every item priced as the dearest form (an argument and nested)
    const n = g.pendingPairItems + g.pendingUcItems;
    addCount(scan, { items: n, long: n, nodes: n });
    addCount(skip, { items: g.pendingUcItems, long: g.pendingUcItems, nodes: g.pendingUcItems });
    skip.items += 6;
    skip.long += 2;
    addCount(scan, { items: g.pendingDataItems, long: g.pendingDataItems, nodes: g.pendingDataItems });
  }
  // the key cache: every signature predicate in parse order (the part, then each parent; per token its mint's recipient and source, then
  // each transfer's recipient and source); the burn's recipient is a burn predicate, its source the part's owner
  const keys = new ProbeTable(g.keyCache);
  let keyLookups = 0;
  const key = (p: Predicate): void => {
    if (p.type !== PRED_SIGNATURE) return;
    keyLookups++;
    keys.lookup(toHex(HE(p.params)));
  };
  for (let i = L.length - 1; i >= 0; i--) {
    const t = L[i];
    key(t.mint.recipient);
    key(t.mintProof.cd.source);
    for (let k = 0; k < t.transfers.length; k++) {
      key(t.transfers[k].recipient);
      key(t.proofs[k].cd.source);
    }
    if (i === L.length - 1 && pending) key(head.owner);
  }
  // the state-ID set (a zero ID shares the sentinel 1's slot)
  const sids = new ProbeTable(pow2At(2 * n));
  for (const st of steps) sids.lookup(st.sid.every((x) => x === 0) ? `${'00'.repeat(31)}01` : toHex(st.sid));
  // the claims: J's EVM UC first (the receipt is checked before the walk), then every proof's, deduplicated by digest; an unknown digest
  // probes every occupied slot and then its own
  const claimIds = new ProbeTable(pow2At(2 * (n + 1)));
  const seen = new Set<string>();
  const claims: RedeemFeatures['claims'] = [];
  let unknownProbes = 0;
  for (const u of [evm, ...steps.map((st) => st.uc)]) {
    const c = { bytes: u.claimBytes, signatures: u.signatures, path: u.stc + u.utc, epoch: u.epoch };
    if (u.claimKey === null) {
      unknownProbes += seen.size + 1;
      claims.push(c);
    } else {
      claimIds.lookup(u.claimKey);
      if (!seen.has(u.claimKey)) {
        seen.add(u.claimKey);
        claims.push(c);
      }
    }
  }
  const f: RedeemFeatures = {
    tokens: L.length, edges: L.length - 1, allocSteps, steps: n, parentSteps: L.slice(0, -1).reduce((m, t) => m + 1 + t.transfers.length, 0), txWords: 0, maxTx: 0, siblings: 0, ucParses: n + 1, ucBytes: evm.bytes, ucIr: evm.ir, ucSignatures: evm.signatures,
    ucStc: evm.stc, ucUtc: evm.utc, ucSlow: evm.slow, helperMemory: memoryGas(3 * ceil32(evm.bytes) + 64 + rcpt.words),
    evmUc: { bytes: evm.bytes, ir: evm.ir, signatures: evm.signatures, stc: evm.stc, utc: evm.utc, slow: evm.slow }, ucCosts: [],
    rcptItems: rcpt.items, rcptLong: rcpt.long, rcptLists: rcpt.lists, rcptHeads: rcpt.heads, rcptLongHeads: rcpt.longHeads, rcptKids: rcpt.kids, rcptWords: rcpt.words,
    pathWords: 0, maxUc: evm.bytes, scratch: 24, scan, skip, jBytes: j.length,
    keyLookups, decompressions: keys.misses, probes: keys.probes + sids.probes + claimIds.probes + unknownProbes, claims,
  };
  // a transaction is hashed from a copy at the free pointer (SHA-256 of calldata); every later step allocates at least its UC's slice and its
  // claim (two copies of the UC), which lie over that scratch, so only what they do not cover can raise the high-water
  let after = 0;
  for (let i = steps.length - 1; i >= 0; i--) {
    f.scratch = Math.max(f.scratch, ceil32(steps[i].tx) + 1 - after);
    after += 2 * ceil32(steps[i].uc.bytes);
  }
  for (const st of steps) {
    f.txWords += ceil32(st.tx);
    f.maxTx = Math.max(f.maxTx, st.tx);
    f.siblings += st.siblings;
    f.ucBytes += st.uc.bytes;
    f.ucIr += st.uc.ir;
    f.ucSignatures += st.uc.signatures;
    f.ucStc += st.uc.stc;
    f.ucUtc += st.uc.utc;
    f.ucSlow += st.uc.slow;
    f.helperMemory += helperMemory(st.uc.bytes);
    const c = { bytes: st.uc.bytes, ir: st.uc.ir, signatures: st.uc.signatures, stc: st.uc.stc, utc: st.uc.utc, slow: st.uc.slow };
    if (!f.ucCosts.some((x) => x.bytes === c.bytes && x.ir === c.ir && x.signatures === c.signatures && x.stc === c.stc && x.utc === c.utc && x.slow === c.slow)) {
      f.ucCosts.push(c);
    }
    f.pathWords += 1 + ceil32(104 + 32 * (st.siblings + 1));
    f.maxUc = Math.max(f.maxUc, st.uc.bytes);
  }
  return f;
}

/** The memory expansion of WORDS words (the Yellow Paper's C_mem). */
export const memoryGas = (words: number): bigint => {
  const w = BigInt(words);
  return 3n * w + (w * w) / 512n;
};

/** One helper call's frame: the UC copied for the claim, the claim and the ABI answer (about three UCs of memory). */
const helperMemory = (ucBytes: number): bigint => memoryGas(3 * ceil32(ucBytes) + 64);

/** CERT_BATCH_V2 over the distinct claims in the verifier's batching (_flush): balanced calls of at most 16 claims and 256 KiB. */
export function batchGas(claims: RedeemFeatures['claims']): { gas: bigint; calls: number; largest: bigint } {
  const g = REDEEM_GAS;
  const m = claims.length;
  if (m === 0) return { gas: 0n, calls: 0, largest: 0n };
  const per = Math.ceil(m / Math.ceil(m / g.batchClaims));
  let gas = 0n;
  let largest = 0n;
  let calls = 0;
  for (let s = 0; s < m;) {
    let e = s;
    let bytes = 4;
    while (e < m && e - s < per && bytes + claims[e].bytes <= g.batchBytes) bytes += claims[e++].bytes;
    if (e === s) bytes += claims[e++].bytes;
    const k = BigInt(e - s);
    const epochs = new Set<string>();
    let q = 0n;
    let p = 0n;
    for (let i = s; i < e; i++) {
      const ep = claims[i].epoch;
      epochs.add(ep === null ? `unknown ${i}` : ep.toString());
      q += BigInt(claims[i].signatures);
      p += BigInt(claims[i].path);
    }
    const c = g.batchCall + g.batchByte * BigInt(bytes) + g.batchPair * k * (k - 1n) + g.batchEpoch * BigInt(epochs.size) + g.batchSignature * q + g.batchClaim * k
      + g.batchPath * p;
    gas += c;
    if (c > largest) largest = c;
    calls++;
    s = e;
  }
  return { gas, calls, largest };
}

/** The verifier frame's memory high-water bound (words): its hash tables exactly, what else it allocates, its largest scratch use. */
export function verifierMemoryWords(f: RedeemFeatures): number {
  const g = REDEEM_GAS;
  const n = f.steps;
  const tables = pow2At(2 * (n + 1)) + pow2At(2 * n) + (n + 1) + 2 * g.keyCache;
  const per = g.memPerStep100 * n + g.memPerParentStep100 * f.parentSteps + g.memPerClaimWord100 * f.claims.reduce((w, c) => w + ceil32(c.bytes) + 1, 0) + g.memPerUcWord100 * ceil32(f.ucBytes) + g.memPerPathWord100 * f.pathWords
    + g.memPerToken100 * f.tokens + g.memPerEdge100 * f.edges + g.memPerAllocStep100 * f.allocSteps + g.memPerJWord100 * ceil32(f.jBytes);
  return g.memBase + Math.ceil(per / 100) + tables + f.scratch;
}

/** The verifier's CBOR walks at the bound's prices. */
export function walkGas(f: RedeemFeatures): bigint {
  const g = REDEEM_GAS;
  const B = (n: number): bigint => BigInt(n);
  return g.scanItem * B(f.scan.items) + g.scanLong * B(f.scan.long) + g.scanNode * B(f.scan.nodes) + g.skipItem * B(f.skip.items) + g.skipLong * B(f.skip.long);
}

/** The receipt helper's RLP walk at the bound's prices. */
export function receiptWalkGas(f: RedeemFeatures): bigint {
  const g = REDEEM_GAS;
  const B = (n: number): bigint => BigInt(n);
  return g.perRlpItem * B(f.rcptItems) + g.perRlpLong * B(f.rcptLong) + g.perRlpList * B(f.rcptLists) + g.perRlpHead * B(f.rcptHeads) + g.perRlpLongHead * B(f.rcptLongHeads)
    + g.perRlpKids * B(f.rcptKids);
}

/** The estimate's terms: each is derived from the code or measured (docs/nb2-gas-model.md lists which). */
export interface GasTerms {
  transaction: bigint;
  vault: bigint;
  batch: bigint;
  membership: bigint;
  sha256: bigint;
  execution: bigint;
  memory: bigint;
  forwarding: bigint;
  safety: bigint;
  reserve: bigint;
  limit: bigint;
  memoryWords: number;
}

/** The terms of a redemption with FEATURES, EVIDENCEBYTES of evidence and PROOFS historical gap proofs at K. */
export function priceFeatures(f: RedeemFeatures, evidenceBytes: number, proofs: bigint, K: bigint): GasTerms {
  const g = REDEEM_GAS;
  const B = (n: number): bigint => BigInt(n);
  const historyBytes = proofs === 0n ? 0 : 32 + Number(proofs) * gapProofLen(K);
  const transaction = g.txBase + g.calldataByte * B(redeemCalldataLength(evidenceBytes, historyBytes));
  const vw = ceil32(evidenceBytes) + 64;
  const vault = g.vaultWorstCall + g.perSegment * proofs + g.copyWord * B(vw) + memoryGas(vw);
  const batch = batchGas(f.claims);
  const membership = B(f.steps) * (g.memberCall + g.memberByte * 136n + g.memberStep) + B(f.siblings) * (32n * g.memberByte + g.memberStep);
  const sha256 = B(f.steps) * g.sha256Call + B(f.txWords) * g.sha256Word;
  const execution = g.verifierBase + g.perToken * B(f.tokens) + g.perEdge * B(f.edges) + g.perAllocStep * B(f.allocSteps) + g.perStep * B(f.steps) + g.perParentStep * B(f.parentSteps)
    + g.perTxWord * B(f.txWords) + g.perSibling * B(f.siblings) + walkGas(f)
    + g.perUcParse * B(f.ucParses) + g.perUcByte * B(f.ucBytes) + g.perUcIrByte * B(f.ucIr) + g.perUcSignature * B(f.ucSignatures) + g.perUcStc * B(f.ucStc) + g.perUcUtc * B(f.ucUtc)
    + g.perUcSlowByte * B(f.ucSlow) + f.helperMemory
    + g.perKeyLookup * B(f.keyLookups) + g.perDecompress * B(f.decompressions) + g.perProbe * B(f.probes) + g.perClaim * B(f.claims.length) + g.jByte * B(f.jBytes)
    + receiptWalkGas(f) + g.coldAccess;
  const memoryWords = verifierMemoryWords(f);
  const memory = memoryGas(memoryWords);
  // the explicit safety margin over the measured terms (the verifier's execution and memory, the vault's call): see docs/nb2-gas-model.md
  const safety = (execution + memory + vault) / g.safetyDivisor + 1n;
  const verifier = batch.gas + membership + sha256 + execution + memory;
  // EIP-150 at the verifier's own calls: the largest of its batch calls, its helper calls (one a UC; J's receipt with its EVM UC)
  let largest = batch.largest;
  for (const c of f.ucCosts) if (helperGas(c) > largest) largest = helperGas(c);
  const receipt = helperGas(f.evmUc) - helperMemory(f.evmUc.bytes) + memoryGas(3 * ceil32(f.evmUc.bytes) + 64 + f.rcptWords) + g.jByte * B(f.jBytes)
    + receiptWalkGas(f);
  if (receipt > largest) largest = receipt;
  const inner = largest / 63n + 1n;
  const forwarding = (verifier + inner) / 63n + 1n + inner;
  const reserve = MEASURED.gasReserve;
  const limit = transaction + vault + verifier + forwarding + safety + reserve;
  return { transaction, vault, batch: batch.gas, membership, sha256, execution, memory, forwarding, safety, reserve, limit, memoryWords };
}

export function redeemGasTerms(s: RedeemShape): GasTerms | null {
  const f = redeemFeatures(s);
  return f === null ? null : priceFeatures(f, s.evidenceBytes, s.proofs, s.K);
}

/** The native gas schedules {@link REDEEM_GAS} assumes (ureth unicity/main crates/unicity/b1, profile 7; SHA-256 as in Cancun). */
export const NATIVE_GAS_SCHEDULE = 'CERT_BATCH_V2 61100+16C+500K(K-1)+29900E+7200Q+2000A+250P; RSMT 2000+16L+250(1+S); SHA256 60+12W';

/**
 * The deployment {@link REDEEM_GAS} is calibrated for: unicity-pos-contracts 884c4829 `src/nb2` as deploy_nb2.py creates it (solc 0.8.37,
 * via-IR; the verifier at optimizer runs 1, the vault at 200), its helper, and {@link NATIVE_GAS_SCHEDULE}. Each runtime is the artifact's
 * code with its immutables filled in; the immutables are all derived from Γ and the verifier's address, so the expected runtime is rebuilt
 * from them and compared with the deployed one in full ({@link calibratedDeployment}).
 */
export const CALIBRATED_DEPLOYMENT = {
  verifier: {
    codeLength: 19_574,
    maskedCodeHash: '65fbc862ae2ea16729506cd9e6a62458785751b690103ce25d9515495029f201',
    admitsTestSet: [8_541, 12_187],
    receipts: [325, 3_071, 8_473, 15_504],
    receiptsCodeHash: [368, 8_417],
  },
  helperCodeHash: '16f1381ed6c1d9cd1c14b467fcfb2ec84ab8903f65da506048fbb2e2c10ffe23',
  vault: {
    codeLength: 6_363,
    maskedCodeHash: '9bc8cce34b22e45345a9a49c28a4041229f748c8d13964e69fbf2020b90545e4',
    // D, VERIFIER, QMAX, K, LOGK, LOGB, GLEN, G0 to G11 (NB2VaultBase's immutables in declaration order)
    immutables: [
      [103, 1_318, 2_642, 4_362, 5_801], [1_218], [5_648], [1_460, 1_792, 1_924, 1_986, 2_090, 2_181, 2_222, 2_391, 2_455, 2_500, 4_057, 6_226],
      [375, 4_228, 4_291, 4_415, 4_531, 4_761], [519, 576, 1_529, 1_567, 1_607, 1_642, 2_031, 2_139, 2_266, 2_344, 3_419, 3_468, 3_543, 3_639, 3_688, 4_019, 6_189],
      [1_097, 4_929], [641, 5_044], [676, 5_079], [713, 5_117], [751, 5_155], [789, 5_193], [827, 5_231], [865, 5_269], [903, 5_307], [941, 5_345], [980, 5_384],
      [1_019, 5_423], [1_058, 5_462],
    ],
  },
} as const;

/** What the bridge shows a gas model of the deployment (codes from the RPC; the vault's and the verifier's hashes already checked). */
export interface DeploymentCode {
  gamma: Uint8Array;
  verifier: Uint8Array; // the verifier's address
  K: bigint;
  B: bigint;
  Qmax: bigint;
  verifierCode: Uint8Array;
  /** The code at the verifier's first CREATE address ({@link createAddress}(verifier, 1)), where its constructor deploys the helper. */
  helperCode: Uint8Array;
  vaultCode: Uint8Array;
  /** The deployment manifest's `nativeGasSchedule` pin, when it has one. */
  nativeGasSchedule?: string;
}

/** The address of the contract ADDRESS creates with nonce NONCE (keccak256(RLP([address, nonce]))[12:]). */
export function createAddress(address: Uint8Array, nonce: bigint): Uint8Array {
  const n = nonce === 0n ? new Uint8Array() : bigBytes(nonce);
  const item = n.length === 1 && n[0] < 0x80 ? n : concat(Uint8Array.of(0x80 + n.length), n);
  const body = concat(Uint8Array.of(0x94), address, item);
  return HE(concat(Uint8Array.of(0xc0 + body.length), body)).slice(12);
}

const bigBytes = (v: bigint): Uint8Array => {
  const out: number[] = [];
  for (let x = v; x > 0n; x >>= 8n) out.unshift(Number(x & 0xffn));
  return Uint8Array.from(out);
};

const word = (v: bigint | Uint8Array): Uint8Array => {
  const w = new Uint8Array(32);
  const b = typeof v === 'bigint' ? bigBytes(v) : v;
  w.set(b, 32 - b.length);
  return w;
};

const log2Ceil = (v: bigint): bigint => {
  let n = 0n;
  while (1n << n < v) n++;
  return n;
};

/** Whether CODE is the template of length N with hash MASKED once POSITIONS are zeroed and every occurrence holds its expected word. */
function rebuilt(code: Uint8Array, length: number, masked: string, positions: readonly (readonly number[])[], values: Uint8Array[]): boolean {
  if (code.length !== length) return false;
  const m = Uint8Array.from(code);
  for (let i = 0; i < positions.length; i++) {
    for (const at of positions[i]) {
      if (toHex(code.subarray(at, at + 32)) !== toHex(values[i])) return false;
      m.fill(0, at, at + 32);
    }
  }
  return toHex(HE(m)) === masked;
}

/**
 * Whether D is the calibrated deployment: the verifier's, the helper's and the vault's runtimes are exactly the calibrated artifacts with the
 * immutables this deployment must have (admitsTestSet unless (K, B) is the production pair; the helper at the verifier's first CREATE
 * address with the calibrated code hash, which the verifier pins; the vault's D = H_U(Γ), verifier, Qmax, K, log2 K, log2 B and Γ's twelve
 * words), and the manifest pins {@link NATIVE_GAS_SCHEDULE}.
 */
export function calibratedDeployment(d: DeploymentCode): boolean {
  const c = CALIBRATED_DEPLOYMENT;
  if (d.nativeGasSchedule !== NATIVE_GAS_SCHEDULE) return false;
  if (toHex(HE(d.helperCode)) !== c.helperCodeHash) return false;
  const production = d.K === 64n && d.B === 16n;
  const v = c.verifier;
  const helper = createAddress(d.verifier, 1n);
  if (!rebuilt(d.verifierCode, v.codeLength, v.maskedCodeHash, [v.admitsTestSet, v.receipts, v.receiptsCodeHash],
    [word(production ? 0n : 1n), word(helper), fromHex(c.helperCodeHash)!])) return false;
  if (d.gamma.length > 384) return false;
  const padded = new Uint8Array(384);
  padded.set(d.gamma);
  const values = [HU(d.gamma), word(d.verifier), word(d.Qmax), word(d.K), word(log2Ceil(d.K)), word(log2Ceil(d.B)), word(BigInt(d.gamma.length))];
  for (let i = 0; i < 12; i++) values.push(padded.slice(32 * i, 32 * i + 32));
  return rebuilt(d.vaultCode, c.vault.codeLength, c.vault.maskedCodeHash, c.vault.immutables, values);
}

/** The default model: {@link REDEEM_GAS}, for the {@link CALIBRATED_DEPLOYMENT} only (the bridge refuses it for any other). */
export class MeasuredGasModel implements GasModel {
  public readonly name = 'estimate-nb2-1179';

  public supportsDeployment(d: DeploymentCode): boolean {
    return calibratedDeployment(d);
  }

  public redeemGasLimit(s: RedeemShape): bigint | null {
    return redeemGasTerms(s)?.limit ?? null;
  }

  public depositGasLimit(): bigint {
    return 2n * MEASURED.depositFirst + 50_000n;
  }
}

/** The signature count of a UC's seal, from its full canonical decode; null (fail closed) when the UC does not decode. */
function countSignatures(uc: Uint8Array): number | null {
  try {
    const sigs = UnicityCertificate.fromCBOR(uc).unicitySeal.witnesses;
    return sigs === null ? 0 : sigs.size;
  } catch {
    return null;
  }
}

/** The byte-level count, kept only as a cross-check in tests. */
export function countSignaturesRaw(uc: Uint8Array): number | null {
  // a full decode is the trust layer's; a byte-level count of the signature map is enough for a bound: find the seal tag 39005
  // (d9 985d) and read its 8-array's last item
  for (let i = 0; i + 3 < uc.length; i++) {
    if (uc[i] === 0xd9 && uc[i + 1] === 0x98 && uc[i + 2] === 0x5d && uc[i + 3] === 0x88) {
      try {
        // skip seven items, then read the map head
        let pos = i + 4;
        for (let k = 0; k < 7; k++) pos = skipItem(uc, pos);
        const ib = uc[pos];
        if (ib === 0xf6) return 0;
        if (ib >> 5 !== 5) return null;
        const ai = ib & 0x1f;
        if (ai < 24) return ai;
        if (ai === 24) return uc[pos + 1];
        return null;
      } catch {
        return null;
      }
    }
  }
  return null;
}

function skipItem(b: Uint8Array, pos: number): number {
  if (pos >= b.length) throw new Error('short');
  const ib = b[pos++];
  const major = ib >> 5;
  const ai = ib & 0x1f;
  let arg = 0;
  if (ai < 24) arg = ai;
  else if (ai <= 27) {
    const n = 1 << (ai - 24);
    for (let k = 0; k < n; k++) arg = arg * 256 + b[pos + k];
    pos += n;
  } else throw new Error('indefinite');
  switch (major) {
    case 0: case 1: case 7: return pos;
    case 2: case 3: return pos + arg;
    case 4: for (let k = 0; k < arg; k++) pos = skipItem(b, pos); return pos;
    case 5: for (let k = 0; k < 2 * arg; k++) pos = skipItem(b, pos); return pos;
    case 6: return skipItem(b, pos);
    default: throw new Error('major');
  }
}

/**
 * The encoded size of a signed EIP-1559 redeem transaction around `calldata` bytes: the envelope, nine scalar fields at their widest,
 * the 20-byte target, an empty access list and a 65-byte signature, plus the RLP heads of the data string and the list.
 */
export const redeemTxFraming = (calldata: number): number => 1 + 9 + 9 * 9 + 21 + 1 + 3 * 33 + (calldata >= 56 ? 5 : 1) + 5;
