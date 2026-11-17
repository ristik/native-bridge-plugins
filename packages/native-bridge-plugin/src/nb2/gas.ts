/**
 * Size and gas bounds of a redemption (sections 12.4 and 12.5). The preflight needs a CONSERVATIVE bound of the complete redeem
 * transaction before the burn exists: its encoded size and its gas limit (expected cost plus `gasReserve`). The gas part is a named,
 * replaceable component: {@link GasModel}. The default {@link MeasuredGasModel} (bound-nb2-1179, docs/nb2-gas-model.md) bounds the redeem
 * term by term from the deployed verifier's cost structure and fails closed (null, which the preflight reports as `CapacityPreflight`) for
 * anything it cannot bound. {@link ProvisionalGasModel} is NB2-07's earlier over-estimate, kept for comparison.
 */

import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';

import { concat, toHex } from '../bytes.js';
import { gapProofLen } from './segment.js';
import { array, bstr, bytesN, headTag, isUint, raw, scanNative, tagContent, u16 } from './cbor.js';
import { TAG } from './config.js';
import { HE, HU } from './crypto.js';
import { decodeReceiptBacking } from './deposit.js';
import { redeemCalldataLength } from './abi.js';
import { decodeSplitJustification } from './split.js';
import { PRED_SIGNATURE, encodeToken, mintSourceHash, resultState, stateId, tokenIdOf, type Predicate, type Token } from './token.js';

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
  // the vault (#1098 bench/nb2 RESULTS.md "worst"; unicity-pos-contracts#80, #81)
  vaultWorstCall: 487_339n,
  perSegment: 6_000n,
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
  verifierBase: 158_000n,
  perToken: 0n,
  perEdge: 57_149n,
  perAllocStep: 2_000n,
  perStep: 16_851n,
  perParentStep: 15_435n,
  perTxWord: 3n,
  perSibling: 3n,
  perItem: 757n,
  perUcParse: 19_100n,
  perUcByte: 7n,
  perUcIrByte: 27n,
  perUcSignature: 1_784n,
  perUcStc: 1_648n,
  perUcUtc: 2_146n,
  perUcSlowByte: 315n,
  perKeyLookup: 0n,
  perDecompress: 2_100n,
  perProbe: 271n,
  perClaim: 1_039n,
  jByte: 10n,
  // the verifier frame's memory high-water beyond its hash tables: words, and hundredths of a word per unit (measured, rounded up)
  memBase: 350,
  memPerStep100: 7_882,
  memPerParentStep100: 0,
  memPerClaimWord100: 103,
  memPerUcWord100: 263,
  memPerPathWord100: 101,
  memPerToken100: 27_775,
  memPerEdge100: 0,
  memPerAllocStep100: 0,
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
  maxSignatures: 16,
  keyCache: 128,
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
  pathWords: number; // the membership requests (words)
  maxUc: number;
  scratch: number; // the largest scratch use beyond the free pointer that the allocations after it do not cover (words)
  items: number; // CBOR items scanned
  jBytes: number;
  keyLookups: number;
  decompressions: number;
  probes: number; // key cache, state-ID set and claim set
  claims: { bytes: number; signatures: number; path: number; epoch: bigint | null }[]; // distinct, in check order
}

const ceil32 = (n: number): number => Math.ceil(n / 32);

/** The heads of a CBOR item sequence (definite lengths, string payloads skipped): the items the verifier's scanner visits. */
export function cborItems(b: Uint8Array): number {
  let n = 0;
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
    }
    if (major === 2 || major === 3) p += arg;
    n++;
  }
  return n;
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
      if (id === undefined) return null;
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
  try {
    evm = shapeOf(decodeReceiptBacking(j).proof.uc);
  } catch {
    return null;
  }
  if (evm === null) return null;
  // CBOR items: the evidence once, every split justification and J once (a byte string's content is scanned by the check that opens it)
  let items = 2 + cborItems(encodeToken(part)) + cborItems(j) + (pending ? g.pendingPairItems + g.pendingUcItems : 0);
  let allocSteps = 0;
  for (let i = 1; i < L.length; i++) {
    const sj = L[i].mint.justification;
    if (sj === null) return null;
    items += cborItems(sj);
    try {
      allocSteps += decodeSplitJustification(sj).proof.length;
    } catch {
      return null;
    }
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
    ucStc: evm.stc, ucUtc: evm.utc, ucSlow: evm.slow, helperMemory: helperMemory(evm.bytes), pathWords: 0, maxUc: evm.bytes, scratch: 24, items, jBytes: j.length,
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
    + g.memPerToken100 * f.tokens + g.memPerEdge100 * f.edges + g.memPerAllocStep100 * f.allocSteps;
  return g.memBase + Math.ceil(per / 100) + tables + f.scratch;
}

/** The bound's terms, each an upper bound of its part of the redeem's gas. */
export interface GasTerms {
  transaction: bigint;
  vault: bigint;
  batch: bigint;
  membership: bigint;
  sha256: bigint;
  execution: bigint;
  memory: bigint;
  forwarding: bigint;
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
    + g.perTxWord * B(f.txWords) + g.perSibling * B(f.siblings) + g.perItem * B(f.items)
    + g.perUcParse * B(f.ucParses) + g.perUcByte * B(f.ucBytes) + g.perUcIrByte * B(f.ucIr) + g.perUcSignature * B(f.ucSignatures) + g.perUcStc * B(f.ucStc) + g.perUcUtc * B(f.ucUtc)
    + g.perUcSlowByte * B(f.ucSlow) + f.helperMemory
    + g.perKeyLookup * B(f.keyLookups) + g.perDecompress * B(f.decompressions) + g.perProbe * B(f.probes) + g.perClaim * B(f.claims.length) + g.jByte * B(f.jBytes);
  const memoryWords = verifierMemoryWords(f);
  const memory = memoryGas(memoryWords);
  const verifier = batch.gas + membership + sha256 + execution + memory;
  const inner = batch.largest / 63n + 1n;
  const forwarding = (verifier + inner) / 63n + 1n + inner;
  const reserve = MEASURED.gasReserve;
  const limit = transaction + vault + verifier + forwarding + reserve;
  return { transaction, vault, batch: batch.gas, membership, sha256, execution, memory, forwarding, reserve, limit, memoryWords };
}

export function redeemGasTerms(s: RedeemShape): GasTerms | null {
  const f = redeemFeatures(s);
  return f === null ? null : priceFeatures(f, s.evidenceBytes, s.proofs, s.K);
}

/** The default model: {@link REDEEM_GAS}. */
export class MeasuredGasModel implements GasModel {
  public readonly name = 'bound-nb2-1179';

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
