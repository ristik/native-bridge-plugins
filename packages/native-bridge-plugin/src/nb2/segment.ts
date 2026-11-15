/**
 * Segments, the sorted circular-gap tree, gap proofs, the archive chain (section 10), the wallet's `SegmentSealed` log check and its
 * history builder (section 12.3); bft-core `nb2ref/segment.go`.
 */
import { concat, eq } from '../bytes.js';
import { u16, u256, u64 } from './cbor.js';
import { log2 } from './config.js';
import { HE } from './crypto.js';
import { TAG_ARCHIVE_GENESIS, TAG_ARCHIVE_STEP } from './deposit.js';
import { Nb2Error, fail } from './errors.js';

/** bucket(eta) = eta >> (256 - log2 B). */
export const bucketOf = (eta: Uint8Array, B: bigint): number => eta[0] >> (8 - log2(B));

export function cmp(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}
const less = (a: Uint8Array, b: Uint8Array): boolean => cmp(a, b) < 0;

export const gapLeaf = (l: Uint8Array, u: Uint8Array): Uint8Array => HE(Uint8Array.of(0x00), l, u);
export const gapNode = (l: Uint8Array, r: Uint8Array): Uint8Array => HE(Uint8Array.of(0x01), l, r);
/** 65 + 32h bytes. */
export const gapProofLen = (K: bigint): number => 65 + 32 * log2(K);

export class GapTree {
  private constructor(public readonly z: Uint8Array[], private readonly levels: Uint8Array[][]) {}

  /** Requires a power-of-two count >= 2, strictly increasing. */
  public static build(z: Uint8Array[]): GapTree | null {
    const k = z.length;
    if (k < 2 || (k & (k - 1)) !== 0) return null;
    for (let i = 1; i < k; i++) if (!less(z[i - 1], z[i])) return null;
    const leaves = z.map((x, i) => gapLeaf(x, z[(i + 1) % k]));
    const levels = [leaves];
    for (let row = leaves; row.length > 1;) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < row.length / 2; i++) next.push(gapNode(row[2 * i], row[2 * i + 1]));
      levels.push(next);
      row = next;
    }
    return new GapTree(z.slice(), levels);
  }

  /** M_j */
  public get root(): Uint8Array {
    return this.levels[this.levels.length - 1][0];
  }

  /** The gap proof of `eta`, or null when `eta` is one of the identifiers (paid in this segment). */
  public prove(eta: Uint8Array): Uint8Array | null {
    const k = this.z.length;
    let i = 0;
    while (i < k && less(this.z[i], eta)) i++;
    if (i < k && eq(this.z[i], eta)) return null;
    const g = i === 0 || i === k ? k - 1 : i - 1;
    const parts = [Uint8Array.of(g), this.z[g], this.z[(g + 1) % k]];
    let pos = g;
    for (const row of this.levels.slice(0, -1)) {
      parts.push(row[pos ^ 1]);
      pos >>= 1;
    }
    return concat(...parts);
  }
}

/** M derived from a gap proof for `eta` (section 10.2), or null when the proof is invalid. */
export function gapRoot(K: bigint, eta: Uint8Array, proof: Uint8Array): Uint8Array | null {
  const h = log2(K);
  if (proof.length !== 65 + 32 * h) return null;
  const i = BigInt(proof[0]);
  const l = proof.subarray(1, 33);
  const u = proof.subarray(33, 65);
  if (i >= K) return null;
  if (i < K - 1n) {
    if (!(less(l, u) && less(l, eta) && less(eta, u))) return null;
  } else if (!(less(u, l) && (less(l, eta) || less(eta, u)))) return null;
  let x = gapLeaf(l, u);
  for (let s = 0; s < h; s++) {
    const sib = proof.subarray(65 + 32 * s, 97 + 32 * s);
    x = ((Number(i) >> s) & 1) === 0 ? gapNode(x, sib) : gapNode(sib, x);
  }
  return x;
}

/** H_0 = H_E(ARCHIVE_GENESIS || D || u16(K)). */
export const genesisHead = (d: Uint8Array, K: bigint): Uint8Array => HE(TAG_ARCHIVE_GENESIS, d, u16(K));
/** H_{j+1} = H_E(ARCHIVE_STEP || D || u64(j) || H_j || M_j). */
export const nextHead = (d: Uint8Array, j: bigint, hj: Uint8Array, mj: Uint8Array): Uint8Array => HE(TAG_ARCHIVE_STEP, d, u64(j), hj, mj);

/** Redeem step 3: fold from `startHead` through j = a .. a+P-1; `BadGapProof(position)` for a refused proof. */
export function foldHistory(d: Uint8Array, K: bigint, eta: Uint8Array, a: bigint, startHead: Uint8Array, proofs: Uint8Array[]): Uint8Array {
  let x = startHead;
  proofs.forEach((pr, p) => {
    const m = gapRoot(K, eta, pr);
    if (m === null) throw new Nb2Error('BadGapProof', undefined, [String(p)]);
    x = nextHead(d, a + BigInt(p), x, m);
  });
  return x;
}

/** The redeem history: empty for P = 0, else startHead || proof_0 || ... || proof_{P-1}. */
export const encodeHistory = (startHead: Uint8Array, proofs: Uint8Array[]): Uint8Array =>
  proofs.length === 0 ? new Uint8Array() : concat(startHead, ...proofs);

/** Split a history into its start head and proofs (the vault's step 1 framing); null when the length is not admitted. */
export function splitHistory(K: bigint, history: Uint8Array): { startHead: Uint8Array; proofs: Uint8Array[] } | null {
  if (history.length === 0) return { startHead: new Uint8Array(32), proofs: [] };
  const pl = gapProofLen(K);
  if (history.length < 32 + pl || (history.length - 32) % pl !== 0) return null;
  const proofs: Uint8Array[] = [];
  for (let i = 32; i < history.length; i += pl) proofs.push(history.subarray(i, i + pl));
  return { startHead: history.subarray(0, 32), proofs };
}

/** The 128 + 32K bytes of SegmentSealed(c, H_c, H_{c+1}, z_0 || ... || z_{K-1}). */
export const segmentSealedData = (before: Uint8Array, after: Uint8Array, z: Uint8Array[]): Uint8Array =>
  concat(before, after, u256(0x60), u256(32 * z.length), ...z);

/** One verified SegmentSealed log. */
export interface Segment { index: bigint; before: Uint8Array; after: Uint8Array; z: Uint8Array[]; root: Uint8Array }

/**
 * The wallet's check of the SegmentSealed log of segment j (section 12.3): exact length, the offset and length words, strictly sorted
 * identifiers, and H_{j+1} == NextHead(D, j, headBefore, M_j) == headAfter with headBefore the expected previous head. Every failure is
 * `SegmentLog`.
 */
export function checkSegmentLog(d: Uint8Array, K: bigint, j: bigint, expectBefore: Uint8Array, data: Uint8Array): Segment {
  if (BigInt(data.length) !== 128n + 32n * K) fail('SegmentLog', `length ${data.length}`);
  if (!eq(data.subarray(64, 96), u256(0x60)) || !eq(data.subarray(96, 128), u256(32n * K))) fail('SegmentLog', 'offset or length word');
  const z: Uint8Array[] = [];
  for (let i = 0; i < Number(K); i++) z.push(data.slice(128 + 32 * i, 160 + 32 * i));
  const tree = GapTree.build(z);
  if (tree === null) fail('SegmentLog', 'identifiers not strictly sorted');
  const s: Segment = { index: j, before: data.slice(0, 32), after: data.slice(32, 64), z, root: tree!.root };
  if (!eq(s.before, expectBefore) || !eq(nextHead(d, j, s.before, s.root), s.after)) fail('SegmentLog', 'chain link');
  return s;
}

/**
 * The wallet's proof builder (section 12.3): one gap proof of `eta` per verified segment a .. e-1 (in order, contiguous) and the start
 * head H_a. `paid` when `eta` is in one of them.
 */
export function buildHistory(segs: Segment[], eta: Uint8Array, a: bigint, e: bigint, ha: Uint8Array): { history: Uint8Array; paid: bigint | null } {
  const proofs: Uint8Array[] = [];
  for (let j = a; j < e; j++) {
    const seg = segs[Number(j - a)];
    if (seg === undefined || seg.index !== j) throw new Nb2Error('SegmentLog', `segment ${j} missing or out of order`);
    const p = GapTree.build(seg.z)!.prove(eta);
    if (p === null) return { history: new Uint8Array(), paid: j };
    proofs.push(p);
  }
  return { history: encodeHistory(ha, proofs), paid: null };
}
