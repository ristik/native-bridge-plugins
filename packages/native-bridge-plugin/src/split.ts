/**
 * Split primitives of the lineage relation (protocol 6, bft-core docs/design/bridge-split-lineage-spec.md, Go `bridgeprofile/split.go`).
 * The byte formats are the SDK's (state-transition-sdk `payment/{manifest,commitment,justification}` and the radix sum tree); nothing
 * here is bridge-specific except the single-asset restriction.
 */
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';

import { concat, eq } from './bytes.js';
import { fail } from './errors.js';
import { MAX_SUM_PROOF_STEPS, TAG_SPLIT_JUSTIFICATION, TAG_SPLIT_MANIFEST } from './limits.js';
import { H, arr, bs, u } from './profile.js';
import { arrayOf, bytesN, scanCounted, scanOne, tagContent, uintMax, type Item } from './scan.js';

const SUM_LEAF_PREFIX = 0x10;
const SUM_NODE_PREFIX = 0x11;
const SPLIT_OUTPUT_DOMAIN = new TextEncoder().encode('UNICITY_SPLIT_OUTPUT');
const TWO_256 = 1n << 256n;

/** The protocol amount domain `1 <= v < 2^256`. */
const validAmount = (v: bigint): boolean => v > 0n && v < TWO_256;

const u256 = (v: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  for (let i = 31, x = v; i >= 0; i--, x >>= 8n) out[i] = Number(x & 0xffn);
  return out;
};

/** Minimal positive big-endian bytes (the CBOR amount of a sum step). */
export const amountBytes = (v: bigint): Uint8Array => {
  const out: number[] = [];
  for (let x = v; x > 0n; x >>= 8n) out.unshift(Number(x & 0xffn));
  return Uint8Array.from(out);
};

export const beToBigint = (b: Uint8Array): bigint => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);

/** Bit `i` of a 256-bit key, MSB first (the SDK's one radix bit order). */
const keyBit = (key: Uint8Array, i: number): boolean => ((key[i >> 3] >> (7 - (i & 7))) & 1) === 1;

/** `SHA-256(0x10 || key || data || u256(value))`, or null outside the amount domain. */
export function sumLeafHash(key: Uint8Array, data: Uint8Array, value: bigint): Uint8Array | null {
  return validAmount(value) ? H(concat(Uint8Array.of(SUM_LEAF_PREFIX), key, data, u256(value))) : null;
}

/** `SHA-256(0x11 || depth || hL || u256(sL) || hR || u256(sR))` and the checked 256-bit sum, or null. */
export function sumNodeHash(depth: number, hl: Uint8Array, sl: bigint, hr: Uint8Array, sr: bigint): { hash: Uint8Array; sum: bigint } | null {
  if (!validAmount(sl) || !validAmount(sr)) return null;
  const sum = sl + sr;
  if (sum >= TWO_256) return null;
  return { hash: H(concat(Uint8Array.of(SUM_NODE_PREFIX, depth), hl, u256(sl), hr, u256(sr))), sum };
}

/** One sibling entry of a leaf-to-root path: the parent's bifurcation depth, the sibling subtree hash and its positive sum. */
export interface SumStep {
  depth: number;
  hash: Uint8Array;
  sum: bigint;
}

/** The exact CBOR `[[depth, b(hash), b(sum)], ...]`. */
export const sumProofBytes = (p: readonly SumStep[]): Uint8Array =>
  arr(...p.map((s) => arr(u(s.depth), bs(s.hash), bs(amountBytes(s.sum)))));

/** Strictly decode an allocation proof item (bft-core `decodeSumProof`). */
export function decodeSumProofItem(it: Item): SumStep[] {
  if (it.kind !== 'array') return fail('ErrShape');
  if (it.kids.length > MAX_SUM_PROOF_STEPS) fail('ErrSplitProofShape');
  const out: SumStep[] = [];
  let prev = 256;
  for (const k of it.kids) {
    const step = arrayOf(k, 3) ?? fail('ErrShape');
    let d: number;
    try {
      d = Number(uintMax(step[0], 255n));
    } catch {
      return fail('ErrSplitProofShape');
    }
    if (d >= prev) fail('ErrSplitProofShape');
    prev = d;
    const hash = bytesN(step[1], 32);
    // a minimal positive big-endian amount of at most 32 bytes
    const s = step[2];
    if (s.kind !== 'bytes' || s.data.length === 0 || s.data.length > 32 || s.data[0] === 0) fail('ErrSplitProofShape');
    out.push({ depth: d, hash, sum: beToBigint((s as { data: Uint8Array }).data) });
  }
  return out;
}

/**
 * Reconstruct the root from the leaf upward; the reconstructed root sum iff the root hash equals `root`. The caller compares that
 * sum with the authenticated source amount: the root hash alone does not conserve value.
 */
export function verifySumProof(p: readonly SumStep[], key: Uint8Array, data: Uint8Array, value: bigint, root: Uint8Array): bigint | null {
  if (p.length > MAX_SUM_PROOF_STEPS) return null;
  const leaf = sumLeafHash(key, data, value);
  if (leaf === null) return null;
  let hash: Uint8Array = leaf;
  let sum = value;
  let prev = 256;
  for (const s of p) {
    if (s.depth >= prev || !validAmount(s.sum)) return null;
    const n = keyBit(key, s.depth) ? sumNodeHash(s.depth, s.hash, s.sum, hash, sum) : sumNodeHash(s.depth, hash, sum, s.hash, s.sum);
    if (n === null) return null;
    hash = n.hash;
    sum = n.sum;
    prev = s.depth;
  }
  return eq(hash, root) ? sum : null;
}

/** The manifest `tag(39046,[b(root)])`: the bridge admits one asset, so exactly one root. */
export const splitManifestBytes = (root: Uint8Array): Uint8Array => C.encodeTag(TAG_SPLIT_MANIFEST, arr(bs(root)));

/** Strictly decode a burn transfer's data as a single-root manifest; returns the root. */
export function decodeSplitManifest(b: Uint8Array): Uint8Array {
  try {
    const c = arrayOf(tagContent(scanOne(b), TAG_SPLIT_MANIFEST), 1);
    if (c === null) return fail('ErrSplitManifest');
    return bytesN(c[0], 32);
  } catch {
    return fail('ErrSplitManifest');
  }
}

/**
 * `SHA-256(CBOR([b("UNICITY_SPLIT_OUTPUT"), b(sourceId), network, b(encodedRecipient), b(salt), b(childId), b(type),
 * b(exactPaymentBytes)]))`: the child mint without its justification.
 */
export const splitOutputCommitment = (
  sourceId: Uint8Array, network: number, recipient: Uint8Array, salt: Uint8Array, childId: Uint8Array, ty: Uint8Array, data: Uint8Array,
): Uint8Array => H(arr(bs(SPLIT_OUTPUT_DOMAIN), bs(sourceId), u(network), bs(recipient), bs(salt), bs(childId), bs(ty), bs(data)));

/**
 * The decoded split mint reason `tag(39044,[token,[proof]])`: the exact burned source token bytes (an inline item, never re-encoded),
 * its one allocation proof (one asset) and the item count of the justification's own scan, which the composition charges.
 */
export interface SplitJustification {
  token: Uint8Array;
  proof: SumStep[];
  items: number;
}

export const splitJustificationBytes = (token: Uint8Array, proof: readonly SumStep[]): Uint8Array =>
  C.encodeTag(TAG_SPLIT_JUSTIFICATION, arr(token, arr(sumProofBytes(proof))));

/** The tag number of a justification without scanning it: the first head must be a tag. */
export function justificationTag(j: Uint8Array | null): bigint | null {
  if (j === null || j.length === 0) return null;
  const ib = j[0];
  if (ib >> 5 !== 6) return null;
  const ai = ib & 0x1f;
  if (ai < 24) return BigInt(ai);
  if (ai > 27) return null;
  const n = 1 << (ai - 24);
  if (j.length - 1 < n) return null;
  let arg = 0n;
  for (let i = 0; i < n; i++) arg = (arg << 8n) | BigInt(j[1 + i]);
  if ((ai === 24 && arg < 24n) || (ai === 25 && arg <= 0xffn) || (ai === 26 && arg <= 0xffffn) || (ai === 27 && arg <= 0xffffffffn)) return null;
  return arg;
}

/** Strictly decode a split mint reason. The burned token is decoded strictly by the caller. */
export function decodeSplitJustification(j: Uint8Array): SplitJustification {
  let root: Item;
  let tokens: number;
  try {
    ({ root, tokens } = scanCounted(j, Number.MAX_SAFE_INTEGER, true));
  } catch {
    return fail('ErrSplitJustif');
  }
  let c: Item[] | null;
  try {
    c = arrayOf(tagContent(root, TAG_SPLIT_JUSTIFICATION), 2);
  } catch {
    return fail('ErrSplitJustif');
  }
  if (c === null || c[0].kind !== 'tag' || c[1].kind !== 'array') return fail('ErrSplitJustif');
  const proofs = (c[1] as { kids: Item[] }).kids;
  if (proofs.length !== 1) fail('ErrSplitProofCount');
  return { token: j.subarray(c[0].start, c[0].end), proof: decodeSumProofItem(proofs[0]), items: tokens };
}
