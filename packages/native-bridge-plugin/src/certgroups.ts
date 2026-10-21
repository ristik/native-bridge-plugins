/**
 * The bridge's side of `CERT_BATCH_V2` (`protocol/interop.md` "Direct-call gas gate"): the structural scan of every claim's
 * UnicityCertificate and the canonical first-occurrence grouping the batch price is computed from. It mirrors the contract's
 * `CertGroups.sol` and the oracle's `b1ref.Group`; it does no cryptography.
 *
 *   K claim occurrences, C request bytes, E distinct declared epochs, S distinct complete seals (the whole tagged CBOR slice,
 *   signature map included), Q the sum of their signature counts, A distinct claims (the whole packed claim: expected tuple and
 *   full UC bytes), P the shard siblings plus Unicity-tree steps of the distinct claims.
 *
 * Identity is exact bytes. A claim's shard-tree depth comes from its own native shard ID, never from a policy. `items` counts the
 * CBOR items of every UC occurrence before deduplication; there is no shared item budget (owner section 36): each UC is bounded by
 * its own native scan (`MAX_CBOR_ITEMS`) and every item is charged. The anchor table is grouped under the composition's limits
 * (`b1ref.Composed`): up to the u16 wire count of claims, with no request-byte, raw-step or signature aggregate (bft-core
 * briefs/dev4-b7-native-compose-spec.md section 7); each UC keeps its own bounds.
 */
import { concat, eq, toHex } from './bytes.js';
import { fail } from './errors.js';
import {
  MAX_ANCHORS, MAX_CBOR_ITEMS, MAX_CBOR_DEPTH, MAX_SIGS_PER_SEAL, MAX_UNICITY_STEPS,
} from './limits.js';
import { shardDepth } from './profile.js';

/** The fields of a batch claim (an `Anchor` without the opening). */
export interface Claim {
  partition: number;
  shard: Uint8Array;
  shardConfHash: Uint8Array;
  expectedStateRoot: Uint8Array;
  expectedIRHash: Uint8Array;
  uc: Uint8Array;
}

/** The most claims one composed batch carries (`K`): the u16 wire count. */
export const MAX_CLAIMS = MAX_ANCHORS;
const CLAIM_FIXED = 106; // partition 4 + shardLen 2 + three hashes 96 + ucLen 4
// ---- the frozen price schedule ----
const SCAN_BASE = 60_000;
const SCAN_PER_BYTE = 16;
const SCAN_PER_PAIR = 500;
const COMMON_READS = 1_100;
const PER_EPOCH = 29_900;
const PER_SIGNATURE = 6_000;
const PER_CLAIM = 2_000;
const PER_STEP = 250;

const TAG_UC = 39001n;
const TAG_SHARD_TREE = 39003n;
const TAG_UNICITY_TREE = 39004n;
const TAG_SEAL = 39005n;

export interface Counts {
  k: number;
  c: number;
  e: number;
  s: number;
  q: number;
  a: number;
  p: number;
  /** CBOR items over all UC occurrences, before deduplication. */
  items: number;
}

/** `G_scan(C, K) = 60000 + 16*C + 500*K*(K-1)`. */
export const scanGas = (c: number, k: number): number => SCAN_BASE + SCAN_PER_BYTE * c + SCAN_PER_PAIR * k * (k - 1);

/** `G_batch`: what the native call is forwarded and charges. */
export const batchGas = (n: Counts): number =>
  scanGas(n.c, n.k) + COMMON_READS + PER_EPOCH * n.e + PER_SIGNATURE * n.q + PER_CLAIM * n.a + PER_STEP * n.p;

interface Budget {
  limit: number;
  items: number;
  steps: number;
}

interface Head { major: number; arg: bigint; next: number }

/** One strict head: shortest form, definite length only. */
function head(b: Uint8Array, pos: number): Head {
  if (pos >= b.length) return fail('ErrTruncated');
  const ib = b[pos];
  const major = ib >> 5;
  const ai = ib & 0x1f;
  if (ai < 24) return { major, arg: BigInt(ai), next: pos + 1 };
  if (ai > 27) return fail(ai === 31 ? 'ErrForbiddenCBOR' : 'ErrNonCanonical');
  const n = 1 << (ai - 24);
  if (b.length - pos - 1 < n) return fail('ErrTruncated');
  let arg = 0n;
  for (let i = 0; i < n; i++) arg = (arg << 8n) | BigInt(b[pos + 1 + i]);
  if ((ai === 24 && arg < 24n) || (ai === 25 && arg <= 0xffn) || (ai === 26 && arg <= 0xffffn) || (ai === 27 && arg <= 0xffffffffn)) fail('ErrNonCanonical');
  return { major, arg, next: pos + 1 + n };
}

function item(bud: Budget): void {
  if (++bud.items > bud.limit) fail('ErrTooManyItems');
}

/** A declared container whose immediate children alone exceed what is left is refused before any of them is walked. */
function fits(bud: Budget, children: bigint): void {
  if (children > BigInt(bud.limit - bud.items)) fail('ErrTooManyItems');
}

/** Skip one complete item; `base` containers already enclose it (the bound counts from the UC root). */
function skip(b: Uint8Array, start: number, bud: Budget, base: number): number {
  let pos = start;
  const left: number[] = [];
  let depth = base;
  for (;;) {
    const h = head(b, pos);
    item(bud);
    pos = h.next;
    let kids = 0n;
    if (h.major === 2 || h.major === 3) {
      if (h.arg > BigInt(b.length - pos)) fail('ErrTruncated');
      pos += Number(h.arg);
    } else if (h.major === 4 || h.major === 5) {
      if (h.arg > BigInt(b.length)) fail('ErrTruncated');
      kids = h.major === 5 ? 2n * h.arg : h.arg;
      fits(bud, kids);
    } else if (h.major === 6) {
      kids = 1n;
    }
    if (kids !== 0n) {
      if (++depth > MAX_CBOR_DEPTH) fail('ErrTooManyItems');
      left[depth] = Number(kids);
      continue;
    }
    while (depth !== base) {
      if (--left[depth] !== 0) break;
      depth--;
    }
    if (depth === base) return pos;
  }
}

function skipN(b: Uint8Array, pos: number, n: number, bud: Budget, base: number): number {
  for (let i = 0; i < n; i++) pos = skip(b, pos, bud, base);
  return pos;
}

/** `tag(t, array(n))`; returns the position of the first element. Counts the two heads as items. */
function tagged(b: Uint8Array, pos: number, tag: bigint, n: bigint, bud: Budget): number {
  const t = head(b, pos);
  if (t.major !== 6 || t.arg !== tag) fail('ErrTag');
  const a = head(b, t.next);
  if (a.major !== 4 || a.arg !== n) fail('ErrShape');
  item(bud);
  item(bud);
  return a.next;
}

/** Element count of an array (major 4) or map (major 5) at `pos`; null is empty. */
function count(b: Uint8Array, pos: number, want: number, bud: Budget): { n: number; next: number } {
  item(bud);
  if (pos < b.length && b[pos] === 0xf6) return { n: 0, next: pos + 1 };
  const h = head(b, pos);
  if (h.major !== want || h.arg > BigInt(b.length)) fail('ErrShape');
  fits(bud, want === 5 ? 2n * h.arg : h.arg);
  return { n: Number(h.arg), next: h.next };
}

interface Occurrence {
  epoch: bigint;
  sealStart: number;
  sealLen: number;
  sigs: number;
  steps: number;
}

/** `tag(39001,[1, IR, h, h, tag(39003,[1, shard, [sib*]]), tag(39004,[1, partition, [step*]]), tag(39005,[1, ..., sigs])])`, no trailing byte. */
function scan(a: Claim, bud: Budget): Occurrence {
  const uc = a.uc;
  const d = shardDepth(a.shard);
  let pos = tagged(uc, 0, TAG_UC, 7n, bud);
  for (let i = 0; i < 4; i++) pos = skip(uc, pos, bud, 2); // version, input record, technical hash, shard configuration hash
  pos = tagged(uc, pos, TAG_SHARD_TREE, 3n, bud);
  pos = skip(uc, pos, bud, 4); // version
  const shard = head(uc, pos);
  if (shard.major !== 2 || shard.arg > BigInt(uc.length - shard.next) || !eq(uc.subarray(shard.next, shard.next + Number(shard.arg)), a.shard)) fail('ErrShardMismatch');
  item(bud);
  pos = shard.next + Number(shard.arg);
  const sib = count(uc, pos, 4, bud);
  if (sib.n !== d) fail('ErrShardMismatch');
  pos = skipN(uc, sib.next, sib.n, bud, 5);
  pos = tagged(uc, pos, TAG_UNICITY_TREE, 3n, bud);
  pos = skip(uc, pos, bud, 4); // version
  pos = skip(uc, pos, bud, 4); // partition
  const steps = count(uc, pos, 4, bud);
  if (steps.n > MAX_UNICITY_STEPS) fail('ErrTooManyItems');
  pos = skipN(uc, steps.next, steps.n, bud, 5);
  const o: Occurrence = { epoch: 0n, sealStart: pos, sealLen: 0, sigs: 0, steps: sib.n + steps.n };
  bud.steps += o.steps;
  pos = tagged(uc, pos, TAG_SEAL, 8n, bud);
  pos = skip(uc, pos, bud, 4); // version
  pos = skip(uc, pos, bud, 4); // network
  pos = skip(uc, pos, bud, 4); // root round
  const ep = head(uc, pos);
  if (ep.major !== 0 || ep.arg > 0xffff_ffff_ffff_ffffn) fail('ErrShape');
  item(bud);
  o.epoch = ep.arg;
  pos = ep.next;
  pos = skip(uc, pos, bud, 4); // timestamp
  pos = skip(uc, pos, bud, 4); // previous hash
  pos = skip(uc, pos, bud, 4); // hash
  const sigs = count(uc, pos, 5, bud);
  if (sigs.n > MAX_SIGS_PER_SEAL) fail('ErrTooManyItems');
  o.sigs = sigs.n;
  pos = skipN(uc, sigs.next, 2 * sigs.n, bud, 5);
  if (pos !== uc.length) fail('ErrShape');
  o.sealLen = pos - o.sealStart;
  return o;
}

/** The CBOR item occurrences of one complete canonical object (`J` contribution), refused as soon as the next item would cross `left`. */
export function countItems(b: Uint8Array, left: number): number {
  const bud: Budget = { limit: left, items: 0, steps: 0 };
  const end = skip(b, 0, bud, 0);
  if (end !== b.length) fail('ErrTrailing');
  return bud.items;
}

const claimKey = (a: Claim): string =>
  [a.partition, toHex(a.shard), toHex(a.shardConfHash), toHex(a.expectedStateRoot), toHex(a.expectedIRHash), toHex(a.uc)].join('|');

/** Scan and group the claims of one batch. Each UC occurrence is scanned within its own `MAX_CBOR_ITEMS`. */
export function measure(claims: readonly Claim[]): Counts {
  const k = claims.length;
  if (k === 0 || k > MAX_CLAIMS) fail('ErrTooManyPaths');
  const n: Counts = { k, c: 4, e: 0, s: 0, q: 0, a: 0, p: 0, items: 0 };
  const bud: Budget = { limit: 0, items: 0, steps: 0 };
  const epochs = new Set<string>();
  const seals = new Set<string>();
  const seen = new Set<string>();
  for (const a of claims) {
    n.c += CLAIM_FIXED + a.shard.length + a.uc.length;
    bud.limit = bud.items + MAX_CBOR_ITEMS;
    const o = scan(a, bud);
    if (!epochs.has(o.epoch.toString())) { epochs.add(o.epoch.toString()); n.e++; }
    const seal = toHex(a.uc.subarray(o.sealStart, o.sealStart + o.sealLen));
    if (!seals.has(seal)) { seals.add(seal); n.s++; n.q += o.sigs; }
    const key = claimKey(a);
    if (!seen.has(key)) { seen.add(key); n.a++; n.p += o.steps; }
  }
  n.items = bud.items;
  return n;
}

/** The `CERT_BATCH_V2` request: `version 2 | flags 0 | K:u16 | Claim[K]`, each `partition:u32 | shardLen:u16 | shard | three hashes | ucLen:u32 | uc`. */
export function batchRequest(claims: readonly Claim[]): Uint8Array {
  if (claims.length === 0 || claims.length > MAX_CLAIMS) fail('ErrTooManyPaths');
  const u32 = (v: number): Uint8Array => Uint8Array.of(v >>> 24, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  const u16 = (v: number): Uint8Array => Uint8Array.of(v >>> 8, v & 0xff);
  return concat(
    Uint8Array.of(2, 0), u16(claims.length),
    ...claims.map((a) => concat(u32(a.partition), u16(a.shard.length), a.shard, a.shardConfHash, a.expectedStateRoot, a.expectedIRHash, u32(a.uc.length), a.uc)),
  );
}
