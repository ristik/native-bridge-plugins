/**
 * Canonical CBOR of the v2 profile (section 3), a port of bft-core `nb2ref/cbor.go`. The encoder writes shortest heads and definite
 * lengths. The decoder is a strict scanner: shortest heads, definite lengths, complete consumption, and no negative integers, floats,
 * text strings, maps or simple values other than null in any v2 structure. A native certificate (inline in an inclusion proof) is the
 * one place text strings and maps are admitted (`scanNative`); its canonical form is the certificate decoder's concern.
 */
import { concat } from '../bytes.js';
import { fail } from './errors.js';

export const MAX_CBOR_DEPTH = 16;
const MAX_CBOR_ITEMS = 1 << 20;

const MAJ_UINT = 0;
const MAJ_BYTES = 2;
const MAJ_TEXT = 3;
export const MAJ_ARRAY = 4;
const MAJ_MAP = 5;
const MAJ_TAG = 6;
const MAJ_SIMPLE = 7;

// ---- encoder ----------------------------------------------------------------------------------

export function head(major: number, n: bigint | number): Uint8Array {
  const v = BigInt(n);
  const m = major << 5;
  if (v < 24n) return Uint8Array.of(m | Number(v));
  if (v < 1n << 8n) return Uint8Array.of(m | 24, Number(v));
  if (v < 1n << 16n) return Uint8Array.of(m | 25, Number(v >> 8n), Number(v & 0xffn));
  if (v < 1n << 32n) return concat(Uint8Array.of(m | 26), be(v, 4));
  return concat(Uint8Array.of(m | 27), be(v, 8));
}

/** Fixed-width big-endian. */
export function be(v: bigint | number, width: number): Uint8Array {
  let x = BigInt(v);
  const out = new Uint8Array(width);
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new RangeError(`value does not fit ${width} bytes`);
  return out;
}

export const u256 = (v: bigint | number): Uint8Array => be(v, 32);
export const u64 = (v: bigint | number): Uint8Array => be(v, 8);
export const u16 = (v: bigint | number): Uint8Array => be(v, 2);

export const cUint = (n: bigint | number): Uint8Array => head(MAJ_UINT, n);
export const cBytes = (b: Uint8Array): Uint8Array => concat(head(MAJ_BYTES, b.length), b);
export const cTag = (tag: bigint | number, content: Uint8Array): Uint8Array => concat(head(MAJ_TAG, tag), content);
export const cArr = (...items: Uint8Array[]): Uint8Array => concat(head(MAJ_ARRAY, items.length), ...items);
export const cNull = Uint8Array.of(0xf6);
export const cNullOr = (b: Uint8Array | null): Uint8Array => (b === null ? cNull : cBytes(b));
export const ascii = (s: string): Uint8Array => new TextEncoder().encode(s);

/** The minimal unsigned big-endian bytes of a positive amount. */
export function amountBytes(v: bigint): Uint8Array {
  if (v <= 0n) throw new RangeError('an amount is positive');
  const out: number[] = [];
  for (let x = v; x > 0n; x >>= 8n) out.unshift(Number(x & 0xffn));
  return Uint8Array.from(out);
}
export const cAmount = (v: bigint): Uint8Array => cBytes(amountBytes(v));

export const beInt = (b: Uint8Array): bigint => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);

/** An SDK deadline: unset (null) or a u64 in [1, 2^64-1]. */
export type Deadline = bigint | null;
export const cDeadline = (d: Deadline): Uint8Array => (d === null ? cNull : cUint(d));

// ---- strict scanner -------------------------------------------------------------------------------

export interface Item {
  major: number;
  arg: bigint;
  start: number;
  end: number;
  data?: Uint8Array;
  kids: Item[];
  isNull: boolean;
}

class Scanner {
  public pos = 0;
  private tokens = 0;
  public constructor(private readonly b: Uint8Array, private readonly native: boolean) {}

  public head(): { major: number; arg: bigint } {
    const b = this.b;
    if (this.pos >= b.length) fail('Truncated');
    const ib = b[this.pos++];
    const major = ib >> 5;
    const ai = ib & 0x1f;
    if (ai < 24) return { major, arg: BigInt(ai) };
    if (ai > 27) fail('NonCanonical');
    const n = 1 << (ai - 24);
    if (b.length - this.pos < n) fail('Truncated');
    let arg = 0n;
    for (let i = 0; i < n; i++) arg = (arg << 8n) | BigInt(b[this.pos + i]);
    this.pos += n;
    if ((ai === 24 && arg < 24n) || (ai === 25 && arg <= 0xffn) || (ai === 26 && arg <= 0xffffn) || (ai === 27 && arg <= 0xffffffffn)) {
      fail('NonCanonical');
    }
    return { major, arg };
  }

  public item(depth: number): Item {
    const b = this.b;
    const start = this.pos;
    if (++this.tokens > MAX_CBOR_ITEMS) fail('InputTooLarge');
    if (this.pos < b.length) {
      const mj = b[this.pos] >> 5;
      if (mj === 1 || (!this.native && (mj === MAJ_TEXT || mj === MAJ_MAP)) || (mj === MAJ_SIMPLE && b[this.pos] !== 0xf6)) fail('NonCanonical');
    }
    const { major, arg } = this.head();
    const it: Item = { major, arg, start, end: 0, kids: [], isNull: false };
    const rest = BigInt(b.length - this.pos);
    switch (major) {
      case MAJ_UINT:
        break;
      case MAJ_BYTES:
      case MAJ_TEXT:
        if (arg > rest) fail('Truncated');
        it.data = b.subarray(this.pos, this.pos + Number(arg));
        this.pos += Number(arg);
        break;
      case MAJ_ARRAY:
      case MAJ_TAG:
      case MAJ_MAP: {
        if (depth + 1 > MAX_CBOR_DEPTH) fail('InputTooLarge');
        let n = arg;
        if (major === MAJ_TAG) n = 1n;
        else if (arg > rest) fail('Truncated');
        else if (major === MAJ_MAP) {
          n = 2n * arg;
          if (n > rest) fail('Truncated');
        }
        for (let i = 0n; i < n; i++) it.kids.push(this.item(depth + 1));
        break;
      }
      case MAJ_SIMPLE:
        it.isNull = true;
        break;
      default:
        fail('NonCanonical');
    }
    it.end = this.pos;
    return it;
  }
}

function scanWith(b: Uint8Array, native: boolean): Item {
  const s = new Scanner(b, native);
  const it = s.item(0);
  if (s.pos !== b.length) fail('Trailing');
  return it;
}

/** Exactly one strict item spanning all of `b`. */
export const scanOne = (b: Uint8Array): Item => scanWith(b, false);
/** One item that may embed a native certificate (text strings and maps admitted). */
export const scanNative = (b: Uint8Array): Item => scanWith(b, true);

/** The tag number at the head of `b`, without scanning further; null when it is not a well-formed tag head. */
export function headTag(b: Uint8Array): bigint | null {
  if (b.length === 0) return null;
  try {
    const s = new Scanner(b, false);
    const { major, arg } = s.head();
    return major === MAJ_TAG ? arg : null;
  } catch {
    return null;
  }
}

// ---- item accessors (the Go reference's methods) -----------------------------------------------------

export const raw = (b: Uint8Array, it: Item): Uint8Array => b.subarray(it.start, it.end);
export const isUint = (it: Item): boolean => it.major === MAJ_UINT;
export const isBytes = (it: Item): boolean => it.major === MAJ_BYTES;
export const isArray = (it: Item): boolean => it.major === MAJ_ARRAY;
export const isTag = (it: Item): boolean => it.major === MAJ_TAG;

export function array(it: Item, n: number): Item[] {
  if (it.major !== MAJ_ARRAY || it.kids.length !== n) fail('Shape');
  return it.kids;
}

export function bytesN(it: Item, n: number): Uint8Array {
  if (it.major !== MAJ_BYTES) fail('Shape');
  if (it.data!.length !== n) fail('Length');
  return it.data!;
}

export function bstr(it: Item): Uint8Array {
  if (it.major !== MAJ_BYTES) fail('Shape');
  return it.data!;
}

export function tagContent(it: Item, tag: bigint | number): Item {
  if (it.major !== MAJ_TAG) fail('Shape');
  if (it.arg !== BigInt(tag)) fail('Tag');
  return it.kids[0];
}

export function uintIn(it: Item, lo: bigint, hi: bigint): bigint {
  if (it.major !== MAJ_UINT) fail('Shape');
  if (it.arg < lo || it.arg > hi) fail('IntRange');
  return it.arg;
}

export function version(it: Item, want: bigint | number): void {
  if (it.major !== MAJ_UINT) fail('Shape');
  if (it.arg !== BigInt(want)) fail('Version');
}

export function literal(it: Item, s: string): void {
  const want = ascii(s);
  if (it.major !== MAJ_BYTES || it.data!.length !== want.length || it.data!.some((x, i) => x !== want[i])) fail('Shape');
}

/** An Amount: a minimal positive big-endian byte string of 1 to 32 bytes. */
export function amount(it: Item): bigint {
  if (it.major !== MAJ_BYTES) fail('Shape');
  const d = it.data!;
  if (d.length === 0) fail('IntRange');
  if (d.length > 32) fail('Length');
  if (d[0] === 0) fail('NonCanonical');
  return beInt(d);
}

export const MAX_U64 = (1n << 64n) - 1n;

export function deadline(it: Item): Deadline {
  if (it.isNull) return null;
  return uintIn(it, 1n, MAX_U64);
}

export function nullableBytes(it: Item): Uint8Array | null {
  if (it.isNull) return null;
  return bstr(it);
}
