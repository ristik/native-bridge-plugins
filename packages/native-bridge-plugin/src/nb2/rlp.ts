/**
 * A strict, minimal RLP reader and the encoder (bft-core `nb2ref/rlp.go`): every non-minimal length, a single byte below 0x80
 * wrapped as a string, trailing bytes and nesting over 16 reject. Callers report failures under their own rule.
 */
import { concat } from '../bytes.js';

export const MAX_RLP_DEPTH = 16;

export interface RlpItem {
  list: boolean;
  str: Uint8Array;
  kids: RlpItem[];
  raw: Uint8Array;
}

export class RlpError extends Error {}
const bad = (): never => {
  throw new RlpError('nb2: malformed RLP');
};

function readLen(b: Uint8Array, ll: number): number {
  if (ll > 4 || b.length < ll || b[0] === 0) bad();
  let n = 0;
  for (let i = 0; i < ll; i++) n = n * 256 + b[i];
  return n;
}

function read(b: Uint8Array, depth: number): [RlpItem, number] {
  if (b.length === 0 || depth > MAX_RLP_DEPTH) bad();
  const p = b[0];
  const empty = new Uint8Array();
  if (p < 0x80) return [{ list: false, str: b.subarray(0, 1), kids: [], raw: b.subarray(0, 1) }, 1];
  if (p <= 0xb7) {
    const n = p - 0x80;
    if (b.length < 1 + n) bad();
    if (n === 1 && b[1] < 0x80) bad();
    return [{ list: false, str: b.subarray(1, 1 + n), kids: [], raw: b.subarray(0, 1 + n) }, 1 + n];
  }
  if (p <= 0xbf) {
    const ll = p - 0xb7;
    const n = readLen(b.subarray(1), ll);
    if (n < 56 || n > b.length - 1 - ll) bad();
    return [{ list: false, str: b.subarray(1 + ll, 1 + ll + n), kids: [], raw: b.subarray(0, 1 + ll + n) }, 1 + ll + n];
  }
  let hdr: number;
  let n: number;
  if (p <= 0xf7) {
    hdr = 1;
    n = p - 0xc0;
  } else {
    const ll = p - 0xf7;
    n = readLen(b.subarray(1), ll);
    if (n < 56) bad();
    hdr = 1 + ll;
  }
  if (n > b.length - hdr) bad();
  const it: RlpItem = { list: true, str: empty, kids: [], raw: b.subarray(0, hdr + n) };
  for (let off = hdr; off < hdr + n;) {
    const [kid, used] = read(b.subarray(off, hdr + n), depth + 1);
    it.kids.push(kid);
    off += used;
  }
  return [it, hdr + n];
}

/** Exactly one item spanning all of `b`; throws {@link RlpError}. */
export function rlpDecode(b: Uint8Array): RlpItem {
  const [it, n] = read(b, 0);
  if (n !== b.length) bad();
  return it;
}

/** A canonical RLP integer string: no leading zero byte, at most `max` bytes (the empty string is zero). */
export function rlpUint(it: RlpItem, max = 32): bigint | null {
  if (it.list || it.str.length > max || (it.str.length > 0 && it.str[0] === 0)) return null;
  return it.str.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
}

// ---- encoder ----

function lenBytes(n: number): Uint8Array {
  const out: number[] = [];
  for (let x = n; x > 0; x = Math.floor(x / 256)) out.unshift(x & 0xff);
  return Uint8Array.from(out);
}

export function rlpBytes(b: Uint8Array): Uint8Array {
  if (b.length === 1 && b[0] < 0x80) return b.slice();
  if (b.length < 56) return concat(Uint8Array.of(0x80 + b.length), b);
  const l = lenBytes(b.length);
  return concat(Uint8Array.of(0xb7 + l.length), l, b);
}

export function rlpList(items: Uint8Array[]): Uint8Array {
  const body = concat(...items);
  if (body.length < 56) return concat(Uint8Array.of(0xc0 + body.length), body);
  const l = lenBytes(body.length);
  return concat(Uint8Array.of(0xf7 + l.length), l, body);
}

/** The minimal big-endian bytes of an unsigned integer (empty for zero). */
export function uintBytes(v: bigint): Uint8Array {
  const out: number[] = [];
  for (let x = v; x > 0n; x >>= 8n) out.unshift(Number(x & 0xffn));
  return Uint8Array.from(out);
}
export const rlpUintEnc = (v: bigint | number): Uint8Array => rlpBytes(uintBytes(BigInt(v)));

/** RLP(i) for an unsigned index: the receipt-trie key. */
export const rlpIndexKey = (i: bigint | number): Uint8Array => rlpUintEnc(i);
