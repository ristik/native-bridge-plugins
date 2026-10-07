import { concat } from './bytes.js';
import { fail } from './errors.js';
import { MAX_RLP_DEPTH } from './limits.js';

/** A decoded RLP item: a byte string or a list, with its raw encoding. */
export type Rlp = { kind: 'bytes'; data: Uint8Array; raw: Uint8Array } | { kind: 'list'; items: Rlp[]; raw: Uint8Array };

function beLen(b: Uint8Array): number {
  if (b.length === 0 || b[0] === 0 || b.length > 4) return fail('ErrRlpMalformed');
  return b.reduce((a, x) => a * 256 + x, 0);
}

function item(b: Uint8Array, depth: number): { it: Rlp; used: number } {
  if (depth > MAX_RLP_DEPTH || b.length === 0) fail('ErrRlpMalformed');
  const p = b[0];
  let isList: boolean;
  let head: number;
  let len: number;
  if (p < 0x80) return { it: { kind: 'bytes', data: b.subarray(0, 1), raw: b.subarray(0, 1) }, used: 1 };
  if (p <= 0xb7) {
    isList = false;
    head = 1;
    len = p - 0x80;
  } else if (p <= 0xbf || p >= 0xf8) {
    const n = p >= 0xf8 ? p - 0xf7 : p - 0xb7;
    if (b.length < 1 + n) fail('ErrRlpMalformed');
    len = beLen(b.subarray(1, 1 + n));
    if (len < 56) fail('ErrRlpMalformed');
    isList = p >= 0xf8;
    head = 1 + n;
  } else {
    isList = true;
    head = 1;
    len = p - 0xc0;
  }
  const end = head + len;
  if (end > b.length) fail('ErrRlpMalformed');
  const body = b.subarray(head, end);
  if (!isList) {
    if (len === 1 && body[0] < 0x80) fail('ErrRlpMalformed');
    return { it: { kind: 'bytes', data: body, raw: b.subarray(0, end) }, used: end };
  }
  const items: Rlp[] = [];
  let pos = 0;
  while (pos < body.length) {
    const r = item(body.subarray(pos), depth + 1);
    items.push(r.it);
    pos += r.used;
  }
  return { it: { kind: 'list', items, raw: b.subarray(0, end) }, used: end };
}

/** Decode exactly one canonical item spanning all of `b`. */
export function decode(b: Uint8Array): Rlp {
  const { it, used } = item(b, 0);
  if (used !== b.length) fail('ErrRlpMalformed');
  return it;
}

export const bytesOf = (r: Rlp): Uint8Array => (r.kind === 'bytes' ? r.data : fail('ErrRlpMalformed'));
export const listOf = (r: Rlp): Rlp[] => (r.kind === 'list' ? r.items : fail('ErrRlpMalformed'));

/** A canonical unsigned integer of at most 8 bytes. */
export function u64Of(r: Rlp): bigint {
  const b = bytesOf(r);
  if (b.length > 8 || (b.length > 0 && b[0] === 0)) fail('ErrRlpMalformed');
  return b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
}

function head(base: number, len: number): Uint8Array {
  if (len < 56) return new Uint8Array([base + len]);
  const lb: number[] = [];
  for (let n = len; n > 0; n = Math.floor(n / 256)) lb.unshift(n % 256);
  return new Uint8Array([base + 55 + lb.length, ...lb]);
}

export function encodeBytes(s: Uint8Array): Uint8Array {
  if (s.length === 1 && s[0] < 0x80) return s.slice();
  return concat(head(0x80, s.length), s);
}

export function encodeList(items: Uint8Array[]): Uint8Array {
  const body = concat(...items);
  return concat(head(0xc0, body.length), body);
}

export function encodeU64(v: bigint): Uint8Array {
  const out: number[] = [];
  for (let x = v; x > 0n; x >>= 8n) out.unshift(Number(x & 0xffn));
  return encodeBytes(new Uint8Array(out));
}
