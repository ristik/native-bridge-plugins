import { fail } from './errors.js';
import { MAX_AMOUNT_BYTES, MAX_CBOR_DEPTH, MAX_CBOR_ITEMS } from './limits.js';

/** A scanned CBOR item of the profile subset, with its byte span. */
export type Item =
  | { kind: 'uint'; value: bigint; start: number; end: number }
  | { kind: 'bytes'; data: Uint8Array; start: number; end: number }
  | { kind: 'array'; kids: Item[]; start: number; end: number }
  | { kind: 'tag'; tag: bigint; content: Item; start: number; end: number }
  | { kind: 'null'; start: number; end: number };

function readHead(b: Uint8Array, p: { pos: number }): { major: number; arg: bigint } {
  if (p.pos >= b.length) fail('ErrTruncated');
  const ib = b[p.pos++];
  const major = ib >> 5;
  const ai = ib & 0x1f;
  if (ai < 24) return { major, arg: BigInt(ai) };
  if (ai > 27) return fail(ai === 31 ? 'ErrForbiddenCBOR' : 'ErrNonCanonical');
  const n = 1 << (ai - 24);
  if (b.length - p.pos < n) fail('ErrTruncated');
  let arg = 0n;
  for (let i = 0; i < n; i++) arg = (arg << 8n) | BigInt(b[p.pos + i]);
  p.pos += n;
  if ((ai === 24 && arg < 24n) || (ai === 25 && arg <= 0xffn) || (ai === 26 && arg <= 0xffffn) || (ai === 27 && arg <= 0xffffffffn)) {
    fail('ErrNonCanonical');
  }
  return { major, arg };
}

/**
 * Strict scanner: shortest-form heads, definite lengths; text strings, maps, floats and every
 * simple value other than null are forbidden.
 */
export function scanOne(b: Uint8Array): Item {
  const p = { pos: 0 };
  let tokens = 0;
  const item = (depth: number): Item => {
    const start = p.pos;
    if (++tokens > MAX_CBOR_ITEMS) fail('ErrTooManyItems');
    if (p.pos < b.length) {
      const mj = b[p.pos] >> 5;
      if (mj === 3 || mj === 5 || (mj === 7 && b[p.pos] !== 0xf6)) fail('ErrForbiddenCBOR');
    }
    const { major, arg } = readHead(b, p);
    const rest = BigInt(b.length - p.pos);
    switch (major) {
      case 0:
        return { kind: 'uint', value: arg, start, end: p.pos };
      case 2: {
        if (arg > rest) fail('ErrTruncated');
        const n = Number(arg);
        const data = b.subarray(p.pos, p.pos + n);
        p.pos += n;
        return { kind: 'bytes', data, start, end: p.pos };
      }
      case 4: {
        if (depth + 1 > MAX_CBOR_DEPTH) fail('ErrTooDeep');
        if (arg > rest) fail('ErrTruncated');
        const kids: Item[] = [];
        for (let i = 0n; i < arg; i++) kids.push(item(depth + 1));
        return { kind: 'array', kids, start, end: p.pos };
      }
      case 6:
        if (depth + 1 > MAX_CBOR_DEPTH) fail('ErrTooDeep');
        return { kind: 'tag', tag: arg, content: item(depth + 1), start, end: p.pos };
      case 7:
        return { kind: 'null', start, end: p.pos };
      default:
        return fail('ErrForbiddenCBOR');
    }
  };
  const root = item(0);
  if (p.pos !== b.length) fail('ErrTrailing');
  return root;
}

export const raw = (b: Uint8Array, it: Item): Uint8Array => b.subarray(it.start, it.end);

export function arrayOf(it: Item, n?: number): Item[] | null {
  if (it.kind !== 'array') return null;
  return n === undefined || it.kids.length === n ? it.kids : null;
}

export function bytesN(it: Item, n: number): Uint8Array {
  if (it.kind !== 'bytes') return fail('ErrShape');
  if (it.data.length !== n) return fail('ErrLength');
  return it.data;
}

export const bytesAny = (it: Item): Uint8Array => (it.kind === 'bytes' ? it.data : fail('ErrShape'));

export function tagContent(it: Item, tag: bigint): Item {
  if (it.kind !== 'tag') return fail('ErrShape');
  return it.tag === tag ? it.content : fail('ErrTag');
}

export const uint = (it: Item): bigint => (it.kind === 'uint' ? it.value : fail('ErrShape'));

export function uintMax(it: Item, max: bigint): bigint {
  if (it.kind !== 'uint') return fail('ErrShape');
  return it.value <= max ? it.value : fail('ErrIntRange');
}

export function version(it: Item, want: bigint): void {
  if (it.kind !== 'uint') fail('ErrShape');
  else if (it.value !== want) fail('ErrVersion');
}

/** A positive minimal big-endian amount of at most 32 bytes. */
export function amount(it: Item): Uint8Array {
  const d = bytesAny(it);
  if (d.length === 0 || d.length > MAX_AMOUNT_BYTES || d[0] === 0) fail('ErrIntRange');
  return d;
}

export function nullableBytes(it: Item): Uint8Array | null {
  if (it.kind === 'null') return null;
  return it.kind === 'bytes' ? it.data : fail('ErrShape');
}

export function nullableUint(it: Item): bigint | null {
  if (it.kind === 'null') return null;
  return it.kind === 'uint' ? it.value : fail('ErrShape');
}

// ---- partition description records -------------------------------------------------------------

/**
 * Split a canonical native tag(39008, PDR array) into the raw bytes of its elements. The PDR carries text and a
 * map, so it cannot use {@link scanOne}; canonical form is still enforced: shortest heads, definite
 * lengths, strictly bytewise-increasing map keys, valid UTF-8, no floats, no nested tags.
 */
export function pdrElements(b: Uint8Array): Uint8Array[] {
  const p = { pos: 0 };
  let tokens = 2;
  const tag = readHead(b, p);
  if (tag.major !== 6) fail('ErrShape');
  if (tag.arg !== 39008n) fail('ErrTag');
  const head = readHead(b, p);
  if (head.major !== 4 || head.arg !== 15n) fail('ErrShape');
  if (head.arg > BigInt(b.length)) fail('ErrTruncated');
  const out: Uint8Array[] = [];
  for (let i = 0n; i < head.arg; i++) {
    const s = p.pos;
    skip(b, p, 2, () => ++tokens);
    out.push(b.subarray(s, p.pos));
  }
  if (p.pos !== b.length) fail('ErrTrailing');
  return out;
}

function lessEq(a: Uint8Array, b: Uint8Array): boolean {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return a.length <= b.length;
}

function skip(b: Uint8Array, p: { pos: number }, depth: number, tick: () => number): void {
  if (tick() > MAX_CBOR_ITEMS) fail('ErrTooManyItems');
  if (depth > MAX_CBOR_DEPTH) fail('ErrTooDeep');
  if (p.pos >= b.length) fail('ErrTruncated');
  const first = b[p.pos];
  const { major, arg } = readHead(b, p);
  const rest = BigInt(b.length - p.pos);
  switch (major) {
    case 0:
    case 1:
      return;
    case 2:
    case 3: {
      if (arg > rest) fail('ErrTruncated');
      const data = b.subarray(p.pos, p.pos + Number(arg));
      p.pos += Number(arg);
      if (major === 3) {
        try {
          new TextDecoder('utf-8', { fatal: true }).decode(data);
        } catch {
          fail('ErrNonCanonical');
        }
      }
      return;
    }
    case 4:
      if (arg > rest) fail('ErrTruncated');
      for (let i = 0n; i < arg; i++) skip(b, p, depth + 1, tick);
      return;
    case 5: {
      if (arg > rest) fail('ErrTruncated');
      let prev: Uint8Array | null = null;
      for (let i = 0n; i < arg; i++) {
        const ks = p.pos;
        skip(b, p, depth + 1, tick);
        const key = b.subarray(ks, p.pos);
        if (prev && lessEq(key, prev)) fail('ErrNonCanonical');
        prev = key;
        skip(b, p, depth + 1, tick);
      }
      return;
    }
    case 7:
      if (first === 0xf6 || first === 0xf4 || first === 0xf5) return;
      return fail('ErrForbiddenCBOR');
    default:
      return fail('ErrForbiddenCBOR');
  }
}
