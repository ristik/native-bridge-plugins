/** Bounded canonical scan of a native unicity certificate before SDK decoding.
 * Native UC sublimits: summary 256 bytes; shard 256 bits/33 bytes/256 siblings;
 * Unicity path 32 steps; seal 64 signatures; signer ID 128 UTF-8 bytes.
 */
import { NativeError, fail } from './errors.js';
import { MAX_CBOR_DEPTH, MAX_CBOR_ITEMS, MAX_UC_BYTES } from './limits.js';

type Node = { major: number; arg: bigint; start: number; end: number; depth: number; data: Uint8Array; kids: Node[] };
/** Items of the object being scanned, within its own limit. */
class Budget {
  items = 0;
  constructor(readonly limit: number = MAX_CBOR_ITEMS) {}
}
function scan(b: Uint8Array, budget: Budget, depth = 0): Node {
  let pos = 0;
  const read = (d: number): Node => {
    if (d > MAX_CBOR_DEPTH) fail('ErrTooDeep');
    if (++budget.items > budget.limit) fail('ErrTooManyItems');
    const start = pos;
    if (pos === b.length) fail('ErrTruncated');
    const ib = b[pos++], major = ib >> 5, ai = ib & 31;
    if (ai > 27) fail('ErrForbiddenCBOR');
    let arg = BigInt(ai);
    if (ai >= 24) {
      const n = 1 << (ai - 24);
      if (b.length - pos < n) fail('ErrTruncated');
      arg = 0n;
      for (let i = 0; i < n; i++) arg = arg << 8n | BigInt(b[pos++]);
      if (arg < (ai === 24 ? 24n : 1n << BigInt(8 * (n / 2)))) fail('ErrNonCanonical');
    }
    if ((major === 4 || major === 5 || major === 6) && d + 1 > MAX_CBOR_DEPTH) fail('ErrTooDeep');
    let data = b.subarray(pos, pos);
    const kids: Node[] = [];
    if (major === 2 || major === 3) {
      if (arg > BigInt(b.length - pos)) fail('ErrTruncated');
      data = b.subarray(pos, pos + Number(arg)); pos += Number(arg);
      if (major === 3) { try { new TextDecoder('utf-8', { fatal: true }).decode(data); } catch { fail('ErrNonCanonical'); } }
    } else if (major === 4 || major === 5) {
      const count = arg * (major === 5 ? 2n : 1n);
      if (count > BigInt(budget.limit - budget.items)) fail('ErrTooManyItems');
      if (count > BigInt(b.length - pos)) fail('ErrTruncated');
      for (let i = 0n; i < count; i++) kids.push(read(d + 1));
      if (major === 5) for (let i = 2; i < kids.length; i += 2) {
        const a = b.subarray(kids[i - 2].start, kids[i - 2].end), c = b.subarray(kids[i].start, kids[i].end);
        let j = 0; while (j < Math.min(a.length, c.length) && a[j] === c[j]) j++;
        if (j === Math.min(a.length, c.length) ? a.length >= c.length : a[j] >= c[j]) fail('ErrNonCanonical');
      }
    } else if (major === 6) kids.push(read(d + 1));
    else if (major === 7 && ib !== 0xf6 && ib !== 0xf4 && ib !== 0xf5) fail('ErrForbiddenCBOR');
    return { major, arg, start, end: pos, depth: d, data, kids };
  };
  const root = read(depth);
  if (pos !== b.length) fail('ErrTrailing');
  return root;
}
const unsupported = (): never => fail('ErrUnsupportedCertificateEncoding');
const array = (n: Node, count?: number): Node[] => n.major === 4 && (count === undefined || n.kids.length === count) ? n.kids : unsupported();
const tagged = (n: Node, tag: bigint, count: number): Node[] => n.major === 6 && n.arg === tag ? array(n.kids[0], count) : unsupported();
const uint = (n: Node, max = 0xffffffffffffffffn): void => { if (n.major !== 0 || n.arg > max) unsupported(); };
const version = (n: Node): void => { uint(n); if (n.arg !== 1n) unsupported(); };
const hash = (n: Node, nullable = false): void => { if (!(nullable && n.major === 7 && n.arg === 22n) && (n.major !== 2 || n.data.length !== 32)) unsupported(); };
function uc(n: Node, budget: Budget, maxBytes = MAX_UC_BYTES): void {
  if (n.end - n.start > maxBytes) fail('ErrProofTooLarge');
  const k = tagged(n, 39001n, 7); version(k[0]);
  const ir = tagged(k[1], 39002n, 10); version(ir[0]); uint(ir[1]); uint(ir[2]);
  hash(ir[3], true); hash(ir[4]);
  if (ir[5].major !== 2) unsupported();
  if (ir[5].data.length > 256) fail('ErrProofTooLarge');
  uint(ir[6]); hash(ir[7], true); uint(ir[8]); hash(ir[9], true); hash(k[2], true); hash(k[3]);
  const st = tagged(k[4], 39003n, 3); version(st[0]);
  if (st[1].major !== 2 || st[1].data.length === 0) unsupported();
  if (st[1].data.length > 33) fail('ErrProofTooLarge');
  const last = st[1].data.at(-1)!; if (last === 0) unsupported();
  let zeros = 0; while (((last >> zeros) & 1) === 0) zeros++;
  if (st[1].data.length * 8 - zeros - 1 > 256) fail('ErrProofTooLarge');
  const siblings = array(st[2]); if (siblings.length > 256) fail('ErrProofTooLarge'); siblings.forEach((x) => hash(x));
  const ut = tagged(k[5], 39004n, 3); version(ut[0]); uint(ut[1], 0xffffffffn);
  const steps = array(ut[2]); if (steps.length > 32) fail('ErrProofTooLarge');
  for (const step of steps) { const x = array(step, 2); uint(x[0], 0xffffffffn); hash(x[1]); }
  const seal = tagged(k[6], 39005n, 8); version(seal[0]); uint(seal[1], 0xffffn); if (seal[1].arg === 0n) unsupported(); uint(seal[2]); // network 0 is none (B1 scan) uint(seal[3]); uint(seal[4]); hash(seal[5], true); hash(seal[6]);
  if (seal[7].major !== 5) unsupported();
  const sigs = seal[7].kids; if (sigs.length > 128) fail('ErrProofTooLarge');
  for (let i = 0; i < sigs.length; i += 2) {
    if (sigs[i].major !== 3) unsupported();
    if (sigs[i].data.length > 128) fail('ErrProofTooLarge');
    // a signature value is any byte string (the upstream seal rule): whether it counts is decided by the SDK verifier, which gives a signature
    // that is not an exact canonical 65-byte recoverable one of its member no weight; the width is not a scan failure
    const sig = sigs[i + 1];
    if (sig.major !== 2) unsupported();
  }
}
/**
 * The native certificate sublimit scan alone (the step bft-core `scanCertificate` takes from `b1ref.ScanUC`), with the B1 byte cap
 * `maxBytes`; any failure is the caller's to classify.
 */
export function nativeUcScan(bytes: Uint8Array, maxBytes: number): void {
  const budget = new Budget();
  uc(scan(bytes, budget), budget, maxBytes);
}

export function preflightUc(bytes: Uint8Array): void {
  if (bytes.length > MAX_UC_BYTES) fail('ErrProofTooLarge');
  const budget = new Budget();
  try { uc(scan(bytes, budget), budget); } catch (e) {
    if (e instanceof NativeError && e.family !== 'budget') unsupported();
    throw e;
  }
}
