/** Bounded canonical scan before SDK decoding, including CBOR hidden in payload byte strings.
 * Native UC sublimits: summary 256 bytes; shard 256 bits/33 bytes/256 siblings;
 * Unicity path 32 steps; seal 64 signatures; signer ID 128 UTF-8 bytes.
 */
import { NativeError, fail } from './errors.js';
import { MAX_CBOR_DEPTH, MAX_CBOR_ITEMS, MAX_JUSTIFICATION_BYTES, MAX_HEADER_BYTES, MAX_MPT_NODES, MAX_MPT_NODE_BYTES, MAX_MPT_TOTAL_BYTES, MAX_PATH_STEPS, MAX_PDR_BYTES, MAX_TOKEN_BYTES, MAX_TRANSFERS, MAX_UC_BYTES } from './limits.js';

type Node = { major: number; arg: bigint; start: number; end: number; depth: number; data: Uint8Array; kids: Node[] };
class Budget {
  items = 0;
  paths = 0;
  addPaths(n: number): void {
    if (n > MAX_PATH_STEPS - this.paths) fail('ErrTooManyPaths');
    this.paths += n;
  }
}
function scan(b: Uint8Array, budget: Budget, depth = 0): Node {
  let pos = 0;
  const read = (d: number): Node => {
    if (d > MAX_CBOR_DEPTH) fail('ErrTooDeep');
    if (++budget.items > MAX_CBOR_ITEMS) fail('ErrTooManyItems');
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
      if (count > BigInt(MAX_CBOR_ITEMS - budget.items)) fail('ErrTooManyItems');
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
function uc(n: Node, budget: Budget): void {
  if (n.end - n.start > MAX_UC_BYTES) fail('ErrProofTooLarge');
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
  budget.addPaths(siblings.length + steps.length);
  const seal = tagged(k[6], 39005n, 8); version(seal[0]); uint(seal[1], 0xffffn); uint(seal[2]); uint(seal[3]); uint(seal[4]); hash(seal[5], true); hash(seal[6]);
  if (seal[7].major !== 5) unsupported();
  const sigs = seal[7].kids; if (sigs.length > 128) fail('ErrProofTooLarge');
  for (let i = 0; i < sigs.length; i += 2) {
    if (sigs[i].major !== 3) unsupported();
    if (sigs[i].data.length > 128) fail('ErrProofTooLarge');
    if (sigs[i + 1].major !== 2 || sigs[i + 1].data.length !== 65 || sigs[i + 1].data[64] > 1) unsupported();
  }
}
function visit(n: Node, budget: Budget): void {
  if (n.major === 6) {
    if (n.arg === 39001n) { uc(n, budget); return; }
    const body = n.kids[0];
    if (body.major === 4) {
      const k = body.kids;
      const nested = (x: Node | undefined, max: number, certificate = false): void => {
        if (!x || x.major !== 2) return;
        if (x.data.length > max) fail('ErrProofTooLarge');
        let root: Node;
        try { root = scan(x.data, budget, x.depth + 1); } catch (e) {
          if (e instanceof NativeError && e.family !== 'budget') { if (certificate) unsupported(); return; }
          throw e;
        }
        if (certificate) uc(root, budget); else visit(root, budget);
      };
      if (n.arg === 39040n && k[2]?.major === 4 && k[2].kids.length > MAX_TRANSFERS) fail('ErrTooManyTx');
      if (n.arg === 39032n) nested(k[1], MAX_TOKEN_BYTES); // The predicate code is CBOR in a bstr.
      if (n.arg === 39041n) { nested(k[5], MAX_JUSTIFICATION_BYTES); nested(k[6], MAX_TOKEN_BYTES); }
      if (n.arg === 39045n) nested(k[3], MAX_TOKEN_BYTES);
      if (n.arg === 39049n && k[5]?.major === 4) {
        const lp = k[5].kids;
        if (lp[5]?.major === 2 && lp[5].data.length > MAX_HEADER_BYTES) fail('ErrProofTooLarge');
        let total = 0;
        for (const list of [lp[6], lp[7]]) if (list?.major === 4) {
          if (list.kids.length > MAX_MPT_NODES) fail('ErrProofTooLarge');
          for (const node of list.kids) if (node.major === 2) {
            if (node.data.length > MAX_MPT_NODE_BYTES || node.data.length > MAX_MPT_TOTAL_BYTES - total) fail('ErrProofTooLarge');
            total += node.data.length;
          }
        }
        nested(lp[3], MAX_PDR_BYTES); nested(lp[4], MAX_UC_BYTES, true);
      }
      if (n.arg === 39033n && k[3]?.major === 2) {
        const len = k[3].data.length;
        if (len < 32 || len % 32 !== 0) unsupported();
        const paths = (len - 32) / 32; if (paths > 256) fail('ErrProofTooLarge'); budget.addPaths(paths);
        if (k[4]) uc(k[4], budget); else unsupported();
        return; // UC paths have already been counted.
      }
    }
  }
  for (const child of n.kids) visit(child, budget);
}
export function preflightToken(bytes: Uint8Array): void {
  if (bytes.length > MAX_TOKEN_BYTES) fail('ErrInputTooLarge');
  const budget = new Budget(); visit(scan(bytes, budget), budget);
}
export function preflightUc(bytes: Uint8Array): void {
  if (bytes.length > MAX_UC_BYTES) fail('ErrProofTooLarge');
  const budget = new Budget();
  try { uc(scan(bytes, budget), budget); } catch (e) {
    if (e instanceof NativeError && e.family !== 'budget') unsupported();
    throw e;
  }
}
