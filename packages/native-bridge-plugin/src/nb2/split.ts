import { eq } from '../bytes.js';
import { amount, array, ascii, bytesN, cAmount, cArr, cBytes, cDeadline, cTag, cUint, scanOne, tagContent, u256, uintIn, type Item } from './cbor.js';
import { DOMAIN, TAG } from './config.js';
import { HU } from './crypto.js';
import { Nb2Error, fail } from './errors.js';
import { encodePredicate, tokenIdOf, type MintTx } from './token.js';

const MAX_SUM_PROOF_STEPS = 256;
const TWO256 = 1n << 256n;

const validAmount = (v: bigint): boolean => v > 0n && v < TWO256;
const keyBit = (key: Uint8Array, i: number): boolean => ((key[i >> 3] >> (7 - (i & 7))) & 1) === 1;

export function sumLeafHash(key: Uint8Array, data: Uint8Array, value: bigint): Uint8Array | null {
  if (!validAmount(value)) return null;
  return HU(Uint8Array.of(0x10), key, data, u256(value));
}

export function sumNodeHash(depth: number, hl: Uint8Array, sl: bigint, hr: Uint8Array, sr: bigint): [Uint8Array, bigint] | null {
  if (!validAmount(sl) || !validAmount(sr)) return null;
  const sum = sl + sr;
  if (sum >= TWO256) return null;
  return [HU(Uint8Array.of(0x11, depth), hl, u256(sl), hr, u256(sr)), sum];
}

export interface SumStep { depth: number; hash: Uint8Array; sum: bigint }

export const encodeSumProof = (p: SumStep[]): Uint8Array => cArr(...p.map((s) => cArr(cUint(s.depth), cBytes(s.hash), cAmount(s.sum))));

export function decodeSumProof(bytes: Uint8Array): SumStep[] {
  const it = scanOne(bytes);
  if (it.major !== 4 || it.kids.length > MAX_SUM_PROOF_STEPS) fail('SplitProofShape');
  const p: SumStep[] = [];
  let prev = 256;
  for (const k of it.kids) {
    let kids: Item[];
    try {
      kids = array(k, 3);
    } catch {
      return fail('SplitProofShape');
    }
    let d: number;
    try {
      d = Number(uintIn(kids[0], 0n, 255n));
    } catch {
      return fail('SplitProofShape');
    }
    if (d >= prev) fail('SplitProofShape');
    prev = d;
    let hash: Uint8Array;
    let sum: bigint;
    try {
      hash = bytesN(kids[1], 32);
      sum = amount(kids[2]);
    } catch {
      return fail('SplitProofShape');
    }
    p.push({ depth: d, hash, sum });
  }
  return p;
}

/** Fold the leaf to the root; the root sum iff the fold equals `root`. */
export function verifySumProof(p: SumStep[], key: Uint8Array, data: Uint8Array, value: bigint, root: Uint8Array): bigint | null {
  const leaf = sumLeafHash(key, data, value);
  if (leaf === null) return null;
  let hash: Uint8Array = leaf;
  let sum = value;
  for (const s of p) {
    const r: [Uint8Array, bigint] | null = keyBit(key, s.depth) ? sumNodeHash(s.depth, s.hash, s.sum, hash, sum) : sumNodeHash(s.depth, hash, sum, s.hash, s.sum);
    if (r === null) return null;
    [hash, sum] = r;
  }
  return eq(hash, root) ? sum : null;
}

export const encodeSplitManifest = (root: Uint8Array): Uint8Array => cTag(TAG.splitManifest, cArr(cBytes(root)));

/** A split burn's data; any failure is `SplitManifest`. */
export function decodeSplitManifest(b: Uint8Array): Uint8Array {
  try {
    return bytesN(array(tagContent(scanOne(b), TAG.splitManifest), 1)[0], 32);
  } catch {
    return fail('SplitManifest');
  }
}

/** The child mint's commitment without its justification. */
export function splitOutputCommitment(parentId: Uint8Array, m: MintTx): Uint8Array {
  const childId = tokenIdOf(m.salt, m.network);
  return HU(cArr(cBytes(ascii(DOMAIN.splitOutput)), cBytes(parentId), cUint(m.network), cBytes(encodePredicate(m.recipient)), cBytes(m.salt),
    cBytes(childId), cBytes(m.type), cBytes(m.data ?? new Uint8Array()), cDeadline(m.deadline)));
}

export function parentLink(d: Uint8Array, id: Uint8Array, sid: Uint8Array, txHash: Uint8Array, manifest: Uint8Array, value: bigint): Uint8Array {
  return HU(ascii('UNICITY/NB2/1.1/PARENT'), d, id, sid, txHash, manifest, u256(value));
}

export function decodeSplitJustification(bytes: Uint8Array): Uint8Array {
  try {
    const [v, link] = array(tagContent(scanOne(bytes), TAG.splitJustification), 2);
    uintIn(v, 2n, 2n);
    return bytesN(link, 32);
  } catch {
    return fail('SplitJustif');
  }
}

export const encodeSplitJustification = (link: Uint8Array): Uint8Array =>
  cTag(TAG.splitJustification, cArr(cUint(2), cBytes(link)));

// ---- the allocation tree (the SDK's radix sparse Merkle sum tree), for building splits and fixtures -------------------

interface SumNode { leaf: boolean; key: Uint8Array; depth: number; left?: SumNode; right?: SumNode; hash: Uint8Array; sum: bigint }

export interface SumLeaf { key: Uint8Array; data: Uint8Array; value: bigint }

const cmp = (a: Uint8Array, b: Uint8Array): number => {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
};

function subtree(nodes: SumNode[], start: number): SumNode {
  if (nodes.length === 1) return nodes[0];
  let depth = start;
  for (; depth < 256; depth++) {
    const first = keyBit(nodes[0].key, depth);
    if (nodes.some((n) => keyBit(n.key, depth) !== first)) break;
  }
  if (depth === 256) throw new Nb2Error('SplitProofShape');
  const l = nodes.filter((n) => !keyBit(n.key, depth));
  const r = nodes.filter((n) => keyBit(n.key, depth));
  const ln = subtree(l, depth + 1);
  const rn = subtree(r, depth + 1);
  const h = sumNodeHash(depth, ln.hash, ln.sum, rn.hash, rn.sum);
  if (h === null) throw new Nb2Error('SplitProofShape');
  return { leaf: false, key: new Uint8Array(32), depth, left: ln, right: rn, hash: h[0], sum: h[1] };
}

export class SumTree {
  private constructor(private readonly rootNode: SumNode) {}

  public static build(leaves: SumLeaf[]): SumTree {
    if (leaves.length === 0) throw new Nb2Error('SplitProofShape');
    const nodes = leaves.map((l) => {
      const h = sumLeafHash(l.key, l.data, l.value);
      if (h === null) throw new Nb2Error('SplitProofShape');
      return { leaf: true, key: l.key, depth: 0, hash: h, sum: l.value } as SumNode;
    }).sort((a, b) => cmp(a.key, b.key));
    for (let i = 1; i < nodes.length; i++) if (cmp(nodes[i].key, nodes[i - 1].key) === 0) throw new Nb2Error('SplitProofShape');
    return new SumTree(subtree(nodes, 0));
  }

  public get root(): Uint8Array {
    return this.rootNode.hash;
  }

  public proof(key: Uint8Array): SumStep[] | null {
    const steps: SumStep[] = [];
    let n = this.rootNode;
    while (!n.leaf) {
      const right = keyBit(key, n.depth);
      const sib = right ? n.left! : n.right!;
      steps.push({ depth: n.depth, hash: sib.hash, sum: sib.sum });
      n = right ? n.right! : n.left!;
    }
    if (!eq(n.key, key)) return null;
    return steps.reverse();
  }
}
