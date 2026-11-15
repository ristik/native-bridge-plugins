/**
 * Ethereum Merkle-Patricia trie: the strict inclusion check of bft-core `nb2ref/mpt.go` (an unhashed key of any length, the nodes
 * exactly the root-to-leaf path in order, every hash reference consuming the next node, an embedded node consuming none, the key
 * consumed completely, no duplicate, unused or out-of-order node), and a builder of a whole trie with the path of one key, which the
 * wallet uses to turn a block's receipts into a receipt-trie proof.
 */
import { eq } from '../bytes.js';
import { HE } from './crypto.js';
import { rlpBytes, rlpDecode, rlpList, type RlpItem } from './rlp.js';

export class MptError extends Error {}
const bad = (): never => {
  throw new MptError('nb2: MPT path does not verify');
};

const nibbles = (key: Uint8Array): number[] => [...key].flatMap((b) => [b >> 4, b & 0x0f]);

function hexPrefix(it: RlpItem): { path: number[]; leaf: boolean } | null {
  if (it.list || it.str.length === 0) return null;
  const f = it.str[0] >> 4;
  if (f > 3) return null;
  const path: number[] = [];
  if (f & 1) path.push(it.str[0] & 0x0f);
  else if ((it.str[0] & 0x0f) !== 0) return null;
  for (const b of it.str.subarray(1)) path.push(b >> 4, b & 0x0f);
  return { path, leaf: f >= 2 };
}

/** The value stored at `key` under `root`; throws {@link MptError}. */
export function mptVerify(root: Uint8Array, key: Uint8Array, nodes: Uint8Array[]): Uint8Array {
  let nib = nibbles(key);
  if (nodes.length === 0 || !eq(HE(nodes[0]), root)) bad();
  let cur: RlpItem;
  try {
    cur = rlpDecode(nodes[0]);
  } catch {
    return bad();
  }
  let used = 1;
  const finish = (v: Uint8Array): Uint8Array => (used !== nodes.length ? bad() : v);
  for (;;) {
    if (!cur.list) bad();
    let child: RlpItem;
    if (cur.kids.length === 17) {
      if (nib.length === 0) {
        const v = cur.kids[16];
        if (v.list || v.str.length === 0) bad();
        return finish(v.str);
      }
      child = cur.kids[nib[0]];
      nib = nib.slice(1);
      if (!child.list && child.str.length === 0) bad();
    } else if (cur.kids.length === 2) {
      const hp = hexPrefix(cur.kids[0]);
      if (hp === null || hp.path.length > nib.length || hp.path.some((x, i) => x !== nib[i])) bad();
      nib = nib.slice(hp!.path.length);
      const v = cur.kids[1];
      if (hp!.leaf) {
        if (nib.length !== 0 || v.list || v.str.length === 0) bad();
        return finish(v.str);
      }
      if (hp!.path.length === 0) bad();
      child = v;
    } else {
      return bad();
    }
    if (child.list) {
      if (child.raw.length >= 32) bad();
      cur = child;
    } else if (child.str.length === 32) {
      if (used >= nodes.length) bad();
      const n = nodes[used];
      if (n.length < 32 || !eq(HE(n), child.str)) bad();
      try {
        cur = rlpDecode(n);
      } catch {
        return bad();
      }
      used++;
    } else {
      bad();
    }
  }
}

// ---- builder ----------------------------------------------------------------------------------

function compact(n: number[], leaf: boolean): Uint8Array {
  const flag = (leaf ? 2 : 0) | (n.length & 1);
  const out: number[] = [];
  let i = 0;
  if (n.length % 2 === 1) out.push((flag << 4) | n[i++]);
  else out.push(flag << 4);
  for (; i < n.length; i += 2) out.push((n[i] << 4) | n[i + 1]);
  return Uint8Array.from(out);
}

const ref = (node: Uint8Array): Uint8Array => (node.length < 32 ? node : rlpBytes(HE(node)));

type Entry = { k: number[]; v: Uint8Array };

function build(entries: Entry[], depth: number, target: number[] | null, path: Uint8Array[]): Uint8Array {
  const onPath = target !== null && entries.some((e) => e.k.length === target.length && e.k.every((x, i) => x === target[i]));
  let node: Uint8Array;
  if (entries.length === 1 && entries[0].k.length >= depth) {
    node = rlpList([rlpBytes(compact(entries[0].k.slice(depth), true)), rlpBytes(entries[0].v)]);
  } else {
    // a value ending exactly here sits in the branch's 17th slot
    const here = entries.filter((e) => e.k.length === depth);
    const deeper = entries.filter((e) => e.k.length > depth);
    let cp = 0;
    if (here.length === 0) {
      const first = deeper[0].k;
      while (deeper.every((e) => e.k.length > depth + cp && e.k[depth + cp] === first[depth + cp])) cp++;
    }
    if (cp > 0) {
      const child = build(entries, depth + cp, target, path);
      node = rlpList([rlpBytes(compact(deeper[0].k.slice(depth, depth + cp), false)), ref(child)]);
    } else {
      const items: Uint8Array[] = [];
      for (let n = 0; n < 16; n++) {
        const group = deeper.filter((e) => e.k[depth] === n);
        items.push(group.length === 0 ? rlpBytes(new Uint8Array()) : ref(build(group, depth + 1, target, path)));
      }
      items.push(rlpBytes(here.length === 1 ? here[0].v : new Uint8Array()));
      node = rlpList(items);
    }
  }
  // the proof carries every hash-referenced node of the path (an embedded one travels inside its parent); the root always
  if (onPath && (node.length >= 32 || depth === 0)) path.push(node);
  return node;
}

/** Build the trie of `entries` (distinct keys): its root and the root-to-leaf path of `target` (empty if `target` is null). */
export function buildTrie(entries: [Uint8Array, Uint8Array][], target: Uint8Array | null): { root: Uint8Array; path: Uint8Array[] } {
  if (entries.length === 0) return { root: HE(rlpBytes(new Uint8Array())), path: [] };
  const es = entries.map(([k, v]) => ({ k: nibbles(k), v }));
  const path: Uint8Array[] = [];
  const root = build(es, 0, target === null ? null : nibbles(target), path);
  return { root: HE(root), path: path.reverse() };
}
