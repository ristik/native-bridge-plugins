import { eq } from './bytes.js';
import { fail } from './errors.js';
import { keccak256 } from './profile.js';
import { decode, listOf, type Rlp } from './rlp.js';

const nibbles = (key: Uint8Array): number[] => [...key].flatMap((b) => [b >> 4, b & 15]);

/** A compact-encoded path: flag nibble 0/1 extension even/odd, 2/3 leaf even/odd; an even path has a zero padding nibble. Null if not one. */
function hexPrefix(it: Rlp): { leaf: boolean; path: number[] } | null {
  if (it.kind !== 'bytes' || it.data.length === 0) return null;
  const b = it.data;
  const flag = b[0] >> 4;
  if (flag > 3) return null;
  const path: number[] = [];
  if ((flag & 1) !== 0) path.push(b[0] & 15);
  else if ((b[0] & 15) !== 0) return null;
  path.push(...nibbles(b.subarray(1)));
  return { leaf: flag >= 2, path };
}

/** A node's RLP; anything that is not one is a bad node. */
function node(b: Uint8Array): Rlp {
  try {
    return decode(b);
  } catch {
    return fail('ErrMPTNode');
  }
}

/** The value, once the walk has used exactly the supplied nodes. */
const finish = (used: number, total: number, v: Uint8Array): Uint8Array => (used !== total ? fail('ErrMPTExtraneous') : v);

/**
 * The value of `key` (32 bytes, the hashed path) under `root`, from the ordered root-to-leaf list of hash-referenced nodes (nodes under 32
 * bytes are embedded in their parent). bft-core `mptVerify` exactly, with its reasons: a node that is not canonical, mis-hashed or out of order
 * `ErrMPTNode`; a path the supplied nodes do not take to its end `ErrMPTPath`; the key absent `ErrMPTAbsent`; a node left unused
 * `ErrMPTExtraneous`. The root is hash-referenced whatever its size.
 */
export function verifyProof(root: Uint8Array, key: Uint8Array, nodes: Uint8Array[]): Uint8Array {
  let nib = nibbles(key);
  if (nodes.length === 0 || !eq(keccak256(nodes[0]), root)) fail('ErrMPTNode');
  let cur = node(nodes[0]);
  let used = 1;
  for (;;) {
    if (cur.kind !== 'list') fail('ErrMPTNode');
    const kids = listOf(cur);
    let child: Rlp;
    if (kids.length === 17) {
      if (nib.length === 0) {
        const v = kids[16];
        if (v.kind === 'list' || v.data.length === 0) fail('ErrMPTAbsent');
        return finish(used, nodes.length, v.data);
      }
      child = kids[nib[0]];
      nib = nib.slice(1);
      if (child.kind !== 'list' && child.data.length === 0) fail('ErrMPTAbsent');
    } else if (kids.length === 2) {
      const hp = hexPrefix(kids[0]) ?? fail('ErrMPTNode');
      if (hp.path.length > nib.length || hp.path.some((n, i) => n !== nib[i])) fail('ErrMPTAbsent');
      nib = nib.slice(hp.path.length);
      const v = kids[1];
      if (hp.leaf) {
        if (nib.length !== 0) fail('ErrMPTPath'); // the leaf ends before the key does
        if (v.kind === 'list' || v.data.length === 0) fail('ErrMPTNode');
        return finish(used, nodes.length, v.data);
      }
      if (hp.path.length === 0) fail('ErrMPTNode'); // an extension consumes at least one nibble
      child = v;
    } else {
      return fail('ErrMPTNode');
    }
    // the child: embedded (under 32 bytes) or a hash reference to the next supplied node
    if (child.kind === 'list') {
      if (child.raw.length >= 32) fail('ErrMPTNode');
      cur = child;
    } else if (child.data.length === 32) {
      if (used >= nodes.length) fail('ErrMPTPath'); // a hash reference with no supplied node
      const n = nodes[used];
      if (n.length < 32 || !eq(keccak256(n), child.data)) fail('ErrMPTNode');
      cur = node(n);
      used++;
    } else {
      fail('ErrMPTNode');
    }
  }
}
