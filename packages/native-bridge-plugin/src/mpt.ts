import { eq } from './bytes.js';
import { fail } from './errors.js';
import { keccak256 } from './profile.js';
import { decode, listOf, bytesOf, type Rlp } from './rlp.js';

const nibbles = (key: Uint8Array): number[] => [...key].flatMap((b) => [b >> 4, b & 15]);

function hexPrefix(b: Uint8Array): { leaf: boolean; path: number[] } {
  if (b.length === 0) return fail('ErrMptMalformed');
  const flag = b[0] >> 4;
  if (flag > 3) fail('ErrMptMalformed');
  const odd = (flag & 1) !== 0;
  const path: number[] = [];
  if (odd) path.push(b[0] & 15);
  else if ((b[0] & 15) !== 0) fail('ErrMptMalformed');
  path.push(...nibbles(b.subarray(1)));
  return { leaf: (flag & 2) !== 0, path };
}

type Child = { hash: Uint8Array } | { embedded: Rlp };

function childRef(it: Rlp): Child {
  if (it.kind === 'bytes' && it.data.length === 32) return { hash: it.data };
  if (it.kind === 'list' && it.raw.length < 32) return { embedded: it };
  return fail('ErrMptMalformed');
}

/**
 * Verify that `key` maps to a non-empty value under `root`, returning that value. The proof is the
 * ordered root-to-leaf list of hashed nodes (nodes under 32 bytes are embedded). Enforces hex-prefix
 * rules, embedded/hash-reference rules, full key consumption and that the list holds exactly the
 * nodes on the path: no duplicate, extraneous or missing node and no unused suffix.
 */
export function verifyProof(root: Uint8Array, key: Uint8Array, nodes: Uint8Array[]): Uint8Array {
  let rest = nibbles(key);
  let used = 0;
  const decoded = nodes.map((n) => decode(n));
  let expect: Child = { hash: root };
  for (;;) {
    let current: Rlp;
    if ('hash' in expect) {
      const idx = used;
      if (idx >= nodes.length) fail('ErrMptMalformed');
      if (nodes[idx].length < 32 || !eq(keccak256(nodes[idx]), expect.hash)) fail('ErrMptMalformed');
      used++;
      current = decoded[idx];
    } else {
      current = expect.embedded;
    }
    if (current.kind !== 'list') fail('ErrMptMalformed');
    const list = listOf(current);
    if (list.length === 17) {
      if (rest.length === 0) fail('ErrMptMalformed');
      expect = childRef(list[rest[0]]);
      rest = rest.slice(1);
    } else if (list.length === 2) {
      const { leaf, path } = hexPrefix(bytesOf(list[0]));
      if (leaf) {
        if (path.length !== rest.length || path.some((n, i) => n !== rest[i])) fail('ErrMptMalformed');
        const value = bytesOf(list[1]);
        if (value.length === 0 || used !== nodes.length) fail('ErrMptMalformed');
        return value;
      }
      if (path.length === 0 || path.length > rest.length || path.some((n, i) => n !== rest[i])) fail('ErrMptMalformed');
      rest = rest.slice(path.length);
      expect = childRef(list[1]);
    } else {
      fail('ErrMptMalformed');
    }
  }
}
