import { eq } from './bytes.js';
import { fail } from './errors.js';
import { bytesOf, decode, listOf, u64Of, type Rlp } from './rlp.js';

/** `keccak256(rlp([]))`, the empty-uncle-list hash. */
export const EMPTY_UNCLE_HASH = Uint8Array.from(
  '1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347'.match(/../g)!.map((x) => parseInt(x, 16)),
);
/** The empty trie root, also the empty withdrawals root. */
export const EMPTY_TRIE_ROOT = Uint8Array.from(
  '56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421'.match(/../g)!.map((x) => parseInt(x, 16)),
);

/** The pinned header shape: 20 fields (Cancun, through parentBeaconBlockRoot) or 21 (+ requestsHash). */
export interface HeaderProfile {
  fields: 20 | 21;
}

export interface Header {
  stateRoot: Uint8Array;
  number: bigint;
}

/** Decode and check a header against the pinned profile. */
export function decodeHeader(raw: Uint8Array, profile: HeaderProfile): Header {
  const bad = (): never => fail('ErrHeaderProfile');
  let f: Rlp[];
  try {
    f = listOf(decode(raw));
  } catch {
    return bad();
  }
  if ((profile.fields !== 20 && profile.fields !== 21) || f.length !== profile.fields) bad();
  const b = (i: number, n?: number): Uint8Array => {
    let d: Uint8Array;
    try {
      d = bytesOf(f[i]);
    } catch {
      return bad();
    }
    if (n !== undefined && d.length !== n) bad();
    return d;
  };
  const int = (i: number): bigint => {
    try {
      return u64Of(f[i]);
    } catch {
      return bad();
    }
  };
  b(0, 32);
  if (!eq(b(1, 32), EMPTY_UNCLE_HASH)) bad();
  b(2, 20);
  const stateRoot = b(3, 32);
  b(4, 32);
  b(5, 32);
  b(6, 256);
  if (b(7).length !== 0) bad();
  const number = int(8);
  int(9);
  int(10);
  int(11);
  if (b(12).length > 32) bad();
  b(13, 32);
  b(14, 8);
  if (int(15) === 0n) bad();
  if (!eq(b(16, 32), EMPTY_TRIE_ROOT) || int(17) !== 0n || int(18) !== 0n) bad();
  b(19, 32);
  if (profile.fields === 21) b(20, 32);
  return { stateRoot, number };
}
