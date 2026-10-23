/**
 * The strict SDK token codec of the lineage relation (bft-core `bridgeprofile/sdktoken.go` and `certscan.go`): the whole token
 * `tag(39040,[2,[M,proof0],[[T1,proof1],...]])` and the inclusion proof `tag(39033,[1,CD,t,b(bitmap32||siblings32...),UC])`. The
 * relation reads an ancestor from these exact bytes (the burned parent inside a split justification) and verifies its projection.
 */
import { NativeError, fail } from './errors.js';
import { decodeCd, decodeMint, decodeTransfer, type Cd, type History, type Mint, type Transfer } from './history.js';
import {
  INCLUSION_VERSION, MAX_DECODED_TOKEN_BYTES, MAX_PROOF_UC_BYTES, TAG_INCLUSION, TAG_TOKEN, TOKEN_VERSION,
} from './limits.js';
import { nativeUcScan } from './resources.js';
import { arrayOf, raw, scanCounted, scanNative, tagContent, uintMax, version, type Item } from './scan.js';

/** B1's certificate byte cap (bft-core `b1ref.MaxUCBytes`). */
const B1_MAX_UC_BYTES = 24576;
/** The only seal signature width the SDK certificate codec accepts; native B1 also admits 64 bytes. */
const SDK_SIGNATURE_LENGTH = 65;

const TAG_UC = 39001n;
const CERT_FIELDS: readonly { index: number; tag: bigint; arity: number; required: number; kind: Item['kind'] }[] = [
  { index: 1, tag: 39002n, arity: 10, required: 5, kind: 'bytes' }, // input record: its summary value
  { index: 4, tag: 39003n, arity: 3, required: 2, kind: 'array' }, // shard tree certificate: its siblings
  { index: 5, tag: 39004n, arity: 3, required: 2, kind: 'array' }, // unicity tree certificate: its steps
  { index: 6, tag: 39005n, arity: 8, required: 7, kind: 'map' }, // seal: its signatures
];

/**
 * The bounded certificate scan every token-carried certificate passes before anything proportional to its contents: the native shape
 * and sublimit scan intersected with the SDK codec subset. Signatures and quorum stay the verifier's.
 */
export function scanCertificate(rawUc: Uint8Array): void {
  if (rawUc.length > B1_MAX_UC_BYTES) fail('ErrCertScan');
  let root: Item;
  try {
    root = scanNative(rawUc);
  } catch {
    return fail('ErrCertScan');
  }
  let uc: Item[] | null;
  try {
    uc = arrayOf(tagContent(root, TAG_UC), 7);
  } catch {
    return fail('ErrCertScan');
  }
  if (uc === null) return fail('ErrCertScan');
  for (const f of CERT_FIELDS) {
    let body: Item[] | null;
    try {
      body = arrayOf(tagContent(uc[f.index], f.tag), f.arity);
    } catch {
      return fail('ErrCertScan');
    }
    if (body === null || body[f.required].kind !== f.kind) fail('ErrCertScan');
  }
  const seal = (tagContent(uc[6], 39005n) as { kids: Item[] }).kids;
  const network = seal[1];
  if (network.kind !== 'uint' || network.value === 0n || network.value > 65535n) fail('ErrCertScan');
  const sigs = (seal[7] as { kids: Item[] }).kids;
  for (let i = 1; i < sigs.length; i += 2) {
    const sig = sigs[i];
    if (sig.kind !== 'bytes') fail('ErrCertScan');
    // 64 bytes (r||s) or 65 with an ignored recovery suffix, as both SDKs and native B1
    const n = (sig as { data: Uint8Array }).data.length;
    if (n !== SDK_SIGNATURE_LENGTH - 1 && n !== SDK_SIGNATURE_LENGTH) fail('ErrCertSigLength');
  }
  try {
    nativeUcScan(rawUc, B1_MAX_UC_BYTES);
  } catch (e) {
    if (e instanceof NativeError) fail('ErrCertScan');
    throw e;
  }
}

/** A certified inclusion proof; pending or uncertified responses are not proofs and have no encoding here. */
export interface InclusionProof {
  cd: Cd;
  /** the reference time: part of the certified leaf, never a UC timestamp */
  t: bigint;
  bitmap: Uint8Array;
  siblings: Uint8Array[];
  /** the canonical native certificate, an inline CBOR item */
  uc: Uint8Array;
}

/** A strictly decoded SDK token: its mint, transfers and proofs, with the exact transaction bytes. */
export interface SdkToken {
  mint: Mint;
  mintProof: InclusionProof;
  transfers: Transfer[];
  proofs: InclusionProof[];
  mintRaw: Uint8Array;
  transfersRaw: Uint8Array[];
}

const popcount = (b: Uint8Array): number => b.reduce((n, x) => {
  let c = 0;
  for (let v = x; v; v &= v - 1) c++;
  return n + c;
}, 0);

function decodeProof(it: Item, b: Uint8Array): InclusionProof {
  // Arity 5: version, CD, t, path, UC. All certified-leaf fields mandatory.
  const k = arrayOf(tagContent(it, TAG_INCLUSION), 5) ?? fail('ErrShape');
  version(k[0], INCLUSION_VERSION);
  const cd = decodeCd(k[1]);
  const t = uintMax(k[2], 0xffff_ffff_ffff_ffffn);
  if (k[3].kind !== 'bytes') fail('ErrShape');
  const path = (k[3] as { data: Uint8Array }).data;
  if (path.length < 32 || path.length % 32 !== 0) fail('ErrLength');
  const bitmap = path.subarray(0, 32);
  const pop = popcount(bitmap);
  if (path.length !== 32 + 32 * pop) fail('ErrLength');
  if (k[4].end - k[4].start > MAX_PROOF_UC_BYTES) fail('ErrInputTooLarge');
  if (k[4].kind !== 'tag') fail('ErrShape');
  const uc = raw(b, k[4]);
  // A certificate outside the native/SDK intersection is never projected: its structure here, its signatures and quorum later.
  scanCertificate(uc);
  const siblings: Uint8Array[] = [];
  for (let i = 0; i < pop; i++) siblings.push(path.subarray(32 + 32 * i, 64 + 32 * i));
  return { cd, t, bitmap, siblings, uc };
}

/**
 * Strictly decode an entire SDK token: every proof mandatory and complete; trailing bytes, extra slots and a separate
 * reference-time slot are refused. A token is bounded by its bytes alone: its transfers and items are those of the history the
 * composition streams.
 */
export function decodeToken(b: Uint8Array): SdkToken {
  if (b.length > MAX_DECODED_TOKEN_BYTES) fail('ErrInputTooLarge');
  const root = scanCounted(b, Number.MAX_SAFE_INTEGER, true).root;
  const c = arrayOf(tagContent(root, TAG_TOKEN), 3) ?? fail('ErrShape');
  version(c[0], TOKEN_VERSION);
  const g = arrayOf(c[1], 2) ?? fail('ErrShape');
  const list = arrayOf(c[2]) ?? fail('ErrShape');
  const t: SdkToken = { mint: decodeMint(g[0]), mintRaw: raw(b, g[0]), mintProof: decodeProof(g[1], b), transfers: [], proofs: [], transfersRaw: [] };
  for (const p of list) {
    const pair = arrayOf(p, 2) ?? fail('ErrShape');
    t.transfers.push(decodeTransfer(pair[0]));
    t.proofs.push(decodeProof(pair[1], b));
    t.transfersRaw.push(raw(b, pair[0]));
  }
  return t;
}

/** The B2 projection of a decoded token: the same tagged transactions and CDs, each `t` taken solely from its proof. */
export const projectSdkToken = (t: SdkToken): History => ({
  mint: t.mint,
  mintCd: t.mintProof.cd,
  mintT: t.mintProof.t,
  mintRaw: t.mintRaw,
  transfers: [...t.transfers],
  cds: t.proofs.map((p) => p.cd),
  times: t.proofs.map((p) => p.t),
  transfersRaw: [...t.transfersRaw],
});
