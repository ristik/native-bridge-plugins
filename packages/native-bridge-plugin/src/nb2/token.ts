/**
 * The SDK token wire (`protocol/interop.md` "SDK wire", unchanged; bft-core `nb2ref/token.go`):
 *
 *   P     = tag(39032, [1, b(encode_uint(type)), b(params)])
 *   M     = tag(39041, [2, network, P0, b(salt32), b(ty32), b(J), b(data), e])
 *   T     = tag(39045, [2, Pnext, b(mask32), dataOrNull, e])
 *   CD    = tag(39031, [2, Psource, b(sourceHash32), b(txHash32), e, b(unlock65)])
 *   Token = tag(39040, [2, [M, proof0], [[T1, proof1], ...]])
 *   proof = tag(39033, [1, CD, t, b(bitmap32 || siblings32...), UC])
 *
 * Decoding fails with the 14.1 encoding rules; a predicate outside the profile is `Predicate`.
 */
import { concat } from '../bytes.js';
import {
  MAX_U64, array, ascii, bstr, bytesN, cArr, cBytes, cDeadline, cNull, cNullOr, cTag, cUint, deadline, isBytes, isTag, isUint, nullableBytes,
  raw, scanNative, tagContent, uintIn, version, type Deadline, type Item,
} from './cbor.js';
import { TAG } from './config.js';
import { HU, imprint, parseKey } from './crypto.js';
import { fail } from './errors.js';

export const TX_VERSION = 2n;
export const CERT_VERSION = 2n;
export const TOKEN_VERSION = 2n;
export const INCLUSION_VERSION = 1n;
export const VALUE_VERSION = 1n;
export const ENGINE_BUILTIN = 1n;
export const PRED_SIGNATURE = 1n;
export const PRED_BURN = 2n;

export interface Predicate { type: bigint; params: Uint8Array }

export const encodePredicate = (p: Predicate): Uint8Array => cTag(TAG.predicate, cArr(cUint(ENGINE_BUILTIN), cBytes(cUint(p.type)), cBytes(p.params)));
export const signaturePredicate = (key33: Uint8Array): Predicate => ({ type: PRED_SIGNATURE, params: key33 });
export const burnPredicate = (reasonHash: Uint8Array): Predicate => ({ type: PRED_BURN, params: reasonHash });

function decodePredicate(it: Item): Predicate {
  const k = array(tagContent(it, TAG.predicate), 3);
  if (!isUint(k[0]) || !isBytes(k[1]) || !isBytes(k[2])) fail('Shape');
  if (k[0].arg !== ENGINE_BUILTIN) fail('Predicate');
  const code = k[1].data!;
  if (code.length !== 1 || (code[0] !== 1 && code[0] !== 2)) fail('Predicate');
  const p: Predicate = { type: BigInt(code[0]), params: k[2].data! };
  if (p.type === PRED_SIGNATURE) parseKey(p.params);
  else if (p.params.length !== 32) fail('Predicate');
  return p;
}

export interface MintTx {
  network: number;
  recipient: Predicate;
  salt: Uint8Array;
  type: Uint8Array;
  justification: Uint8Array | null;
  data: Uint8Array | null;
  deadline: Deadline;
}

export const encodeMint = (m: MintTx): Uint8Array => cTag(TAG.mint, cArr(cUint(TX_VERSION), cUint(m.network), encodePredicate(m.recipient),
  cBytes(m.salt), cBytes(m.type), cNullOr(m.justification), cNullOr(m.data), cDeadline(m.deadline)));

export interface TransferTx { recipient: Predicate; mask: Uint8Array; data: Uint8Array | null; deadline: Deadline }

export const encodeTransfer = (t: TransferTx): Uint8Array =>
  cTag(TAG.transfer, cArr(cUint(TX_VERSION), encodePredicate(t.recipient), cBytes(t.mask), cNullOr(t.data), cDeadline(t.deadline)));

export interface Certification { source: Predicate; sourceHash: Uint8Array; txHash: Uint8Array; deadline: Deadline; unlock: Uint8Array }

export const encodeCertification = (c: Certification): Uint8Array => cTag(TAG.certification, cArr(cUint(CERT_VERSION), encodePredicate(c.source),
  cBytes(c.sourceHash), cBytes(c.txHash), cDeadline(c.deadline), cBytes(c.unlock)));

export interface InclusionProof { cd: Certification; t: bigint; bitmap: Uint8Array; siblings: Uint8Array[]; uc: Uint8Array }

export const encodeProof = (p: InclusionProof): Uint8Array =>
  cTag(TAG.inclusion, cArr(cUint(INCLUSION_VERSION), encodeCertification(p.cd), cUint(p.t), cBytes(concat(p.bitmap, ...p.siblings)), p.uc));

export interface Token {
  mint: MintTx;
  mintProof: InclusionProof;
  transfers: TransferTx[];
  proofs: InclusionProof[];
  /** The exact transaction bytes, as decoded. */
  mintRaw: Uint8Array;
  transfersRaw: Uint8Array[];
}

export function encodeToken(t: Token): Uint8Array {
  const pairs = t.transfers.map((tr, i) => cArr(t.transfersRaw[i] ?? encodeTransfer(tr), encodeProof(t.proofs[i])));
  return cTag(TAG.token, cArr(cUint(TOKEN_VERSION), cArr(t.mintRaw, encodeProof(t.mintProof)), cArr(...pairs)));
}

/** Strictly decode a token from its exact bytes. */
export function decodeToken(b: Uint8Array): Token {
  return decodeTokenItem(scanNative(b), b);
}

export function decodeTokenItem(it: Item, b: Uint8Array): Token {
  const c = array(tagContent(it, TAG.token), 3);
  version(c[0], TOKEN_VERSION);
  const g = array(c[1], 2);
  if (c[2].major !== 4) fail('Shape');
  const mint = decodeMint(g[0]);
  const mintRaw = raw(b, g[0]);
  const mintProof = decodeProof(g[1], b);
  const t: Token = { mint, mintProof, transfers: [], proofs: [], mintRaw, transfersRaw: [] };
  for (const p of c[2].kids) {
    const k = array(p, 2);
    const tx = decodeTransfer(k[0]);
    const pr = decodeProof(k[1], b);
    t.transfers.push(tx);
    t.proofs.push(pr);
    t.transfersRaw.push(raw(b, k[0]));
  }
  return t;
}

function decodeMint(it: Item): MintTx {
  const k = array(tagContent(it, TAG.mint), 8);
  version(k[0], TX_VERSION);
  const network = Number(uintIn(k[1], 1n, 65535n));
  const recipient = decodePredicate(k[2]);
  const salt = bytesN(k[3], 32);
  const type = bytesN(k[4], 32);
  const justification = nullableBytes(k[5]);
  const data = nullableBytes(k[6]);
  return { network, recipient, salt, type, justification, data, deadline: deadline(k[7]) };
}

function decodeTransfer(it: Item): TransferTx {
  const k = array(tagContent(it, TAG.transfer), 5);
  version(k[0], TX_VERSION);
  const recipient = decodePredicate(k[1]);
  const mask = bytesN(k[2], 32);
  const data = nullableBytes(k[3]);
  return { recipient, mask, data, deadline: deadline(k[4]) };
}

function decodeCD(it: Item): Certification {
  const k = array(tagContent(it, TAG.certification), 6);
  version(k[0], CERT_VERSION);
  const source = decodePredicate(k[1]);
  const sourceHash = bytesN(k[2], 32);
  const txHash = bytesN(k[3], 32);
  const dl = deadline(k[4]);
  return { source, sourceHash, txHash, deadline: dl, unlock: bstr(k[5]) };
}

const MAX_PROOF_UC_BYTES = 24 << 10;

function popcount(b: Uint8Array): number {
  let n = 0;
  for (let x of b) for (; x; x &= x - 1) n++;
  return n;
}

function decodeProof(it: Item, b: Uint8Array): InclusionProof {
  const k = array(tagContent(it, TAG.inclusion), 5);
  version(k[0], INCLUSION_VERSION);
  const cd = decodeCD(k[1]);
  const t = uintIn(k[2], 0n, MAX_U64);
  const path = bstr(k[3]);
  if (path.length < 32 || path.length % 32 !== 0) fail('Length');
  const bitmap = path.subarray(0, 32);
  const pop = popcount(bitmap);
  if (path.length !== 32 + 32 * pop) fail('Length');
  const siblings: Uint8Array[] = [];
  for (let i = 0; i < pop; i++) siblings.push(path.subarray(32 + 32 * i, 64 + 32 * i));
  if (!isTag(k[4])) fail('Shape');
  if (k[4].end - k[4].start > MAX_PROOF_UC_BYTES) fail('InputTooLarge');
  return { cd, t, bitmap, siblings, uc: raw(b, k[4]) };
}

/** sid = H(C(Psource, b(sourceHash32))). */
export const stateId = (source: Predicate, sourceHash: Uint8Array): Uint8Array => HU(cArr(encodePredicate(source), cBytes(sourceHash)));
/** The output state H(C(b(I(sourceHash)), b(mask))); a mint's mask is the token ID. */
export const resultState = (sourceHash: Uint8Array, mask: Uint8Array): Uint8Array => HU(cArr(cBytes(imprint(sourceHash)), cBytes(mask)));
/** v = H(C(b(txHash32), t)). */
export const leafValue = (txHash: Uint8Array, t: bigint): Uint8Array => HU(cArr(cBytes(txHash), cUint(t)));
/** id = H(C(b(salt), network)). */
export const tokenIdOf = (salt: Uint8Array, network: number): Uint8Array => HU(cArr(cBytes(salt), cUint(network)));
const TOKENID_SUFFIX = HU(ascii('TOKENID'));
/** h0 = H(C(b(id), b(H("TOKENID")))). */
export const mintSourceHash = (id: Uint8Array): Uint8Array => HU(cArr(cBytes(id), cBytes(TOKENID_SUFFIX)));
/** tag(39050, [1, [[b(aid32), b(v)]], null]). */
export const valueData = (aid: Uint8Array, v: bigint | Uint8Array): Uint8Array => {
  const vb = typeof v === 'bigint' ? (v === 0n ? new Uint8Array() : bigBytes(v)) : v;
  return cTag(TAG.value, cArr(cUint(VALUE_VERSION), cArr(cArr(cBytes(aid), cBytes(vb))), cNull));
};
const bigBytes = (v: bigint): Uint8Array => {
  const out: number[] = [];
  for (let x = v; x > 0n; x >>= 8n) out.unshift(Number(x & 0xffn));
  return Uint8Array.from(out);
};
