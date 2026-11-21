import { concat, concatBytes } from '../bytes.js';
import {
  MAX_U64, array, ascii, bstr, bytesN, cArr, cBytes, cDeadline, cNull, cNullOr, cTag, cUint, deadline, isBytes, isTag, isUint, nullableBytes,
  raw, scanNative, scanOne, tagContent, uintIn, version, type Deadline, type Item,
} from './cbor.js';
import { TAG } from './config.js';
import { HU, imprint, parseKey } from './crypto.js';
import { fail } from './errors.js';

export const TX_VERSION = 2n;
export const CERT_VERSION = 2n;
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

export interface LineageLevel {
  allocation: Uint8Array;
  mint: MintTx;
  mintProof: InclusionProof;
  transfers: TransferTx[];
  proofs: InclusionProof[];
  /** The exact transaction bytes, as decoded. */
  mintRaw: Uint8Array;
  transfersRaw: Uint8Array[];
}

export interface Token extends LineageLevel {
  ancestors: LineageLevel[];
}

export const lineageOf = (token: Token): LineageLevel[] => [...token.ancestors, token];

export const MAX_TRANSFER_PAIR = 40_960;
export const MAX_ROOT_MINT = 66_048;
export const MAX_CHILD_MINT = 512;
export const MAX_ALLOCATION = 20_480;
const FLAT_HEADER = Uint8Array.of(0x4e, 0x42, 0x32, 0x4c, 1, 1);

function width(value: number, size: number): Uint8Array {
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  if (size === 4) view.setUint32(0, value);
  else view.setBigUint64(0, BigInt(value));
  return out;
}

const blob = (bytes: Uint8Array): Uint8Array => concat(width(bytes.length, 4), bytes);

export function encodeLevel(level: LineageLevel): Uint8Array {
  const pairs = level.transfersRaw.map((tx, i) => cArr(tx, encodeProof(level.proofs[i])));
  return frameLevel(level.allocation, level.mintRaw, encodeProof(level.mintProof), pairs);
}

export function frameLevel(allocation: Uint8Array, mint: Uint8Array, proof: Uint8Array, pairs: Uint8Array[]): Uint8Array {
  return concatBytes([blob(allocation), blob(mint), blob(proof), width(pairs.length, 8), ...pairs.map(blob)]);
}

export function frameLineage(levels: Uint8Array[]): Uint8Array {
  return concatBytes([FLAT_HEADER, width(levels.length, 8), ...levels]);
}

export const encodeToken = (token: Token): Uint8Array => frameLineage(lineageOf(token).map(encodeLevel));

/** Import exact signed bytes. Counts drive reads only after checking remaining bytes. */
export function decodeToken(input: Uint8Array): Token {
  // Verification awaits historical authority, so keep the decoded signed bytes independent of the caller buffer.
  const b = Uint8Array.from(input);
  let offset = 0;
  const take = (len: number): Uint8Array => {
    if (len > b.length - offset) fail('Length');
    const result = b.subarray(offset, offset + len);
    offset += len;
    return result;
  };
  const number = (size: number): bigint => {
    const bytes = take(size);
    const v = new DataView(bytes.buffer, bytes.byteOffset, size);
    return size === 4 ? BigInt(v.getUint32(0)) : v.getBigUint64(0);
  };
  const framed = (max: number): Uint8Array => {
    const len = Number(number(4));
    if (len > max) fail('InputTooLarge');
    return take(len);
  };
  if (!take(FLAT_HEADER.length).every((byte, i) => byte === FLAT_HEADER[i])) fail('EvidenceShape');
  const n = number(8);
  if (n === 0n || n > BigInt(Math.floor((b.length - offset) / 20))) fail('EvidenceShape');
  const levels: LineageLevel[] = [];
  for (let i = 0; i < Number(n); i++) {
    const allocation = framed(i === 0 ? 0 : MAX_ALLOCATION);
    if (i !== 0 && allocation.length === 0) fail('SplitProofShape');
    const mintRaw = framed(i === 0 ? MAX_ROOT_MINT : MAX_CHILD_MINT);
    const mint = decodeMint(scanOne(mintRaw));
    const proofRaw = framed(40_960 - 8);
    const mintProof = decodeProof(scanNative(proofRaw), proofRaw);
    const count = number(8);
    if (count > BigInt(Math.floor((b.length - offset) / 4))) fail('Length');
    const level: LineageLevel = { allocation, mintRaw, mint, mintProof, transfersRaw: [], transfers: [], proofs: [] };
    for (let j = 0; j < Number(count); j++) {
      const pair = framed(MAX_TRANSFER_PAIR);
      const [tx, proof] = array(scanNative(pair), 2);
      level.transfersRaw.push(raw(pair, tx));
      level.transfers.push(decodeTransfer(tx));
      level.proofs.push(decodeProof(proof, pair));
    }
    levels.push(level);
  }
  if (offset !== b.length) fail('Trailing');
  return { ...levels.pop()!, ancestors: levels };
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
  return { source, sourceHash, txHash, deadline: dl, unlock: bytesN(k[5], 65) };
}

/** Decode the exact signed transfer and its separate certification request. */
export const parseTransfer = (raw: Uint8Array): TransferTx => decodeTransfer(scanNative(raw));
export const parseCertification = (raw: Uint8Array): Certification => decodeCD(scanNative(raw));

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
