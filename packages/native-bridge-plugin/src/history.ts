/**
 * The compact history projection `C([M,CD0,t0],[[T1,CD1,t1],...])` and the pure token-semantics
 * relation for SDK 3.0.1 bytes. Projection tuples are not SDK certified-transaction tuples.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import type { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';

import { concat, eq, toHex } from './bytes.js';
import type { Deployment } from './deployment.js';
import { fail } from './errors.js';
import {
  MAX_AMOUNT_BYTES, MAX_SEMANTIC_BYTES, MAX_TRANSFERS, PRED_BURN, PRED_SIGNATURE, TAG_CERTIFICATION, TAG_MINT,
  TAG_PREDICATE, TAG_RETURN_REASON, TAG_TRANSFER, TAG_WALLET_VALUE,
} from './limits.js';
import { encodeJustification, encodeLockProof, parseJustification } from './lockproof.js';
import {
  H, arr, bs, burnId, deriveSalt, deriveTokenId, leafValue, lockDigest, lockRecord, nullifier, u, valueEnvelope,
} from './profile.js';
import {
  amount as amountItem, arrayOf, bytesAny, bytesN, nullableBytes, nullableUint, raw, scanOne, tagContent, uint,
  uintMax, version, type Item,
} from './scan.js';
import { parseKey, verifyUnlock } from './unlock.js';

export interface Pred {
  type: number;
  params: Uint8Array;
}

export const predBytes = (p: Pred): Uint8Array =>
  C.encodeTag(TAG_PREDICATE, arr(u(1), bs(C.encodeUnsignedInteger(BigInt(p.type))), bs(p.params)));

function decodePredicate(it: Item): Pred {
  const k = arrayOf(tagContent(it, TAG_PREDICATE), 3) ?? fail('ErrShape');
  if (k[0].kind !== 'uint') fail('ErrShape');
  else if (k[0].value !== 1n) fail('ErrPredicate');
  if (k[1].kind !== 'bytes' || k[2].kind !== 'bytes') fail('ErrShape');
  const code = (k[1] as { data: Uint8Array }).data;
  const params = (k[2] as { data: Uint8Array }).data;
  if (code.length !== 1 || (code[0] !== PRED_SIGNATURE && code[0] !== PRED_BURN)) fail('ErrPredicate');
  if (code[0] === PRED_SIGNATURE) parseKey(params);
  else if (params.length !== 32) fail('ErrPredicate');
  return { type: code[0], params };
}

/** A request deadline: null or an integer in [1, 2^64-1]. */
function deadline(it: Item): bigint | null {
  const e = nullableUint(it);
  return e === 0n ? fail('ErrIntRange') : e;
}

export interface Mint {
  network: number;
  recipient: Pred;
  salt: Uint8Array;
  ty: Uint8Array;
  justification: Uint8Array | null;
  data: Uint8Array | null;
  expiresAt: bigint | null;
}
export interface Transfer {
  recipient: Pred;
  mask: Uint8Array;
  data: Uint8Array | null;
  expiresAt: bigint | null;
}
export interface Cd {
  source: Pred;
  sourceHash: Uint8Array;
  txHash: Uint8Array;
  expiresAt: bigint | null;
  unlock: Uint8Array;
}

function decodeCd(it: Item): Cd {
  const k = arrayOf(tagContent(it, TAG_CERTIFICATION), 6) ?? fail('ErrShape');
  version(k[0], 2n);
  return { source: decodePredicate(k[1]), sourceHash: bytesN(k[2], 32), txHash: bytesN(k[3], 32), expiresAt: deadline(k[4]), unlock: bytesAny(k[5]) };
}

function decodeMint(it: Item): Mint {
  const k = arrayOf(tagContent(it, TAG_MINT), 8) ?? fail('ErrShape');
  version(k[0], 2n);
  return {
    network: Number(uintMax(k[1], 0xffffn)),
    recipient: decodePredicate(k[2]),
    salt: bytesN(k[3], 32),
    ty: bytesN(k[4], 32),
    justification: nullableBytes(k[5]),
    data: nullableBytes(k[6]),
    expiresAt: deadline(k[7]),
  };
}

function decodeTransfer(it: Item): Transfer {
  const k = arrayOf(tagContent(it, TAG_TRANSFER), 5) ?? fail('ErrShape');
  version(k[0], 2n);
  return { recipient: decodePredicate(k[1]), mask: bytesN(k[2], 32), data: nullableBytes(k[3]), expiresAt: deadline(k[4]) };
}

export interface History {
  mint: Mint;
  mintCd: Cd;
  mintT: bigint;
  transfers: Transfer[];
  cds: Cd[];
  times: bigint[];
  mintRaw: Uint8Array;
  transfersRaw: Uint8Array[];
}

/** Strictly decode `C([M,CD0,t0],[[T1,CD1,t1],...])`; the transfer count is bounded first. */
export function decodeHistory(b: Uint8Array): History {
  if (b.length > MAX_SEMANTIC_BYTES) fail('ErrInputTooLarge');
  const k = arrayOf(scanOne(b), 2) ?? fail('ErrShape');
  const head = arrayOf(k[0], 3) ?? fail('ErrShape');
  const list = arrayOf(k[1]) ?? fail('ErrShape');
  if (list.length > MAX_TRANSFERS) fail('ErrTooManyTx');
  const h: History = {
    mint: decodeMint(head[0]), mintRaw: raw(b, head[0]), mintCd: decodeCd(head[1]), mintT: uint(head[2]),
    transfers: [], cds: [], times: [], transfersRaw: [],
  };
  for (const p of list) {
    const tuple = arrayOf(p, 3) ?? fail('ErrShape');
    h.transfers.push(decodeTransfer(tuple[0]));
    h.cds.push(decodeCd(tuple[1]));
    h.times.push(uint(tuple[2]));
    h.transfersRaw.push(raw(b, tuple[0]));
  }
  return h;
}

export interface Leaf {
  sid: Uint8Array;
  txHash: Uint8Array;
  referenceTime: bigint;
  value: Uint8Array;
  expiresAt: bigint | null;
}

export interface Outcome {
  cfg: Uint8Array;
  nonce: bigint;
  amount: Uint8Array;
  tokenId: Uint8Array;
  salt: Uint8Array;
  firstPredicateHash: Uint8Array;
  lockDigest: Uint8Array;
  releaseTo: Uint8Array;
  nullifier: Uint8Array;
  leaves: Leaf[];
}

const ZERO32 = new Uint8Array(32);
const ZERO20 = new Uint8Array(20);
export const stateId = (source: Pred, sourceHash: Uint8Array): Uint8Array => H(arr(predBytes(source), bs(sourceHash)));
export const resultState = (sourceHash: Uint8Array, mask: Uint8Array): Uint8Array => H(arr(bs(concat(new Uint8Array(2), sourceHash)), bs(mask)));
const mintSourceHash = (id: Uint8Array): Uint8Array => H(arr(bs(id), bs(H(new TextEncoder().encode('TOKENID')))));

function minterKey(id: Uint8Array): Uint8Array {
  const sk = H(arr(bs(new TextEncoder().encode('I_AM_UNIVERSAL_MINTER_FOR_')), bs(id)));
  try {
    return secp256k1.getPublicKey(sk, true);
  } catch {
    return fail('ErrMinterKey');
  }
}

const amountOk = (a: Uint8Array): boolean => a.length > 0 && a.length <= MAX_AMOUNT_BYTES && a[0] !== 0;

const be = (b: Uint8Array): bigint => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);

/** `prepareLock`: validate a lock request and derive the values the vault compares with its own. */
export function prepareLock(dep: Deployment, n: bigint, amount: Uint8Array, p0: Uint8Array): Outcome {
  if (n === 0n || !amountOk(amount)) fail('ErrLockInput');
  if (p0.length > MAX_SEMANTIC_BYTES) fail('ErrInputTooLarge');
  const pred = decodePredicate(scanOne(p0));
  if (pred.type !== PRED_SIGNATURE || !eq(predBytes(pred), p0)) fail('ErrPredicate');
  const salt = deriveSalt(dep.cfgHash, n);
  const id = deriveTokenId(salt, dep.cfg.network);
  const first = H(p0);
  const digest = lockDigest(dep.cfgHash, n, lockRecord(dep.cfg.zeroAddress, dep.cfg.ty, dep.cfg.aid, amount, id, first));
  if (eq(digest, ZERO32)) fail('ErrZeroDigest');
  return { cfg: dep.cfgHash, nonce: n, amount, tokenId: id, salt, firstPredicateHash: first, lockDigest: digest, releaseTo: new Uint8Array(20), nullifier: new Uint8Array(32), leaves: [] };
}

/** Parse and cross-check the mint justification, returning the nonce. Structure only; the proof's
 * cryptography needs the trust input. */
export function checkJustification(dep: Deployment, j: Uint8Array | null): bigint {
  if (j === null) return fail('ErrMintJustif');
  let p;
  try {
    p = parseJustification(j);
  } catch (e) {
    const r = (e as { reason?: string }).reason;
    if (r === 'ErrInputTooLarge' || r === 'ErrProofTooLarge' || r === 'ErrTooDeep' || r === 'ErrTooManyItems') throw e;
    return fail('ErrMintJustif');
  }
  if (p.chainId !== dep.cfg.chainId || !eq(p.vault, dep.cfg.vault) || !eq(p.zero, dep.cfg.zeroAddress) || p.nonce === 0n) fail('ErrMintJustif');
  const proof = p.proof;
  const back = encodeJustification(p.chainId, p.vault, p.zero, p.nonce, encodeLockProof(proof));
  if (!eq(back, j)) fail('ErrMintJustif');
  return p.nonce;
}

/** Exactly `tag(39050,[1,[[b(aid),b(amount)]],null])`; returns the amount. */
export function checkMintData(dep: Deployment, d: Uint8Array | null): Uint8Array {
  if (d === null) return fail('ErrMintData');
  try {
    const k = arrayOf(tagContent(scanOne(d), TAG_WALLET_VALUE), 3) ?? fail('ErrMintData');
    version(k[0], 1n);
    const assets = arrayOf(k[1], 1) ?? fail('ErrMintData');
    const entry = arrayOf(assets[0], 2) ?? fail('ErrMintData');
    const aid = bytesN(entry[0], 32);
    if (!eq(aid, dep.cfg.aid) || k[2].kind !== 'null') fail('ErrMintData');
    const amount = amountItem(entry[1]);
    if (!eq(valueEnvelope(aid, amount), d)) fail('ErrMintData');
    return amount;
  } catch {
    return fail('ErrMintData');
  }
}

async function checkStep(
  source: Pred, sourceHash: Uint8Array, txRaw: Uint8Array, txDeadline: bigint | null, cd: Cd, t: bigint,
  key: Uint8Array, seen: Set<string>,
): Promise<Leaf> {
  if (!eq(predBytes(cd.source), predBytes(source)) || !eq(cd.sourceHash, sourceHash)) fail('ErrCDMismatch');
  const txHash = H(txRaw);
  if (!eq(cd.txHash, txHash) || cd.expiresAt !== txDeadline) fail('ErrCDMismatch');
  // For an explicit deadline the leaf must have been created strictly before it.
  if (txDeadline !== null && t >= txDeadline) fail('ErrDeadlineExpired');
  await verifyUnlock(key, sourceHash, txHash, cd.unlock);
  const sid = stateId(source, sourceHash);
  const hex = toHex(sid);
  if (seen.has(hex)) fail('ErrRepeatedSID');
  seen.add(hex);
  return { sid, txHash, referenceTime: t, value: leafValue(txHash, t), expiresAt: txDeadline };
}

/** The relation. `wantBurn` selects the return relation (terminal burn) or the receipt relation. */
export async function verifyHistory(dep: Deployment, hist: History, wantBurn: boolean): Promise<Outcome> {
  const cfg = dep.cfg;
  const ch = dep.cfgHash;
  const m = hist.mint;
  if (wantBurn && hist.transfers.length === 0) fail('ErrNoTransfers');
  if (m.network !== cfg.network || m.recipient.type !== PRED_SIGNATURE) fail('ErrMintShape');
  if (!eq(m.ty, cfg.ty)) fail('ErrMintType');
  const n = checkJustification(dep, m.justification);
  const salt = deriveSalt(ch, n);
  if (!eq(m.salt, salt)) fail('ErrMintSalt');
  const id = deriveTokenId(salt, cfg.network);
  const amount = checkMintData(dep, m.data);
  const first = H(predBytes(m.recipient));
  const digest = lockDigest(ch, n, lockRecord(cfg.zeroAddress, cfg.ty, cfg.aid, amount, id, first));
  if (eq(digest, ZERO32)) fail('ErrZeroDigest');
  const out: Outcome = { cfg: ch, nonce: n, amount, tokenId: id, salt, firstPredicateHash: first, lockDigest: digest, releaseTo: new Uint8Array(20), nullifier: new Uint8Array(32), leaves: [] };

  const mk = minterKey(id);
  const h0 = mintSourceHash(id);
  const seen = new Set<string>();
  out.leaves.push(await checkStep({ type: PRED_SIGNATURE, params: mk }, h0, hist.mintRaw, m.expiresAt, hist.mintCd, hist.mintT, mk, seen));
  let state = resultState(h0, id);
  let owner = m.recipient;
  for (let i = 0; i < hist.transfers.length; i++) {
    const t = hist.transfers[i];
    const last = i === hist.transfers.length - 1;
    const leaf = await checkStep(owner, state, hist.transfersRaw[i], t.expiresAt, hist.cds[i], hist.times[i], parseKey(owner.params), seen);
    out.leaves.push(leaf);
    if (last && wantBurn) {
      checkReturn(dep, out, t);
      out.nullifier = nullifier(ch, burnId(leaf.sid, leaf.txHash));
      if (eq(out.nullifier, ZERO32)) fail('ErrZeroDigest');
    } else {
      if (t.recipient.type !== PRED_SIGNATURE) fail(last ? 'ErrUnexpectedBurn' : 'ErrBurnNotFinal');
      if (t.data !== null) fail('ErrTransferData');
    }
    state = resultState(state, t.mask);
    owner = t.recipient;
  }
  return out;
}

function checkReturn(dep: Deployment, out: Outcome, t: Transfer): void {
  const cfg = dep.cfg;
  if (t.recipient.type !== PRED_BURN) fail('ErrNotBurn');
  if (t.data === null) fail('ErrReturnData');
  const data = t.data as Uint8Array;
  if (data.length > MAX_SEMANTIC_BYTES) fail('ErrInputTooLarge');
  const bad = <T>(f: () => T): T => {
    try {
      return f();
    } catch {
      return fail('ErrReturnData');
    }
  };
  const k = bad(() => arrayOf(tagContent(scanOne(data), TAG_RETURN_REASON), 11) ?? fail('ErrReturnData'));
  bad(() => version(k[0], 1n));
  if (bad(() => uint(k[1])) !== cfg.chainId) fail('ErrReturnData');
  const vault = bad(() => bytesN(k[2], 20));
  const zero = bad(() => bytesN(k[3], 20));
  const ty = bad(() => bytesN(k[4], 32));
  const aid = bad(() => bytesN(k[5], 32));
  const recip = bad(() => bytesN(k[6], 20));
  if (!eq(vault, cfg.vault) || !eq(zero, cfg.zeroAddress) || !eq(ty, cfg.ty) || !eq(aid, cfg.aid)) fail('ErrReturnData');
  let amt: Uint8Array;
  try {
    amt = amountItem(k[7]);
  } catch {
    return fail('ErrReturnAmount');
  }
  if (be(amt) !== be(out.amount)) fail('ErrReturnAmount');
  const zero2 = bad(() => bytesN(k[8], 20));
  const emptyOk = k[9].kind === 'bytes' && k[9].data.length === 0;
  const zeroOk = k[10].kind === 'uint' && k[10].value === 0n;
  if (!eq(zero2, cfg.zeroAddress) || !emptyOk || !zeroOk) fail('ErrReturnData');
  if (eq(recip, ZERO20) || eq(recip, cfg.vault)) fail('ErrReturnRecip');
  if (!eq(t.recipient.params, H(data))) fail('ErrBurnReason');
  out.releaseTo = recip;
}

/**
 * Export the compact history of an SDK token: the unchanged tagged transactions and certification
 * data with each original reference time `t`, and no inclusion proofs.
 */
export function projectToken(token: Token): Uint8Array {
  const pair = (certified: { toCBOR(): Uint8Array; inclusionProof: { certificationData: { toCBOR(): Uint8Array }; referenceTime: bigint } }): Uint8Array =>
    arr(CborDeserializer.decodeArray(certified.toCBOR(), 2)[0], certified.inclusionProof.certificationData.toCBOR(), u(certified.inclusionProof.referenceTime));
  return arr(pair(token.genesis), arr(...token.transactions.map(pair)));
}
