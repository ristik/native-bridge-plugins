import { ShardId } from '@unicitylabs/state-transition-sdk/lib/api/bft/ShardId.js';

import { concat, eq, toHex } from '../bytes.js';
import {
  amount, array, ascii, bytesN, cAmount, cArr, cBytes, cTag, cUint, isUint, scanOne, tagContent, u256, version, type Item,
} from './cbor.js';
import { ASSET_UCT, DOMAIN, MAX_SEGMENT, TAG, V2_VERSION, decodeConfig, deriveType, deriveCoin, domainOf, type Config, type Params } from './config.js';
import { HU, minterKey, parseKey, verifyUnlock } from './crypto.js';
import { verifyRootMint } from './deposit.js';
import { Nb2Error, fail, wrap } from './errors.js';
import { decodeSplitJustification, decodeSplitManifest, decodeSumProof, parentLink, splitOutputCommitment, verifySumProof } from './split.js';
import {
  PRED_BURN, PRED_SIGNATURE, VALUE_VERSION, decodeToken, encodeMint, encodeTransfer, lineageOf, encodePredicate, leafValue, mintSourceHash, resultState, signaturePredicate, stateId,
  tokenIdOf, type InclusionProof, type LineageLevel, type Predicate, type Token,
} from './token.js';
import { bindTrust, claimConsistency, decodeUc, inShard, ucCheck, type TrustInput } from './trust.js';
import type { Deadline } from './cbor.js';

/** The authenticated return tuple. */
export interface Verdict {
  domain: Uint8Array;
  eta: Uint8Array;
  minSegment: bigint;
  asset: Uint8Array;
  recipient: Uint8Array;
  amount: bigint;
}

/** The verifier's exact 192-byte return data. */
export function verdictAbi(v: Verdict): Uint8Array {
  return concat(v.domain, v.eta, u256(v.minSegment), v.asset, concat(new Uint8Array(12), v.recipient), u256(v.amount));
}

/** btid = H_U(C(b("UNICITY_NB2_BURN"), b(sidBurn), b(txHashBurn))). */
export const burnTransitionId = (sid: Uint8Array, txHash: Uint8Array): Uint8Array => HU(cArr(cBytes(ascii(DOMAIN.burn)), cBytes(sid), cBytes(txHash)));
/** eta = H_U(C(b("UNICITY_NB2_REDEMPTION"), b(D), b(btid))). */
export const redemptionId = (d: Uint8Array, btid: Uint8Array): Uint8Array => HU(cArr(cBytes(ascii(DOMAIN.redemption)), cBytes(d), cBytes(btid)));

/** R = tag(39052, [1, b(D), b(asset32), b(recipient20), b(v), a]). */
export interface ReturnData { d: Uint8Array; asset: Uint8Array; recipient: Uint8Array; amount: bigint; minIndex: bigint }

export const encodeReturnData = (r: ReturnData): Uint8Array =>
  cTag(TAG.segmentReturn, cArr(cUint(V2_VERSION), cBytes(r.d), cBytes(r.asset), cBytes(r.recipient), cAmount(r.amount), cUint(r.minIndex)));

/** The exported token is the flat evidence, including its exact signed records. */
export const evidenceOf = (token: Uint8Array): Uint8Array => token;
export const decodeEvidence = decodeToken;

export async function verifyReturn(gamma: Uint8Array, evidence: Uint8Array, t: TrustInput, p: Params): Promise<Verdict> {
  return verifyPart(decodeConfig(gamma, p), domainOf(gamma), t, decodeEvidence(evidence));
}

interface Level {
  id: Uint8Array; amount: bigint; lastSid: Uint8Array; lastTx: Uint8Array;
  owner: Predicate; state: Uint8Array;
}
interface Split { manifest: Uint8Array; link: Uint8Array; id: Uint8Array; amount: bigint }
interface LineageChecks { seen: Set<string>; claim: ReturnType<typeof claimConsistency> }

export async function verifyPart(c: Config, d: Uint8Array, t: TrustInput, part: Token): Promise<Verdict> {
  const { level, terminal } = await walk(c, d, t, part, 'return');
  const r = checkReturn(c, d, terminal, level);
  const btid = burnTransitionId(level.lastSid, level.lastTx);
  return { domain: d, eta: redemptionId(d, btid), minSegment: r.minIndex, asset: r.asset, recipient: r.recipient, amount: level.amount };
}

export interface Held { tokenId: Uint8Array; amount: bigint; owner: Predicate; state: Uint8Array }

export async function verifyHeld(c: Config, d: Uint8Array, t: TrustInput, part: Token): Promise<Held> {
  const { level } = await walk(c, d, t, part, 'held');
  return { tokenId: level.id, amount: level.amount, owner: level.owner, state: level.state };
}

/** Authenticate every level and the split spend before deriving a link for child signing. */
export async function verifySplit(c: Config, d: Uint8Array, t: TrustInput, part: Token): Promise<Split> {
  const { level, terminal } = await walk(c, d, t, part, 'split');
  return checkSplitBurn(d, terminal, level);
}

async function walk(c: Config, d: Uint8Array, t: TrustInput, part: Token, mode: 'held' | 'split' | 'return'): Promise<{ level: Level; terminal: LineageLevel }> {
  bindTrust(t, c);
  if (!eq(c.asset, ASSET_UCT) || !eq(c.ty, deriveType(c.network, c.rootGenesis, c.executionGenesis, c.chainId))
    || !eq(c.aid, deriveCoin(c.network, c.rootGenesis, c.executionGenesis, c.chainId))) fail('ConfigShape');
  const chain = lineageOf(part);
  const checks: LineageChecks = { seen: new Set(), claim: claimConsistency() };
  let parent: Split | null = null;
  let level: Level | undefined;
  for (let i = 0; i < chain.length; i++) {
    const tok = chain[i];
    const last = i === chain.length - 1;
    if (parent === null) {
      if (tok.allocation.length !== 0) fail('SplitProofShape');
      const { j } = await verifyRootMint(c, d, t, tok.mint);
      checks.claim(decodeUc(j.proof.uc), j.proof.uc);
    } else {
      checkSplitEdge(c, parent, tok);
    }
    level = await verifyLevel(c, t, tok, checks, last && mode === 'held');
    if (!last) parent = checkSplitBurn(d, tok, level);
  }
  return { level: level!, terminal: part };
}

export function parseMintData(c: Config, data: Uint8Array | null): bigint {
  if (data === null) fail('MintData');
  try {
    const v = array(tagContent(scanOne(data!), TAG.value), 3);
    version(v[0], VALUE_VERSION);
    if (!v[2].isNull) fail('MintData');
    const assets = v[1];
    if (assets.major !== 4 || assets.kids.length !== 1) fail('MintData');
    const pair = array(assets.kids[0], 2);
    if (!eq(bytesN(pair[0], 32), c.aid)) fail('MintData');
    return amount(pair[1]);
  } catch {
    return fail('MintData');
  }
}

async function verifyLevel(c: Config, t: TrustInput, tok: LineageLevel, checks: LineageChecks, held = false): Promise<Level> {
  const m = tok.mint;
  if (!eq(encodeMint(m), tok.mintRaw) || tok.transfers.length !== tok.transfersRaw.length || tok.transfers.length !== tok.proofs.length) fail('CDMismatch');
  if (m.network !== c.network || m.recipient.type !== PRED_SIGNATURE) fail('MintShape');
  if (!eq(m.type, c.ty)) fail('MintType');
  const amt = parseMintData(c, m.data);
  if (tok.transfers.length === 0 && !held) fail('NoTransfers');
  const id = tokenIdOf(m.salt, m.network);
  const lv: Level = { id, amount: amt, lastSid: new Uint8Array(32), lastTx: new Uint8Array(32), owner: m.recipient, state: new Uint8Array(32) };
  const h0 = mintSourceHash(id);
  await checkStep(c, t, signaturePredicate(minterKey(id)), h0, tok.mintRaw, m.deadline, tok.mintProof, checks);
  let state = resultState(h0, id);
  let owner = m.recipient;
  for (let i = 0; i < tok.transfers.length; i++) {
    const tr = tok.transfers[i];
    if (!eq(encodeTransfer(tr), tok.transfersRaw[i])) fail('CDMismatch');
    const { sid, txHash } = await checkStep(c, t, owner, state, tok.transfersRaw[i], tr.deadline, tok.proofs[i], checks);
    lv.lastSid = sid;
    lv.lastTx = txHash;
    if (i < tok.transfers.length - 1 || held) {
      if (tr.recipient.type !== PRED_SIGNATURE) fail('BurnNotFinal');
      if (tr.data !== null) fail('TransferData');
    }
    state = resultState(state, tr.mask);
    owner = tr.recipient;
  }
  return { ...lv, owner, state };
}

const sameDeadline = (a: Deadline, b: Deadline): boolean => a === b;

async function checkStep(
  c: Config, t: TrustInput, source: Predicate, sourceHash: Uint8Array, txRaw: Uint8Array, e: Deadline, p: InclusionProof, checks: LineageChecks,
): Promise<{ sid: Uint8Array; txHash: Uint8Array }> {
  const cd = p.cd;
  const txHash = HU(txRaw);
  if (!eq(encodePredicate(cd.source), encodePredicate(source)) || !eq(cd.sourceHash, sourceHash) || !eq(cd.txHash, txHash)) fail('CDMismatch');
  if (!sameDeadline(cd.deadline, e)) fail('DeadlineMismatch');
  if (source.type !== PRED_SIGNATURE) fail('BurnNotFinal');
  try {
    parseKey(source.params);
  } catch {
    fail('BurnNotFinal');
  }
  verifyUnlock(source.params, sourceHash, txHash, cd.unlock);
  if (e !== null && p.t >= e) fail('DeadlineExpired');
  const sid = stateId(source, sourceHash);
  const key = toHex(sid);
  if (checks.seen.has(key)) fail('RepeatedSID');
  checks.seen.add(key);
  await verifyInclusion(c, t, sid, leafValue(txHash, p.t), p, checks.claim);
  return { sid, txHash };
}

/** Validate a newly returned certificate for a request already matched by certifyChecked. */
export async function verifyCertifiedStep(c: Config, t: TrustInput, tx: Uint8Array, proof: InclusionProof): Promise<void> {
  bindTrust(t, c);
  await checkStep(c, t, proof.cd.source, proof.cd.sourceHash, tx, proof.cd.deadline, proof, { seen: new Set(), claim: claimConsistency() });
}

/**
 * One aggregator inclusion proof: the UC (its encoding, its epoch's entry, partition `aggregatorPartition` and its own shard, the folds
 * and the quorum), the shard owning the state ID, the RSMT membership of (sid, v) under the certified state root (`InclusionProof`),
 * and t <= IR.timestamp of that UC (`ReferenceTime`).
 */
async function verifyInclusion(c: Config, t: TrustInput, sid: Uint8Array, value: Uint8Array, p: InclusionProof, claim: LineageChecks['claim']): Promise<void> {
  const uc = decodeUc(p.uc);
  const shard: ShardId = uc.shardTreeCertificate.shard;
  await ucCheck(t, uc, c.aggregatorPartition, shard.encode());
  claim(uc, p.uc);
  if (!inShard(shard, sid)) fail('InclusionProof', 'state ID outside the certificate\'s shard');
  const root = uc.inputRecord.nullableHash;
  if (root === null || root.length !== 32 || !rsmtMember(root, sid, value, p.bitmap, p.siblings)) fail('InclusionProof');
  if (p.t > uc.inputRecord.timestamp) fail('ReferenceTime');
}

const rsmtLeaf = (key: Uint8Array, value: Uint8Array): Uint8Array => HU(Uint8Array.of(0x00), key, value);
const rsmtNode = (l: Uint8Array, r: Uint8Array, depth: number, region: Uint8Array): Uint8Array => HU(Uint8Array.of(0x01, depth), region, l, r);
const keyBitAt = (key: Uint8Array, pos: number): number => (key[pos >> 3] >> (7 - (pos & 7))) & 1;
function prefixRegion(key: Uint8Array, depth: number): Uint8Array {
  const region = new Uint8Array(32);
  const full = depth >> 3;
  const partial = depth & 7;
  region.set(key.subarray(0, full));
  if (partial !== 0) region[full] = key[full] & ((0xff << (8 - partial)) & 0xff);
  return region;
}

/** Fold (key, value) along the path (siblings root to leaf, bitmap bit d MSB-first) to `root`: the generic RSMT membership. */
export function rsmtMember(root: Uint8Array, key: Uint8Array, value: Uint8Array, bitmap: Uint8Array, siblings: Uint8Array[]): boolean {
  if (root.every((x) => x === 0)) return false;
  let h = rsmtLeaf(key, value);
  let idx = siblings.length;
  for (let d = 255; d >= 0; d--) {
    if ((bitmap[d >> 3] & (0x80 >> (d & 7))) === 0) continue;
    idx--;
    if (idx < 0) return false;
    const sib = siblings[idx];
    const region = prefixRegion(key, d);
    h = keyBitAt(key, d) === 1 ? rsmtNode(sib, h, d, region) : rsmtNode(h, sib, d, region);
  }
  return idx === 0 && eq(h, root);
}

/** A parent's terminal transfer burns exactly its manifest; a return burn fails here, so a token cannot both split and return. */
function checkSplitBurn(d: Uint8Array, tok: LineageLevel, lv: Level): Split {
  const last = tok.transfers[tok.transfers.length - 1];
  if (last.recipient.type !== PRED_BURN || last.data === null) fail('SplitBurn');
  const manifest = decodeSplitManifest(last.data);
  if (!eq(last.recipient.params, HU(last.data))) fail('SplitBurn');
  return { manifest, link: parentLink(d, lv.id, lv.lastSid, lv.lastTx, manifest, lv.amount), id: lv.id, amount: lv.amount };
}

function checkSplitEdge(c: Config, parent: Split, tok: LineageLevel): void {
  if (tok.mint.justification === null || !eq(decodeSplitJustification(tok.mint.justification), parent.link)) fail('SplitJustif');
  const id = tokenIdOf(tok.mint.salt, tok.mint.network);
  const data = splitOutputCommitment(parent.id, tok.mint);
  const sum = verifySumProof(decodeSumProof(tok.allocation), id, data, parseMintData(c, tok.mint.data), parent.manifest);
  if (sum === null) fail('SplitProof');
  if (sum !== parent.amount) fail('SplitSum');
}

function checkReturn(c: Config, d: Uint8Array, part: LineageLevel, lv: Level): ReturnData {
  const last = part.transfers[part.transfers.length - 1];
  if (last.recipient.type !== PRED_BURN) fail('NotBurn');
  const r = decodeReturnData(last.data);
  if (r.minIndex > MAX_SEGMENT) fail('ReturnIndex');
  if (!eq(r.d, d)) fail('ReturnDomain');
  if (!eq(r.asset, ASSET_UCT)) fail('ReturnAsset');
  if (r.amount !== lv.amount) fail('ReturnAmount');
  if (r.recipient.every((x) => x === 0) || eq(r.recipient, c.vault)) fail('ReturnRecipient');
  if (!eq(last.recipient.params, HU(last.data!))) fail('BurnReason');
  return r;
}

/** Strictly decode R; any failure to be exactly a tag(39052, ...) R is `ReturnData`. */
export function decodeReturnData(b: Uint8Array | null): ReturnData {
  if (b === null) fail('ReturnData');
  let root: Item;
  try {
    root = scanOne(b!);
  } catch (e) {
    return wrap('ReturnData', e);
  }
  let k: Item[];
  try {
    k = array(tagContent(root, TAG.segmentReturn), 6);
    version(k[0], V2_VERSION);
  } catch {
    return fail('ReturnData');
  }
  try {
    const out: ReturnData = { d: bytesN(k[1], 32), asset: bytesN(k[2], 32), recipient: bytesN(k[3], 20), amount: 0n, minIndex: 0n };
    if (!isUint(k[5])) fail('ReturnData');
    out.amount = amount(k[4]);
    out.minIndex = k[5].arg;
    return out;
  } catch (e) {
    if (e instanceof Nb2Error && e.rule === 'ReturnData') throw e;
    return fail('ReturnData');
  }
}
