/**
 * The lineage relation (protocol 6, bft-core docs/design/bridge-split-lineage-spec.md section 3, Go `bridgeprofile/lineage.go`): a
 * redeemed part is a token whose mint justification is either the lock reason (the root) or a split reason carrying the burned
 * parent token. Verification starts at the root and descends: every token's complete history is checked as in the protocol 5
 * relation, a parent ends in a split burn that commits a manifest, and every child is an allocation of that manifest. Depth 0 is an
 * ordinary full redemption.
 */
import { eq } from './bytes.js';
import type { Deployment } from './deployment.js';
import { fail } from './errors.js';
import {
  checkJustification, checkMintData, checkReturn, checkStep, decodeHistory, mintSourceHash, minterKey, predBytes, resultState,
  type History, type Leaf, type Outcome, type Transfer,
} from './history.js';
import { COMPOSED_HISTORY, PRED_BURN, PRED_SIGNATURE, TAG_MINT_LOCK, TAG_SPLIT_JUSTIFICATION, type HistoryBounds } from './limits.js';
import { H, burnId, deriveSalt, deriveTokenId, lockDigest, lockRecord, nullifier } from './profile.js';
import {
  beToBigint, decodeSplitJustification, decodeSplitManifest, justificationTag, splitManifestBytes, splitOutputCommitment,
  verifySumProof, type SplitJustification,
} from './split.js';
import { decodeToken, projectSdkToken } from './sdktoken.js';
import { parseKey } from './unlock.js';

// Work charges of the lineage walk (trial values, spec section 6), each taken before the work it pays for.
/** Scanning and hashing one nested byte: the outer mint and every justification descended into. */
export const SPLIT_PER_BYTE = 16;
/** One allocation proof: the commitment and the leaf hash, then each node hash. */
export const SPLIT_EDGE_BASE = 20_000;
export const SPLIT_PER_STEP = 1_500;
/** The composition's per-item price, charged for every justification descended into (gas.ts `COMPOSE_PER_ITEM`). */
const PER_ITEM = 20;

/** One token of a verified lineage, root first. */
export interface LevelInfo {
  tokenId: Uint8Array;
  amount: Uint8Array;
  /** certified leaves the token contributes: its mint and every transfer */
  leaves: number;
}

/**
 * A verified redemption: the root's identity (words 3 to 8 of BRIDGE_COMPOSE_V2), the part's return (releaseTo, nullifier), every
 * leaf in root-to-part order, the part and the depth. `splitGas` is the walk's byte, item and edge charge beyond the protocol 5
 * schedule; the ancestors' leaves are in that schedule's `L` (one leaf proof per leaf of the whole lineage).
 */
export interface LineageOutcome extends Outcome {
  partTokenId: Uint8Array;
  partAmount: Uint8Array;
  depth: number;
  levels: LevelInfo[];
  splitGas: number;
}

interface LevelState {
  id: Uint8Array;
  amount: Uint8Array;
  nonce: bigint;
  leaves: Leaf[];
  manifestRoot?: Uint8Array;
}

/** The return operation: `history` is the redeemed part's projection; its ancestry is read from the exact bytes of its mint reason. */
export async function verifyLineageReturn(dep: Deployment, history: Uint8Array, lim: HistoryBounds = COMPOSED_HISTORY): Promise<LineageOutcome> {
  const h = decodeHistory(history, lim);
  if (h.transfers.length === 0) fail('ErrNoTransfers');
  return verifyLineage(dep, h);
}

/** The walk (part first), then the verification (root first). */
export async function verifyLineage(dep: Deployment, h: History): Promise<LineageOutcome> {
  const chain: History[] = [h];
  const just: SplitJustification[] = []; // just[i] is chain[i]'s reason; chain[i+1] is its burned token
  let splitGas = SPLIT_PER_BYTE * h.mintRaw.length;
  for (let cur = h; ;) {
    const tag = justificationTag(cur.mint.justification);
    if (tag === null) fail('ErrMintJustif');
    if (tag === TAG_MINT_LOCK) break;
    if (tag !== TAG_SPLIT_JUSTIFICATION) fail('ErrMintJustif');
    const j = cur.mint.justification as Uint8Array;
    splitGas += SPLIT_PER_BYTE * j.length;
    const sj = decodeSplitJustification(j);
    splitGas += PER_ITEM * sj.items;
    const parent = projectSdkToken(decodeToken(sj.token));
    just.push(sj);
    chain.push(parent);
    cur = parent;
  }

  const d = chain.length - 1;
  const ch = dep.cfgHash;
  const seen = new Set<string>();
  const out: LineageOutcome = {
    cfg: ch, nonce: 0n, amount: new Uint8Array(0), tokenId: new Uint8Array(32), salt: new Uint8Array(32), firstPredicateHash: new Uint8Array(32),
    lockDigest: new Uint8Array(32), releaseTo: new Uint8Array(20), nullifier: new Uint8Array(32), leaves: [],
    partTokenId: new Uint8Array(32), partAmount: new Uint8Array(0), depth: d, levels: [], splitGas: 0,
  };
  let parent: LevelState | undefined;
  for (let i = d; i >= 0; i--) {
    const lv = await verifyLevel(dep, chain[i], i === d, seen);
    if (i < d) splitGas += checkSplitEdge(parent!, lv, chain[i], just[i]);
    out.leaves.push(...lv.leaves);
    out.levels.push({ tokenId: lv.id, amount: lv.amount, leaves: lv.leaves.length });
    const last = lv.leaves[lv.leaves.length - 1];
    const lastT = chain[i].transfers[chain[i].transfers.length - 1];
    if (i === 0) {
      const rr = { ...out, amount: lv.amount };
      checkReturn(dep, rr, lastT);
      out.releaseTo = rr.releaseTo;
      out.nullifier = nullifier(ch, burnId(last.sid, last.txHash));
      if (eq(out.nullifier, new Uint8Array(32))) fail('ErrZeroDigest');
      out.partTokenId = lv.id;
      out.partAmount = lv.amount;
    } else {
      checkSplitBurn(lastT, lv);
    }
    if (i === d) {
      const m = chain[i].mint;
      out.nonce = lv.nonce;
      out.salt = m.salt;
      out.tokenId = lv.id;
      out.amount = lv.amount;
      out.firstPredicateHash = H(predBytes(m.recipient));
      out.lockDigest = lockDigest(ch, lv.nonce, lockRecord(dep.cfg.zeroAddress, dep.cfg.ty, dep.cfg.aid, lv.amount, lv.id, out.firstPredicateHash));
      if (eq(out.lockDigest, new Uint8Array(32))) fail('ErrZeroDigest');
    }
    parent = lv;
  }
  out.splitGas = splitGas;
  return out;
}

/**
 * One token's mint and complete transfer history as in the protocol 5 relation, except the terminal transfer, which the caller
 * classifies. A root's mint reason is the lock reason with the derived salt; a child's is the split reason, checked against its
 * parent by {@link checkSplitEdge}, and its salt is free (its ID derives from it).
 */
async function verifyLevel(dep: Deployment, h: History, root: boolean, seen: Set<string>): Promise<LevelState> {
  const cfg = dep.cfg;
  const m = h.mint;
  if (m.network !== cfg.network || m.recipient.type !== PRED_SIGNATURE) fail('ErrMintShape');
  if (!eq(m.ty, cfg.ty)) fail('ErrMintType');
  let nonce = 0n;
  if (root) {
    nonce = checkJustification(dep, m.justification);
    if (!eq(m.salt, deriveSalt(dep.cfgHash, nonce))) fail('ErrMintSalt');
  }
  const id = deriveTokenId(m.salt, cfg.network);
  const amount = checkMintData(dep, m.data);
  if (h.transfers.length === 0) fail('ErrNoTransfers');
  const mk = minterKey(id);
  const h0 = mintSourceHash(id);
  const leaves: Leaf[] = [await checkStep({ type: PRED_SIGNATURE, params: mk }, h0, h.mintRaw, m.expiresAt, h.mintCd, h.mintT, mk, seen)];
  let state = resultState(h0, id);
  let owner = m.recipient;
  for (let i = 0; i < h.transfers.length; i++) {
    const t = h.transfers[i];
    // the owner is a signature predicate: the mint recipient or the previous intermediate recipient
    leaves.push(await checkStep(owner, state, h.transfersRaw[i], t.expiresAt, h.cds[i], h.times[i], parseKey(owner.params), seen));
    if (i < h.transfers.length - 1) {
      if (t.recipient.type !== PRED_SIGNATURE) fail('ErrBurnNotFinal');
      if (t.data !== null) fail('ErrTransferData');
    }
    state = resultState(state, t.mask);
    owner = t.recipient;
  }
  return { id, amount, nonce, leaves };
}

/**
 * A parent's final transfer burns exactly its manifest: `Burn(SHA-256(b_M))` with `b_M` the transfer's data. A return burn fails here
 * (its data is a return reason), so a token cannot be both returned and split.
 */
function checkSplitBurn(t: Transfer, lv: LevelState): void {
  if (t.recipient.type !== PRED_BURN || t.data === null) fail('ErrSplitBurn');
  const data = t.data as Uint8Array;
  const root = decodeSplitManifest(data);
  const bytes = splitManifestBytes(root);
  if (!eq(t.recipient.params, H(bytes)) || !eq(bytes, data)) fail('ErrSplitBurn');
  lv.manifestRoot = root;
}

/**
 * One edge: the child's allocation proof against the parent's manifest root with the child's recomputed commitment, and the
 * reconstructed root sum equal to the parent's authenticated amount (value conservation). Network and type equality follow from both
 * mints being checked against the configuration. Returns the edge's charge.
 */
function checkSplitEdge(parent: LevelState, child: LevelState, h: History, sj: SplitJustification): number {
  const m = h.mint;
  const d = splitOutputCommitment(parent.id, m.network, predBytes(m.recipient), m.salt, child.id, m.ty, m.data as Uint8Array);
  const sum = verifySumProof(sj.proof, child.id, d, beToBigint(child.amount), parent.manifestRoot!);
  if (sum === null) fail('ErrSplitProof');
  if (sum !== beToBigint(parent.amount)) fail('ErrSplitSum');
  return SPLIT_EDGE_BASE + SPLIT_PER_STEP * sj.proof.length;
}
