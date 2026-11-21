import { secp256k1 } from '@noble/curves/secp256k1.js';
import { DataHash } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHash.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import type { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';

import { eq } from '../bytes.js';
import { array, cArr, headTag, MAX_U64, raw, scanNative, tagContent } from './cbor.js';
import { TAG } from './config.js';
import { LIMITS, decodeReceiptBacking } from './deposit.js';
import { HU, minterScalar, minterScalarValid, parseKey, signUnlock, unlockMessage, verifyUnlock } from './crypto.js';
import { WalletError, refuse } from './errors.js';
import { decodeSplitJustification, encodeSplitJustification, encodeSplitManifest, encodeSumProof, splitOutputCommitment, SumTree } from './split.js';
import {
  MAX_CHILD_MINT, MAX_ROOT_MINT, burnPredicate, decodeToken, encodeLevel, frameLevel, frameLineage, lineageOf, encodeProof, encodeCertification, encodeMint, encodePredicate, encodeTransfer, mintSourceHash, resultState, signaturePredicate,
  tokenIdOf, valueData, type Certification, type MintTx, type Predicate, type LineageLevel, type TransferTx,
} from './token.js';
import type { Deadline } from './cbor.js';

/** A Unicity owner key: its compressed public key and the 65-byte r||s||id unlock signature over a 32-byte message. */
export interface OwnerSigner {
  readonly publicKey: Uint8Array;
  signUnlock(message: Uint8Array): Promise<Uint8Array>;
}

/** An owner key held in memory. */
export function localOwner(privateKey: Uint8Array): OwnerSigner {
  return {
    publicKey: secp256k1.getPublicKey(privateKey, true),
    signUnlock: (m) => {
      const rec = secp256k1.sign(m, privateKey, { prehash: false, lowS: true, format: 'recovered' });
      const out = new Uint8Array(65);
      out.set(rec.subarray(1, 65));
      out[64] = rec[0];
      return Promise.resolve(out);
    },
  };
}

/** An owner key behind the SDK's signing service. */
export function sdkOwner(s: SigningService): OwnerSigner {
  return { publicKey: s.publicKey, signUnlock: async (m) => (await s.sign(new DataHash(HashAlgorithm.SHA256, m))).encode() };
}

/** The aggregator: certify a request (exact CD bytes) and return its inclusion proof (exact bytes). Resubmitting must be harmless. */
export interface Aggregator {
  certify(request: Uint8Array): Promise<Uint8Array>;
}

/** The certification request of a mint: the universal minter's unlock over (h0, txHash). */
export function mintRequest(m: MintTx): { tx: Uint8Array; cd: Uint8Array } {
  const reason = m.justification;
  const kind = reason === null ? null : headTag(reason);
  if (reason === null || (kind !== TAG.receiptBacking && kind !== TAG.splitJustification)) refuse('BadInput', 'missing bridge mint reason');
  const tx = encodeMint(m);
  if (kind === TAG.receiptBacking ? reason.length > LIMITS.justificationBytes || tx.length > MAX_ROOT_MINT : tx.length > MAX_CHILD_MINT) {
    refuse('BadInput', 'bridge mint exceeds its signed byte limit');
  }
  if (kind === TAG.receiptBacking) decodeReceiptBacking(reason);
  else decodeSplitJustification(reason);
  const id = tokenIdOf(m.salt, m.network);
  const h0 = mintSourceHash(id);
  const txHash = HU(tx);
  const key = minterScalar(id);
  if (!minterScalarValid(key)) refuse('BadInput', 'invalid universal minter scalar');
  const unlock = signUnlock(key, h0, txHash);
  verifyUnlock(secp256k1.getPublicKey(key, true), h0, txHash, unlock);
  const cd: Certification = { source: signaturePredicate(secp256k1.getPublicKey(key, true)), sourceHash: h0, txHash, deadline: m.deadline, unlock };
  return { tx, cd: encodeCertification(cd) };
}

/** Export a certified root. */
export const tokenOfMint = (tx: Uint8Array, proof: Uint8Array): Uint8Array =>
  frameLineage([frameLevel(new Uint8Array(), tx, proof, [])]);

/** Add the child level to the exact signed records of the parent. */
export function tokenOfChild(parent: Uint8Array, allocation: Uint8Array, tx: Uint8Array, proof: Uint8Array): Uint8Array {
  const levels = lineageOf(decodeToken(parent)).map(encodeLevel);
  return frameLineage([...levels, frameLevel(allocation, tx, proof, [])]);
}

/** Preserve the exact signed bytes when appending a certified transfer. */
export function appendTransfer(token: Uint8Array, tx: Uint8Array, proof: Uint8Array): Uint8Array {
  const part = decodeToken(token);
  const pairs = part.transfersRaw.map((rawTx, i) => cArr(rawTx, encodeProof(part.proofs[i])));
  const last = frameLevel(part.allocation, part.mintRaw, encodeProof(part.mintProof), [...pairs, cArr(tx, proof)]);
  return frameLineage([...part.ancestors.map(encodeLevel), last]);
}

/** The current owner predicate and state of a decoded token. */
export function headOf(t: LineageLevel): { owner: Predicate; state: Uint8Array } {
  const id = tokenIdOf(t.mint.salt, t.mint.network);
  let state = resultState(mintSourceHash(id), id);
  let owner = t.mint.recipient;
  for (const tr of t.transfers) {
    state = resultState(state, tr.mask);
    owner = tr.recipient;
  }
  return { owner, state };
}

/** A transfer of `token` and its certification request, signed by the current owner. */
export async function transferRequest(token: Uint8Array, owner: OwnerSigner, tr: TransferTx): Promise<{ tx: Uint8Array; cd: Uint8Array }> {
  const t = decodeToken(token);
  const head = headOf(t);
  if (head.owner.type !== 1n || !eq(head.owner.params, owner.publicKey)) refuse('BadInput', 'the token is not owned by this key');
  const tx = encodeTransfer(tr);
  const txHash = HU(tx);
  const unlock = await owner.signUnlock(unlockMessage(head.state, txHash));
  // the owner's signature is checked by the NB2 unlock rule (recovery ID 0 or 1 included) before anything is journaled or certified
  verifyUnlock(head.owner.params, head.state, txHash, unlock);
  const cd: Certification = { source: head.owner, sourceHash: head.state, txHash, deadline: tr.deadline, unlock };
  return { tx, cd: encodeCertification(cd) };
}

/** Certify and check that the proof is for exactly this request. */
export async function certifyChecked(agg: Aggregator, cd: Uint8Array): Promise<Uint8Array> {
  const proof = await agg.certify(cd);
  const k = array(tagContent(scanNative(proof), TAG.inclusion), 5);
  if (!eq(raw(proof, k[1]), cd)) refuse('ProviderFault', 'the inclusion proof is not for the submitted request');
  return proof;
}

/** A fresh 32-byte state mask. */
export const freshMask = (): Uint8Array => crypto.getRandomValues(new Uint8Array(32));

// ---- splits -------------------------------------------------------------------------------------

export interface SplitOutput { ownerKey: Uint8Array; amount: bigint; salt: Uint8Array; deadline?: Deadline }

/** The fixed parts of a split: the manifest, its burn transfer, and each child's mint template (without its justification). */
export function splitPlan(parent: LineageLevel, outputs: SplitOutput[], ty: Uint8Array, aid: Uint8Array, mask: Uint8Array, deadline: Deadline = null): {
  manifest: Uint8Array; burn: TransferTx; children: MintTx[]; tree: SumTree; parentId: Uint8Array;
} {
  for (const output of outputs) {
    parseKey(output.ownerKey);
    if (output.salt.length !== 32 || (output.deadline != null && (output.deadline <= 0n || output.deadline > MAX_U64))) {
      refuse('BadInput', 'invalid child salt or deadline');
    }
  }
  const parentId = tokenIdOf(parent.mint.salt, parent.mint.network);
  const children: MintTx[] = outputs.map((o) => ({
    network: parent.mint.network, recipient: signaturePredicate(o.ownerKey), salt: o.salt, type: ty, justification: null, data: valueData(aid, o.amount), deadline: o.deadline ?? null,
  }));
  const tree = SumTree.build(children.map((m, i) => ({ key: tokenIdOf(m.salt, m.network), data: splitOutputCommitment(parentId, m), value: outputs[i].amount })));
  const manifest = encodeSplitManifest(tree.root);
  return { manifest, burn: { recipient: burnPredicate(HU(manifest)), mask, data: manifest, deadline }, children, tree, parentId };
}

/** Prepare a child after the parent split verifier has derived its authenticated link. */
export function childMint(link: Uint8Array, tree: SumTree, child: MintTx): { mint: MintTx; allocation: Uint8Array } {
  const proof = tree.proof(tokenIdOf(child.salt, child.network));
  if (proof === null) throw new WalletError('BadInput', 'child not in the allocation tree');
  return { mint: { ...child, justification: encodeSplitJustification(link) }, allocation: encodeSumProof(proof) };
}

export { encodePredicate };
