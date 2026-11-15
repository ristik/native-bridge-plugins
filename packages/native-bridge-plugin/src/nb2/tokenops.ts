/**
 * Ordinary token operations on the unchanged SDK wire (`protocol/interop.md` "SDK wire"): the root mint with the receipt-backed reason,
 * transfers, the return burn and the split (burn-and-mint with the protocol 6 lineage formats). Transactions are built byte for byte
 * as the SDK builds them (test/nb2/sdk-parity.test.ts compares with the SDK's own constructors), signed by the owner's
 * {@link OwnerSigner} (the universal minter for a mint), and certified by an {@link Aggregator}. Every certified result is verified
 * offline by this package's verifier before it is returned.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { DataHash } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHash.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import type { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';

import { eq } from '../bytes.js';
import { array, cArr, raw, scanNative, tagContent } from './cbor.js';
import { TAG } from './config.js';
import { HU, minterScalar, signUnlock, unlockMessage } from './crypto.js';
import { WalletError, refuse } from './errors.js';
import { encodeSplitJustification, encodeSplitManifest, splitOutputCommitment, SumTree } from './split.js';
import {
  burnPredicate, decodeToken, encodeCertification, encodeMint, encodePredicate, encodeTransfer, mintSourceHash, resultState, signaturePredicate,
  tokenIdOf, valueData, type Certification, type MintTx, type Predicate, type Token, type TransferTx,
} from './token.js';
import { cTag, cUint } from './cbor.js';
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
  const tx = encodeMint(m);
  const id = tokenIdOf(m.salt, m.network);
  const h0 = mintSourceHash(id);
  const txHash = HU(tx);
  const key = minterScalar(id);
  const cd: Certification = { source: signaturePredicate(secp256k1.getPublicKey(key, true)), sourceHash: h0, txHash, deadline: m.deadline, unlock: signUnlock(key, h0, txHash) };
  return { tx, cd: encodeCertification(cd) };
}

/** The exact token of one certified mint. */
export const tokenOfMint = (tx: Uint8Array, proof: Uint8Array): Uint8Array => cTag(TAG.token, cArr(cUint(2), cArr(tx, proof), cArr()));

/** A token with one more certified transfer: the exact earlier pairs, then (tx, proof). */
export function appendTransfer(token: Uint8Array, tx: Uint8Array, proof: Uint8Array): Uint8Array {
  const k = array(tagContent(scanNative(token), TAG.token), 3);
  const pairs = k[2].kids.map((p) => raw(token, p));
  return cTag(TAG.token, cArr(cUint(2), raw(token, k[1]), cArr(...pairs, cArr(tx, proof))));
}

/** The current owner predicate and state of a decoded token. */
export function headOf(t: Token): { owner: Predicate; state: Uint8Array } {
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

export interface SplitOutput { ownerKey: Uint8Array; amount: bigint; salt: Uint8Array }

/** The fixed parts of a split: the manifest, its burn transfer, and each child's mint template (without its justification). */
export function splitPlan(parent: Token, outputs: SplitOutput[], ty: Uint8Array, aid: Uint8Array, mask: Uint8Array, deadline: Deadline = null): {
  manifest: Uint8Array; burn: TransferTx; children: MintTx[]; tree: SumTree; parentId: Uint8Array;
} {
  const parentId = tokenIdOf(parent.mint.salt, parent.mint.network);
  const children: MintTx[] = outputs.map((o) => ({
    network: parent.mint.network, recipient: signaturePredicate(o.ownerKey), salt: o.salt, type: ty, justification: null, data: valueData(aid, o.amount), deadline: null,
  }));
  const tree = SumTree.build(children.map((m, i) => ({ key: tokenIdOf(m.salt, m.network), data: splitOutputCommitment(parentId, m), value: outputs[i].amount })));
  const manifest = encodeSplitManifest(tree.root);
  return { manifest, burn: { recipient: burnPredicate(HU(manifest)), mask, data: manifest, deadline }, children, tree, parentId };
}

/** A child's mint with its split reason over the exact burned parent token. */
export function childMint(burnedParent: Uint8Array, tree: SumTree, child: MintTx): MintTx {
  const proof = tree.proof(tokenIdOf(child.salt, child.network));
  if (proof === null) throw new WalletError('BadInput', 'child not in the allocation tree');
  return { ...child, justification: encodeSplitJustification(burnedParent, proof) };
}

export { encodePredicate };
