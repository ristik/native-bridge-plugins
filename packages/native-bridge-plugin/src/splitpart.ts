/**
 * The wallet side of a split part (protocol 6): the strict value-envelope payment decoder the SDK's split verifier needs, the walk
 * from a part to its root's lock reason (the root decides the deployment) and the part's ancestry as SDK tokens, root first, whose
 * proofs witness the lineage's leaves in the relation's order.
 */
import { Asset } from '@unicitylabs/state-transition-sdk/lib/payment/asset/Asset.js';
import { AssetId } from '@unicitylabs/state-transition-sdk/lib/payment/asset/AssetId.js';
import { PaymentAssetCollection } from '@unicitylabs/state-transition-sdk/lib/payment/asset/PaymentAssetCollection.js';
import type { IPaymentData } from '@unicitylabs/state-transition-sdk/lib/payment/IPaymentData.js';
import { SplitMintJustification } from '@unicitylabs/state-transition-sdk/lib/payment/SplitMintJustification.js';
import type { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import type { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';

import { eq } from './bytes.js';
import { fail } from './errors.js';
import { TAG_MINT_LOCK, TAG_SPLIT_JUSTIFICATION, TAG_WALLET_VALUE } from './limits.js';
import { valueEnvelope } from './profile.js';
import { amount as amountItem, arrayOf, bytesN, scanOne, tagContent, version } from './scan.js';
import { decodeToken } from './sdktoken.js';
import { beToBigint, decodeSplitJustification, justificationTag } from './split.js';

/**
 * The bridge's value envelope `tag(39050,[1,[[b(aid32),b(amount)]],null])` as SDK payment data: exactly one asset, no memo, the exact
 * canonical bytes. The deployment's asset is the issuance policy's check; this decoder only refuses everything that is not an envelope.
 */
export class WalletValue implements IPaymentData {
  private constructor(
    public readonly assets: PaymentAssetCollection,
    private readonly bytes: Uint8Array,
  ) {}

  public static of(aid: Uint8Array, amount: Uint8Array): WalletValue {
    return new WalletValue(PaymentAssetCollection.create(new Asset(new AssetId(aid), beToBigint(amount))), valueEnvelope(aid, amount));
  }

  /** Strict decode; throws on anything but one exact envelope. */
  public static decode(bytes: Uint8Array): Promise<WalletValue> {
    const k = arrayOf(tagContent(scanOne(bytes), TAG_WALLET_VALUE), 3) ?? fail('ErrMintData');
    version(k[0], 1n);
    const entry = arrayOf((arrayOf(k[1], 1) ?? fail('ErrMintData'))[0], 2) ?? fail('ErrMintData');
    const aid = bytesN(entry[0], 32);
    const amount = amountItem(entry[1]);
    if (k[2].kind !== 'null' || !eq(valueEnvelope(aid, amount), bytes)) fail('ErrMintData');
    return Promise.resolve(WalletValue.of(aid, amount));
  }

  public encode(): Promise<Uint8Array> {
    return Promise.resolve(this.bytes.slice());
  }
}

/** Whether a mint justification is a split reason (the token is a split part, not a lock-backed root). */
export const isSplitReason = (j: Uint8Array | null): boolean => justificationTag(j) === TAG_SPLIT_JUSTIFICATION;

/**
 * The lock reason of a part's root: walk the exact split reasons (each embeds its burned parent) down to the token minted from the
 * lock. Structure only: the relation and the SDK verify the walk; this only finds which deployment the part belongs to.
 */
export function rootJustification(j: Uint8Array | null): Uint8Array {
  let cur = j;
  for (;;) {
    const tag = justificationTag(cur);
    if (tag === TAG_MINT_LOCK) return cur as Uint8Array;
    if (tag !== TAG_SPLIT_JUSTIFICATION) return fail('ErrMintJustif');
    cur = decodeToken(decodeSplitJustification(cur as Uint8Array).token).mint.justification;
  }
}

/** The part's ancestry as SDK tokens, root first, ending with the part itself. */
export async function splitChain(part: Token): Promise<Token[]> {
  const chain: Token[] = [part];
  for (let cur = part; isSplitReason(cur.genesis.justification); ) {
    cur = (await SplitMintJustification.fromCBOR(cur.genesis.justification as Uint8Array)).token;
    chain.unshift(cur);
  }
  return chain;
}

/** Every certified transaction's proof of the lineage, root first, in the relation's leaf order (each token's mint, then its transfers). */
export const lineageProofs = (chain: readonly Token[]): InclusionProof[] =>
  chain.flatMap((t) => [t.genesis, ...t.transactions].map((c) => c.inclusionProof));
