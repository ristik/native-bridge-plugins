/**
 * EVM transactions: the {@link EvmSigner} seam and a local-key EIP-1559 signer. The plug-in always holds the signed raw transaction
 * before it is broadcast, so its hash is known up front: an ambiguous broadcast (#1121) is resolved by polling that hash, never by
 * signing a second transaction.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';

import { concat, eq } from '../bytes.js';
import { HE } from './crypto.js';
import { rlpBytes, rlpDecode, rlpList, rlpUint, rlpUintEnc } from './rlp.js';

/** An unsigned EIP-1559 transaction. */
export interface TxRequest {
  chainId: bigint;
  nonce: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gas: bigint;
  to: Uint8Array;
  value: bigint;
  data: Uint8Array;
}

/** Minimum bid for replacing a possibly pooled transaction, rounded up past ten percent. */
export const replacementBid = (bid: bigint): bigint => bid + bid / 10n + 1n;

/** A signed transaction: its exact bytes and hash. */
export interface SignedTx { raw: Uint8Array; hash: Uint8Array; request: TxRequest }

/** The wallet's EVM account. Implementations may be a hardware wallet or a remote signer; they only have to return the raw bytes. */
export interface EvmSigner {
  readonly address: Uint8Array;
  signTransaction(tx: TxRequest): Promise<Uint8Array>;
}

const fields = (t: TxRequest): Uint8Array[] => [
  rlpUintEnc(t.chainId), rlpUintEnc(t.nonce), rlpUintEnc(t.maxPriorityFeePerGas), rlpUintEnc(t.maxFeePerGas), rlpUintEnc(t.gas), rlpBytes(t.to),
  rlpUintEnc(t.value), rlpBytes(t.data), rlpList([]),
];

/** keccak256(0x02 || RLP(unsigned fields)): the EIP-1559 signing hash. */
export const signingHash = (t: TxRequest): Uint8Array => HE(Uint8Array.of(0x02), rlpList(fields(t)));

/** The address of a secp256k1 public key. */
export const addressOf = (pub: Uint8Array): Uint8Array => HE(secp256k1.Point.fromBytes(pub).toBytes(false).subarray(1)).slice(12);

export class LocalKeySigner implements EvmSigner {
  public readonly address: Uint8Array;
  public constructor(private readonly key: Uint8Array) {
    this.address = addressOf(secp256k1.getPublicKey(key, true));
  }

  public signTransaction(t: TxRequest): Promise<Uint8Array> {
    const sig = secp256k1.sign(signingHash(t), this.key, { prehash: false, lowS: true, format: 'recovered' });
    const r = sig.subarray(1, 33);
    const s = sig.subarray(33, 65);
    const strip = (b: Uint8Array): Uint8Array => {
      let i = 0;
      while (i < b.length && b[i] === 0) i++;
      return b.subarray(i);
    };
    return Promise.resolve(concat(Uint8Array.of(0x02), rlpList([...fields(t), rlpUintEnc(sig[0]), rlpBytes(strip(r)), rlpBytes(strip(s))])));
  }
}

/**
 * Sign `t` with `signer` and check the signed bytes before they are journaled: an external signer must return exactly this request
 * (chain ID, nonce, fees, gas, target, value, data), signed by its own address. The journaled request is the decoded one.
 */
export async function signTx(signer: EvmSigner, t: TxRequest): Promise<SignedTx> {
  const raw = await signer.signTransaction(t);
  let d: ReturnType<typeof decodeSignedTx>;
  try {
    d = decodeSignedTx(raw);
  } catch (e) {
    throw new Error(`nb2: the signer returned a transaction that does not decode: ${String((e as Error)?.message ?? e)}`);
  }
  const r = d.request;
  const same = r.chainId === t.chainId && r.nonce === t.nonce && r.maxPriorityFeePerGas === t.maxPriorityFeePerGas && r.maxFeePerGas === t.maxFeePerGas
    && r.gas === t.gas && eq(r.to, t.to) && r.value === t.value && eq(r.data, t.data);
  if (!same) throw new Error('nb2: the signer returned another transaction than the one requested');
  if (!eq(d.from, signer.address)) throw new Error('nb2: the signed transaction is not from the signer\'s address');
  return { raw, hash: d.hash, request: r };
}

/** Decode a signed EIP-1559 transaction and recover its sender (used by the offline simulator and by tests). */
export function decodeSignedTx(raw: Uint8Array): { request: TxRequest; from: Uint8Array; hash: Uint8Array } {
  if (raw[0] !== 0x02) throw new Error('nb2: not an EIP-1559 transaction');
  const it = rlpDecode(raw.subarray(1));
  if (!it.list || it.kids.length !== 12) throw new Error('nb2: not an EIP-1559 transaction');
  const k = it.kids;
  const n = (i: number): bigint => {
    const v = rlpUint(k[i]);
    if (v === null) throw new Error('nb2: noncanonical integer');
    return v;
  };
  const request: TxRequest = { chainId: n(0), nonce: n(1), maxPriorityFeePerGas: n(2), maxFeePerGas: n(3), gas: n(4), to: k[5].str, value: n(6), data: k[7].str };
  const word = (b: Uint8Array): Uint8Array => concat(new Uint8Array(32 - b.length), b);
  const sig = concat(Uint8Array.of(Number(n(9))), word(k[10].str), word(k[11].str));
  const pub = secp256k1.Signature.fromBytes(sig, 'recovered').recoverPublicKey(signingHash(request)).toBytes(true);
  return { request, from: addressOf(pub), hash: HE(raw) };
}
