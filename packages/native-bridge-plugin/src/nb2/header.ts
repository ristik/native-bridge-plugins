/**
 * The pinned execution header (section 6.2 step 3): the go-ethereum v1.14.11 Cancun `types.Header`, exactly 20 RLP fields ending at
 * `parentBeaconBlockRoot`. The decoder accepts exactly what go-ethereum decodes into that struct and re-encodes identically, plus the
 * profile's constraints; every failure is `DepositHeader`.
 */
import { eq } from '../bytes.js';
import { HE } from './crypto.js';
import { fail } from './errors.js';
import { rlpBytes, rlpDecode, rlpList, rlpUint, rlpUintEnc, type RlpItem } from './rlp.js';

/** keccak256(RLP([])) */
export const EMPTY_UNCLE_HASH = HE(Uint8Array.of(0xc0));
/** keccak256(RLP("")), the empty trie root. */
export const EMPTY_TRIE_ROOT = HE(Uint8Array.of(0x80));

export interface Header {
  parentHash: Uint8Array;
  ommersHash: Uint8Array;
  beneficiary: Uint8Array;
  stateRoot: Uint8Array;
  transactionsRoot: Uint8Array;
  receiptsRoot: Uint8Array;
  logsBloom: Uint8Array;
  difficulty: bigint;
  number: bigint;
  gasLimit: bigint;
  gasUsed: bigint;
  timestamp: bigint;
  extraData: Uint8Array;
  mixHash: Uint8Array;
  nonce: Uint8Array;
  baseFeePerGas: bigint;
  withdrawalsRoot: Uint8Array;
  blobGasUsed: bigint;
  excessBlobGas: bigint;
  parentBeaconBlockRoot: Uint8Array;
}

export function encodeHeader(h: Header): Uint8Array {
  return rlpList([
    rlpBytes(h.parentHash), rlpBytes(h.ommersHash), rlpBytes(h.beneficiary), rlpBytes(h.stateRoot), rlpBytes(h.transactionsRoot),
    rlpBytes(h.receiptsRoot), rlpBytes(h.logsBloom), rlpUintEnc(h.difficulty), rlpUintEnc(h.number), rlpUintEnc(h.gasLimit),
    rlpUintEnc(h.gasUsed), rlpUintEnc(h.timestamp), rlpBytes(h.extraData), rlpBytes(h.mixHash), rlpBytes(h.nonce),
    rlpUintEnc(h.baseFeePerGas), rlpBytes(h.withdrawalsRoot), rlpUintEnc(h.blobGasUsed), rlpUintEnc(h.excessBlobGas),
    rlpBytes(h.parentBeaconBlockRoot),
  ]);
}

/** Decode the pinned header shape (exact field widths, canonical integers, 20 fields, identical re-encoding); `DepositHeader` otherwise. */
export function decodeHeader(raw: Uint8Array): Header {
  let it: RlpItem;
  try {
    it = rlpDecode(raw);
  } catch {
    return fail('DepositHeader', 'not RLP');
  }
  if (!it.list || it.kids.length !== 20) fail('DepositHeader', 'not the 20-field Cancun header');
  const k = it.kids;
  const fixed = (i: number, n: number): Uint8Array => {
    if (k[i].list || k[i].str.length !== n) fail('DepositHeader', `field ${i}`);
    return k[i].str;
  };
  const int = (i: number, max: number): bigint => {
    const v = rlpUint(k[i], max);
    if (v === null) fail('DepositHeader', `field ${i}`);
    return v!;
  };
  const bytes = (i: number): Uint8Array => (k[i].list ? fail('DepositHeader', `field ${i}`) : k[i].str);
  const h: Header = {
    parentHash: fixed(0, 32), ommersHash: fixed(1, 32), beneficiary: fixed(2, 20), stateRoot: fixed(3, 32), transactionsRoot: fixed(4, 32),
    receiptsRoot: fixed(5, 32), logsBloom: fixed(6, 256), difficulty: int(7, 32), number: int(8, 32), gasLimit: int(9, 8), gasUsed: int(10, 8),
    timestamp: int(11, 8), extraData: bytes(12), mixHash: fixed(13, 32), nonce: fixed(14, 8), baseFeePerGas: int(15, 32),
    withdrawalsRoot: fixed(16, 32), blobGasUsed: int(17, 8), excessBlobGas: int(18, 8), parentBeaconBlockRoot: fixed(19, 32),
  };
  if (!eq(encodeHeader(h), raw)) fail('DepositHeader', 'not canonical');
  return h;
}

/**
 * Bind a header to its certified input record: `H_E(headerRLP) == IR.blockHash` and `header.stateRoot == IR.hash`, then the profile's
 * constraints (zero difficulty, empty uncles and withdrawals, no blob gas, a nonzero u64 base fee, at most 32 extra bytes, number below
 * 2^63).
 */
export function bindHeader(raw: Uint8Array, irBlockHash: Uint8Array | null, irHash: Uint8Array | null): Header {
  const h = decodeHeader(raw);
  if (h.number >= 1n << 64n) fail('DepositHeader');
  if (irBlockHash === null || irHash === null || !eq(HE(raw), irBlockHash) || !eq(h.stateRoot, irHash)) fail('DepositHeader', 'not the certified block');
  if (h.number >= 1n << 63n || !eq(h.ommersHash, EMPTY_UNCLE_HASH) || h.difficulty !== 0n || h.baseFeePerGas <= 0n || h.baseFeePerGas >= 1n << 64n
    || !eq(h.withdrawalsRoot, EMPTY_TRIE_ROOT) || h.blobGasUsed !== 0n || h.excessBlobGas !== 0n || h.extraData.length > 32) {
    fail('DepositHeader', 'outside the pinned profile');
  }
  return h;
}
