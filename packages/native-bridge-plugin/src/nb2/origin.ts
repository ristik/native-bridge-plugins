import { WalletError } from './errors.js';
import type { AuthenticatedOrigin, TrustInput } from './trust.js';

/** Taken from the independently selected release, including its SHA-256 pin. */
export interface Nb2OriginBinding {
  network: number;
  generation: string;
  genesisHash: string;
  releaseSha256: string;
}

export interface Nb2OriginCheckpoint extends AuthenticatedOrigin {
  blockHash: string;
  blockNumber: number;
}

/** Maximum UTF-8 size of the complete `nb2-origin.json` response body. */
export const MAX_NB2_ORIGIN_BYTES = 4096;

const hash = /^0x[0-9a-f]{64}$/;
const uint64Max = (1n << 64n) - 1n;

function word(value: unknown): bigint {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > uint64Max) {
    throw new WalletError('TrustInput', 'invalid B1 checkpoint epoch or root round');
  }
  return BigInt(value);
}

function decodeOrigin(bytes: Uint8Array): Record<string, unknown> {
  if (bytes.byteLength > MAX_NB2_ORIGIN_BYTES) {
    throw new WalletError('TrustInput', `B1 checkpoint exceeds ${MAX_NB2_ORIGIN_BYTES} bytes`);
  }
  let document: unknown;
  try {
    document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new WalletError('TrustInput', 'invalid B1 checkpoint JSON', error);
  }
  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    throw new WalletError('TrustInput', 'invalid B1 checkpoint document');
  }
  return document as Record<string, unknown>;
}

/**
 * Decode and validate UTF-8 bytes fetched over the operator's authenticated HTTPS channel.
 * Start with the pinned release's checkpoint, then use the last accepted checkpoint
 * as `held`. The caller persists it and returns `trust` from the existing refresh hook.
 */
export function refreshNb2Origin(trust: TrustInput, binding: Nb2OriginBinding, held: Nb2OriginCheckpoint, bytes: Uint8Array):
  { trust: TrustInput; checkpoint: Nb2OriginCheckpoint } {
  const record = decodeOrigin(bytes);
  if (record.schema !== 'unicity-nb2-origin' || record.version !== 1 ||
      record.network !== binding.network || record.network !== Number(trust.network.id) ||
      record.generation !== binding.generation ||
      typeof record.genesisHash !== 'string' || !hash.test(record.genesisHash) || record.genesisHash !== binding.genesisHash ||
      typeof record.releaseSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(record.releaseSha256) || record.releaseSha256 !== binding.releaseSha256) {
    throw new WalletError('TrustInput', 'B1 checkpoint belongs to a different release or network');
  }
  const { blockHash, blockNumber } = record;
  if (typeof blockHash !== 'string' || !hash.test(blockHash) || blockHash === '0x' + '0'.repeat(64) ||
      typeof blockNumber !== 'number' || !Number.isSafeInteger(blockNumber) || blockNumber < 0) {
    throw new WalletError('TrustInput', 'invalid finalized block in B1 checkpoint');
  }
  const checkpoint = { blockHash, blockNumber, usableEpoch: word(record.usableEpoch), rootRound: word(record.rootRound) };
  if (checkpoint.blockNumber < held.blockNumber || checkpoint.rootRound < held.rootRound ||
      checkpoint.usableEpoch < held.usableEpoch ||
      (trust.origin && (checkpoint.rootRound < trust.origin.rootRound || checkpoint.usableEpoch < trust.origin.usableEpoch))) {
    throw new WalletError('TrustInput', 'B1 checkpoint rolls back the held authority');
  }
  if ((blockNumber === held.blockNumber || blockHash === held.blockHash) &&
      (blockNumber !== held.blockNumber || blockHash !== held.blockHash ||
       checkpoint.usableEpoch !== held.usableEpoch || checkpoint.rootRound !== held.rootRound)) {
    throw new WalletError('TrustInput', 'B1 checkpoint conflicts with the held finalized block');
  }
  return { trust: trust.withAuthenticatedOrigin(checkpoint), checkpoint };
}
