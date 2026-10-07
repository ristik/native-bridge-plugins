/**
 * The embedded lock proof and its fully offline verification.
 *
 * `J = tag(39049,[2,chainId,b(vault20),b(zero20),nonce,LockProof])`,
 * `LockProof = [1,b(cfg32),b(trustBaseId32),b(evmPDR),b(evmUC),b(headerRLP),[b(acctNode)...],[b(storNode)...]]`.
 * Verification reads only the token and the pinned deployment and trust base: no RPC, node, URL
 * resolution or witness provider.
 */
import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';

import { eq } from './bytes.js';
import type { Deployment } from './deployment.js';
import { fail } from './errors.js';
import { decodeHeader } from './header.js';
import {
  LOCK_PROOF_VERSION, MAX_HEADER_BYTES, MAX_JUSTIFICATION_BYTES, MAX_MPT_NODE_BYTES, MAX_MPT_NODES,
  MAX_MPT_TOTAL_BYTES, MAX_PDR_BYTES, MAX_UC_BYTES, MINT_LOCK_VERSION, TAG_MINT_LOCK,
} from './limits.js';
import { verifyProof } from './mpt.js';
import { H, accountTrieKey, arr, bs, keccak256, lockDigestSlot, storageTrieKey, u } from './profile.js';
import { bytesOf, decode, listOf, u64Of } from './rlp.js';
import { arrayOf, bytesAny, bytesN, pdrElements, scanOne, tagContent, uint, version, type Item } from './scan.js';
import type { TrustInput } from './trust.js';

export interface LockProof {
  cfg: Uint8Array;
  trustBaseId: Uint8Array;
  pdr: Uint8Array;
  uc: Uint8Array;
  header: Uint8Array;
  accountNodes: Uint8Array[];
  storageNodes: Uint8Array[];
}

export interface Justification {
  chainId: bigint;
  vault: Uint8Array;
  zero: Uint8Array;
  nonce: bigint;
  proof: LockProof;
}

function nodes(it: Item, total: { n: number }): Uint8Array[] {
  const list = arrayOf(it) ?? fail('ErrShape');
  if (list.length > MAX_MPT_NODES) fail('ErrProofTooLarge');
  return list.map((n) => {
    const b = bytesAny(n);
    if (b.length === 0 || b.length > MAX_MPT_NODE_BYTES) fail('ErrProofTooLarge');
    total.n += b.length;
    return b;
  });
}

/** Parse one scanned LockProof, enforcing exact arity and every size bound before any crypto. */
export function parseLockProof(it: Item): LockProof {
  const k = arrayOf(it, 8) ?? fail('ErrShape');
  version(k[0], LOCK_PROOF_VERSION);
  const pdr = bytesAny(k[3]);
  const uc = bytesAny(k[4]);
  const header = bytesAny(k[5]);
  if (pdr.length === 0 || pdr.length > MAX_PDR_BYTES || uc.length === 0 || uc.length > MAX_UC_BYTES) fail('ErrProofTooLarge');
  if (header.length === 0 || header.length > MAX_HEADER_BYTES) fail('ErrProofTooLarge');
  const total = { n: 0 };
  const accountNodes = nodes(k[6], total);
  const storageNodes = nodes(k[7], total);
  if (total.n > MAX_MPT_TOTAL_BYTES) fail('ErrProofTooLarge');
  return { cfg: bytesN(k[1], 32), trustBaseId: bytesN(k[2], 32), pdr, uc, header, accountNodes, storageNodes };
}

export function encodeLockProof(p: LockProof): Uint8Array {
  return arr(
    u(LOCK_PROOF_VERSION), bs(p.cfg), bs(p.trustBaseId), bs(p.pdr), bs(p.uc), bs(p.header),
    arr(...p.accountNodes.map(bs)), arr(...p.storageNodes.map(bs)),
  );
}

export function encodeJustification(chainId: bigint, vault: Uint8Array, zero: Uint8Array, nonce: bigint, lockProof: Uint8Array): Uint8Array {
  return C.encodeTag(TAG_MINT_LOCK, arr(u(MINT_LOCK_VERSION), u(chainId), bs(vault), bs(zero), u(nonce), lockProof));
}

export function parseJustification(j: Uint8Array): Justification {
  if (j.length > MAX_JUSTIFICATION_BYTES) fail('ErrInputTooLarge');
  const k = arrayOf(tagContent(scanOne(j), TAG_MINT_LOCK), 6) ?? fail('ErrShape');
  version(k[0], MINT_LOCK_VERSION);
  return { chainId: uint(k[1]), vault: bytesN(k[2], 20), zero: bytesN(k[3], 20), nonce: uint(k[4]), proof: parseLockProof(k[5]) };
}

export function configHashOfPdr(pdr: Uint8Array): Uint8Array {
  const elems = pdrElements(pdr);
  if (elems.length !== 15) fail('ErrEvmConfigPin');
  return configHash(elems);
}

function configHash(elems: Uint8Array[]): Uint8Array {
  // Every non-membership setting: validators, epoch and activation round are neutralised.
  return H(arr(...elems.slice(0, 12), u(0), u(0), C.encodeNull()));
}

const smallUint = (raw: Uint8Array): bigint => uint(scanOne(raw));

export interface VerifiedLock {
  trustBaseId: Uint8Array;
  evmBlockNumber: bigint;
  evmRootRound: bigint;
}

/** Verify a lock proof against the pinned deployment and trust input, in the specified order. */
export async function verifyLockProof(dep: Deployment, trust: TrustInput, j: Justification, expectedDigest: Uint8Array): Promise<VerifiedLock> {
  const lp = j.proof;
  if (j.chainId !== dep.cfg.chainId || !eq(j.vault, dep.cfg.vault) || !eq(j.zero, dep.cfg.zeroAddress)) fail('ErrMintJustif');
  if (!eq(lp.cfg, dep.cfgHash)) fail('ErrLockProofCfg');
  if (!eq(lp.trustBaseId, trust.id)) fail('ErrLockProofTrust');
  let uc: UnicityCertificate;
  try {
    uc = UnicityCertificate.fromCBOR(lp.uc);
    if (!eq(uc.toCBOR(), lp.uc)) fail('ErrUnsupportedCertificateEncoding');
  } catch (e) {
    if (e instanceof Error && e.name === 'NativeError') throw e;
    return fail('ErrUnsupportedCertificateEncoding');
  }
  await trust.verifyEmbeddedUc(uc);
  // Admitted EVM partition, shard and configuration: pinned, never read from the UC tuple.
  if (uc.unicityTreeCertificate.partitionIdentifier !== BigInt(dep.cfg.evmPartition)) fail('ErrEvmPartition');
  if (!eq(uc.shardTreeCertificate.shard.encode(), dep.cfg.evmShard)) fail('ErrEvmShard');
  if (!eq(H(lp.pdr), uc.shardConfigurationHash)) fail('ErrEvmConfigHash');
  let elems: Uint8Array[];
  try {
    elems = pdrElements(lp.pdr);
  } catch {
    return fail('ErrEvmConfigPin');
  }
  if (elems.length !== 15) fail('ErrEvmConfigPin');
  let net: bigint, part: bigint, shard: Uint8Array, pdrEpoch: bigint;
  try {
    net = smallUint(elems[1]);
    part = smallUint(elems[2]);
    shard = bytesAny(scanOne(elems[3]));
    pdrEpoch = smallUint(elems[12]);
  } catch {
    return fail('ErrEvmConfigPin');
  }
  if (net !== BigInt(dep.cfg.network) || part !== BigInt(dep.cfg.evmPartition) || !eq(shard, dep.cfg.evmShard)) fail('ErrEvmConfigPin');
  if (!eq(configHash(elems), dep.evmConfigHash)) fail('ErrEvmConfigPin');
  // The certified shard epoch must be the epoch the carried PDR describes.
  if (pdrEpoch !== uc.inputRecord.epoch) fail('ErrEvmConfigPin');
  // keccak256(headerRLP) == IR.blockHash and header.stateRoot == IR.hash.
  const blockHash = uc.inputRecord.blockHash;
  if (blockHash === null || blockHash.length !== 32 || uc.inputRecord.hash.length !== 32) fail('ErrHeaderHash');
  if (!eq(keccak256(lp.header), blockHash!)) fail('ErrHeaderHash');
  const hdr = decodeHeader(lp.header, dep.header);
  if (!eq(hdr.stateRoot, uc.inputRecord.hash)) fail('ErrHeaderRoot');
  // Account MPT at keccak256(vault) under header.stateRoot; codeHash == immutable runtime pin.
  let storageRoot: Uint8Array;
  try {
    const f = listOf(decode(verifyProof(hdr.stateRoot, accountTrieKey(dep.cfg.vault), lp.accountNodes)));
    if (f.length !== 4) throw new Error('arity');
    u64Of(f[0]);
    if (bytesOf(f[1]).length > 32) throw new Error('balance');
    storageRoot = bytesOf(f[2]);
    const code = bytesOf(f[3]);
    if (storageRoot.length !== 32 || code.length !== 32) throw new Error('width');
    if (!eq(code, dep.vaultCodeHash)) {
      return fail('ErrAccountCode');
    }
  } catch (e) {
    if (e instanceof Error && e.name === 'NativeError' && (e as { reason?: string }).reason === 'ErrAccountCode') throw e;
    return fail('ErrAccountProof');
  }
  // Storage MPT at keccak256(keccak256(abi.encode(nonce, 5))).
  let stored: Uint8Array;
  try {
    stored = verifyProof(storageRoot, storageTrieKey(lockDigestSlot(j.nonce)), lp.storageNodes);
  } catch {
    return fail('ErrStorageProof');
  }
  let v: Uint8Array;
  try {
    v = bytesOf(decode(stored));
  } catch {
    return fail('ErrStorageValue');
  }
  if (v.length === 0 || v.length > 32 || v[0] === 0) fail('ErrStorageValue');
  const padded = new Uint8Array(32);
  padded.set(v, 32 - v.length);
  if (!eq(padded, expectedDigest)) fail('ErrLockDigest');
  return { trustBaseId: lp.trustBaseId, evmBlockNumber: hdr.number, evmRootRound: uc.unicitySeal.rootChainRoundNumber };
}
