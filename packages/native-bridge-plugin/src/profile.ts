import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';

import { concat, eq, toHex } from './bytes.js';
import { fail } from './errors.js';
import { MAX_POLICY_BYTES, MAX_SEMANTIC_BYTES, MAX_SHARD_BYTES, TAG_RETURN_REASON, TAG_WALLET_VALUE } from './limits.js';
import { arrayOf, bytesAny, bytesN, scanOne, uint, uintMax, version } from './scan.js';

export const H = (b: Uint8Array): Uint8Array => sha256(b);
export const keccak256 = (...parts: Uint8Array[]): Uint8Array => keccak_256(concat(...parts));

const enc = new TextEncoder();
export const bs = (b: Uint8Array): Uint8Array => C.encodeByteString(b);
export const u = (n: bigint | number): Uint8Array => C.encodeUnsignedInteger(BigInt(n));
export const arr = (...items: Uint8Array[]): Uint8Array => C.encodeArray(...items);
const dom = (s: string): Uint8Array => bs(enc.encode(s));

/** The one-byte native encoding of the empty shard prefix (not the empty bstr). */
export const EMPTY_PREFIX_SHARD = new Uint8Array([0x80]);
const CFG_DOMAIN = enc.encode('UNICITY_BR_CFG');
const POLICY_DOMAIN = enc.encode('UNICITY_BR_AGG_PARTITION');
/** The literal version field of the policy body (the v3 `AGG_SHARDED` and `AGG_ONE` bodies are not decoded). */
const POLICY_VERSION = 2n;

/** The immutable bridge configuration. Integers are bigint; widths follow the Go oracle. */
export interface Cfg {
  network: number;
  rootGenesis: Uint8Array;
  chainId: bigint;
  executionGenesis: Uint8Array;
  evmPartition: number;
  evmShard: Uint8Array;
  vault: Uint8Array;
  zeroAddress: Uint8Array;
  ty: Uint8Array;
  aid: Uint8Array;
  semanticProfileHash: Uint8Array;
  tokenVerifierAddress: Uint8Array;
  tokenVerifierCodeHash: Uint8Array;
  b1ProfileHash: Uint8Array;
  aggregatorPolicyHash: Uint8Array;
}

export function cfgBytes(c: Cfg): Uint8Array {
  return arr(
    bs(CFG_DOMAIN), u(c.network), bs(c.rootGenesis), u(c.chainId), bs(c.executionGenesis), u(c.evmPartition),
    bs(c.evmShard), bs(c.vault), bs(c.zeroAddress), bs(c.ty), bs(c.aid), bs(c.semanticProfileHash),
    bs(c.tokenVerifierAddress), bs(c.tokenVerifierCodeHash), bs(c.b1ProfileHash), bs(c.aggregatorPolicyHash),
  );
}

export const cfgHash = (c: Cfg): Uint8Array => H(cfgBytes(c));

export function decodeCfg(b: Uint8Array): Cfg {
  if (b.length > MAX_SEMANTIC_BYTES) fail('ErrInputTooLarge');
  const k = arrayOf(scanOne(b), 16) ?? fail('ErrShape');
  if (!eq(bytesAny(k[0]), CFG_DOMAIN)) fail('ErrShape');
  return {
    network: Number(uintMax(k[1], 0xffffn)),
    rootGenesis: bytesN(k[2], 32),
    chainId: uint(k[3]),
    executionGenesis: bytesN(k[4], 32),
    evmPartition: Number(uintMax(k[5], 0xffffffffn)),
    evmShard: bytesAny(k[6]),
    vault: bytesN(k[7], 20),
    zeroAddress: bytesN(k[8], 20),
    ty: bytesN(k[9], 32),
    aid: bytesN(k[10], 32),
    semanticProfileHash: bytesN(k[11], 32),
    tokenVerifierAddress: bytesN(k[12], 20),
    tokenVerifierCodeHash: bytesN(k[13], 32),
    b1ProfileHash: bytesN(k[14], 32),
    aggregatorPolicyHash: bytesN(k[15], 32),
  };
}

/** `D = networkDecimal:rootGenesisHex:executionGenesisHex:chainIdDecimal:zeroAddressHex`. */
export function identityDomain(network: number, rootGenesis: Uint8Array, executionGenesis: Uint8Array, chainId: bigint): string {
  return `${network}:${toHex(rootGenesis)}:${toHex(executionGenesis)}:${chainId}:${'0'.repeat(40)}`;
}

/** `ty = SHA256(UTF8("unicity-bridge:unicity-native:" + D))`; the vault is deliberately not part of it. */
export const deriveType = (n: number, rg: Uint8Array, eg: Uint8Array, c: bigint): Uint8Array =>
  H(enc.encode(`unicity-bridge:unicity-native:${identityDomain(n, rg, eg, c)}`));

/** `aid = SHA256(UTF8("unicity-bridge-coin:unicity-native:" + D))`. */
export const deriveAsset = (n: number, rg: Uint8Array, eg: Uint8Array, c: bigint): Uint8Array =>
  H(enc.encode(`unicity-bridge-coin:unicity-native:${identityDomain(n, rg, eg, c)}`));

/** The common wallet value envelope `tag(39050,[1,[[b(aid),b(amount)]],null])`. */
export const valueEnvelope = (aid: Uint8Array, amount: Uint8Array): Uint8Array =>
  C.encodeTag(TAG_WALLET_VALUE, arr(u(1), arr(arr(bs(aid), bs(amount))), C.encodeNull()));

/**
 * The sole admitted aggregator policy body `C("UNICITY_BR_AGG_PARTITION", 2, partition)`: it names the aggregation
 * partition only. Every anchor's UC authenticates its own historical shard and shard configuration hash; there is
 * no depth, shard list or allow-list in the policy.
 */
export interface Policy {
  partition: number;
}

export const makePolicy = (partition: number): Policy => ({ partition });

export const policyBytes = (p: Policy): Uint8Array => arr(bs(POLICY_DOMAIN), u(POLICY_VERSION), u(p.partition));

export const policyHash = (p: Policy): Uint8Array => H(policyBytes(p));

export function decodePolicy(b: Uint8Array): Policy {
  if (b.length > MAX_POLICY_BYTES) fail('ErrInputTooLarge');
  const k = arrayOf(scanOne(b), 3) ?? fail('ErrShape');
  if (!eq(bytesAny(k[0]), POLICY_DOMAIN)) fail('ErrShape');
  version(k[1], POLICY_VERSION);
  const partition = Number(uintMax(k[2], 0xffffffffn));
  if (partition === 0) fail('ErrIntRange');
  return { partition };
}

/**
 * The depth of a native shard ID: the bits before its terminator, `8*len - trailingZeroBits(lastByte) - 1`.
 * The ID is 1..33 bytes with a nonzero last byte (the terminator is that byte's lowest set bit).
 */
export function shardDepth(shard: Uint8Array): number {
  if (shard.length === 0 || shard.length > MAX_SHARD_BYTES) fail('ErrShardMismatch');
  const last = shard[shard.length - 1];
  if (last === 0) fail('ErrShardMismatch');
  let tz = 0;
  while (((last >> tz) & 1) === 0) tz++;
  return 8 * shard.length - tz - 1;
}

/** Whether the first `shardDepth(shard)` bits of `sid` equal the prefix bits of the native shard ID `shard`. */
export function shardCovers(shard: Uint8Array, sid: Uint8Array): boolean {
  const d = shardDepth(shard);
  const whole = d >> 3;
  for (let i = 0; i < whole; i++) if (sid[i] !== shard[i]) return false;
  const rest = d & 7;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return (sid[whole] & mask) === (shard[whole] & mask);
}

export const deriveSalt = (cfg: Uint8Array, n: bigint): Uint8Array => H(arr(dom('UNICITY_BR_SALT'), bs(cfg), u(n)));
export const deriveTokenId = (salt: Uint8Array, network: number): Uint8Array => H(arr(bs(salt), u(network)));

export const lockRecord = (
  zero: Uint8Array, ty: Uint8Array, aid: Uint8Array, amount: Uint8Array, id: Uint8Array, rcpt: Uint8Array,
): Uint8Array => arr(bs(zero), bs(ty), bs(aid), bs(amount), bs(id), bs(rcpt));

/** `d = H(C("UNICITY_BR_LOCK", b(cfg), n, K))`; binds cfg, nonce, amount, id, recipient, not J. */
export const lockDigest = (cfg: Uint8Array, n: bigint, k: Uint8Array): Uint8Array =>
  H(arr(dom('UNICITY_BR_LOCK'), bs(cfg), u(n), k));

export function returnReason(
  chainId: bigint, vault: Uint8Array, zero: Uint8Array, ty: Uint8Array, aid: Uint8Array,
  recipient: Uint8Array, amount: Uint8Array,
): Uint8Array {
  return C.encodeTag(
    TAG_RETURN_REASON,
    arr(u(1), u(chainId), bs(vault), bs(zero), bs(ty), bs(aid), bs(recipient), bs(amount), bs(zero), bs(new Uint8Array()), u(0)),
  );
}

export const burnId = (sid: Uint8Array, txHash: Uint8Array): Uint8Array =>
  H(arr(dom('unicity-burn-transition:v1'), bs(sid), bs(txHash)));

export const nullifier = (cfg: Uint8Array, btid: Uint8Array): Uint8Array =>
  H(arr(dom('UNICITY_BR_NUL'), bs(cfg), bs(btid)));

/** The certified leaf value `v = H(C(b(txHash32), t))`. */
export const leafValue = (txHash: Uint8Array, t: bigint): Uint8Array => H(arr(bs(txHash), u(t)));

// ---- vault storage layout ------------------------------------------------------------------------

// protocol 6 (interop.md "Resource and custody profile"): slot 6 is redeemedAmount (was the spent nullifier), 8 lockedAmount, 9 spentPart
export const SLOT_LOCK_DIGEST = 5n;
export const SLOT_REDEEMED_AMOUNT = 6n;
export const SLOT_CLAIMABLE = 7n;
export const SLOT_LOCKED_AMOUNT = 8n;
export const SLOT_SPENT_PART = 9n;

export function word(n: bigint): Uint8Array {
  const w = new Uint8Array(32);
  for (let i = 31, v = n; i >= 0; i--, v >>= 8n) w[i] = Number(v & 0xffn);
  return w;
}

export function mappingSlot(key: Uint8Array, base: bigint): Uint8Array {
  const k = new Uint8Array(32);
  k.set(key, 32 - key.length);
  return keccak256(k, word(base));
}

export const lockDigestSlot = (n: bigint): Uint8Array => mappingSlot(word(n), SLOT_LOCK_DIGEST);
export const redeemedAmountSlot = (n: bigint): Uint8Array => mappingSlot(word(n), SLOT_REDEEMED_AMOUNT);
export const lockedAmountSlot = (n: bigint): Uint8Array => mappingSlot(word(n), SLOT_LOCKED_AMOUNT);
/** `spentPart[nonce][partId]`: the inner mapping's slot is `keccak256(partId . keccak256(nonce . 9))`. */
export const spentPartSlot = (n: bigint, partId: Uint8Array): Uint8Array => keccak256(partId, mappingSlot(word(n), SLOT_SPENT_PART));
export const claimableSlot = (a: Uint8Array): Uint8Array => mappingSlot(a, SLOT_CLAIMABLE);
export const storageTrieKey = (slot: Uint8Array): Uint8Array => keccak256(slot);
export const accountTrieKey = (a: Uint8Array): Uint8Array => keccak256(a);
