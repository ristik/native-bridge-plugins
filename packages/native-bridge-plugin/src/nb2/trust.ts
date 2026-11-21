/**
 * Historical authority (section 11.3; bft-core `nb2ref/trust.go`). The trust input is the network's Unicity Trust Base history (the
 * SDK's `TrustBaseHistory`, installed from a release bundle and pinned by its genesis EntryID, `Γ.rootGenesis32`). Every UC is
 * judged under the entry of its own seal epoch by the upstream seal rule: an unknown signer or a signature that fails the weighting
 * rule counts zero, the weights reach floor(2W/3)+1 of that entry, and no legacy pre-scan rejects a seal for a signature's length or
 * recovery byte.
 */
import { ShardId } from '@unicitylabs/state-transition-sdk/lib/api/bft/ShardId.js';
import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { UnicityCertificateVerifier } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/UnicityCertificateVerifier.js';
import { UnicitySealQuorumSignaturesVerificationRule } from '@unicitylabs/state-transition-sdk/lib/api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js';
import { Secp256k1SignatureVerifier } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Secp256k1SignatureVerifier.js';

import { eq, toHex } from '../bytes.js';
import { HU } from './crypto.js';
import { nativeUcScan } from '../resources.js';
import { certificateFailure, TrustInput } from '../trust.js';
import { NativeError } from '../errors.js';
import { array, isBytes, isUint, scanNative, tagContent, type Item } from './cbor.js';
import type { Config } from './config.js';
import { Nb2Error, fail, refuse, wrap, type Rule } from './errors.js';

export { TrustInput };

/** The B1 bound of one certificate's bytes (b1ref.MaxUCBytes). */
export const MAX_B1_UC_BYTES = 24_576;

/** The history must be the one Γ names: its genesis EntryID is rootGenesis32 and its network Γ's. */
export function bindTrust(t: TrustInput, c: Config): void {
  if (!eq(t.id, c.rootGenesis) || Number(t.network.id) !== c.network) refuse('TrustInput', 'the trust-base history is not the one Γ names');
}

const TAG_UC = 39001n;
const SDK_FIELDS: { index: number; arity: number; required: number; tag: bigint; major: number }[] = [
  { index: 1, arity: 10, required: 5, tag: 39002n, major: 2 },
  { index: 4, arity: 3, required: 2, tag: 39003n, major: 4 },
  { index: 5, arity: 3, required: 2, tag: 39004n, major: 4 },
  { index: 6, arity: 8, required: 7, tag: 39005n, major: 5 },
];

/** The SDK codec subset of a certificate (field majors, seal network 1..65535, byte-string signatures), then the native scan. */
function scanCertificate(raw: Uint8Array): void {
  if (raw.length > MAX_B1_UC_BYTES) fail('InputTooLarge');
  const uc = array(tagContent(scanNative(raw), TAG_UC), 7);
  for (const f of SDK_FIELDS) {
    const body: Item = tagContent(uc[f.index], f.tag);
    const k = array(body, f.arity);
    if (k[f.required].major !== f.major) fail('Shape', `SDK field ${f.index}`);
  }
  const seal = uc[6].kids[0].kids;
  if (!isUint(seal[1]) || seal[1].arg === 0n || seal[1].arg > 65535n) fail('Shape', 'seal network');
  for (let i = 1; i < seal[7].kids.length; i += 2) if (!isBytes(seal[7].kids[i])) fail('Shape', 'seal signature');
  try {
    nativeUcScan(raw, MAX_B1_UC_BYTES);
  } catch (e) {
    if (e instanceof NativeError) fail('Shape', e.reason);
    throw e;
  }
}

/** The bounded certificate scan and the canonical decode; every failure is `UnsupportedCertificateEncoding`. */
export function decodeUc(raw: Uint8Array): UnicityCertificate {
  try {
    scanCertificate(raw);
  } catch (e) {
    wrap('UnsupportedCertificateEncoding', e);
  }
  let uc: UnicityCertificate;
  try {
    uc = UnicityCertificate.fromCBOR(raw);
  } catch (e) {
    return fail('UnsupportedCertificateEncoding', String((e as Error)?.message ?? e).slice(0, 120));
  }
  let again: Uint8Array;
  try {
    again = uc.toCBOR();
  } catch {
    return fail('UnsupportedCertificateEncoding', 'not re-encodable');
  }
  if (!eq(again, raw)) fail('UnsupportedCertificateEncoding', 'noncanonical');
  return uc;
}

const UC_VERIFIER = new UnicityCertificateVerifier(
  new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier(), undefined, { maxSignatures: 16 }),
);

const NATIVE_TO_RULE: Record<string, Rule> = {
  ErrSealNetwork: 'SealNetwork', ErrNoEntryForEpoch: 'NoEntryForEpoch', ErrSealEpoch: 'SealEpoch', ErrCertStructure: 'CertStructure',
  ErrSealRoot: 'SealRoot', ErrQuorumNotMet: 'QuorumNotMet', ErrTrustBase: 'CertStructure',
};

function asRule(e: unknown): never {
  if (e instanceof NativeError) throw new Nb2Error(NATIVE_TO_RULE[e.reason] ?? 'CertStructure', e.detail ?? e.reason);
  throw e;
}

/**
 * One UC for the expected partition and shard, in the order of bft-core `nb2ref` (after the NB2-05 UC order): the seal's network
 * (`SealNetwork`), the structure (`CertStructure`: partition, shard, input record, a 32-byte ShardConfHash), the shard and unicity tree
 * folds over the UC's own ShardConfHash to the seal hash (`SealRoot`), then the entry of the seal's epoch (`NoEntryForEpoch`,
 * `SealEpoch`) and the quorum under it (`QuorumNotMet`). No expected configuration hash is supplied.
 */
export async function ucCheck(t: TrustInput, uc: UnicityCertificate, partition: number, shard: Uint8Array): Promise<void> {
  if (!uc.unicitySeal.networkId.equals(t.network)) fail('SealNetwork');
  if (uc.shardConfigurationHash.length !== 32) fail('CertStructure', 'ShardConfHash is not 32 bytes');
  if (!eq(uc.shardTreeCertificate.shard.encode(), shard)) fail('CertStructure', 'shard');
  if (BigInt(uc.unicityTreeCertificate.partitionIdentifier) !== BigInt(partition)) fail('CertStructure', 'partition');
  let r;
  try {
    r = await UC_VERIFIER.verifyCertificate(t.history, uc, { partitionId: uc.unicityTreeCertificate.partitionIdentifier });
  } catch (e) {
    return asRule(e);
  }
  if (String(r.status) !== 'OK') {
    const reason = certificateFailure(r) ?? 'ErrQuorumNotMet';
    fail(NATIVE_TO_RULE[reason] ?? 'CertStructure', reason);
  }
}

/**
 * A deposit or seal receipt's EVM certificate for exactly (Γ.evmPartition, Γ.evmShard). Every failure is `DepositUC` except
 * `NoEntryForEpoch`, which keeps its retryable name.
 */
export async function verifyEvmUc(t: TrustInput, raw: Uint8Array, c: Config): Promise<UnicityCertificate> {
  let uc: UnicityCertificate;
  try {
    uc = decodeUc(raw);
  } catch (e) {
    return wrap('DepositUC', e);
  }
  try {
    ShardId.decode(c.evmShard);
  } catch {
    fail('DepositUC', 'Γ.evmShard');
  }
  try {
    await ucCheck(t, uc, c.evmPartition, c.evmShard);
  } catch (e) {
    // retryable on the wallet side; on chain it is DepositUC
    if (e instanceof Nb2Error && e.rule === 'NoEntryForEpoch') throw new Nb2Error('NoEntryForEpoch', e.detail, undefined, new Nb2Error('DepositUC'));
    wrap('DepositUC', e);
  }
  return uc;
}

/** Whether a state ID falls in a shard's key range (the shard ID's bits are a prefix of the ID's). */
export function inShard(shard: ShardId, sid: Uint8Array): boolean {
  return shard.isPrefixOf(sid);
}

/** For one complete seal and shard, canonical UC equality implies exact B1 claim equality. */
export function claimConsistency(): (uc: UnicityCertificate, raw: Uint8Array) => void {
  const claims = new Map<string, string>();
  return (uc, raw) => {
    const key = [toHex(HU(uc.unicitySeal.toCBOR())), uc.unicityTreeCertificate.partitionIdentifier,
      toHex(uc.shardTreeCertificate.shard.encode())].join('/');
    const digest = toHex(HU(raw));
    const previous = claims.get(key);
    if (previous !== undefined && previous !== digest) fail('CertStructure', 'conflicting claims for the same seal and shard');
    claims.set(key, digest);
  };
}
