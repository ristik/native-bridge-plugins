/**
 * Root committee fixtures for the trust-input tests: trust-base entries (tag 39000) of a fixture network, their release bundle and
 * certificates signed by a committee. Moved verbatim from the protocol 7 test world when that bridge was removed (bft-core#1106).
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { InputRecord } from '@unicitylabs/state-transition-sdk/lib/api/bft/InputRecord.js';
import { ShardId } from '@unicitylabs/state-transition-sdk/lib/api/bft/ShardId.js';
import { ShardTreeCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/ShardTreeCertificate.js';
import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { UnicitySeal } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicitySeal.js';
import { UnicityTreeCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityTreeCertificate.js';
import { RootTrustBaseV2 } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/RootTrustBaseV2.js';
import { TrustBaseBundle } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseBundle.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { DataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasher.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { CborMap } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborMap.js';
import { CborMapEntry } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborMapEntry.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';

import { concat } from '../src/bytes.js';
import { TrustInput } from '../src/trust.js';

export const NETWORK = 3;
export const AGG_PARTITION = 7;

export const sha = (b: Uint8Array): Uint8Array => sha256(b);
export const signer = (seed: number): SigningService => new SigningService(sha(Uint8Array.of(0x73, seed)));
const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const bs = (b: Uint8Array): Uint8Array => C.encodeByteString(b);

export interface Root {
  /** The committee of the latest epoch: it signs this root's certificates. */
  signers: [string, SigningService][];
  /** Every entry from the genesis, canonical bytes. */
  entries: Uint8Array[];
  /** The release bundle (tag 39015) of {@link entries}. */
  bundle: Uint8Array;
  /** The genesis EntryID: the trust pin and every lock proof's `trustBaseId`. */
  pin: Uint8Array;
  trust: TrustInput;
}

const members = (signers: [string, SigningService][], weights?: number[]) =>
  signers.map(([nodeId, s], i) => ({ nodeId, signingKey: s.publicKey, weight: BigInt(weights?.[i] ?? 1) }));
/** A version-2 trust base entry (tag 39000) of the fixture network, encoded at the CBOR level: the SDK's entry class has no public constructor. */
function entryBytes(f: {
  epoch: bigint; epochStartRound: bigint; previousEntryId: Uint8Array; quorumThreshold: bigint;
  rootNodes: { nodeId: string; signingKey: Uint8Array; weight: bigint }[]; signatures: Map<string, Uint8Array> | null;
}): Uint8Array {
  return C.encodeTag(39000n, C.encodeArray(
    C.encodeUnsignedInteger(2n), C.encodeUnsignedInteger(BigInt(NETWORK)), C.encodeUnsignedInteger(f.epoch), C.encodeUnsignedInteger(f.epochStartRound),
    C.encodeArray(...f.rootNodes.map((m) => C.encodeArray(C.encodeTextString(m.nodeId), C.encodeByteString(m.signingKey), C.encodeUnsignedInteger(m.weight)))),
    C.encodeUnsignedInteger(f.quorumThreshold), C.encodeNull(), C.encodeNull(), C.encodeByteString(f.previousEntryId),
    f.signatures === null ? C.encodeNull()
      : C.encodeMap(new CborMap([...f.signatures].map(([id, sig]) => new CborMapEntry(C.encodeTextString(id), C.encodeByteString(sig))))),
  ));
}

const thresholdOf = (weights: bigint[]): bigint => (2n * weights.reduce((a, b) => a + b, 0n)) / 3n + 1n;

function committee(n: number, seed: number): [string, SigningService][] {
  const signers: [string, SigningService][] = Array.from({ length: n }, (_, i) => [`root-${seed}-${String(i).padStart(2, '0')}`, signer(seed + i)] as [string, SigningService]);
  return signers.sort((a, b) => (a[0] < b[0] ? -1 : 1));
}

async function rootOf(signers: [string, SigningService][], entries: Uint8Array[], pin: Uint8Array): Promise<Root> {
  const bundle = await TrustBaseBundle.encode(entries.map((e) => RootTrustBaseV2.decode(e)));
  return { signers, entries, bundle, pin, trust: await TrustInput.fromBundle(bundle, pin) };
}

/** A trust base history holding only a genesis entry of epoch `epoch` (start round 1) with `n` members, unit weights unless given. */
export async function makeRoot(epoch: number, n: number, seed: number, weights?: number[]): Promise<Root> {
  const signers = committee(n, seed);
  const rootNodes = members(signers, weights);
  const genesisBytes = entryBytes({
    epoch: BigInt(epoch), epochStartRound: 1n, previousEntryId: new Uint8Array(32), quorumThreshold: thresholdOf(rootNodes.map((m) => m.weight)), rootNodes,
    signatures: null,
  });
  return rootOf(signers, [genesisBytes], await RootTrustBaseV2.decode(genesisBytes).entryId());
}

/**
 * The next epoch of `root`, from root round `start`: a committee of `n` members (seed `seed`), witnessed by every member of the current one.
 * Same pin, one more entry; the new committee signs the new root's certificates.
 */
export async function nextEpoch(root: Root, start: bigint, n: number, seed: number, weights?: number[]): Promise<Root> {
  return rootOf(committee(n, seed), [...root.entries, await successorEntry(root, start, n, seed, weights)], root.pin);
}

/** The canonical bytes of the entry {@link nextEpoch} appends, witnessed by `witnesses` (the current committee unless given). */
export async function successorEntry(root: Root, start: bigint, n: number, seed: number, weights?: number[], witnesses = root.signers): Promise<Uint8Array> {
  const tip = RootTrustBaseV2.decode(root.entries[root.entries.length - 1]);
  const rootNodes = members(committee(n, seed), weights);
  const fields = { epoch: tip.epoch + 1n, epochStartRound: start, previousEntryId: await tip.entryId(), quorumThreshold: thresholdOf(rootNodes.map((m) => m.weight)), rootNodes };
  // the entry id and the witnesses' message are over the entry with a null signature field
  const hash = await new DataHasher(HashAlgorithm.SHA256).update(entryBytes({ ...fields, signatures: null })).digest();
  const signatures = new Map<string, Uint8Array>();
  for (const [id, s] of witnesses) signatures.set(id, (await s.sign(hash)).encode());
  return entryBytes({ ...fields, signatures });
}

export interface UcSpec {
  partition: number;
  conf: Uint8Array;
  epochIr: bigint;
  rootEpoch: bigint;
  round: bigint;
  timestamp: bigint;
  stateHash: Uint8Array;
  blockHash: Uint8Array | null;
  signers: number;
  /** Override the seal's committed unicity-tree root (to test a false root). */
  sealHash?: Uint8Array;
  network?: number;
  /** Extra signers keyed by id (strangers or wrong-key signatures). */
  extra?: [string, SigningService][];
  shard?: { bytes: Uint8Array; siblings: Uint8Array[] };
}

/** Every fixture certificate's technical record hash (natively it is always 32 bytes). */
const TECHNICAL_RECORD_HASH = sha(text('technical record'));

export async function makeUc(root: Root, s: UcSpec): Promise<UnicityCertificate> {
  // Native-valid records (bft-go-base IsValid, checked by the SDK): an aggregator round that changes the state always has a block
  const blockHash = s.blockHash ?? (s.partition === AGG_PARTITION ? sha(concat(text('aggregator block'), s.stateHash)) : null);
  const ir = new InputRecord(s.round, s.epochIr, null, s.stateHash, new Uint8Array(), s.timestamp, blockHash, 0n, null);
  const shard = s.shard ? ShardId.decode(s.shard.bytes) : ShardId.decode(Uint8Array.of(0x80));
  const stc = new ShardTreeCertificate(shard, s.shard?.siblings ?? []);
  const shardRoot = await UnicityCertificate.calculateShardTreeCertificateRootHash(ir, TECHNICAL_RECORD_HASH, s.conf, stc);
  const key = new Uint8Array(4);
  new DataView(key.buffer).setUint32(0, s.partition);
  const unicityTreeHash = sha(bs(shardRoot.data));
  const treeRoot = sha(concat(bs(Uint8Array.of(1)), bs(key), bs(unicityTreeHash)));
  const signers = new Map<string, SigningService>(root.signers.slice(0, s.signers));
  for (const [id, sg] of s.extra ?? []) signers.set(id, sg);
  const seal = await UnicitySeal.create(
    NetworkId.fromId(s.network ?? NETWORK), s.round, s.rootEpoch, s.timestamp, null, s.sealHash ?? treeRoot, signers,
  );
  return new UnicityCertificate(ir, TECHNICAL_RECORD_HASH, s.conf, stc, new UnicityTreeCertificate(BigInt(s.partition), []), seal);
}
