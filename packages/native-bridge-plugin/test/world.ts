/**
 * Independent TS constructors: a complete synthetic native world built from the SDK's own public
 * types (SigningService, SparseMerkleTree, transactions, certificates). Mirrors the Rust world so
 * the two stacks can be compared byte for byte.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { InputRecord } from '@unicitylabs/state-transition-sdk/lib/api/bft/InputRecord.js';
import { ShardId } from '@unicitylabs/state-transition-sdk/lib/api/bft/ShardId.js';
import { ShardTreeCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/ShardTreeCertificate.js';
import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { UnicitySeal } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicitySeal.js';
import { UnicityTreeCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityTreeCertificate.js';
import { InclusionCertificate } from '@unicitylabs/state-transition-sdk/lib/api/InclusionCertificate.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { DataHasherFactory } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasherFactory.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { NodeDataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/NodeDataHasher.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { SignaturePredicateUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicateUnlockScript.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { SparseMerkleTree } from '@unicitylabs/state-transition-sdk/lib/smt/radix/SparseMerkleTree.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import { MintSigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/MintSigningService.js';

import { concat, toHex } from '../src/bytes.js';
import { DeploymentRegistry, makeDeployment, type Deployment } from '../src/deployment.js';
import { EMPTY_TRIE_ROOT, EMPTY_UNCLE_HASH } from '../src/header.js';
import { encodeJustification, encodeLockProof, type LockProof } from '../src/lockproof.js';
import {
  H, accountTrieKey, arr, bs, deriveAsset, deriveSalt, deriveTokenId, deriveType, keccak256, leafValue, lockDigest,
  lockDigestSlot, lockRecord, makePolicy, policyHash, returnReason, shardId, shardRow, storageTrieKey, u, valueEnvelope, type Policy,
} from '../src/profile.js';
import { encodeBytes, encodeList, encodeU64 } from '../src/rlp.js';
import { TrustInput } from '../src/trust.js';
import { NativeBridge } from '../src/verifier.js';

export const NETWORK = 3;
export const CHAIN_ID = 7777n;
export const EVM_PARTITION = 7;
export const AGG_PARTITION = 1;
export const VAULT = new Uint8Array(20).fill(0xaa);
export const ROOT_GENESIS = new Uint8Array(32).fill(0x11);
export const EXEC_GENESIS = new Uint8Array(32).fill(0x22);
export const ZERO20 = new Uint8Array(20);

export const sha = (b: Uint8Array): Uint8Array => sha256(b);
export const signer = (seed: number): SigningService => new SigningService(sha(Uint8Array.of(0x73, seed)));
export const text = (s: string): Uint8Array => new TextEncoder().encode(s);

// ---- Ethereum MPT builder ----------------------------------------------------------------------

const nibs = (k: Uint8Array): number[] => [...k].flatMap((b) => [b >> 4, b & 15]);

function hexPrefix(n: number[], leaf: boolean): Uint8Array {
  const flag = (leaf ? 2 : 0) | (n.length & 1);
  const out: number[] = [];
  let i = 0;
  if (n.length % 2 === 1) out.push((flag << 4) | n[i++]);
  else out.push(flag << 4);
  for (; i < n.length; i += 2) out.push((n[i] << 4) | n[i + 1]);
  return Uint8Array.from(out);
}

const childItem = (node: Uint8Array): Uint8Array => (node.length < 32 ? node : encodeBytes(keccak256(node)));

function build(entries: [number[], Uint8Array][], depth: number, target: number[], proof: Uint8Array[]): Uint8Array {
  const onPath = entries.some((e) => e[0].length === target.length && e[0].every((x, i) => x === target[i]));
  let node: Uint8Array;
  if (entries.length === 1) {
    node = encodeList([encodeBytes(hexPrefix(entries[0][0].slice(depth), true)), encodeBytes(entries[0][1])]);
  } else {
    const first = entries[0][0];
    let cp = 0;
    while (entries.every((e) => e[0].length > depth + cp && e[0][depth + cp] === first[depth + cp])) cp++;
    if (cp > 0) {
      const child = build(entries, depth + cp, target, proof);
      node = encodeList([encodeBytes(hexPrefix(first.slice(depth, depth + cp), false)), childItem(child)]);
    } else {
      const items: Uint8Array[] = [];
      for (let n = 0; n < 16; n++) {
        const group = entries.filter((e) => e[0][depth] === n);
        items.push(group.length === 0 ? encodeBytes(new Uint8Array()) : childItem(build(group, depth + 1, target, proof)));
      }
      items.push(encodeBytes(new Uint8Array()));
      node = encodeList(items);
    }
  }
  if (onPath && node.length >= 32) proof.push(node);
  return node;
}

/** `(root, root-first proof of target)` of a trie of 32-byte keys. */
export function trie(entries: [Uint8Array, Uint8Array][], target: Uint8Array): { root: Uint8Array; proof: Uint8Array[] } {
  const e = entries.map(([k, v]) => [nibs(k), v] as [number[], Uint8Array]);
  e.sort((a, b) => (a[0].join(',') < b[0].join(',') ? -1 : 1));
  const proof: Uint8Array[] = [];
  const root = build(e, 0, nibs(target), proof);
  return { root: keccak256(root), proof: proof.reverse() };
}

// ---- EVM backing -------------------------------------------------------------------------------

export function pdrBytes(epoch: bigint, setting: bigint): Uint8Array {
  const params = concat(Uint8Array.of(0xa1), C.encodeTextString('chainId'), C.encodeTextString('7777'));
  return C.encodeTag(39008, arr(
    u(1), u(NETWORK), u(EVM_PARTITION), bs(Uint8Array.of(0x80)), u(1), C.encodeNull(), u(0), u(256), bs(new Uint8Array()),
    u(2_500_000_000n + setting), C.encodeNull(), params, u(epoch), u(0),
    arr(arr(C.encodeTextString('evm-1'), bs(signer(99).publicKey), u(1))),
  ));
}

/** The genesis ConfigHash of {@link pdrBytes}: neutralised validators, epoch and activation round. */
export function pdrConfigHash(): Uint8Array {
  const raw = pdrBytes(5n, 0n);
  const elems = splitArray(raw.subarray(3));
  return H(C.encodeTag(39008, arr(...elems.slice(0, 12), u(0), u(0), C.encodeNull())));
}

function splitArray(b: Uint8Array): Uint8Array[] {
  // a minimal splitter over the test's own canonical encodings
  let pos = 1;
  const n = b[0] & 0x1f;
  const out: Uint8Array[] = [];
  const skip = (): void => {
    const ib = b[pos++];
    const major = ib >> 5;
    const ai = ib & 31;
    let arg = ai;
    if (ai === 24) arg = b[pos++];
    else if (ai === 25) { arg = (b[pos] << 8) | b[pos + 1]; pos += 2; }
    else if (ai === 26) { arg = b[pos] * 2 ** 24 + (b[pos + 1] << 16) + (b[pos + 2] << 8) + b[pos + 3]; pos += 4; }
    else if (ai === 27) { arg = Number(Buffer.from(b.subarray(pos, pos + 8)).readBigUInt64BE()); pos += 8; }
    if (major === 2 || major === 3) pos += arg;
    else if (major === 4) for (let i = 0; i < arg; i++) skip();
    else if (major === 5) for (let i = 0; i < arg * 2; i++) skip();
  };
  for (let i = 0; i < n; i++) {
    const s = pos;
    skip();
    out.push(b.subarray(s, pos));
  }
  return out;
}

export function headerRlp(stateRoot: Uint8Array, number: bigint, fields: 20 | 21): Uint8Array {
  const items: Uint8Array[] = [
    encodeBytes(new Uint8Array(32).fill(0x33)), encodeBytes(EMPTY_UNCLE_HASH), encodeBytes(new Uint8Array(20).fill(0x44)),
    encodeBytes(stateRoot), encodeBytes(new Uint8Array(32).fill(0x55)), encodeBytes(new Uint8Array(32).fill(0x66)),
    encodeBytes(new Uint8Array(256)), encodeU64(0n), encodeU64(number), encodeU64(30_000_000n), encodeU64(21_000n),
    encodeU64(1_700_000_000n), encodeBytes(text('native')), encodeBytes(new Uint8Array(32).fill(0x77)),
    encodeBytes(new Uint8Array(8)), encodeU64(7n), encodeBytes(EMPTY_TRIE_ROOT), encodeU64(0n), encodeU64(0n),
    encodeBytes(new Uint8Array(32).fill(0x88)),
  ];
  if (fields === 21) items.push(encodeBytes(new Uint8Array(32).fill(0x99)));
  return encodeList(items);
}

// ---- unicity certificates ------------------------------------------------------------------------

export interface Root {
  signers: [string, SigningService][];
  /** The pinned SDK trust document `B`. */
  doc: Uint8Array;
  trust: TrustInput;
}

/** A unit-weight SDK trust base document in the SDK's emitted field order. */
export function makeRoot(epoch: number, n: number, seed: number, stakes?: number[], threshold?: number): Root {
  const signers: [string, SigningService][] = Array.from({ length: n }, (_, i) => [`root-${seed}-${String(i).padStart(2, '0')}`, signer(seed + i)] as [string, SigningService]);
  signers.sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const th = threshold ?? n - Math.floor((n - 1) / 3);
  const nodes = signers.map(([id, s], i) => `{"nodeId":"${id}","sigKey":"${toHex(s.publicKey)}","stake":"${stakes?.[i] ?? 1}"}`);
  const doc = text(
    `{"changeRecordHash":null,"epoch":"${epoch}","epochStartRound":"1","networkId":${NETWORK},"previousEntryHash":null,"quorumThreshold":"${th}","rootNodes":[${nodes.join(',')}],"signatures":{},"stateHash":"","version":"1"}`,
  );
  return { signers, doc, trust: TrustInput.fromJson(doc, sha(doc)) };
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

export async function makeUc(root: Root, s: UcSpec): Promise<UnicityCertificate> {
  const ir = new InputRecord(s.round, s.epochIr, null, s.stateHash, new Uint8Array(), s.timestamp, s.blockHash, 0n, null);
  const shard = s.shard ? ShardId.decode(s.shard.bytes) : ShardId.decode(Uint8Array.of(0x80));
  const stc = new ShardTreeCertificate(shard, s.shard?.siblings ?? []);
  const shardRoot = await UnicityCertificate.calculateShardTreeCertificateRootHash(ir, null, s.conf, stc);
  const key = new Uint8Array(4);
  new DataView(key.buffer).setUint32(0, s.partition);
  const unicityTreeHash = sha(bs(shardRoot.data));
  const treeRoot = sha(concat(bs(Uint8Array.of(1)), bs(key), bs(unicityTreeHash)));
  const signers = new Map<string, SigningService>(root.signers.slice(0, s.signers));
  for (const [id, sg] of s.extra ?? []) signers.set(id, sg);
  const seal = await UnicitySeal.create(
    NetworkId.fromId(s.network ?? NETWORK), s.round, s.rootEpoch, s.timestamp, null, s.sealHash ?? treeRoot, signers,
  );
  return new UnicityCertificate(ir, null, s.conf, stc, new UnicityTreeCertificate(BigInt(s.partition), []), seal);
}

// ---- the world ---------------------------------------------------------------------------------

export interface World {
  agg: Root;
  evm: Root;
  dep: Deployment;
  bridge: NativeBridge;
  policy: Policy;
  /** The configuration hash of the first policy row (the only one at depth 0). */
  aggConf: Uint8Array;
  /** The configuration hash of every policy row. */
  aggConfs: Uint8Array[];
}

export function makeWorld(headerFields: 20 | 21 = 20, depth: 0 | 1 = 0): World {
  const agg = makeRoot(2, 4, 10);
  const evm = makeRoot(2, 4, 10);
  const aggConfs = Array.from({ length: 1 << depth }, (_, i) => sha(text(`aggregator shard configuration ${i}`)));
  if (depth === 0) aggConfs[0] = sha(text('aggregator shard configuration'));
  const aggConf = aggConfs[0];
  const policy: Policy = makePolicy(AGG_PARTITION, ...aggConfs);
  const cfg = {
    network: NETWORK, rootGenesis: ROOT_GENESIS, chainId: CHAIN_ID, executionGenesis: EXEC_GENESIS, evmPartition: EVM_PARTITION,
    evmShard: Uint8Array.of(0x80), vault: VAULT, zeroAddress: ZERO20,
    ty: deriveType(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID), aid: deriveAsset(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID),
    semanticProfileHash: sha(text('semantic profile v2')), tokenVerifierAddress: new Uint8Array(20).fill(0xbb),
    tokenVerifierCodeHash: sha(text('token verifier runtime')), b1ProfileHash: sha(text('b1 profile')),
    aggregatorPolicyHash: policyHash(policy),
  };
  const dep = makeDeployment(cfg, sha(text('vault runtime')), pdrConfigHash(), { fields: headerFields }, policy);
  const bridge = new NativeBridge(new DeploymentRegistry([dep]), agg.trust);
  return { agg, evm, dep, bridge, policy, aggConf, aggConfs };
}

export interface EvmSpec {
  vaultCodeHash: Uint8Array;
  stored?: Uint8Array;
  nonce: bigint;
  blockNumber: bigint;
}

export interface MintSpec {
  nonce: bigint;
  amount: Uint8Array;
  owner: SigningService;
  mintDeadline: bigint | null;
  evm: EvmSpec;
}

export function spec(owner: number): MintSpec {
  return {
    nonce: 1n, amount: Uint8Array.of(3, 232), owner: signer(owner), mintDeadline: null,
    evm: { vaultCodeHash: sha(text('vault runtime')), nonce: 1n, blockNumber: 1234n },
  };
}

export interface LockParts extends Omit<LockProof, 'uc'> {
  uc: UnicityCertificate;
  ucSpec: UcSpec;
  ucRaw?: Uint8Array;
}

export const ownerPredicate = (s: SigningService): EncodedPredicate => EncodedPredicate.fromPredicate(SignaturePredicate.create(s.publicKey));

export function digestOf(w: World, s: MintSpec): { digest: Uint8Array; salt: Uint8Array; tokenId: Uint8Array } {
  const salt = deriveSalt(w.dep.cfgHash, s.nonce);
  const tokenId = deriveTokenId(salt, NETWORK);
  const p0 = sha(ownerPredicate(s.owner).toCBOR());
  const digest = lockDigest(w.dep.cfgHash, s.nonce, lockRecord(ZERO20, w.dep.cfg.ty, w.dep.cfg.aid, s.amount, tokenId, p0));
  return { digest, salt, tokenId };
}

export async function lockParts(w: World, s: MintSpec): Promise<LockParts> {
  const { digest } = digestOf(w, s);
  const stored = s.evm.stored ?? digest;
  let i = 0;
  while (i < 32 && stored[i] === 0) i++;
  const skey = storageTrieKey(lockDigestSlot(s.evm.nonce));
  const other = storageTrieKey(lockDigestSlot(4242n));
  const st = trie([[skey, encodeBytes(stored.subarray(i))], [other, encodeBytes(Uint8Array.of(1, 2, 3))]], skey);
  const acct = encodeList([encodeU64(1n), encodeBytes(Uint8Array.of(0x0f, 0x42)), encodeBytes(st.root), encodeBytes(s.evm.vaultCodeHash)]);
  const akey = accountTrieKey(VAULT);
  const otherAcct = encodeList([encodeU64(0n), encodeBytes(new Uint8Array()), encodeBytes(st.root), encodeBytes(new Uint8Array(32))]);
  const ac = trie([[akey, acct], [accountTrieKey(new Uint8Array(20).fill(0xcc)), otherAcct]], akey);
  const header = headerRlp(ac.root, s.evm.blockNumber, w.dep.header.fields);
  const pdr = pdrBytes(5n, 0n);
  const ucSpec: UcSpec = {
    partition: EVM_PARTITION, conf: sha(pdr), epochIr: 5n, rootEpoch: 2n, round: 500n, timestamp: 1_700_000_100n,
    stateHash: ac.root, blockHash: keccak256(header), signers: 4,
  };
  const uc = await makeUc(w.evm, ucSpec);
  return { cfg: w.dep.cfgHash, trustBaseId: w.agg.trust.id, pdr, uc, ucSpec, header, accountNodes: ac.proof, storageNodes: st.proof };
}

export const encodeParts = (p: LockParts): Uint8Array => encodeLockProof({ ...p, uc: p.ucRaw ?? p.uc.toCBOR() });

export type Step =
  | { kind: 'transfer'; to: SigningService; mask: number; deadline: bigint | null; t: bigint }
  | { kind: 'burn'; recipient: Uint8Array; deadline: bigint | null; t: bigint }
  | { kind: 'burnWith'; reason: Uint8Array; t: bigint };

export const txStep = (to: number, mask: number, t: bigint, deadline: bigint | null = null): Step => ({ kind: 'transfer', to: signer(to), mask, deadline, t });
export const recipient20 = (): Uint8Array => new Uint8Array(20).fill(0xd0);
export const burnStep = (t: bigint): Step => ({ kind: 'burn', recipient: recipient20(), deadline: null, t });

/** Post-construction mutations applied with consistent hashes, so exactly one guard fires. */
export interface Tweaks {
  mintTy?: Uint8Array;
  mintNetwork?: number;
  mintData?: Uint8Array | null;
  mintJustification?: Uint8Array | null;
  mintSalt?: Uint8Array;
  cdDeadline?: [number, bigint | null][];
  unlock?: [number, (u: Uint8Array) => Uint8Array][];
  transferData?: [number, Uint8Array | null][];
  minterOverride?: SigningService;
  proofTime?: [number, bigint][];
  /** The root round of the certificate of leaf `i`; leaves of one shard in different rounds get different UCs. */
  ucRound?: (i: number) => bigint;
}

export interface TokenOut {
  token: Token;
  bytes: Uint8Array;
  /** The first certificate (the only one when every leaf is in one shard and round). */
  uc: UnicityCertificate;
  /** Every distinct certificate, in first-use leaf order. */
  ucs: UnicityCertificate[];
  leaves: [Uint8Array, Uint8Array][];
}

export async function buildToken(w: World, s: MintSpec, steps: Step[], mintT: bigint, ucTs: bigint, tw: Tweaks = {}, parts?: LockParts): Promise<TokenOut> {
  const lp = parts ?? (await lockParts(w, s));
  const { salt } = digestOf(w, s);
  const journal = encodeJustification(CHAIN_ID, VAULT, ZERO20, s.nonce, encodeParts(lp));
  const mint = await MintTransaction.create(NetworkId.fromId(tw.mintNetwork ?? NETWORK), SignaturePredicate.create(s.owner.publicKey), {
    data: tw.mintData === undefined ? valueEnvelope(w.dep.cfg.aid, s.amount) : tw.mintData,
    expiresAt: s.mintDeadline,
    justification: tw.mintJustification === undefined ? journal : tw.mintJustification,
    salt: TokenSalt.fromBytes(tw.mintSalt ?? salt),
    tokenType: new TokenType(tw.mintTy ?? w.dep.cfg.ty),
  });
  return assembleToken(w, s, mint, tw, steps, mintT, ucTs);
}

const unlockFor = async (tx: { calculateTransactionHash(): Promise<unknown> }, signingService: SigningService): Promise<Uint8Array> =>
  (await SignaturePredicateUnlockScript.create(tx as never, signingService)).encode();

function cdBytes(lock: EncodedPredicate, sourceHash: Uint8Array, txHash: Uint8Array, e: bigint | null, unlock: Uint8Array): Uint8Array {
  return C.encodeTag(39031, arr(u(2), lock.toCBOR(), bs(sourceHash), bs(txHash), C.encodeNullable(e, C.encodeUnsignedInteger), bs(unlock)));
}

export async function assembleToken(w: World, s: MintSpec, mint: MintTransaction, tw: Tweaks, steps: Step[], mintT: bigint, ucTs: bigint): Promise<TokenOut> {
  interface Item { txBytes: Uint8Array; cd: Uint8Array; sid: Uint8Array; txHash: Uint8Array; t: bigint }
  const items: Item[] = [];
  const tweakUnlock = (i: number, un: Uint8Array): Uint8Array => (tw.unlock ?? []).filter(([k]) => k === i).reduce((a, [, f]) => f(a), un);
  const cdDeadline = (i: number, e: bigint | null): bigint | null => {
    const f = (tw.cdDeadline ?? []).find(([k]) => k === i);
    return f ? f[1] : e;
  };
  const minterService = tw.minterOverride ?? (await MintSigningService.create(mint.tokenId));
  const mintHash = await mint.calculateTransactionHash();
  const mintUnlock = tweakUnlock(0, (await SignaturePredicateUnlockScript.create(mint, minterService)).encode());
  const mintSid = sha(arr(mint.lockScript.toCBOR(), bs(mint.sourceStateHash.data)));
  items.push({ txBytes: mint.toCBOR(), cd: cdBytes(mint.lockScript, mint.sourceStateHash.data, mintHash.data, cdDeadline(0, mint.expiresAt), mintUnlock), sid: mintSid, txHash: mintHash.data, t: mintT });
  let state = (await mint.calculateStateHash()).data;
  let stateHash = await mint.calculateStateHash();
  let lock = mint.recipient;
  let curOwner = s.owner;
  for (let k = 0; k < steps.length; k++) {
    const i = k + 1;
    const st = steps[k];
    let recipient: EncodedPredicate;
    let mask: Uint8Array;
    let data: Uint8Array | null = null;
    let deadline: bigint | null;
    let t: bigint;
    let nextOwner: SigningService | null = null;
    if (st.kind === 'transfer') {
      recipient = ownerPredicate(st.to); mask = new Uint8Array(32).fill(st.mask); deadline = st.deadline; t = st.t; nextOwner = st.to;
    } else {
      const reason = st.kind === 'burn' ? returnReason(CHAIN_ID, VAULT, ZERO20, w.dep.cfg.ty, w.dep.cfg.aid, st.recipient, s.amount) : st.reason;
      recipient = EncodedPredicate.fromPredicate(BurnPredicate.create(sha(reason)));
      mask = new Uint8Array(32).fill(0x42); data = reason; deadline = st.kind === 'burn' ? st.deadline : null; t = st.t;
    }
    const td = (tw.transferData ?? []).find(([idx]) => idx === i);
    if (td) data = td[1];
    const txBytes = C.encodeTag(39045, arr(u(2), recipient.toCBOR(), bs(mask), C.encodeNullable(data, C.encodeByteString), C.encodeNullable(deadline, C.encodeUnsignedInteger)));
    const tx = TransferTransaction.fromCBOR(txBytes, stateHash, lock);
    const th = await tx.calculateTransactionHash();
    const unlock = tweakUnlock(i, await unlockFor(tx, signerService(curOwner)));
    items.push({ txBytes, cd: cdBytes(lock, stateHash.data, th.data, cdDeadline(i, deadline), unlock), sid: sha(arr(lock.toCBOR(), bs(stateHash.data))), txHash: th.data, t });
    stateHash = await tx.calculateStateHash();
    state = stateHash.data;
    lock = recipient;
    if (nextOwner) curOwner = nextOwner;
  }
  void state;
  const values = items.map((it) => leafValue(it.txHash, it.t));
  const factory = new DataHasherFactory(HashAlgorithm.SHA256, NodeDataHasher);
  // One tree and one certificate per (shard row, root round): leaves of a shard certified in different
  // rounds are separate anchors even when every other field is equal.
  const groups = new Map<string, { row: number; round: bigint; members: number[] }>();
  items.forEach((it, i) => {
    const row = shardRow(w.policy, it.sid);
    const round = tw.ucRound ? tw.ucRound(i) : 900n;
    const key = `${row}:${round}`;
    const g = groups.get(key) ?? { row, round, members: [] };
    g.members.push(i);
    groups.set(key, g);
  });
  const certOf: { root: Awaited<ReturnType<SparseMerkleTree['calculateRoot']>>; uc: UnicityCertificate }[] = new Array(items.length);
  const ucs: UnicityCertificate[] = [];
  for (const g of groups.values()) {
    const smt = new SparseMerkleTree(factory);
    for (const i of g.members) await smt.addLeaf(items[i].sid, values[i]);
    const root = await smt.calculateRoot();
    const uc = await makeUc(w.agg, {
      partition: AGG_PARTITION, conf: w.aggConfs[g.row], epochIr: 1n, rootEpoch: 2n, round: g.round, timestamp: ucTs, stateHash: root.hash.data,
      blockHash: null, signers: 4,
      shard: { bytes: shardId(w.policy, g.row), siblings: w.policy.depth === 0 ? [] : [sha(text(`sibling of shard ${g.row}`))] },
    });
    for (const i of g.members) certOf[i] = { root, uc };
  }
  // Certificates in first-use leaf order.
  for (let i = 0; i < items.length; i++) if (!ucs.includes(certOf[i].uc)) ucs.push(certOf[i].uc);
  const proofs = items.map((it, i) => {
    const t = (tw.proofTime ?? []).find(([k]) => k === i)?.[1] ?? it.t;
    const cert = InclusionCertificate.create(certOf[i].root, it.sid);
    return C.encodeTag(39033, arr(u(1), it.cd, u(t), bs(cert.encode()), certOf[i].uc.toCBOR()));
  });
  const certified = items.map((it, i) => arr(it.txBytes, proofs[i]));
  const bytes = C.encodeTag(39040, arr(u(2), certified[0], arr(...certified.slice(1))));
  const token = await Token.fromCBOR(bytes);
  return { token, bytes, uc: ucs[0], ucs, leaves: items.map((it, i) => [it.sid, values[i]]) };
}

// The signer service for a SigningService key owner (identity).
const signerService = (s: SigningService): SigningService => s;

export { concat };
