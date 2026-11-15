/**
 * The offline simulator of NB2-07's tests: a trust-base history, a fake aggregator (one RSMT leaf and one certificate per request) and
 * a fake EVM gateway that executes deposits and redemptions against the in-process vault model, certifies every block (the UC of block
 * N in the companion of N+1), and answers the section 12.7 methods with the gateway's limits. The token verifier inside the vault is
 * the plug-in's own `verifyReturn` (the Solidity verifier is NB2-05's; the live run against it is NB2-09's).
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
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { InclusionCertificate } from '@unicitylabs/state-transition-sdk/lib/api/InclusionCertificate.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { DataHasherFactory } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasherFactory.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { NodeDataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/NodeDataHasher.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { SparseMerkleTree } from '@unicitylabs/state-transition-sdk/lib/smt/radix/SparseMerkleTree.js';

import { concat, eq, fromHex, toHex } from '../../src/bytes.js';
import { SELECTOR, revertData } from '../../src/nb2/abi.js';
import { ascii, beInt, cArr, cBytes, cTag, cUint, u256 } from '../../src/nb2/cbor.js';
import { ASSET_UCT, TEST_PARAMS, deriveCoin, deriveType, domainOf, encodeConfig, type Config } from '../../src/nb2/config.js';
import { HE, HU } from '../../src/nb2/crypto.js';
import { TOPIC, depositedData } from '../../src/nb2/deposit.js';
import { Nb2Error } from '../../src/nb2/errors.js';
import { decodeSignedTx } from '../../src/nb2/evm.js';
import { EMPTY_TRIE_ROOT, EMPTY_UNCLE_HASH, encodeHeader, type Header } from '../../src/nb2/header.js';
import { buildTrie } from '../../src/nb2/mpt.js';
import { rlpBytes, rlpIndexKey, rlpList, rlpUintEnc } from '../../src/nb2/rlp.js';
import { segmentSealedData } from '../../src/nb2/segment.js';
import { TrustInput } from '../../src/nb2/trust.js';
import { RpcError, type JsonRpc } from '../../src/nb2/rpc.js';
import { VaultModel, type RecipientBehaviour, type VaultEvent } from '../../src/nb2/vaultmodel.js';
import { verdictAbi, verifyReturn } from '../../src/nb2/verify.js';
import type { Aggregator } from '../../src/nb2/tokenops.js';
import { deriveBridgeKey, type BridgeOptions } from '../../src/nb2/bridge.js';
import { LocalKeySigner } from '../../src/nb2/evm.js';
import { MemoryJournalStore } from '../../src/nb2/journal.js';

export const NETWORK = 3;
export const CHAIN_ID = 31337n;
export const EVM_PARTITION = 8;
export const AGG_PARTITION = 7;
export const VAULT = new Uint8Array(20).fill(0xaa);
export const VERIFIER = new Uint8Array(20).fill(0xbb);
const sha = (b: Uint8Array): Uint8Array => sha256(b);
export const key = (seed: string): Uint8Array => sha(ascii(`key ${seed}`));
const h = (b: Uint8Array): string => `0x${toHex(b)}`;
const q = (v: bigint | number): string => `0x${BigInt(v).toString(16)}`;

// ---- trust base -------------------------------------------------------------------------------------

export interface Root { signers: [string, SigningService][]; bundle: Uint8Array; pin: Uint8Array; trust: TrustInput }

export async function makeRoot(n = 4): Promise<Root> {
  const signers: [string, SigningService][] = Array.from({ length: n }, (_, i) => [`root-${String(i).padStart(2, '0')}`, new SigningService(key(`root ${i}`))]);
  const entry = C.encodeTag(39000n, C.encodeArray(
    C.encodeUnsignedInteger(2n), C.encodeUnsignedInteger(BigInt(NETWORK)), C.encodeUnsignedInteger(1n), C.encodeUnsignedInteger(1n),
    C.encodeArray(...signers.map(([id, s]) => C.encodeArray(C.encodeTextString(id), C.encodeByteString(s.publicKey), C.encodeUnsignedInteger(1n)))),
    C.encodeUnsignedInteger(BigInt(Math.floor((2 * n) / 3) + 1)), C.encodeNull(), C.encodeNull(), C.encodeByteString(new Uint8Array(32)), C.encodeNull(),
  ));
  const pin = await RootTrustBaseV2.decode(entry).entryId();
  const bundle = await TrustBaseBundle.encode([RootTrustBaseV2.decode(entry)]);
  return { signers, bundle, pin, trust: await TrustInput.fromBundle(bundle, pin) };
}

const TR_HASH = sha(ascii('technical record'));
let round = 1000n;

export async function makeUc(root: Root, partition: number, stateHash: Uint8Array, blockHash: Uint8Array, timestamp: bigint): Promise<Uint8Array> {
  const ir = new InputRecord(++round, 1n, null, stateHash, new Uint8Array(), timestamp, blockHash, 0n, null);
  const conf = sha(ascii(`shard configuration ${partition}`));
  const stc = new ShardTreeCertificate(ShardId.decode(Uint8Array.of(0x80)), []);
  const shardRoot = await UnicityCertificate.calculateShardTreeCertificateRootHash(ir, TR_HASH, conf, stc);
  const pkey = new Uint8Array(4);
  new DataView(pkey.buffer).setUint32(0, partition);
  const treeRoot = sha(concat(C.encodeByteString(Uint8Array.of(1)), C.encodeByteString(pkey), C.encodeByteString(sha(C.encodeByteString(shardRoot.data)))));
  const seal = await UnicitySeal.create(NetworkId.fromId(NETWORK), round, 1n, timestamp, null, treeRoot, new Map(root.signers));
  return new UnicityCertificate(ir, TR_HASH, conf, stc, new UnicityTreeCertificate(BigInt(partition), []), seal).toCBOR();
}

// ---- deployment ---------------------------------------------------------------------------------------

export function makeConfig(root: Root, K = 4n, B = 2n): Config {
  const executionGenesis = sha(ascii('execution genesis'));
  return {
    network: NETWORK, rootGenesis: root.pin, executionGenesis, chainId: CHAIN_ID, evmPartition: EVM_PARTITION, evmShard: Uint8Array.of(0x80),
    aggregatorPartition: AGG_PARTITION, vault: VAULT, asset: ASSET_UCT, ty: deriveType(NETWORK, root.pin, executionGenesis, CHAIN_ID),
    aid: deriveCoin(NETWORK, root.pin, executionGenesis, CHAIN_ID), semanticProfileHash: sha(ascii('profile')), verifier: VERIFIER,
    verifierCodeHash: sha(ascii('verifier code')), K, B, Qmax: (1n << 120n) - 1n,
  };
}

// ---- aggregator -----------------------------------------------------------------------------------------

export class FakeAggregator implements Aggregator {
  private readonly certified = new Map<string, Uint8Array>();
  public time = 1_700_000_000n;
  public calls = 0;
  public constructor(private readonly root: Root) {}

  public async certify(request: Uint8Array): Promise<Uint8Array> {
    this.calls++;
    const cd = CertificationData.fromCBOR(request);
    const sid = (await StateId.fromCertificationData(cd)).data;
    const prior = this.certified.get(toHex(sid));
    if (prior !== undefined) {
      // single spend: the same request gets its proof again, another transaction from the same state is refused
      if (toHex(prior).includes(toHex(request))) return prior;
      throw new Error('fake aggregator: state already spent by another transaction');
    }
    const t = ++this.time;
    const smt = new SparseMerkleTree(new DataHasherFactory(HashAlgorithm.SHA256, NodeDataHasher));
    await smt.addLeaf(sid, HU(cArr(cBytes(cd.transactionHash.data), cUint(t))));
    const r = await smt.calculateRoot();
    const uc = await makeUc(this.root, AGG_PARTITION, r.hash.data, sha(concat(ascii('aggregator block'), r.hash.data)), t + 1n);
    const proof = cTag(39033, cArr(cUint(1), request, cUint(t), cBytes(InclusionCertificate.create(r, sid).encode()), uc));
    this.certified.set(toHex(sid), proof);
    return proof;
  }
}

// ---- the EVM gateway --------------------------------------------------------------------------------------

interface Log { address: Uint8Array; topics: Uint8Array[]; data: Uint8Array }
interface Rcpt { status: 0n | 1n; logs: Log[]; tx: Uint8Array; from: Uint8Array; revert: Uint8Array | null; gas: bigint; type: number }
interface Block { header: Header; hash: Uint8Array; uc: Uint8Array | null; receipts: Rcpt[] }

export interface Faults {
  /** The next N sends are included but answered with HTTP 503 (partial broadcast, #1121). */
  ambiguousSends: number;
  /** SegmentSealed logs of these segments are not served by eth_getLogs. */
  hideSegments: Set<bigint>;
  /** Hide every SegmentSealed log (a provider that withholds seals). */
  hideAllSeals: boolean;
  /** Recipient behaviour by address hex. */
  recipients: Map<string, RecipientBehaviour>;
}

export class FakeChain implements JsonRpc {
  public readonly blocks: Block[] = [];
  public readonly vault: VaultModel;
  public readonly balances = new Map<string, bigint>();
  private readonly nonces = new Map<string, bigint>();
  public readonly code = new Map<string, Uint8Array>();
  public readonly faults: Faults = { ambiguousSends: 0, hideSegments: new Set(), hideAllSeals: false, recipients: new Map() };
  public readonly vaultCode = ascii('fake vault runtime');
  public calls: string[] = [];
  public autoMine = true;
  private pool: Uint8Array[] = [];

  private constructor(public readonly root: Root, public readonly gamma: Uint8Array, private readonly cfg: Config) {
    this.vault = new VaultModel(gamma, { address: VAULT, chainId: CHAIN_ID, verifierCodeHash: cfg.verifierCodeHash }, TEST_PARAMS);
    this.code.set(toHex(VAULT), this.vaultCode);
  }

  public static async create(root: Root, cfg: Config): Promise<FakeChain> {
    const c = new FakeChain(root, encodeConfig(cfg), cfg);
    await c.mine([]); // genesis
    await c.mine([]); // the deployment block
    return c;
  }

  public get domain(): Uint8Array {
    return domainOf(this.gamma);
  }

  public fund(addr: Uint8Array, wei: bigint): void {
    this.balances.set(toHex(addr), (this.balances.get(toHex(addr)) ?? 0n) + wei);
  }

  public balanceOf(addr: Uint8Array): bigint {
    return this.balances.get(toHex(addr)) ?? 0n;
  }

  /** Mine one block with the given signed transactions, and certify the previous block (its UC goes in this block's companion). */
  public async mine(raws: Uint8Array[]): Promise<void> {
    const n = BigInt(this.blocks.length);
    const receipts: Rcpt[] = [];
    for (const raw of raws) receipts.push(await this.execute(raw));
    let cum = 0n;
    const enc = receipts.map((r) => {
      cum += r.gas;
      const logs = rlpList(r.logs.map((l) => rlpList([rlpBytes(l.address), rlpList(l.topics.map(rlpBytes)), rlpBytes(l.data)])));
      return concat(Uint8Array.of(2), rlpList([rlpUintEnc(r.status), rlpUintEnc(cum), rlpBytes(new Uint8Array(256)), logs]));
    });
    const trie = buildTrie(enc.map((e, i) => [rlpIndexKey(i), e]), null);
    const header: Header = {
      parentHash: n === 0n ? new Uint8Array(32) : this.blocks[Number(n) - 1].hash, ommersHash: EMPTY_UNCLE_HASH, beneficiary: new Uint8Array(20),
      stateRoot: sha(concat(ascii('state'), u256(n), ...raws)), transactionsRoot: sha(concat(ascii('txs'), ...raws)), receiptsRoot: trie.root,
      logsBloom: new Uint8Array(256), difficulty: 0n, number: n, gasLimit: 30_000_000n, gasUsed: cum, timestamp: 1_700_000_000n + n, extraData: new Uint8Array(),
      mixHash: new Uint8Array(32), nonce: new Uint8Array(8), baseFeePerGas: 7n, withdrawalsRoot: EMPTY_TRIE_ROOT, blobGasUsed: 0n, excessBlobGas: 0n,
      parentBeaconBlockRoot: new Uint8Array(32),
    };
    const hash = HE(encodeHeader(header));
    const parent = this.blocks[Number(n) - 1];
    if (parent) parent.uc = await makeUc(this.root, EVM_PARTITION, parent.header.stateRoot, parent.hash, header.timestamp);
    this.blocks.push({ header, hash, uc: null, receipts });
  }

  /** The verifier inside the vault: the plug-in's own relation (the Solidity verifier is NB2-05's). */
  private async verifierAnswer(evidence: Uint8Array): Promise<{ ret: Uint8Array } | { revert: Uint8Array }> {
    try {
      return { ret: verdictAbi(await verifyReturn(this.gamma, evidence, this.root.trust, TEST_PARAMS)) };
    } catch (e) {
      if (e instanceof Nb2Error) return { revert: revertData(e.rule) };
      throw e;
    }
  }

  /** Run a call against a vault (the real one, or a copy for a simulation); events and the payout as effects. */
  private async run(v: VaultModel, from: Uint8Array, to: Uint8Array, value: bigint, data: Uint8Array): Promise<{ ok: true; events: VaultEvent[] } | { ok: false; revert: Uint8Array }> {
    if (!eq(to, VAULT)) return { ok: true, events: [] };
    const before = v.events.length;
    try {
      const sel = data.subarray(0, 4);
      const word = (i: number): Uint8Array => data.subarray(4 + 32 * i, 36 + 32 * i);
      const dyn = (i: number): Uint8Array => {
        const off = Number(beInt(word(i)));
        const len = Number(beInt(data.subarray(4 + off, 36 + off)));
        return data.subarray(36 + off, 36 + off + len);
      };
      if (eq(sel, SELECTOR.deposit)) v.deposit(value, dyn(0), word(1));
      else if (eq(sel, SELECTOR.redeem)) {
        const evidence = dyn(0);
        const ver = await this.verifierAnswer(evidence);
        const rcpt = (() => {
          if (!('ret' in ver)) return 'accepts' as RecipientBehaviour;
          return this.faults.recipients.get(toHex(ver.ret.subarray(140, 160))) ?? 'accepts';
        })();
        v.redeem(word(1), beInt(word(2)), dyn(3), ver, rcpt);
      } else return { ok: false, revert: new Uint8Array() };
      return { ok: true, events: v.events.slice(before) };
    } catch (e) {
      if (!(e instanceof Nb2Error)) throw e;
      const vals = (e.args ?? []).map((a) => (a.startsWith('0x') ? fromHex(a.slice(2))! : BigInt(a)));
      return { ok: false, revert: revertData(e.rule, ...vals) };
    }
  }

  private async execute(raw: Uint8Array): Promise<Rcpt> {
    const { request: t, from, hash } = decodeSignedTx(raw);
    const nonce = this.nonces.get(toHex(from)) ?? 0n;
    if (t.nonce !== nonce) throw new Error(`fake chain: nonce ${t.nonce}, expected ${nonce}`);
    this.nonces.set(toHex(from), nonce + 1n);
    const fee = t.gas * 7n;
    if (this.balanceOf(from) < fee + t.value) throw new Error('fake chain: insufficient funds');
    this.balances.set(toHex(from), this.balanceOf(from) - fee);
    const r = await this.run(this.vault, from, t.to, t.value, t.data);
    if (!r.ok) return { status: 0n, logs: [], tx: hash, from, revert: r.revert, gas: t.gas, type: 2 };
    this.balances.set(toHex(from), this.balanceOf(from) - t.value);
    const logs: Log[] = [];
    for (const e of r.events) {
      if (e.name === 'Deposited') logs.push({ address: VAULT, topics: [TOPIC.Deposited, u256(e.n)], data: depositedData(this.domain, e.amount, e.rho, e.firstOwner) });
      else if (e.name === 'Paid') {
        logs.push({ address: VAULT, topics: [TOPIC.Paid, e.eta, concat(new Uint8Array(12), e.recipient)], data: u256(e.amount) });
        this.fund(e.recipient, e.amount);
      } else logs.push({ address: VAULT, topics: [TOPIC.SegmentSealed, u256(e.segment)], data: segmentSealedData(e.before, e.after, e.ids) });
    }
    return { status: 1n, logs, tx: hash, from, revert: null, gas: 150_000n, type: 2 };
  }

  // ---- JSON-RPC ----

  private headerJson(b: Block): Record<string, unknown> {
    const x = b.header;
    return {
      hash: h(b.hash), parentHash: h(x.parentHash), sha3Uncles: h(x.ommersHash), miner: h(x.beneficiary), stateRoot: h(x.stateRoot), transactionsRoot: h(x.transactionsRoot),
      receiptsRoot: h(x.receiptsRoot), logsBloom: h(x.logsBloom), difficulty: q(x.difficulty), number: q(x.number), gasLimit: q(x.gasLimit), gasUsed: q(x.gasUsed),
      timestamp: q(x.timestamp), extraData: h(x.extraData), mixHash: h(x.mixHash), nonce: h(x.nonce), baseFeePerGas: q(x.baseFeePerGas),
      withdrawalsRoot: h(x.withdrawalsRoot), blobGasUsed: q(x.blobGasUsed), excessBlobGas: q(x.excessBlobGas), parentBeaconBlockRoot: h(x.parentBeaconBlockRoot),
    };
  }

  private receiptJson(b: Block, i: number): Record<string, unknown> {
    const r = b.receipts[i];
    let cum = 0n;
    for (let k = 0; k <= i; k++) cum += b.receipts[k].gas;
    let logBase = 0;
    for (let k = 0; k < i; k++) logBase += b.receipts[k].logs.length;
    return {
      type: '0x2', status: q(r.status), cumulativeGasUsed: q(cum), logsBloom: h(new Uint8Array(256)), blockHash: h(b.hash), blockNumber: q(b.header.number),
      transactionIndex: q(i), transactionHash: h(r.tx), gasUsed: q(r.gas),
      logs: r.logs.map((l, k) => ({ address: h(l.address), topics: l.topics.map(h), data: h(l.data), logIndex: q(logBase + k), blockNumber: q(b.header.number), blockHash: h(b.hash), transactionHash: h(r.tx) })),
    };
  }

  private findTx(hash: string): [Block, number] | null {
    for (const b of this.blocks) {
      const i = b.receipts.findIndex((r) => h(r.tx) === hash);
      if (i >= 0) return [b, i];
    }
    return null;
  }

  public async call<T>(method: string, params: any[]): Promise<T> {
    this.calls.push(method);
    const r = await this.dispatch(method, params);
    return r as T;
  }

  private async dispatch(method: string, p: any[]): Promise<unknown> {
    const top = this.blocks[this.blocks.length - 1];
    switch (method) {
      case 'eth_chainId': return q(CHAIN_ID);
      case 'eth_blockNumber': return q(top.header.number);
      case 'eth_maxPriorityFeePerGas': return q(1n);
      case 'eth_getBlockByNumber': {
        const b = p[0] === 'latest' ? top : this.blocks[Number(BigInt(p[0]))];
        return b ? this.headerJson(b) : null;
      }
      case 'eth_getBlockByHash': {
        if (p.length !== 2 || p[1] !== false) throw new RpcError(400, 0, 'eth_getBlockByHash takes [hash, false]');
        const b = this.blocks.find((x) => h(x.hash) === p[0]);
        return b ? this.headerJson(b) : null;
      }
      case 'eth_getTransactionReceipt': {
        const f = this.findTx(p[0]);
        return f ? this.receiptJson(f[0], f[1]) : null;
      }
      case 'eth_getBlockReceipts': {
        const b = this.blocks.find((x) => h(x.hash) === p[0]);
        return b ? b.receipts.map((_, i) => this.receiptJson(b, i)) : null;
      }
      case 'unicity_getSealCompanionV1': {
        const i = this.blocks.findIndex((x) => h(x.hash) === p[0]);
        if (i <= 0) return { status: 'unknown' };
        return { status: 'found', companion: { witnesses: [h(this.blocks[i - 1].uc!), h(ascii('technical record'))] } };
      }
      case 'eth_getLogs': {
        const f = p[0];
        if (typeof f.address !== 'string' || typeof f.fromBlock !== 'string' || typeof f.toBlock !== 'string') throw new RpcError(400, 0, 'one address and a numeric window');
        const lo = BigInt(f.fromBlock);
        const hi = BigInt(f.toBlock);
        if (hi - lo + 1n > 10_000n) throw new RpcError(400, 0, 'window over 10000 blocks');
        const out: unknown[] = [];
        for (const b of this.blocks.slice(Number(lo), Number(hi) + 1)) {
          b.receipts.forEach((r, i) => {
            if (r.status !== 1n) return;
            const rj = this.receiptJson(b, i) as { logs: { address: string; topics: string[] }[] };
            for (const l of rj.logs) {
              if (l.address !== f.address) continue;
              const ok = (f.topics as (string | string[] | null)[]).every((t, k) => t === null || (Array.isArray(t) ? t.includes(l.topics[k]) : l.topics[k] === t));
              if (!ok) continue;
              if (l.topics[0] === h(TOPIC.SegmentSealed) && (this.faults.hideAllSeals || this.faults.hideSegments.has(BigInt(l.topics[1])))) continue;
              out.push(l);
            }
          });
        }
        return out;
      }
      case 'eth_call': case 'eth_estimateGas': {
        const t = p[0];
        const to = fromHex(t.to.slice(2))!;
        const data = fromHex(t.data.slice(2))!;
        if (method === 'eth_call' && eq(to, VAULT)) {
          if (eq(data, SELECTOR.config)) return h(concat(u256(32), u256(this.gamma.length), this.gamma, new Uint8Array((32 - (this.gamma.length % 32)) % 32)));
          if (eq(data, SELECTOR.state)) {
            const s = this.vault.state();
            return h(concat(u256(s.deposits), u256(s.segment), u256(s.population), u256(s.outstanding), s.head, s.previousHead));
          }
        }
        const r = await this.run(this.vault.copy(), fromHex((t.from ?? '0x' + '00'.repeat(20)).slice(2))!, to, BigInt(t.value ?? '0x0'), data);
        if (!r.ok) throw new RpcError(200, 3, `execution reverted: ${h(r.revert)}`, h(r.revert));
        return method === 'eth_estimateGas' ? q(120_000n) : '0x';
      }
      case 'eth_getCode': return h(this.code.get(p[0].slice(2)) ?? new Uint8Array());
      case 'eth_getBalance': return q(this.balanceOf(fromHex(p[0].slice(2))!));
      case 'eth_getTransactionCount': {
        const a = p[0].slice(2);
        let n = this.nonces.get(a) ?? 0n;
        if (p[1] === 'pending') n += BigInt(this.pool.filter((raw) => toHex(decodeSignedTx(raw).from) === a).length);
        return q(n);
      }
      case 'eth_sendRawTransaction': {
        const raw = fromHex(p[0].slice(2))!;
        if (this.findTx(h(HE(raw))) !== null || this.pool.some((x) => eq(x, raw))) throw new RpcError(200, -32000, 'already known');
        this.pool.push(raw);
        if (this.autoMine) await this.flush();
        if (this.faults.ambiguousSends > 0) {
          this.faults.ambiguousSends--;
          throw new RpcError(503, 0, 'broadcast may be partial');
        }
        return h(HE(raw));
      }
      default: throw new RpcError(200, -32601, `fake chain: no method ${method}`);
    }
  }

  /** Mine the pool, then one empty block so the transactions' block is certified. */
  public async flush(): Promise<void> {
    const raws = this.pool;
    this.pool = [];
    await this.mine(raws);
    await this.mine([]);
  }

  public dropPool(): void {
    this.pool = [];
  }
}

// ---- a whole simulated deployment --------------------------------------------------------------------

export async function setup() {
  const root = await makeRoot();
  const cfg = makeConfig(root);
  const chain = await FakeChain.create(root, cfg);
  const agg = new FakeAggregator(root);
  const pins = {
    gamma: chain.gamma, build: 'test' as const, vaultRuntimeCodeHash: HE(chain.vaultCode), maxEncodedTxBytes: 524_288n, userGasLimit: 60_000_000n,
    gasReserve: 500_000n, returnReserveSegments: 64n, deploymentBlock: 1n, stateReadOnly: false,
  };
  const options = (seed: string, store = new MemoryJournalStore()): BridgeOptions => ({
    pins, trust: root.trust, rpc: chain, aggregator: agg, journal: store, bridgeKey: deriveBridgeKey(key(seed)), backup: async () => {},
    receiptTimeoutMs: 0, pollMs: 0, sleep: async () => {},
  });
  return { root, cfg, chain, agg, pins, options };
}

export const evmAccount = (chain: FakeChain, seed: string): LocalKeySigner => {
  const s = new LocalKeySigner(key(`evm ${seed}`));
  chain.fund(s.address, 10n ** 24n);
  return s;
};

