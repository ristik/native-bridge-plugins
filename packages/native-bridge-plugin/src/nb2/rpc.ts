/**
 * Wallet evidence from the ordinary execution RPC behind the deployment's public gateway (section 12.7, NB2-06 #1102): one URL,
 * JSON-RPC 2.0 POST, one request per call. The paired RPC selects the canonical child for Mint and receive.
 * Receipt, quorum and lineage checks independently authenticate the evidence.
 *
 * Gateway rules honoured here: `eth_getLogs` names one address and an explicit window of at most 10,000 blocks (a result-count error
 * or the 8 MiB answer cap, HTTP 413, halves the window); every read takes exactly its accepted parameter shape; 429 and a busy 503 are waited out; an HTTP 503 from `eth_sendRawTransaction` is ambiguous (the transaction may
 * still land, #1121), so it is reported as such and the caller polls for the receipt of the locally computed hash.
 */
import { concat, eq, fromHex, toHex } from '../bytes.js';
import { decodeRevert, decodeBytesReturn, decodeStateReturn, SELECTOR, type RawLog, type VaultState } from './abi.js';
import { TOPIC, encodeDepositProof, type DepositProof } from './deposit.js';
import { Nb2Error, WalletError, fail, refuse } from './errors.js';
import { bindHeader, decodeHeader, encodeHeader, type Header } from './header.js';
import { HE, HU } from './crypto.js';
import { buildTrie, mptVerify } from './mpt.js';
import { rlpBytes, rlpIndexKey, rlpList, rlpUintEnc } from './rlp.js';
import type { Config } from './config.js';
import { checkCompanion } from './rules.js';
import { array, isBytes, isUint, scanNative, u256 } from './cbor.js';

import type { RecoveryEvent, RecoveryReceiptSource } from './recovery.js';
import { decodeUc, verifyEvmUc, type TrustInput } from './trust.js';

export const LOG_BLOCK_RANGE = 10_000n;

/** A JSON-RPC transport: one method call. */
export interface JsonRpc {
  call<T = unknown>(method: string, params: unknown[]): Promise<T>;
}

/** A JSON-RPC error object, or a gateway refusal (HTTP status and its error text). */
export class RpcError extends Error {
  /** Milliseconds the gateway asked us to wait (`Retry-After`), when it did. */
  public retryAfterMs?: number;

  public constructor(public readonly status: number, public readonly code: number, message: string, public readonly data?: unknown) {
    super(code !== 0 ? `rpc error ${code}: ${message}` : status === 0 ? `network error: ${message}` : `gateway HTTP ${status}: ${message}`);
    this.name = 'RpcError';
  }

  /**
   * A transport condition, not an answer about the request: HTTP 429, 502, 503 or 504, or no HTTP answer at all (status 0: network
   * failure or timeout). Nothing was learned about the chain; the caller may run the same read again later. It is never a verdict.
   */
  public get retryable(): boolean {
    return this.code === 0 && (this.status === 0 || this.status === 429 || this.status === 502 || this.status === 503 || this.status === 504);
  }

  /** The node does not implement the method (JSON-RPC -32601), as opposed to a transport failure. */
  public get methodNotFound(): boolean {
    return this.code === -32601;
  }
}

/** Readers exhausted for a component of an identified transaction's certificate. */
export class ProofUnavailable extends Error {
  public constructor(public readonly component: string, public readonly pruned: boolean) {
    super(`no configured reader supplied ${component}`);
  }
}

async function proofFrom<T>(readers: readonly EvmReader[], component: string, read: (reader: EvmReader) => Promise<T>): Promise<T> {
  let pruned = false;
  let refresh: Nb2Error | undefined;
  for (const reader of readers) {
    try {
      return await read(reader);
    } catch (e) {
      if (e instanceof WalletError && e.reason === 'TrustInput') throw e;
      if (e instanceof Nb2Error && e.retryable) refresh ??= e;
      if (e instanceof ProofUnavailable && e.pruned || e instanceof Nb2Error && e.rule === 'EvidencePruned' ||
        e instanceof RpcError && (e.status === 413 || e.code === -32601 || /unknown block|not found|pruned/i.test(e.message))) pruned = true;
    }
  }
  if (refresh) throw refresh;
  throw new ProofUnavailable(component, pruned);
}

/** An `eth_sendRawTransaction` answered with HTTP 503 ("broadcast may be partial"): the transaction may still be included. */
export class AmbiguousBroadcast extends Error {
  public constructor(public readonly txHash: Uint8Array, detail: string) {
    super(`broadcast of 0x${toHex(txHash)} is ambiguous (${detail}): poll its receipt before any resubmission`);
    this.name = 'AmbiguousBroadcast';
  }
}

export interface HttpRpcOptions {
  fetch?: typeof fetch;
  /** Retries of a 429 or busy 503 (not of a send); default 2 (three attempts). Outer loops must not multiply this. */
  retries?: number;
  /** Total time spent waiting between attempts of one call; default 5,000 ms. A longer `Retry-After` is not waited out. */
  maxWaitMs?: number;
  /** Uniform [0, 1) source for jitter. */
  random?: () => number;
  sleep?: (ms: number) => Promise<void>;
  timeoutMs?: number;
}

const BACKOFF_BASE_MS = 500;
const BACKOFF_STEP_CAP_MS = 2_000;

/** `Retry-After` as milliseconds: delta-seconds or an HTTP date. */
function retryAfterOf(value: string | null | undefined): number | undefined {
  if (!value) return undefined;
  const t = value.trim();
  if (/^\d+(\.\d+)?$/.test(t)) return Math.round(Number(t) * 1000);
  const at = Date.parse(t);
  return Number.isNaN(at) ? undefined : Math.max(0, at - Date.now());
}

const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** The gateway client. */
export class HttpJsonRpc implements JsonRpc {
  private id = 0;
  public constructor(private readonly url: string, private readonly opts: HttpRpcOptions = {}) {}

  public async call<T>(method: string, params: unknown[]): Promise<T> {
    const sleep = this.opts.sleep ?? realSleep;
    const random = this.opts.random ?? Math.random;
    const budget = this.opts.maxWaitMs ?? 5_000;
    let waited = 0;
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.once<T>(method, params);
      } catch (e) {
        const wait = e instanceof RpcError && (e.status === 429 || (e.status === 503 && method !== 'eth_sendRawTransaction'));
        if (!wait || attempt >= (this.opts.retries ?? 2)) throw e;
        // exponential backoff with full jitter; a `Retry-After` replaces it, and one that does not fit the budget is surfaced
        const ask = (e as RpcError).retryAfterMs;
        const delay = ask ?? Math.floor(random() * Math.min(BACKOFF_STEP_CAP_MS, BACKOFF_BASE_MS * 2 ** attempt));
        if (waited + delay > budget) throw e;
        waited += delay;
        await sleep(delay);
      }
    }
  }

  private async once<T>(method: string, params: unknown[]): Promise<T> {
    const f = this.opts.fetch ?? fetch;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.opts.timeoutMs ?? 45_000);
    try {
      let resp: Response;
      let text: string;
      try {
        resp = await f(this.url, {
          method: 'POST', headers: { 'content-type': 'application/json' }, signal: ctl.signal,
          body: JSON.stringify({ jsonrpc: '2.0', id: ++this.id, method, params }),
        });
        text = await resp.text();
      } catch (e) {
        if (e instanceof RpcError) throw e;
        throw new RpcError(0, 0, e instanceof Error ? e.message : String(e)); // network failure or timeout: retryable, not a verdict
      }
      if (resp.status !== 200) {
        let msg = text.slice(0, 200);
        try {
          msg = (JSON.parse(text) as { error?: string }).error ?? msg;
        } catch { /* not JSON */ }
        const err = new RpcError(resp.status, 0, msg);
        err.retryAfterMs = retryAfterOf(resp.headers?.get?.('retry-after'));
        throw err;
      }
      const env = JSON.parse(text) as { result?: T; error?: { code: number; message: string; data?: unknown } };
      if (env.error) throw new RpcError(200, env.error.code, env.error.message, env.error.data);
      return env.result as T;
    } finally {
      clearTimeout(timer);
    }
  }
}

// ---- typed reads --------------------------------------------------------------------------------

const hexOf = (b: Uint8Array): string => `0x${toHex(b)}`;
export const qty = (v: bigint | number): string => `0x${BigInt(v).toString(16)}`;
export function bytesOf(s: unknown, what: string): Uint8Array {
  if (typeof s !== 'string' || !s.startsWith('0x')) return refuse('ProviderFault', `${what} is not hex`);
  const b = fromHex(s.slice(2));
  return b ?? refuse('ProviderFault', `${what} is not hex`);
}
export function qtyOf(s: unknown, what: string): bigint {
  if (typeof s !== 'string' || !/^0x[0-9a-fA-F]+$/.test(s)) return refuse('ProviderFault', `${what} is not a quantity`);
  return BigInt(s);
}
const fixedOf = (s: unknown, n: number, what: string): Uint8Array => {
  const b = bytesOf(s, what);
  return b.length === n ? b : refuse('ProviderFault', `${what} is not ${n} bytes`);
};

/** The header fields of an `eth_getBlockBy*` answer, as the 20-field Cancun header. */
export function headerOfJson(j: Record<string, unknown>): Header {
  return {
    parentHash: fixedOf(j.parentHash, 32, 'parentHash'), ommersHash: fixedOf(j.sha3Uncles, 32, 'sha3Uncles'), beneficiary: fixedOf(j.miner, 20, 'miner'),
    stateRoot: fixedOf(j.stateRoot, 32, 'stateRoot'), transactionsRoot: fixedOf(j.transactionsRoot, 32, 'transactionsRoot'),
    receiptsRoot: fixedOf(j.receiptsRoot, 32, 'receiptsRoot'), logsBloom: fixedOf(j.logsBloom, 256, 'logsBloom'), difficulty: qtyOf(j.difficulty, 'difficulty'),
    number: qtyOf(j.number, 'number'), gasLimit: qtyOf(j.gasLimit, 'gasLimit'), gasUsed: qtyOf(j.gasUsed, 'gasUsed'), timestamp: qtyOf(j.timestamp, 'timestamp'),
    extraData: bytesOf(j.extraData, 'extraData'), mixHash: fixedOf(j.mixHash, 32, 'mixHash'), nonce: fixedOf(j.nonce, 8, 'nonce'),
    baseFeePerGas: qtyOf(j.baseFeePerGas, 'baseFeePerGas'), withdrawalsRoot: fixedOf(j.withdrawalsRoot, 32, 'withdrawalsRoot'),
    blobGasUsed: qtyOf(j.blobGasUsed, 'blobGasUsed'), excessBlobGas: qtyOf(j.excessBlobGas, 'excessBlobGas'),
    parentBeaconBlockRoot: fixedOf(j.parentBeaconBlockRoot, 32, 'parentBeaconBlockRoot'),
  };
}

export interface ReceiptJson {
  type?: string;
  status: string;
  cumulativeGasUsed: string;
  logsBloom: string;
  logs: { address: string; topics: string[]; data: string; logIndex?: string; blockNumber?: string; blockHash?: string; transactionHash?: string }[];
  blockHash: string;
  blockNumber: string;
  transactionIndex: string;
  transactionHash: string;
  gasUsed?: string;
  effectiveGasPrice?: string;
}

/** The consensus encoding of a receipt: a legacy RLP list, or type || RLP(...) for types 1..3. */
export function encodeReceiptJson(r: ReceiptJson): Uint8Array {
  const logs = r.logs.map((l) => rlpList([rlpBytes(fixedOf(l.address, 20, 'log address')), rlpList(l.topics.map((t) => rlpBytes(fixedOf(t, 32, 'topic')))), rlpBytes(bytesOf(l.data, 'log data'))]));
  const body = rlpList([rlpUintEnc(qtyOf(r.status, 'status')), rlpUintEnc(qtyOf(r.cumulativeGasUsed, 'cumulativeGasUsed')), rlpBytes(fixedOf(r.logsBloom, 256, 'logsBloom')), rlpList(logs)]);
  const ty = r.type === undefined ? 0n : qtyOf(r.type, 'type');
  return ty === 0n ? body : concat(Uint8Array.of(Number(ty)), body);
}

export function rawLogOf(l: Record<string, unknown>): RawLog {
  return {
    address: fixedOf(l.address, 20, 'address'), topics: (l.topics as unknown[]).map((t) => fixedOf(t, 32, 'topic')), data: bytesOf(l.data, 'data'),
    blockNumber: qtyOf(l.blockNumber, 'blockNumber'), blockHash: fixedOf(l.blockHash, 32, 'blockHash'), transactionHash: fixedOf(l.transactionHash, 32, 'transactionHash'),
    logIndex: qtyOf(l.logIndex, 'logIndex'), removed: l.removed === true,
  };
}

/** The fresh B1 RootInputV2 limit (ureth execution/src/wire.rs). */
const MAX_ROOT_INPUT_BYTES = 32 * 1024;

function checkMintWitness(child: Header, rootInput: unknown, witness: Uint8Array): void {
  if (rootInput === undefined || rootInput === null || rootInput === '0x') {
    refuse('CompanionUnknown', 'the canonical child has no committed root input available');
  }
  if (typeof rootInput !== 'string' || rootInput.length > 2 + MAX_ROOT_INPUT_BYTES * 2) {
    refuse('CompanionProvider', 'invalid child root input size');
  }
  const raw = bytesOf(rootInput, 'child root input');
  if (!eq(HU(raw), child.extraData)) refuse('CompanionProvider', 'root input does not open the child header commitment');
  const fields = array(scanNative(raw), 13);
  const origin = array(fields[8], 8);
  const uc = decodeUc(witness);
  const seal = uc.unicitySeal;
  const position = [BigInt(seal.networkId.id), seal.rootChainRoundNumber, seal.epoch, seal.timestamp];
  const hashes = [[origin[4], seal.hash], [origin[6], uc.technicalRecordHash], [origin[7], uc.shardConfigurationHash]] as const;
  if (!isUint(fields[0]) || fields[0].arg !== 2n || !isBytes(fields[7]) || !eq(fields[7].data!, child.parentHash)
      || position.some((value, i) => !isUint(origin[i]) || origin[i].arg !== value)
      || hashes.some(([field, hash]) => hash === null || !isBytes(field) || !eq(field.data!, hash))) {
    refuse('CompanionProvider', 'certificate is not the origin committed by the canonical child');
  }
}

/** A built receipt proof and the facts it was built from. */
export interface ReceiptProof { proof: DepositProof; encoded: Uint8Array; blockNumber: bigint; blockHash: Uint8Array; log: RawLog; receiptLogIndex: number }

/** The typed RPC reads the wallet uses. */
export class EvmReader {
  public constructor(public readonly rpc: JsonRpc) {}

  public async blockNumber(): Promise<bigint> {
    return qtyOf(await this.rpc.call('eth_blockNumber', []), 'eth_blockNumber');
  }

  public async chainId(): Promise<bigint> {
    return qtyOf(await this.rpc.call('eth_chainId', []), 'eth_chainId');
  }

  public async receipt(txHash: Uint8Array): Promise<ReceiptJson | null> {
    return this.rpc.call<ReceiptJson | null>('eth_getTransactionReceipt', [hexOf(txHash)]);
  }

  /** The header of a block by hash, as its exact RLP, which must hash to the requested hash. */
  public async headerByHash(hash: Uint8Array): Promise<{ header: Header; raw: Uint8Array }> {
    const j = await this.rpc.call<Record<string, unknown> | null>('eth_getBlockByHash', [hexOf(hash), false]);
    if (j === null) fail('EvidencePruned', `block 0x${toHex(hash)} is not held by this node`);
    const header = headerOfJson(j!);
    const raw = encodeHeader(header);
    if (!eq(HE(raw), hash)) refuse('ProviderFault', `the header served for 0x${toHex(hash)} does not re-encode to its hash`);
    return { header, raw };
  }

  /** The header of a block by number and its hash (the hash of its exact re-encoding); null when the node does not hold it. */
  public async headerByNumber(n: bigint): Promise<{ header: Header; hash: Uint8Array } | null> {
    const j = await this.rpc.call<Record<string, unknown> | null>('eth_getBlockByNumber', [qty(n), false]);
    if (j === null) return null;
    const header = headerOfJson(j);
    return { header, hash: HE(encodeHeader(header)) };
  }

  /**
   * The certificate of block N: witness 0 of the companion of its child N+1 (section 12.7). Not yet served while the child does not
   * exist (`CompanionUnknown`, retry after a round); `EvidencePruned` below the node's horizon.
   */
  public async certificateOf(header: Header, hash: Uint8Array, bindTechnicalRecord = false,
    sources?: readonly EvmReader[], authenticate?: (uc: Uint8Array) => Promise<void>, mintWitness: boolean | Uint8Array = false): Promise<Uint8Array> {
    const childOf = async (reader: EvmReader) => {
      const child = await reader.headerByNumber(header.number + 1n);
      if (!child || child.header.number !== header.number + 1n || !eq(child.header.parentHash, hash)) {
        refuse('CompanionUnknown', `block ${header.number} has no canonical child on this reader`);
      }
      return child;
    };
    const companion = async (reader: EvmReader, child: { header: Header; hash: Uint8Array }) => {
      const l = await reader.rpc.call<{ status: string; companion?: { rootInput?: unknown; witnesses?: string[] }; witnesses?: string[] }>('unicity_getSealCompanionV1', [hexOf(child.hash)]);
      const witnesses = l.companion?.witnesses ?? l.witnesses ?? [];
      if (mintWitness && l.status === 'found' && witnesses.length === 0) {
        refuse('CompanionUnknown', 'the canonical child has no committed witness available');
      }
      checkCompanion(l.status, witnesses.length);
      const uc = bytesOf(witnesses[0], 'companion witness 0');
      if (mintWitness) checkMintWitness(child.header, l.companion?.rootInput, mintWitness === true ? uc : mintWitness);
      if (bindTechnicalRecord) {
        const record = bytesOf(witnesses[1], 'companion witness 1');
        if (record.length > 4096) refuse('CompanionProvider', 'technical record is oversized');
        const [round, epoch, leader, stat, fee] = array(scanNative(record), 5);
        const digest = decodeUc(uc).technicalRecordHash;
        if (!isUint(round) || round.arg === 0n || !isUint(epoch) || leader.major !== 3 || leader.arg === 0n
          || !isBytes(stat) || stat.arg === 0n || !isBytes(fee) || fee.arg === 0n || digest === null || !eq(HU(record), digest)) {
          refuse('CompanionProvider', 'technical record does not open the certificate commitment');
        }
      }
      await authenticate?.(uc);
      return uc;
    };
    if (!sources) return companion(this, await childOf(this));
    const companions = new Map<string, Promise<Uint8Array>>();
    return proofFrom(sources, 'a child block header and its seal companion', async (reader) => {
      const child = await childOf(reader);
      const key = hexOf(child.hash);
      let candidate = companions.get(key);
      if (!candidate) {
        candidate = proofFrom(sources, 'the seal companion', (source) => companion(source, child));
        companions.set(key, candidate);
      }
      return candidate;
    });
  }

  /** The root-to-leaf receipt-trie path of RLP(txIndex), from the block's receipts, whose trie must hash to the header's root. */
  public async receiptPath(header: Header, hash: Uint8Array, txIndex: bigint): Promise<Uint8Array[]> {
    let receipts: ReceiptJson[] | null;
    try {
      receipts = await this.rpc.call<ReceiptJson[] | null>('eth_getBlockReceipts', [hexOf(hash)]);
    } catch (e) {
      // an answer over the gateway's 8 MiB cap is not served by this gateway: use another provider for this block
      if (e instanceof RpcError && e.status === 413) fail('EvidencePruned', `the receipts of block ${header.number} exceed this gateway's answer cap: use another provider`);
      throw e;
    }
    if (!receipts) fail('EvidencePruned', `the receipts of block ${header.number} are not served`);
    if (txIndex >= BigInt(receipts!.length)) refuse('ProviderFault', `block ${header.number} has ${receipts!.length} receipts, no index ${txIndex}`);
    const entries = receipts!.map((r, i) => [rlpIndexKey(i), encodeReceiptJson(r)] as [Uint8Array, Uint8Array]);
    const t = buildTrie(entries, rlpIndexKey(txIndex));
    if (!eq(t.root, header.receiptsRoot)) refuse('ProviderFault', `the receipts served for block ${header.number} do not hash to its receiptsRoot`);
    return t.path;
  }

  /** Verify a failed receipt against its certified block before abandoning a pending send. */
  public async verifyFailedReceipt(txHash: Uint8Array, cfg: Config, trust: TrustInput, receipt: ReceiptJson,
    archives: readonly EvmReader[] = []): Promise<void> {
    if (qtyOf(receipt.status, 'status') !== 0n) return refuse('ProviderFault', 'expected a failed receipt');
    const hash = fixedOf(receipt.blockHash, 32, 'blockHash');
    const sources = [...new Set([this, ...archives])];
    const { header, raw } = await proofFrom(sources, 'the failed transaction block header', (r) => r.headerByHash(hash));
    if (header.number !== qtyOf(receipt.blockNumber, 'blockNumber')) refuse('ProviderFault', 'failed receipt has the wrong block number');
    await this.certificateOf(header, hash, true, sources, async (encoded) => {
      const uc = await verifyEvmUc(trust, encoded, cfg);
      bindHeader(raw, uc.inputRecord.blockHash, uc.inputRecord.nullableHash);
    });
    const idx = qtyOf(receipt.transactionIndex, 'transactionIndex');
    const path = await proofFrom(sources, 'the failed transaction block receipts', (r) => r.receiptPath(header, hash, idx));
    if (!eq(mptVerify(header.receiptsRoot, rlpIndexKey(idx), path), encodeReceiptJson(receipt))) {
      refuse('ProviderFault', 'failed receipt is not committed in the certified block');
    }
    await this.transactionIn(header, hash, idx, txHash, sources);
  }

  /** Read the exact signed transaction committed at an independently certified block and receipt index. */
  public async transactionAt(blockHash: Uint8Array, index: bigint, txHash: Uint8Array): Promise<Uint8Array> {
    const { header } = await this.headerByHash(blockHash);
    return this.transactionIn(header, blockHash, index, txHash, [this]);
  }

  private transactionIn(header: Header, hash: Uint8Array, idx: bigint, txHash: Uint8Array,
    sources: readonly EvmReader[]): Promise<Uint8Array> {
    return proofFrom(sources, 'the certified transaction block body', async (r) => {
      const body = await r.rpc.call<{ transactions?: string[] } | null>('eth_getBlockByHash', [hexOf(hash), false]);
      if (!Array.isArray(body?.transactions)) fail('EvidencePruned', 'the certified block body is unavailable');
      if (BigInt(body.transactions.length) > header.gasLimit / 21_000n + 16n || idx >= BigInt(body.transactions.length) ||
        !eq(fixedOf(body.transactions[Number(idx)], 32, 'transaction hash'), txHash)) {
        return refuse('ProviderFault', 'certified receipt has no matching transaction in the block body');
      }
      const entries: [Uint8Array, Uint8Array][] = [];
      for (const [i, tx] of body.transactions.entries()) {
        const raw = await proofFrom(sources, 'an exact raw transaction in the certified block', async (reader) => {
          const wire = await reader.rpc.call<string | null>('eth_getRawTransactionByBlockHashAndIndex', [hexOf(hash), qty(i)]);
          if (!wire || wire === '0x') fail('EvidencePruned', 'an exact transaction in the certified block is unavailable');
          const decoded = bytesOf(wire, 'raw transaction');
          if (!eq(HE(decoded), fixedOf(tx, 32, 'transaction hash'))) refuse('ProviderFault', 'raw transaction hash mismatch');
          return decoded;
        });
        entries.push([rlpIndexKey(i), raw]);
      }
      if (!eq(buildTrie(entries, null).root, header.transactionsRoot)) refuse('ProviderFault', 'transactions root mismatch');
      return entries[Number(idx)][1];
    });
  }

  public async checkMintReceipt(proof: DepositProof): Promise<void> {
    await this.certificateOf(decodeHeader(proof.header), HE(proof.header), false, undefined, undefined, proof.uc);
  }

  /** The paired profile selects the parent's UC from the canonical child's committed origin. */
  public mintReceiptProof(txHash: Uint8Array, vault: Uint8Array, bound: boolean): Promise<ReceiptProof> {
    return this.receiptProof(txHash, vault, TOPIC.Deposited, false, undefined, [], undefined, bound);
  }

  /** The DepositProof container for the first log of `txHash` emitted by `emitter` with `topic0`. */
  public async receiptProof(txHash: Uint8Array, emitter: Uint8Array, topic0: Uint8Array, bindTechnicalRecord = false, expected?: Pick<RecoveryEvent, 'topics' | 'data'>, archives: readonly EvmReader[] = [], authenticate?: (raw: Uint8Array, uc: Uint8Array) => Promise<void>, bindMintWitness = false): Promise<ReceiptProof> {
    const r = await this.receipt(txHash);
    if (r === null) refuse('EvidenceMissing', `transaction 0x${toHex(txHash)} has no receipt on this node (pending, unknown or pruned)`);
    if (qtyOf(r!.status, 'status') !== 1n) refuse('Reverted', `transaction 0x${toHex(txHash)} failed: its logs never count`);
    const idx = r!.logs.findIndex((l) => eq(bytesOf(l.address, 'address'), emitter) && l.topics.length > 0
      && eq(bytesOf(l.topics[0], 'topic'), topic0) && (expected === undefined || (
        l.topics.length === expected.topics.length && l.topics.every((topic, i) => eq(bytesOf(topic, 'topic'), expected.topics[i]))
        && eq(bytesOf(l.data, 'log data'), expected.data))));
    if (idx < 0) refuse('EvidenceMissing', `transaction 0x${toHex(txHash)} emitted no such log from 0x${toHex(emitter)}`);
    const blockHash = fixedOf(r!.blockHash, 32, 'blockHash');
    const sources = archives.length ? [...new Set([this, ...archives])] : undefined;
    const { header, raw } = sources
      ? await proofFrom(sources, 'the payment block header', (reader) => reader.headerByHash(blockHash))
      : await this.headerByHash(blockHash);
    const uc = await this.certificateOf(header, blockHash, bindTechnicalRecord, sources,
      authenticate && ((encoded) => authenticate(raw, encoded)), bindMintWitness);
    const txIndex = qtyOf(r!.transactionIndex, 'transactionIndex');
    const nodes = sources
      ? await proofFrom(sources, 'the payment block receipts', (reader) => reader.receiptPath(header, blockHash, txIndex))
      : await this.receiptPath(header, blockHash, txIndex);
    const proof: DepositProof = { uc, header: raw, txIndex, logIndex: BigInt(idx), nodes };
    const l = r!.logs[idx];
    const log: RawLog = {
      address: emitter, topics: l.topics.map((x) => fixedOf(x, 32, 'topic')), data: bytesOf(l.data, 'data'), blockNumber: header.number, blockHash,
      transactionHash: txHash, logIndex: l.logIndex === undefined ? BigInt(idx) : qtyOf(l.logIndex, 'logIndex'),
    };
    return { proof, encoded: encodeDepositProof(proof), blockNumber: header.number, blockHash, log, receiptLogIndex: idx };
  }

  /** `eth_getLogs` of `address` and `topics` over [from, to], in gateway windows, in order; a result-count error halves the window. */
  public async logs(address: Uint8Array, topics: (string | string[] | null)[], from: bigint, to: bigint): Promise<RawLog[]> {
    const out: RawLog[] = [];
    for (let lo = from; lo <= to;) {
      let hi = lo + LOG_BLOCK_RANGE - 1n < to ? lo + LOG_BLOCK_RANGE - 1n : to;
      for (;;) {
        try {
          const page = await this.rpc.call<Record<string, unknown>[]>('eth_getLogs', [{ address: hexOf(address), topics, fromBlock: qty(lo), toBlock: qty(hi) }]);
          for (const l of page) if (l.removed !== true) out.push(rawLogOf(l));
          break;
        } catch (e) {
          // the node's result-count error, or the gateway's 8 MiB answer cap (HTTP 413): ask for less
          if (e instanceof RpcError && (e.status === 413 || /max results|too many|exceed/i.test(e.message)) && hi > lo) {
            hi = lo + (hi - lo) / 2n;
            continue;
          }
          throw e;
        }
      }
      lo = hi + 1n;
    }
    return out;
  }

  /** The newest SegmentSealed log of the vault at or after `from`, paging backwards from the head; null when it never sealed. */
  public async newestSeal(vault: Uint8Array, from: bigint): Promise<RawLog | null> {
    const top = await this.blockNumber();
    for (let hi = top; hi >= from;) {
      const lo = hi >= from + LOG_BLOCK_RANGE ? hi - LOG_BLOCK_RANGE + 1n : from;
      const page = await this.logs(vault, [hexOf(TOPIC.SegmentSealed)], lo, hi);
      if (page.length > 0) return page[page.length - 1];
      if (lo === from) break;
      hi = lo - 1n;
    }
    return null;
  }

  /** The SegmentSealed logs of segments [start, end) in order, paging forwards from `from` (a block at or before segment `start`'s seal). */
  public async segmentLogs(vault: Uint8Array, from: bigint, start: bigint, end: bigint): Promise<RawLog[]> {
    if (end <= start) return [];
    const top = await this.blockNumber();
    const want = new Map<bigint, RawLog>();
    for (let lo = from; lo <= top && BigInt(want.size) < end - start; lo += LOG_BLOCK_RANGE) {
      const hi = lo + LOG_BLOCK_RANGE - 1n < top ? lo + LOG_BLOCK_RANGE - 1n : top;
      for (const l of await this.logs(vault, [hexOf(TOPIC.SegmentSealed)], lo, hi)) {
        if (l.topics.length !== 2) continue;
        const j = BigInt(`0x${toHex(l.topics[1])}`);
        // a second log for one index is a provider fault: the chain link check refuses whichever is wrong
        if (j >= start && j < end && !want.has(j)) want.set(j, l);
      }
    }
    const out: RawLog[] = [];
    for (let j = start; j < end; j++) {
      const l = want.get(j);
      // a missing log is missing evidence, never absence
      if (l === undefined) refuse('EvidenceMissing', `no SegmentSealed log of segment ${j} was served`);
      out.push(l!);
    }
    return out;
  }

  /** `Paid(eta)` logs of the vault from block `from`. */
  public async paid(vault: Uint8Array, eta: Uint8Array, from: bigint): Promise<RawLog[]> {
    const top = await this.blockNumber();
    if (top < from) return [];
    return this.logs(vault, [hexOf(TOPIC.Paid), hexOf(eta)], from, top);
  }

  public async call(to: Uint8Array, data: Uint8Array, from?: Uint8Array): Promise<Uint8Array> {
    return bytesOf(await this.rpc.call('eth_call', [{ to: hexOf(to), data: hexOf(data), ...(from ? { from: hexOf(from) } : {}) }, 'latest']), 'eth_call');
  }

  /** Check imported authority and simulate the exact fee-bearing return at the same finalized block. */
  public async checkReturnImport(cfg: Config, epoch: bigint, tx?: {
    from: Uint8Array; to: Uint8Array; data: Uint8Array; gas: bigint; value: bigint;
  }): Promise<void> {
    const [chain, genesis, finalized] = await Promise.all([
      this.chainId(),
      this.rpc.call<{ hash: string } | null>('eth_getBlockByNumber', ['0x0', false]),
      this.rpc.call<{ hash: string } | null>('eth_getBlockByNumber', ['finalized', false]),
    ]);
    if (chain !== cfg.chainId || !genesis || !eq(bytesOf(genesis.hash, 'genesis hash'), cfg.executionGenesis)) {
      refuse('TrustInput', 'return RPC does not serve the pinned execution genesis');
    }
    if (!finalized || bytesOf(finalized.hash, 'finalized hash').length !== 32) {
      refuse('ImportLag', 'waiting for a finalized execution block');
    }
    const at = { blockHash: finalized!.hash, requireCanonical: true };
    const registry = '0xff00000000000000000000000000000000000002';
    const slot = '0xefa6b7f0bacdcf81ddd8a710fb8420140ae07d47982dc167bb647c00d3f5f4fc';
    const tip = bytesOf(await this.rpc.call('eth_getStorageAt', [registry, slot, at]), 'B1 imported tip epoch');
    if (tip.length !== 32 || BigInt(hexOf(tip)) < epoch) {
      refuse('ImportLag', `waiting for finalized B1 import of epoch ${epoch}`);
    }
    if (!tx) return;
    try {
      await this.rpc.call('eth_call', [{
        from: hexOf(tx.from), to: hexOf(tx.to), data: hexOf(tx.data), value: qty(tx.value), gas: qty(tx.gas),
      }, at]);
    } catch (error) {
      if (error instanceof RpcError) {
        const raw = revertDataOf(error);
        if (raw && decodeRevert(raw)?.rule === 'StaleEndpoint') fail('StaleEndpoint', 'payout history expired at the finalized head');
      }
      throw error;
    }
  }

  public async vaultState(vault: Uint8Array): Promise<VaultState> {
    return decodeStateReturn(await this.call(vault, SELECTOR.state));
  }

  public async vaultConfig(vault: Uint8Array): Promise<Uint8Array> {
    return decodeBytesReturn(await this.call(vault, SELECTOR.config));
  }

  public async code(address: Uint8Array): Promise<Uint8Array> {
    return bytesOf(await this.rpc.call('eth_getCode', [hexOf(address), 'latest']), 'eth_getCode');
  }

  public async balance(address: Uint8Array, tag: 'latest' | bigint = 'latest'): Promise<bigint> {
    return qtyOf(await this.rpc.call('eth_getBalance', [hexOf(address), typeof tag === 'bigint' ? qty(tag) : tag]), 'eth_getBalance');
  }

  /** Best-effort view of calls a gateway exposes in its pending block. */
  public async pendingCalls(to: Uint8Array): Promise<{ hash: Uint8Array; calldata: Uint8Array }[]> {
    const block = await this.rpc.call<{ transactions?: unknown[] } | null>('eth_getBlockByNumber', ['pending', true]);
    const calls: { hash: Uint8Array; calldata: Uint8Array }[] = [];
    if (!Array.isArray(block?.transactions)) return calls;
    const destination = hexOf(to);
    for (const tx of block.transactions) {
      if (tx === null || typeof tx !== 'object') continue;
      const call = tx as { to?: string; hash?: string; input?: string };
      if (typeof call.to !== 'string' || call.to.toLowerCase() !== destination ||
        typeof call.hash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(call.hash) ||
        typeof call.input !== 'string' || call.input.length > 2 + 2 * 393216 || !/^0x(?:[0-9a-f]{2})*$/i.test(call.input)) continue;
      calls.push({ hash: bytesOf(call.hash, 'pending hash'), calldata: bytesOf(call.input, 'pending calldata') });
      if (calls.length === 1024) break;
    }
    return calls;
  }

  /** The account nonce: 'pending' counts the pool (for signing), 'latest' only mined transactions (for deciding a send is dead). */
  public async nonce(address: Uint8Array, tag: 'pending' | 'latest' | bigint = 'pending'): Promise<bigint> {
    return qtyOf(await this.rpc.call('eth_getTransactionCount', [hexOf(address), typeof tag === 'bigint' ? qty(tag) : tag]), 'eth_getTransactionCount');
  }

  /** The base fee of the latest block and a priority fee. */
  public async fees(): Promise<{ baseFee: bigint; priority: bigint }> {
    const latest = await this.rpc.call<Record<string, unknown>>('eth_getBlockByNumber', ['latest', false]);
    const baseFee = qtyOf(latest.baseFeePerGas, 'baseFeePerGas');
    let priority = 1_000_000_000n;
    try {
      priority = qtyOf(await this.rpc.call('eth_maxPriorityFeePerGas', []), 'eth_maxPriorityFeePerGas');
    } catch (e) {
      // only a node without the method falls back; a rate limit or transport failure must not become a guessed fee
      if (!(e instanceof RpcError && e.methodNotFound)) throw e;
    }
    return { baseFee, priority };
  }

  /** `eth_estimateGas`; a revert is returned as its data (for classification), never thrown as success. */
  public async estimateGas(tx: { from: Uint8Array; to: Uint8Array; data: Uint8Array; value?: bigint }): Promise<{ gas: bigint } | { revert: Uint8Array | null; message: string }> {
    try {
      const g = await this.rpc.call('eth_estimateGas', [{ from: hexOf(tx.from), to: hexOf(tx.to), data: hexOf(tx.data), value: qty(tx.value ?? 0n) }]);
      return { gas: qtyOf(g, 'eth_estimateGas') };
    } catch (e) {
      if (e instanceof RpcError && e.code !== 0) return { revert: revertDataOf(e), message: e.message };
      throw e;
    }
  }

  /** Submit a signed raw transaction; an HTTP 503 is {@link AmbiguousBroadcast}. */
  public async sendRaw(raw: Uint8Array): Promise<Uint8Array> {
    const hash = HE(raw);
    try {
      await this.rpc.call('eth_sendRawTransaction', [hexOf(raw)]);
    } catch (e) {
      if (e instanceof RpcError && e.status === 503) throw new AmbiguousBroadcast(hash, e.message);
      if (e instanceof RpcError && /already known|nonce too low/i.test(e.message)) return hash;
      throw e;
    }
    return hash;
  }
}

/** The revert data an RPC error carries (`data` of the error object is not kept by every client; the message may embed it). */
export function revertDataOf(e: RpcError): Uint8Array | null {
  const d = e.data;
  if (typeof d === 'string' && d.startsWith('0x')) return fromHex(d.slice(2));
  const m = /0x[0-9a-fA-F]{8,}/.exec(e.message);
  return m ? fromHex(m[0].slice(2)) : null;
}

export { WalletError, u256 };

export const recoveryRpcSource = (reader: EvmReader, txHash: Uint8Array): RecoveryReceiptSource => {
  const tx = Uint8Array.from(txHash);
  return async (emitter, event) => (await reader.receiptProof(tx, emitter, event.topics[0], true, event)).encoded;
};
