/** Shell and JSON-RPC helpers of the live DN-B lane driver. Foundry's `cast` is the EVM client (it is already a lane requirement). */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256 } from '../../packages/native-bridge-plugin/src/profile.js';
import { encodeBytes, encodeList, encodeU64 } from '../../packages/native-bridge-plugin/src/rlp.js';

export interface LaneConfig {
  dir: string;
  ethUrls: string[];
  aggUrl: string;
  /** One aggregator endpoint per policy row (shard), in row order; absent for a single-shard lane. */
  aggUrls?: string[];
  vault: string;
  verifier: string;
  rootRpc: string;
  chainId: number;
  evmPartition: number;
  aggPartition: number;
  archive: string;
}

export const loadConfig = (path: string): LaneConfig => JSON.parse(readFileSync(path, 'utf8')) as LaneConfig;

export const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
export const unhex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));

export function run(cmd: string, args: string[], opts: { input?: string } = {}): string {
  return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1 << 28, input: opts.input }).trim();
}

export async function rpc(url: string, method: string, params: unknown[]): Promise<any> {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const body = (await res.json()) as { result?: unknown; error?: { message: string } };
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export async function until<T>(what: string, timeoutMs: number, f: () => Promise<T | undefined | null | false>): Promise<T> {
  const end = Date.now() + timeoutMs;
  let last: unknown;
  for (;;) {
    try {
      const v = await f();
      if (v) return v;
    } catch (e) {
      last = e;
    }
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}${last ? `: ${String(last)}` : ''}`);
    await sleep(1000);
  }
}

/** A signed EIP-155 legacy transaction, built in-process: its calldata never goes on a command line (Linux limits one argv string to 128 KiB, and a
 * long-history envelope is larger). Returns the raw transaction and its hash. */
export function signLegacyTx(t: { nonce: bigint; gasPrice: bigint; gas: bigint; to: string; value: bigint; data: Uint8Array; chainId: bigint }, key: string): { raw: string; hash: string } {
  const fields = [encodeU64(t.nonce), encodeU64(t.gasPrice), encodeU64(t.gas), encodeBytes(unhex(t.to)), encodeU64(t.value), encodeBytes(t.data)];
  const digest = keccak256(encodeList([...fields, encodeU64(t.chainId), encodeU64(0n), encodeU64(0n)]));
  const sig = secp256k1.sign(digest, unhex(key), { prehash: false, format: 'recovered' });
  const strip = (b: Uint8Array): Uint8Array => { let i = 0; while (i < b.length && b[i] === 0) i++; return b.subarray(i); };
  const raw = encodeList([...fields, encodeU64(t.chainId * 2n + 35n + BigInt(sig[0])), encodeBytes(strip(sig.subarray(1, 33))), encodeBytes(strip(sig.subarray(33, 65)))]);
  return { raw: `0x${hex(raw)}`, hash: `0x${hex(keccak256(raw))}` };
}
