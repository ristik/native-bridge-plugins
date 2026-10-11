/** Shell and JSON-RPC helpers of the live DN-B lane driver. Foundry's `cast` is the EVM client (it is already a lane requirement). */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

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
