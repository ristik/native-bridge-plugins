/** Gateway rate limits are transport conditions: typed, retried briefly with jitter, and never mistaken for an answer. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EvmReader, HttpJsonRpc, RpcError, type JsonRpc } from '../../src/nb2/rpc.js';

const reply = (status: number, body: string, headers: Record<string, string> = {}): Response =>
  new Response(body, { status, headers });

function gateway(answers: Array<Response | Error>) {
  const calls: string[] = [];
  const fetchFn = (async (_url: string, init: RequestInit): Promise<Response> => {
    calls.push(String(init.body));
    const next = answers.shift();
    if (!next) throw new Error('unexpected call');
    if (next instanceof Error) throw next;
    return next;
  }) as unknown as typeof fetch;
  return { calls, fetchFn };
}

const ok = (result: unknown) => reply(200, JSON.stringify({ jsonrpc: '2.0', id: 1, result }));

test('a 429 is retried with jittered backoff and succeeds', async () => {
  const g = gateway([reply(429, '{"error":"slow down"}'), reply(429, '{"error":"slow down"}'), ok('0x1')]);
  const sleeps: number[] = [];
  const rpc = new HttpJsonRpc('http://x', { fetch: g.fetchFn, sleep: async (ms) => { sleeps.push(ms); }, random: () => 0.5 });
  assert.equal(await rpc.call('eth_chainId', []), '0x1');
  assert.deepEqual(sleeps, [250, 500]);
});

test('Retry-After is honoured, and one beyond the budget is surfaced instead of waited out', async () => {
  const short = gateway([reply(429, '{}', { 'retry-after': '2' }), ok('0x1')]);
  const sleeps: number[] = [];
  await new HttpJsonRpc('http://x', { fetch: short.fetchFn, sleep: async (ms) => { sleeps.push(ms); } }).call('eth_chainId', []);
  assert.deepEqual(sleeps, [2000]);

  const long = gateway([reply(503, '{}', { 'retry-after': '120' })]);
  await assert.rejects(new HttpJsonRpc('http://x', { fetch: long.fetchFn, sleep: async () => assert.fail('must not wait') }).call('eth_chainId', []),
    (e: unknown) => e instanceof RpcError && e.status === 503 && e.retryable && e.retryAfterMs === 120_000);
});

test('persistent 429 stops after three attempts and is a retryable RpcError', async () => {
  const g = gateway([reply(429, '{}'), reply(429, '{}'), reply(429, '{}'), reply(429, '{}')]);
  let slept = 0;
  await assert.rejects(new HttpJsonRpc('http://x', { fetch: g.fetchFn, sleep: async (ms) => { slept += ms; }, random: () => 0.99 }).call('eth_chainId', []),
    (e: unknown) => e instanceof RpcError && e.status === 429 && e.retryable);
  assert.equal(g.calls.length, 3);
  assert.ok(slept <= 5_000);
});

test('a network failure is a retryable RpcError and is not retried by the transport', async () => {
  const g = gateway([new TypeError('fetch failed')]);
  await assert.rejects(new HttpJsonRpc('http://x', { fetch: g.fetchFn, sleep: async () => assert.fail('no wait') }).call('eth_chainId', []),
    (e: unknown) => e instanceof RpcError && e.status === 0 && e.retryable);
});

test('a JSON-RPC error or a 4xx is not retryable', () => {
  assert.equal(new RpcError(200, -32601, 'no method').retryable, false);
  assert.equal(new RpcError(413, 0, 'too large').retryable, false);
});

const latest: JsonRpc['call'] = async <T>(method: string): Promise<T> =>
  (method === 'eth_getBlockByNumber' ? { baseFeePerGas: '0x7' } : undefined) as T;

test('fees() propagates a 429 and a network failure from eth_maxPriorityFeePerGas', async () => {
  for (const err of [new RpcError(429, 0, 'rate limited'), new RpcError(0, 0, 'fetch failed')]) {
    const reader = new EvmReader({ call: async <T>(m: string, p: unknown[]): Promise<T> => {
      if (m === 'eth_maxPriorityFeePerGas') throw err;
      return latest<T>(m, p);
    } });
    await assert.rejects(reader.fees(), (e: unknown) => e === err);
  }
});

test('fees() falls back to 1 gwei only when the method is not found', async () => {
  const reader = new EvmReader({ call: async <T>(m: string, p: unknown[]): Promise<T> => {
    if (m === 'eth_maxPriorityFeePerGas') throw new RpcError(200, -32601, 'method not found');
    return latest<T>(m, p);
  } });
  assert.deepEqual(await reader.fees(), { baseFee: 7n, priority: 1_000_000_000n });
});
