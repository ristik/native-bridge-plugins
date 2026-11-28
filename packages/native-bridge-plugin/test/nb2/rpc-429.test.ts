/** Gateway rate limits are transport conditions: typed, retried briefly with jitter, and never mistaken for an answer. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { toHex } from '../../src/bytes.js';
import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { MemoryJournalStore } from '../../src/nb2/journal.js';
import { AmbiguousBroadcast, EvmReader, HttpJsonRpc, RpcError, type JsonRpc } from '../../src/nb2/rpc.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { evmAccount, key, setup } from './world.js';

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

test('writes and unknown methods each make one attempt on 429 and 503', async () => {
  for (const method of ['eth_sendRawTransaction', 'eth_sendTransaction', 'eth_unknown']) {
    for (const status of [429, 503]) {
      const g = gateway([reply(status, '{}')]);
      const rpc = new HttpJsonRpc('http://x', { fetch: g.fetchFn, sleep: async () => assert.fail('unexpected retry') });
      await assert.rejects(rpc.call(method, []), (e: unknown) => e instanceof RpcError && e.status === status);
      assert.equal(g.calls.length, 1);
    }
  }
});

test('a transport runs at most four concurrent reads and returns slots after failures', async () => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let started = 0;
  let inFlight = 0;
  let peak = 0;
  const rpc = new HttpJsonRpc('http://x', { fetch: async () => {
    const call = ++started;
    peak = Math.max(peak, ++inFlight);
    await gate;
    inFlight--;
    return call === 1 ? reply(502, 'bad gateway') : ok('0x1');
  } });
  const reads = Promise.allSettled(Array.from({ length: 9 }, () => rpc.call('eth_chainId', [])));
  const initiallyStarted = started;
  release();
  const results = await reads;
  assert.equal(initiallyStarted, 4);
  assert.equal(peak, 4);
  assert.equal(started, 9);
  assert.equal(results[0].status, 'rejected');
  assert.ok(results.slice(1).every((r) => r.status === 'fulfilled'));
});

test('HTTP errors retain nested envelope messages and Retry-After', async () => {
  const g = gateway([reply(503, '{"error":{"code":-32601,"message":"upstream out of slots"}}', { 'retry-after': '120' })]);
  const rpc = new HttpJsonRpc('http://x', { fetch: g.fetchFn, retries: 0 });
  await assert.rejects(rpc.call('eth_chainId', []), (e: unknown) => e instanceof RpcError && e.status === 503
    && e.message === 'gateway HTTP 503: upstream out of slots' && e.retryAfterMs === 120_000 && e.retryable && !e.methodNotFound);
});

test('logs keep the original page when the provider throttles it', async () => {
  for (const response of [reply(429, '{"error":"Too Many Requests"}'),
    reply(200, '{"error":{"code":-32005,"message":"Too Many Requests: rate limit exceeded"}}')]) {
    const g = gateway([response]);
    const reader = new EvmReader(new HttpJsonRpc('http://x', { fetch: g.fetchFn, retries: 0 }));
    await assert.rejects(reader.logs(new Uint8Array(20), [], 0n, 3n), /Too Many Requests/);
    assert.equal(g.calls.length, 1);
  }
});

test('logs split for explicit response-size, result-count, and range limits', async () => {
  for (const limit of [reply(413, 'answer too large'),
    reply(200, '{"error":{"code":-32005,"message":"query returned more than 10000 results"}}'),
    reply(400, '{"error":{"message":"block range exceeds provider limit"}}')]) {
    const g = gateway([limit, ok([]), ok([])]);
    const reader = new EvmReader(new HttpJsonRpc('http://x', { fetch: g.fetchFn, retries: 0 }));
    assert.deepEqual(await reader.logs(new Uint8Array(20), [], 0n, 3n), []);
    assert.deepEqual(g.calls.map((body) => {
      const [{ fromBlock, toBlock }] = JSON.parse(body).params;
      return [fromBlock, toBlock];
    }), [['0x0', '0x3'], ['0x0', '0x1'], ['0x2', '0x3']]);
  }
});

for (const [name, unanswered] of [
  ['502', () => reply(502, 'bad gateway')],
  ['503', () => reply(503, 'broadcast may be partial')],
  ['504', () => reply(504, 'gateway timeout')],
  ['a lost connection', () => { throw new TypeError('fetch failed'); }],
  ['a missing result', () => reply(200, '{}')],
] as const) {
  test(`a send with ${name} reconciles by local hash and retries the journaled bytes`, async () => {
    const { chain, options } = await setup();
    const signer = evmAccount(chain, 'RPC fault payer');
    const store = new MemoryJournalStore();
    const sends: string[] = [];
    const receiptReads: string[] = [];
    const rpc = new HttpJsonRpc('http://x', { fetch: async (_url, init) => {
      const { method, params } = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
      if (method === 'eth_sendRawTransaction') {
        sends.push(String(params[0]));
        if (sends.length === 1) return unanswered();
      }
      if (method === 'eth_getTransactionReceipt') receiptReads.push(String(params[0]));
      return ok(await chain.call(method, params));
    } });
    const bridge = await NativeBridgeV2.open({ ...options('RPC fault wallet', store), rpc });
    const plan = await bridge.planDeposit(4n, localOwner(key('RPC fault owner')).publicKey);
    await assert.rejects(bridge.submitDeposit(plan, signer), { reason: 'Unconfirmed' });
    const record = await bridge.journal.deposit(plan.intent);
    assert.equal(record?.sends.length, 1);
    const [send] = record!.sends;
    assert.deepEqual(sends, [send.raw]);
    assert.ok(receiptReads.length > 0);
    assert.ok(receiptReads.every((hash) => hash === send.hash));
    await assert.rejects(bridge.submitDeposit(plan, signer), { reason: 'Unconfirmed' });
    assert.deepEqual(sends, [send.raw, send.raw]);
    assert.equal((await bridge.submitDeposit(plan, signer)).txHash.length, 32);
    assert.equal(sends.length, 2);
  });
}

test('sendRaw requires the local hash in the acknowledgement and receipt reads accept null', async () => {
  const raw = Uint8Array.of(1);
  const hash = HE(raw);
  const g = gateway([ok(null), ok(''), ok(`0x${'ff'.repeat(32)}`), ok(`0x${toHex(hash).toUpperCase()}`), ok(null)]);
  const reader = new EvmReader(new HttpJsonRpc('http://x', { fetch: g.fetchFn }));
  for (let i = 0; i < 3; i++) {
    await assert.rejects(reader.sendRaw(raw), (e: unknown) => {
      assert.ok(e instanceof AmbiguousBroadcast);
      assert.deepEqual(e.txHash, hash);
      return true;
    });
  }
  assert.deepEqual(await reader.sendRaw(raw), hash);
  assert.equal(await reader.receipt(hash), null);
  assert.equal(g.calls.length, 5);
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
  for (const err of [new RpcError(429, 0, 'rate limited'), new RpcError(0, 0, 'fetch failed'),
    new RpcError(503, -32601, 'method not found in gateway error')]) {
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
