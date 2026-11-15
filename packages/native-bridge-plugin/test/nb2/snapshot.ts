/**
 * The JSON snapshot of a whole offline world (chain, aggregator, journal), shared with the Rust plug-in's test world
 * (`crates/native-bridge-sdk-ext/tests/nb2_world`). A journal written by one plug-in is continued by the other against the same
 * chain: `tests/nb2-journal/` holds one snapshot written by each (bft-core#1104).
 */
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';

import { fromHex, toHex } from '../../src/bytes.js';
import { u256 } from '../../src/nb2/cbor.js';
import { TEST_PARAMS, decodeConfig } from '../../src/nb2/config.js';
import { HE } from '../../src/nb2/crypto.js';
import { encodeHeader } from '../../src/nb2/header.js';
import { MemoryJournalStore } from '../../src/nb2/journal.js';
import { headerOfJson } from '../../src/nb2/rpc.js';
import { deriveBridgeKey, type BridgeOptions } from '../../src/nb2/bridge.js';
import { TrustInput } from '../../src/nb2/trust.js';
import { FakeAggregator, FakeChain, key, roundAtLeast, roundNow, type Root } from './world.js';

export const SNAPSHOT_FORMAT = 'unicity-nb2-offline-world';

const h = (b: Uint8Array): string => `0x${toHex(b)}`;
const unh = (s: string): Uint8Array => fromHex(s.slice(2))!;
const q = (v: bigint | number): string => `0x${BigInt(v).toString(16)}`;

/** The world's pins and options, as `setup()` makes them. */
export function worldOf(root: Root, chain: FakeChain, agg: FakeAggregator) {
  const pins = {
    gamma: chain.gamma, build: 'test' as const, vaultRuntimeCodeHash: HE(chain.vaultCode), maxEncodedTxBytes: 524_288n, userGasLimit: 60_000_000n,
    gasReserve: 500_000n, returnReserveSegments: 64n, deploymentBlock: 1n, stateReadOnly: false,
  };
  const options = (seed: string, store = new MemoryJournalStore()): BridgeOptions => ({
    pins, trust: root.trust, rpc: chain, aggregator: agg, journal: store, bridgeKey: deriveBridgeKey(key(seed)), backup: async () => {},
    receiptTimeoutMs: 0, pollMs: 0, sleep: async () => {},
  });
  return { root, chain, agg, pins, options };
}

export function snapshot(root: Root, chain: FakeChain, agg: FakeAggregator, journal: MemoryJournalStore): unknown {
  const c = chain as any;
  const headerJson = (b: any): Record<string, unknown> => c.headerJson(b);
  const obj = (m: Map<string, unknown>, f: (v: any) => string): Record<string, string> => Object.fromEntries([...m].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => [`0x${k}`, f(v)]));
  const v = chain.vault;
  return {
    format: SNAPSHOT_FORMAT, version: 1, signers: root.signers.length, bundle: h(root.bundle), pin: h(root.pin), round: roundNow().toString(), gamma: h(chain.gamma),
    blocks: chain.blocks.map((b: any) => ({
      header: headerJson(b), uc: b.uc === null ? null : h(b.uc),
      receipts: b.receipts.map((r: any) => ({
        status: r.status.toString(), tx: h(r.tx), from: h(r.from), revert: r.revert === null ? null : h(r.revert), gas: r.gas.toString(),
        logs: r.logs.map((l: any) => ({ address: h(l.address), topics: l.topics.map(h), data: h(l.data) })),
      })),
    })),
    balances: obj(chain.balances, (x: bigint) => x.toString()),
    nonces: obj(chain.nonces, (x: bigint) => x.toString()),
    code: obj(chain.code, (x: Uint8Array) => h(x)),
    vault: {
      deposits: v.n.toString(), segment: v.c.toString(), population: v.m.toString(), outstanding: v.q.toString(), head: h(v.head), prev: h(v.prev),
      tagWords: v.T.map((ws) => ws.map((w) => h(u256(w)))), ids: v.S.map((b) => b.map(h)),
    },
    aggregator: { time: agg.time.toString(), certified: obj(agg.certified, (x: Uint8Array) => h(x)) },
    pool: (c.pool as Uint8Array[]).map(h),
    journal: Object.fromEntries([...journal.map].sort(([a], [b]) => (a < b ? -1 : 1))),
  };
}

/** A world and its journal from a snapshot (either plug-in's). */
export async function restore(s: any) {
  if (s.format !== SNAPSHOT_FORMAT || s.version !== 1) throw new Error('not an offline-world snapshot');
  const signers: [string, SigningService][] = Array.from({ length: s.signers }, (_, i) => [`root-${String(i).padStart(2, '0')}`, new SigningService(key(`root ${i}`))]);
  const bundle = unh(s.bundle);
  const pin = unh(s.pin);
  const root: Root = { signers, bundle, pin, trust: await TrustInput.fromBundle(bundle, pin) };
  roundAtLeast(BigInt(s.round));
  const cfg = decodeConfig(unh(s.gamma), TEST_PARAMS);
  const chain = await FakeChain.create(root, cfg);
  chain.blocks.length = 0;
  for (const b of s.blocks) {
    const header = headerOfJson(b.header);
    const hash = HE(encodeHeader(header));
    if (h(hash) !== b.header.hash) throw new Error('snapshot header does not hash to its hash');
    chain.blocks.push({
      header, hash, uc: b.uc === null ? null : unh(b.uc),
      receipts: b.receipts.map((r: any) => ({
        status: BigInt(r.status), tx: unh(r.tx), from: unh(r.from), revert: r.revert === null ? null : unh(r.revert), gas: BigInt(r.gas), type: 2,
        logs: r.logs.map((l: any) => ({ address: unh(l.address), topics: l.topics.map(unh), data: unh(l.data) })),
      })),
    } as any);
  }
  const fill = <T>(m: Map<string, T>, o: Record<string, string>, f: (x: string) => T): void => {
    m.clear();
    for (const [k, x] of Object.entries(o)) m.set(k.slice(2), f(x));
  };
  fill(chain.balances, s.balances, BigInt);
  fill(chain.nonces, s.nonces, BigInt);
  fill(chain.code, s.code, unh);
  (chain as any).pool = (s.pool ?? []).map(unh);
  const v = s.vault;
  const vm = chain.vault;
  vm.A = (BigInt(v.deposits) << 200n) | (BigInt(v.segment) << 152n) | (BigInt(v.population) << 144n) | BigInt(v.outstanding);
  vm.T = v.tagWords.map((ws: string[]) => ws.map((w) => BigInt(w))) as [bigint[], bigint[]];
  vm.S = v.ids.map((b: string[]) => b.map(unh)) as [Uint8Array[], Uint8Array[]];
  vm.head = unh(v.head);
  vm.prev = unh(v.prev);
  const agg = new FakeAggregator(root);
  agg.time = BigInt(s.aggregator.time);
  fill(agg.certified, s.aggregator.certified, unh);
  const journal = new MemoryJournalStore();
  for (const [k, x] of Object.entries<string>(s.journal)) journal.map.set(k, x);
  return { ...worldOf(root, chain, agg), cfg, journal };
}

export { q };
