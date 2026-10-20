import assert from 'node:assert/strict';
import { test } from 'node:test';

import { toHex } from '../src/bytes.js';
import { loadManifests, manifestTrustBaseId, validateManifest } from '../src/manifest.js';
import { cfgBytes, cfgHash, deriveAsset, deriveType, policyBytes, policyHash } from '../src/profile.js';
import { TrustInput } from '../src/trust.js';
import { throwsReason } from './util.js';
import { CHAIN_ID, EXEC_GENESIS, NETWORK, ROOT_GENESIS, makeRoot, makeWorld, nextEpoch, pdrBytes, sha, text, type World } from './world.js';

const execProfile = text('{"headerFields":20}');
const pdr = pdrBytes(5n, 0n);
const store = new Map<string, Uint8Array>([[toHex(sha(execProfile)), execProfile], [toHex(sha(pdr)), pdr]]);
const artifacts = (h: string): Uint8Array | undefined => store.get(h);
const art = (b: Uint8Array): Record<string, unknown> => ({ sha256: toHex(sha(b)) });

const rec = (w: World): Record<string, any> => ({
  vaultAddress: toHex(w.dep.cfg.vault),
  vaultRuntimeHash: toHex(sha(text('vault runtime'))),
  cfgHex: toHex(cfgBytes(w.dep.cfg)),
  cfgHash: toHex(cfgHash(w.dep.cfg)),
  tokenVerifierAddress: toHex(w.dep.cfg.tokenVerifierAddress),
  tokenVerifierRuntimeHash: toHex(w.dep.cfg.tokenVerifierCodeHash),
  semanticProfile: { sha256: toHex(w.dep.cfg.semanticProfileHash) },
  b1: {
    profile: { sha256: toHex(w.dep.cfg.b1ProfileHash) },
    registryAddress: toHex(new Uint8Array(20).fill(0x0b)),
    registryRuntimeHash: toHex(sha(text('registry'))),
    registryLayout: art(text('layout')),
    genesis: art(text('b1 genesis')),
  },
  lockLayoutVersion: 1,
  aggregatorPolicy: { bodyHex: toHex(policyBytes(w.policy)), sha256: toHex(policyHash(w.policy)), partition: w.policy.partition },
  evmBackingPolicy: { partition: w.dep.cfg.evmPartition, shardHex: toHex(w.dep.cfg.evmShard), configurationHash: toHex(w.dep.evmConfigHash), pdr: art(pdr), executionProfile: art(execProfile) },
});

const entry = (w: World): Record<string, any> => ({
  schemaVersion: 1, protocolVersion: 5, family: 'unicity-native', sdkVersion: '4.0.0',
  tokenTypeHex: toHex(deriveType(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID)),
  coinIdHex: toHex(deriveAsset(NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID)),
  symbol: 'UCT', decimals: 18,
  plugin: { npm: { name: '@unicitylabs/native-bridge-plugin', version: '0.1.0', integrity: `sha512-${'A'.repeat(86)}==` }, rust: { crate: 'native-bridge-sdk-ext', version: '0.1.0', revision: '1'.repeat(40) }, protocolCommit: '2'.repeat(40), vectorManifestSha256: '3'.repeat(64) },
  networkId: NETWORK, rootGenesisHash: toHex(ROOT_GENESIS), executionGenesisHash: toHex(EXEC_GENESIS),
  evmChainId: CHAIN_ID.toString(), chainRef: `eip155:${CHAIN_ID}`, asset: '0'.repeat(40),
  activeDeployment: rec(w), replacedDeployments: [],
  trustBase: {
    networkId: NETWORK, rootGenesisHash: toHex(ROOT_GENESIS), format: 'utb-release-bundle-v1', genesisEntryId: toHex(w.bridge.trust.id),
    bundle: { sha256: toHex(sha(w.agg.bundle)), location: 'file:///etc/native/trust-base.bundle.cbor' },
  },
  proofEndpoints: ['https://aggregator.invalid'], rpcUrls: [],
});

const registry = (e: Record<string, any>): string => JSON.stringify({ [e.tokenTypeHex]: e });

const load = (w: World, f: (d: Record<string, any>) => void): number => {
  const e = entry(w);
  f(e);
  return loadManifests(registry(e), artifacts).registry.deployments.length;
};

test('a schema-shaped manifest loads the recomputed deployment and installs under the pinned trust base genesis', async () => {
  const w = await makeWorld();
  const loaded = loadManifests(registry(entry(w)), artifacts);
  assert.equal(loaded.registry.deployments.length, 1);
  assert.deepEqual(loaded.registry.deployments[0].cfg, w.dep.cfg);
  loaded.install(w.bridge.trust);
});

test('every identity and profile field is recomputed or rejected', async () => {
  const cases: [string, (d: Record<string, any>) => void][] = [
    ['schema', (d) => void (d.schemaVersion = 2)],
    ['protocol', (d) => void (d.protocolVersion = 1)],
    ['family', (d) => void (d.family = 'eip155')],
    ['sdk', (d) => void (d.sdkVersion = '3.0.1')],
    ['genesis entry id', (d) => void (d.trustBase.genesisEntryId = 'zz'.repeat(32))],
    ['bundle digest missing', (d) => void delete d.trustBase.bundle.sha256],
    ['legacy trust document', (d) => void (d.trustBase = { networkId: NETWORK, rootGenesisHash: d.rootGenesisHash, format: 'sdk-root-trust-base-json-v1', document: d.trustBase.bundle })],
    ['type', (d) => void (d.tokenTypeHex = toHex(new Uint8Array(32).fill(1)))],
    ['coin', (d) => void (d.coinIdHex = toHex(new Uint8Array(32).fill(1)))],
    ['chain ref', (d) => void (d.chainRef = 'eip155:1')],
    ['chain id leading zero', (d) => void (d.evmChainId = '07777')],
    ['chain id zero', (d) => void (d.evmChainId = '0')],
    ['asset with 0x', (d) => void (d.asset = `0x${'0'.repeat(40)}`)],
    ['asset nonzero', (d) => void (d.asset = `${'0'.repeat(39)}1`)],
    ['vault', (d) => void (d.activeDeployment.vaultAddress = toHex(new Uint8Array(20).fill(1)))],
    ['zero vault', (d) => void (d.activeDeployment.vaultAddress = '0'.repeat(40))],
    ['cfg hash', (d) => void (d.activeDeployment.cfgHash = toHex(new Uint8Array(32).fill(1)))],
    ['semantic profile', (d) => void (d.activeDeployment.semanticProfile.sha256 = toHex(new Uint8Array(32).fill(1)))],
    ['b1 profile', (d) => void (d.activeDeployment.b1.profile.sha256 = toHex(new Uint8Array(32).fill(1)))],
    ['policy partition', (d) => void (d.activeDeployment.aggregatorPolicy.partition = 99)],
    ['evm partition', (d) => void (d.activeDeployment.evmBackingPolicy.partition = 99)],
    ['evm configuration pin', (d) => void (d.activeDeployment.evmBackingPolicy.configurationHash = toHex(new Uint8Array(32).fill(1)))],
    ['execution profile missing', (d) => void (d.activeDeployment.evmBackingPolicy.executionProfile.sha256 = toHex(new Uint8Array(32).fill(2)))],
    ['uppercase hex', (d) => void (d.rootGenesisHash = 'AA'.repeat(32))],
    ['unknown field', (d) => void (d.extra = 1)],
    ['bundle-style trust base', (d) => void (d.trustBase = { bundleDigest: 'x', epochs: [] })],
    ['trust format', (d) => void (d.trustBase.format = 'epoch-bundle')],
    ['trust network', (d) => void (d.trustBase.networkId = NETWORK + 1)],
    ['npm version', (d) => void (d.plugin.npm.version = '9.9.9')],
    ['replaced missing', (d) => void delete d.replacedDeployments],
  ];
  const lw = await makeWorld();
  for (const [name, f] of cases) assert.throws(() => load(lw, f), /./s, name);
});

test('installed artifacts must match their pins and the genesis PDR must yield the pinned configuration', async () => {
  const e = entry(await makeWorld());
  const wrong = (h: string): Uint8Array | undefined => (h === toHex(sha(pdr)) ? text('not the pdr') : artifacts(h));
  throwsReason(() => loadManifests(registry(e), wrong), 'ErrManifest');
  const otherPdr = pdrBytes(5n, 1n);
  const e2 = entry(await makeWorld());
  e2.activeDeployment.evmBackingPolicy.pdr.sha256 = toHex(sha(otherPdr));
  const other = (h: string): Uint8Array | undefined => (h === toHex(sha(otherPdr)) ? otherPdr : artifacts(h));
  throwsReason(() => loadManifests(registry(e2), other), 'ErrManifest');
  // The execution profile is required and must be exactly the header shape.
  const bare = entry(await makeWorld());
  throwsReason(() => loadManifests(registry(bare), () => undefined), 'ErrManifest');
});

test('symbol is not identity', async () => {
  assert.equal(load(await makeWorld(), (d) => void (d.symbol = 'SOMETHING-ELSE')), 1);
});

test('the registry key must be the tokenTypeHex and a replaced vault may not equal the active one', async () => {
  const w = await makeWorld();
  const e = entry(w);
  assert.throws(() => loadManifests(JSON.stringify({ [toHex(new Uint8Array(32))]: e }), artifacts), /./);
  const dup = entry(w);
  dup.replacedDeployments = [rec(w)];
  throwsReason(() => loadManifests(registry(dup), artifacts), 'ErrAmbiguousDeployment');
  assert.throws(() => loadManifests('{}', artifacts));
});

test('the pinned genesis must be the installed trust input\'s; a grown history of it installs', async () => {
  const w = await makeWorld();
  const other = await makeRoot(2, 4, 20);
  const e = entry(w);
  e.trustBase.genesisEntryId = toHex(new Uint8Array(32).fill(9));
  const loaded = loadManifests(registry(e), artifacts);
  throwsReason(() => loaded.install(w.bridge.trust), 'ErrTrustBaseDigest');
  assert.deepEqual(manifestTrustBaseId(entry(w)), w.bridge.trust.id);
  assert.equal(validateManifest(entry(w), artifacts).deployments.length, 1);
  // the authority is the genesis pin: a history grown past the named bundle, exported and reinstalled (a wallet's own bundle) installs
  const grown = await nextEpoch(w.agg, 1000n, 4, 30);
  const exported = await TrustInput.fromBundle(await grown.trust.history.exportBundle(), w.agg.pin);
  assert.equal(exported.history.tipEpoch, 3n);
  loadManifests(registry(entry(w)), artifacts).install(exported);
  // another genesis is another trust input
  throwsReason(() => loadManifests(registry(entry(w)), artifacts).install(other.trust), 'ErrTrustBaseDigest');
});

test('endpoints and locations are installation metadata, never verification inputs', async () => {
  const e = entry(await makeWorld());
  e.proofEndpoints = ['https://unreachable.invalid'];
  e.trustBase.bundle.location = 'https://unreachable.invalid/trust-base.bundle.cbor';
  assert.equal(loadManifests(registry(e), artifacts).registry.deployments.length, 1);
});
