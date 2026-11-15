/** Γ, D and the asset identity (section 4; bft-core `nb2ref/config.go`). */
import { eq, toHex } from '../bytes.js';
import {
  MAX_U64, amount, array, ascii, bstr, bytesN, cAmount, cArr, cBytes, cUint, literal, scanOne, uintIn, version,
} from './cbor.js';
import { HU } from './crypto.js';
import { Nb2Error, fail, type Rule } from './errors.js';

export const NATIVE_BRIDGE_PROTO_VERSION = 9;

export const TAG = {
  predicate: 39032n, mint: 39041n, transfer: 39045n, certification: 39031n, token: 39040n, inclusion: 39033n, value: 39050n,
  splitJustification: 39044n, splitManifest: 39046n, receiptBacking: 39051n, segmentReturn: 39052n,
} as const;

export const V2_VERSION = 1n;
export const DOMAIN = {
  config: 'UNICITY_NB2_CFG', depositIntent: 'UNICITY_NB2_DEPOSIT_INTENT', depositSalt: 'UNICITY_NB2_DEPOSIT_SALT', burn: 'UNICITY_NB2_BURN',
  redemption: 'UNICITY_NB2_REDEMPTION', splitOutput: 'UNICITY_SPLIT_OUTPUT',
} as const;

/** a_UCT = H_U(UTF8("unicity-nb2-asset:native-uct")). */
export const ASSET_UCT = HU(ascii('unicity-nb2-asset:native-uct'));

export const MAX_DEPOSIT = (1n << 56n) - 1n;
export const MAX_SEGMENT = (1n << 48n) - 1n;
export const MAX_INDEX = (1n << 32n) - 1n;
export const QMAX_LIMIT = (1n << 144n) - 1n;
/** The largest K any build admits. */
export const MAX_K = 64n;

/** An admitted (K, B) set: production admits only (64, 16) (#1098); a test build admits K in {4, 8} x B in {2, 4}, never both. */
export interface Params { readonly K: readonly bigint[]; readonly B: readonly bigint[] }
export const PRODUCTION_PARAMS: Params = { K: [64n], B: [16n] };
export const TEST_PARAMS: Params = { K: [4n, 8n], B: [2n, 4n] };
export type Build = 'production' | 'test';
export const buildParams = (b: Build): Params => (b === 'test' ? TEST_PARAMS : PRODUCTION_PARAMS);

const pow2 = (x: bigint): boolean => x > 0n && (x & (x - 1n)) === 0n;
export const admits = (p: Params, k: bigint, b: bigint): boolean =>
  k >= 2n && k <= MAX_K && pow2(k) && b >= 2n && b <= k && pow2(b) && p.K.includes(k) && p.B.includes(b);

/** log2 of a power of two. */
export const log2 = (x: bigint): number => x.toString(2).length - 1;

export interface Config {
  network: number;
  rootGenesis: Uint8Array;
  executionGenesis: Uint8Array;
  chainId: bigint;
  evmPartition: number;
  evmShard: Uint8Array;
  aggregatorPartition: number;
  vault: Uint8Array;
  asset: Uint8Array;
  ty: Uint8Array;
  aid: Uint8Array;
  semanticProfileHash: Uint8Array;
  verifier: Uint8Array;
  verifierCodeHash: Uint8Array;
  K: bigint;
  B: bigint;
  Qmax: bigint;
}

export const CONFIG_ARITY = 19;

export function encodeConfig(c: Config): Uint8Array {
  return cArr(
    cBytes(ascii(DOMAIN.config)), cUint(V2_VERSION), cUint(c.network), cBytes(c.rootGenesis), cBytes(c.executionGenesis), cUint(c.chainId),
    cUint(c.evmPartition), cBytes(c.evmShard), cUint(c.aggregatorPartition), cBytes(c.vault), cBytes(c.asset), cBytes(c.ty), cBytes(c.aid),
    cBytes(c.semanticProfileHash), cBytes(c.verifier), cBytes(c.verifierCodeHash), cUint(c.K), cUint(c.B), cAmount(c.Qmax),
  );
}

/** D = H_U(Γ). */
export const domainOf = (gamma: Uint8Array): Uint8Array => HU(gamma);

/** A Γ failure naming the first failing field (19: the array itself). The verifier reports it as ConfigShape. */
export class ConfigError extends Nb2Error {
  public constructor(public readonly field: number, public readonly cause: Nb2Error) {
    super('ConfigShape', `field ${field}: ${cause.rule}`);
  }
}

const MAX_CONFIG_BYTES = 1024;

function at<T>(field: number, f: () => T): T {
  try {
    return f();
  } catch (e) {
    if (e instanceof Nb2Error) throw new ConfigError(field, e);
    throw e;
  }
}

/** A canonical native shard ID: 1..33 bytes, a last byte that is nonzero (the terminator bit), at most 256 prefix bits. */
export function canonicalShardId(b: Uint8Array): boolean {
  if (b.length === 0 || b.length > 33 || b[b.length - 1] === 0) return false;
  const last = b[b.length - 1];
  let tz = 0;
  while (((last >> tz) & 1) === 0) tz++;
  return 8 * b.length - tz - 1 <= 256;
}

/** Strictly decode Γ under the admitted set `p` (every section 4.1 check that needs no deployment environment). */
export function decodeConfig(b: Uint8Array, p: Params): Config {
  if (b.length > MAX_CONFIG_BYTES) throw new ConfigError(CONFIG_ARITY, new Nb2Error('InputTooLarge'));
  const k = at(CONFIG_ARITY, () => array(scanOne(b), CONFIG_ARITY));
  at(0, () => literal(k[0], DOMAIN.config));
  at(1, () => version(k[1], V2_VERSION));
  const network = Number(at(2, () => uintIn(k[2], 1n, 65535n)));
  const rootGenesis = at(3, () => bytesN(k[3], 32));
  const executionGenesis = at(4, () => bytesN(k[4], 32));
  const chainId = at(5, () => uintIn(k[5], 1n, MAX_U64));
  const ep = at(6, () => uintIn(k[6], 1n, (1n << 32n) - 1n));
  const evmShard = at(7, () => bstr(k[7]));
  if (!canonicalShardId(evmShard)) throw new ConfigError(7, new Nb2Error('Length'));
  const ap = at(8, () => uintIn(k[8], 1n, (1n << 32n) - 1n));
  if (ap === ep) throw new ConfigError(8, new Nb2Error('IntRange'));
  const vault = at(9, () => bytesN(k[9], 20));
  const asset = at(10, () => bytesN(k[10], 32));
  const ty = at(11, () => bytesN(k[11], 32));
  const aid = at(12, () => bytesN(k[12], 32));
  const semanticProfileHash = at(13, () => bytesN(k[13], 32));
  const verifier = at(14, () => bytesN(k[14], 20));
  const verifierCodeHash = at(15, () => bytesN(k[15], 32));
  const K = at(16, () => uintIn(k[16], 2n, MAX_K));
  const B = at(17, () => uintIn(k[17], 2n, MAX_K));
  if (!admits(p, K, B)) {
    if (!(p.K.includes(K) && pow2(K))) throw new ConfigError(16, new Nb2Error('IntRange'));
    throw new ConfigError(17, new Nb2Error('IntRange'));
  }
  const Qmax = at(18, () => amount(k[18]));
  if (Qmax > QMAX_LIMIT) throw new ConfigError(18, new Nb2Error('IntRange'));
  return {
    network, rootGenesis: rootGenesis.slice(), executionGenesis: executionGenesis.slice(), chainId, evmPartition: Number(ep), evmShard: evmShard.slice(),
    aggregatorPartition: Number(ap), vault: vault.slice(), asset: asset.slice(), ty: ty.slice(), aid: aid.slice(),
    semanticProfileHash: semanticProfileHash.slice(), verifier: verifier.slice(), verifierCodeHash: verifierCodeHash.slice(), K, B, Qmax,
  };
}

const identityString = (network: number, rootGenesis: Uint8Array, executionGenesis: Uint8Array, chainId: bigint): string =>
  `${network}:${toHex(rootGenesis)}:${toHex(executionGenesis)}:${chainId}`;

/** ty = H_U(UTF8("unicity-bridge:unicity-native-nb2:" + Dstr)). */
export const deriveType = (network: number, rootGenesis: Uint8Array, executionGenesis: Uint8Array, chainId: bigint): Uint8Array =>
  HU(ascii(`unicity-bridge:unicity-native-nb2:${identityString(network, rootGenesis, executionGenesis, chainId)}`));
/** aid = H_U(UTF8("unicity-bridge-coin:unicity-native-nb2:" + Dstr)). */
export const deriveCoin = (network: number, rootGenesis: Uint8Array, executionGenesis: Uint8Array, chainId: bigint): Uint8Array =>
  HU(ascii(`unicity-bridge-coin:unicity-native-nb2:${identityString(network, rootGenesis, executionGenesis, chainId)}`));

/** What the vault constructor checks Γ against. */
export interface Environment { address: Uint8Array; chainId: bigint; verifierCodeHash: Uint8Array }

/** BadConfig(field). */
export class BadConfigError extends Nb2Error {
  public constructor(public readonly field: number) {
    super('BadConfig', undefined, [String(field)]);
  }
}

/** The vault constructor's acceptance of Γ, in the reference's order. */
export function construct(gamma: Uint8Array, env: Environment, p: Params): Config {
  let c: Config;
  try {
    c = decodeConfig(gamma, p);
  } catch (e) {
    throw new BadConfigError(e instanceof ConfigError ? e.field : CONFIG_ARITY);
  }
  if (!eq(c.asset, ASSET_UCT)) throw new BadConfigError(10);
  if (!eq(c.ty, deriveType(c.network, c.rootGenesis, c.executionGenesis, c.chainId))) throw new BadConfigError(11);
  if (!eq(c.aid, deriveCoin(c.network, c.rootGenesis, c.executionGenesis, c.chainId))) throw new BadConfigError(12);
  if (!eq(c.vault, env.address)) throw new BadConfigError(9);
  if (c.chainId !== env.chainId) throw new BadConfigError(5);
  if (!eq(c.verifierCodeHash, env.verifierCodeHash)) throw new BadConfigError(15);
  return c;
}

/** A decoded Γ with its exact bytes and D. */
export interface Deployment {
  readonly gamma: Uint8Array;
  readonly cfg: Config;
  readonly domain: Uint8Array;
  /** h = log2 K, the gap-proof depth. */
  readonly h: number;
}

export function deployment(gamma: Uint8Array, p: Params): Deployment {
  const cfg = decodeConfig(gamma, p);
  return { gamma: gamma.slice(), cfg, domain: domainOf(gamma), h: log2(cfg.K) };
}

export type { Rule };
export { fail };
