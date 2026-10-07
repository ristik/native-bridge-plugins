/**
 * Manifest loading and validation against `protocol/manifest.schema.json` (schema v1: a registry
 * object keyed by `tokenTypeHex`).
 *
 * Structural validity is not authorisation: installation recomputes identifiers, `chainRef`,
 * Cfg/cfg, policy hashes and every pin, and cross-checks the artifacts the application installed.
 * JSON is never a hash preimage. `trustBase.document.sha256` is the exact-file digest of the one
 * pinned SDK `RootTrustBase` document `B`; it must equal the installed trust input and every lock
 * proof's `trustBaseId`. `proofEndpoints`, `rpcUrls` and artifact locations are installation
 * metadata for construction and refresh; verification never reads them.
 *
 * Artifacts pinned by hash (`pdr`, `executionProfile`) are supplied by the installer through an
 * {@link Artifacts} resolver; a missing or mismatching one fails installation. The execution
 * profile artifact is, for now, the UTF-8 JSON `{"headerFields":20}` or `{"headerFields":21}`.
 */
import { eq, fromHex, toHex } from './bytes.js';
import { DeploymentRegistry, makeDeployment, type Deployment } from './deployment.js';
import { fail } from './errors.js';
import type { HeaderProfile } from './header.js';
import { NATIVE_BRIDGE_FAMILY, NATIVE_BRIDGE_PROTO_VERSION, SDK_VERSION } from './limits.js';
import { configHashOfPdr } from './lockproof.js';
import { H, cfgBytes, cfgHash, decodeCfg, decodePolicy, deriveAsset, deriveType, policyBytes, policyHash } from './profile.js';
import { NativeBridge } from './verifier.js';
import type { TrustInput } from './trust.js';

/** Resolver for artifacts pinned by SHA-256 (the installer's local artifact store). */
export type Artifacts = (sha256Hex: string) => Uint8Array | undefined;

type Json = Record<string, unknown>;

const obj = (v: unknown, keys: readonly string[], optional: readonly string[] = []): Json => {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return fail('ErrManifest');
  const o = v as Json;
  if (Object.keys(o).some((k) => !keys.includes(k)) || keys.some((k) => !optional.includes(k) && !(k in o))) return fail('ErrManifest');
  return o;
};

const str = (v: unknown): string => (typeof v === 'string' ? v : fail('ErrManifest'));
const int = (v: unknown, max: number): number => (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max ? v : fail('ErrManifest'));

function hexN(v: unknown, n: number): Uint8Array {
  const s = str(v);
  if (s.length !== n * 2 || /[A-F]/.test(s)) return fail('ErrManifest');
  return fromHex(s) ?? fail('ErrManifest');
}

function hexVec(v: unknown, max: number): Uint8Array {
  const s = str(v);
  if (s.length === 0 || /[A-F]/.test(s)) return fail('ErrManifest');
  const b = fromHex(s) ?? fail('ErrManifest');
  return b.length > 0 && b.length <= max ? b : fail('ErrManifest');
}

/** Canonical uint64 decimal, at least 1, no leading zero. */
function decU64(v: unknown): bigint {
  const s = str(v);
  if (!/^[1-9][0-9]{0,19}$/.test(s)) return fail('ErrManifest');
  const n = BigInt(s);
  return n < 2n ** 64n ? n : fail('ErrManifest');
}

const ARTIFACT = ['sha256', 'location'] as const;

function artifact(v: unknown, artifacts?: Artifacts): { pin: Uint8Array; bytes: Uint8Array | undefined } {
  const a = obj(v, ARTIFACT, ['location']);
  const pin = hexN(a.sha256, 32);
  const bytes = artifacts?.(toHex(pin));
  if (bytes && !eq(H(bytes), pin)) fail('ErrManifest');
  return { pin, bytes };
}

function headerProfile(bytes: Uint8Array): HeaderProfile {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return fail('ErrManifest');
  }
  const o = obj(v, ['headerFields']);
  const f = o.headerFields;
  return f === 20 || f === 21 ? { fields: f } : fail('ErrManifest');
}

interface Ctx {
  network: number;
  root: Uint8Array;
  exec: Uint8Array;
  chain: bigint;
  ty: Uint8Array;
  aid: Uint8Array;
}

const DEPLOYMENT = ['vaultAddress', 'vaultRuntimeHash', 'cfgHex', 'cfgHash', 'tokenVerifierAddress', 'tokenVerifierRuntimeHash', 'semanticProfile', 'b1', 'lockLayoutVersion', 'aggregatorPolicy', 'evmBackingPolicy'] as const;

function deployment(c: Ctx, d: unknown, artifacts?: Artifacts): Deployment {
  const r = obj(d, DEPLOYMENT);
  const cfgRaw = hexVec(r.cfgHex, 2048);
  const cfg = decodeCfg(cfgRaw);
  if (!eq(cfgBytes(cfg), cfgRaw) || !eq(cfgHash(cfg), hexN(r.cfgHash, 32))) fail('ErrManifest');
  const pol = obj(r.aggregatorPolicy, ['bodyHex', 'sha256', 'partition', 'shardHex', 'configurationHash']);
  const polRaw = hexVec(pol.bodyHex, 128);
  const policy = decodePolicy(polRaw);
  if (!eq(policyBytes(policy), polRaw) || !eq(policyHash(policy), hexN(pol.sha256, 32)) || policy.partition !== int(pol.partition, 0xffffffff) || pol.shardHex !== '80' || !eq(policy.shardConf, hexN(pol.configurationHash, 32))) {
    fail('ErrManifest');
  }
  const backing = obj(r.evmBackingPolicy, ['partition', 'shardHex', 'configurationHash', 'pdr', 'executionProfile']);
  const evmShard = hexVec(backing.shardHex, 33);
  const semantic = artifact(r.semanticProfile, artifacts).pin;
  const b1 = obj(r.b1, ['profile', 'registryAddress', 'registryRuntimeHash', 'registryLayout', 'genesis']);
  const b1Profile = artifact(b1.profile, artifacts).pin;
  hexN(b1.registryAddress, 20);
  hexN(b1.registryRuntimeHash, 32);
  artifact(b1.registryLayout, artifacts);
  artifact(b1.genesis, artifacts);
  const ok =
    cfg.network === c.network && eq(cfg.rootGenesis, c.root) && eq(cfg.executionGenesis, c.exec) && cfg.chainId === c.chain &&
    eq(cfg.vault, hexN(r.vaultAddress, 20)) && cfg.zeroAddress.every((x) => x === 0) && eq(cfg.ty, c.ty) && eq(cfg.aid, c.aid) &&
    eq(cfg.semanticProfileHash, semantic) && eq(cfg.tokenVerifierAddress, hexN(r.tokenVerifierAddress, 20)) &&
    eq(cfg.tokenVerifierCodeHash, hexN(r.tokenVerifierRuntimeHash, 32)) && eq(cfg.b1ProfileHash, b1Profile) &&
    eq(cfg.aggregatorPolicyHash, policyHash(policy)) && cfg.evmPartition === int(backing.partition, 0xffffffff) && eq(cfg.evmShard, evmShard) &&
    r.lockLayoutVersion === 1;
  if (!ok || cfg.vault.every((x) => x === 0) || cfg.tokenVerifierAddress.every((x) => x === 0)) fail('ErrManifest');
  // The genesis PDR must yield the pinned configuration hash; the execution profile selects the
  // block-header shape.
  const configuration = hexN(backing.configurationHash, 32);
  const pdr = artifact(backing.pdr, artifacts);
  if (pdr.bytes && !eq(configHashOfPdr(pdr.bytes), configuration)) fail('ErrManifest');
  const exec = artifact(backing.executionProfile, artifacts);
  if (!exec.bytes) fail('ErrManifest');
  return makeDeployment(cfg, hexN(r.vaultRuntimeHash, 32), configuration, headerProfile(exec.bytes as Uint8Array), policy);
}

const ENTRY = ['schemaVersion', 'protocolVersion', 'family', 'sdkVersion', 'tokenTypeHex', 'coinIdHex', 'symbol', 'decimals', 'plugin', 'networkId', 'rootGenesisHash', 'executionGenesisHash', 'evmChainId', 'chainRef', 'asset', 'activeDeployment', 'replacedDeployments', 'trustBase', 'proofEndpoints', 'rpcUrls'] as const;

export interface TrustPin {
  network: number;
  rootGenesis: Uint8Array;
  documentSha256: Uint8Array;
}

/** Validate one entry (its registry key already matched) and return its deployments, active first. */
export function validateManifest(raw: unknown, artifacts?: Artifacts): { deployments: Deployment[]; pin: TrustPin } {
  const m = obj(raw, ENTRY, ['proofEndpoints', 'rpcUrls']);
  if (m.schemaVersion !== 1 || m.protocolVersion !== NATIVE_BRIDGE_PROTO_VERSION || m.family !== NATIVE_BRIDGE_FAMILY || m.sdkVersion !== SDK_VERSION) fail('ErrManifest');
  const symbol = str(m.symbol);
  if (symbol.length < 1 || [...symbol].length > 16) fail('ErrManifest');
  int(m.decimals, 255);
  const plugin = obj(m.plugin, ['npm', 'rust', 'protocolCommit', 'vectorManifestSha256']);
  const npm = obj(plugin.npm, ['name', 'version', 'integrity']);
  const rust = obj(plugin.rust, ['crate', 'version', 'revision']);
  if (npm.name !== '@unicitylabs/native-bridge-plugin' || npm.version !== '0.1.0' || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(str(npm.integrity))) fail('ErrManifest');
  if (rust.crate !== 'native-bridge-sdk-ext' || rust.version !== '0.1.0') fail('ErrManifest');
  hexN(rust.revision, 20);
  hexN(plugin.protocolCommit, 20);
  hexN(plugin.vectorManifestSha256, 32);
  const network = int(m.networkId, 0xffff);
  const root = hexN(m.rootGenesisHash, 32);
  const exec = hexN(m.executionGenesisHash, 32);
  const chain = decU64(m.evmChainId);
  // Both identifiers are recomputed; the symbol is never identity.
  const ty = deriveType(network, root, exec, chain);
  const aid = deriveAsset(network, root, exec, chain);
  if (!eq(hexN(m.tokenTypeHex, 32), ty) || !eq(hexN(m.coinIdHex, 32), aid)) fail('ErrManifest');
  if (m.chainRef !== `eip155:${chain}` || m.asset !== '0'.repeat(40)) fail('ErrManifest');
  for (const k of ['proofEndpoints', 'rpcUrls'] as const) if (k in m && !Array.isArray(m[k])) fail('ErrManifest');
  const t = obj(m.trustBase, ['networkId', 'rootGenesisHash', 'format', 'document']);
  if (t.format !== 'sdk-root-trust-base-json-v1' || t.networkId !== network || !eq(hexN(t.rootGenesisHash, 32), root)) fail('ErrManifest');
  const doc = obj(t.document, ARTIFACT, ['location']);
  const pin: TrustPin = { network, rootGenesis: root, documentSha256: hexN(doc.sha256, 32) };
  const c: Ctx = { network, root, exec, chain, ty, aid };
  if (!Array.isArray(m.replacedDeployments)) fail('ErrManifest');
  const deployments = [deployment(c, m.activeDeployment, artifacts), ...(m.replacedDeployments as unknown[]).map((r) => deployment(c, r, artifacts))];
  const seen = new Set<string>();
  for (const d of deployments) {
    const k = toHex(d.cfg.vault);
    if (seen.has(k)) fail('ErrAmbiguousDeployment');
    seen.add(k);
  }
  return { deployments, pin };
}

/** A validated registry and the single trust-document pins it names. */
export class Loaded {
  public constructor(
    public readonly registry: DeploymentRegistry,
    public readonly trustPins: readonly TrustPin[],
  ) {}

  /** Install: every entry's pinned document must be exactly the installed trust input. */
  public install(trust: TrustInput): NativeBridge {
    for (const p of this.trustPins) {
      if (!eq(p.documentSha256, trust.id) || p.network !== trust.base.networkId.id) fail('ErrTrustBaseDigest');
    }
    return new NativeBridge(this.registry, trust);
  }
}

/**
 * Parse a manifest registry (an object keyed by `tokenTypeHex`), validate every entry and return
 * the allow-list. A key differing from its entry's `tokenTypeHex`, or any vault claimed twice, is
 * rejected.
 */
export function loadManifests(json: string, artifacts?: Artifacts): Loaded {
  let file: unknown;
  try {
    file = JSON.parse(json);
  } catch {
    return fail('ErrManifest');
  }
  if (typeof file !== 'object' || file === null || Array.isArray(file) || Object.keys(file).length === 0) return fail('ErrManifest');
  const all: Deployment[] = [];
  const pins: TrustPin[] = [];
  for (const [key, entry] of Object.entries(file as Json)) {
    if (key !== (entry as Json | null)?.tokenTypeHex) fail('ErrManifest');
    const v = validateManifest(entry, artifacts);
    all.push(...v.deployments);
    pins.push(v.pin);
  }
  return new Loaded(new DeploymentRegistry(all), pins);
}

/** The pinned `trustBaseId` (document digest) of one manifest entry. */
export function manifestTrustBaseId(raw: unknown): Uint8Array {
  const m = obj(raw, ENTRY, ['proofEndpoints', 'rpcUrls']);
  return hexN(obj(obj(m.trustBase, ['networkId', 'rootGenesisHash', 'format', 'document']).document, ARTIFACT, ['location']).sha256, 32);
}
