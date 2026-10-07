import { eq } from './bytes.js';
import { fail } from './errors.js';
import type { HeaderProfile } from './header.js';
import { cfgBytes, cfgHash, deriveAsset, deriveType, policyHash, type Cfg, type Policy } from './profile.js';

/** One allow-listed deployment: everything the offline verifier needs about one vault. */
export interface Deployment {
  cfg: Cfg;
  cfgHash: Uint8Array;
  /** Immutable vault runtime code hash (the account `codeHash`). */
  vaultCodeHash: Uint8Array;
  /** Genesis `ConfigHash` of the EVM partition description. */
  evmConfigHash: Uint8Array;
  header: HeaderProfile;
  policy: Policy;
}

/** Validate a deployment: identifiers recomputed from the family, policy bound into Cfg. */
export function makeDeployment(cfg: Cfg, vaultCodeHash: Uint8Array, evmConfigHash: Uint8Array, header: HeaderProfile, policy: Policy): Deployment {
  if (!eq(cfg.ty, deriveType(cfg.network, cfg.rootGenesis, cfg.executionGenesis, cfg.chainId)) ||
      !eq(cfg.aid, deriveAsset(cfg.network, cfg.rootGenesis, cfg.executionGenesis, cfg.chainId))) fail('ErrCfgMismatch');
  if (!eq(cfg.aggregatorPolicyHash, policyHash(policy))) fail('ErrPolicyHash');
  if (policy.partition === cfg.evmPartition) fail('ErrPolicyPartition');
  if (cfg.zeroAddress.some((x) => x !== 0) || cfg.vault.every((x) => x === 0) || (header.fields !== 20 && header.fields !== 21)) {
    fail('ErrCfgMismatch');
  }
  return { cfg, cfgHash: cfgHash(cfg), vaultCodeHash, evmConfigHash, header, policy };
}

/** An immutable allow-list keyed by `(network, chainId, vault)`; duplicates fail at registration. */
export class DeploymentRegistry {
  public readonly deployments: readonly Deployment[];

  public constructor(deployments: Deployment[]) {
    deployments.forEach((a, i) => {
      for (const b of deployments.slice(0, i)) {
        if ((a.cfg.network === b.cfg.network && a.cfg.chainId === b.cfg.chainId && eq(a.cfg.vault, b.cfg.vault)) || eq(a.cfgHash, b.cfgHash)) {
          fail('ErrAmbiguousDeployment');
        }
      }
    });
    this.deployments = deployments;
  }

  public index(network: number, chainId: bigint, vault: Uint8Array): number {
    const i = this.deployments.findIndex((d) => d.cfg.network === network && d.cfg.chainId === chainId && eq(d.cfg.vault, vault));
    return i < 0 ? fail('ErrUnknownDeployment') : i;
  }

  public find(network: number, chainId: bigint, vault: Uint8Array): Deployment {
    return this.deployments[this.index(network, chainId, vault)];
  }

  public get tokenTypes(): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (const d of this.deployments) if (!out.some((t) => eq(t, d.cfg.ty))) out.push(d.cfg.ty);
    return out;
  }
}

export { cfgBytes };
