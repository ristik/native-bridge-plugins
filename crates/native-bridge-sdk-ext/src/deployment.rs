//! A pinned deployment record: everything the offline verifier needs about one vault, frozen at
//! installation. A token can never select its own policy.

use alloc::vec::Vec;

use crate::error::{NativeError as E, Result};
use crate::header::HeaderProfile;
use crate::profile::{derive_asset, derive_type, Cfg, Policy};

/// One allow-listed deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    pub cfg: Cfg,
    /// `H(Cfg)`, recomputed at construction.
    pub cfg_hash: [u8; 32],
    /// Immutable vault runtime code hash (the account `codeHash`).
    pub vault_code_hash: [u8; 32],
    /// Genesis `ConfigHash` of the EVM partition description (all non-membership settings).
    pub evm_config_hash: [u8; 32],
    pub header: HeaderProfile,
    /// The sole admitted one-shard aggregator policy.
    pub policy: Policy,
}

impl Deployment {
    /// Validate a deployment: identifiers recomputed from the bridge identity family, the policy
    /// hash bound into Cfg, and the aggregator partition distinct from the EVM partition.
    pub fn new(
        cfg: Cfg,
        vault_code_hash: [u8; 32],
        evm_config_hash: [u8; 32],
        header: HeaderProfile,
        policy: Policy,
    ) -> Result<Self> {
        let ty = derive_type(
            cfg.network,
            &cfg.root_genesis,
            &cfg.execution_genesis,
            cfg.chain_id,
        );
        let aid = derive_asset(
            cfg.network,
            &cfg.root_genesis,
            &cfg.execution_genesis,
            cfg.chain_id,
        );
        if cfg.ty != ty || cfg.aid != aid {
            return Err(E::CfgMismatch);
        }
        if cfg.aggregator_policy_hash != policy.hash() {
            return Err(E::PolicyHash);
        }
        if policy.partition == cfg.evm_partition {
            return Err(E::PolicyPartition);
        }
        if cfg.zero_address != [0u8; 20]
            || cfg.vault == [0u8; 20]
            || !matches!(header.fields, 20 | 21)
        {
            return Err(E::CfgMismatch);
        }
        let cfg_hash = cfg.hash();
        Ok(Deployment {
            cfg,
            cfg_hash,
            vault_code_hash,
            evm_config_hash,
            header,
            policy,
        })
    }
}

/// An immutable allow-list of deployments keyed by `(network, chainId, vault)`.
///
/// Duplicate or ambiguous entries fail at registration: the same key twice, or two deployments
/// sharing a token type, a Cfg hash or an asset id under different keys.
#[derive(Debug, Clone, Default)]
pub struct DeploymentRegistry {
    deployments: Vec<Deployment>,
}

impl DeploymentRegistry {
    pub fn new(deployments: Vec<Deployment>) -> Result<Self> {
        for (i, a) in deployments.iter().enumerate() {
            for b in &deployments[..i] {
                let same_key = a.cfg.network == b.cfg.network
                    && a.cfg.chain_id == b.cfg.chain_id
                    && a.cfg.vault == b.cfg.vault;
                if same_key || a.cfg_hash == b.cfg_hash {
                    return Err(E::AmbiguousDeployment);
                }
            }
        }
        Ok(DeploymentRegistry { deployments })
    }

    pub fn deployments(&self) -> &[Deployment] {
        &self.deployments
    }

    /// Resolve by the claimed `(network, chainId, vault)`.
    pub fn find(&self, network: u16, chain_id: u64, vault: &[u8; 20]) -> Result<&Deployment> {
        self.deployments
            .iter()
            .find(|d| {
                d.cfg.network == network && d.cfg.chain_id == chain_id && &d.cfg.vault == vault
            })
            .ok_or(E::UnknownDeployment)
    }

    /// The deployments whose derived token type equals `ty` (replacement vaults share a type).
    pub fn by_token_type(&self, ty: &[u8]) -> impl Iterator<Item = &Deployment> {
        let ty = ty.to_vec();
        self.deployments
            .iter()
            .filter(move |d| d.cfg.ty.as_slice() == ty.as_slice())
    }
}
