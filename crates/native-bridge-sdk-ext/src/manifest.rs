//! Manifest loading and validation against `protocol/manifest.schema.json` (schema v1: a registry
//! object keyed by `tokenTypeHex`).
//!
//! Structural validity is not authorisation: installation recomputes identifiers, `chainRef`,
//! Cfg/cfg, policy hashes and every pin, and cross-checks the artifacts the application installed.
//! JSON is never a hash preimage. `trustBase.document.sha256` is the exact-file digest of the one
//! pinned SDK `RootTrustBase` document `B` and must equal the installed [`TrustInput`] and every
//! lock proof's `trustBaseId`. `proofEndpoints`/`rpcUrls`/artifact locations are installation
//! metadata for construction and refresh only; verification never reads them.
//!
//! Artifacts pinned by hash (`pdr`, `executionProfile`) are supplied by the installer through an
//! [`Artifacts`] resolver; a missing or mismatching artifact fails installation. The execution
//! profile artifact is, for now, the UTF-8 JSON `{"headerFields":20}` or `{"headerFields":21}`
//! selecting the pinned block-header shape.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;

use crate::deployment::{Deployment, DeploymentRegistry};
use crate::error::{NativeError as E, Result};
use crate::header::HeaderProfile;
use crate::lockproof::config_hash_of_pdr;
use crate::profile::*;
use crate::token::NativeBridge;
use crate::trust::TrustInput;

/// Resolver for artifacts pinned by SHA-256 (the installer's local artifact store).
pub type Artifacts<'a> = &'a dyn Fn(&[u8; 32]) -> Option<Vec<u8>>;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: u64,
    pub protocol_version: u64,
    pub family: String,
    pub sdk_version: String,
    pub token_type_hex: String,
    pub coin_id_hex: String,
    pub symbol: String,
    pub decimals: u64,
    pub plugin: Plugin,
    pub network_id: u64,
    pub root_genesis_hash: String,
    pub execution_genesis_hash: String,
    pub evm_chain_id: String,
    pub chain_ref: String,
    pub asset: String,
    pub active_deployment: DeploymentRecord,
    pub replaced_deployments: Vec<DeploymentRecord>,
    pub trust_base: TrustBasePin,
    #[serde(default)]
    pub proof_endpoints: Vec<String>,
    #[serde(default)]
    pub rpc_urls: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Plugin {
    pub npm: NpmPin,
    pub rust: RustPin,
    pub protocol_commit: String,
    pub vector_manifest_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NpmPin {
    pub name: String,
    pub version: String,
    pub integrity: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustPin {
    #[serde(rename = "crate")]
    pub crate_name: String,
    pub version: String,
    pub revision: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Artifact {
    pub sha256: String,
    #[serde(default)]
    pub location: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustBasePin {
    pub network_id: u64,
    pub root_genesis_hash: String,
    pub format: String,
    pub document: Artifact,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct B1Record {
    pub profile: Artifact,
    pub registry_address: String,
    pub registry_runtime_hash: String,
    pub registry_layout: Artifact,
    pub genesis: Artifact,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyRecord {
    pub body_hex: String,
    pub sha256: String,
    pub partition: u64,
    pub shard_hex: String,
    pub configuration_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BackingRecord {
    pub partition: u64,
    pub shard_hex: String,
    /// The genesis `ConfigHash` of the EVM partition description: every non-membership setting.
    pub configuration_hash: String,
    pub pdr: Artifact,
    pub execution_profile: Artifact,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeploymentRecord {
    pub vault_address: String,
    pub vault_runtime_hash: String,
    pub cfg_hex: String,
    pub cfg_hash: String,
    pub token_verifier_address: String,
    pub token_verifier_runtime_hash: String,
    pub semantic_profile: Artifact,
    pub b1: B1Record,
    pub lock_layout_version: u64,
    pub aggregator_policy: PolicyRecord,
    pub evm_backing_policy: BackingRecord,
}

fn hex_n<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2 || s.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(E::Manifest);
    }
    from_hex(s)
        .and_then(|v| v.try_into().ok())
        .ok_or(E::Manifest)
}

fn hex_vec(s: &str, max: usize) -> Result<Vec<u8>> {
    if s.is_empty() || s.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(E::Manifest);
    }
    let v = from_hex(s).ok_or(E::Manifest)?;
    if v.is_empty() || v.len() > max {
        return Err(E::Manifest);
    }
    Ok(v)
}

/// Canonical uint64 decimal, at least 1, no leading zero.
fn dec_u64(s: &str) -> Result<u64> {
    if s.is_empty() || s.starts_with('0') || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(E::Manifest);
    }
    s.parse().map_err(|_| E::Manifest)
}

fn artifact<'a>(
    a: &Artifact,
    artifacts: Option<Artifacts<'a>>,
) -> Result<([u8; 32], Option<Vec<u8>>)> {
    let pin = hex_n::<32>(&a.sha256)?;
    let bytes = artifacts.and_then(|f| f(&pin));
    if let Some(b) = &bytes {
        if h(b) != pin {
            return Err(E::Manifest);
        }
    }
    Ok((pin, bytes))
}

fn header_profile(bytes: &[u8]) -> Result<HeaderProfile> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| E::Manifest)?;
    let f = v
        .get("headerFields")
        .and_then(|x| x.as_u64())
        .ok_or(E::Manifest)?;
    if v.as_object().map(|o| o.len()) != Some(1) || !matches!(f, 20 | 21) {
        return Err(E::Manifest);
    }
    Ok(HeaderProfile { fields: f as u8 })
}

struct Ctx {
    network: u16,
    root: [u8; 32],
    exec: [u8; 32],
    chain: u64,
    ty: [u8; 32],
    aid: [u8; 32],
}

fn deployment(
    c: &Ctx,
    d: &DeploymentRecord,
    artifacts: Option<Artifacts<'_>>,
) -> Result<Deployment> {
    let cfg_bytes = hex_vec(&d.cfg_hex, 2048)?;
    let cfg = Cfg::from_bytes(&cfg_bytes)?;
    if cfg.to_bytes() != cfg_bytes || cfg.hash() != hex_n::<32>(&d.cfg_hash)? {
        return Err(E::Manifest);
    }
    let pol = &d.aggregator_policy;
    let policy_bytes = hex_vec(&pol.body_hex, MAX_POLICY_BODY)?;
    let policy = Policy::from_bytes(&policy_bytes)?;
    if policy.to_bytes() != policy_bytes
        || policy.hash() != hex_n::<32>(&pol.sha256)?
        || u64::from(policy.partition) != pol.partition
        || pol.shard_hex != "80"
        || policy.shard_conf != hex_n::<32>(&pol.configuration_hash)?
    {
        return Err(E::Manifest);
    }
    let backing = &d.evm_backing_policy;
    let evm_shard = hex_vec(&backing.shard_hex, 33)?;
    // Every Cfg field is recomputed from the manifest's own claims and matched.
    let semantic = hex_n::<32>(&d.semantic_profile.sha256)?;
    let b1_profile = hex_n::<32>(&d.b1.profile.sha256)?;
    let ok = u64::from(cfg.network) == u64::from(c.network)
        && cfg.root_genesis == c.root
        && cfg.execution_genesis == c.exec
        && cfg.chain_id == c.chain
        && cfg.vault == hex_n::<20>(&d.vault_address)?
        && cfg.zero_address == [0u8; 20]
        && cfg.ty == c.ty
        && cfg.aid == c.aid
        && cfg.semantic_profile_hash == semantic
        && cfg.token_verifier_address == hex_n::<20>(&d.token_verifier_address)?
        && cfg.token_verifier_code_hash == hex_n::<32>(&d.token_verifier_runtime_hash)?
        && cfg.b1_profile_hash == b1_profile
        && cfg.aggregator_policy_hash == policy.hash()
        && u64::from(cfg.evm_partition) == backing.partition
        && cfg.evm_shard == evm_shard
        && d.lock_layout_version == 1;
    if !ok || cfg.vault == [0u8; 20] || cfg.token_verifier_address == [0u8; 20] {
        return Err(E::Manifest);
    }
    hex_n::<20>(&d.b1.registry_address)?;
    hex_n::<32>(&d.b1.registry_runtime_hash)?;
    artifact(&d.b1.registry_layout, artifacts)?;
    artifact(&d.b1.genesis, artifacts)?;
    // The installer's artifacts must match their pins; the genesis PDR must yield the pinned
    // configuration hash, and the execution profile selects the block-header shape.
    let config_hash = hex_n::<32>(&backing.configuration_hash)?;
    let (_, pdr) = artifact(&backing.pdr, artifacts)?;
    if let Some(pdr) = pdr {
        if config_hash_of_pdr(&pdr)? != config_hash {
            return Err(E::Manifest);
        }
    }
    let (_, exec) = artifact(&backing.execution_profile, artifacts)?;
    let header = header_profile(&exec.ok_or(E::Manifest)?)?;
    Deployment::new(
        cfg,
        hex_n::<32>(&d.vault_runtime_hash)?,
        config_hash,
        header,
        policy,
    )
}

const MAX_POLICY_BODY: usize = 128;

/// `(networkId, rootGenesisHash, document sha256)` of an entry's trust pin.
pub type TrustPin = (u16, [u8; 32], [u8; 32]);

/// A validated registry and the single trust-document pins it names.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub registry: DeploymentRegistry,
    /// `(networkId, rootGenesisHash, document sha256)` per entry.
    pub trust_pins: Vec<TrustPin>,
}

impl Loaded {
    /// Install: every entry's pinned document must be exactly the installed trust input and name its
    /// network; the bridge then verifies under that one base.
    pub fn install(&self, trust: TrustInput) -> Result<NativeBridge> {
        for (network, _root, doc) in &self.trust_pins {
            if *doc != trust.id() || *network != trust.base().network_id.id() {
                return Err(E::TrustBaseDigest);
            }
        }
        NativeBridge::new(self.registry.clone(), trust)
    }
}

/// Validate one entry (its registry key already matched) and return its deployments, active first.
pub fn validate(
    m: &Manifest,
    artifacts: Option<Artifacts<'_>>,
) -> Result<(Vec<Deployment>, TrustPin)> {
    if m.schema_version != 1
        || m.protocol_version != u64::from(crate::NATIVE_BRIDGE_PROTO_VERSION)
        || m.family != crate::NATIVE_BRIDGE_FAMILY
        || m.sdk_version != crate::SDK_VERSION
        || m.symbol.is_empty()
        || m.symbol.chars().count() > 16
        || m.decimals > 255
    {
        return Err(E::Manifest);
    }
    let network = u16::try_from(m.network_id).map_err(|_| E::Manifest)?;
    let root = hex_n::<32>(&m.root_genesis_hash)?;
    let exec = hex_n::<32>(&m.execution_genesis_hash)?;
    let chain = dec_u64(&m.evm_chain_id)?;
    // Both identifiers are recomputed; the symbol is never identity.
    let ty = derive_type(network, &root, &exec, chain);
    let aid = derive_asset(network, &root, &exec, chain);
    if hex_n::<32>(&m.token_type_hex)? != ty || hex_n::<32>(&m.coin_id_hex)? != aid {
        return Err(E::Manifest);
    }
    if m.chain_ref != alloc::format!("eip155:{chain}") || m.asset != "0".repeat(40) {
        return Err(E::Manifest);
    }
    if m.plugin.npm.name != "@unicitylabs/native-bridge-plugin"
        || m.plugin.npm.version != "0.1.0"
        || m.plugin.rust.crate_name != "native-bridge-sdk-ext"
        || m.plugin.rust.version != "0.1.0"
    {
        return Err(E::Manifest);
    }
    hex_n::<20>(&m.plugin.rust.revision)?;
    hex_n::<20>(&m.plugin.protocol_commit)?;
    hex_n::<32>(&m.plugin.vector_manifest_sha256)?;
    let t = &m.trust_base;
    if t.format != "sdk-root-trust-base-json-v1"
        || t.network_id != m.network_id
        || hex_n::<32>(&t.root_genesis_hash)? != root
    {
        return Err(E::Manifest);
    }
    let doc = hex_n::<32>(&t.document.sha256)?;
    let c = Ctx {
        network,
        root,
        exec,
        chain,
        ty,
        aid,
    };
    let mut out = Vec::new();
    out.push(deployment(&c, &m.active_deployment, artifacts)?);
    for r in &m.replaced_deployments {
        out.push(deployment(&c, r, artifacts)?);
    }
    // Active and replaced vaults are all distinct: no ambiguity within one manifest.
    let mut seen = BTreeSet::new();
    for d in &out {
        if !seen.insert(d.cfg.vault) {
            return Err(E::AmbiguousDeployment);
        }
    }
    Ok((out, (network, root, doc)))
}

/// Parse a manifest registry (an object keyed by `tokenTypeHex`), validate every entry and return
/// the allow-list. A key differing from its entry's `tokenTypeHex`, or any vault claimed twice, is
/// rejected.
pub fn load(json: &str, artifacts: Option<Artifacts<'_>>) -> Result<Loaded> {
    let file: BTreeMap<String, Manifest> = serde_json::from_str(json).map_err(|_| E::Manifest)?;
    if file.is_empty() {
        return Err(E::Manifest);
    }
    let mut all = Vec::new();
    let mut pins = Vec::new();
    for (key, m) in &file {
        if key != &m.token_type_hex {
            return Err(E::Manifest);
        }
        let (deployments, pin) = validate(m, artifacts)?;
        all.extend(deployments);
        pins.push(pin);
    }
    Ok(Loaded {
        registry: DeploymentRegistry::new(all)?,
        trust_pins: pins,
    })
}

/// A deployment record for tests and tooling.
pub fn deployment_record(
    d: &Deployment,
    vault_runtime_hash: &[u8; 32],
    pdr_sha256: &[u8; 32],
    exec_sha256: &[u8; 32],
) -> DeploymentRecordOut {
    DeploymentRecordOut {
        vault_address: hex_lower(&d.cfg.vault),
        vault_runtime_hash: hex_lower(vault_runtime_hash),
        cfg_hex: hex_lower(&d.cfg.to_bytes()),
        cfg_hash: hex_lower(&d.cfg_hash),
        token_verifier_address: hex_lower(&d.cfg.token_verifier_address),
        token_verifier_runtime_hash: hex_lower(&d.cfg.token_verifier_code_hash),
        semantic_profile_sha256: hex_lower(&d.cfg.semantic_profile_hash),
        b1_profile_sha256: hex_lower(&d.cfg.b1_profile_hash),
        policy_body_hex: hex_lower(&d.policy.to_bytes()),
        policy_sha256: hex_lower(&d.policy.hash()),
        policy_partition: d.policy.partition,
        policy_configuration_hash: hex_lower(&d.policy.shard_conf),
        evm_partition: d.cfg.evm_partition,
        evm_shard_hex: hex_lower(&d.cfg.evm_shard),
        evm_configuration_hash: hex_lower(&d.evm_config_hash),
        pdr_sha256: hex_lower(pdr_sha256),
        execution_profile_sha256: hex_lower(exec_sha256),
    }
}

/// Flat view of a deployment's manifest fields (tooling helper).
#[derive(Debug, Clone)]
pub struct DeploymentRecordOut {
    pub vault_address: String,
    pub vault_runtime_hash: String,
    pub cfg_hex: String,
    pub cfg_hash: String,
    pub token_verifier_address: String,
    pub token_verifier_runtime_hash: String,
    pub semantic_profile_sha256: String,
    pub b1_profile_sha256: String,
    pub policy_body_hex: String,
    pub policy_sha256: String,
    pub policy_partition: u32,
    pub policy_configuration_hash: String,
    pub evm_partition: u32,
    pub evm_shard_hex: String,
    pub evm_configuration_hash: String,
    pub pdr_sha256: String,
    pub execution_profile_sha256: String,
}
