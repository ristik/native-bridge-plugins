//! Γ, D and the asset identity (section 4; `config.ts`, bft-core `nb2ref/config.go`).

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use num_bigint::BigUint;

use super::cbor::*;
use super::crypto::hu;
use super::errors::{Error, Nb2Error, Result, Rule};
use super::util::{max_bits, to_hex};

pub const NATIVE_BRIDGE_PROTO_VERSION: u64 = 9;

/// The CBOR tags of the profile.
pub mod tag {
    pub const PREDICATE: u64 = 39032;
    pub const MINT: u64 = 39041;
    pub const TRANSFER: u64 = 39045;
    pub const CERTIFICATION: u64 = 39031;
    pub const TOKEN: u64 = 39040;
    pub const INCLUSION: u64 = 39033;
    pub const VALUE: u64 = 39050;
    pub const SPLIT_JUSTIFICATION: u64 = 39044;
    pub const SPLIT_MANIFEST: u64 = 39046;
    pub const RECEIPT_BACKING: u64 = 39051;
    pub const SEGMENT_RETURN: u64 = 39052;
}

pub const V2_VERSION: u64 = 1;

/// The domain strings.
pub mod domain {
    pub const CONFIG: &str = "UNICITY_NB2_CFG";
    pub const DEPOSIT_INTENT: &str = "UNICITY_NB2_DEPOSIT_INTENT";
    pub const DEPOSIT_SALT: &str = "UNICITY_NB2_DEPOSIT_SALT";
    pub const BURN: &str = "UNICITY_NB2_BURN";
    pub const REDEMPTION: &str = "UNICITY_NB2_REDEMPTION";
    pub const SPLIT_OUTPUT: &str = "UNICITY_SPLIT_OUTPUT";
}

/// a_UCT = H_U(UTF8("unicity-nb2-asset:native-uct")).
pub fn asset_uct() -> [u8; 32] {
    hu(&[b"unicity-nb2-asset:native-uct"])
}

pub const MAX_DEPOSIT: u64 = (1 << 56) - 1;
pub const MAX_SEGMENT: u64 = (1 << 48) - 1;
pub const MAX_INDEX: u64 = (1 << 32) - 1;
/// The largest K any build admits.
pub const MAX_K: u64 = 64;

/// 2^144 - 1.
pub fn qmax_limit() -> BigUint {
    max_bits(144)
}

/// An admitted (K, B) set: production admits only (64, 16) (#1098); a test build admits K in {4, 8} x B in {2, 4}, never both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    pub k: Vec<u64>,
    pub b: Vec<u64>,
}

/// The build a deployment is judged under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Build {
    Production,
    Test,
}

impl Build {
    pub fn name(self) -> &'static str {
        match self {
            Build::Production => "production",
            Build::Test => "test",
        }
    }

    pub fn from_name(s: &str) -> Option<Build> {
        match s {
            "production" => Some(Build::Production),
            "test" => Some(Build::Test),
            _ => None,
        }
    }
}

pub fn production_params() -> Params {
    Params {
        k: alloc::vec![64],
        b: alloc::vec![16],
    }
}

pub fn test_params() -> Params {
    Params {
        k: alloc::vec![4, 8],
        b: alloc::vec![2, 4],
    }
}

pub fn build_params(b: Build) -> Params {
    match b {
        Build::Test => test_params(),
        Build::Production => production_params(),
    }
}

fn pow2(x: u64) -> bool {
    x > 0 && x & (x - 1) == 0
}

pub fn admits(p: &Params, k: u64, b: u64) -> bool {
    (2..=MAX_K).contains(&k)
        && pow2(k)
        && b >= 2
        && b <= k
        && pow2(b)
        && p.k.contains(&k)
        && p.b.contains(&b)
}

/// log2 of a power of two.
pub fn log2(x: u64) -> u32 {
    63 - x.leading_zeros()
}

/// Γ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub network: u16,
    pub root_genesis: [u8; 32],
    pub execution_genesis: [u8; 32],
    pub chain_id: u64,
    pub evm_partition: u32,
    pub evm_shard: Vec<u8>,
    pub aggregator_partition: u32,
    pub vault: [u8; 20],
    pub asset: [u8; 32],
    pub ty: [u8; 32],
    pub aid: [u8; 32],
    pub semantic_profile_hash: [u8; 32],
    pub verifier: [u8; 20],
    pub verifier_code_hash: [u8; 32],
    pub k: u64,
    pub b: u64,
    pub qmax: BigUint,
}

pub const CONFIG_ARITY: usize = 19;

pub fn encode_config(c: &Config) -> Vec<u8> {
    c_arr_v(&[
        c_bytes(domain::CONFIG.as_bytes()),
        c_uint(V2_VERSION),
        c_uint(c.network as u64),
        c_bytes(&c.root_genesis),
        c_bytes(&c.execution_genesis),
        c_uint(c.chain_id),
        c_uint(c.evm_partition as u64),
        c_bytes(&c.evm_shard),
        c_uint(c.aggregator_partition as u64),
        c_bytes(&c.vault),
        c_bytes(&c.asset),
        c_bytes(&c.ty),
        c_bytes(&c.aid),
        c_bytes(&c.semantic_profile_hash),
        c_bytes(&c.verifier),
        c_bytes(&c.verifier_code_hash),
        c_uint(c.k),
        c_uint(c.b),
        c_amount(&c.qmax),
    ])
}

/// D = H_U(Γ).
pub fn domain_of(gamma: &[u8]) -> [u8; 32] {
    hu(&[gamma])
}

const MAX_CONFIG_BYTES: usize = 1024;

/// A Γ failure naming the first failing field (19: the array itself). The verifier reports it as ConfigShape.
pub fn config_error(field: usize, cause: Rule) -> Error {
    Error::Rule(Nb2Error {
        config_field: Some(field),
        ..Nb2Error::with_detail(
            Rule::ConfigShape,
            format!("field {field}: {}", cause.name()),
        )
    })
}

fn at<T>(field: usize, r: Result<T>) -> Result<T> {
    r.map_err(|e| match e {
        Error::Rule(n) => config_error(field, n.rule),
        other => other,
    })
}

/// A canonical native shard ID: 1..33 bytes, a last byte that is nonzero (the terminator bit), at most 256 prefix bits.
pub fn canonical_shard_id(b: &[u8]) -> bool {
    if b.is_empty() || b.len() > 33 || b[b.len() - 1] == 0 {
        return false;
    }
    let tz = b[b.len() - 1].trailing_zeros() as usize;
    8 * b.len() - tz - 1 <= 256
}

fn a32(b: &[u8]) -> [u8; 32] {
    super::util::arr(b)
}

/// Strictly decode Γ under the admitted set `p` (every section 4.1 check that needs no deployment environment).
pub fn decode_config(b: &[u8], p: &Params) -> Result<Config> {
    if b.len() > MAX_CONFIG_BYTES {
        return Err(config_error(CONFIG_ARITY, Rule::InputTooLarge));
    }
    let root = at(CONFIG_ARITY, scan_one(b))?;
    let k = at(CONFIG_ARITY, array(&root, CONFIG_ARITY))?;
    at(0, literal(&k[0], domain::CONFIG))?;
    at(1, version(&k[1], V2_VERSION))?;
    let network = at(2, uint_in(&k[2], 1, 65535))? as u16;
    let root_genesis = a32(at(3, bytes_n(&k[3], 32))?);
    let execution_genesis = a32(at(4, bytes_n(&k[4], 32))?);
    let chain_id = at(5, uint_in(&k[5], 1, MAX_U64))?;
    let ep = at(6, uint_in(&k[6], 1, (1 << 32) - 1))?;
    let evm_shard = at(7, bstr(&k[7]))?;
    if !canonical_shard_id(evm_shard) {
        return Err(config_error(7, Rule::Length));
    }
    let ap = at(8, uint_in(&k[8], 1, (1 << 32) - 1))?;
    if ap == ep {
        return Err(config_error(8, Rule::IntRange));
    }
    let vault = super::util::arr(at(9, bytes_n(&k[9], 20))?);
    let asset = a32(at(10, bytes_n(&k[10], 32))?);
    let ty = a32(at(11, bytes_n(&k[11], 32))?);
    let aid = a32(at(12, bytes_n(&k[12], 32))?);
    let semantic_profile_hash = a32(at(13, bytes_n(&k[13], 32))?);
    let verifier = super::util::arr(at(14, bytes_n(&k[14], 20))?);
    let verifier_code_hash = a32(at(15, bytes_n(&k[15], 32))?);
    // fields in index order: K's own admitted-set rule (16) before B's range (17)
    let kk = at(16, uint_in(&k[16], 2, MAX_K))?;
    if !(p.k.contains(&kk) && pow2(kk)) {
        return Err(config_error(16, Rule::IntRange));
    }
    let bb = at(17, uint_in(&k[17], 2, MAX_K))?;
    if !admits(p, kk, bb) {
        return Err(config_error(17, Rule::IntRange));
    }
    let qmax = at(18, amount(&k[18]))?;
    if qmax > qmax_limit() {
        return Err(config_error(18, Rule::IntRange));
    }
    Ok(Config {
        network,
        root_genesis,
        execution_genesis,
        chain_id,
        evm_partition: ep as u32,
        evm_shard: evm_shard.to_vec(),
        aggregator_partition: ap as u32,
        vault,
        asset,
        ty,
        aid,
        semantic_profile_hash,
        verifier,
        verifier_code_hash,
        k: kk,
        b: bb,
        qmax,
    })
}

fn identity_string(
    network: u16,
    root_genesis: &[u8],
    execution_genesis: &[u8],
    chain_id: u64,
) -> alloc::string::String {
    format!(
        "{network}:{}:{}:{}",
        to_hex(root_genesis),
        to_hex(execution_genesis),
        chain_id
    )
}

/// ty = H_U(UTF8("unicity-bridge:unicity-native-nb2:" + Dstr)).
pub fn derive_type(
    network: u16,
    root_genesis: &[u8],
    execution_genesis: &[u8],
    chain_id: u64,
) -> [u8; 32] {
    let s = format!(
        "unicity-bridge:unicity-native-nb2:{}",
        identity_string(network, root_genesis, execution_genesis, chain_id)
    );
    hu(&[s.as_bytes()])
}

/// aid = H_U(UTF8("unicity-bridge-coin:unicity-native-nb2:" + Dstr)).
pub fn derive_coin(
    network: u16,
    root_genesis: &[u8],
    execution_genesis: &[u8],
    chain_id: u64,
) -> [u8; 32] {
    let s = format!(
        "unicity-bridge-coin:unicity-native-nb2:{}",
        identity_string(network, root_genesis, execution_genesis, chain_id)
    );
    hu(&[s.as_bytes()])
}

/// What the vault constructor checks Γ against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    pub address: [u8; 20],
    pub chain_id: u64,
    pub verifier_code_hash: [u8; 32],
}

/// BadConfig(field).
pub fn bad_config(field: usize) -> Error {
    Error::Rule(Nb2Error::with_args(
        Rule::BadConfig,
        alloc::vec![field.to_string()],
    ))
}

/// The vault constructor's acceptance of Γ, in the reference's order.
pub fn construct(gamma: &[u8], env: &Environment, p: &Params) -> Result<Config> {
    let c = match decode_config(gamma, p) {
        Ok(c) => c,
        Err(Error::Rule(e)) => return Err(bad_config(e.config_field.unwrap_or(CONFIG_ARITY))),
        Err(e) => return Err(e),
    };
    if c.asset != asset_uct() {
        return Err(bad_config(10));
    }
    if c.ty != derive_type(c.network, &c.root_genesis, &c.execution_genesis, c.chain_id) {
        return Err(bad_config(11));
    }
    if c.aid != derive_coin(c.network, &c.root_genesis, &c.execution_genesis, c.chain_id) {
        return Err(bad_config(12));
    }
    if c.vault != env.address {
        return Err(bad_config(9));
    }
    if c.chain_id != env.chain_id {
        return Err(bad_config(5));
    }
    if c.verifier_code_hash != env.verifier_code_hash {
        return Err(bad_config(15));
    }
    Ok(c)
}

/// A decoded Γ with its exact bytes and D.
#[derive(Debug, Clone)]
pub struct Deployment {
    pub gamma: Vec<u8>,
    pub cfg: Config,
    pub domain: [u8; 32],
    /// h = log2 K, the gap-proof depth.
    pub h: u32,
}

pub fn deployment(gamma: &[u8], p: &Params) -> Result<Deployment> {
    let cfg = decode_config(gamma, p)?;
    Ok(Deployment {
        gamma: gamma.to_vec(),
        h: log2(cfg.k),
        cfg,
        domain: domain_of(gamma),
    })
}
