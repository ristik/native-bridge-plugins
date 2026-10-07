//! Independent constructors: a complete synthetic native world built only from public SDK types and
//! this crate's pinned-input types. Nothing here calls the verifier's own helpers to *produce*
//! expected bytes except where the profile defines the derivation (identifiers, digests).

use native_bridge_sdk_ext::deployment::{Deployment, DeploymentRegistry};
use native_bridge_sdk_ext::header::HeaderProfile;
use native_bridge_sdk_ext::lockproof::encode_justification;
use native_bridge_sdk_ext::profile::*;
use native_bridge_sdk_ext::rlp;
use native_bridge_sdk_ext::token::NativeBridge;
use native_bridge_sdk_ext::trust::TrustInput;
use unicity_token::api::bft::{
    InputRecord, ShardId, ShardTreeCertificate, UnicityCertificate, UnicitySeal,
    UnicityTreeCertificate,
};
use unicity_token::api::bft::{RootTrustBase, RootTrustBaseNodeInfo};
use unicity_token::api::{
    CertificationData, InclusionCertificate, InclusionProof, NetworkId, StateId,
};
use unicity_token::cbor::{
    encode_array, encode_byte_string, encode_null, encode_tag, encode_text_string, encode_uint,
};
use unicity_token::crypto::hash::{DataHash, HashAlgorithm};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};
use unicity_token::predicate::builtin::{BurnPredicate, SignaturePredicate};
use unicity_token::predicate::unlock::sign_signature_unlock;
use unicity_token::predicate::EncodedPredicate;
use unicity_token::transaction::{
    CertifiedMintTransaction, CertifiedTransferTransaction, MintTransaction, Token, TokenId,
    TokenSalt, TokenType, Transaction, TransferTransaction,
};

pub const NETWORK: u16 = 3;
pub const CHAIN_ID: u64 = 7777;
pub const EVM_PARTITION: u32 = 7;
pub const AGG_PARTITION: u32 = 1;
pub const VAULT: [u8; 20] = [0xaa; 20];
pub const ROOT_GENESIS: [u8; 32] = [0x11; 32];
pub const EXEC_GENESIS: [u8; 32] = [0x22; 32];

pub fn sha(b: &[u8]) -> [u8; 32] {
    h(b)
}

pub fn dh(b: [u8; 32]) -> DataHash {
    DataHash::new(HashAlgorithm::Sha256, b).unwrap()
}

pub fn signer(seed: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_bytes(&sha(&[b's', seed])).unwrap()
}

// ---- Ethereum MPT builder -----------------------------------------------------------------------

fn nibs(k: &[u8]) -> Vec<u8> {
    k.iter().flat_map(|b| [b >> 4, b & 15]).collect()
}

fn hex_prefix(n: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 2 } else { 0 } | (n.len() & 1) as u8;
    let mut out = Vec::new();
    let mut it = n.iter();
    if n.len() % 2 == 1 {
        out.push(flag << 4 | it.next().unwrap());
    } else {
        out.push(flag << 4);
    }
    while let (Some(a), Some(b)) = (it.next(), it.next()) {
        out.push(a << 4 | b);
    }
    out
}

fn child_item(node: &[u8]) -> Vec<u8> {
    if node.len() < 32 {
        node.to_vec()
    } else {
        rlp::encode_bytes(&keccak(&[node]))
    }
}

/// Build a trie over `(key, value-bytes)` and return the root node and the root-first proof for `target`.
fn build(
    entries: &[(Vec<u8>, Vec<u8>)],
    depth: usize,
    target: &[u8],
    proof: &mut Vec<Vec<u8>>,
) -> Vec<u8> {
    let on_path = |e: &[(Vec<u8>, Vec<u8>)]| e.iter().any(|x| x.0 == target);
    let node = if entries.len() == 1 {
        rlp::encode_list(&[
            &rlp::encode_bytes(&hex_prefix(&entries[0].0[depth..], true)),
            &rlp::encode_bytes(&entries[0].1),
        ])
    } else {
        let first = &entries[0].0;
        let mut cp = 0;
        while entries
            .iter()
            .all(|e| e.0.len() > depth + cp && e.0[depth + cp] == first[depth + cp])
        {
            cp += 1;
        }
        if cp > 0 {
            let child = build(entries, depth + cp, target, proof);
            rlp::encode_list(&[
                &rlp::encode_bytes(&hex_prefix(&first[depth..depth + cp], false)),
                &child_item(&child),
            ])
        } else {
            let mut items: Vec<Vec<u8>> = Vec::new();
            for n in 0..16u8 {
                let group: Vec<_> = entries
                    .iter()
                    .filter(|e| e.0[depth] == n)
                    .cloned()
                    .collect();
                if group.is_empty() {
                    items.push(rlp::encode_bytes(&[]));
                } else {
                    let c = build(&group, depth + 1, target, proof);
                    items.push(child_item(&c));
                }
            }
            items.push(rlp::encode_bytes(&[]));
            let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
            rlp::encode_list(&refs)
        }
    };
    if on_path(entries) && node.len() >= 32 {
        proof.push(node.clone());
    }
    node
}

/// `(root, root-first proof of key)` of a trie of 32-byte keys.
pub fn trie(entries: &[([u8; 32], Vec<u8>)], target: &[u8; 32]) -> ([u8; 32], Vec<Vec<u8>>) {
    let mut e: Vec<(Vec<u8>, Vec<u8>)> =
        entries.iter().map(|(k, v)| (nibs(k), v.clone())).collect();
    e.sort();
    let mut proof = Vec::new();
    let root = build(&e, 0, &nibs(target), &mut proof);
    proof.reverse();
    (keccak(&[&root]), proof)
}

// ---- EVM backing --------------------------------------------------------------------------------

pub struct EvmSpec {
    pub vault_code_hash: [u8; 32],
    /// Overrides the stored lock digest (None = the correct one).
    pub stored: Option<[u8; 32]>,
    pub nonce: u64,
    pub block_number: u64,
}

pub fn pdr_bytes(epoch: u64, setting: u64) -> Vec<u8> {
    // [version, network, partition, shard, typeId, partitionType(null), typeIdLen, unitIdLen,
    //  summaryTrustBase, t2, feeCreditBill(null), partitionParams, epoch, epochStart, validators]
    let params = {
        let mut m = vec![0xa1];
        m.extend(encode_text_string("chainId"));
        m.extend(encode_text_string("7777"));
        m
    };
    encode_tag(
        39008,
        &encode_array(&[
            &encode_uint(1),
            &encode_uint(NETWORK as u64),
            &encode_uint(EVM_PARTITION as u64),
            &encode_byte_string(&[0x80]),
            &encode_uint(1),
            &encode_null(),
            &encode_uint(0),
            &encode_uint(256),
            &encode_byte_string(&[]),
            &encode_uint(2_500_000_000 + setting),
            &encode_null(),
            &params,
            &encode_uint(epoch),
            &encode_uint(0),
            &encode_array(&[&encode_array(&[
                &encode_text_string("evm-1"),
                &encode_byte_string(signer(99).public_key().as_bytes()),
                &encode_uint(1),
            ])]),
        ]),
    )
}

/// The genesis ConfigHash of [`pdr_bytes`]: neutralised validators, epoch and activation round.
pub fn pdr_config_hash() -> [u8; 32] {
    let raw = pdr_bytes(5, 0);
    let elems = native_bridge_sdk_ext::scan::pdr_elements(&raw).unwrap();
    let mut parts: Vec<Vec<u8>> = elems[..12].iter().map(|e| e.to_vec()).collect();
    parts.push(encode_uint(0));
    parts.push(encode_uint(0));
    parts.push(encode_null());
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    sha(&encode_tag(39008, &encode_array(&refs)))
}

pub fn header_rlp(state_root: &[u8; 32], number: u64, fields: usize) -> Vec<u8> {
    use native_bridge_sdk_ext::header::{EMPTY_TRIE_ROOT, EMPTY_UNCLE_HASH};
    let b32 = |x: &[u8]| rlp::encode_bytes(x);
    let mut items: Vec<Vec<u8>> = vec![
        b32(&[0x33; 32]),
        b32(&EMPTY_UNCLE_HASH),
        b32(&[0x44; 20]),
        b32(state_root),
        b32(&[0x55; 32]),
        b32(&[0x66; 32]),
        b32(&[0u8; 256]),
        rlp::encode_u64(0),
        rlp::encode_u64(number),
        rlp::encode_u64(30_000_000),
        rlp::encode_u64(21_000),
        rlp::encode_u64(1_700_000_000),
        b32(b"native"),
        b32(&[0x77; 32]),
        b32(&[0u8; 8]),
        rlp::encode_u64(7),
        b32(&EMPTY_TRIE_ROOT),
        rlp::encode_u64(0),
        rlp::encode_u64(0),
        b32(&[0x88; 32]),
    ];
    if fields == 21 {
        items.push(b32(&[0x99; 32]));
    }
    let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    rlp::encode_list(&refs)
}

// ---- unicity certificates -----------------------------------------------------------------------

pub struct Root {
    pub signers: Vec<(String, Secp256k1Signer)>,
    pub tb: RootTrustBase,
}

/// The pinned document B: the SDK JSON representation in the SDK's emitted field order.
pub fn trust_doc(r: &Root) -> Vec<u8> {
    let nodes: Vec<String> =
        r.tb.root_nodes
            .iter()
            .map(|n| {
                format!(
                    "{{\"nodeId\":\"{}\",\"sigKey\":\"{}\",\"stake\":\"{}\"}}",
                    n.node_id,
                    hex_lower(n.signing_key.as_bytes()),
                    n.stake
                )
            })
            .collect();
    format!(
        "{{\"changeRecordHash\":null,\"epoch\":\"{}\",\"epochStartRound\":\"{}\",\"networkId\":{},\"previousEntryHash\":null,\"quorumThreshold\":\"{}\",\"rootNodes\":[{}],\"signatures\":{{}},\"stateHash\":\"\",\"version\":\"1\"}}",
        r.tb.epoch,
        r.tb.epoch_start_round,
        r.tb.network_id.id(),
        r.tb.quorum_threshold,
        nodes.join(",")
    )
    .into_bytes()
}

pub fn trust_input(r: &Root) -> TrustInput {
    let doc = trust_doc(r);
    TrustInput::from_json(&doc, &sha(&doc)).unwrap()
}

/// A unit-weight SDK trust base (the only model the SDK expresses today).
pub fn make_root(epoch: u64, n: usize, seed: u8) -> Root {
    let mut signers: Vec<(String, Secp256k1Signer)> = (0..n)
        .map(|i| {
            (
                format!("root-{seed}-{i:02}"),
                signer(seed.wrapping_add(i as u8)),
            )
        })
        .collect();
    signers.sort_by(|a, b| a.0.cmp(&b.0));
    let nodes = signers
        .iter()
        .map(|(id, s)| RootTrustBaseNodeInfo {
            node_id: id.clone(),
            signing_key: s.public_key(),
            stake: 1,
        })
        .collect();
    let tb = RootTrustBase::try_new(
        1,
        NetworkId::new(NETWORK).unwrap(),
        epoch,
        1,
        nodes,
        (n as u64) * 2 / 3 + 1,
    )
    .unwrap();
    Root { signers, tb }
}

pub struct UcSpec {
    pub partition: u32,
    pub conf: Vec<u8>,
    pub epoch_ir: u64,
    pub root_epoch: u64,
    pub round: u64,
    pub timestamp: u64,
    pub state_hash: Vec<u8>,
    pub block_hash: Option<Vec<u8>>,
    /// How many of the root signers sign (in id order).
    pub signers: usize,
}

pub fn make_uc(root: &Root, s: &UcSpec) -> UnicityCertificate {
    let ir = InputRecord {
        round_number: s.round,
        epoch: s.epoch_ir,
        previous_hash: None,
        hash: s.state_hash.clone(),
        summary_value: vec![],
        timestamp: s.timestamp,
        block_hash: s.block_hash.clone(),
        sum_of_earned_fees: 0,
        executed_transactions_hash: None,
    };
    let mut uc = UnicityCertificate {
        input_record: ir,
        technical_record_hash: None,
        shard_configuration_hash: s.conf.clone(),
        shard_tree_certificate: ShardTreeCertificate {
            shard: ShardId::decode(&[0x80]).unwrap(),
            sibling_hash_list: vec![],
        },
        unicity_tree_certificate: UnicityTreeCertificate {
            partition_identifier: s.partition,
            steps: vec![],
        },
        unicity_seal: UnicitySeal {
            network_id: NetworkId::new(NETWORK).unwrap(),
            root_chain_round_number: s.round,
            epoch: s.root_epoch,
            timestamp: s.timestamp,
            previous_hash: None,
            hash: vec![],
            signatures: vec![],
        },
    };
    uc.unicity_seal.hash = uc.computed_seal_hash().unwrap().data().to_vec();
    let digest = uc.unicity_seal.calculate_hash();
    uc.unicity_seal.signatures = root
        .signers
        .iter()
        .take(s.signers)
        .map(|(id, sg)| (id.clone(), sg.sign(&digest).encode().to_vec()))
        .collect();
    uc
}

// ---- aggregator radix tree ----------------------------------------------------------------------

fn bit(k: &[u8; 32], i: usize) -> bool {
    k[i / 8] & (0x80 >> (i % 8)) != 0
}

fn region(k: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[..depth / 8].copy_from_slice(&k[..depth / 8]);
    if depth % 8 != 0 {
        r[depth / 8] = k[depth / 8] & (0xffu8 << (8 - depth % 8));
    }
    r
}

fn tree_hash(leaves: &[([u8; 32], [u8; 32])]) -> ([u8; 32], Option<usize>) {
    if leaves.len() == 1 {
        let mut m = vec![0u8];
        m.extend(leaves[0].0);
        m.extend(leaves[0].1);
        return (sha(&m), None);
    }
    let mut d = 0;
    while leaves.iter().all(|l| bit(&l.0, d) == bit(&leaves[0].0, d)) {
        d += 1;
    }
    let (l, r): (Vec<_>, Vec<_>) = leaves.iter().cloned().partition(|x| !bit(&x.0, d));
    let (lh, _) = tree_hash(&l);
    let (rh, _) = tree_hash(&r);
    let mut m = vec![1u8, d as u8];
    m.extend(region(&leaves[0].0, d));
    m.extend(lh);
    m.extend(rh);
    (sha(&m), Some(d))
}

/// `(root, encoded inclusion certificate of key)`; siblings ordered root-first.
pub fn tree(leaves: &[([u8; 32], [u8; 32])], key: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let (root, _) = tree_hash(leaves);
    let mut bitmap = [0u8; 32];
    let mut sibs: Vec<[u8; 32]> = Vec::new();
    let mut cur: Vec<_> = leaves.to_vec();
    while cur.len() > 1 {
        let (_, d) = tree_hash(&cur);
        let d = d.unwrap();
        bitmap[d / 8] |= 0x80 >> (d % 8);
        let (l, r): (Vec<_>, Vec<_>) = cur.iter().cloned().partition(|x| !bit(&x.0, d));
        let (mine, other) = if bit(key, d) { (r, l) } else { (l, r) };
        sibs.push(tree_hash(&other).0);
        cur = mine;
    }
    let mut out = bitmap.to_vec();
    for s in sibs {
        out.extend(s);
    }
    (root, out)
}

// ---- the world ----------------------------------------------------------------------------------

pub struct World {
    pub agg: Root,
    pub evm_root: Root,
    pub dep: Deployment,
    pub bridge: NativeBridge,
    pub policy: Policy,
    pub agg_conf: [u8; 32],
}

pub fn identity() -> (u16, [u8; 32], [u8; 32], u64) {
    (NETWORK, ROOT_GENESIS, EXEC_GENESIS, CHAIN_ID)
}

pub fn make_world(header_fields: u8) -> World {
    // One root-chain epoch authenticates both the EVM and the aggregator partitions.
    let agg = make_root(2, 4, 10);
    let evm_root = make_root(2, 4, 10);
    let agg_conf = sha(b"aggregator shard configuration");
    let policy = Policy {
        partition: AGG_PARTITION,
        shard_conf: agg_conf,
    };
    let (n, rg, eg, c) = identity();
    let cfg = Cfg {
        network: n,
        root_genesis: rg,
        chain_id: c,
        execution_genesis: eg,
        evm_partition: EVM_PARTITION,
        evm_shard: vec![0x80],
        vault: VAULT,
        zero_address: [0; 20],
        ty: derive_type(n, &rg, &eg, c),
        aid: derive_asset(n, &rg, &eg, c),
        semantic_profile_hash: sha(b"semantic profile v2"),
        token_verifier_address: [0xbb; 20],
        token_verifier_code_hash: sha(b"token verifier runtime"),
        b1_profile_hash: sha(b"b1 profile"),
        aggregator_policy_hash: policy.hash(),
    };
    let dep = Deployment::new(
        cfg,
        sha(b"vault runtime"),
        pdr_config_hash(),
        HeaderProfile {
            fields: header_fields,
        },
        policy,
    )
    .unwrap();
    let bridge = NativeBridge::new(
        DeploymentRegistry::new(vec![dep.clone()]).unwrap(),
        trust_input(&agg),
    )
    .unwrap();
    World {
        agg,
        evm_root,
        dep,
        bridge,
        policy,
        agg_conf,
    }
}

/// A mint of `amount` locked under nonce `n`, with all knobs for mutation.
pub struct MintSpec {
    pub nonce: u64,
    pub amount: Vec<u8>,
    pub owner: Secp256k1Signer,
    pub mint_deadline: Option<u64>,
    pub evm: EvmSpec,
    pub evm_t: u64,
}

pub fn spec(owner: u8) -> MintSpec {
    MintSpec {
        nonce: 1,
        amount: vec![0x03, 0xe8],
        owner: signer(owner),
        mint_deadline: None,
        evm: EvmSpec {
            vault_code_hash: sha(b"vault runtime"),
            stored: None,
            nonce: 1,
            block_number: 1234,
        },
        evm_t: 0,
    }
}

pub struct Built {
    pub justification: Vec<u8>,
    pub digest: [u8; 32],
    pub recipient: EncodedPredicate,
    pub token_id: TokenId,
    pub salt: [u8; 32],
    pub data: Vec<u8>,
}

/// The fields of a LockProof, mutable before encoding.
#[derive(Clone)]
pub struct LockParts {
    pub cfg: [u8; 32],
    pub trust_base_id: [u8; 32],
    pub pdr: Vec<u8>,
    pub uc: UnicityCertificate,
    pub header: Vec<u8>,
    pub account_nodes: Vec<Vec<u8>>,
    pub storage_nodes: Vec<Vec<u8>>,
    /// Raw override of the encoded UC bytes (for non-canonical or garbage UC tests).
    pub uc_raw: Option<Vec<u8>>,
}

impl LockParts {
    pub fn encode(&self) -> Vec<u8> {
        let nodes = |v: &Vec<Vec<u8>>| {
            let enc: Vec<Vec<u8>> = v.iter().map(|n| encode_byte_string(n)).collect();
            let refs: Vec<&[u8]> = enc.iter().map(Vec::as_slice).collect();
            encode_array(&refs)
        };
        let uc = self.uc_raw.clone().unwrap_or_else(|| self.uc.to_cbor());
        encode_array(&[
            &encode_uint(1),
            &encode_byte_string(&self.cfg),
            &encode_byte_string(&self.trust_base_id),
            &encode_byte_string(&self.pdr),
            &encode_byte_string(&uc),
            &encode_byte_string(&self.header),
            &nodes(&self.account_nodes),
            &nodes(&self.storage_nodes),
        ])
    }
}

pub fn digest_of(w: &World, s: &MintSpec) -> ([u8; 32], EncodedPredicate, TokenId, [u8; 32]) {
    let cfgh = w.dep.cfg_hash;
    let recipient = SignaturePredicate::new(s.owner.public_key()).to_encoded();
    let salt = derive_salt(&cfgh, s.nonce);
    let tid = TokenId::derive(
        NetworkId::new(NETWORK).unwrap(),
        &TokenSalt::from_bytes(salt),
    );
    assert_eq!(tid.bytes(), &derive_token_id(&salt, NETWORK));
    let p0 = sha(&recipient.to_cbor());
    let digest = lock_digest(
        &cfgh,
        s.nonce,
        &lock_record(
            &[0; 20],
            &w.dep.cfg.ty,
            &w.dep.cfg.aid,
            &s.amount,
            tid.bytes(),
            &p0,
        ),
    );
    (digest, recipient, tid, salt)
}

/// Build the parts of a genuine embedded lock proof.
pub fn lock_parts(w: &World, s: &MintSpec) -> LockParts {
    let cfgh = w.dep.cfg_hash;
    let (digest, _, _, _) = digest_of(w, s);
    let stored = s.evm.stored.unwrap_or(digest);
    let skey = storage_trie_key(&lock_digest_slot(s.evm.nonce));
    let trimmed: Vec<u8> = {
        let i = stored.iter().take_while(|&&b| b == 0).count();
        stored[i..].to_vec()
    };
    let other_slot = storage_trie_key(&lock_digest_slot(4242));
    let (sroot, sproof) = trie(
        &[
            (skey, rlp::encode_bytes(&trimmed)),
            (other_slot, rlp::encode_bytes(&[1, 2, 3])),
        ],
        &skey,
    );
    let acct = rlp::encode_list(&[
        &rlp::encode_u64(1),
        &rlp::encode_bytes(&[0x0f, 0x42]),
        &rlp::encode_bytes(&sroot),
        &rlp::encode_bytes(&s.evm.vault_code_hash),
    ]);
    let akey = account_trie_key(&VAULT);
    let other_acct = account_trie_key(&[0xcc; 20]);
    let (aroot, aproof) = trie(
        &[
            (akey, acct),
            (
                other_acct,
                rlp::encode_list(&[
                    &rlp::encode_u64(0),
                    &rlp::encode_bytes(&[]),
                    &rlp::encode_bytes(&sroot),
                    &rlp::encode_bytes(&[0u8; 32]),
                ]),
            ),
        ],
        &akey,
    );
    let header = header_rlp(&aroot, s.evm.block_number, w.dep.header.fields as usize);
    let pdr = pdr_bytes(5, 0);
    let uc = make_uc(
        &w.evm_root,
        &UcSpec {
            partition: EVM_PARTITION,
            conf: sha(&pdr).to_vec(),
            epoch_ir: 5,
            root_epoch: 2,
            round: 500,
            timestamp: 1_700_000_100,
            state_hash: aroot.to_vec(),
            block_hash: Some(keccak(&[&header]).to_vec()),
            signers: 4,
        },
    );
    LockParts {
        cfg: cfgh,
        trust_base_id: w.bridge.trust.id(),
        pdr,
        uc,
        header,
        account_nodes: aproof,
        storage_nodes: sproof,
        uc_raw: None,
    }
}

pub fn built_from(w: &World, s: &MintSpec, parts: &LockParts) -> Built {
    let (digest, recipient, tid, salt) = digest_of(w, s);
    let justification = encode_justification(CHAIN_ID, &VAULT, &[0; 20], s.nonce, &parts.encode());
    Built {
        justification,
        digest,
        recipient,
        token_id: tid,
        salt,
        data: value_envelope(&w.dep.cfg.aid, &s.amount),
    }
}

/// Re-sign a mutated certificate: recompute the seal hash and all signatures.
pub fn resign(root: &Root, uc: &mut UnicityCertificate, signers: usize) {
    uc.unicity_seal.hash = uc.computed_seal_hash().unwrap().data().to_vec();
    let digest = uc.unicity_seal.calculate_hash();
    uc.unicity_seal.signatures = root
        .signers
        .iter()
        .take(signers)
        .map(|(id, sg)| (id.clone(), sg.sign(&digest).encode().to_vec()))
        .collect();
}

/// A step of the history: transaction plus the signer that spends its *source*.
pub enum Step {
    Transfer {
        to: Secp256k1Signer,
        mask: u8,
        deadline: Option<u64>,
        t: u64,
    },
    Burn {
        recipient: [u8; 20],
        deadline: Option<u64>,
        t: u64,
    },
    /// A burn carrying an arbitrary reason; the burn predicate commits to exactly those bytes.
    BurnWith { reason: Vec<u8>, t: u64 },
}

/// Post-construction mutations applied with consistent hashes, so exactly one guard fires.
#[derive(Default)]
pub struct Tweaks {
    pub mint_ty: Option<Vec<u8>>,
    pub mint_network: Option<u16>,
    pub mint_data: Option<Option<Vec<u8>>>,
    pub mint_justification: Option<Option<Vec<u8>>>,
    pub mint_salt: Option<[u8; 32]>,
    /// `(index, deadline)`: certification data carries a different deadline from its transaction.
    pub cd_deadline: Vec<(usize, Option<u64>)>,
    pub unlock: Vec<(usize, Box<dyn Fn(&mut Vec<u8>)>)>,
    pub transfer_data: Vec<(usize, Option<Vec<u8>>)>,
    /// The minter signs with this key instead of the derived one.
    pub minter_override: Option<Secp256k1Signer>,
    /// Skip the aggregator proof's reference-time override: `(index, t)` changes proof.reference_time only.
    pub proof_time: Vec<(usize, u64)>,
}

pub struct TokenOut {
    pub token: Token,
    pub uc: UnicityCertificate,
    pub leaves: Vec<([u8; 32], [u8; 32])>,
}

pub fn build_token(w: &World, s: &MintSpec, steps: &[Step], mint_t: u64, uc_ts: u64) -> TokenOut {
    let parts = lock_parts(w, s);
    build_token_with(w, s, &parts, &Tweaks::default(), steps, mint_t, uc_ts)
}

pub fn build_token_with(
    w: &World,
    s: &MintSpec,
    parts: &LockParts,
    tw: &Tweaks,
    steps: &[Step],
    mint_t: u64,
    uc_ts: u64,
) -> TokenOut {
    let b = built_from(w, s, parts);
    let network = NetworkId::new(tw.mint_network.unwrap_or(NETWORK)).unwrap();
    let justification = match &tw.mint_justification {
        Some(j) => j.clone(),
        None => Some(b.justification.clone()),
    };
    let data = match &tw.mint_data {
        Some(d) => d.clone(),
        None => Some(b.data.clone()),
    };
    let mint = MintTransaction::create(
        network,
        b.recipient.clone(),
        TokenType::new(tw.mint_ty.clone().unwrap_or_else(|| w.dep.cfg.ty.to_vec())),
        TokenSalt::from_bytes(tw.mint_salt.unwrap_or(b.salt)),
        data,
        justification,
        s.mint_deadline,
    )
    .unwrap();
    assemble_token(w, s, mint, tw, steps, mint_t, uc_ts)
}

fn apply_unlock(tw: &Tweaks, i: usize, unlock: Vec<u8>) -> Vec<u8> {
    let mut u = unlock;
    for (idx, f) in &tw.unlock {
        if *idx == i {
            f(&mut u);
        }
    }
    u
}

pub fn assemble_token(
    w: &World,
    s: &MintSpec,
    mint: MintTransaction,
    tw: &Tweaks,
    steps: &[Step],
    mint_t: u64,
    uc_ts: u64,
) -> TokenOut {
    struct Item {
        cd: CertificationData,
        sid: [u8; 32],
        t: u64,
    }
    let minter = match &tw.minter_override {
        Some(m) => m.clone(),
        None => unicity_token::transaction::Minter::signer(mint.token_id()).unwrap(),
    };
    let mut items: Vec<Item> = Vec::new();
    let mint_hash = mint.calculate_transaction_hash();
    let mut cd0 = CertificationData::from_transaction(
        &mint,
        apply_unlock(
            tw,
            0,
            sign_signature_unlock(&minter, mint.source_state_hash(), &mint_hash),
        ),
    );
    if let Some((_, e)) = tw.cd_deadline.iter().find(|(i, _)| *i == 0) {
        cd0 = CertificationData::new(
            cd0.lock_script().clone(),
            cd0.source_state_hash().clone(),
            cd0.transaction_hash().clone(),
            cd0.unlock_script().to_vec(),
            *e,
        );
    }
    items.push(Item {
        cd: cd0,
        sid: *StateId::derive(mint.lock_script(), mint.source_state_hash()).bytes(),
        t: mint_t,
    });
    let mut state = mint.calculate_state_hash();
    let mut lock = mint.recipient().clone();
    let mut cur_owner = s.owner.clone();
    let mut txs: Vec<TransferTransaction> = Vec::new();
    for (k, st) in steps.iter().enumerate() {
        let i = k + 1;
        let (recipient, mask, mut data, deadline, t, next_owner): (
            EncodedPredicate,
            [u8; 32],
            Option<Vec<u8>>,
            Option<u64>,
            u64,
            Option<Secp256k1Signer>,
        ) = match st {
            Step::Transfer {
                to,
                mask,
                deadline,
                t,
            } => (
                SignaturePredicate::new(to.public_key()).to_encoded(),
                [*mask; 32],
                None,
                *deadline,
                *t,
                Some(to.clone()),
            ),
            Step::BurnWith { reason, t } => (
                BurnPredicate::new(sha(reason).to_vec()).to_encoded(),
                [0x42; 32],
                Some(reason.clone()),
                None,
                *t,
                None,
            ),
            Step::Burn {
                recipient,
                deadline,
                t,
            } => {
                let reason = return_reason(
                    CHAIN_ID,
                    &VAULT,
                    &[0; 20],
                    &w.dep.cfg.ty,
                    &w.dep.cfg.aid,
                    recipient,
                    &s.amount,
                );
                (
                    BurnPredicate::new(sha(&reason).to_vec()).to_encoded(),
                    [0x42; 32],
                    Some(reason),
                    *deadline,
                    *t,
                    None,
                )
            }
        };
        if let Some((_, d)) = tw.transfer_data.iter().find(|(idx, _)| *idx == i) {
            data = d.clone();
        }
        let tx = TransferTransaction::new(
            state.clone(),
            lock.clone(),
            recipient.clone(),
            mask.to_vec(),
            data,
            deadline,
        );
        let th = tx.calculate_transaction_hash();
        let mut cd = CertificationData::from_transaction(
            &tx,
            apply_unlock(
                tw,
                i,
                sign_signature_unlock(&cur_owner, tx.source_state_hash(), &th),
            ),
        );
        if let Some((_, e)) = tw.cd_deadline.iter().find(|(idx, _)| *idx == i) {
            cd = CertificationData::new(
                cd.lock_script().clone(),
                cd.source_state_hash().clone(),
                cd.transaction_hash().clone(),
                cd.unlock_script().to_vec(),
                *e,
            );
        }
        items.push(Item {
            cd,
            sid: *StateId::derive(tx.lock_script(), tx.source_state_hash()).bytes(),
            t,
        });
        state = tx.calculate_state_hash();
        lock = recipient;
        if let Some(n) = next_owner {
            cur_owner = n;
        }
        txs.push(tx);
    }
    let leaves: Vec<([u8; 32], [u8; 32])> = items
        .iter()
        .map(|i| {
            (
                i.sid,
                native_bridge_sdk_ext::profile::leaf_value(
                    i.cd.transaction_hash().data().try_into().unwrap(),
                    i.t,
                ),
            )
        })
        .collect();
    let (root, _) = tree(&leaves, &leaves[0].0);
    let uc = make_uc(
        &w.agg,
        &UcSpec {
            partition: AGG_PARTITION,
            conf: w.agg_conf.to_vec(),
            epoch_ir: 1,
            root_epoch: 2,
            round: 900,
            timestamp: uc_ts,
            state_hash: root.to_vec(),
            block_hash: None,
            signers: 4,
        },
    );
    let proof = |i: usize| InclusionProof {
        certification_data: items[i].cd.clone(),
        reference_time: tw
            .proof_time
            .iter()
            .find(|(idx, _)| *idx == i)
            .map(|(_, t)| *t)
            .unwrap_or(items[i].t),
        inclusion_certificate: InclusionCertificate::decode(&tree(&leaves, &leaves[i].0).1)
            .unwrap(),
        unicity_certificate: uc.clone(),
    };
    let genesis = CertifiedMintTransaction::new(mint, proof(0));
    let transfers = txs
        .into_iter()
        .enumerate()
        .map(|(i, tx)| CertifiedTransferTransaction::new(tx, proof(i + 1)))
        .collect();
    let _ = lock;
    TokenOut {
        token: Token::new(genesis, transfers),
        uc,
        leaves,
    }
}

pub fn recipient20() -> [u8; 20] {
    [0xd0; 20]
}

pub fn tx_step(to: u8, mask: u8, t: u64) -> Step {
    Step::Transfer {
        to: signer(to),
        mask,
        deadline: None,
        t,
    }
}

pub fn burn_step(t: u64) -> Step {
    Step::Burn {
        recipient: recipient20(),
        deadline: None,
        t,
    }
}
