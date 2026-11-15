//! Root committee fixtures for the trust-input tests: trust-base entries of a fixture network, their history and certificates signed
//! by a committee. Moved verbatim from the protocol 7 test world when that bridge was removed (bft-core#1106).
#![allow(dead_code)]

use native_bridge_sdk_ext::trust::TrustInput;
use sha2::{Digest, Sha256};
use unicity_token::api::bft::{
    InputRecord, ShardId, ShardTreeCertificate, UnicityCertificate, UnicitySeal,
    UnicityTreeCertificate,
};
use unicity_token::api::bft::{TrustBaseEntry, TrustBaseHistory, TrustBaseMember};
use unicity_token::api::NetworkId;
use unicity_token::crypto::hash::{DataHash, HashAlgorithm};
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};

pub const NETWORK: u16 = 3;
/// The SDK's fixed aggregation partition.
pub const AGG_PARTITION: u32 = 7;

fn h(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn sha(b: &[u8]) -> [u8; 32] {
    h(b)
}

pub fn dh(b: [u8; 32]) -> DataHash {
    DataHash::new(HashAlgorithm::Sha256, b).unwrap()
}

pub fn signer(seed: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_bytes(&sha(&[b's', seed])).unwrap()
}

// ---- unicity certificates -----------------------------------------------------------------------

pub struct Root {
    /// The committee of the latest epoch: it signs this root's certificates.
    pub signers: Vec<(String, Secp256k1Signer)>,
    /// Every entry from the genesis.
    pub entries: Vec<TrustBaseEntry>,
    /// The release bundle (tag 39015) of `entries`.
    pub bundle: Vec<u8>,
    /// The genesis EntryID: the trust pin and every lock proof's `trustBaseId`.
    pub pin: [u8; 32],
}

impl Root {
    /// The latest entry.
    pub fn tb(&self) -> &TrustBaseEntry {
        self.entries.last().unwrap()
    }
}

pub fn trust_input(r: &Root) -> TrustInput {
    TrustInput::from_bundle(&r.bundle, &r.pin).unwrap()
}

fn committee(n: usize, seed: u8) -> Vec<(String, Secp256k1Signer)> {
    let mut signers: Vec<(String, Secp256k1Signer)> = (0..n)
        .map(|i| {
            (
                format!("root-{seed}-{i:02}"),
                signer(seed.wrapping_add(i as u8)),
            )
        })
        .collect();
    signers.sort_by(|a, b| a.0.cmp(&b.0));
    signers
}

fn members(signers: &[(String, Secp256k1Signer)], weights: Option<&[u64]>) -> Vec<TrustBaseMember> {
    signers
        .iter()
        .enumerate()
        .map(|(i, (id, s))| {
            TrustBaseMember::new(id.clone(), s.public_key(), weights.map_or(1, |w| w[i]))
        })
        .collect()
}

fn root_of(signers: Vec<(String, Secp256k1Signer)>, entries: Vec<TrustBaseEntry>) -> Root {
    let pin = entries[0].entry_id();
    let bundle = TrustBaseHistory::from_trusted_chain(entries.clone())
        .unwrap()
        .to_bundle();
    Root {
        signers,
        entries,
        bundle,
        pin,
    }
}

fn entry_of(
    epoch: u64,
    start: u64,
    members: Vec<TrustBaseMember>,
    previous: [u8; 32],
) -> TrustBaseEntry {
    let total = members.iter().map(|m| m.weight).sum();
    TrustBaseEntry::new(
        NetworkId::new(NETWORK).unwrap(),
        epoch,
        start,
        members,
        TrustBaseEntry::threshold_for(total).unwrap(),
        None,
        None,
        previous,
    )
}

/// A trust base history holding only a genesis entry of epoch `epoch` (start round 1) with `n`
/// members, unit weights.
pub fn make_root(epoch: u64, n: usize, seed: u8) -> Root {
    make_weighted_root(epoch, n, seed, None)
}

pub fn make_weighted_root(epoch: u64, n: usize, seed: u8, weights: Option<&[u64]>) -> Root {
    let signers = committee(n, seed);
    let genesis = entry_of(epoch, 1, members(&signers, weights), [0; 32]);
    root_of(signers, vec![genesis])
}

/// The next epoch of `root` from root round `start`: a committee of `n` members (seed `seed`),
/// witnessed by every member of the current one. Same pin, one more entry.
pub fn next_epoch(root: &Root, start: u64, n: usize, seed: u8) -> Root {
    next_weighted_epoch(root, start, n, seed, None)
}

/// `next_epoch` with the new committee's weights in member (id) order; unit weights when `None`.
pub fn next_weighted_epoch(
    root: &Root,
    start: u64,
    n: usize,
    seed: u8,
    weights: Option<&[u64]>,
) -> Root {
    let mut entries = root.entries.clone();
    entries.push(weighted_successor_entry(
        root,
        start,
        n,
        seed,
        weights,
        &root.signers,
    ));
    root_of(committee(n, seed), entries)
}

/// The entry `next_epoch` appends, witnessed by `witnesses`.
pub fn successor_entry(
    root: &Root,
    start: u64,
    n: usize,
    seed: u8,
    witnesses: &[(String, Secp256k1Signer)],
) -> TrustBaseEntry {
    weighted_successor_entry(root, start, n, seed, None, witnesses)
}

fn weighted_successor_entry(
    root: &Root,
    start: u64,
    n: usize,
    seed: u8,
    weights: Option<&[u64]>,
    witnesses: &[(String, Secp256k1Signer)],
) -> TrustBaseEntry {
    let tip = root.tb();
    let mut next = entry_of(
        tip.epoch + 1,
        start,
        members(&committee(n, seed), weights),
        tip.entry_id(),
    );
    for (id, s) in witnesses {
        next.sign(id, s);
    }
    next
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
    make_uc_in_shard(root, s, &[0x80], &[])
}

/// A certificate naming the native shard `shard` with the given shard-tree siblings.
pub fn make_uc_in_shard(
    root: &Root,
    s: &UcSpec,
    shard: &[u8],
    siblings: &[[u8; 32]],
) -> UnicityCertificate {
    // Native-valid records (bft-go-base IsValid, checked by the SDK): an aggregator round that
    // changes the state always has a block
    let block_hash = s.block_hash.clone().or_else(|| {
        (s.partition == AGG_PARTITION)
            .then(|| sha(&[b"aggregator block".as_slice(), &s.state_hash].concat()).to_vec())
    });
    let ir = InputRecord {
        round_number: s.round,
        epoch: s.epoch_ir,
        previous_hash: None,
        hash: Some(s.state_hash.clone()),
        summary_value: Some(vec![]),
        timestamp: s.timestamp,
        block_hash,
        sum_of_earned_fees: 0,
        executed_transactions_hash: None,
    };
    let mut uc = UnicityCertificate {
        input_record: ir,
        // natively always 32 bytes
        technical_record_hash: Some(sha(b"technical record").to_vec()),
        shard_configuration_hash: s.conf.clone(),
        shard_tree_certificate: ShardTreeCertificate {
            shard: ShardId::decode(shard).unwrap(),
            sibling_hash_list: siblings.iter().map(|x| x.to_vec()).collect(),
            empty_as_null: false,
        },
        unicity_tree_certificate: UnicityTreeCertificate {
            partition_identifier: s.partition,
            steps: vec![],
            empty_as_null: false,
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
