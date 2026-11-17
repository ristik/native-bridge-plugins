//! The offline simulator of the NB2 tests, a port of the TypeScript `test/nb2/world.ts`: a trust-base history, a fake aggregator
//! (one RSMT leaf and one certificate per request) and a fake EVM gateway that executes deposits and redemptions against the
//! vault model, certifies every block (the UC of block N in the companion of N+1), and answers the section 12.7 methods with
//! the gateway's limits. The token verifier inside the vault is the plug-in's own `verify_return`.
//!
//! A whole world (chain, aggregator, journal) has a JSON snapshot that the TypeScript world reads and writes too, so a journal
//! written by one plug-in is continued by the other against the same chain (`nb2_journal_interop.rs`).
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use native_bridge_sdk_ext::nb2::abi::{revert_data, selector, ErrArg};
use native_bridge_sdk_ext::nb2::bridge::{derive_bridge_key, BridgeOptions, DeploymentPins};
use native_bridge_sdk_ext::nb2::cbor::{c_arr, c_bytes, c_tag, c_uint};
use native_bridge_sdk_ext::nb2::config::{
    asset_uct, derive_coin, derive_type, domain_of, encode_config, test_params, Build, Config,
};
use native_bridge_sdk_ext::nb2::crypto::{he, hu};
use native_bridge_sdk_ext::nb2::deposit::{deposited_data, topic};
use native_bridge_sdk_ext::nb2::errors::{Error, Result};
use native_bridge_sdk_ext::nb2::evm::{decode_signed_tx, EvmSigner, LocalKeySigner};
use native_bridge_sdk_ext::nb2::gas::{GasModel, MeasuredGasModel, RedeemShape};
use native_bridge_sdk_ext::nb2::header::{
    empty_trie_root, empty_uncle_hash, encode_header, Header,
};
use native_bridge_sdk_ext::nb2::journal::{JournalStore, MemoryJournalStore};
use native_bridge_sdk_ext::nb2::mpt::build_trie;
use native_bridge_sdk_ext::nb2::rlp::{rlp_bytes, rlp_index_key, rlp_list, rlp_u64_enc};
use native_bridge_sdk_ext::nb2::rpc::{JsonRpc, RpcError};
use native_bridge_sdk_ext::nb2::segment::segment_sealed_data;
use native_bridge_sdk_ext::nb2::token::leaf_value;
use native_bridge_sdk_ext::nb2::tokenops::Aggregator;
use native_bridge_sdk_ext::nb2::util::{arr, be_int, from_hex, hex0x, to_u64, u256, u256_64};
use native_bridge_sdk_ext::nb2::vaultmodel::{
    tag_words, RecipientBehaviour, VaultEvent, VaultModel, VerifierAnswer,
};
use native_bridge_sdk_ext::nb2::verify::{verdict_abi, verify_return};
use native_bridge_sdk_ext::trust::TrustInput;
use num_bigint::BigUint;
use serde_json::{json, Map, Value};
use unicity_token::api::bft::{
    InputRecord, ShardId, ShardTreeCertificate, TrustBaseEntry, TrustBaseHistory, TrustBaseMember,
    UnicityCertificate, UnicitySeal, UnicityTreeCertificate,
};
use unicity_token::api::{CertificationData, NetworkId, StateId};
use unicity_token::cbor::Decoder;
use unicity_token::crypto::signer::{Secp256k1Signer, Signer};

pub const NETWORK: u16 = 3;
pub const CHAIN_ID: u64 = 31337;
pub const EVM_PARTITION: u32 = 8;
pub const AGG_PARTITION: u32 = 7;
pub const VAULT: [u8; 20] = [0xaa; 20];
pub const VERIFIER: [u8; 20] = [0xbb; 20];
pub const SNAPSHOT_FORMAT: &str = "unicity-nb2-offline-world";

pub fn sha(b: &[u8]) -> [u8; 32] {
    hu(&[b])
}

pub fn key(seed: &str) -> [u8; 32] {
    sha(format!("key {seed}").as_bytes())
}

pub fn addr_of(seed: &str) -> [u8; 20] {
    arr(&he(&[&key(seed)])[12..])
}

fn h(b: &[u8]) -> String {
    hex0x(b)
}

fn q(v: impl Into<BigUint>) -> String {
    format!("0x{}", v.into().to_str_radix(16))
}

fn unh(v: &Value) -> Vec<u8> {
    from_hex(&v.as_str().expect("a hex string")[2..]).expect("hex")
}

fn qn(v: &Value) -> u64 {
    let s = v.as_str().expect("a quantity");
    u64::from_str_radix(&s[2..], 16).expect("a quantity")
}

// ---- trust base -------------------------------------------------------------------------------------

pub struct Root {
    pub signers: Vec<(String, Secp256k1Signer)>,
    pub bundle: Vec<u8>,
    pub pin: [u8; 32],
    pub trust: TrustInput,
}

fn signers_of(n: usize) -> Vec<(String, Secp256k1Signer)> {
    (0..n)
        .map(|i| {
            (
                format!("root-{i:02}"),
                Secp256k1Signer::from_bytes(&key(&format!("root {i}"))).unwrap(),
            )
        })
        .collect()
}

pub fn make_root(n: usize) -> Root {
    let signers = signers_of(n);
    let members: Vec<TrustBaseMember> = signers
        .iter()
        .map(|(id, s)| TrustBaseMember::new(id.clone(), s.public_key(), 1))
        .collect();
    let entry = TrustBaseEntry::new(
        NetworkId::new(NETWORK).unwrap(),
        1,
        1,
        members,
        TrustBaseEntry::threshold_for(n as u64).unwrap(),
        None,
        None,
        [0; 32],
    );
    let pin = entry.entry_id();
    let bundle = TrustBaseHistory::from_trusted_chain(vec![entry])
        .unwrap()
        .to_bundle();
    let trust = TrustInput::from_bundle(&bundle, &pin).unwrap();
    Root {
        signers,
        bundle,
        pin,
        trust,
    }
}

/// The root of a snapshot: its bundle and pin, the deterministic signer keys.
pub fn root_of(bundle: &[u8], pin: [u8; 32], n: usize) -> Root {
    Root {
        signers: signers_of(n),
        bundle: bundle.to_vec(),
        pin,
        trust: TrustInput::from_bundle(bundle, &pin).unwrap(),
    }
}

static ROUND: AtomicU64 = AtomicU64::new(1000);

pub fn make_uc(
    root: &Root,
    partition: u32,
    state_hash: &[u8],
    block_hash: &[u8],
    timestamp: u64,
) -> Vec<u8> {
    let round = ROUND.fetch_add(1, Ordering::SeqCst) + 1;
    let ir = InputRecord {
        round_number: round,
        epoch: 1,
        previous_hash: None,
        hash: Some(state_hash.to_vec()),
        summary_value: Some(vec![]),
        timestamp,
        block_hash: Some(block_hash.to_vec()),
        sum_of_earned_fees: 0,
        executed_transactions_hash: None,
    };
    let mut uc = UnicityCertificate {
        input_record: ir,
        technical_record_hash: Some(sha(b"technical record").to_vec()),
        shard_configuration_hash: sha(format!("shard configuration {partition}").as_bytes())
            .to_vec(),
        shard_tree_certificate: ShardTreeCertificate {
            shard: ShardId::decode(&[0x80]).unwrap(),
            sibling_hash_list: vec![],
            empty_as_null: false,
        },
        unicity_tree_certificate: UnicityTreeCertificate {
            partition_identifier: partition,
            steps: vec![],
            empty_as_null: false,
        },
        unicity_seal: UnicitySeal {
            network_id: NetworkId::new(NETWORK).unwrap(),
            root_chain_round_number: round,
            epoch: 1,
            timestamp,
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
        .map(|(id, s)| (id.clone(), s.sign(&digest).encode().to_vec()))
        .collect();
    uc.to_cbor()
}

// ---- deployment ---------------------------------------------------------------------------------------

pub fn make_config(root: &Root, k: u64, b: u64) -> Config {
    let execution_genesis = sha(b"execution genesis");
    Config {
        network: NETWORK,
        root_genesis: root.pin,
        execution_genesis,
        chain_id: CHAIN_ID,
        evm_partition: EVM_PARTITION,
        evm_shard: vec![0x80],
        aggregator_partition: AGG_PARTITION,
        vault: VAULT,
        asset: asset_uct(),
        ty: derive_type(NETWORK, &root.pin, &execution_genesis, CHAIN_ID),
        aid: derive_coin(NETWORK, &root.pin, &execution_genesis, CHAIN_ID),
        semantic_profile_hash: sha(b"profile"),
        verifier: VERIFIER,
        verifier_code_hash: sha(b"verifier code"),
        k,
        b,
        qmax: (BigUint::from(1u8) << 120) - 1u8,
    }
}

// ---- aggregator -----------------------------------------------------------------------------------------

#[derive(Default)]
pub struct AggState {
    pub certified: BTreeMap<[u8; 32], Vec<u8>>,
    pub time: u64,
    pub calls: u64,
}

pub struct FakeAggregator {
    root: Arc<Root>,
    pub st: Mutex<AggState>,
    /// The aggregator is unreachable.
    pub down: AtomicBool,
    /// Certify this many more requests, then fail (None: never).
    pub fail_after: Mutex<Option<u64>>,
}

impl FakeAggregator {
    pub fn new(root: Arc<Root>) -> Self {
        FakeAggregator {
            root,
            st: Mutex::new(AggState {
                time: 1_700_000_000,
                ..Default::default()
            }),
            down: AtomicBool::new(false),
            fail_after: Mutex::new(None),
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

impl Aggregator for FakeAggregator {
    fn certify(&self, request: &[u8]) -> Result<Vec<u8>> {
        if self.down.load(Ordering::SeqCst) {
            return Err(Error::Other("aggregator unreachable".into()));
        }
        {
            let mut f = self.fail_after.lock().unwrap();
            match *f {
                Some(0) => return Err(Error::Other("aggregator unreachable".into())),
                Some(n) => *f = Some(n - 1),
                None => {}
            }
        }
        let mut st = self.st.lock().unwrap();
        st.calls += 1;
        let cd = CertificationData::from_cbor(Decoder::new(request))
            .map_err(|e| Error::Other(format!("{e:?}")))?;
        let sid = *StateId::derive(cd.lock_script(), cd.source_state_hash()).bytes();
        if let Some(prior) = st.certified.get(&sid) {
            // single spend: the same request gets its proof again, another transaction from the same state is refused
            if contains(prior, request) {
                return Ok(prior.clone());
            }
            return Err(Error::Other(
                "fake aggregator: state already spent by another transaction".into(),
            ));
        }
        st.time += 1;
        let t = st.time;
        let root = hu(&[&[0x00], &sid, &leaf_value(cd.transaction_hash().data(), t)]);
        let uc = make_uc(
            &self.root,
            AGG_PARTITION,
            &root,
            &sha(&[b"aggregator block".as_slice(), &root].concat()),
            t + 1,
        );
        let proof = c_tag(
            39033,
            &c_arr(&[&c_uint(1), request, &c_uint(t), &c_bytes(&[0u8; 32]), &uc]),
        );
        st.certified.insert(sid, proof.clone());
        Ok(proof)
    }
}

// ---- the EVM gateway --------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Log {
    pub address: Vec<u8>,
    pub topics: Vec<Vec<u8>>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Rcpt {
    pub status: u8,
    pub logs: Vec<Log>,
    pub tx: [u8; 32],
    pub from: [u8; 20],
    pub revert: Option<Vec<u8>>,
    pub gas: u64,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub header: Header,
    pub hash: [u8; 32],
    pub uc: Option<Vec<u8>>,
    pub receipts: Vec<Rcpt>,
}

#[derive(Default)]
pub struct Faults {
    /// The next N sends are included but answered with HTTP 503 (partial broadcast, #1121).
    pub ambiguous_sends: u32,
    /// SegmentSealed logs of these segments are not served by eth_getLogs.
    pub hide_segments: BTreeSet<u64>,
    /// Hide every SegmentSealed log (a provider that withholds seals).
    pub hide_all_seals: bool,
    /// Recipient behaviour by address.
    pub recipients: HashMap<[u8; 20], RecipientBehaviour>,
    /// Deposited events carry this domain instead of the vault's (a provider or vault of another deployment).
    pub deposit_domain: Option<[u8; 32]>,
}

pub struct ChainState {
    pub blocks: Vec<Block>,
    pub vault: VaultModel,
    pub balances: HashMap<[u8; 20], BigUint>,
    pub nonces: HashMap<[u8; 20], u64>,
    pub code: HashMap<[u8; 20], Vec<u8>>,
    pub faults: Faults,
    pub auto_mine: bool,
    pub pool: Vec<Vec<u8>>,
    pub calls: Vec<String>,
}

type PreHook =
    Box<dyn Fn(&str, &Value) -> Option<core::result::Result<Value, RpcError>> + Send + Sync>;
type PostHook = Box<dyn Fn(&str, &Value, Value) -> Value + Send + Sync>;

pub struct FakeChain {
    pub root: Arc<Root>,
    pub gamma: Vec<u8>,
    pub cfg: Config,
    pub vault_code: Vec<u8>,
    pub st: Mutex<ChainState>,
    /// Answer a call instead of the chain (a lagging or lying backend).
    pub pre: Mutex<Option<PreHook>>,
    /// Rewrite an answer of the chain.
    pub post: Mutex<Option<PostHook>>,
}

fn err(status: u16, code: i64, message: &str) -> RpcError {
    RpcError {
        status,
        code,
        message: message.into(),
        data: None,
    }
}

impl FakeChain {
    pub fn create(root: Arc<Root>, cfg: Config) -> Arc<FakeChain> {
        let gamma = encode_config(&cfg);
        let vault = VaultModel::with_config(&gamma, cfg.clone());
        let vault_code = b"fake vault runtime".to_vec();
        let mut code = HashMap::new();
        code.insert(VAULT, vault_code.clone());
        let c = FakeChain {
            root,
            gamma,
            cfg,
            vault_code,
            st: Mutex::new(ChainState {
                blocks: vec![],
                vault,
                balances: HashMap::new(),
                nonces: HashMap::new(),
                code,
                faults: Faults::default(),
                auto_mine: true,
                pool: vec![],
                calls: vec![],
            }),
            pre: Mutex::new(None),
            post: Mutex::new(None),
        };
        {
            let mut st = c.st.lock().unwrap();
            c.mine(&mut st, vec![]); // genesis
            c.mine(&mut st, vec![]); // the deployment block
        }
        Arc::new(c)
    }

    pub fn domain(&self) -> [u8; 32] {
        domain_of(&self.gamma)
    }

    pub fn fund(&self, a: &[u8; 20], wei: BigUint) {
        let mut st = self.st.lock().unwrap();
        *st.balances.entry(*a).or_default() += wei;
    }

    pub fn set_balance(&self, a: &[u8; 20], wei: BigUint) {
        self.st.lock().unwrap().balances.insert(*a, wei);
    }

    pub fn balance_of(&self, a: &[u8; 20]) -> BigUint {
        self.st
            .lock()
            .unwrap()
            .balances
            .get(a)
            .cloned()
            .unwrap_or_default()
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut ChainState) -> T) -> T {
        f(&mut self.st.lock().unwrap())
    }

    pub fn set_pre(&self, f: Option<PreHook>) {
        *self.pre.lock().unwrap() = f;
    }

    pub fn set_post(&self, f: Option<PostHook>) {
        *self.post.lock().unwrap() = f;
    }

    /// Mine one block with the given signed transactions, and certify the previous block (its UC goes in this block's companion).
    pub fn mine(&self, st: &mut ChainState, raws: Vec<Vec<u8>>) {
        let n = st.blocks.len() as u64;
        let receipts: Vec<Rcpt> = raws.iter().map(|r| self.execute(st, r)).collect();
        let mut cum = 0u64;
        let enc: Vec<(Vec<u8>, Vec<u8>)> = receipts
            .iter()
            .enumerate()
            .map(|(i, r)| {
                cum += r.gas;
                let logs = rlp_list(
                    &r.logs
                        .iter()
                        .map(|l| {
                            rlp_list(&[
                                rlp_bytes(&l.address),
                                rlp_list(
                                    &l.topics.iter().map(|t| rlp_bytes(t)).collect::<Vec<_>>(),
                                ),
                                rlp_bytes(&l.data),
                            ])
                        })
                        .collect::<Vec<_>>(),
                );
                (
                    rlp_index_key(i as u64),
                    [
                        vec![2u8],
                        rlp_list(&[
                            rlp_u64_enc(r.status as u64),
                            rlp_u64_enc(cum),
                            rlp_bytes(&[0u8; 256]),
                            logs,
                        ]),
                    ]
                    .concat(),
                )
            })
            .collect();
        let (root, _) = build_trie(&enc, None);
        let mut state_pre = b"state".to_vec();
        state_pre.extend_from_slice(&u256_64(n));
        let mut txs_pre = b"txs".to_vec();
        for r in &raws {
            state_pre.extend_from_slice(r);
            txs_pre.extend_from_slice(r);
        }
        let header = Header {
            parent_hash: if n == 0 {
                vec![0; 32]
            } else {
                st.blocks[n as usize - 1].hash.to_vec()
            },
            ommers_hash: empty_uncle_hash().to_vec(),
            beneficiary: vec![0; 20],
            state_root: sha(&state_pre).to_vec(),
            transactions_root: sha(&txs_pre).to_vec(),
            receipts_root: root.to_vec(),
            logs_bloom: vec![0; 256],
            difficulty: BigUint::default(),
            number: BigUint::from(n),
            gas_limit: 30_000_000,
            gas_used: cum,
            timestamp: 1_700_000_000 + n,
            extra_data: vec![],
            mix_hash: vec![0; 32],
            nonce: vec![0; 8],
            base_fee_per_gas: BigUint::from(7u8),
            withdrawals_root: empty_trie_root().to_vec(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            parent_beacon_block_root: vec![0; 32],
        };
        let hash = he(&[&encode_header(&header)]);
        if n > 0 {
            let ts = header.timestamp;
            let parent = &st.blocks[n as usize - 1];
            let uc = make_uc(
                &self.root,
                EVM_PARTITION,
                &parent.header.state_root,
                &parent.hash,
                ts,
            );
            st.blocks[n as usize - 1].uc = Some(uc);
        }
        st.blocks.push(Block {
            header,
            hash,
            uc: None,
            receipts,
        });
    }

    /// The verifier inside the vault: the plug-in's own relation (the Solidity verifier is NB2-05's).
    fn verifier_answer(&self, evidence: &[u8]) -> VerifierAnswer {
        match verify_return(&self.gamma, evidence, &self.root.trust, &test_params()) {
            Ok(v) => VerifierAnswer::Ret(verdict_abi(&v)),
            Err(Error::Rule(e)) => VerifierAnswer::Revert(revert_data(e.rule, &[])),
            Err(e) => panic!("fake chain verifier: {e}"),
        }
    }

    /// Run a call against a vault (the real one, or a copy for a simulation); events and the payout as effects.
    fn run(
        &self,
        v: &mut VaultModel,
        faults: &Faults,
        to: &[u8],
        value: &BigUint,
        data: &[u8],
    ) -> core::result::Result<Vec<VaultEvent>, Vec<u8>> {
        if to != VAULT {
            return Ok(vec![]);
        }
        let before = v.events.len();
        let word = |i: usize| data.get(4 + 32 * i..36 + 32 * i).unwrap_or(&[]).to_vec();
        let dynamic = |i: usize| -> Vec<u8> {
            let off = to_u64(&be_int(&word(i))).unwrap() as usize;
            let len = to_u64(&be_int(&data[4 + off..36 + off])).unwrap() as usize;
            data[36 + off..36 + off + len].to_vec()
        };
        let sel = &data[..4.min(data.len())];
        let r = if sel == selector::deposit() {
            v.deposit(value, &dynamic(0), &word(1))
        } else if sel == selector::redeem() {
            let ver = self.verifier_answer(&dynamic(0));
            let rcpt = match &ver {
                VerifierAnswer::Ret(r) => faults
                    .recipients
                    .get(&arr::<20>(&r[140..160]))
                    .copied()
                    .unwrap_or(RecipientBehaviour::Accepts),
                VerifierAnswer::Revert(_) => RecipientBehaviour::Accepts,
            };
            v.redeem(
                &arr(&word(1)),
                to_u64(&be_int(&word(2))).unwrap(),
                &dynamic(3),
                &ver,
                rcpt,
            )
            .map(|_| ())
        } else {
            return Err(vec![]);
        };
        match r {
            Ok(()) => Ok(v.events[before..].to_vec()),
            Err(Error::Rule(e)) => {
                let vals: Vec<ErrArg> = e
                    .args
                    .iter()
                    .map(|a| {
                        if let Some(x) = a.strip_prefix("0x") {
                            ErrArg::Word(from_hex(x).unwrap())
                        } else {
                            ErrArg::Int(a.parse().unwrap())
                        }
                    })
                    .collect();
                Err(revert_data(e.rule, &vals))
            }
            Err(e) => panic!("fake chain vault: {e}"),
        }
    }

    fn execute(&self, st: &mut ChainState, raw: &[u8]) -> Rcpt {
        let d = decode_signed_tx(raw).unwrap();
        let t = &d.request;
        let nonce = st.nonces.get(&d.from).copied().unwrap_or(0);
        assert_eq!(t.nonce, nonce, "fake chain: nonce");
        st.nonces.insert(d.from, nonce + 1);
        let fee = BigUint::from(t.gas) * 7u8;
        let bal = st.balances.get(&d.from).cloned().unwrap_or_default();
        assert!(bal >= &fee + &t.value, "fake chain: insufficient funds");
        st.balances.insert(d.from, bal - &fee);
        let mut vault = st.vault.clone();
        let r = self.run(&mut vault, &st.faults, &t.to, &t.value, &t.data);
        match r {
            Err(revert) => Rcpt {
                status: 0,
                logs: vec![],
                tx: d.hash,
                from: d.from,
                revert: Some(revert),
                gas: t.gas,
            },
            Ok(events) => {
                st.vault = vault;
                let b = st.balances.get(&d.from).cloned().unwrap_or_default();
                st.balances.insert(d.from, b - &t.value);
                let mut logs = vec![];
                for e in events {
                    match e {
                        VaultEvent::Deposited {
                            n,
                            amount,
                            rho,
                            first_owner,
                        } => logs.push(Log {
                            address: VAULT.to_vec(),
                            topics: vec![topic::deposited().to_vec(), u256_64(n).to_vec()],
                            data: deposited_data(
                                &st.faults.deposit_domain.unwrap_or(self.domain()),
                                &amount,
                                &rho,
                                &first_owner,
                            ),
                        }),
                        VaultEvent::Paid {
                            eta,
                            recipient,
                            amount,
                        } => {
                            let mut w = [0u8; 32];
                            w[12..].copy_from_slice(&recipient);
                            logs.push(Log {
                                address: VAULT.to_vec(),
                                topics: vec![topic::paid().to_vec(), eta.to_vec(), w.to_vec()],
                                data: u256(&amount).to_vec(),
                            });
                            *st.balances.entry(recipient).or_default() += amount;
                        }
                        VaultEvent::SegmentSealed {
                            segment,
                            before,
                            after,
                            ids,
                        } => logs.push(Log {
                            address: VAULT.to_vec(),
                            topics: vec![
                                topic::segment_sealed().to_vec(),
                                u256_64(segment).to_vec(),
                            ],
                            data: segment_sealed_data(&before, &after, &ids),
                        }),
                    }
                }
                Rcpt {
                    status: 1,
                    logs,
                    tx: d.hash,
                    from: d.from,
                    revert: None,
                    gas: 150_000,
                }
            }
        }
    }

    // ---- JSON-RPC ----

    pub fn header_json(b: &Block) -> Value {
        let x = &b.header;
        json!({
            "hash": h(&b.hash), "parentHash": h(&x.parent_hash), "sha3Uncles": h(&x.ommers_hash), "miner": h(&x.beneficiary), "stateRoot": h(&x.state_root),
            "transactionsRoot": h(&x.transactions_root), "receiptsRoot": h(&x.receipts_root), "logsBloom": h(&x.logs_bloom), "difficulty": q(x.difficulty.clone()),
            "number": q(x.number.clone()), "gasLimit": q(x.gas_limit), "gasUsed": q(x.gas_used), "timestamp": q(x.timestamp), "extraData": h(&x.extra_data),
            "mixHash": h(&x.mix_hash), "nonce": h(&x.nonce), "baseFeePerGas": q(x.base_fee_per_gas.clone()), "withdrawalsRoot": h(&x.withdrawals_root),
            "blobGasUsed": q(x.blob_gas_used), "excessBlobGas": q(x.excess_blob_gas), "parentBeaconBlockRoot": h(&x.parent_beacon_block_root),
        })
    }

    fn receipt_json(b: &Block, i: usize) -> Value {
        let r = &b.receipts[i];
        let cum: u64 = b.receipts[..=i].iter().map(|x| x.gas).sum();
        let log_base: usize = b.receipts[..i].iter().map(|x| x.logs.len()).sum();
        let n = b.header.number_u64();
        json!({
            "type": "0x2", "status": q(r.status), "cumulativeGasUsed": q(cum), "logsBloom": h(&[0u8; 256]), "blockHash": h(&b.hash), "blockNumber": q(n),
            "transactionIndex": q(i as u64), "transactionHash": h(&r.tx), "gasUsed": q(r.gas),
            "logs": r.logs.iter().enumerate().map(|(k, l)| json!({
                "address": h(&l.address), "topics": l.topics.iter().map(|t| h(t)).collect::<Vec<_>>(), "data": h(&l.data), "logIndex": q((log_base + k) as u64),
                "blockNumber": q(n), "blockHash": h(&b.hash), "transactionHash": h(&r.tx),
            })).collect::<Vec<_>>(),
        })
    }

    fn find_tx(st: &ChainState, hash: &str) -> Option<(usize, usize)> {
        for (bi, b) in st.blocks.iter().enumerate() {
            if let Some(i) = b.receipts.iter().position(|r| h(&r.tx) == hash) {
                return Some((bi, i));
            }
        }
        None
    }

    fn dispatch(
        &self,
        st: &mut ChainState,
        method: &str,
        p: &Value,
    ) -> core::result::Result<Value, RpcError> {
        let top = st.blocks.last().unwrap();
        match method {
            "eth_chainId" => Ok(json!(q(CHAIN_ID))),
            "eth_blockNumber" => Ok(json!(q(top.header.number_u64()))),
            "eth_maxPriorityFeePerGas" => Ok(json!(q(1u8))),
            "eth_getBlockByNumber" => {
                let b = if p[0] == "latest" {
                    Some(top)
                } else {
                    st.blocks.get(qn(&p[0]) as usize)
                };
                Ok(b.map_or(Value::Null, Self::header_json))
            }
            "eth_getBlockByHash" => {
                if p.as_array().map(|a| a.len()) != Some(2) || p[1] != json!(false) {
                    return Err(err(400, 0, "eth_getBlockByHash takes [hash, false]"));
                }
                Ok(st
                    .blocks
                    .iter()
                    .find(|x| json!(h(&x.hash)) == p[0])
                    .map_or(Value::Null, Self::header_json))
            }
            "eth_getTransactionReceipt" => Ok(Self::find_tx(st, p[0].as_str().unwrap())
                .map_or(Value::Null, |(b, i)| Self::receipt_json(&st.blocks[b], i))),
            "eth_getBlockReceipts" => Ok(st
                .blocks
                .iter()
                .find(|x| json!(h(&x.hash)) == p[0])
                .map_or(Value::Null, |b| {
                    json!((0..b.receipts.len())
                        .map(|i| Self::receipt_json(b, i))
                        .collect::<Vec<_>>())
                })),
            "unicity_getSealCompanionV1" => {
                let i = st.blocks.iter().position(|x| json!(h(&x.hash)) == p[0]);
                match i {
                    None | Some(0) => Ok(json!({"status": "unknown"})),
                    Some(i) => Ok(
                        json!({"status": "found", "companion": {"witnesses": [h(st.blocks[i - 1].uc.as_ref().unwrap()), h(b"technical record")]}}),
                    ),
                }
            }
            "eth_getLogs" => {
                let f = &p[0];
                if !f["address"].is_string()
                    || !f["fromBlock"].is_string()
                    || !f["toBlock"].is_string()
                {
                    return Err(err(400, 0, "one address and a numeric window"));
                }
                let lo = qn(&f["fromBlock"]);
                let hi = qn(&f["toBlock"]);
                if hi - lo + 1 > 10_000 {
                    return Err(err(400, 0, "window over 10000 blocks"));
                }
                let mut out = vec![];
                let topics = f["topics"].as_array().cloned().unwrap_or_default();
                for b in st
                    .blocks
                    .iter()
                    .skip(lo as usize)
                    .take((hi - lo + 1) as usize)
                {
                    for (i, r) in b.receipts.iter().enumerate() {
                        if r.status != 1 {
                            continue;
                        }
                        let rj = Self::receipt_json(b, i);
                        for l in rj["logs"].as_array().unwrap() {
                            if l["address"] != f["address"] {
                                continue;
                            }
                            let ok = topics.iter().enumerate().all(|(k, t)| {
                                t.is_null()
                                    || if let Some(a) = t.as_array() {
                                        a.contains(&l["topics"][k])
                                    } else {
                                        l["topics"][k] == *t
                                    }
                            });
                            if !ok {
                                continue;
                            }
                            if l["topics"][0] == json!(h(&topic::segment_sealed()))
                                && (st.faults.hide_all_seals
                                    || st
                                        .faults
                                        .hide_segments
                                        .contains(&to_u64(&be_int(&unh(&l["topics"][1]))).unwrap()))
                            {
                                continue;
                            }
                            out.push(l.clone());
                        }
                    }
                }
                Ok(json!(out))
            }
            "eth_call" | "eth_estimateGas" => {
                let t = &p[0];
                let to = unh(&t["to"]);
                let data = unh(&t["data"]);
                if method == "eth_call" && to == VAULT {
                    if data == selector::config() {
                        let g = &self.gamma;
                        let pad = vec![0u8; (32 - g.len() % 32) % 32];
                        return Ok(json!(h(&[
                            u256_64(32).as_slice(),
                            &u256_64(g.len() as u64),
                            g,
                            &pad
                        ]
                        .concat())));
                    }
                    if data == selector::state() {
                        let s = st.vault.state();
                        return Ok(json!(h(&[
                            u256_64(s.deposits).as_slice(),
                            &u256_64(s.segment),
                            &u256_64(s.population),
                            &u256(&s.outstanding),
                            &s.head,
                            &s.previous_head
                        ]
                        .concat())));
                    }
                }
                let value = t
                    .get("value")
                    .and_then(|v| v.as_str())
                    .map_or(BigUint::default(), |v| {
                        BigUint::parse_bytes(&v.as_bytes()[2..], 16).unwrap()
                    });
                let mut copy = st.vault.clone();
                match self.run(&mut copy, &st.faults, &to, &value, &data) {
                    Err(revert) => Err(RpcError {
                        status: 200,
                        code: 3,
                        message: format!("execution reverted: {}", h(&revert)),
                        data: Some(json!(h(&revert))),
                    }),
                    Ok(_) => Ok(if method == "eth_estimateGas" {
                        json!(q(120_000u64))
                    } else {
                        json!("0x")
                    }),
                }
            }
            "eth_getCode" => Ok(json!(h(st
                .code
                .get(&arr::<20>(&unh(&p[0])))
                .map_or(&[][..], |c| c.as_slice())))),
            "eth_getBalance" => Ok(json!(q(st
                .balances
                .get(&arr::<20>(&unh(&p[0])))
                .cloned()
                .unwrap_or_default()))),
            "eth_getTransactionCount" => {
                let a: [u8; 20] = arr(&unh(&p[0]));
                let mut n = st.nonces.get(&a).copied().unwrap_or(0);
                if p[1] == "pending" {
                    n += st
                        .pool
                        .iter()
                        .filter(|raw| decode_signed_tx(raw).unwrap().from == a)
                        .count() as u64;
                }
                Ok(json!(q(n)))
            }
            "eth_sendRawTransaction" => {
                let raw = unh(&p[0]);
                if Self::find_tx(st, &h(&he(&[&raw]))).is_some() || st.pool.contains(&raw) {
                    return Err(err(200, -32000, "already known"));
                }
                st.pool.push(raw.clone());
                if st.auto_mine {
                    self.flush_locked(st);
                }
                if st.faults.ambiguous_sends > 0 {
                    st.faults.ambiguous_sends -= 1;
                    return Err(err(503, 0, "broadcast may be partial"));
                }
                Ok(json!(h(&he(&[&raw]))))
            }
            _ => Err(err(200, -32601, &format!("fake chain: no method {method}"))),
        }
    }

    fn flush_locked(&self, st: &mut ChainState) {
        let raws = std::mem::take(&mut st.pool);
        self.mine(st, raws);
        self.mine(st, vec![]);
    }

    /// Mine the pool, then one empty block so the transactions' block is certified.
    pub fn flush(&self) {
        let mut st = self.st.lock().unwrap();
        self.flush_locked(&mut st);
    }

    pub fn mine_empty(&self) {
        let mut st = self.st.lock().unwrap();
        self.mine(&mut st, vec![]);
    }

    pub fn drop_pool(&self) {
        self.st.lock().unwrap().pool.clear();
    }

    /// The real chain, without the hooks.
    pub fn real(&self, method: &str, params: Value) -> core::result::Result<Value, RpcError> {
        let mut st = self.st.lock().unwrap();
        st.calls.push(method.into());
        self.dispatch(&mut st, method, &params)
    }
}

impl JsonRpc for FakeChain {
    fn call(&self, method: &str, params: Value) -> core::result::Result<Value, RpcError> {
        if let Some(pre) = self.pre.lock().unwrap().as_ref() {
            if let Some(r) = pre(method, &params) {
                return r;
            }
        }
        let r = self.real(method, params.clone())?;
        Ok(match self.post.lock().unwrap().as_ref() {
            Some(post) => post(method, &params, r),
            None => r,
        })
    }
}

// ---- a whole simulated deployment --------------------------------------------------------------------

pub struct World {
    pub root: Arc<Root>,
    pub cfg: Config,
    pub chain: Arc<FakeChain>,
    pub agg: Arc<FakeAggregator>,
    pub pins: DeploymentPins,
}

pub fn pins_of(chain: &FakeChain) -> DeploymentPins {
    DeploymentPins {
        gamma: chain.gamma.clone(),
        build: Build::Test,
        vault_runtime_code_hash: he(&[&chain.vault_code]),
        max_encoded_tx_bytes: 524_288,
        user_gas_limit: 60_000_000,
        gas_reserve: 500_000,
        return_reserve_segments: 64,
        deployment_block: 1,
        state_read_only: false,
        max_jump: None,
    }
}

pub fn setup() -> World {
    let root = Arc::new(make_root(4));
    let cfg = make_config(&root, 4, 2);
    let chain = FakeChain::create(root.clone(), cfg.clone());
    let agg = Arc::new(FakeAggregator::new(root.clone()));
    let pins = pins_of(&chain);
    World {
        root,
        cfg,
        chain,
        agg,
        pins,
    }
}

/// The bound without its build check (`world.ts` WORLD_GAS).
pub struct WorldGas;

impl GasModel for WorldGas {
    fn name(&self) -> &str {
        MeasuredGasModel.name()
    }
    fn redeem_gas_limit(&self, s: &RedeemShape<'_>) -> Option<u64> {
        MeasuredGasModel.redeem_gas_limit(s)
    }
    fn deposit_gas_limit(&self) -> u64 {
        MeasuredGasModel.deposit_gas_limit()
    }
}

impl World {
    pub fn options(&self, seed: &str, store: Arc<dyn JournalStore>) -> BridgeOptions {
        let mut o = BridgeOptions::new(
            self.pins.clone(),
            self.root.trust.clone(),
            self.chain.clone(),
            self.agg.clone(),
            store,
            &derive_bridge_key(&key(seed))[..],
        );
        o.backup = Some(Box::new(|_| Ok(())));
        o.receipt_timeout_ms = Some(0);
        o.poll_ms = Some(0);
        o.sleep = Some(Box::new(|_| {}));
        // the world's verifier is a stand-in, not the calibrated build: its tests supply the bound as a wallet supplies its own model
        o.gas = Some(Box::new(WorldGas));
        o
    }

    pub fn store() -> Arc<MemoryJournalStore> {
        Arc::new(MemoryJournalStore::new())
    }

    pub fn evm_account(&self, seed: &str) -> LocalKeySigner {
        let s = LocalKeySigner::new(&key(&format!("evm {seed}")));
        self.chain.fund(&s.address(), BigUint::from(10u8).pow(24));
        s
    }

    // ---- snapshot: the chain, the aggregator and a journal, as JSON shared with the TypeScript world ----

    pub fn snapshot(&self, journal: &MemoryJournalStore) -> Value {
        let st = self.chain.st.lock().unwrap();
        let blocks: Vec<Value> = st
            .blocks
            .iter()
            .map(|b| {
                json!({
                    "header": FakeChain::header_json(b),
                    "uc": b.uc.as_ref().map(|u| h(u)),
                    "receipts": b.receipts.iter().map(|r| json!({
                        "status": r.status.to_string(), "tx": h(&r.tx), "from": h(&r.from), "revert": r.revert.as_ref().map(|x| h(x)), "gas": r.gas.to_string(),
                        "logs": r.logs.iter().map(|l| json!({"address": h(&l.address), "topics": l.topics.iter().map(|t| h(t)).collect::<Vec<_>>(), "data": h(&l.data)})).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        let map = |m: &HashMap<[u8; 20], String>| -> Value {
            Value::Object(
                m.iter()
                    .map(|(k, v)| (h(k), json!(v)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            )
        };
        let v = &st.vault;
        let (_, ids) = v.buffers();
        let agg = self.agg.st.lock().unwrap();
        json!({
            "format": SNAPSHOT_FORMAT, "version": 1, "signers": self.root.signers.len(), "bundle": h(&self.root.bundle), "pin": h(&self.root.pin),
            "round": ROUND.load(Ordering::SeqCst).to_string(), "gamma": h(&self.chain.gamma), "blocks": blocks,
            "balances": map(&st.balances.iter().map(|(k, v)| (*k, v.to_string())).collect()),
            "nonces": map(&st.nonces.iter().map(|(k, v)| (*k, v.to_string())).collect()),
            "code": map(&st.code.iter().map(|(k, v)| (*k, h(v))).collect()),
            "vault": {
                "deposits": v.n().to_string(), "segment": v.c().to_string(), "population": v.m().to_string(), "outstanding": v.q().to_string(),
                "head": h(&v.head), "prev": h(&v.prev),
                "tagWords": v.tag_words().iter().map(|ws| ws.iter().map(|w| h(&u256(w))).collect::<Vec<_>>()).collect::<Vec<_>>(),
                "ids": ids.iter().map(|b| b.iter().map(|x| h(x)).collect::<Vec<_>>()).collect::<Vec<_>>(),
            },
            "aggregator": {"time": agg.time.to_string(), "certified": agg.certified.iter().map(|(k, v)| (h(k), json!(h(v)))).collect::<Map<_, _>>()},
            "pool": st.pool.iter().map(|r| h(r)).collect::<Vec<_>>(),
            "journal": journal.dump(),
        })
    }

    /// A world and its journal from a snapshot (either plug-in's).
    pub fn restore(s: &Value) -> (World, Arc<MemoryJournalStore>) {
        assert_eq!(s["format"], SNAPSHOT_FORMAT);
        assert_eq!(s["version"], 1);
        let root = Arc::new(root_of(
            &unh(&s["bundle"]),
            arr(&unh(&s["pin"])),
            s["signers"].as_u64().unwrap() as usize,
        ));
        let round: u64 = s["round"].as_str().unwrap().parse().unwrap();
        ROUND.fetch_max(round, Ordering::SeqCst);
        let gamma = unh(&s["gamma"]);
        let cfg =
            native_bridge_sdk_ext::nb2::config::decode_config(&gamma, &test_params()).unwrap();
        let chain = FakeChain::create(root.clone(), cfg.clone());
        {
            let mut st = chain.st.lock().unwrap();
            st.blocks = s["blocks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| {
                    let header =
                        native_bridge_sdk_ext::nb2::rpc::header_of_json(&b["header"]).unwrap();
                    let hash = he(&[&encode_header(&header)]);
                    assert_eq!(json!(h(&hash)), b["header"]["hash"]);
                    Block {
                        header,
                        hash,
                        uc: b["uc"].as_str().map(|_| unh(&b["uc"])),
                        receipts: b["receipts"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|r| Rcpt {
                                status: r["status"].as_str().unwrap().parse().unwrap(),
                                tx: arr(&unh(&r["tx"])),
                                from: arr(&unh(&r["from"])),
                                revert: r["revert"].as_str().map(|_| unh(&r["revert"])),
                                gas: r["gas"].as_str().unwrap().parse().unwrap(),
                                logs: r["logs"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|l| Log {
                                        address: unh(&l["address"]),
                                        topics: l["topics"]
                                            .as_array()
                                            .unwrap()
                                            .iter()
                                            .map(unh)
                                            .collect(),
                                        data: unh(&l["data"]),
                                    })
                                    .collect(),
                            })
                            .collect(),
                    }
                })
                .collect();
            st.balances = s["balances"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| {
                    (
                        arr(&from_hex(&k[2..]).unwrap()),
                        v.as_str().unwrap().parse().unwrap(),
                    )
                })
                .collect();
            st.nonces = s["nonces"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| {
                    (
                        arr(&from_hex(&k[2..]).unwrap()),
                        v.as_str().unwrap().parse().unwrap(),
                    )
                })
                .collect();
            st.pool = s["pool"]
                .as_array()
                .map_or(vec![], |p| p.iter().map(unh).collect());
            st.code = s["code"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (arr(&from_hex(&k[2..]).unwrap()), unh(v)))
                .collect();
            let v = &s["vault"];
            let k = cfg.k as usize;
            let lb = 63 - cfg.b.leading_zeros() as usize;
            let per = 256 / lb;
            let words = v["tagWords"].as_array().unwrap();
            assert_eq!(words[0].as_array().unwrap().len(), tag_words(cfg.k, cfg.b));
            let tags: Vec<Vec<u8>> = words
                .iter()
                .map(|ws| {
                    let ws: Vec<BigUint> = ws
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|w| be_int(&unh(w)))
                        .collect();
                    (0..k)
                        .map(|i| {
                            to_u64(
                                &((&ws[i / per] >> (lb * (i % per)))
                                    & BigUint::from((1u64 << lb) - 1)),
                            )
                            .unwrap() as u8
                        })
                        .collect()
                })
                .collect();
            let ids: Vec<Vec<[u8; 32]>> = v["ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b.as_array().unwrap().iter().map(|x| arr(&unh(x))).collect())
                .collect();
            let num = |f: &str| -> u64 { v[f].as_str().unwrap().parse().unwrap() };
            st.vault.load(
                num("deposits"),
                num("segment"),
                num("population"),
                v["outstanding"].as_str().unwrap().parse().unwrap(),
                arr(&unh(&v["head"])),
                arr(&unh(&v["prev"])),
                [tags[0].clone(), tags[1].clone()],
                [ids[0].clone(), ids[1].clone()],
            );
        }
        let agg = Arc::new(FakeAggregator::new(root.clone()));
        {
            let mut a = agg.st.lock().unwrap();
            a.time = s["aggregator"]["time"].as_str().unwrap().parse().unwrap();
            a.certified = s["aggregator"]["certified"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (arr(&from_hex(&k[2..]).unwrap()), unh(v)))
                .collect();
        }
        let journal = Arc::new(MemoryJournalStore::from_map(
            s["journal"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect(),
        ));
        let pins = pins_of(&chain);
        (
            World {
                root,
                cfg,
                chain,
                agg,
                pins,
            },
            journal,
        )
    }
}

/// A recipient address from a seed (the TypeScript `HE(key(s)).slice(12)`).
pub fn recipient(seed: &str) -> [u8; 20] {
    addr_of(seed)
}
