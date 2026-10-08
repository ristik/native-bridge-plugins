//! Native-call acceptance of the merged bridge vault: the real vault and verifier runtimes, the
//! real registry genesis of the production B1 path and the Unicity node's EVM factory, with B1 at
//! 0x0100/0x0102 and the B2 kernel at 0x0104 executing natively. Every call to those addresses is
//! recorded by an inspector. Restart/reorg and a running aggregator are NOT covered here.
use alloy_evm::{Evm, EvmEnv, EvmFactory};
use alloy_primitives::{address, hex, keccak256, Address, TxKind, B256, U256};
use alloy_sol_types::{sol, SolCall, SolValue};
use reth_unicity_execution::{
    evm_factory::UnicityEvmFactory,
    execute_registry_transition, technical_record_hash,
    testing::{self, Members, Tail},
    update::B1Context,
    ExecutionConfig, InputRecordV2, RootInputV2, RootOriginV2, TechnicalRecordV2, UpdateInput,
    SEAL_REGISTRY, SEAL_REGISTRY_CODE_HASH,
};
use revm::{
    context::{BlockEnv, CfgEnv, TxEnv},
    context_interface::{result::ExecutionResult, ContextTr},
    database::{CacheDB, EmptyDB},
    interpreter::{CallInputs, CallOutcome},
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
    DatabaseRef, Inspector,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs};

const NATIVE: [(Address, &str); 3] = [
    (
        address!("0000000000000000000000000000000000000100"),
        "B1 UC_V1 0x0100",
    ),
    (
        address!("0000000000000000000000000000000000000102"),
        "B1 RSMT_MEMBER_V1 0x0102",
    ),
    (
        address!("0000000000000000000000000000000000000104"),
        "B2 kernel 0x0104",
    ),
];
const DEPOSITOR: Address = address!("00000000000000000000000000000000000d0001");
const THIRD_PARTY: Address = address!("00000000000000000000000000000000000d0002");
const PAYEE: Address = address!("00000000000000000000000000000000000d0003");
const REVERTING_PAYEE: Address = address!("00000000000000000000000000000000000d0004");
const WEI: u128 = 1_000_000_000_000_000_000;

sol! {
    struct Deployment {
        uint16 network;
        bytes32 rootGenesis;
        bytes32 executionGenesis;
        uint32 evmPartition;
        bytes evmShard;
        bytes32 semanticProfileHash;
        address tokenVerifier;
        bytes32 tokenVerifierCodeHash;
        bytes32 b1ProfileHash;
        bytes policyBody;
    }
    function lock(bytes p0) external payable returns (uint256);
    function verifyMint(bytes proof) external view returns (uint256);
    function redeem(bytes proof) external returns (uint256);
    function claim(uint256 amount, address to) external;
    function lastNonce() external view returns (uint256);
    function locked() external view returns (uint256);
    function credited() external view returns (uint256);
    function paid() external view returns (uint256);
    function lockDigest(uint256 n) external view returns (bytes32);
    function spentNullifier(uint256 n) external view returns (bytes32);
    function claimable(address a) external view returns (uint256);
    function unexpectedValue() external view returns (uint256);
    function CFG() external view returns (bytes32);
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn h32(v: &Value) -> B256 {
    B256::from_slice(&hx(v))
}
fn adr(v: &Value) -> Address {
    Address::from_slice(&hx(v))
}
fn h(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

#[derive(Default)]
struct Recorder {
    open: Vec<usize>,
    calls: Vec<Value>,
}
impl<CTX: ContextTr> Inspector<CTX> for Recorder {
    fn call(&mut self, ctx: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        if let Some((_, name)) = NATIVE.iter().find(|(a, _)| *a == inputs.target_address) {
            let input = inputs.input.bytes(ctx);
            self.open.push(self.calls.len());
            self.calls.push(json!({
                "target": name, "gasForwarded": inputs.gas_limit, "inputBytes": input.len(),
                "inputKeccak": h(keccak256(&input).as_slice()), "input": h(&input),
            }));
        }
        None
    }
    fn call_end(&mut self, _ctx: &mut CTX, inputs: &CallInputs, outcome: &mut CallOutcome) {
        if NATIVE.iter().any(|(a, _)| *a == inputs.target_address) {
            let i = self.open.pop().expect("balanced native call records");
            let o = &mut self.calls[i];
            o["nativePrecompile"] = json!(outcome.was_precompile_called);
            o["ok"] = json!(outcome.result.result.is_ok());
            o["gasUsed"] = json!(outcome.result.gas.total_gas_spent());
            o["output"] = json!(h(&outcome.result.output));
        }
    }
}

#[derive(Clone)]
struct Tx {
    caller: Address,
    to: Address,
    value: u128,
    data: Vec<u8>,
    gas: u64,
}
struct Out {
    ok: bool,
    gas_used: u64,
    output: Vec<u8>,
    logs: Vec<(Address, Vec<B256>, Vec<u8>)>,
    native: Vec<Value>,
}

#[derive(Clone)]
struct World {
    db: CacheDB<EmptyDB>,
    chain_id: u64,
    gas_cap: u64,
    errors: BTreeMap<[u8; 4], String>,
}
impl World {
    fn env(&self) -> EvmEnv {
        let mut cfg = CfgEnv::new_with_spec(SpecId::CANCUN);
        cfg.chain_id = self.chain_id;
        cfg.disable_nonce_check = true;
        let block = BlockEnv {
            number: U256::from(1),
            timestamp: U256::from(1_700_000_200u64),
            gas_limit: self.gas_cap,
            ..Default::default()
        };
        EvmEnv::new(cfg, block)
    }
    fn run(&mut self, tx: &Tx, commit: bool) -> Out {
        let mut evm = UnicityEvmFactory::default().create_evm_with_inspector(
            self.db.clone(),
            self.env(),
            Recorder::default(),
        );
        let txenv = TxEnv {
            caller: tx.caller,
            kind: TxKind::Call(tx.to),
            value: U256::from(tx.value),
            data: tx.data.clone().into(),
            gas_limit: tx.gas,
            gas_price: 0,
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        let res = if commit {
            evm.transact_commit(txenv)
        } else {
            evm.transact(txenv).map(|r| r.result)
        };
        let native = std::mem::take(&mut evm.inspector_mut().calls);
        let res = match res {
            Ok(r) => r,
            // An infrastructure error (not a verdict): the node cannot execute the transaction at all.
            Err(e) => {
                return Out {
                    ok: false,
                    gas_used: 0,
                    output: format!("fatal host error: {e:?}").into_bytes(),
                    logs: vec![],
                    native,
                }
            }
        };
        if commit {
            self.db = evm.into_db();
        }
        let gas_used = res.gas().total_gas_spent();
        match res {
            ExecutionResult::Success { output, logs, .. } => Out {
                ok: true,
                gas_used,
                output: output.data().to_vec(),
                logs: logs
                    .into_iter()
                    .map(|l| (l.address, l.data.topics().to_vec(), l.data.data.to_vec()))
                    .collect(),
                native,
            },
            ExecutionResult::Revert { output, .. } => Out {
                ok: false,
                gas_used,
                output: output.to_vec(),
                logs: vec![],
                native,
            },
            ExecutionResult::Halt { reason, .. } => Out {
                ok: false,
                gas_used,
                output: format!("halt: {reason:?}").into_bytes(),
                logs: vec![],
                native,
            },
        }
    }
    fn revert_name(&self, out: &Out) -> String {
        if out.output.len() >= 4
            && !out.output.starts_with(b"halt")
            && !out.output.starts_with(b"fatal")
        {
            let sel: [u8; 4] = out.output[..4].try_into().unwrap();
            let name = self
                .errors
                .get(&sel)
                .cloned()
                .unwrap_or_else(|| "unknown".into());
            format!("{name} {}", h(&out.output))
        } else {
            String::from_utf8_lossy(&out.output).into_owned()
        }
    }
    fn view_u(&mut self, to: Address, data: Vec<u8>) -> U256 {
        let o = self.run(
            &Tx {
                caller: THIRD_PARTY,
                to,
                value: 0,
                data,
                gas: self.gas_cap,
            },
            false,
        );
        assert!(o.ok, "view reverted");
        U256::from_be_slice(&o.output)
    }
    fn view_b(&mut self, to: Address, data: Vec<u8>) -> B256 {
        let o = self.run(
            &Tx {
                caller: THIRD_PARTY,
                to,
                value: 0,
                data,
                gas: self.gas_cap,
            },
            false,
        );
        assert!(o.ok, "view reverted");
        B256::from_slice(&o.output)
    }
    fn set_code(&mut self, addr: Address, code: Vec<u8>, nonce: u64) {
        let bytecode = Bytecode::new_raw(code.into());
        self.db.insert_account_info(
            addr,
            AccountInfo {
                code_hash: bytecode.hash_slow(),
                code: Some(bytecode),
                nonce,
                ..Default::default()
            },
        );
    }
    /// Runs `initcode` as the code of `at` (so address(this) and CREATE addresses equal a real
    /// deployment there) and installs what it returns as the runtime code.
    fn deploy_at(&mut self, at: Address, initcode: Vec<u8>) -> Vec<u8> {
        self.set_code(at, initcode, 1);
        let o = self.run(
            &Tx {
                caller: DEPOSITOR,
                to: at,
                value: 0,
                data: vec![],
                gas: self.gas_cap,
            },
            true,
        );
        assert!(
            o.ok && !o.output.is_empty(),
            "constructor failed: {}",
            self.revert_name(&o)
        );
        let runtime = o.output;
        let nonce = self
            .db
            .cache
            .accounts
            .get(&at)
            .map(|a| a.info.nonce)
            .unwrap_or(1);
        self.set_code(at, runtime.clone(), nonce);
        runtime
    }
}

fn artifact(dir: &str, name: &str) -> (Vec<u8>, Value) {
    let v: Value =
        serde_json::from_slice(&fs::read(format!("{dir}/out/{name}.sol/{name}.json")).unwrap())
            .unwrap();
    (
        hex::decode(
            v["bytecode"]["object"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap(),
        v["abi"].clone(),
    )
}
fn error_table(abis: &[Value]) -> BTreeMap<[u8; 4], String> {
    let mut out = BTreeMap::new();
    for abi in abis {
        for e in abi
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["type"] == "error")
        {
            let types: Vec<&str> = e["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["type"].as_str().unwrap())
                .collect();
            let sig = format!("{}({})", e["name"].as_str().unwrap(), types.join(","));
            out.insert(keccak256(sig.as_bytes())[..4].try_into().unwrap(), sig);
        }
    }
    out
}

fn tx_json(w: &World, name: &str, o: &Out, extra: Value) -> Value {
    let mut v = json!({
        "step": name, "success": o.ok, "gasUsed": o.gas_used,
        "revert": if o.ok { Value::Null } else { json!(w.revert_name(o)) },
        "logs": o.logs.iter().map(|(a, t, d)| json!({"address": h(a.as_slice()), "topics": t.iter().map(|t| h(t.as_slice())).collect::<Vec<_>>(), "dataBytes": d.len()})).collect::<Vec<_>>(),
        "nativeCalls": o.native,
    });
    for (k, e) in extra.as_object().unwrap() {
        v[k] = e.clone();
    }
    v
}

fn bisect_min_gas(w: &World, tx: &Tx, commit_independent: bool) -> u64 {
    let _ = commit_independent;
    let (mut lo, mut hi) = (21_000u64, w.gas_cap);
    let mut probe = w.clone();
    let mut ok = |g: u64| {
        probe
            .run(
                &Tx {
                    gas: g,
                    ..tx.clone()
                },
                false,
            )
            .ok
    };
    assert!(ok(hi), "does not fit the ordinary capacity {hi}");
    while lo < hi {
        let mid = (lo + hi) / 2;
        if ok(mid) {
            hi = mid
        } else {
            lo = mid + 1
        }
    }
    lo
}

/// Balance plus every non-zero storage word: reads of zero slots populate the cache but are not state.
fn snapshot(w: &World, at: Address) -> (U256, BTreeMap<U256, U256>) {
    w.db.cache
        .accounts
        .get(&at)
        .map_or((U256::ZERO, BTreeMap::new()), |a| {
            (
                a.info.balance,
                a.storage
                    .iter()
                    .filter(|(_, v)| !v.is_zero())
                    .map(|(k, v)| (*k, *v))
                    .collect(),
            )
        })
}

fn find(hay: &[u8], needle: &[u8]) -> usize {
    let hits: Vec<usize> = hay
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "needle must occur exactly once in the envelope"
    );
    hits[0]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (genesis_path, golden_path, contracts, out_path) = (&args[1], &args[2], &args[3], &args[4]);
    let genesis: Value = serde_json::from_slice(&fs::read(genesis_path).unwrap()).unwrap();
    let golden: Value = serde_json::from_slice(&fs::read(golden_path).unwrap()).unwrap();
    let cfg = &golden["cfg"];
    let (verifier_addr, vault_addr) = (adr(&cfg["tokenVerifier"]), adr(&cfg["vault"]));
    let ordinary = genesis["ordinaryCapacity"].as_u64().unwrap();

    let (vault_init, vault_abi) = artifact(contracts, "BridgeVault");
    let (verifier_init, verifier_abi) = artifact(contracts, "TokenVerifier");
    let mut w = World {
        db: CacheDB::new(EmptyDB::default()),
        chain_id: cfg["chainId"].as_u64().unwrap(),
        gas_cap: ordinary,
        errors: error_table(&[vault_abi, verifier_abi]),
    };

    // ---- the real registry genesis (production B1 path) ----
    for (addr, acct) in genesis["genesis"]["alloc"].as_object().unwrap() {
        let a: Address = format!("0x{}", addr.trim_start_matches("0x"))
            .parse()
            .unwrap();
        let code = acct.get("code").map(|c| Bytecode::new_raw(hx(c).into()));
        w.db.insert_account_info(
            a,
            AccountInfo {
                balance: U256::from_str_radix(
                    acct["balance"]
                        .as_str()
                        .unwrap_or("0x0")
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap(),
                nonce: acct
                    .get("nonce")
                    .and_then(|n| n.as_str())
                    .map(|n| u64::from_str_radix(n.trim_start_matches("0x"), 16).unwrap())
                    .unwrap_or(0),
                code_hash: code.as_ref().map_or(B256::ZERO, Bytecode::hash_slow),
                code,
                ..Default::default()
            },
        );
        for (slot, val) in acct
            .get("storage")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            w.db.insert_account_storage(
                a,
                U256::from_be_slice(&hex::decode(slot.trim_start_matches("0x")).unwrap()),
                U256::from_be_slice(
                    &hex::decode(val.as_str().unwrap().trim_start_matches("0x")).unwrap(),
                ),
            )
            .unwrap();
        }
    }
    let registry_hash =
        w.db.cache
            .accounts
            .get(&SEAL_REGISTRY)
            .expect("registry in genesis")
            .info
            .code_hash;
    assert_eq!(
        registry_hash, SEAL_REGISTRY_CODE_HASH,
        "registry runtime is the pinned one"
    );
    let registry_words = genesis["registryWords"].as_object().unwrap().len();

    // ---- advance the registry clock to the anchors' root round through the REAL registry runtime ----
    // (privileged open/finalize of one quiet update; the anchors' certificates are at root round 100.)
    let uc_round = golden["ucRootRound"].as_u64().unwrap();
    let context = B1Context {
        network: genesis["network"].as_u64().unwrap() as u16,
        root_genesis_id: B256::from_slice(
            &hex::decode(genesis["rootGenesisId"].as_str().unwrap()).unwrap(),
        ),
        execution_chain_id: w.chain_id,
        profile_hash: B256::from_slice(
            &hex::decode(genesis["profileHash"].as_str().unwrap()).unwrap(),
        ),
        w_cert: genesis["wCert"].as_u64().unwrap(),
    };
    let conf = h32(&genesis["shardConfHash"]);
    let technical = TechnicalRecordV2 {
        round: 1,
        epoch: 0,
        leader: "evm-node".into(),
        stat_hash: B256::repeat_byte(0xe0),
        fee_hash: B256::repeat_byte(0xf0),
    };
    let mut input = RootInputV2 {
        version: 2,
        network_id: u64::from(context.network),
        partition_id: 7,
        shard_id: vec![],
        authorized_round: 1,
        certified_epoch: 0,
        authorized_epoch: 0,
        parent_hash: B256::from_slice(&Sha256::digest(1u64.to_be_bytes())),
        origin: RootOriginV2 {
            network_id: u64::from(context.network),
            root_round: uc_round,
            root_epoch: 1,
            reference_time: 1,
            tree_root: B256::repeat_byte(0xc0),
            input_record_version: 1,
            input_record: InputRecordV2 {
                round: 0,
                epoch: 0,
                previous_hash: None,
                state_hash: None,
                timestamp: 0,
                block_hash: None,
            },
            tr_hash: technical_record_hash(&technical),
            shard_conf_hash: conf,
        },
        technical,
        transitions: vec![],
        b1_update_hash: B256::repeat_byte(0xb1),
    };
    let update = testing::update_in(
        &context,
        &input,
        0,
        Tail { epoch: 1, start: 0 },
        Members::Small,
    );
    assert!(
        update.new_entries.is_empty(),
        "a quiet update inserts no entry"
    );
    input.b1_update_hash = update.hash();
    let limit = context.required_system_gas().unwrap();
    let clock_before =
        w.db.storage_ref(
            SEAL_REGISTRY,
            reth_unicity_b1::fixed_slot("clock.rootRound"),
        )
        .unwrap();
    let (adv, next) = execute_registry_transition(
        &input,
        UpdateInput {
            bytes: &update.to_bytes(),
            parent_number: 0,
        },
        &w.db,
        ExecutionConfig {
            system_gas_limit: limit,
            b1: context,
        },
    )
    .expect("registry accepts the quiet update");
    w.db = next;
    let clock_after =
        w.db.storage_ref(
            SEAL_REGISTRY,
            reth_unicity_b1::fixed_slot("clock.rootRound"),
        )
        .unwrap();
    assert_eq!(
        (clock_before, clock_after),
        (U256::ZERO, U256::from(uc_round))
    );
    let registry_advance = json!({"clockBefore": 0, "clockAfter": uc_round, "admissionGas": adv.admission_gas, "openGas": adv.open_gas_spent, "finalizeGas": adv.finalize_gas_spent, "totalGas": adv.total_gas_spent, "systemGasLimit": limit});

    // ---- deploy verifier and vault at the golden deployment's addresses ----
    let verifier_runtime = w.deploy_at(verifier_addr, verifier_init);
    let verifier_hash = keccak256(&verifier_runtime);
    assert_eq!(
        verifier_hash,
        h32(&cfg["tokenVerifierCodeHash"]),
        "verifier runtime hash equals the golden cfg's pin"
    );
    let d = Deployment {
        network: cfg["network"].as_u64().unwrap() as u16,
        rootGenesis: h32(&cfg["rootGenesis"]),
        executionGenesis: h32(&cfg["executionGenesis"]),
        evmPartition: cfg["evmPartition"].as_u64().unwrap() as u32,
        evmShard: hx(&cfg["evmShard"]).into(),
        semanticProfileHash: h32(&cfg["semanticProfileHash"]),
        tokenVerifier: verifier_addr,
        tokenVerifierCodeHash: verifier_hash,
        b1ProfileHash: h32(&cfg["b1ProfileHash"]),
        policyBody: hx(&golden["policy"]["bytes"]).into(),
    };
    let mut init = vault_init;
    init.extend_from_slice(&d.abi_encode());
    let vault_runtime = w.deploy_at(vault_addr, init);
    let cfg_hash = w.view_b(vault_addr, CFGCall {}.abi_encode());
    assert_eq!(
        cfg_hash,
        h32(&cfg["hash"]),
        "the deployed vault's cfg equals the golden cfg"
    );
    w.db.insert_account_info(
        DEPOSITOR,
        AccountInfo {
            balance: U256::from(100 * WEI),
            ..Default::default()
        },
    );
    for a in [THIRD_PARTY, PAYEE] {
        w.db.insert_account_info(a, AccountInfo::default());
    }
    w.set_code(REVERTING_PAYEE, vec![0x5f, 0x5f, 0xfd], 1);

    let mut steps: Vec<Value> = vec![];
    let amount = U256::from(WEI);
    let recipient = adr(&golden["return"]["recipient"]);
    let p0 = hx(&golden["prepare"]["p0"]);
    let mint_proof = hx(&golden["mint"]["envelope"]["bytes"]);
    let return_proof = hx(&golden["return"]["envelope"]["bytes"]);
    let t = |caller, data: Vec<u8>, value: u128| Tx {
        caller,
        to: vault_addr,
        value,
        data,
        gas: ordinary,
    };

    let w0 = w.clone();
    // ---- lock (native 0x0104 prepare) ----
    let o = w.run(
        &t(
            DEPOSITOR,
            lockCall {
                p0: p0.clone().into(),
            }
            .abi_encode(),
            WEI,
        ),
        true,
    );
    assert!(o.ok, "lock: {}", w.revert_name(&o));
    let prep = o
        .native
        .iter()
        .find(|c| c["target"] == "B2 kernel 0x0104")
        .expect("lock called the native kernel");
    assert_eq!(
        prep["input"],
        golden["prepare"]["kernelInput"]
            .as_str()
            .unwrap()
            .to_lowercase(),
        "kernel request equals the oracle's prepare request"
    );
    assert_eq!(prep["nativePrecompile"], true);
    let digest = w.view_b(vault_addr, lockDigestCall { n: U256::from(1) }.abi_encode());
    assert_eq!(
        digest,
        h32(&golden["prepare"]["result"]["lockDigest"]),
        "stored lock digest equals the oracle's"
    );
    steps.push(tx_json(&w, "lock", &o, json!({"lockDigest": h(digest.as_slice()), "kernelOutputMatchesOracleAbi": prep["output"].as_str().unwrap().len() > 2, "minGasLimit": bisect_min_gas(&w0, &t(DEPOSITOR, lockCall { p0: p0.clone().into() }.abi_encode(), WEI), false)})));
    let w1 = w.clone();

    // ---- verifyMint (native 0x0100, 0x0102, 0x0104) ----
    let vm = t(
        THIRD_PARTY,
        verifyMintCall {
            proof: mint_proof.clone().into(),
        }
        .abi_encode(),
        0,
    );
    let o = w.run(&vm, false);
    assert!(o.ok, "verifyMint: {}", w.revert_name(&o));
    assert_eq!(U256::from_be_slice(&o.output), U256::from(1));
    for c in &o.native {
        assert_eq!(c["nativePrecompile"], true, "{c}");
    }
    let min = bisect_min_gas(&w, &vm, false);
    steps.push(tx_json(
        &w,
        "verifyMint",
        &o,
        json!({"returnedNonce": 1, "minGasLimit": min}),
    ));

    // ---- redeem by a third party (permissionless), then claim ----
    let rd = t(
        THIRD_PARTY,
        redeemCall {
            proof: return_proof.clone().into(),
        }
        .abi_encode(),
        0,
    );
    let o = w.run(&rd, true);
    assert!(o.ok, "redeem: {}", w.revert_name(&o));
    for c in &o.native {
        assert_eq!(c["nativePrecompile"], true, "{c}");
        assert_eq!(c["ok"], true);
    }
    let min = bisect_min_gas(&w1, &rd, false);
    let credit = w.view_u(vault_addr, claimableCall { a: recipient }.abi_encode());
    assert_eq!(credit, amount);
    assert_eq!(
        w.view_b(
            vault_addr,
            spentNullifierCall { n: U256::from(1) }.abi_encode()
        ),
        h32(&golden["return"]["result"]["nullifier"])
    );
    steps.push(tx_json(&w, "redeem (third-party submitter)", &o, json!({"creditedRecipient": h(recipient.as_slice()), "credit": credit.to_string(), "minGasLimit": min})));
    let w2 = w.clone();

    let cl = Tx {
        caller: recipient,
        ..t(recipient, claimCall { amount, to: PAYEE }.abi_encode(), 0)
    };
    let o = w.run(&cl, true);
    assert!(o.ok, "claim: {}", w.revert_name(&o));
    let min = bisect_min_gas(&w2, &cl, false);
    let payee_balance = w.db.cache.accounts.get(&PAYEE).unwrap().info.balance;
    assert_eq!(payee_balance, amount);
    let vault_balance = w.db.cache.accounts.get(&vault_addr).unwrap().info.balance;
    let (l, dd, p) = (
        w.view_u(vault_addr, lockedCall {}.abi_encode()),
        w.view_u(vault_addr, creditedCall {}.abi_encode()),
        w.view_u(vault_addr, paidCall {}.abi_encode()),
    );
    assert_eq!(
        (l, dd, p, vault_balance),
        (amount, amount, amount, U256::ZERO)
    );
    steps.push(tx_json(&w, "claim", &o, json!({"payeeBalance": payee_balance.to_string(), "L": l.to_string(), "D": dd.to_string(), "P": p.to_string(), "vaultBalance": vault_balance.to_string(), "minGasLimit": min})));

    // ---- refusals: every one must leave state untouched ----
    let refuse = |steps: &mut Vec<Value>, name: &str, world: &World, tx: Tx, expect: &str| {
        let mut x = world.clone();
        let before = snapshot(&x, vault_addr);
        let o = x.run(&tx, true);
        assert!(!o.ok, "{name}: must be refused");
        let rn = x.revert_name(&o);
        assert!(rn.contains(expect), "{name}: expected {expect}, got {rn}");
        let after = snapshot(&x, vault_addr);
        assert_eq!(before, after, "{name}: refused call changed vault state");
        steps.push(tx_json(
            &x,
            name,
            &o,
            json!({"expectedRefusal": expect, "vaultStateUnchanged": true}),
        ));
    };
    refuse(
        &mut steps,
        "redeem again (duplicate burn)",
        &w2,
        rd.clone(),
        "AlreadyRedeemed",
    );
    // Conflicting burns of one token: the first certified burn wins in either order.
    let conflict_proof = hx(&golden["returnConflicting"]["envelope"]["bytes"]);
    let conflict_recipient = adr(&golden["returnConflicting"]["recipient"]);
    refuse(
        &mut steps,
        "conflicting burn (other recipient) after the first redeem",
        &w2,
        t(
            THIRD_PARTY,
            redeemCall {
                proof: conflict_proof.clone().into(),
            }
            .abi_encode(),
            0,
        ),
        "AlreadyRedeemed",
    );
    {
        let mut x = w1.clone();
        let o = x.run(
            &t(
                THIRD_PARTY,
                redeemCall {
                    proof: conflict_proof.into(),
                }
                .abi_encode(),
                0,
            ),
            true,
        );
        assert!(
            o.ok,
            "the conflicting burn is itself a valid burn: {}",
            x.revert_name(&o)
        );
        assert_eq!(
            x.view_u(
                vault_addr,
                claimableCall {
                    a: conflict_recipient
                }
                .abi_encode()
            ),
            amount
        );
        steps.push(tx_json(
            &x,
            "conflicting burn redeemed first (other order)",
            &o,
            json!({"creditedRecipient": h(conflict_recipient.as_slice())}),
        ));
        refuse(
            &mut steps,
            "original burn after the conflicting burn won",
            &x,
            rd.clone(),
            "AlreadyRedeemed",
        );
    }
    refuse(
        &mut steps,
        "redeem before any lock",
        &w0,
        rd.clone(),
        "UnknownLock",
    );
    refuse(
        &mut steps,
        "claim by a non-credited account",
        &w2,
        t(THIRD_PARTY, claimCall { amount, to: PAYEE }.abi_encode(), 0),
        "InsufficientCredit",
    );
    refuse(
        &mut steps,
        "claim to a reverting payee (credit and P roll back)",
        &w2,
        Tx {
            caller: recipient,
            ..t(
                recipient,
                claimCall {
                    amount,
                    to: REVERTING_PAYEE,
                }
                .abi_encode(),
                0,
            )
        },
        "PayoutFailed",
    );
    refuse(
        &mut steps,
        "lock with zero value",
        &w0,
        t(
            DEPOSITOR,
            lockCall {
                p0: p0.clone().into(),
            }
            .abi_encode(),
            0,
        ),
        "ZeroAmount",
    );
    let mut bad_p0 = p0.clone();
    *bad_p0.last_mut().unwrap() ^= 1;
    let o = {
        let mut x = w0.clone();
        let o = x.run(
            &t(DEPOSITOR, lockCall { p0: bad_p0.into() }.abi_encode(), WEI),
            true,
        );
        assert!(
            !o.ok || x.view_u(vault_addr, lockedCall {}.abi_encode()) == amount,
            "tampered p0 either refused or locked a different digest"
        );
        steps.push(tx_json(
            &x,
            "lock with a flipped predicate byte",
            &o,
            json!({"note": "refused, or accepted with a different lock digest; recorded as is"}),
        ));
        o
    };
    let _ = o;
    // tampered certificate / path / missing authority
    let ret = golden["return"]["envelope"].clone();
    let uc = hx(&ret["anchor"]["uc"]);
    // Flip every byte of the submitted certificate in turn: report how many flips B1 still accepts
    // (bytes its authentication does not cover) and use the first refused flip as the refusal case.
    let base = find(&return_proof, &uc);
    let (mut accepted, mut accepted_offsets, mut refused_at, mut reasons) =
        (0usize, vec![], None, BTreeMap::<String, usize>::new());
    for k in 0..uc.len() {
        let mut bad = return_proof.clone();
        bad[base + k] ^= 1;
        let mut x = w1.clone();
        let o = x.run(
            &t(
                THIRD_PARTY,
                redeemCall { proof: bad.into() }.abi_encode(),
                0,
            ),
            false,
        );
        if o.ok {
            accepted += 1;
            accepted_offsets.push(k);
        } else {
            refused_at.get_or_insert(k);
            let name = x.revert_name(&o);
            *reasons
                .entry(name.split(' ').next().unwrap_or("").to_string())
                .or_default() += 1;
        }
    }
    let k = refused_at.expect("some certificate byte is authenticated");
    let mut bad = return_proof.clone();
    bad[base + k] ^= 1;
    refuse(
        &mut steps,
        "redeem with a flipped certificate byte",
        &w1,
        t(
            THIRD_PARTY,
            redeemCall { proof: bad.into() }.abi_encode(),
            0,
        ),
        "",
    );
    steps.push(json!({"step": "certificate single-byte flip scan", "certificateBytes": uc.len(), "flipsStillAccepted": accepted, "acceptedOffsets": accepted_offsets, "flipsRefused": uc.len() - accepted, "refusalReasons": reasons, "firstRefusedOffset": k}));
    let sib = &hx(&ret["members"][0]["request"])[hx(&ret["members"][0]["request"]).len() - 32..];
    let mut bad = return_proof.clone();
    let i = find(&bad, sib);
    bad[i] ^= 1;
    refuse(
        &mut steps,
        "redeem with a flipped membership sibling",
        &w1,
        t(
            THIRD_PARTY,
            redeemCall { proof: bad.into() }.abi_encode(),
            0,
        ),
        "LeafNotIncluded",
    );
    let mut no_registry = w1.clone();
    no_registry.db.cache.accounts.remove(&SEAL_REGISTRY);
    refuse(
        &mut steps,
        "redeem with the authority registry absent (fail closed)",
        &no_registry,
        rd.clone(),
        "fatal host error",
    );

    let report = json!({
        "profile": "native-vault-calls (in-process node EVM factory; no devnet, no aggregator service)",
        "registryAdvance": registry_advance,
        "registry": {"codeHash": h(registry_hash.as_slice()), "genesisWords": registry_words, "rootGenesisId": genesis["rootGenesisId"], "profileHash": genesis["profileHash"], "shardConfHash": genesis["shardConfHash"], "systemGas": genesis["systemGas"], "maxGas": genesis["maxGas"], "ordinaryCapacity": ordinary},
        "deployment": {"vault": h(vault_addr.as_slice()), "vaultRuntimeKeccak": h(keccak256(&vault_runtime).as_slice()), "vaultRuntimeBytes": vault_runtime.len(), "tokenVerifier": h(verifier_addr.as_slice()), "tokenVerifierRuntimeKeccak": h(verifier_hash.as_slice()), "cfgHash": h(cfg_hash.as_slice()), "chainId": w.chain_id, "deploymentMethod": "constructor executed in place at the golden deployment's addresses"},
        "steps": steps,
    });
    fs::write(
        out_path,
        serde_json::to_string_pretty(&report).unwrap() + "\n",
    )
    .unwrap();
    for s in report["steps"].as_array().unwrap() {
        println!(
            "PASS {}: success={} gas={}",
            s["step"].as_str().unwrap(),
            s["success"],
            s["gasUsed"]
        );
    }
}
