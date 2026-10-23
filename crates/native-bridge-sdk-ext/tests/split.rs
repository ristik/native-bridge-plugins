//! The protocol 6 split corpus (bft-core `bridgeprofile/testdata/split-corpus`, sealed under `protocol/vectors/split`),
//! replayed by an implementation independent of the Go oracle that generated it (and of the TypeScript plug-in's).

use std::collections::BTreeMap;

use native_bridge_sdk_ext::compose::{
    compose_input, compose_status_name_v2, decode_compose_output_v2, COMPOSE_OUTPUT_BYTES_V2,
};
use native_bridge_sdk_ext::deployment::Deployment;
use native_bridge_sdk_ext::envelope::{check_anchors, check_policy_body, plan_anchors, Envelope};
use native_bridge_sdk_ext::error::Family;
use native_bridge_sdk_ext::header::HeaderProfile;
use native_bridge_sdk_ext::history::decode_predicate_bytes;
use native_bridge_sdk_ext::lineage::{compose_offline_v2, verify_lineage_return};
use native_bridge_sdk_ext::profile::{from_hex, h, Cfg, Policy};
use native_bridge_sdk_ext::scan::scan_one;
use native_bridge_sdk_ext::split::{
    decode_split_justification, decode_sum_proof_item, split_manifest_bytes,
    split_output_commitment, sum_leaf_hash, sum_node_hash, sum_proof_bytes, verify_sum_proof,
    SumStep,
};
use native_bridge_sdk_ext::NativeError as E;
use num_bigint::BigUint;
use serde_json::Value;
use unicity_token::cbor::{encode_array, encode_byte_string, encode_tag, encode_uint};

fn root() -> String {
    format!("{}/../../protocol", env!("CARGO_MANIFEST_DIR"))
}

fn load(rel: &str) -> Value {
    serde_json::from_slice(&std::fs::read(format!("{}/{rel}", root())).unwrap()).unwrap()
}

fn cases(family: &str) -> Vec<Value> {
    load(&format!("vectors/split/{family}/cases.json"))["cases"]
        .as_array()
        .unwrap()
        .clone()
}

fn hx(s: &Value) -> Vec<u8> {
    from_hex(s.as_str().unwrap()).unwrap()
}

fn b32(s: &str) -> [u8; 32] {
    from_hex(s).unwrap().try_into().unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn family(f: Family) -> &'static str {
    match f {
        Family::Malformed => "malformed",
        Family::Invalid => "invalid",
        Family::Budget => "budget",
        Family::Unavailable => "unavailable",
    }
}

fn dev() -> Deployment {
    let f = load("vectors/config/fixtures.json");
    let d = &f["fixtures"]["dev"];
    Deployment::new(
        Cfg::from_bytes(&hx(&d["cfg"])).unwrap(),
        hx(&f["pins"]["dev"]["vaultCodeHash"]).try_into().unwrap(),
        [0; 32],
        HeaderProfile { fields: 20 },
        Policy::from_bytes(&hx(&d["policyBody"])).unwrap(),
    )
    .unwrap()
}

/// abi.encode(uint8 op, bytes cfg, bytes envelope) read back.
fn read_compose_input(b: &[u8]) -> (u8, Vec<u8>, Vec<u8>) {
    let w = |o: usize| u64::from_be_bytes(b[o + 24..o + 32].try_into().unwrap()) as usize;
    let field = |off: usize| b[off + 32..off + 32 + w(off)].to_vec();
    (w(0) as u8, field(w(32)), field(w(64)))
}

/// The reasons only B1 decides (certificate signatures and quorum, RSMT membership): the plug-ins' composition steps all pass.
const B1_ONLY: [&str; 2] = ["ErrAnchorAuth", "ErrLeafProof"];

fn verdict(r: Result<(), E>) -> (String, Option<&'static str>) {
    match r {
        Ok(()) => ("ok".into(), None),
        Err(e) => (e.name().to_string(), Some(family(e.family()))),
    }
}

#[test]
fn every_split_file_is_in_the_sealed_manifest_unedited() {
    let sums = std::fs::read_to_string(format!("{}/vectors/SHA256SUMS", root())).unwrap();
    let listed: Vec<(&str, &str)> = sums
        .lines()
        .filter_map(|l| {
            let (d, f) = l.split_once("  ")?;
            f.starts_with("split/").then_some((f, d))
        })
        .collect();
    assert_eq!(listed.len(), 6);
    for (file, digest) in listed {
        assert_eq!(
            hex(&h(
                &std::fs::read(format!("{}/vectors/{file}", root())).unwrap()
            )),
            digest,
            "{file}"
        );
    }
    assert_eq!(
        hex(&h(sums.as_bytes())),
        std::fs::read_to_string(format!("{}/vectors/MANIFEST.sha256", root()))
            .unwrap()
            .trim()
    );
    assert_eq!(
        load("vectors/split/config/fixtures.json")["nativeBridgeProtoVersion"],
        6
    );
    assert_eq!(
        hex(&dev().cfg_hash),
        "67c007348bc786d6a4d31f1c55fa35ef5d42e37eec63a7b91e32594d190a907a"
    );
}

#[test]
fn every_allocation_proof_manifest_and_commitment_is_the_oracles() {
    let (mut trees, mut proofs, mut commitments) = (0, 0, 0);
    for c in cases("sum-tree") {
        let id = c["id"].as_str().unwrap();
        let aux = &c["aux"];
        match c["op"].as_str().unwrap() {
            "sum-tree" => {
                // the builder is the SDK's; the plug-ins verify: every leaf's recorded proof reconstructs the root and the total
                if c["expected"]["status"] != "ok" {
                    continue;
                }
                let v = &c["expected"]["values"];
                let root = b32(v["root"].as_str().unwrap());
                assert_eq!(hex(&split_manifest_bytes(&root)), v["manifest"], "{id}");
                assert_eq!(
                    hex(&h(&split_manifest_bytes(&root))),
                    v["reasonHash"],
                    "{id}"
                );
                let total: BigUint = v["total"].as_str().unwrap().parse().unwrap();
                for (i, leaf) in aux["leaves"].as_str().unwrap().split(';').enumerate() {
                    let f: Vec<&str> = leaf.split(':').collect();
                    let bytes = hx(&v[format!("proof.{i}")]);
                    let p = decode_sum_proof_item(&scan_one(&bytes).unwrap()).unwrap();
                    assert_eq!(
                        sum_proof_bytes(&p),
                        bytes,
                        "{id}: proof {i} re-encodes exactly"
                    );
                    let amount: BigUint = f[2].parse().unwrap();
                    assert_eq!(
                        verify_sum_proof(&p, &b32(f[0]), &b32(f[1]), &amount, &root),
                        Some(total.clone()),
                        "{id}: proof {i}"
                    );
                }
                trees += 1;
            }
            "sum-proof" => {
                let input = hx(&c["input"]);
                let got = scan_one(&input)
                    .and_then(|it| decode_sum_proof_item(&it))
                    .and_then(|p| {
                        let amount: BigUint = aux["amount"].as_str().unwrap().parse().unwrap();
                        let root = b32(aux["root"].as_str().unwrap());
                        verify_sum_proof(
                            &p,
                            &b32(aux["key"].as_str().unwrap()),
                            &b32(aux["data"].as_str().unwrap()),
                            &amount,
                            &root,
                        )
                        .map(|s| (s, p.len()))
                        .ok_or(E::SplitProof)
                    });
                let want = &c["expected"];
                match got {
                    Ok((sum, steps)) => {
                        assert_eq!(want["status"], "ok", "{id}");
                        assert_eq!(want["values"]["sum"], sum.to_string(), "{id}");
                        assert_eq!(want["values"]["steps"], steps.to_string(), "{id}");
                    }
                    Err(e) => {
                        assert_eq!(want["reason"], e.name().to_string(), "{id}");
                        assert_eq!(want["family"], family(e.family()), "{id}");
                    }
                }
                proofs += 1;
            }
            "split-commitment" => {
                let s = |k: &str| aux[k].as_str().unwrap();
                let d = split_output_commitment(
                    &b32(s("source")),
                    s("network").parse().unwrap(),
                    &decode_predicate_bytes(&from_hex(s("recipient")).unwrap()).unwrap(),
                    &b32(s("salt")),
                    &b32(s("childId")),
                    &b32(s("type")),
                    &from_hex(s("data")).unwrap(),
                );
                assert_eq!(hex(&d), c["expected"]["values"]["commitment"], "{id}");
                commitments += 1;
            }
            op => panic!("{id}: unknown op {op}"),
        }
    }
    assert!(
        trees >= 5 && proofs >= 10 && commitments >= 5,
        "{trees} {proofs} {commitments}"
    );
}

#[test]
fn every_lineage_case_gets_the_oracles_verdict_and_result() {
    let dep = dev();
    let all = cases("lineage");
    assert!(all.len() >= 39);
    let mut ok = 0;
    for c in &all {
        let id = c["id"].as_str().unwrap();
        let env = Envelope::decode(&hx(&c["input"])).unwrap();
        let mut res = None;
        let got = verdict((|| {
            let pol = check_policy_body(&dep.cfg, &env)?;
            let r = verify_lineage_return(&dep, &env.history)?;
            let sids: Vec<[u8; 32]> = r.outcome.leaves.iter().map(|l| l.sid).collect();
            let times: Vec<u64> = r.outcome.leaves.iter().map(|l| l.reference_time).collect();
            check_anchors(&env, &plan_anchors(&pol, &env, &sids)?, &times)?;
            res = Some(r);
            Ok(())
        })());
        let want = &c["expected"];
        if want["status"] == "error" && B1_ONLY.contains(&want["reason"].as_str().unwrap()) {
            assert_eq!(got.0, "ok", "{id}: every step before B1 passes");
            continue;
        }
        if want["status"] == "error" {
            assert_eq!(got.0, want["reason"].as_str().unwrap(), "{id}");
            assert_eq!(got.1, want["family"].as_str(), "{id}");
            continue;
        }
        assert_eq!(got.0, "ok", "{id}");
        let r = res.unwrap();
        let s = &want["split"];
        let o = &r.outcome;
        for (k, v) in [
            ("cfg", hex(&o.cfg)),
            ("nonce", o.nonce.to_string()),
            ("amount", hex(&o.amount)),
            ("tokenId", hex(&o.token_id)),
            ("salt", hex(&o.salt)),
            ("firstPredicateHash", hex(&o.first_predicate_hash)),
            ("lockDigest", hex(&o.lock_digest)),
            ("releaseTo", hex(&o.release_to)),
            ("nullifier", hex(&o.nullifier)),
            ("partTokenId", hex(&r.part_token_id)),
            ("partAmount", hex(&r.part_amount)),
            ("depth", r.depth.to_string()),
        ] {
            assert_eq!(s[k], v, "{id}: {k}");
        }
        let levels: Vec<Value> = r
            .levels
            .iter()
            .map(|l| serde_json::json!({ "tokenId": hex(&l.token_id), "amount": hex(&l.amount), "leaves": l.leaves }))
            .collect();
        assert_eq!(s["levels"], Value::Array(levels), "{id}: levels");
        let leaves = s["leaves"].as_array().unwrap();
        assert_eq!(leaves.len(), o.leaves.len(), "{id}");
        for (want, got) in leaves.iter().zip(&o.leaves) {
            assert_eq!(want["sid"], hex(&got.sid), "{id}");
            assert_eq!(want["txHash"], hex(&got.tx_hash), "{id}");
            assert_eq!(
                want["referenceTime"],
                got.reference_time.to_string(),
                "{id}"
            );
            assert_eq!(want["leafValue"], hex(&got.value), "{id}");
        }
        ok += 1;
    }
    assert!(ok >= 11, "{ok}");
}

#[test]
fn the_v2_status_table_is_the_corpus_table() {
    let table = load("vectors/split/config/compose-status-v2.json");
    let table = table.as_array().unwrap();
    for e in table {
        let code = e["code"].as_u64().unwrap();
        assert_eq!(compose_status_name_v2(code), e["name"].as_str(), "{code}");
    }
    assert_eq!(compose_status_name_v2(table.len() as u64), None);
}

#[test]
fn every_compose_v2_output_is_the_relation_result_and_every_success_its_gas() {
    let dep = dev();
    let (mut priced, mut refused) = (0, 0);
    for c in cases("native") {
        let id = c["id"].as_str().unwrap();
        let want = &c["expected"];
        if want["status"] == "halt" {
            assert!(
                ["abi", "out-of-gas"].contains(&want["values"]["halt"].as_str().unwrap()),
                "{id}"
            );
            continue;
        }
        let input = hx(&c["input"]);
        let v = &want["values"];
        let out = hx(&want["output"]);
        assert_eq!(out.len(), COMPOSE_OUTPUT_BYTES_V2, "{id}");
        let (status, result) = decode_compose_output_v2(&out).unwrap();
        assert_eq!(status.to_string(), v["status"].as_str().unwrap(), "{id}");
        let name = compose_status_name_v2(status).unwrap();
        assert_eq!(
            name,
            if status == 0 {
                "ok"
            } else {
                v["statusName"].as_str().unwrap()
            },
            "{id}"
        );
        let (op, cfg, envelope) = read_compose_input(&input);
        assert_eq!(
            compose_input(op, &cfg, &envelope),
            input,
            "{id}: the canonical three-field input"
        );
        let got = compose_offline_v2(&dep, &cfg, &envelope);
        if status != 0 {
            if !B1_ONLY.contains(&name) {
                assert_eq!(
                    got.err().map(|e| e.name().to_string()).as_deref(),
                    Some(name),
                    "{id}"
                );
            }
            refused += 1;
            continue;
        }
        let (r, gas) = got.unwrap();
        let o = result.unwrap();
        assert_eq!(o.lock_digest, r.outcome.lock_digest, "{id}");
        assert_eq!(o.nullifier, r.outcome.nullifier, "{id}");
        assert_eq!(o.part_token_id, r.part_token_id, "{id}");
        assert_eq!(o.part_amount, r.part_amount, "{id}");
        assert_eq!(o.amount, r.outcome.amount, "{id}");
        assert_eq!(o.split_depth, r.depth as u64, "{id}");
        assert_eq!(o.leaf_count, r.outcome.leaves.len() as u64, "{id}");
        assert_eq!(gas.to_string(), v["gas"].as_str().unwrap(), "{id}: gas");
        priced += 1;
    }
    assert!(priced >= 10 && refused >= 10, "{priced} {refused}");
}

/// Mutations whose status differs only in the anchor phase of protocol 5: the native composition scans the anchors and lets B1
/// authenticate them before it opens their input records; the plug-ins' offline steps open them first. No lineage status differs.
/// (mutation-198, a malformed anchor certificate, is the oracle's `ErrAnchorAuth` here; the TypeScript scan names it `ErrShape`.)
/// `(case, the oracle's status, the plug-ins' refusal)`.
const ANCHOR_ORDER: [(&str, &str, &str); 4] = [
    ("mutation-029", "ErrPathBitmap", "ErrIROpening"),
    ("mutation-240", "ErrIRShape", "ErrIROpening"),
    ("mutation-269", "ErrAnchorAuth", "ErrIROpening"),
    ("mutation-297", "ErrAnchorAuth", "ErrIROpening"),
];

#[test]
fn every_mutation_gets_the_oracles_status_and_gas_wherever_the_plug_ins_decide() {
    let dep = dev();
    let m = load("vectors/split/mutation/cases.json");
    assert_eq!(m["format"], "native-bridge-split-mutations/1");
    let names: Vec<String> = load("vectors/split/config/compose-status-v2.json")
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect();
    let base = hx(&m["base"]);
    let order: BTreeMap<&str, (&str, &str)> = ANCHOR_ORDER
        .into_iter()
        .map(|(id, oracle, ours)| (id, (oracle, ours)))
        .collect();
    let mut tally = BTreeMap::<&str, usize>::new();
    for c in m["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let want = &c["expected"];
        if want["status"] == "halt" {
            *tally.entry("halt").or_default() += 1;
            continue;
        }
        let mut input = base.clone();
        for p in c["patch"].as_array().unwrap() {
            input[p["o"].as_u64().unwrap() as usize] ^= p["x"].as_u64().unwrap() as u8;
        }
        let name = &names[want["values"]["status"]
            .as_str()
            .unwrap()
            .parse::<usize>()
            .unwrap()];
        let (_, cfg, envelope) = read_compose_input(&input);
        let got = compose_offline_v2(&dep, &cfg, &envelope);
        let got_name = match &got {
            Ok(_) => "ok".to_string(),
            Err(e) => e.name().to_string(),
        };
        if let Some((oracle, ours)) = order.get(id) {
            assert_eq!(name, oracle, "{id}: the allow-list entry still applies");
            assert_eq!(
                &got_name, ours,
                "{id}: the plug-ins refuse it, for the listed reason"
            );
            *tally.entry("anchorOrder").or_default() += 1;
        } else if B1_ONLY.contains(&name.as_str()) && got_name == "ok" {
            *tally.entry("b1").or_default() += 1;
        } else {
            assert_eq!(&got_name, name, "{id} {}", c["patch"]);
            if name == "ok" {
                assert_eq!(
                    got.unwrap().1.to_string(),
                    want["values"]["gas"].as_str().unwrap(),
                    "{id}: gas"
                );
                *tally.entry("priced").or_default() += 1;
            } else {
                *tally.entry("same").or_default() += 1;
            }
        }
    }
    let want: BTreeMap<&str, usize> = [
        ("halt", 7),
        ("same", 373),
        ("priced", 10),
        ("b1", 6),
        ("anchorOrder", 4),
    ]
    .into_iter()
    .collect();
    assert_eq!(tally, want);
}

#[test]
fn a_split_justification_carries_exactly_one_allocation_proof() {
    let token = encode_tag(39040, &encode_array(&[])); // the count is refused before the token is decoded
    let proof = encode_array(&[&encode_array(&[
        &encode_uint(3),
        &encode_byte_string(&[0; 32]),
        &encode_byte_string(&[5]),
    ])]);
    for proofs in [encode_array(&[]), encode_array(&[&proof, &proof])] {
        let j = encode_tag(39044, &encode_array(&[&token, &proofs]));
        assert_eq!(
            decode_split_justification(&j).unwrap_err(),
            E::SplitProofCount
        );
    }
    let j = encode_tag(39044, &encode_array(&[&token, &encode_array(&[&proof])]));
    assert_eq!(decode_split_justification(&j).unwrap().proof.len(), 1);
}

#[test]
fn verify_sum_proof_refuses_steps_that_are_not_strictly_root_ward_even_when_the_root_matches() {
    let key = [0u8; 32]; // every key bit 0: the leaf is always the left child
    let data = [0u8; 32];
    let sib = |depth: u8| SumStep {
        depth,
        hash: [1; 32],
        sum: BigUint::from(5u8),
    };
    let root_of = |depths: &[u8]| {
        let (mut hh, mut sum) = (
            sum_leaf_hash(&key, &data, &BigUint::from(2u8)).unwrap(),
            BigUint::from(2u8),
        );
        for &d in depths {
            (hh, sum) = sum_node_hash(d, &hh, &sum, &[1; 32], &BigUint::from(5u8)).unwrap();
        }
        hh
    };
    let two = BigUint::from(2u8);
    assert_eq!(
        verify_sum_proof(&[sib(7), sib(3)], &key, &data, &two, &root_of(&[7, 3])),
        Some(BigUint::from(12u8))
    );
    // the same steps leaf-ward, against the root they hash to: refused by the depth order alone
    assert_eq!(
        verify_sum_proof(&[sib(3), sib(7)], &key, &data, &two, &root_of(&[3, 7])),
        None
    );
    assert_eq!(
        verify_sum_proof(&[sib(3), sib(3)], &key, &data, &two, &root_of(&[3, 3])),
        None
    );
    for bad in [[sib(3), sib(7)], [sib(3), sib(3)]] {
        let b = sum_proof_bytes(&bad);
        assert_eq!(
            decode_sum_proof_item(&scan_one(&b).unwrap()).unwrap_err(),
            E::SplitProofShape
        );
    }
}
