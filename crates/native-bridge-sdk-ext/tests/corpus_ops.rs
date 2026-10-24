//! The corpus ops the oracle alone used to replay (bft-core #438 "independent JS/Rust conformance"): config (cfg-decode, identifiers,
//! value-data, trust-input), history prepareLock, lock (lock-backing, mpt), unlock and wire token-project. Each op is the oracle's
//! definition (bft-core `bridgeprofile.Replay`), run on this crate's own code; every case of the op is replayed and counted. The `kernel`
//! op (the 0x0104 ABI output) has no plug-in counterpart: the plug-ins never call the kernel, whose relation the kernel mirror in
//! `corpus.rs` replays. The same cases and name maps as the TypeScript plug-in's `corpus-ops.test.ts`.

use std::collections::BTreeMap;

use native_bridge_sdk_ext::deployment::Deployment;
use native_bridge_sdk_ext::error::Family;
use native_bridge_sdk_ext::header::HeaderProfile;
use native_bridge_sdk_ext::history::{check_mint_data, prepare_lock, project, History};
use native_bridge_sdk_ext::lockproof::{config_hash_of_pdr, parse_justification_for, verify};
use native_bridge_sdk_ext::mpt::verify_proof;
use native_bridge_sdk_ext::profile::{
    derive_asset, derive_salt, derive_token_id, derive_type, from_hex, h, identity_domain,
    lock_digest, lock_record, value_envelope, Cfg, Policy,
};
use native_bridge_sdk_ext::resources::preflight_token;
use native_bridge_sdk_ext::trust::TrustInput;
use native_bridge_sdk_ext::unlock::{parse_key, verify_unlock};
use native_bridge_sdk_ext::NativeError as E;
use serde_json::Value;

fn load(rel: &str) -> Value {
    let p = format!(
        "{}/../../protocol/vectors/{rel}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bytes(s: &str) -> Vec<u8> {
    from_hex(s).unwrap()
}

fn b32(s: &str) -> [u8; 32] {
    bytes(s).try_into().unwrap()
}

/// A decimal amount as the minimal big-endian bytes the profile encodes (no leading zero byte).
fn amount_of(dec: &str) -> Vec<u8> {
    // any length (the profile's amounts reach 32 bytes): base 10 into base 256, most significant byte first
    let mut out: Vec<u8> = Vec::new();
    for d in dec.bytes() {
        let mut carry = u32::from(d - b'0');
        for x in out.iter_mut().rev() {
            let v = u32::from(*x) * 10 + carry;
            *x = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    out
}

fn family(f: Family) -> &'static str {
    match f {
        Family::Malformed => "malformed",
        Family::Invalid => "invalid",
        Family::Budget => "budget",
        Family::Unavailable => "unavailable",
    }
}

/// A success's values (`values`), or an error.
type Got = Result<BTreeMap<String, String>, E>;

/// Where the plug-ins name a refusal differently from the oracle, per op: the oracle's reason and the plug-in reasons it may appear as
/// (see `corpus-ops.test.ts`), each as the plug-in's `reason/family`: the family is compared too. The verdict never differs;
/// only these names do, and only as listed.
fn aliases(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    pairs
        .iter()
        .map(|(o, p)| (o.to_string(), p.iter().map(|x| x.to_string()).collect()))
        .collect()
}

/// Replay every case of an op: a success must be a success with the corpus's values (when it gives them; `result` cases compare their
/// `result` as values); an error must be an error with the corpus's family and reason, or a listed alias of that reason.
fn replay_all(
    family_name: &str,
    op: &str,
    count: usize,
    names: &BTreeMap<String, Vec<String>>,
    skip: &[(&str, &str)],
    mut run: impl FnMut(&Value) -> Got,
) {
    let cases: Vec<Value> = load(&format!("{family_name}/cases.json"))["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["op"] == op)
        .cloned()
        .collect();
    assert_eq!(
        cases.len(),
        count,
        "{family_name}/{op}: the corpus case count"
    );
    for (id, _why) in skip {
        assert!(
            cases.iter().any(|c| c["id"] == *id),
            "{id}: a skipped case exists"
        );
    }
    let mut mismatches = Vec::new();
    for c in cases
        .iter()
        .filter(|c| !skip.iter().any(|(id, _)| c["id"] == *id))
    {
        let id = c["id"].as_str().unwrap();
        let want = &c["expected"];
        let ok = match (want["status"].as_str().unwrap(), run(c)) {
            ("ok", Ok(values)) => {
                let expect = want
                    .get("values")
                    .or_else(|| want.get("result"))
                    .and_then(Value::as_object);
                expect.map_or(true, |m| {
                    m.iter().all(|(k, v)| match v {
                        Value::String(s) => values.get(k) == Some(s),
                        Value::Array(a) => {
                            a.is_empty() && values.get(k).map(String::as_str) == Some("[]")
                        }
                        _ => false,
                    })
                })
            }
            ("error", Err(e)) => {
                let reason = want["reason"].as_str().unwrap();
                (e.name() == reason && family(e.family()) == want["family"].as_str().unwrap())
                    || names.get(reason).is_some_and(|p| {
                        p.iter()
                            .any(|x| *x == format!("{}/{}", e.name(), family(e.family())))
                    })
            }
            _ => false,
        };
        if !ok {
            mismatches.push(id.to_string());
        }
    }
    assert!(
        mismatches.is_empty(),
        "{family_name}/{op}: {} of {} cases differ from the oracle: {mismatches:?}",
        mismatches.len(),
        cases.len()
    );
}

fn values(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn fixtures() -> Value {
    load("config/fixtures.json")
}

fn dev_deployment(vault_code_hash: [u8; 32], evm_config_hash: [u8; 32]) -> Deployment {
    let f = fixtures();
    let d = &f["fixtures"]["dev"];
    Deployment::new(
        Cfg::from_bytes(&bytes(d["cfg"].as_str().unwrap())).unwrap(),
        vault_code_hash,
        evm_config_hash,
        HeaderProfile { fields: 20 },
        Policy::from_bytes(&bytes(d["policyBody"].as_str().unwrap())).unwrap(),
    )
    .unwrap()
}

#[test]
fn config_cfg_decode() {
    replay_all("config", "cfg-decode", 12, &BTreeMap::new(), &[], |c| {
        let input = bytes(c["input"].as_str().unwrap());
        let cfg = Cfg::from_bytes(&input)?;
        if cfg.to_bytes() != input {
            return Err(E::NonCanonical);
        }
        let derived = Deployment::validate_cfg(&cfg).is_ok();
        Ok(values(&[
            ("cfgHash", hex(&cfg.hash())),
            ("ty", hex(&cfg.ty)),
            ("aid", hex(&cfg.aid)),
            ("identitiesDerived", derived.to_string()),
        ]))
    });
}

#[test]
fn config_identifiers() {
    replay_all("config", "identifiers", 7, &BTreeMap::new(), &[], |c| {
        let p: Vec<&str> = c["input"].as_str().unwrap().split(':').collect();
        let (n, rg, eg, ch) = (
            p[0].parse().unwrap(),
            b32(p[1]),
            b32(p[2]),
            p[3].parse().unwrap(),
        );
        Ok(values(&[
            ("D", identity_domain(n, &rg, &eg, ch)),
            ("ty", hex(&derive_type(n, &rg, &eg, ch))),
            ("aid", hex(&derive_asset(n, &rg, &eg, ch))),
        ]))
    });
}

#[test]
fn config_value_data() {
    replay_all("config", "value-data", 4, &BTreeMap::new(), &[], |c| {
        let p: Vec<&str> = c["input"].as_str().unwrap().split(':').collect();
        Ok(values(&[(
            "data",
            hex(&value_envelope(&b32(p[0]), &amount_of(p[1]))),
        )]))
    });
}

#[test]
fn config_trust_input() {
    replay_all("config", "trust-input", 5, &BTreeMap::new(), &[], |c| {
        TrustInput::from_bundle(
            &bytes(c["input"].as_str().unwrap()),
            &b32(c["aux"]["pin"].as_str().unwrap()),
        )?;
        Ok(BTreeMap::new())
    });
}

#[test]
fn history_prepare_lock() {
    let f = fixtures();
    let cfg = Cfg::from_bytes(&bytes(f["fixtures"]["dev"]["cfg"].as_str().unwrap())).unwrap();
    replay_all("history", "prepareLock", 5, &BTreeMap::new(), &[], |c| {
        assert_eq!(c["cfg"], "dev");
        let o = prepare_lock(
            &cfg,
            c["aux"]["n"].as_str().unwrap().parse().unwrap(),
            &amount_of(c["aux"]["amount"].as_str().unwrap()),
            &bytes(c["input"].as_str().unwrap()),
        )?;
        Ok(values(&[
            ("cfg", hex(&o.cfg)),
            ("nonce", o.nonce.to_string()),
            ("amount", hex(&o.amount)),
            ("tokenId", hex(&o.token_id)),
            ("salt", hex(&o.salt)),
            ("firstPredicateHash", hex(&o.first_predicate_hash)),
            ("lockDigest", hex(&o.lock_digest)),
            ("releaseTo", hex(&o.release_to)),
            ("nullifier", hex(&o.nullifier)),
            (
                "leaves",
                if o.leaves.is_empty() {
                    "[]".into()
                } else {
                    format!("{}", o.leaves.len())
                },
            ),
        ]))
    });
}

#[test]
fn lock_lock_backing() {
    let f = fixtures();
    let cfg = Cfg::from_bytes(&bytes(f["fixtures"]["dev"]["cfg"].as_str().unwrap())).unwrap();
    let ch = cfg.hash();
    let names = BTreeMap::new();
    let skip = [(
        "backing-no-pin",
        "a plug-in deployment always carries its pin (Deployment::new requires the vault code hash and EVM configuration)",
    )];
    replay_all("lock", "lock-backing", 66, &names, &skip, |c| {
        assert_eq!(c["cfg"], "dev");
        let hist = History::decode(&bytes(c["input"].as_str().unwrap()))?;
        let tb = &f["trustBases"][c["aux"]["trustBase"].as_str().unwrap()];
        if tb.is_null() {
            return Err(E::TrustBaseDigest);
        }
        let trust = TrustInput::from_bundle(
            &bytes(tb["bundle"].as_str().unwrap()),
            &b32(tb["pin"].as_str().unwrap()),
        )?;
        let pin = &f["pins"][c["aux"]["pin"].as_str().unwrap()];
        let dep = dev_deployment(
            b32(pin["vaultCodeHash"].as_str().unwrap()),
            config_hash_of_pdr(&bytes(pin["genesisPDR"].as_str().unwrap()))?,
        );
        let j = parse_justification_for(
            &cfg,
            &ch,
            hist.mint.justification.as_deref().unwrap_or_default(),
        )?;
        let amount = check_mint_data(&dep, hist.mint.data.as_deref())?;
        let salt = derive_salt(&ch, j.nonce);
        if hist.mint.salt != salt {
            return Err(E::MintSalt);
        }
        let id = derive_token_id(&salt, cfg.network);
        let digest = lock_digest(
            &ch,
            j.nonce,
            &lock_record(
                &cfg.zero_address,
                &cfg.ty,
                &cfg.aid,
                &amount,
                &id,
                &h(&hist.mint.recipient.to_bytes()),
            ),
        );
        verify(&dep, &trust, &j, &digest)?;
        Ok(BTreeMap::new())
    });
}

#[test]
fn lock_mpt() {
    let names = BTreeMap::new();
    replay_all("lock", "mpt", 7, &names, &[], |c| {
        let nodes: Vec<Vec<u8>> = c["aux"]["nodes"]
            .as_str()
            .unwrap_or("")
            .split(',')
            .filter(|n| !n.is_empty())
            .map(bytes)
            .collect();
        let refs: Vec<&[u8]> = nodes.iter().map(Vec::as_slice).collect();
        let v = verify_proof(
            &b32(c["aux"]["root"].as_str().unwrap()),
            &bytes(c["aux"]["key"].as_str().unwrap()),
            &refs,
        )?;
        Ok(values(&[("value", hex(&v))]))
    });
}

#[test]
fn unlock_unlock() {
    replay_all("unlock", "unlock", 17, &BTreeMap::new(), &[], |c| {
        let input = bytes(c["input"].as_str().unwrap());
        if input.len() < 64 {
            return Err(E::UnlockLength);
        }
        let key = parse_key(&bytes(c["aux"]["key"].as_str().unwrap()))?;
        verify_unlock(
            &key,
            &input[..32].try_into().unwrap(),
            &input[32..64].try_into().unwrap(),
            &input[64..],
        )?;
        Ok(BTreeMap::new())
    });
}

#[test]
fn wire_token_project() {
    // A refused case goes through this crate's token intake (NativeBridge::verify_native_token_bytes: the bounded native scan, then the
    // SDK decode, re-encoding equal). The accepted cases carry a synthetic certificate inside the mint's lock proof, which the intake
    // scans (and refuses) and the oracle's projection never reads, so their projection is compared through the SDK decode alone.
    let names = aliases(&[
        (
            "ErrCertScan",
            &[
                "ErrUnsupportedCertificateEncoding/invalid",
                "ErrNonCanonical/malformed",
            ],
        ),
        (
            "ErrCertSigLength",
            &["ErrUnsupportedCertificateEncoding/invalid"],
        ),
        (
            "ErrInputTooLarge",
            &["ErrUnsupportedCertificateEncoding/invalid"],
        ),
        ("ErrLength", &["ErrUnsupportedCertificateEncoding/invalid"]),
        ("ErrShape", &["ErrUnsupportedCertificateEncoding/invalid"]),
        ("ErrTag", &["ErrUnsupportedCertificateEncoding/invalid"]),
        ("ErrVersion", &["ErrUnsupportedCertificateEncoding/invalid"]),
    ]);
    replay_all("wire", "token-project", 36, &names, &[], |c| {
        let input = bytes(c["input"].as_str().unwrap());
        if c["expected"]["status"] != "ok" {
            preflight_token(&input)?;
        }
        let token = unicity_token::Token::from_cbor(&input).map_err(|_| E::SdkDecode)?;
        if token.to_cbor() != input {
            return Err(E::NonCanonical);
        }
        Ok(values(&[("projection", hex(&project(&token)))]))
    });
}
