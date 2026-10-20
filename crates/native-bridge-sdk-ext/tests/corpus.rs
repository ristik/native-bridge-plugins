#![allow(clippy::type_complexity)]
//! The released protocol-4 corpus (`protocol/vectors`), replayed by an implementation independent of the Go oracle that generated
//! it: the policy family (partition-policy bodies and envelopes) and the gate of every published envelope, component by component.

use native_bridge_sdk_ext::envelope::{check_policy_body, plan_anchors, Envelope};
use native_bridge_sdk_ext::error::Family;
use native_bridge_sdk_ext::gas::{compute_gate, kernel_request_bytes};
use native_bridge_sdk_ext::profile::{from_hex, Cfg, Policy};
use native_bridge_sdk_ext::NativeError as E;
use serde_json::Value;

fn load(rel: &str) -> Value {
    let p = format!(
        "{}/../../protocol/vectors/{rel}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn cases(rel: &str, op: &str) -> Vec<Value> {
    load(rel)["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["op"] == op)
        .cloned()
        .collect()
}

fn cfg_of(name: &str) -> Cfg {
    let f = load("config/fixtures.json");
    Cfg::from_bytes(&from_hex(f["fixtures"][name]["cfg"].as_str().unwrap()).unwrap()).unwrap()
}

fn family(f: Family) -> &'static str {
    match f {
        Family::Malformed => "malformed",
        Family::Invalid => "invalid",
        Family::Budget => "budget",
        Family::Unavailable => "unavailable",
    }
}

/// The verdict of a case: `Ok` or the shared sentinel name with its family.
fn check(c: &Value, got: Result<(), E>) {
    let id = c["id"].as_str().unwrap();
    let want = &c["expected"];
    match (want["status"].as_str().unwrap(), got) {
        ("ok", Ok(())) => {}
        ("error", Err(e)) => {
            assert_eq!(e.name(), want["reason"].as_str().unwrap(), "{id}");
            assert_eq!(family(e.family()), want["family"].as_str().unwrap(), "{id}");
        }
        (w, g) => panic!("{id}: want {w}, got {g:?}"),
    }
}

#[test]
fn policy_bodies_decode_or_are_refused_with_the_corpus_verdict() {
    let cs = cases("policy/cases.json", "policy-decode");
    assert!(cs.len() >= 13);
    for c in &cs {
        let input = from_hex(c["input"].as_str().unwrap()).unwrap();
        check(c, Policy::from_bytes(&input).map(|_| ()));
    }
}

#[test]
fn envelopes_are_framed_opened_and_planned_as_the_corpus_says() {
    let cs = cases("policy/cases.json", "envelope-policy");
    assert!(cs.len() >= 49);
    for c in &cs {
        let cfg = cfg_of(c["cfg"].as_str().unwrap());
        let input = from_hex(c["input"].as_str().unwrap()).unwrap();
        let sids: Vec<[u8; 32]> = c["aux"]["sids"]
            .as_str()
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| from_hex(s).unwrap().try_into().unwrap())
            .collect();
        let run = || -> Result<(), E> {
            let env = Envelope::decode(&input)?;
            let pol = check_policy_body(&cfg, &env)?;
            plan_anchors(&pol, &env, &sids)?;
            Ok(())
        };
        check(c, run());
    }
}

#[test]
fn the_gate_of_every_published_envelope_is_the_oracles_component_by_component() {
    let cs = cases("proof/cases.json", "gate");
    assert!(cs.len() >= 14);
    for c in &cs {
        let cfg = cfg_of(c["cfg"].as_str().unwrap());
        let cfg_raw = cfg.to_bytes();
        let input = from_hex(c["input"].as_str().unwrap()).unwrap();
        // the mint case carries no budget: the profile's own
        let budget: u64 = c["aux"]["budget"]
            .as_str()
            .map_or(7_000_000, |b| b.parse().unwrap());
        let mut gate = None;
        let run = || -> Result<_, E> {
            let env = Envelope::decode(&input)?;
            check_policy_body(&cfg, &env)?;
            compute_gate(
                &cfg_raw,
                input.len(),
                kernel_request_bytes(cfg_raw.len() as u64, env.history.len() as u64),
                &env,
                budget,
            )
        };
        let r = run();
        if let Ok(g) = &r {
            gate = Some(*g);
        }
        check(c, r.map(|_| ()));
        if let Some(g) = gate {
            let want = &c["expected"]["values"];
            for (k, v) in [
                ("b2", g.b2),
                ("batch", g.batch),
                ("intrinsic", g.intrinsic),
                ("items", g.items),
                ("j", g.j),
                ("rsmt", g.rsmt),
                ("steps", g.steps),
                ("total", g.total),
            ] {
                assert_eq!(want[k].as_str().unwrap(), v.to_string(), "{} {k}", c["id"]);
            }
        }
    }
}

#[test]
fn the_k_anchor_projection_is_a_lower_bound_of_every_consolidated_bundle() {
    use native_bridge_sdk_ext::gas::{projected_gate, projected_gate_anchors};
    let cs: Vec<Value> = cases("proof/cases.json", "gate")
        .into_iter()
        .filter(|c| {
            let id = c["id"].as_str().unwrap();
            id.strip_prefix("gate-consolidated-m")
                .is_some_and(|r| r.starts_with(|ch: char| ch.is_ascii_digit()))
                && id.ends_with("-exact")
        })
        .collect();
    assert_eq!(cs.len(), 8, "m in {{1,2,4,8}} x committee {{4,16}}");
    for c in &cs {
        let cfg = cfg_of(c["cfg"].as_str().unwrap()).to_bytes().len() as u64;
        let env = Envelope::decode(&from_hex(c["input"].as_str().unwrap()).unwrap()).unwrap();
        let (k, l) = (env.anchors.len() as u64, env.leaf_proofs.len() as u64);
        let (p, h) = (env.policy_body.len() as u64, env.history.len() as u64);
        let exact: u64 = c["aux"]["budget"].as_str().unwrap().parse().unwrap();
        let best = projected_gate_anchors(cfg, p, l, h, k).0.total;
        assert!(best <= exact, "{}: {best} > {exact}", c["id"]);
        if k > 1 {
            assert!(best > projected_gate(cfg, p, l, h).0.total);
        }
        assert_eq!(
            projected_gate_anchors(cfg, p, l, h, l + 5).0.total,
            projected_gate_anchors(cfg, p, l, h, l).0.total
        );
    }
}
