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
fn the_gas_estimate_of_every_published_envelope_is_the_oracles_component_by_component() {
    let cs = cases("proof/cases.json", "gate");
    assert!(cs.len() >= 14);
    for c in &cs {
        let cfg = cfg_of(c["cfg"].as_str().unwrap());
        let cfg_raw = cfg.to_bytes();
        let input = from_hex(c["input"].as_str().unwrap()).unwrap();
        let mut gate = None;
        let run = || -> Result<_, E> {
            let env = Envelope::decode(&input)?;
            check_policy_body(&cfg, &env)?;
            compute_gate(
                &cfg_raw,
                input.len(),
                kernel_request_bytes(cfg_raw.len() as u64, env.history.len() as u64),
                &env,
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
                ("total", g.legacy_total),
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
        })
        .collect();
    assert_eq!(cs.len(), 8, "m in {{1,2,4,8}} x committee {{4,16}}");
    for c in &cs {
        let cfg = cfg_of(c["cfg"].as_str().unwrap()).to_bytes().len() as u64;
        let env = Envelope::decode(&from_hex(c["input"].as_str().unwrap()).unwrap()).unwrap();
        let (k, l) = (env.anchors.len() as u64, env.leaf_proofs.len() as u64);
        let (p, h) = (env.policy_body.len() as u64, env.history.len() as u64);
        let exact: u64 = c["expected"]["values"]["total"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let best = projected_gate_anchors(cfg, p, l, h, k).0.legacy_total;
        assert!(best <= exact, "{}: {best} > {exact}", c["id"]);
        if k > 1 {
            assert!(best > projected_gate(cfg, p, l, h).0.legacy_total);
        }
        assert_eq!(
            projected_gate_anchors(cfg, p, l, h, l + 5).0.legacy_total,
            projected_gate_anchors(cfg, p, l, h, l).0.legacy_total
        );
    }
}

/// No gas ceiling (owner section 36): a bundle estimated above the former 7,000,000 is estimated, not refused.
#[test]
fn a_bundle_above_the_former_ceiling_is_estimated_not_refused() {
    let c = cases("proof/cases.json", "gate")
        .into_iter()
        .find(|c| c["id"] == "gate-compose-leaves-max-two-anchors")
        .unwrap();
    assert_eq!(c["expected"]["status"], "ok");
    let cfg_raw = cfg_of(c["cfg"].as_str().unwrap()).to_bytes();
    let input = from_hex(c["input"].as_str().unwrap()).unwrap();
    let env = Envelope::decode(&input).unwrap();
    let g = compute_gate(
        &cfg_raw,
        input.len(),
        kernel_request_bytes(cfg_raw.len() as u64, env.history.len() as u64),
        &env,
    )
    .unwrap();
    assert_eq!(g.legacy_total, 7_206_166);
    assert!(g.legacy_total > 7_000_000);
}

#[test]
fn the_compose_status_table_is_the_corpus_append_only_table() {
    use native_bridge_sdk_ext::compose::COMPOSE_STATUS;
    let table = load("config/compose-status.json");
    let rows = table.as_array().unwrap();
    assert_eq!(rows.len(), COMPOSE_STATUS.len() + 1);
    for (code, row) in rows.iter().enumerate() {
        assert_eq!(row["code"].as_u64().unwrap(), code as u64);
        let want = if code == 0 {
            "ok"
        } else {
            COMPOSE_STATUS[code - 1]
        };
        assert_eq!(row["name"], want, "code {code}");
    }
}

/// `abi.encode(uint8 op, bytes cfg, bytes envelope)` read back (the corpus input of a native-compose case).
fn read_compose_input(b: &[u8]) -> (u8, Vec<u8>, Vec<u8>) {
    let w = |o: usize| u64::from_be_bytes(b[o + 24..o + 32].try_into().unwrap()) as usize;
    let field = |off: usize| b[off + 32..off + 32 + w(off)].to_vec();
    (w(0) as u8, field(w(32)), field(w(64)))
}

#[test]
fn every_native_compose_case_is_the_plug_in_estimate_when_it_succeeds() {
    use native_bridge_sdk_ext::compose::{
        compose_input, compose_output_status, compose_status_name, COMPOSE_OUTPUT_BYTES,
    };
    use native_bridge_sdk_ext::gas::compose_gas;
    let cs = cases("proof/cases.json", "native-compose");
    assert!(cs.len() >= cases("proof/cases.json", "compose").len() + 4);
    let mut priced = 0;
    for c in &cs {
        let id = c["id"].as_str().unwrap();
        let v = &c["expected"]["values"];
        if c["expected"]["status"] == "halt" {
            assert!(v["halt"] == "abi" || v["halt"] == "out-of-gas", "{id}");
            continue;
        }
        assert_eq!(c["expected"]["status"], "ok", "{id}");
        let input = from_hex(c["input"].as_str().unwrap()).unwrap();
        let (op, cfg, envelope) = read_compose_input(&input);
        assert_eq!(
            compose_input(op, &cfg, &envelope),
            input,
            "{id}: canonical input"
        );
        let out = from_hex(c["expected"]["output"].as_str().unwrap()).unwrap();
        assert_eq!(out.len(), COMPOSE_OUTPUT_BYTES, "{id}");
        let status = compose_output_status(&out).unwrap();
        assert_eq!(status.to_string(), v["status"].as_str().unwrap(), "{id}");
        let want_name = if status == 0 {
            "ok"
        } else {
            v["statusName"].as_str().unwrap()
        };
        assert_eq!(compose_status_name(status), Some(want_name), "{id}");
        if status != 0 {
            assert!(
                out[64..].iter().all(|&x| x == 0),
                "{id}: a status zeroes every field"
            );
            continue;
        }
        let env = Envelope::decode(&envelope).unwrap();
        let g = compute_gate(
            &cfg,
            envelope.len(),
            kernel_request_bytes(cfg.len() as u64, env.history.len() as u64),
            &env,
        )
        .unwrap();
        assert_eq!(g.compose.b, input.len() as u64, "{id}: B");
        assert_eq!(
            compose_gas(&g.compose).to_string(),
            v["gas"].as_str().unwrap(),
            "{id}: gas"
        );
        assert_eq!(g.native, compose_gas(&g.compose));
        priced += 1;
    }
    assert!(priced >= 10, "{priced}");
}
