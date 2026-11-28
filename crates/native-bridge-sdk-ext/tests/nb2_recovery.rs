#![cfg(feature = "host")]

use std::{fs, path::Path, process::Command};

use native_bridge_sdk_ext::nb2::{
    config::{decode_config, production_params, test_params},
    deposit::{decode_deposit_proof, verify_receipt_log},
    errors::{fail, refuse},
    journal::unhex,
    recovery::{
        GapCursor, GapEntry, GapPredecessor, RecoveryAuthority, RecoveryDeployment, RecoveryEvent,
        RecoverySession,
    },
    segment::{next_head, segment_sealed_data, GapTree},
    trust::TrustInput,
    util::{arr, from_hex},
    verify::verify_return,
    Rule, WalletReason,
};
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../protocol/vectors/");
const BASE: &str = "nb2-continuation-v1.1";
const EXTRA: &str = "nb2-continuation-v1.1-supplement";

fn read(base: &str, name: &str) -> Vec<u8> {
    fs::read(Path::new(DIR).join(base).join(name)).unwrap()
}

fn json(base: &str, name: &str) -> Value {
    serde_json::from_slice(&read(base, name)).unwrap()
}

fn hex<const N: usize>(value: &Value) -> [u8; N] {
    arr(&from_hex(value.as_str().unwrap()).unwrap())
}

fn load(base: &str, lineage: &str) -> (RecoverySession, TrustInput, Vec<u8>, [u8; 20]) {
    let gamma = read(base, "gamma.bin");
    let params = production_params();
    let cfg = decode_config(&gamma, &params).unwrap();
    let trust = TrustInput::from_bundle(
        &read(base, &format!("{lineage}/utb.cbor")),
        &cfg.root_genesis,
    )
    .unwrap();
    let context = json(base, &format!("{lineage}/context.json"));
    let recovery = hex(&context["RecoveryAddress"]);
    let pins = if base == BASE {
        arr(&read(base, "pins.bin"))
    } else {
        hex(&json(base, "deployment.json")["Pins"])
    };
    let session = RecoverySession::create(
        &gamma,
        &read(base, &format!("{lineage}/evidence.bin")),
        RecoveryAuthority::new(trust.clone(), |_| Ok(())),
        &params,
        RecoveryDeployment {
            salt: arr(&read(base, "generation-salt.bin")),
            recovery,
            runtime_hash: hex(&context["RecoveryRuntimeHash"]),
            pins,
            vault_runtime_hash: None,
        },
    )
    .unwrap();
    assert_eq!(session.id(), hex(&context["Session"]));
    assert_eq!(session.page_root(), hex(&context["PageRoot"]));
    (session, trust, gamma, recovery)
}

fn trace(base: &str, lineage: &str) -> Vec<u8> {
    let output = Command::new("gzip")
        .arg("-cd")
        .arg(Path::new(DIR).join(base).join(lineage).join("trace.bin.gz"))
        .output()
        .unwrap();
    assert!(output.status.success());
    output.stdout
}

fn u32_at(b: &[u8], pos: usize) -> usize {
    u32::from_be_bytes(arr(&b[pos..pos + 4])) as usize
}
fn u64_at(b: &[u8], pos: usize) -> u64 {
    u64::from_be_bytes(arr(&b[pos..pos + 8]))
}

fn op_count(calldata: &[u8]) -> usize {
    let raw = &calldata[68..];
    let n = u64_at(raw, 2) as usize;
    let depth = n.div_ceil(4096).next_power_of_two().trailing_zeros() as usize;
    let pages = if raw[42] == 0 {
        43
    } else {
        337 + u32_at(raw, 333)
    };
    let mut pos = pages + 1;
    for _ in 0..raw[pages] {
        let index = u64_at(raw, pos) as usize;
        pos += 8 + (n - index * 4096).min(4096) + 32 * depth;
    }
    raw[pos] as usize
}

#[test]
fn shared_archive_fold_authenticates_witness_and_membership_beyond_limit() {
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nb2-archive-fold.json"
    ))
    .unwrap();
    let bytes = |v: &Value| unhex(v.as_str().unwrap()).unwrap();
    let gamma = bytes(&f["gamma"]);
    let params = test_params();
    let cfg = decode_config(&gamma, &params).unwrap();
    let trust = TrustInput::from_bundle(&bytes(&f["trustBundle"]), &cfg.root_genesis).unwrap();
    let d = &f["deployment"];
    let session = RecoverySession::create(
        &gamma,
        &bytes(&f["evidence"]),
        RecoveryAuthority::new(trust.clone(), |_| Ok(())),
        &params,
        RecoveryDeployment {
            salt: arr(&bytes(&d["salt"])),
            recovery: arr(&bytes(&d["recovery"])),
            runtime_hash: arr(&bytes(&d["runtimeHash"])),
            pins: arr(&bytes(&d["pins"])),
            vault_runtime_hash: Some(arr(&bytes(&d["vaultRuntimeHash"]))),
        },
    )
    .unwrap();
    let fold = |example: &Value| {
        let rows: Vec<_> = example["logs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["index"].as_str().unwrap().parse::<u64>().unwrap(),
                    bytes(&row["data"]),
                )
            })
            .collect();
        let logs: Vec<_> = rows
            .iter()
            .map(|(index, data)| (*index, data.as_slice()))
            .collect();
        session.archived_gaps(
            &trust,
            f["start"].as_str().unwrap().parse().unwrap(),
            arr(&bytes(&f["head"])),
            &logs,
            &bytes(&example["terminalSeal"]),
            f["limit"].as_u64().unwrap() as usize,
        )
    };
    let expected: Vec<_> = f["positive"]["witnesses"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect();
    assert_eq!(fold(&f["positive"]).unwrap(), expected);
    assert_eq!(
        fold(&f["paid"]).unwrap_err().reason(),
        Some(WalletReason::AlreadyPaid)
    );
}

#[test]
fn archived_gaps_check_the_suffix_beyond_the_first_packet() {
    let path = "transcripts/root";
    let (session, trust, gamma, _) = load(BASE, path);
    let params = production_params();
    let cfg = decode_config(&gamma, &params).unwrap();
    let evidence = read(BASE, &format!("{path}/evidence.bin"));
    let verdict = verify_return(&gamma, &evidence, &trust, &params).unwrap();
    let start = verdict.min_segment;
    let ids: Vec<[u8; 32]> = (0..cfg.k).map(|i| [i as u8; 32]).collect();
    let root = GapTree::build(&ids).unwrap().root();
    let head = [3; 32];
    let middle = next_head(&verdict.domain, start, &head, &root);
    let end = next_head(&verdict.domain, start + 1, &middle, &root);
    let first = segment_sealed_data(&head, &middle, &ids);
    let last = segment_sealed_data(&middle, &end, &ids);
    let bad = [(start, first.as_slice()), (start + 2, last.as_slice())];
    let err = session
        .archived_gaps(&trust, start, head, &bad, &[], 1)
        .unwrap_err();
    assert_eq!(err.rule().unwrap().rule, Rule::SegmentLog);
    let consecutive = [(start, first.as_slice()), (start + 1, last.as_slice())];
    let err = session
        .archived_gaps(&trust, start, head, &consecutive, &[], 1)
        .unwrap_err();
    assert_eq!(err.rule().unwrap().rule, Rule::SealReceipt);
}

#[test]
fn prescribed_runs_match_t1() {
    for (base, path) in [
        (BASE, "transcripts/root"),
        (BASE, "transcripts/transfers"),
        (BASE, "transcripts/one-split"),
        (BASE, "transcripts/depth-20"),
        (BASE, "transcripts/shared-claim"),
        (BASE, "transcripts/alternate-certificate"),
        (BASE, "transcripts/transfers-600"),
        (BASE, "transcripts/capped-root"),
        (BASE, "transcripts/parent-over-32-pages"),
        (BASE, "transcripts/combined-large-receipt-and-paths"),
        (EXTRA, "b1-rollover"),
    ] {
        let (session, trust, _, _) = load(base, path);
        let trace = trace(base, path);
        let mut pos = 0;
        let mut from = 0;
        let mut seq = 0;
        let mut prior = None;
        while pos < trace.len() {
            let [calldata, _, state, topics, data, receipt] = core::array::from_fn(|_| {
                let width = u32_at(&trace, pos);
                pos += 4;
                let field = &trace[pos..pos + width];
                pos += width;
                field
            });
            let run = session
                .run(from, op_count(calldata), &trust, prior)
                .unwrap();
            assert_eq!(run.calldata, calldata, "{path}");
            assert_eq!(run.state.as_deref().unwrap_or_default(), state, "{path}");
            assert_eq!(run.event.topics.concat(), topics);
            assert_eq!(run.event.data, data);
            let primary = |_: &[u8; 20], _: &RecoveryEvent| fail(Rule::EvidencePruned);
            let archive = |_: &[u8; 20], _: &RecoveryEvent| Ok(receipt.to_vec());
            let (proof, _) = session
                .acquire(&trust, &run.event, &[&primary, &archive], None)
                .unwrap();
            assert_eq!(proof.encoded, receipt);
            if path == "transcripts/root" {
                let trimmed = session.trim_receipt(&trust, receipt, &run.event).unwrap();
                assert!(trimmed.encoded.len() <= receipt.len());
                session
                    .verify_event(&trust, &trimmed.encoded, &run.event)
                    .unwrap();
            }
            let unknown = |_: &[u8; 20], _: &RecoveryEvent| {
                refuse(WalletReason::CompanionUnknown, "child not served")
            };
            let missing = session
                .acquire(&trust, &run.event, &[&primary, &unknown], None)
                .err()
                .unwrap();
            assert_eq!(missing.reason(), Some(WalletReason::CompanionUnknown));
            from = run.end;
            seq += 1;
            prior = Some((seq, receipt));
        }
        assert_eq!(from, session.operation_count());
    }
}

#[test]
fn prescribed_cold_calls_match_t1() {
    let (session, trust, gamma, recovery) = load(BASE, "transcripts/root");
    let mut cfg = decode_config(&gamma, &production_params()).unwrap();
    for entry in fs::read_dir(Path::new(DIR).join(BASE).join("transcripts/cold")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        let base = format!("transcripts/cold/{name}");
        let calldata = read(BASE, &format!("{base}/calldata.bin"));
        let size = u64_at(&calldata, 60) as usize;
        let body = &calldata[68..68 + size];
        let kind = body[42];
        let end = 47 + u32_at(body, 43);
        let receipt = &body[47..end];
        let count = u16::from_be_bytes(arr(&body[end..end + 2])) as usize;
        let gap_start = end + 2 + if kind == 1 && count > 0 { 32 } else { 0 };
        let gap_bytes = &body[gap_start..];
        let width = gap_bytes.len().checked_div(count).unwrap_or(1);
        let gaps: Vec<Vec<u8>> = gap_bytes.chunks_exact(width).map(<[u8]>::to_vec).collect();
        let proof = decode_deposit_proof(receipt).unwrap();
        cfg.vault = recovery;
        let log = verify_receipt_log(&cfg, &trust, &proof).unwrap();
        let seq = u64_at(&log.data, 24);
        let prior = GapPredecessor {
            seq,
            receipt,
            cursor: (kind == 2).then(|| GapCursor {
                next: u64_at(&log.data, 248),
                head: arr(&log.data[256..288]),
            }),
        };
        let start_head = (gap_start != end + 2).then(|| arr(&body[end + 2..gap_start]));
        let entry = if name.starts_with("advance") {
            GapEntry::Advance
        } else {
            GapEntry::Redeem
        };
        let packet = session
            .gaps(entry, &trust, &prior, &gaps, start_head)
            .unwrap();
        assert_eq!(packet.calldata, calldata, "{name}");
        if let Some(event) = packet.event {
            let result = json(BASE, &format!("{base}/outcome.json"));
            assert_eq!(
                event.data,
                from_hex(result["Data"].as_str().unwrap()).unwrap()
            );
        }
    }
}

#[test]
fn cold_admission_prices_the_terminal_bound_and_refuses_one_unit_over() {
    use native_bridge_sdk_ext::nb2::recovery_cost::{
        preflight_recovery, quote_recovery, AdmissionContext, RecoveryBacklog, RecoveryCalibration,
        RecoveryCalibrationRange, RecoveryEntry, RecoveryLimits, RecoveryShape,
    };
    struct Calibration([u8; 32], [u8; 32], Vec<RecoveryCalibrationRange>);
    impl RecoveryCalibration for Calibration {
        fn pins(&self) -> [u8; 32] {
            self.0
        }
        fn runtime_hash(&self) -> [u8; 32] {
            self.1
        }
        fn vault_runtime_hash(&self) -> Option<[u8; 32]> {
            Some([1; 32])
        }
        fn ranges(&self) -> &[RecoveryCalibrationRange] {
            &self.2
        }
    }
    let ranges = |advance_max| {
        let range = |entry, operations, gaps| RecoveryCalibrationRange {
            min_receipt_bytes: usize::from(entry != RecoveryEntry::Run),
            max: RecoveryShape {
                entry,
                operations,
                gaps,
                receipt_bytes: 65_536,
                calldata_bytes: 393_216,
                pages: 32,
                opening_bytes: 393_216,
            },
            execution: 1_000_000 + operations as u64 * 500_000 + gaps as u64 * 7_000,
        };
        (1..=16)
            .map(|n| range(RecoveryEntry::Run, n, 0))
            .chain((1..=advance_max).map(|n| range(RecoveryEntry::AdvanceGaps, 0, n)))
            .chain((0..1024).map(|n| range(RecoveryEntry::RedeemRecovered, 0, n)))
            .collect::<Vec<_>>()
    };
    let gamma = read(BASE, "gamma.bin");
    let params = production_params();
    let cfg = decode_config(&gamma, &params).unwrap();
    let path = "transcripts/held-sibling-0";
    let trust =
        TrustInput::from_bundle(&read(BASE, &format!("{path}/utb.cbor")), &cfg.root_genesis)
            .unwrap();
    let context = json(BASE, &format!("{path}/context.json"));
    let deployment = RecoveryDeployment {
        salt: arr(&read(BASE, "generation-salt.bin")),
        recovery: hex(&context["RecoveryAddress"]),
        runtime_hash: hex(&context["RecoveryRuntimeHash"]),
        pins: arr(&read(BASE, "pins.bin")),
        vault_runtime_hash: Some([1; 32]),
    };
    let held = read(BASE, &format!("{path}/evidence.bin"));
    let calibration = Calibration(deployment.pins, deployment.runtime_hash, ranges(1024));
    let mut limits = RecoveryLimits {
        signed_bytes: 524_288,
        calldata_bytes: 393_216,
        gas: 24_000_000,
        chain_id: cfg.chain_id,
        max_nonce: 255,
        max_fee_per_gas: 10u8.into(),
        max_priority_fee_per_gas: 1u8.into(),
        max_transaction_fee: None,
        balance: 1_000_000_000_000_000_000u64.into(),
        fee_budget: 1_000_000_000_000_000_000u64.into(),
    };
    let backlog = RecoveryBacklog {
        signed_start: 0,
        observed: 2,
        during_progress: 3,
        peak_seals: 1,
        elapsed_ms: 1_000,
        receipt_p99_ms: 1_000,
        advance_peak_seals: 1,
        final_inclusion_ms: 25,
        final_peak_seals: 1,
        qualified_for_ms: 200_000,
    };
    let quote = |limits: &RecoveryLimits| {
        preflight_recovery(
            &AdmissionContext {
                gamma: &gamma,
                trust: &trust,
                params: &params,
                deployment: &deployment,
                calibration: &calibration,
                limits,
            },
            &held,
            &backlog,
            None,
        )
    };
    let (session, _, _, _) = load(BASE, "transcripts/root");
    let whole = session.run(0, 2, &trust, None).unwrap();
    let one = session.run(0, 1, &trust, None).unwrap();
    assert!(whole.calldata.len() > one.calldata.len());
    limits.calldata_bytes = whole.calldata.len() - 1;
    let (cut, _) = session
        .run_bounded(0, &trust, &calibration, &limits, None)
        .unwrap();
    assert_eq!(cut.end, 1);
    assert_eq!(cut.calldata, one.calldata);
    limits.calldata_bytes = 393_216;
    let admitted = quote(&limits).unwrap();
    assert_eq!(
        admitted
            .run
            .iter()
            .map(|q| q.shape.operations)
            .sum::<usize>(),
        4
    );
    assert_eq!(admitted.advance.shape.gaps, 69);
    assert_eq!(admitted.advance_calls, 2);
    limits.fee_budget = admitted.total_fee.clone();
    assert_eq!(quote(&limits).unwrap().total_fee, admitted.total_fee);
    limits.fee_budget -= 1u8;
    assert_eq!(
        quote(&limits).err().unwrap().rule().unwrap().rule,
        Rule::CapacityPreflight
    );
    let mut growing = RecoveryBacklog {
        observed: 1024,
        during_progress: 0,
        peak_seals: 32,
        advance_peak_seals: 32,
        ..backlog
    };
    let max64 = Calibration(deployment.pins, deployment.runtime_hash, ranges(64));
    let growing_quote = |bounds: &RecoveryLimits, growth: &RecoveryBacklog, model: &Calibration| {
        preflight_recovery(
            &AdmissionContext {
                gamma: &gamma,
                trust: &trust,
                params: &params,
                deployment: &deployment,
                calibration: model,
                limits: bounds,
            },
            &held,
            growth,
            None,
        )
    };
    limits.fee_budget = limits.balance.clone();
    let extended = growing_quote(&limits, &growing, &max64).unwrap();
    assert_eq!(extended.advance_calls, 34);
    assert_eq!(extended.settlement_max_gaps, 63);
    assert_eq!(extended.settle.shape.gaps, 63);
    let old_budget = extended
        .run
        .iter()
        .fold(&extended.advance.fee * 17u8, |sum, q| sum + &q.fee)
        + quote_recovery(
            RecoveryShape {
                gaps: 0,
                calldata_bytes: 65_668,
                ..extended.settle.shape
            },
            &max64,
            &limits,
        )
        .unwrap()
        .fee;
    limits.fee_budget = old_budget;
    assert!(growing_quote(&limits, &growing, &max64)
        .err()
        .unwrap()
        .name()
        .contains("CapacityPreflight"));
    limits.fee_budget = limits.balance.clone();
    growing.final_peak_seals = 2;
    assert!(growing_quote(&limits, &growing, &max64).is_err());
    growing.final_peak_seals = 1;
    growing.advance_peak_seals = 64;
    assert!(growing_quote(&limits, &growing, &max64).is_err());
    growing.advance_peak_seals = 32;
    let smaller = RecoveryShape {
        receipt_bytes: 2073,
        calldata_bytes: 20_000,
        ..extended.advance.shape
    };
    let narrow = Calibration(
        deployment.pins,
        deployment.runtime_hash,
        max64
            .ranges()
            .iter()
            .copied()
            .map(|mut range| {
                if range.max.entry == RecoveryEntry::AdvanceGaps {
                    range.min_receipt_bytes = 65_536;
                }
                range
            })
            .collect(),
    );
    assert!(quote_recovery(extended.advance.shape, &narrow, &limits).is_some());
    assert!(quote_recovery(smaller, &narrow, &limits).is_none());
    assert!(growing_quote(&limits, &growing, &narrow).is_err());
    assert!(quote_recovery(smaller, &max64, &limits).unwrap().fee <= extended.advance.fee);
    growing.qualified_for_ms = 34_000;
    assert!(growing_quote(&limits, &growing, &max64).is_err());
    growing.qualified_for_ms = 200_000;
    growing.observed = (1u64 << 48) - 66;
    assert!(growing_quote(&limits, &growing, &max64).is_err());
    growing.observed = 0;
    growing.peak_seals = 0;
    growing.advance_peak_seals = 0;
    for entry in [RecoveryEntry::AdvanceGaps, RecoveryEntry::RedeemRecovered] {
        let model = Calibration(
            deployment.pins,
            deployment.runtime_hash,
            max64
                .ranges()
                .iter()
                .copied()
                .filter(|range| range.max.entry != entry || range.max.gaps != 1)
                .collect(),
        );
        let error = growing_quote(&limits, &growing, &model).err().unwrap();
        assert_eq!(error.rule().unwrap().rule, Rule::CapacityPreflight);
    }
    limits.gas = admitted.settle.gas;
    limits.signed_bytes = admitted.settle.signed_bytes;
    assert!(quote_recovery(admitted.settle.shape, &calibration, &limits).is_some());
    limits.max_transaction_fee = Some(&admitted.settle.fee - 1u8);
    assert!(quote_recovery(admitted.settle.shape, &calibration, &limits).is_none());
    limits.max_transaction_fee = None;
    limits.signed_bytes -= 1;
    assert!(quote_recovery(admitted.settle.shape, &calibration, &limits).is_none());
}

#[test]
fn refuses_the_invalid_supplement_lineages() {
    let (_, trust, gamma, recovery) = load(EXTRA, "b1-rollover");
    let params = production_params();
    let deployment = json(EXTRA, "deployment.json");
    for path in ["b1-rollover-refusals", "cross-cut-conflict"] {
        let evidence = read(EXTRA, &format!("{path}/evidence.bin"));
        assert!(RecoverySession::create(
            &gamma,
            &evidence,
            RecoveryAuthority::new(trust.clone(), |_| Ok(())),
            &params,
            RecoveryDeployment {
                salt: arr(&read(EXTRA, "generation-salt.bin")),
                recovery,
                runtime_hash: hex(&deployment["RecoveryRuntimeHash"]),
                pins: hex(&deployment["Pins"]),
                vault_runtime_hash: None,
            },
        )
        .is_err());
    }
}

#[test]
fn authority_refresh_persists_and_reconstructed_sessions_refuse_rollbacks() {
    use std::{cell::RefCell, rc::Rc};
    use unicity_token::api::bft::TrustBaseHistory;
    let path = "transcripts/root";
    let (_, full, gamma, emitter) = load(BASE, path);
    let params = production_params();
    let context = json(BASE, &format!("{path}/context.json"));
    let deployment = || RecoveryDeployment {
        salt: arr(&read(BASE, "generation-salt.bin")),
        recovery: emitter,
        runtime_hash: hex(&context["RecoveryRuntimeHash"]),
        pins: arr(&read(BASE, "pins.bin")),
        vault_runtime_hash: None,
    };
    let short_bundle = TrustBaseHistory::from_trusted_chain(full.history().entries()[..1].to_vec())
        .unwrap()
        .to_bundle();
    let short = TrustInput::from_bundle(&short_bundle, &full.id()).unwrap();
    let lagging = short.clone();
    let previous = short;
    let persisted = Rc::new(RefCell::new(previous.clone()));
    let store = persisted.clone();
    let authority = RecoveryAuthority::new(previous.clone(), move |next| {
        *store.borrow_mut() = next.clone();
        Ok(())
    });
    let evidence = read(BASE, &format!("{path}/evidence.bin"));
    let session =
        RecoverySession::create(&gamma, &evidence, authority, &params, deployment()).unwrap();
    let mut run = session.run(0, 2, &previous, None).unwrap();
    let rec = trace(BASE, path);
    let mut pos = 0;
    let fields: [&[u8]; 6] = core::array::from_fn(|_| {
        let width = u32_at(&rec, pos);
        pos += 4;
        let field = &rec[pos..pos + width];
        pos += width;
        field
    });
    let receipt = fields[5];
    let source = |_: &[u8; 20], _: &RecoveryEvent| Ok(receipt.to_vec());
    session
        .acquire(&full, &run.event, &[&source], None)
        .unwrap();
    assert_eq!(*persisted.borrow(), full);
    let error = session
        .acquire(&lagging, &run.event, &[&source], None)
        .err()
        .unwrap();
    assert_eq!(error.reason(), Some(WalletReason::TrustInput));
    let reopened = RecoverySession::create(
        &gamma,
        &evidence,
        RecoveryAuthority::new(persisted.borrow().clone(), |_| Ok(())),
        &params,
        deployment(),
    )
    .unwrap();
    assert_eq!(
        reopened.run(0, 2, &lagging, None).err().unwrap().reason(),
        Some(WalletReason::TrustInput)
    );
    reopened.verify_event(&full, receipt, &run.event).unwrap();
    run.event.topics[1] = [0; 32];
    assert_eq!(
        reopened
            .verify_event(&full, receipt, &run.event)
            .err()
            .unwrap()
            .reason(),
        Some(WalletReason::ProviderFault)
    );
}
