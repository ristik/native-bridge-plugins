//! Measurement helper (bft-core measure/nb2-consolidation): the Rust plug-in's verifier on evidence files, one JSON line each.
//!
//!     nb2_verify_return GAMMA_HEX_FILE TRUST_BUNDLE PIN_HEX_FILE test|production EVIDENCE...
//!
//! A line holds the 192-byte verdict ABI (`verdict`) or the section 14 rule that refuses the evidence (`rule`), and the time it took.
use std::time::Instant;

use native_bridge_sdk_ext::nb2::config::{build_params, Build};
use native_bridge_sdk_ext::nb2::errors::Error;
use native_bridge_sdk_ext::nb2::util::{from_hex, hex0x};
use native_bridge_sdk_ext::nb2::verify::{verdict_abi, verify_return};
use native_bridge_sdk_ext::trust::TrustInput;

fn hex_file(path: &str) -> Vec<u8> {
    let s = std::fs::read_to_string(path).expect("read a hex file");
    from_hex(s.trim().trim_start_matches("0x")).expect("hex")
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(a.len() >= 5, "usage: nb2_verify_return GAMMA_HEX_FILE TRUST_BUNDLE PIN_HEX_FILE test|production EVIDENCE...");
    let gamma = hex_file(&a[1]);
    let bundle = std::fs::read(&a[2]).expect("read the trust bundle");
    let pin: [u8; 32] = hex_file(&a[3]).try_into().expect("a 32-byte pin");
    let trust = TrustInput::from_bundle(&bundle, &pin).expect("the trust bundle");
    let params = build_params(if a[4] == "production" { Build::Production } else { Build::Test });
    for f in &a[5..] {
        let ev = std::fs::read(f).expect("read evidence");
        let t0 = Instant::now();
        let r = verify_return(&gamma, &ev, &trust, &params);
        let us = t0.elapsed().as_micros();
        match r {
            Ok(v) => println!("{{\"file\":\"{f}\",\"verdict\":\"{}\",\"us\":{us}}}", hex0x(&verdict_abi(&v))),
            Err(Error::Rule(n)) => println!("{{\"file\":\"{f}\",\"rule\":\"{}\",\"us\":{us}}}", n.rule.name()),
            Err(e) => println!("{{\"file\":\"{f}\",\"rule\":\"{}\",\"us\":{us}}}", format!("{e:?}").replace('"', "'")),
        }
    }
}
