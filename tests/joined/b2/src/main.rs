//! Direct merged B2 execution, not a node factory, RPC or vault call.
use reth_unicity_b2::{run, Error};
use serde_json::Value;

fn hx(s: &Value) -> Vec<u8> {
    let s = s.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).unwrap()).unwrap();
    let f: Value = serde_json::from_slice(&bytes).unwrap();
    let cases = f["cases"].as_array().unwrap();
    assert!(cases.len() >= 5);
    for c in cases {
        let request = hx(&c["request"]);
        let out = run(&request, u64::MAX).unwrap();
        assert_eq!(out.bytes, hx(&c["expected"]), "{}", c["name"]);
        assert!(out.gas > 0);
        assert_eq!(run(&request, out.gas - 1).unwrap_err(), Error::OutOfGas);
        assert_eq!(run(&request, out.gas).unwrap().bytes, out.bytes);
        println!(
            "PASS {}: exact ABI, exact gas {}, gas-1 OOG",
            c["name"], out.gas
        );
    }
    assert_eq!(run(&[0], u64::MAX).unwrap_err(), Error::ABIFraming);
    assert_eq!(
        run(&vec![0; reth_unicity_b2::MAX_INPUT + 1], u64::MAX).unwrap_err(),
        Error::InputTooLarge
    );
    println!("PASS framing and outer input budget (named errors)");
}
