//! The protocol 6 vault layout: the slots the plug-ins read against the corpus derive cases and the contracts' layout test.
use native_bridge_sdk_ext::profile::{
    keccak, lock_digest_slot, locked_amount_slot, redeemed_amount_slot, spent_part_slot,
    storage_trie_key, word, SLOT_SPENT_PART,
};
use serde_json::Value;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn lock_redeemed_and_locked_amount_slots_of_every_corpus_derive_case() {
    let path = format!(
        "{}/../../protocol/vectors/vault/cases.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let derive: Vec<&Value> = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["op"] == "derive")
        .collect();
    assert!(derive.len() >= 4);
    for c in derive {
        let n: u64 = c["input"].as_str().unwrap().parse().unwrap();
        let want = &c["expected"]["values"];
        for (slot, name) in [
            (lock_digest_slot(n), "lock"),
            (redeemed_amount_slot(n), "redeemed"),
            (locked_amount_slot(n), "lockedAmount"),
        ] {
            assert_eq!(
                hex(&slot),
                want[format!("{name}Slot")],
                "{} {name}Slot",
                c["id"]
            );
            assert_eq!(
                hex(&storage_trie_key(&slot)),
                want[format!("{name}TrieKey")],
                "{} {name}TrieKey",
                c["id"]
            );
        }
    }
}

/// contracts `test_layout_u64MaxNonceSlotsHoldTheAmountsAndTheSpentPart`:
/// `keccak256(abi.encode(partId, keccak256(abi.encode(nonce, 9))))`.
#[test]
fn spent_part_is_the_nested_mapping_slot() {
    let part = [0xabu8; 32];
    let n = u64::MAX;
    let inner = keccak(&[&word(n), &word(SLOT_SPENT_PART)]);
    assert_eq!(spent_part_slot(n, &part), keccak(&[&part, &inner]));
    assert_ne!(spent_part_slot(n, &part), spent_part_slot(n - 1, &part));
    assert_ne!(spent_part_slot(n, &part), spent_part_slot(n, &[0xac; 32]));
}
