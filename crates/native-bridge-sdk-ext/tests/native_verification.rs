#![allow(
    clippy::type_complexity,
    clippy::ptr_arg,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    unused_imports,
    unused_variables,
    dead_code
)]
//! Full-history verification: positive vectors and isolated negative mutations. Every negative
//! test asserts the exact `NativeError` identity of exactly one guard.

mod common;
use common::*;
use native_bridge_sdk_ext::history::{self, History};
use native_bridge_sdk_ext::lockproof::parse_justification;
use native_bridge_sdk_ext::profile::*;
use native_bridge_sdk_ext::token::{Expect, VerifiedToken};
use native_bridge_sdk_ext::NativeError as E;

const T0: u64 = 1_700_000_040;
const UC_TS: u64 = 1_700_000_900;

fn verify(w: &World, out: &TokenOut, expect: Expect) -> Result<VerifiedToken, E> {
    w.bridge.verify_native_token(&out.token, expect)
}

fn err(w: &World, out: &TokenOut, expect: Expect) -> E {
    verify(w, out, expect).expect_err("must be rejected")
}

fn basic(w: &World) -> (MintSpec, Vec<Step>) {
    (
        spec(1),
        vec![tx_step(2, 7, T0 + 10), tx_step(3, 8, T0 + 20)],
    )
}

// ---- positive ----------------------------------------------------------------------------------

#[test]
fn genesis_only_receipt_verifies() {
    let w = make_world(20);
    let s = spec(1);
    let out = build_token(&w, &s, &[], T0, UC_TS);
    let v = verify(&w, &out, Expect::Receipt).unwrap();
    assert_eq!(v.outcome.leaves.len(), 1);
    assert_eq!(v.outcome.amount, s.amount);
    assert_eq!(v.lock.evm_block_number, 1234);
}

#[test]
fn receipt_with_transfers_verifies_and_exports_leaves() {
    let w = make_world(20);
    let (s, steps) = basic(&w);
    let out = build_token(&w, &s, &steps, T0, UC_TS);
    let v = verify(&w, &out, Expect::Receipt).unwrap();
    assert_eq!(v.outcome.leaves.len(), 3);
    assert_eq!(v.outcome.leaves[1].reference_time, T0 + 10);
    for (leaf, (sid, value)) in v.outcome.leaves.iter().zip(&out.leaves) {
        assert_eq!(&leaf.sid, sid);
        assert_eq!(&leaf.value, value);
    }
}

#[test]
fn return_with_terminal_burn_verifies_and_commits_release() {
    let w = make_world(20);
    let s = spec(1);
    let out = build_token(
        &w,
        &s,
        &[tx_step(2, 7, T0 + 10), burn_step(T0 + 20)],
        T0,
        UC_TS,
    );
    let v = verify(&w, &out, Expect::Return).unwrap();
    assert_eq!(v.outcome.release_to, recipient20());
    assert_ne!(v.outcome.nullifier, [0u8; 32]);
    let leaf = &v.outcome.leaves[2];
    assert_eq!(
        v.outcome.nullifier,
        nullifier(&v.outcome.cfg, &burn_id(&leaf.sid, &leaf.tx_hash))
    );
}

#[test]
fn prague_header_with_requests_hash_verifies() {
    let w = make_world(21);
    let out = build_token(&w, &spec(1), &[], T0, UC_TS);
    verify(&w, &out, Expect::Receipt).unwrap();
}

#[test]
fn explicit_deadlines_bound_the_leaf_time_strictly() {
    let w = make_world(20);
    let mut s = spec(1);
    s.mint_deadline = Some(T0 + 1);
    let steps = [Step::Transfer {
        to: signer(2),
        mask: 7,
        deadline: Some(T0 + 11),
        t: T0 + 10,
    }];
    let out = build_token(&w, &s, &steps, T0, UC_TS);
    verify(&w, &out, Expect::Receipt).unwrap();
}

#[test]
fn canonical_token_bytes_round_trip() {
    let w = make_world(20);
    let (s, steps) = basic(&w);
    let out = build_token(&w, &s, &steps, T0, UC_TS);
    let bytes = out.token.to_cbor();
    w.bridge
        .verify_native_token_bytes(&bytes, Expect::Receipt)
        .unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(w
        .bridge
        .verify_native_token_bytes(&trailing, Expect::Receipt)
        .is_err());
}

// ---- deadlines and reference times -------------------------------------------------------------

#[test]
fn deadline_equal_to_leaf_time_is_expired() {
    let w = make_world(20);
    let mut s = spec(1);
    s.mint_deadline = Some(T0);
    let out = build_token(&w, &s, &[], T0, UC_TS);
    assert_eq!(err(&w, &out, Expect::Receipt), E::DeadlineExpired);
}

#[test]
fn deadline_below_leaf_time_is_expired() {
    let w = make_world(20);
    let mut s = spec(1);
    s.mint_deadline = Some(T0 - 1);
    let out = build_token(&w, &s, &[], T0, UC_TS);
    assert_eq!(err(&w, &out, Expect::Receipt), E::DeadlineExpired);
}

#[test]
fn deadline_one_above_leaf_time_is_accepted() {
    let w = make_world(20);
    let mut s = spec(1);
    s.mint_deadline = Some(T0 + 1);
    verify(&w, &build_token(&w, &s, &[], T0, UC_TS), Expect::Receipt).unwrap();
}

#[test]
fn transfer_deadline_equal_to_leaf_time_is_expired() {
    let w = make_world(20);
    let s = spec(1);
    let steps = [Step::Transfer {
        to: signer(2),
        mask: 7,
        deadline: Some(T0 + 10),
        t: T0 + 10,
    }];
    assert_eq!(
        err(&w, &build_token(&w, &s, &steps, T0, UC_TS), Expect::Receipt),
        E::DeadlineExpired
    );
}

#[test]
fn zero_deadline_is_rejected_as_out_of_range() {
    let w = make_world(20);
    let mut s = spec(1);
    s.mint_deadline = Some(0);
    assert_eq!(
        err(&w, &build_token(&w, &s, &[], T0, UC_TS), Expect::Receipt),
        E::IntRange
    );
}

#[test]
fn old_transaction_never_expires_because_the_anchor_is_later() {
    // The deadline is far in the past relative to the certificate's later time; only t matters.
    let w = make_world(20);
    let mut s = spec(1);
    s.mint_deadline = Some(T0 + 1);
    verify(
        &w,
        &build_token(&w, &s, &[], T0, UC_TS + 10_000_000),
        Expect::Receipt,
    )
    .unwrap();
}

#[test]
fn certification_data_deadline_must_equal_the_transaction_deadline_including_null() {
    let w = make_world(20);
    let s = spec(1);
    let tw = Tweaks {
        cd_deadline: vec![(0, Some(T0 + 5))],
        ..Default::default()
    };
    let parts = lock_parts(&w, &s);
    let out = build_token_with(&w, &s, &parts, &tw, &[], T0, UC_TS);
    assert_eq!(err(&w, &out, Expect::Receipt), E::CDMismatch);

    let mut s2 = spec(1);
    s2.mint_deadline = Some(T0 + 5);
    let tw = Tweaks {
        cd_deadline: vec![(0, None)],
        ..Default::default()
    };
    let out = build_token_with(&w, &s2, &lock_parts(&w, &s2), &tw, &[], T0, UC_TS);
    assert_eq!(err(&w, &out, Expect::Receipt), E::CDMismatch);

    let tw = Tweaks {
        cd_deadline: vec![(1, Some(T0 + 99))],
        ..Default::default()
    };
    let out = build_token_with(&w, &s, &parts, &tw, &[tx_step(2, 7, T0 + 10)], T0, UC_TS);
    assert_eq!(err(&w, &out, Expect::Receipt), E::CDMismatch);
}

#[test]
fn leaf_time_after_the_anchor_time_is_rejected() {
    let w = make_world(20);
    let out = build_token(&w, &spec(1), &[], UC_TS + 1, UC_TS);
    assert_eq!(err(&w, &out, Expect::Receipt), E::ReferenceTimeFuture);
}

#[test]
fn leaf_time_equal_to_the_anchor_time_is_accepted() {
    let w = make_world(20);
    verify(
        &w,
        &build_token(&w, &spec(1), &[], UC_TS, UC_TS),
        Expect::Receipt,
    )
    .unwrap();
}

#[test]
fn mutating_only_the_proofs_reference_time_breaks_the_path() {
    let w = make_world(20);
    let s = spec(1);
    let tw = Tweaks {
        proof_time: vec![(0, T0 + 1)],
        ..Default::default()
    };
    let out = build_token_with(&w, &s, &lock_parts(&w, &s), &tw, &[], T0, UC_TS);
    // The relation uses the proof's t, so the certified path (built for T0) no longer matches.
    assert_eq!(err(&w, &out, Expect::Receipt), E::PathInvalid);
}

// ---- mint binding ------------------------------------------------------------------------------

fn mint_tweak(f: impl FnOnce(&mut Tweaks)) -> Tweaks {
    let mut t = Tweaks::default();
    f(&mut t);
    t
}

fn with(w: &World, tw: &Tweaks) -> E {
    let s = spec(1);
    let out = build_token_with(w, &s, &lock_parts(w, &s), tw, &[], T0, UC_TS);
    err(w, &out, Expect::Receipt)
}

#[test]
fn unknown_network_is_an_unknown_deployment() {
    assert_eq!(
        with(&make_world(20), &mint_tweak(|t| t.mint_network = Some(4))),
        E::UnknownDeployment
    );
}

#[test]
fn wrong_token_type_is_rejected() {
    assert_eq!(
        with(
            &make_world(20),
            &mint_tweak(|t| t.mint_ty = Some(vec![9; 32]))
        ),
        E::MintType
    );
}

#[test]
fn wrong_salt_is_rejected() {
    assert_eq!(
        with(
            &make_world(20),
            &mint_tweak(|t| t.mint_salt = Some([5; 32]))
        ),
        E::MintSalt
    );
}

#[test]
fn missing_genesis_data_is_rejected_before_generic_verification() {
    assert_eq!(
        with(&make_world(20), &mint_tweak(|t| t.mint_data = Some(None))),
        E::MintData
    );
}

#[test]
fn missing_justification_is_rejected() {
    assert_eq!(
        with(
            &make_world(20),
            &mint_tweak(|t| t.mint_justification = Some(None))
        ),
        E::MintJustif
    );
}

#[test]
fn bare_pre_envelope_payload_is_rejected() {
    let w = make_world(20);
    let bare = unicity_token::cbor::encode_array(&[
        &unicity_token::cbor::encode_byte_string(&w.dep.cfg.aid),
        &unicity_token::cbor::encode_byte_string(&[3, 232]),
    ]);
    assert_eq!(
        with(&w, &mint_tweak(|t| t.mint_data = Some(Some(bare)))),
        E::MintData
    );
}

#[test]
fn value_envelope_variants_are_each_rejected() {
    use unicity_token::cbor::*;
    let w = make_world(20);
    let aid = w.dep.cfg.aid;
    let entry =
        |id: &[u8], amt: &[u8]| encode_array(&[&encode_byte_string(id), &encode_byte_string(amt)]);
    let env = |assets: &[&[u8]], memo: Vec<u8>, version: u64| {
        encode_tag(
            39050,
            &encode_array(&[&encode_uint(version), &encode_array(assets), &memo]),
        )
    };
    let two = env(
        &[&entry(&aid, &[3, 232]), &entry(&[7; 32], &[1])],
        encode_null(),
        1,
    );
    let none = env(&[], encode_null(), 1);
    let foreign = env(&[&entry(&[7; 32], &[3, 232])], encode_null(), 1);
    let memo = env(&[&entry(&aid, &[3, 232])], encode_byte_string(b"m"), 1);
    let ver2 = env(&[&entry(&aid, &[3, 232])], encode_null(), 2);
    let leading_zero = env(&[&entry(&aid, &[0, 3, 232])], encode_null(), 1);
    let zero = env(&[&entry(&aid, &[])], encode_null(), 1);
    let too_big = env(&[&entry(&aid, &[1; 33])], encode_null(), 1);
    for (name, bad) in [
        ("two assets", two),
        ("no asset", none),
        ("foreign coin", foreign),
        ("memo", memo),
        ("version", ver2),
        ("leading zero", leading_zero),
        ("zero amount", zero),
        ("33-byte amount", too_big),
    ] {
        assert_eq!(
            with(&w, &mint_tweak(|t| t.mint_data = Some(Some(bad)))),
            E::MintData,
            "{name}"
        );
    }
}

#[test]
fn data_amount_differing_from_the_locked_amount_fails_the_lock_digest() {
    let w = make_world(20);
    let bad = value_envelope(&w.dep.cfg.aid, &[3, 233]);
    assert_eq!(
        with(&w, &mint_tweak(|t| t.mint_data = Some(Some(bad)))),
        E::LockDigest
    );
}

#[test]
fn old_v1_pointer_reason_is_rejected() {
    use unicity_token::cbor::*;
    let w = make_world(20);
    let old = encode_tag(
        39049,
        &encode_array(&[
            &encode_uint(1),
            &encode_uint(CHAIN_ID),
            &encode_byte_string(&VAULT),
            &encode_byte_string(&[0; 20]),
            &encode_uint(1),
        ]),
    );
    assert_eq!(
        with(&w, &mint_tweak(|t| t.mint_justification = Some(Some(old)))),
        E::MintJustif
    );
}

#[test]
fn foreign_registered_tag_is_rejected_as_justification() {
    use unicity_token::cbor::*;
    let w = make_world(20);
    let other = encode_tag(1330002, &encode_array(&[&encode_uint(1)]));
    assert_eq!(
        with(
            &w,
            &mint_tweak(|t| t.mint_justification = Some(Some(other)))
        ),
        E::MintJustif
    );
}

#[test]
fn unknown_vault_in_the_justification_is_an_unknown_deployment() {
    let w = make_world(20);
    let s = spec(1);
    let parts = lock_parts(&w, &s);
    let j = native_bridge_sdk_ext::lockproof::encode_justification(
        CHAIN_ID,
        &[0xee; 20],
        &[0; 20],
        1,
        &parts.encode(),
    );
    assert_eq!(
        with(&w, &mint_tweak(|t| t.mint_justification = Some(Some(j)))),
        E::UnknownDeployment
    );
}

#[test]
fn nonzero_asset_address_in_the_justification_is_rejected() {
    let w = make_world(20);
    let s = spec(1);
    let parts = lock_parts(&w, &s);
    let j = native_bridge_sdk_ext::lockproof::encode_justification(
        CHAIN_ID,
        &VAULT,
        &[1; 20],
        1,
        &parts.encode(),
    );
    assert_eq!(
        with(&w, &mint_tweak(|t| t.mint_justification = Some(Some(j)))),
        E::MintJustif
    );
}

#[test]
fn zero_nonce_is_rejected() {
    let w = make_world(20);
    let s = spec(1);
    let parts = lock_parts(&w, &s);
    let j = native_bridge_sdk_ext::lockproof::encode_justification(
        CHAIN_ID,
        &VAULT,
        &[0; 20],
        0,
        &parts.encode(),
    );
    assert_eq!(
        with(&w, &mint_tweak(|t| t.mint_justification = Some(Some(j)))),
        E::MintJustif
    );
}

// ---- strict unlock ------------------------------------------------------------------------------

fn unlock_err(idx: usize, f: impl Fn(&mut Vec<u8>) + 'static) -> E {
    let w = make_world(20);
    let s = spec(1);
    let tw = Tweaks {
        unlock: vec![(idx, Box::new(f))],
        ..Default::default()
    };
    let out = build_token_with(
        &w,
        &s,
        &lock_parts(&w, &s),
        &tw,
        &[tx_step(2, 7, T0 + 10)],
        T0,
        UC_TS,
    );
    err(&w, &out, Expect::Receipt)
}

#[test]
fn unlock_of_wrong_length_is_rejected() {
    // The SDK's own decoder would refuse a 64-byte unlock at its CBOR layer only when re-decoded
    // as a signature; the relation checks the length first.
    assert_eq!(unlock_err(1, |u| u.truncate(64)), E::UnlockLength);
    assert_eq!(unlock_err(1, |u| u.push(0)), E::UnlockLength);
}

#[test]
fn zero_r_is_rejected() {
    assert_eq!(unlock_err(1, |u| u[..32].fill(0)), E::UnlockScalars);
}

#[test]
fn high_s_is_rejected_without_normalisation() {
    // s' = n - s, with the recovery parity flipped as a normaliser would.
    assert_eq!(
        unlock_err(1, |u| {
            let n = hex_n();
            let mut s = [0u8; 32];
            s.copy_from_slice(&u[32..64]);
            let hs = sub(&n, &s);
            u[32..64].copy_from_slice(&hs);
            u[64] ^= 1;
        }),
        E::UnlockScalars
    );
}

#[test]
fn recovery_id_above_three_is_rejected() {
    assert_eq!(unlock_err(1, |u| u[64] = 4), E::UnlockRecovery);
}

#[test]
fn flipped_recovery_parity_is_rejected_though_the_signature_is_valid() {
    assert_eq!(unlock_err(1, |u| u[64] ^= 1), E::UnlockKey);
}

#[test]
fn recovery_id_two_or_three_needs_a_real_matching_recovery() {
    assert_eq!(unlock_err(1, |u| u[64] = 2), E::UnlockKey);
    assert_eq!(unlock_err(1, |u| u[64] = 3), E::UnlockKey);
}

#[test]
fn the_universal_minter_unlock_is_held_to_the_same_rule() {
    assert_eq!(unlock_err(0, |u| u[64] ^= 1), E::UnlockKey);
}

#[test]
fn mint_signed_by_a_non_minter_key_is_rejected() {
    let w = make_world(20);
    let s = spec(1);
    let tw = Tweaks {
        minter_override: Some(signer(77)),
        ..Default::default()
    };
    let out = build_token_with(&w, &s, &lock_parts(&w, &s), &tw, &[], T0, UC_TS);
    assert_eq!(err(&w, &out, Expect::Receipt), E::UnlockKey);
}

fn hex_n() -> [u8; 32] {
    let mut n = [0u8; 32];
    n.copy_from_slice(
        &from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap(),
    );
    n
}

fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = a[i] as i16 - b[i] as i16 - borrow;
        borrow = if d < 0 {
            d += 256;
            1
        } else {
            0
        };
        out[i] = d as u8;
    }
    out
}

// ---- transfers and burns -----------------------------------------------------------------------

#[test]
fn intermediate_transfer_data_is_rejected() {
    let w = make_world(20);
    let s = spec(1);
    let tw = Tweaks {
        transfer_data: vec![(1, Some(vec![1, 2, 3]))],
        ..Default::default()
    };
    let out = build_token_with(
        &w,
        &s,
        &lock_parts(&w, &s),
        &tw,
        &[tx_step(2, 7, T0 + 10), tx_step(3, 8, T0 + 20)],
        T0,
        UC_TS,
    );
    assert_eq!(err(&w, &out, Expect::Receipt), E::TransferData);
}

#[test]
fn burn_before_the_last_transfer_is_rejected() {
    let w = make_world(20);
    let out = build_token(
        &w,
        &spec(1),
        &[burn_step(T0 + 10), tx_step(3, 8, T0 + 20)],
        T0,
        UC_TS,
    );
    assert_eq!(err(&w, &out, Expect::Return), E::BurnNotFinal);
}

#[test]
fn receipt_rejects_a_terminal_burn() {
    let w = make_world(20);
    let out = build_token(&w, &spec(1), &[burn_step(T0 + 10)], T0, UC_TS);
    assert_eq!(err(&w, &out, Expect::Receipt), E::UnexpectedBurn);
}

#[test]
fn return_requires_a_burn() {
    let w = make_world(20);
    let out = build_token(&w, &spec(1), &[], T0, UC_TS);
    assert_eq!(err(&w, &out, Expect::Return), E::NoTransfers);
}

#[test]
fn return_whose_last_transfer_is_a_signature_transfer_is_not_a_burn() {
    let w = make_world(20);
    let out = build_token(&w, &spec(1), &[tx_step(2, 7, T0 + 10)], T0, UC_TS);
    assert_eq!(err(&w, &out, Expect::Return), E::NotBurn);
}

fn burn_reason_err(f: impl FnOnce(&World, &MintSpec) -> Vec<u8>) -> E {
    let w = make_world(20);
    let s = spec(1);
    let reason = f(&w, &s);
    let out = build_token(&w, &s, &[Step::BurnWith { reason, t: T0 + 10 }], T0, UC_TS);
    err(&w, &out, Expect::Return)
}

#[test]
fn burn_recipient_zero_or_vault_is_rejected() {
    let zero = burn_reason_err(|w, s| {
        return_reason(
            CHAIN_ID,
            &VAULT,
            &[0; 20],
            &w.dep.cfg.ty,
            &w.dep.cfg.aid,
            &[0; 20],
            &s.amount,
        )
    });
    assert_eq!(zero, E::ReturnRecip);
    let vault = burn_reason_err(|w, s| {
        return_reason(
            CHAIN_ID,
            &VAULT,
            &[0; 20],
            &w.dep.cfg.ty,
            &w.dep.cfg.aid,
            &VAULT,
            &s.amount,
        )
    });
    assert_eq!(vault, E::ReturnRecip);
}

#[test]
fn burn_amount_must_equal_the_genesis_amount() {
    let e = burn_reason_err(|w, _| {
        return_reason(
            CHAIN_ID,
            &VAULT,
            &[0; 20],
            &w.dep.cfg.ty,
            &w.dep.cfg.aid,
            &recipient20(),
            &[3, 231],
        )
    });
    assert_eq!(e, E::ReturnAmount);
}

#[test]
fn burn_reason_naming_another_vault_or_chain_is_rejected() {
    let a = burn_reason_err(|w, s| {
        return_reason(
            CHAIN_ID,
            &[0xee; 20],
            &[0; 20],
            &w.dep.cfg.ty,
            &w.dep.cfg.aid,
            &recipient20(),
            &s.amount,
        )
    });
    assert_eq!(a, E::ReturnData);
    let b = burn_reason_err(|w, s| {
        return_reason(
            CHAIN_ID + 1,
            &VAULT,
            &[0; 20],
            &w.dep.cfg.ty,
            &w.dep.cfg.aid,
            &recipient20(),
            &s.amount,
        )
    });
    assert_eq!(b, E::ReturnData);
}

#[test]
fn burn_reason_with_a_nonzero_fee_deadline_slot_is_rejected() {
    use unicity_token::cbor::*;
    let e = burn_reason_err(|w, s| {
        encode_tag(
            39048,
            &encode_array(&[
                &encode_uint(1),
                &encode_uint(CHAIN_ID),
                &encode_byte_string(&VAULT),
                &encode_byte_string(&[0; 20]),
                &encode_byte_string(&w.dep.cfg.ty),
                &encode_byte_string(&w.dep.cfg.aid),
                &encode_byte_string(&recipient20()),
                &encode_byte_string(&s.amount),
                &encode_byte_string(&[0; 20]),
                &encode_byte_string(&[]),
                &encode_uint(5),
            ]),
        )
    });
    assert_eq!(e, E::ReturnData);
}

#[test]
fn burn_predicate_must_commit_to_the_reason() {
    let w = make_world(20);
    let s = spec(1);
    let reason = return_reason(
        CHAIN_ID,
        &VAULT,
        &[0; 20],
        &w.dep.cfg.ty,
        &w.dep.cfg.aid,
        &recipient20(),
        &s.amount,
    );
    // The data is right, the predicate commits to other bytes.
    let out = build_token(
        &w,
        &s,
        &[Step::BurnWith {
            reason: reason.clone(),
            t: T0 + 10,
        }],
        T0,
        UC_TS,
    );
    verify(&w, &out, Expect::Return).unwrap();
    let mut other = reason;
    other.push(0);
    // Trailing byte: the strict scan of the reason itself fails first.
    let out = build_token(
        &w,
        &s,
        &[Step::BurnWith {
            reason: other,
            t: T0 + 10,
        }],
        T0,
        UC_TS,
    );
    assert_eq!(err(&w, &out, Expect::Return), E::ReturnData);
}

#[test]
fn nullifier_excludes_time_paths_and_unlock_representation() {
    let w = make_world(20);
    let s = spec(1);
    let a = build_token(&w, &s, &[burn_step(T0 + 10)], T0, UC_TS);
    let b = build_token(&w, &s, &[burn_step(T0 + 10)], T0, UC_TS + 50);
    let va = verify(&w, &a, Expect::Return).unwrap();
    let vb = verify(&w, &b, Expect::Return).unwrap();
    assert_eq!(va.outcome.nullifier, vb.outcome.nullifier);
}

#[test]
fn too_many_transfers_is_a_budget_failure() {
    let w = make_world(20);
    let steps: Vec<Step> = (0..65)
        .map(|i| tx_step(2 + (i % 2) as u8, i as u8, T0 + 1))
        .collect();
    let out = build_token(&w, &spec(1), &steps, T0, UC_TS);
    assert_eq!(err(&w, &out, Expect::Receipt), E::TooManyTx);
}

#[test]
fn sixty_four_transfers_verify() {
    let w = make_world(20);
    let steps: Vec<Step> = (0..64)
        .map(|i| tx_step(2 + (i % 2) as u8, i as u8, T0 + 1))
        .collect();
    let out = build_token(&w, &spec(1), &steps, T0, UC_TS);
    // The chain alternates owners 2,3: each transfer is signed by the previous recipient.
    verify(&w, &out, Expect::Receipt).unwrap_or_else(|e| panic!("{e}"));
}

// ---- compact history level ---------------------------------------------------------------------

#[test]
fn compact_history_round_trips_the_projection() {
    let w = make_world(20);
    let (s, steps) = basic(&w);
    let out = build_token(&w, &s, &steps, T0, UC_TS);
    let bytes = history::project(&out.token);
    let h = History::decode(&bytes).unwrap();
    assert_eq!(h.transfers.len(), 2);
    assert_eq!(h.mint_t, T0);
    assert_eq!(h.times, vec![T0 + 10, T0 + 20]);
    let o = history::verify_receipt(&w.dep, &bytes).unwrap();
    assert_eq!(o.leaves.len(), 3);
    assert_eq!(
        history::verify_mint(&w.dep, &bytes).unwrap_err(),
        E::HasTransfers
    );
    assert_eq!(
        history::verify_return(&w.dep, &bytes).unwrap_err(),
        E::NotBurn
    );
}

#[test]
fn compact_history_rejects_noncanonical_trailing_and_truncated_bytes() {
    let w = make_world(20);
    let out = build_token(&w, &spec(1), &[], T0, UC_TS);
    let bytes = history::project(&out.token);
    let mut t = bytes.clone();
    t.push(0);
    assert_eq!(History::decode(&t).unwrap_err(), E::Trailing);
    assert_eq!(
        History::decode(&bytes[..bytes.len() - 1]).unwrap_err(),
        E::Truncated
    );
    // A pre-3.0 shape: two-element tuples with no reference time.
    let old = unicity_token::cbor::encode_array(&[
        &unicity_token::cbor::encode_array(&[&[0u8; 0][..], &[0u8; 0][..]]),
        &unicity_token::cbor::encode_array(&[]),
    ]);
    assert!(History::decode(&old).is_err());
}

#[test]
fn old_version_one_transaction_shapes_are_rejected() {
    use unicity_token::cbor::*;
    // A v1 mint (arity 7) inside an otherwise well-formed projection tuple.
    let mint_v1 = encode_tag(
        39041,
        &encode_array(&[
            &encode_uint(1),
            &encode_uint(3),
            &encode_null(),
            &encode_null(),
            &encode_null(),
            &encode_null(),
            &encode_null(),
        ]),
    );
    let tuple = encode_array(&[&mint_v1, &encode_null(), &encode_uint(1)]);
    let bytes = encode_array(&[&tuple, &encode_array(&[])]);
    assert!(History::decode(&bytes).is_err());
}

#[test]
fn prepare_lock_binds_cfg_nonce_amount_id_and_recipient() {
    let w = make_world(20);
    let s = spec(1);
    let (digest, recipient, tid, salt) = digest_of(&w, &s);
    let o = history::prepare_lock(&w.dep.cfg, 1, &s.amount, &recipient.to_cbor()).unwrap();
    assert_eq!(o.lock_digest, digest);
    assert_eq!(&o.token_id, tid.bytes());
    assert_eq!(o.salt, salt);
    assert_eq!(
        history::prepare_lock(&w.dep.cfg, 0, &s.amount, &recipient.to_cbor()).unwrap_err(),
        E::LockInput
    );
    assert_eq!(
        history::prepare_lock(&w.dep.cfg, 1, &[0, 1], &recipient.to_cbor()).unwrap_err(),
        E::LockInput
    );
    assert_eq!(
        history::prepare_lock(&w.dep.cfg, 1, &[], &recipient.to_cbor()).unwrap_err(),
        E::LockInput
    );
}

#[test]
fn justification_is_bounded_before_parsing() {
    let big = vec![0u8; 64 * 1024 + 1];
    assert_eq!(parse_justification(&big).unwrap_err(), E::InputTooLarge);
}

// ---- the pure relation, with no SDK in the loop (what ureth and the B2 kernel run) -------------

fn relation(w: &World, out: &TokenOut) -> Result<history::Outcome, E> {
    history::verify_receipt(&w.dep, &history::project(&out.token))
}

#[test]
fn relation_alone_enforces_certification_data_deadline_equality() {
    let w = make_world(20);
    let s = spec(1);
    let parts = lock_parts(&w, &s);
    let tw = Tweaks {
        cd_deadline: vec![(0, Some(T0 + 5))],
        ..Default::default()
    };
    let out = build_token_with(&w, &s, &parts, &tw, &[], T0, UC_TS);
    assert_eq!(relation(&w, &out).unwrap_err(), E::CDMismatch);
    let mut s2 = spec(1);
    s2.mint_deadline = Some(T0 + 5);
    let tw = Tweaks {
        cd_deadline: vec![(0, None)],
        ..Default::default()
    };
    let out = build_token_with(&w, &s2, &lock_parts(&w, &s2), &tw, &[], T0, UC_TS);
    assert_eq!(relation(&w, &out).unwrap_err(), E::CDMismatch);
}

#[test]
fn relation_alone_enforces_t_strictly_below_the_deadline() {
    let w = make_world(20);
    for (e, ok) in [(T0 - 1, false), (T0, false), (T0 + 1, true)] {
        let mut s = spec(1);
        s.mint_deadline = Some(e);
        let out = build_token(&w, &s, &[], T0, UC_TS);
        match relation(&w, &out) {
            Ok(_) => assert!(ok, "e={e}"),
            Err(err) => {
                assert!(!ok);
                assert_eq!(err, E::DeadlineExpired, "e={e}");
            }
        }
    }
}
