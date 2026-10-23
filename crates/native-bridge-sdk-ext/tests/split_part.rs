#![allow(clippy::type_complexity, clippy::too_many_arguments, dead_code)]
//! The wallet side of a split part (protocol 6) on real lineages in the test world: a lock-backed root split into two outputs, the
//! outputs minted with certified proofs, a split of a split. The split itself is built here from the crate's own primitives (the
//! pinned SDK's builder commits bare assets, not the bridge's envelope); the SDK's split verifier then checks it, so the two agree on
//! the bytes.

mod common;
use common::*;
use native_bridge_sdk_ext::compose::compose_input;
use native_bridge_sdk_ext::history::project;
use native_bridge_sdk_ext::limits::MAX_JUSTIFICATION_BYTES;
use native_bridge_sdk_ext::lineage::compose_offline_v2;
use native_bridge_sdk_ext::profile::{derive_token_id, value_envelope};
use native_bridge_sdk_ext::proof::{
    build_return_proof, build_return_proof_with, check_burn_projection_anchors, preflight_burn,
};
use native_bridge_sdk_ext::resources::preflight_token;
use native_bridge_sdk_ext::split::{
    split_justification_bytes, split_manifest_bytes, split_output_commitment, sum_leaf_hash,
    sum_node_hash, SumStep,
};
use native_bridge_sdk_ext::splitpart::{lineage_proofs, split_chain};
use native_bridge_sdk_ext::token::Expect;
use native_bridge_sdk_ext::verifier::BridgedTokenIssuancePolicy;
use native_bridge_sdk_ext::NativeError as E;
use num_bigint::BigUint;
use std::rc::Rc;
use unicity_token::api::NetworkId;
use unicity_token::crypto::signer::Signer;
use unicity_token::predicate::builtin::SignaturePredicate;
use unicity_token::transaction::{MintTransaction, Token, TokenSalt, TokenType};

const T0: u64 = 1_700_000_000;
const UC_TS: u64 = T0 + 10_000;

fn amt(n: u64) -> Vec<u8> {
    let b = n.to_be_bytes();
    b[b.iter().position(|&x| x != 0).unwrap_or(7)..].to_vec()
}

/// One output: its owner, amount and salt.
#[derive(Clone, Copy)]
struct Out {
    owner: u8,
    amount: u64,
    salt: u8,
}

/// A two-output split of the token `source_id`: the manifest and, per output, its exact mint data, salt and allocation proof.
fn split2(
    w: &World,
    source_id: &[u8; 32],
    outs: [Out; 2],
) -> (Vec<u8>, Vec<(Vec<u8>, [u8; 32], Vec<SumStep>)>) {
    let leaf = |o: &Out| {
        let salt = [o.salt; 32];
        let id = derive_token_id(&salt, NETWORK);
        let data = value_envelope(&w.dep.cfg.aid, &amt(o.amount));
        let recipient = SignaturePredicate::new(signer(o.owner).public_key())
            .to_encoded()
            .to_cbor();
        let d = split_output_commitment(
            source_id,
            NETWORK,
            &recipient,
            &salt,
            &id,
            &w.dep.cfg.ty,
            &data,
        );
        (
            id,
            data,
            salt,
            sum_leaf_hash(&id, &d, &BigUint::from(o.amount)).unwrap(),
            BigUint::from(o.amount),
        )
    };
    let (a, b) = (leaf(&outs[0]), leaf(&outs[1]));
    // the bifurcation is the first bit, MSB first, where the two IDs differ; the 0 side is the left child
    let depth = (0..256u16)
        .find(|&i| (a.0[(i / 8) as usize] ^ b.0[(i / 8) as usize]) >> (7 - i % 8) & 1 == 1)
        .unwrap() as u8;
    let a_left = a.0[(depth / 8) as usize] >> (7 - depth % 8) & 1 == 0;
    let (l, r) = if a_left { (&a, &b) } else { (&b, &a) };
    let (root, _) = sum_node_hash(depth, &l.3, &l.4, &r.3, &r.4).unwrap();
    let proof = |sib: &(_, _, _, [u8; 32], BigUint)| {
        vec![SumStep {
            depth,
            hash: sib.3,
            sum: sib.4.clone(),
        }]
    };
    (
        split_manifest_bytes(&root),
        vec![(a.1.clone(), a.2, proof(&b)), (b.1.clone(), b.2, proof(&a))],
    )
}

/// Mint output `j` of a split of `burned` and give it `steps`.
fn mint_child(
    w: &World,
    burned: &Token,
    out: Out,
    data: &[u8],
    salt: [u8; 32],
    proof: &[SumStep],
    steps: &[Step],
    t: u64,
) -> TokenOut {
    let mint = MintTransaction::create(
        NetworkId::new(NETWORK).unwrap(),
        SignaturePredicate::new(signer(out.owner).public_key()).to_encoded(),
        TokenType::new(w.dep.cfg.ty.to_vec()),
        TokenSalt::from_bytes(salt),
        Some(data.to_vec()),
        Some(split_justification_bytes(&burned.to_cbor(), proof)),
        None,
    )
    .unwrap();
    let mut s = spec(out.owner);
    s.amount = amt(out.amount);
    assemble_token(w, &s, mint, &Tweaks::default(), steps, t, UC_TS)
}

#[derive(Default)]
struct RootOpts {
    stored: Option<[u8; 32]>,
    uc_partition: Option<u32>,
    steps: Vec<Step>,
}

/// Lock 1000 -> split 400 + 600 (the 400 to owner 2); `depth` 2 splits the 400 again into 150 + 250 (the 150 to owner 4).
fn lineage(w: &World, child_steps: Vec<Step>, depth: u8, o: RootOpts) -> (TokenOut, TokenOut) {
    let mut root = spec(1);
    root.evm.stored = o.stored;
    let root_id = derive_token_id(&derive_salt_of(w, &root), NETWORK);
    let first = [
        Out {
            owner: 2,
            amount: 400,
            salt: 0x10,
        },
        Out {
            owner: 3,
            amount: 600,
            salt: 0x20,
        },
    ];
    let (manifest, outs) = split2(w, &root_id, first);
    let mut steps = o.steps;
    let burn_t = T0 + 10 + steps.len() as u64;
    steps.push(Step::BurnWith {
        reason: manifest,
        t: burn_t,
    });
    let parts = lock_parts(w, &root);
    let tw = Tweaks {
        uc_partition: o.uc_partition,
        ..Tweaks::default()
    };
    let burned = build_token_with(w, &root, &parts, &tw, &steps, T0, UC_TS);
    if depth == 1 {
        let (d, s, p) = &outs[0];
        let child = mint_child(
            w,
            &burned.token,
            first[0],
            d,
            *s,
            p,
            &child_steps,
            burn_t + 10,
        );
        return (burned, child);
    }
    let child_id = derive_token_id(&outs[0].1, NETWORK);
    let second = [
        Out {
            owner: 4,
            amount: 150,
            salt: 0x30,
        },
        Out {
            owner: 5,
            amount: 250,
            salt: 0x40,
        },
    ];
    let (manifest2, outs2) = split2(w, &child_id, second);
    let (d, s, p) = &outs[0];
    let burned_child = mint_child(
        w,
        &burned.token,
        first[0],
        d,
        *s,
        p,
        &[Step::BurnWith {
            reason: manifest2,
            t: burn_t + 20,
        }],
        burn_t + 10,
    );
    let (d2, s2, p2) = &outs2[0];
    let child = mint_child(
        w,
        &burned_child.token,
        second[0],
        d2,
        *s2,
        p2,
        &child_steps,
        burn_t + 30,
    );
    (burned, child)
}

fn derive_salt_of(w: &World, s: &MintSpec) -> [u8; 32] {
    digest_of(w, s).3
}

#[test]
fn a_held_part_verifies_with_its_root_lock_and_every_lineage_leaf() {
    let w = make_world(20);
    let (root, child) = lineage(&w, vec![tx_step(7, 9, T0 + 40)], 1, RootOpts::default());
    let v = w
        .bridge
        .verify_native_token(&child.token, Expect::Receipt)
        .unwrap();
    let l = v.lineage.as_ref().unwrap();
    assert_eq!(l.depth, 1);
    assert_eq!(l.part_amount, amt(400));
    assert_eq!(
        v.outcome.amount,
        amt(1000),
        "the root amount: what the lock digest commits"
    );
    assert_eq!(v.outcome.token_id, *root.token.id().bytes());
    assert_eq!(l.part_token_id, *child.token.id().bytes());
    assert_eq!(
        v.outcome.leaves.len(),
        4,
        "the root mint and its split burn, the part mint and its transfer"
    );
    assert_eq!(v.outcome.nullifier, [0; 32], "a held part has no return");
    let chain = split_chain(&child.token).unwrap();
    assert_eq!(
        chain.iter().map(|t| *t.id().bytes()).collect::<Vec<_>>(),
        vec![*root.token.id().bytes(), *child.token.id().bytes()]
    );
}

#[test]
fn a_returned_part_builds_the_v2_envelope_priced_as_the_composition_prices_it() {
    let w = make_world(20);
    let (_, child) = lineage(
        &w,
        vec![tx_step(7, 9, T0 + 40), burn_step(T0 + 41)],
        1,
        RootOpts::default(),
    );
    let (env, verified, gate) = build_return_proof(&w.bridge, &child.token).unwrap();
    let l = verified.lineage.unwrap();
    assert_eq!(env.leaf_proofs.len(), l.outcome.leaves.len());
    let cfg = w.dep.cfg.to_bytes();
    let (offline, gas) = compose_offline_v2(&w.dep, &cfg, &env.encode()).unwrap();
    assert_eq!(
        gate.native, gas,
        "the gate is the V2 charge: the schedule over every leaf plus the walk"
    );
    assert_eq!(offline.outcome.nullifier, l.outcome.nullifier);
    assert_eq!(offline.outcome.lock_digest, l.outcome.lock_digest);
    assert!(!compose_input(2, &cfg, &env.encode()).is_empty());
}

#[test]
fn a_depth_two_part_verifies_and_returns() {
    let w = make_world(20);
    let (root, child) = lineage(&w, vec![burn_step(T0 + 80)], 2, RootOpts::default());
    preflight_token(&child.token.to_cbor()).unwrap();
    let (env, verified, gate) = build_return_proof(&w.bridge, &child.token).unwrap();
    let l = verified.lineage.unwrap();
    assert_eq!(l.depth, 2);
    assert_eq!(l.part_amount, amt(150));
    assert_eq!(l.outcome.token_id, *root.token.id().bytes());
    assert_eq!(
        l.levels
            .iter()
            .map(|x| x.amount.clone())
            .collect::<Vec<_>>(),
        vec![amt(1000), amt(400), amt(150)]
    );
    assert_eq!(
        gate.native,
        compose_offline_v2(&w.dep, &w.dep.cfg.to_bytes(), &env.encode())
            .unwrap()
            .1
    );
}

#[test]
fn the_burn_estimate_adds_exactly_the_walk_to_the_lineage_projection() {
    let w = make_world(20);
    let (_, child) = lineage(&w, vec![tx_step(7, 9, T0 + 40)], 1, RootOpts::default());
    let held = w
        .bridge
        .verify_native_token(&child.token, Expect::Receipt)
        .unwrap();
    let leaves = held.outcome.leaves.len() + 1;
    let base = check_burn_projection_anchors(
        w.dep.cfg.to_bytes().len() as u64,
        w.dep.policy.to_bytes().len() as u64,
        leaves as u64,
        project(&child.token).len(),
        1,
    )
    .unwrap();
    let gate = preflight_burn(&w.bridge, &child.token).unwrap();
    let split = held.lineage.unwrap().split_gas;
    assert_eq!(gate.native - base.native, split);
    assert_eq!(gate.total - base.total, split);
}

#[test]
fn a_held_part_ending_in_a_burn_is_not_held() {
    let w = make_world(20);
    let (_, child) = lineage(
        &w,
        vec![tx_step(7, 9, T0 + 40), burn_step(T0 + 41)],
        1,
        RootOpts::default(),
    );
    assert_eq!(
        w.bridge
            .verify_native_token(&child.token, Expect::Receipt)
            .unwrap_err(),
        E::UnexpectedBurn
    );
    w.bridge
        .verify_native_token(&child.token, Expect::Return)
        .unwrap();
}

#[test]
fn an_ancestor_certified_in_another_partition_is_not_admitted() {
    let w = make_world(20);
    let o = RootOpts {
        uc_partition: Some(AGG_PARTITION + 1),
        ..RootOpts::default()
    };
    let (_, child) = lineage(&w, vec![], 1, o);
    assert_eq!(
        w.bridge
            .verify_native_token(&child.token, Expect::Receipt)
            .unwrap_err(),
        E::NotAdmitted
    );
}

#[test]
fn the_roots_lock_proof_backs_every_part() {
    let w = make_world(20);
    let o = RootOpts {
        stored: Some([0; 32]),
        ..RootOpts::default()
    };
    let (_, child) = lineage(&w, vec![], 1, o);
    assert_eq!(
        w.bridge
            .verify_native_token(&child.token, Expect::Receipt)
            .unwrap_err(),
        E::StorageValue
    );
}

#[test]
fn a_split_reason_is_bounded_as_a_token_not_as_a_lock_reason() {
    let w = make_world(20);
    let steps: Vec<Step> = (0..90)
        .map(|i| {
            tx_step(
                if i % 2 == 0 { 8 } else { 1 },
                3 + (i % 5) as u8,
                T0 + 1 + i,
            )
        })
        .collect();
    let (_, child) = lineage(
        &w,
        vec![],
        1,
        RootOpts {
            steps,
            ..RootOpts::default()
        },
    );
    let j = child
        .token
        .genesis()
        .transaction()
        .justification()
        .unwrap()
        .len();
    assert!(j > MAX_JUSTIFICATION_BYTES, "{j}");
    preflight_token(&child.token.to_cbor()).unwrap();
    w.bridge
        .verify_native_token(&child.token, Expect::Receipt)
        .unwrap();
}

#[test]
fn the_issuance_policy_admits_a_split_output_only_as_its_root_deployments_envelope() {
    let w = make_world(20);
    let (_, child) = lineage(&w, vec![], 1, RootOpts::default());
    let policy = BridgedTokenIssuancePolicy::new(Rc::new(w.bridge.clone()), &w.dep.cfg.ty);
    policy.check(child.token.genesis()).unwrap();
    // the same reason over another asset's envelope
    let g = child.token.genesis().transaction();
    let other = MintTransaction::create(
        NetworkId::new(NETWORK).unwrap(),
        SignaturePredicate::new(signer(2).public_key()).to_encoded(),
        g.token_type().clone(),
        g.salt().clone(),
        Some(value_envelope(&[9; 32], &amt(400))),
        g.justification().map(<[u8]>::to_vec),
        None,
    )
    .unwrap();
    let forged = assemble_token(&w, &spec(2), other, &Tweaks::default(), &[], T0 + 30, UC_TS);
    assert_eq!(
        policy.check(forged.token.genesis()).unwrap_err(),
        E::IssuanceData
    );
}

#[test]
fn fresh_witnesses_go_into_the_envelope_only_for_the_same_certified_leaves() {
    let w = make_world(20);
    let (_, child) = lineage(&w, vec![burn_step(T0 + 41)], 1, RootOpts::default());
    let proofs = lineage_proofs(&split_chain(&child.token).unwrap());
    let same = build_return_proof_with(&w.bridge, &child.token, Some(&proofs))
        .unwrap()
        .0;
    assert_eq!(
        same.encode(),
        build_return_proof(&w.bridge, &child.token)
            .unwrap()
            .0
            .encode()
    );
    assert_eq!(
        build_return_proof_with(&w.bridge, &child.token, Some(&proofs[1..])).unwrap_err(),
        E::RefreshMismatch
    );
    // a prefix: every pair it has matches, so only the count refuses it
    assert_eq!(
        build_return_proof_with(&w.bridge, &child.token, Some(&proofs[..proofs.len() - 1]))
            .unwrap_err(),
        E::RefreshMismatch
    );
    let mut swapped = proofs.clone();
    swapped.swap(0, 1);
    assert_eq!(
        build_return_proof_with(&w.bridge, &child.token, Some(&swapped)).unwrap_err(),
        E::RefreshMismatch
    );
    // the same certification data with another reference time is another leaf
    let mut later = proofs.clone();
    later[1].reference_time += 1;
    assert_eq!(
        build_return_proof_with(&w.bridge, &child.token, Some(&later)).unwrap_err(),
        E::RefreshMismatch
    );
}

#[test]
fn the_sdk_verification_runs_on_a_part_a_certificate_of_another_tree_is_refused() {
    use unicity_token::transaction::CertifiedMintTransaction;
    let w = make_world(20);
    let root = spec(1);
    let root_id = derive_token_id(&derive_salt_of(&w, &root), NETWORK);
    let first = [
        Out {
            owner: 2,
            amount: 400,
            salt: 0x10,
        },
        Out {
            owner: 3,
            amount: 600,
            salt: 0x20,
        },
    ];
    let (manifest, outs) = split2(&w, &root_id, first);
    let burned = build_token(
        &w,
        &root,
        &[Step::BurnWith {
            reason: manifest,
            t: T0 + 10,
        }],
        T0,
        UC_TS,
    );
    let child = mint_child(
        &w,
        &burned.token,
        first[0],
        &outs[0].0,
        outs[0].1,
        &outs[0].2,
        &[],
        T0 + 20,
    );
    let sibling = mint_child(
        &w,
        &burned.token,
        first[1],
        &outs[1].0,
        outs[1].1,
        &outs[1].2,
        &[],
        T0 + 21,
    );
    w.bridge
        .verify_native_token(&child.token, Expect::Receipt)
        .unwrap();
    // the part's mint proof with the sibling's certificate: same partition, shard and time, another state root
    let mut proof = child.token.genesis().inclusion_proof().clone();
    proof.unicity_certificate = sibling
        .token
        .genesis()
        .inclusion_proof()
        .unicity_certificate
        .clone();
    let forged = Token::new(
        CertifiedMintTransaction::new(child.token.genesis().transaction().clone(), proof),
        child.token.transactions().to_vec(),
    );
    let e = w
        .bridge
        .verify_native_token(&forged, Expect::Receipt)
        .unwrap_err();
    // the relation and the admission accept it (the certificate is the deployment's own): only the SDK's path check refuses
    assert!(
        ![
            E::ReferenceTimeFuture,
            E::NotAdmitted,
            E::ShardMismatch,
            E::CDMismatch
        ]
        .contains(&e),
        "{e:?}"
    );
}

#[test]
fn a_depth_32_part_preflights_verifies_and_returns() {
    let w = make_world(20);
    let mut spec_root = spec(1);
    spec_root.amount = amt(1000);
    let mut source_id = derive_token_id(&derive_salt_of(&w, &spec_root), NETWORK);
    let mut amount = 1000u64;
    // each level: the part keeps amount-1, a sibling of 1 goes to owner 9; the last part is returned
    let mut t = T0 + 10;
    let level = |amount: u64, salt: u8| {
        [
            Out {
                owner: 2 + salt % 3,
                amount: amount - 1,
                salt,
            },
            Out {
                owner: 9,
                amount: 1,
                salt: salt.wrapping_add(0x80),
            },
        ]
    };
    let outs0 = level(amount, 1);
    let (manifest, mut outs) = split2(&w, &source_id, outs0);
    let mut burned = build_token(
        &w,
        &spec_root,
        &[Step::BurnWith {
            reason: manifest,
            t,
        }],
        T0,
        UC_TS,
    )
    .token;
    let mut out = outs0[0];
    for d in 2..=32u8 {
        amount -= 1;
        let next = level(amount, d);
        source_id = derive_token_id(&outs[0].1, NETWORK);
        let (m, o) = split2(&w, &source_id, next);
        t += 10;
        let part = mint_child(
            &w,
            &burned,
            out,
            &outs[0].0,
            outs[0].1,
            &outs[0].2,
            &[Step::BurnWith {
                reason: m,
                t: t + 5,
            }],
            t,
        );
        burned = part.token;
        outs = o;
        out = next[0];
    }
    let last = mint_child(
        &w,
        &burned,
        out,
        &outs[0].0,
        outs[0].1,
        &outs[0].2,
        &[burn_step(t + 20)],
        t + 10,
    );
    preflight_token(&last.token.to_cbor()).unwrap();
    let (env, verified, gate) = build_return_proof(&w.bridge, &last.token).unwrap();
    let l = verified.lineage.unwrap();
    assert_eq!(l.depth, 32);
    assert_eq!(l.part_amount, amt(1000 - 32));
    assert_eq!(
        gate.native,
        compose_offline_v2(&w.dep, &w.dep.cfg.to_bytes(), &env.encode())
            .unwrap()
            .1
    );
}
