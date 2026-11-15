//! An in-process model of the vault (sections 5.2, 9, 10.4, 11.1; `vaultmodel.ts`, bft-core `nb2ref/vault.go`): the packed
//! accounting word, the position-tag recent buffers, rotation and sealing, deposit and redeem in the frozen check order. It is
//! not the contract. The tests use it as the vault of the offline simulator, and the shared vault vectors check that it behaves
//! as the reference. The verifier is outside the model: a redeem carries the verifier's raw return data or its revert.

use alloc::string::String;
use alloc::vec::Vec;
use num_bigint::BigUint;

use super::config::{
    asset_uct, construct, domain_of, log2, Config, Environment, Params, MAX_DEPOSIT, MAX_SEGMENT,
};
use super::deposit::{FIRST_OWNER_BYTES, FIRST_OWNER_PREFIX};
use super::errors::{fail, Error, Nb2Error, Result, Rule};
use super::segment::{bucket_of, fold_history, gap_proof_len, genesis_head, next_head, GapTree};
use super::util::{arr, be_int, hex0x, max_bits, to_u64};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultEvent {
    Deposited {
        n: u64,
        amount: BigUint,
        rho: Vec<u8>,
        first_owner: Vec<u8>,
    },
    Paid {
        eta: [u8; 32],
        recipient: [u8; 20],
        amount: BigUint,
    },
    SegmentSealed {
        segment: u64,
        before: [u8; 32],
        after: [u8; 32],
        ids: Vec<[u8; 32]>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientBehaviour {
    Accepts,
    Reverts,
    ReentersRedeem,
    ReentersDeposit,
}

impl RecipientBehaviour {
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "accepts" => RecipientBehaviour::Accepts,
            "reverts" => RecipientBehaviour::Reverts,
            "reenters-redeem" => RecipientBehaviour::ReentersRedeem,
            "reenters-deposit" => RecipientBehaviour::ReentersDeposit,
            _ => return None,
        })
    }
}

/// The mock verifier's answer: a revert with that data, or its return data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierAnswer {
    Revert(Vec<u8>),
    Ret(Vec<u8>),
}

/// The longest verifier revert the vault relays (`MAX_VERIFIER_REVERT`); longer is `VerifierBadReturn`, never copied.
pub const MAX_VERIFIER_REVERT: usize = 1024;

const SHIFT_N: u64 = 200;
const SHIFT_C: u64 = 152;
const SHIFT_M: u64 = 144;
const WIDTH_N: u64 = 56;
const WIDTH_C: u64 = 48;
const WIDTH_M: u64 = 8;
const WIDTH_Q: u64 = 144;

fn args_err(rule: Rule, args: Vec<String>) -> Error {
    Error::Rule(Nb2Error::with_args(rule, args))
}

fn dec(v: impl core::fmt::Display) -> String {
    alloc::format!("{v}")
}

/// The outcome of a redeem: the error of a reentrant inner call, when there was one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemOutcome {
    pub inner: Option<Nb2Error>,
}

#[derive(Debug, Clone)]
struct Snapshot {
    n: u64,
    c: u64,
    m: u64,
    q: BigUint,
    t: [Vec<u8>; 2],
    s: [Vec<[u8; 32]>; 2],
    head: [u8; 32],
    prev: [u8; 32],
    ev: usize,
}

/// The vault model.
#[derive(Debug, Clone)]
pub struct VaultModel {
    pub gamma: Vec<u8>,
    pub cfg: Config,
    pub d: [u8; 32],
    n: u64,
    c: u64,
    m: u64,
    q: BigUint,
    /// The bucket tag of every position of each buffer (stale beyond the population).
    t: [Vec<u8>; 2],
    s: [Vec<[u8; 32]>; 2],
    pub head: [u8; 32],
    pub prev: [u8; 32],
    pub events: Vec<VaultEvent>,
    entered: bool,
}

/// The state() view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelState {
    pub deposits: u64,
    pub segment: u64,
    pub population: u64,
    pub outstanding: BigUint,
    pub head: [u8; 32],
    pub previous_head: [u8; 32],
}

impl VaultModel {
    pub fn new(gamma: &[u8], env: &Environment, p: &Params) -> Result<Self> {
        let cfg = construct(gamma, env, p)?;
        Ok(Self::with_config(gamma, cfg))
    }

    pub fn with_config(gamma: &[u8], cfg: Config) -> Self {
        let d = domain_of(gamma);
        let k = cfg.k as usize;
        let head = genesis_head(&d, cfg.k);
        VaultModel {
            gamma: gamma.to_vec(),
            d,
            n: 0,
            c: 0,
            m: 0,
            q: BigUint::default(),
            t: [alloc::vec![0; k], alloc::vec![0; k]],
            s: [alloc::vec![[0; 32]; k], alloc::vec![[0; 32]; k]],
            head,
            prev: [0; 32],
            events: Vec::new(),
            entered: false,
            cfg,
        }
    }

    pub fn n(&self) -> u64 {
        self.n
    }
    pub fn c(&self) -> u64 {
        self.c
    }
    pub fn m(&self) -> u64 {
        self.m
    }
    pub fn q(&self) -> &BigUint {
        &self.q
    }

    /// The packed accounting word A = n || c || m || q.
    pub fn accounting(&self) -> BigUint {
        (BigUint::from(self.n) << SHIFT_N)
            | (BigUint::from(self.c) << SHIFT_C)
            | (BigUint::from(self.m) << SHIFT_M)
            | self.q.clone()
    }

    /// The tag words of both buffers.
    pub fn tag_words(&self) -> [Vec<BigUint>; 2] {
        let lb = log2(self.cfg.b) as usize;
        let per = 256 / lb;
        let words = tag_words(self.cfg.k, self.cfg.b);
        let render = |tags: &Vec<u8>| -> Vec<BigUint> {
            (0..words)
                .map(|w| {
                    let mut x = BigUint::default();
                    for i in (w * per..((w + 1) * per).min(tags.len())).rev() {
                        x = (x << lb) | BigUint::from(tags[i]);
                    }
                    x
                })
                .collect()
        };
        [render(&self.t[0]), render(&self.t[1])]
    }

    /// The live identifiers of the current and previous buffer, in arrival order.
    pub fn live_ids(&self) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let p = (self.c % 2) as usize;
        (
            self.s[p][..self.m as usize].to_vec(),
            if self.c > 0 {
                self.s[1 - p].clone()
            } else {
                Vec::new()
            },
        )
    }

    pub fn state(&self) -> ModelState {
        ModelState {
            deposits: self.n,
            segment: self.c,
            population: self.m,
            outstanding: self.q.clone(),
            head: self.head,
            previous_head: if self.c == 0 { [0; 32] } else { self.prev },
        }
    }

    pub fn deposit(&mut self, value: &BigUint, first_owner: &[u8], rho: &[u8]) -> Result<()> {
        if self.entered {
            return fail(Rule::Reentrancy);
        }
        if value.bits() == 0 {
            return fail(Rule::ZeroValue);
        }
        if first_owner.len() != FIRST_OWNER_BYTES
            || first_owner[..9] != FIRST_OWNER_PREFIX
            || (first_owner[9] != 2 && first_owner[9] != 3)
        {
            return fail(Rule::BadFirstOwner);
        }
        if self.q > self.cfg.qmax || *value > &self.cfg.qmax - &self.q {
            return Err(args_err(
                Rule::LiabilityCap,
                alloc::vec![dec(&self.q), dec(value), dec(&self.cfg.qmax)],
            ));
        }
        if self.n >= MAX_DEPOSIT {
            return fail(Rule::DepositCounterExhausted);
        }
        let q = &self.q + value;
        if q > max_bits(WIDTH_Q) {
            return Err(Error::Other("nb2: accounting field q overflow".into()));
        }
        self.n += 1;
        self.q = q;
        self.events.push(VaultEvent::Deposited {
            n: self.n,
            amount: value.clone(),
            rho: rho.to_vec(),
            first_owner: first_owner.to_vec(),
        });
        Ok(())
    }

    /// redeem(evidence, claimedEta, claimedStart, history) with the verifier's answer and the recipient's behaviour; a failure
    /// reverts all.
    pub fn redeem(
        &mut self,
        eta: &[u8; 32],
        a: u64,
        history: &[u8],
        ver: &VerifierAnswer,
        rcp: RecipientBehaviour,
    ) -> Result<RedeemOutcome> {
        if self.entered {
            return fail(Rule::Reentrancy);
        }
        let snap = self.snapshot();
        let r = self.redeem_inner(eta, a, history, ver, rcp);
        if r.is_err() {
            self.restore(snap);
        }
        r
    }

    fn redeem_inner(
        &mut self,
        eta: &[u8; 32],
        a: u64,
        history: &[u8],
        ver: &VerifierAnswer,
        rcp: RecipientBehaviour,
    ) -> Result<RedeemOutcome> {
        let k = self.cfg.k;
        let pl = gap_proof_len(k) as u64;
        let l = history.len() as u64;
        let mut p_count = 0u64;
        if l != 0 {
            if l < 32 + pl || (l - 32) % pl != 0 {
                return Err(args_err(Rule::BadHistoryLength, alloc::vec![dec(l)]));
            }
            p_count = (l - 32) / pl;
        }
        let c = self.c;
        if a > c {
            return Err(args_err(Rule::FutureIndex, alloc::vec![dec(a), dec(c)]));
        }
        let e = a + p_count;
        if !(e == c || (c > 0 && e == c - 1)) {
            return Err(args_err(Rule::StaleEndpoint, alloc::vec![dec(e), dec(c)]));
        }
        if p_count > 0 {
            let proofs: Vec<&[u8]> = history[32..].chunks(pl as usize).collect();
            let x = fold_history(&self.d, k, eta, a, &history[..32], &proofs)?;
            if x != if e == c { self.head } else { self.prev } {
                return fail(Rule::ChainMismatch);
            }
        }
        let p = (c % 2) as usize;
        let b = bucket_of(eta, self.cfg.b) as u8;
        let mut scan = alloc::vec![(p, self.m as usize)];
        if c > 0 && e == c - 1 {
            scan.push((1 - p, k as usize));
        }
        for (buf, pop) in scan {
            for i in 0..pop {
                if self.t[buf][i] == b && self.s[buf][i] == *eta {
                    return Err(args_err(Rule::AlreadyPaid, alloc::vec![hex0x(eta)]));
                }
            }
        }
        let ret = match ver {
            VerifierAnswer::Revert(data) if data.len() > MAX_VERIFIER_REVERT => {
                return fail(Rule::VerifierBadReturn)
            }
            VerifierAnswer::Revert(data) => {
                return Err(args_err(Rule::VerifierRefused, alloc::vec![hex0x(data)]))
            }
            VerifierAnswer::Ret(r) => r,
        };
        let Some(vd) = decode_verdict_abi(ret) else {
            return fail(Rule::VerifierBadReturn);
        };
        let q = self.q.clone();
        if vd.domain != self.d {
            return fail(Rule::DomainMismatch);
        }
        if vd.asset != asset_uct() {
            return fail(Rule::AssetMismatch);
        }
        if vd.eta != *eta || vd.min_segment != a {
            return fail(Rule::ClaimMismatch);
        }
        if vd.recipient.iter().all(|&x| x == 0) || vd.recipient == self.cfg.vault {
            return fail(Rule::BadRecipient);
        }
        if vd.amount.bits() == 0 {
            return fail(Rule::ZeroAmount);
        }
        if vd.amount > q {
            return Err(args_err(
                Rule::LiabilityUnderflow,
                alloc::vec![dec(&q), dec(&vd.amount)],
            ));
        }
        let mut m = self.m as usize;
        self.s[p][m] = vd.eta;
        self.t[p][m] = bucket_of(&vd.eta, self.cfg.b) as u8;
        m += 1;
        self.q = q - &vd.amount;
        self.events.push(VaultEvent::Paid {
            eta: vd.eta,
            recipient: vd.recipient,
            amount: vd.amount.clone(),
        });
        if m as u64 == k {
            self.seal(p)?;
        } else {
            self.m = m as u64;
        }
        let mut out = RedeemOutcome { inner: None };
        self.entered = true;
        let r = match rcp {
            RecipientBehaviour::Reverts => fail(Rule::PayoutFailed),
            RecipientBehaviour::ReentersRedeem => {
                out.inner = self
                    .redeem(eta, a, history, ver, RecipientBehaviour::Accepts)
                    .err()
                    .and_then(|e| e.rule().cloned());
                Ok(())
            }
            RecipientBehaviour::ReentersDeposit => {
                out.inner = self
                    .deposit(&BigUint::from(1u8), &[], &[0; 32])
                    .err()
                    .and_then(|e| e.rule().cloned());
                Ok(())
            }
            RecipientBehaviour::Accepts => Ok(()),
        };
        self.entered = false;
        r.map(|_| out)
    }

    fn seal(&mut self, p: usize) -> Result<()> {
        let c = self.c;
        let k = self.cfg.k as usize;
        if c >= MAX_SEGMENT {
            return fail(Rule::SegmentCounterExhausted);
        }
        let mut buckets: Vec<Vec<[u8; 32]>> = alloc::vec![Vec::new(); self.cfg.b as usize];
        for i in 0..k {
            buckets[self.t[p][i] as usize].push(self.s[p][i]);
        }
        let mut z = Vec::with_capacity(k);
        for (t, bk) in buckets.iter_mut().enumerate() {
            bk.sort();
            for x in bk.iter() {
                if bucket_of(x, self.cfg.b) != t {
                    return Err(Error::Other("nb2: seal assertion failed".into()));
                }
            }
            z.extend_from_slice(bk);
        }
        let Some(tree) = GapTree::build(&z) else {
            return Err(Error::Other("nb2: seal assertion failed".into()));
        };
        let next = next_head(&self.d, c, &self.head, &tree.root());
        self.events.push(VaultEvent::SegmentSealed {
            segment: c,
            before: self.head,
            after: next,
            ids: z,
        });
        self.prev = self.head;
        self.head = next;
        if c + 1 > max_bits(WIDTH_C).to_u64_digits()[0] {
            return Err(Error::Other("nb2: accounting field c overflow".into()));
        }
        self.c = c + 1;
        self.m = 0;
        Ok(())
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            n: self.n,
            c: self.c,
            m: self.m,
            q: self.q.clone(),
            t: self.t.clone(),
            s: self.s.clone(),
            head: self.head,
            prev: self.prev,
            ev: self.events.len(),
        }
    }

    fn restore(&mut self, s: Snapshot) {
        self.n = s.n;
        self.c = s.c;
        self.m = s.m;
        self.q = s.q;
        self.t = s.t;
        self.s = s.s;
        self.head = s.head;
        self.prev = s.prev;
        self.events.truncate(s.ev);
        self.entered = false;
    }

    /// The test harness's storage injection (states no sequence can reach).
    #[allow(clippy::too_many_arguments)]
    pub fn set_state(
        &mut self,
        n: u64,
        c: u64,
        m: u64,
        q: BigUint,
        head: [u8; 32],
        prev: [u8; 32],
        current: &[[u8; 32]],
        previous: &[[u8; 32]],
    ) -> Result<()> {
        if n > max_bits(WIDTH_N).to_u64_digits()[0]
            || c > max_bits(WIDTH_C).to_u64_digits()[0]
            || m > (1 << WIDTH_M) - 1
            || q > max_bits(WIDTH_Q)
        {
            return Err(Error::Other("nb2: accounting field overflow".into()));
        }
        self.n = n;
        self.c = c;
        self.m = m;
        self.q = q;
        self.head = head;
        self.prev = prev;
        let p = (c % 2) as usize;
        for (i, x) in current.iter().enumerate() {
            self.s[p][i] = *x;
            self.t[p][i] = bucket_of(x, self.cfg.b) as u8;
        }
        for (i, x) in previous.iter().enumerate() {
            self.s[1 - p][i] = *x;
            self.t[1 - p][i] = bucket_of(x, self.cfg.b) as u8;
        }
        Ok(())
    }

    /// The raw buffers and tags, for a snapshot of the whole model (the offline simulator's state dump).
    pub fn buffers(&self) -> (&[Vec<u8>; 2], &[Vec<[u8; 32]>; 2]) {
        (&self.t, &self.s)
    }

    /// Restore every field of the model (the offline simulator's state load).
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        &mut self,
        n: u64,
        c: u64,
        m: u64,
        q: BigUint,
        head: [u8; 32],
        prev: [u8; 32],
        t: [Vec<u8>; 2],
        s: [Vec<[u8; 32]>; 2],
    ) {
        self.n = n;
        self.c = c;
        self.m = m;
        self.q = q;
        self.head = head;
        self.prev = prev;
        self.t = t;
        self.s = s;
    }
}

/// words(K, B) = ceil(K / floor(256 / log2 B)).
pub fn tag_words(k: u64, b: u64) -> usize {
    let t = 256 / log2(b) as u64;
    k.div_ceil(t) as usize
}

/// The verifier's decoded return data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictWords {
    pub domain: [u8; 32],
    pub eta: [u8; 32],
    pub min_segment: u64,
    pub asset: [u8; 32],
    pub recipient: [u8; 20],
    pub amount: BigUint,
}

/// The verifier's return data: exactly 192 canonical bytes (uint64 and address words with zero high bytes).
pub fn decode_verdict_abi(b: &[u8]) -> Option<VerdictWords> {
    if b.len() != 192 || b[64..88].iter().any(|&x| x != 0) || b[128..140].iter().any(|&x| x != 0) {
        return None;
    }
    Some(VerdictWords {
        domain: arr(&b[..32]),
        eta: arr(&b[32..64]),
        min_segment: to_u64(&be_int(&b[64..96]))?,
        asset: arr(&b[96..128]),
        recipient: arr(&b[140..160]),
        amount: be_int(&b[160..192]),
    })
}
