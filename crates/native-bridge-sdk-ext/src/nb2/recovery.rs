//! NB2 continuation packets built from authenticated flat evidence.
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use alloc::{rc::Rc, vec};
use core::cell::RefCell;

use super::abi::{abi_encode, AbiArg};
use super::config::{decode_config, domain_of, Config, Params, MAX_SEGMENT};
use super::crypto::{he, hu};
use super::deposit::{
    decode_deposit_proof, decode_receipt_backing, encode_deposit_proof, verify_receipt_log_at,
};
use super::errors::{fail_d, refuse, Result, Rule, WalletReason};
use super::recovery_cost::{
    quote_recovery, RecoveryCalibration, RecoveryEntry, RecoveryLimits, RecoveryQuote,
    RecoveryShape,
};
use super::rules::verify_seal_receipt;
use super::segment::{fold_history, gap_proof_len, GapTree};
use super::split::{decode_split_manifest, parent_link};
use super::token::{decode_token, mint_source_hash, result_state, state_id, token_id_of, Token};
use super::trust::{bind_trust, decode_uc, shard_bytes, TrustInput};
use super::util::{cat, u256, u256_64};
use super::verify::{parse_mint_data, verdict_abi, verify_part, Verdict};

type Hash = [u8; 32];
const ZERO: Hash = [0; 32];
const VERSION: [u8; 2] = [1, 1];
const PAGE_SIZE: usize = 4096;
const CALLDATA_CAP: usize = 393_216;
const RECEIPT_CAP: usize = 65_536;

fn hash(label: &str, parts: &[&[u8]]) -> Hash {
    let domain = he(&[b"UNICITY/NB2/CONT/1.1/", label.as_bytes()]);
    let mut fields = vec![domain.as_slice()];
    fields.extend_from_slice(parts);
    he(&fields)
}

fn blob(data: &[u8]) -> Vec<u8> {
    cat(&[&(data.len() as u32).to_be_bytes(), data])
}

fn cold_call(signature: &[u8], body: Vec<u8>) -> Result<Vec<u8>> {
    if 68 + body.len().div_ceil(32) * 32 > CALLDATA_CAP {
        return fail_d(Rule::InputTooLarge, "cold calldata");
    }
    Ok(cat(&[
        &he(&[signature])[..4],
        &abi_encode(&[AbiArg::Bytes(body)]),
    ]))
}

struct Pages {
    evidence: Vec<u8>,
    tree: Vec<Vec<Hash>>,
}

impl Pages {
    fn new(evidence: &[u8]) -> Self {
        let count = evidence.len().div_ceil(PAGE_SIZE);
        let length = (evidence.len() as u64).to_be_bytes();
        let mut leaves: Vec<_> = evidence
            .chunks(PAGE_SIZE)
            .enumerate()
            .map(|(i, bytes)| {
                hash(
                    "PAGE",
                    &[
                        &length,
                        &(i as u64).to_be_bytes(),
                        &(bytes.len() as u16).to_be_bytes(),
                        bytes,
                    ],
                )
            })
            .collect();
        leaves.resize(count.next_power_of_two(), hash("PAD", &[]));
        let mut tree = vec![leaves];
        while tree.last().unwrap().len() > 1 {
            tree.push(
                tree.last()
                    .unwrap()
                    .chunks_exact(2)
                    .map(|pair| hash("PAGE_NODE", &[&pair[0], &pair[1]]))
                    .collect(),
            );
        }
        Self {
            evidence: evidence.to_vec(),
            tree,
        }
    }

    fn root(&self) -> Hash {
        self.tree.last().unwrap()[0]
    }

    fn append_opening(&self, mut index: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(&(index as u64).to_be_bytes());
        out.extend_from_slice(
            &self.evidence[index * PAGE_SIZE..((index + 1) * PAGE_SIZE).min(self.evidence.len())],
        );
        for level in &self.tree[..self.tree.len() - 1] {
            out.extend_from_slice(&level[index ^ 1]);
            index >>= 1;
        }
    }
}

struct Sparse {
    label: &'static str,
    nodes: Vec<BTreeMap<Hash, Hash>>,
    defaults: Vec<Hash>,
}

impl Sparse {
    fn new(label: &'static str) -> Self {
        let mut defaults = vec![ZERO];
        for height in 0..256 {
            defaults.push(hash(label, &[&defaults[height], &defaults[height]]));
        }
        Self {
            label,
            nodes: vec![BTreeMap::new(); 257],
            defaults,
        }
    }

    fn root(&self) -> Hash {
        self.nodes[256]
            .get(&ZERO)
            .copied()
            .unwrap_or(self.defaults[256])
    }

    fn open(&mut self, mut index: Hash, mut leaf: Option<Hash>) -> Vec<u8> {
        let mut out = vec![0; 32];
        for h in 0..256 {
            let mut other = index;
            other[31] ^= 1;
            let sibling = self.nodes[h].get(&other).copied();
            if let Some(sibling) = sibling {
                out[31 - h / 8] |= 1 << (h % 8);
                out.extend_from_slice(&sibling);
            }
            if let Some(current) = leaf {
                self.nodes[h].insert(index, current);
                let other = sibling.unwrap_or(self.defaults[h]);
                leaf = Some(if index[31] & 1 == 0 {
                    hash(self.label, &[&current, &other])
                } else {
                    hash(self.label, &[&other, &current])
                });
            }
            let mut carry = 0;
            for byte in &mut index {
                let next = (*byte & 1) << 7;
                *byte = (*byte >> 1) | carry;
                carry = next;
            }
        }
        if let Some(leaf) = leaf {
            self.nodes[256].insert(ZERO, leaf);
        }
        out
    }
}

struct ClaimOpening {
    key: Hash,
    full: Vec<u8>,
}
struct Operation {
    start: usize,
    end: usize,
    code: u8,
    sid: Vec<u8>,
    claims: Vec<ClaimOpening>,
    after: Option<Vec<u8>>,
}

struct State {
    phase: u8,
    pos: usize,
    levels: usize,
    transfers: usize,
    owner: [u8; 33],
    state: Hash,
    id: Hash,
    amount: Hash,
    link: Hash,
    manifest: Hash,
}

impl State {
    fn body(&self, seen: &Sparse, claims: &Sparse) -> Vec<u8> {
        cat(&[
            &[self.phase],
            &(self.pos as u64).to_be_bytes(),
            &(self.levels as u64).to_be_bytes(),
            &(self.transfers as u64).to_be_bytes(),
            &seen.root(),
            &claims.root(),
            &self.owner,
            &self.state,
            &self.id,
            &self.amount,
            &self.link,
            &self.manifest,
        ])
    }
}

fn with_seq(body: &[u8], seq: u64) -> Vec<u8> {
    cat(&[&body[..1], &seq.to_be_bytes(), &body[1..]])
}

fn claim_opening(
    raw: &[u8],
    claims: &mut Sparse,
    values: &mut BTreeMap<Hash, Hash>,
) -> Result<ClaimOpening> {
    let uc = decode_uc(raw)?;
    let shard = shard_bytes(&uc);
    let location = cat(&[
        &uc.unicity_tree_certificate
            .partition_identifier
            .to_be_bytes(),
        &(shard.len() as u16).to_be_bytes(),
        &shard,
    ]);
    let key = hash(
        "CLAIM_KEY",
        &[&hu(&[&uc.unicity_seal.to_cbor()]), &location],
    );
    let value = hash(
        "CLAIM_VALUE",
        &[&hu(&[
            &location,
            &uc.shard_configuration_hash,
            uc.input_record
                .hash
                .as_deref()
                .ok_or_else(|| super::errors::rule_err(Rule::CertStructure))?,
            &hu(&[&uc.input_record.to_cbor()]),
            &blob(raw),
        ])],
    );
    let old = values.insert(key, value);
    if old.is_some_and(|old| old != value) {
        return fail_d(Rule::CertStructure, "conflicting recovery claim");
    }
    let opening = claims.open(key, old.is_none().then(|| hash("CLAIM", &[&key, &value])));
    let full = match old {
        Some(old) => cat(&[&[0, 1], &old, &opening]),
        None => cat(&[&[0, 0], &opening]),
    };
    Ok(ClaimOpening { key, full })
}

/// Called only after the flat decoder has checked complete consumption and framing bounds.
fn skip_blob(evidence: &[u8], pos: &mut usize) {
    let width = u32::from_be_bytes(evidence[*pos..*pos + 4].try_into().unwrap());
    *pos += 4 + width as usize;
}

fn operations(
    evidence: &[u8],
    token: &Token,
    cfg: &Config,
    domain: &Hash,
) -> Result<Vec<Operation>> {
    let mut seen = Sparse::new("SID_NODE");
    let mut claims = Sparse::new("CLAIM_NODE");
    let mut values = BTreeMap::new();
    let mut result = Vec::new();
    let mut state = State {
        phase: 1,
        pos: 14,
        levels: token.ancestors.len() + 1,
        transfers: 0,
        owner: [0; 33],
        state: ZERO,
        id: ZERO,
        amount: ZERO,
        link: ZERO,
        manifest: ZERO,
    };
    let chain = token.levels();
    for (i, level) in chain.enumerate() {
        let start = state.pos;
        for _ in 0..3 {
            skip_blob(evidence, &mut state.pos);
        }
        state.pos += 8;
        let mint = &level.mint;
        let amount = parse_mint_data(cfg, mint.data.as_deref())?;
        state.id = token_id_of(&mint.salt, mint.network);
        state.amount = u256(&amount);
        state.owner.copy_from_slice(&mint.recipient.params);
        state.state = result_state(&mint_source_hash(&state.id), &state.id);
        state.phase = 3;
        state.transfers = level.transfers.len();
        state.link = ZERO;
        state.manifest = ZERO;
        let cd = &level.mint_proof.cd;
        let sid = state_id(&cd.source, &cd.source_hash);
        let opening = seen.open(sid, Some(hash("SID", &[&sid])));
        let mut mint_claims = Vec::new();
        if i == 0 {
            let backing = decode_receipt_backing(mint.justification.as_deref().unwrap())?;
            mint_claims.push(claim_opening(&backing.proof.uc, &mut claims, &mut values)?);
        }
        mint_claims.push(claim_opening(
            &level.mint_proof.uc,
            &mut claims,
            &mut values,
        )?);
        result.push(Operation {
            start,
            end: state.pos,
            code: if i == 0 { 1 } else { 2 },
            sid: opening,
            claims: mint_claims,
            after: Some(state.body(&seen, &claims)),
        });
        for (transfer, proof) in level.transfers.iter().zip(&level.proofs) {
            let start = state.pos;
            skip_blob(evidence, &mut state.pos);
            let sid = state_id(&proof.cd.source, &proof.cd.source_hash);
            let opening = seen.open(sid, Some(hash("SID", &[&sid])));
            let claim = claim_opening(&proof.uc, &mut claims, &mut values)?;
            state.transfers -= 1;
            let terminal = state.transfers == 0 && state.levels == 1;
            if state.transfers != 0 {
                state.state = result_state(&state.state, &transfer.mask);
                state.owner.copy_from_slice(&transfer.recipient.params);
            } else if !terminal {
                state.manifest = decode_split_manifest(transfer.data.as_deref().unwrap())?;
                state.link = parent_link(
                    domain,
                    &state.id,
                    &sid,
                    &proof.cd.tx_hash,
                    &state.manifest,
                    &amount,
                );
                state.owner = [0; 33];
                state.state = ZERO;
                state.levels -= 1;
                state.phase = 2;
            }
            result.push(Operation {
                start,
                end: state.pos,
                code: 3,
                sid: opening,
                claims: vec![claim],
                after: (!terminal).then(|| state.body(&seen, &claims)),
            });
        }
    }
    Ok(result)
}

/// Identities from the authenticated deployment.
pub struct RecoveryDeployment {
    pub salt: Hash,
    pub recovery: [u8; 20],
    pub runtime_hash: Hash,
    pub pins: Hash,
    pub vault_runtime_hash: Option<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Progress,
    Complete,
    Gap,
}

impl EventKind {
    fn topic(self) -> Hash {
        let signature: &[u8] = match self {
            Self::Progress => b"NB2Progress11(bytes32,uint64,bytes32)",
            Self::Complete => b"NB2Complete11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256)",
            Self::Gap => b"NB2Gap11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256,uint64,bytes32)",
        };
        he(&[signature])
    }
}

pub struct RecoveryEvent {
    pub kind: EventKind,
    pub topics: [Hash; 2],
    pub data: Vec<u8>,
}

pub struct RunPacket {
    pub shape: RecoveryShape,
    pub calldata: Vec<u8>,
    pub end: usize,
    pub state: Option<Vec<u8>>,
    pub event: RecoveryEvent,
}

/// One authority shared by sessions on the deployment. Restore the persisted input before reopening.
#[derive(Clone)]
pub struct RecoveryAuthority(Rc<AuthorityState>);

type PersistAuthority = dyn Fn(&TrustInput) -> Result<()>;

struct AuthorityState {
    held: RefCell<TrustInput>,
    persist: Box<PersistAuthority>,
}

impl RecoveryAuthority {
    pub fn new(
        checkpoint: TrustInput,
        persist: impl Fn(&TrustInput) -> Result<()> + 'static,
    ) -> Self {
        Self(Rc::new(AuthorityState {
            held: RefCell::new(checkpoint),
            persist: Box::new(persist),
        }))
    }

    pub fn checkpoint(&self) -> Result<TrustInput> {
        self.0
            .held
            .try_borrow()
            .map(|held| held.clone())
            .map_err(|_| {
                super::errors::wallet_err(
                    WalletReason::TrustInput,
                    "recovery authority persistence in progress",
                )
            })
    }

    pub fn accept(&self, offered: &TrustInput, cfg: &Config) -> Result<()> {
        let mut held = self.0.held.try_borrow_mut().map_err(|_| {
            super::errors::wallet_err(
                WalletReason::TrustInput,
                "recovery authority persistence in progress",
            )
        })?;
        bind_trust(&held, cfg)?;
        bind_trust(offered, cfg)?;
        if *held == *offered {
            return Ok(());
        }
        let old = held.history().entries();
        let new = offered.history().entries();
        let before = held.origin().unwrap();
        let after = offered.origin().unwrap();
        if new.len() < old.len()
            || old
                .iter()
                .zip(new)
                .any(|(a, b)| a.entry_id() != b.entry_id())
            || after.usable_epoch < before.usable_epoch
            || after.root_round < before.root_round
        {
            return refuse(
                WalletReason::TrustInput,
                "recovery authority rolls back the held history or origin",
            );
        }
        (self.0.persist)(offered).map_err(|error| {
            super::errors::wallet_err(
                WalletReason::TrustInput,
                alloc::format!("could not persist recovery authority: {}", error.name()),
            )
        })?;
        *held = offered.clone();
        Ok(())
    }
}

pub struct RecoverySession {
    cfg: Config,
    deployment: RecoveryDeployment,
    pages: Pages,
    session: Hash,
    header: Vec<u8>,
    verdict: Verdict,
    ops: Vec<Operation>,
    authority: RecoveryAuthority,
}

impl RecoverySession {
    pub fn create(
        gamma: &[u8],
        evidence: &[u8],
        authority: RecoveryAuthority,
        params: &Params,
        deployment: RecoveryDeployment,
    ) -> Result<Self> {
        let cfg = decode_config(gamma, params)?;
        let domain = domain_of(gamma);
        let token = decode_token(evidence)?;
        let verdict = verify_part(&cfg, &domain, &authority.checkpoint()?, &token)?;
        let pages = Pages::new(evidence);
        let header = cat(&[
            &VERSION,
            &(evidence.len() as u64).to_be_bytes(),
            &pages.root(),
        ]);
        let generation = hash("GEN", &[&deployment.salt, &domain]);
        let session = hash(
            "SESSION",
            &[
                &VERSION,
                &generation,
                &domain,
                &cfg.vault,
                &deployment.recovery,
                &deployment.runtime_hash,
                &deployment.pins,
                &header[2..],
            ],
        );
        let ops = operations(evidence, &token, &cfg, &domain)?;
        Ok(Self {
            cfg,
            deployment,
            pages,
            session,
            header,
            verdict,
            ops,
            authority,
        })
    }

    pub fn id(&self) -> Hash {
        self.session
    }
    pub fn page_root(&self) -> Hash {
        self.pages.root()
    }
    pub fn operation_count(&self) -> usize {
        self.ops.len()
    }

    fn event(&self, kind: EventKind, data: Vec<u8>) -> RecoveryEvent {
        RecoveryEvent {
            kind,
            topics: [kind.topic(), self.session],
            data,
        }
    }

    /// Build a prescribed cut, authenticating the exact predecessor state when resuming.
    pub fn run(
        &self,
        from: usize,
        count: usize,
        trust: &TrustInput,
        prior: Option<(u64, &[u8])>,
    ) -> Result<RunPacket> {
        if from > self.ops.len()
            || !(1..=16).contains(&count)
            || count > self.ops.len() - from
            || (from == 0) != prior.is_none()
        {
            return fail_d(Rule::Shape, "run cut");
        }
        let mut body = self.header.clone();
        let seq = if let Some((seq, receipt)) = prior {
            if seq == 0 || seq == u64::MAX {
                return fail_d(Rule::Shape, "sequence");
            }
            let state = with_seq(self.ops[from - 1].after.as_ref().unwrap(), seq);
            let event = self.event(
                EventKind::Progress,
                cat(&[&u256_64(seq), &hash("STATE", &[&self.session, &state])]),
            );
            self.verify_event(trust, receipt, &event)?;
            body.extend_from_slice(&cat(&[&[1], &state, &blob(receipt)]));
            seq + 1
        } else {
            self.authority.accept(trust, &self.cfg)?;
            body.push(0);
            1
        };
        let end = from + count;
        let first = if from == 0 {
            0
        } else {
            self.ops[from].start / PAGE_SIZE
        };
        let last = (self.ops[end - 1].end - 1) / PAGE_SIZE;
        let pages = last - first + 1;
        if pages > 32 {
            return fail_d(Rule::InputTooLarge, "run pages");
        }
        body.push(pages as u8);
        for i in first..=last {
            self.pages.append_opening(i, &mut body);
        }
        body.push(count as u8);
        let mut used = BTreeSet::new();
        let openings = body.len();
        for op in &self.ops[from..end] {
            body.push(op.code);
            body.extend_from_slice(&op.sid);
            for claim in &op.claims {
                if used.insert(claim.key) {
                    body.extend_from_slice(&claim.full);
                } else {
                    body.push(1);
                }
            }
        }
        let state = self.ops[end - 1]
            .after
            .as_ref()
            .map(|after| with_seq(after, seq));
        let event = match &state {
            Some(state) => self.event(
                EventKind::Progress,
                cat(&[&u256_64(seq), &hash("STATE", &[&self.session, state])]),
            ),
            None => self.event(
                EventKind::Complete,
                cat(&[&u256_64(seq), &verdict_abi(&self.verdict)]),
            ),
        };
        let opening_bytes = body.len() - openings - count;
        let calldata = cold_call(b"run(bytes)", body)?;
        let shape = RecoveryShape {
            entry: RecoveryEntry::Run,
            calldata_bytes: calldata.len(),
            operations: count,
            pages,
            gaps: 0,
            receipt_bytes: prior.map_or(0, |(_, r)| r.len()),
            opening_bytes,
        };
        Ok(RunPacket {
            shape,
            calldata,
            end,
            state,
            event,
        })
    }

    fn check_calibration(
        &self,
        calibration: &dyn RecoveryCalibration,
        limits: &RecoveryLimits,
    ) -> Result<()> {
        if self.deployment.pins != calibration.pins()
            || self.deployment.runtime_hash != calibration.runtime_hash()
            || self.cfg.chain_id != limits.chain_id
        {
            return fail_d(Rule::CapacityPreflight, "unqualified recovery deployment");
        }
        Ok(())
    }

    /// Fit the largest prefix within the authenticated packet and transaction limits.
    pub fn run_bounded(
        &self,
        from: usize,
        trust: &TrustInput,
        calibration: &dyn RecoveryCalibration,
        limits: &RecoveryLimits,
        prior: Option<(u64, &[u8])>,
    ) -> Result<(RunPacket, RecoveryQuote)> {
        self.check_calibration(calibration, limits)?;
        for count in (1..=self.ops.len().saturating_sub(from).min(16)).rev() {
            match self.run(from, count, trust, prior) {
                Ok(packet) => {
                    if let Some(quote) = quote_recovery(packet.shape, calibration, limits) {
                        return Ok((packet, quote));
                    }
                }
                Err(e)
                    if e.rule().is_some_and(|rule| {
                        rule.rule == Rule::InputTooLarge
                            && matches!(rule.detail.as_deref(), Some("run pages" | "cold calldata"))
                    }) => {}
                Err(e) => return Err(e),
            }
        }
        fail_d(Rule::CapacityPreflight, "indivisible run operation")
    }

    fn check_expectation(&self, event: &RecoveryEvent) -> Result<()> {
        if event.topics != [event.kind.topic(), self.session] {
            return refuse(
                WalletReason::ProviderFault,
                "recovery expectation belongs to a different session or event",
            );
        }
        Ok(())
    }

    pub fn verify_event(
        &self,
        trust: &TrustInput,
        receipt: &[u8],
        expected: &RecoveryEvent,
    ) -> Result<RecoveryReceipt> {
        if receipt.len() > RECEIPT_CAP {
            return fail_d(Rule::InputTooLarge, "cold receipt");
        }
        self.check_expectation(expected)?;
        let proof = decode_deposit_proof(receipt)?;
        self.authority.accept(trust, &self.cfg)?;
        let held = self.authority.checkpoint()?;
        let log = verify_receipt_log_at(&self.cfg, &held, &proof, &self.deployment.recovery)?;
        if log.address != self.deployment.recovery
            || log.topics.len() != 2
            || log.topics[0] != expected.kind.topic()
            || log.topics[1] != self.session
            || log.data != expected.data
        {
            return refuse(WalletReason::ProviderFault, "recovery checkpoint mismatch");
        }
        Ok(RecoveryReceipt {
            encoded: receipt.to_vec(),
            block_number: log.header.number_u64(),
            block_hash: he(&[&proof.header]),
            tx_index: proof.tx_index,
            log_index: proof.log_index,
        })
    }

    /// Trim only an external predecessor presentation, rechecking the actual historical quorum after each removal.
    pub fn trim_receipt(
        &self,
        trust: &TrustInput,
        receipt: &[u8],
        expected: &RecoveryEvent,
    ) -> Result<RecoveryReceipt> {
        let mut best = self.verify_event(trust, receipt, expected)?;
        let mut proof = decode_deposit_proof(receipt)?;
        let mut uc = decode_uc(&proof.uc)?;
        for i in (0..uc.unicity_seal.signatures.len()).rev() {
            let removed = uc.unicity_seal.signatures.remove(i);
            proof.uc = uc.to_cbor();
            match self.verify_event(trust, &encode_deposit_proof(&proof), expected) {
                Ok(valid) => best = valid,
                Err(error)
                    if error
                        .rule()
                        .is_some_and(|rule| rule.innermost() == Rule::QuorumNotMet) =>
                {
                    uc.unicity_seal.signatures.insert(i, removed);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(best)
    }

    /// Try independently authenticated receipts, retaining unknown and pruned as availability outcomes.
    pub fn acquire(
        &self,
        trust: &TrustInput,
        event: &RecoveryEvent,
        sources: &[&ReceiptSource<'_>],
        refresh: Option<&TrustRefresh<'_>>,
    ) -> Result<(RecoveryReceipt, TrustInput)> {
        self.check_expectation(event)?;
        self.authority.accept(trust, &self.cfg)?;
        let mut unavailable = None;
        let mut fault = None;
        for source in sources {
            let result = (|| {
                let proof = source(&self.deployment.recovery, event)?;
                let authority = self.authority.checkpoint()?;
                match self.verify_event(&authority, &proof, event) {
                    Err(e)
                        if refresh.is_some()
                            && (e.retryable() || ahead_of_origin(&authority, &proof)) =>
                    {
                        let fresh = refresh.unwrap()(&authority)?;
                        self.authority.accept(&fresh, &self.cfg)?;
                        self.verify_event(&self.authority.checkpoint()?, &proof, event)
                    }
                    result => result,
                }
            })();
            match result {
                Ok(receipt) => return Ok((receipt, self.authority.checkpoint()?)),
                Err(e) if e.reason() == Some(WalletReason::TrustInput) => return Err(e),
                Err(e)
                    if matches!(
                        e.reason(),
                        Some(WalletReason::CompanionUnknown | WalletReason::EvidenceMissing)
                    ) =>
                {
                    unavailable = Some(e)
                }
                Err(e) if e.rule().is_some_and(|r| r.rule == Rule::EvidencePruned) => {
                    unavailable.get_or_insert(e);
                }
                Err(e) => {
                    fault.get_or_insert(e);
                }
            }
        }
        if let Some(error) = fault.or(unavailable) {
            return Err(error);
        }
        refuse(WalletReason::EvidenceMissing, "no recovery receipt source")
    }
}

fn ahead_of_origin(trust: &TrustInput, receipt: &[u8]) -> bool {
    let Some(origin) = trust.origin() else {
        return false;
    };
    decode_deposit_proof(receipt)
        .and_then(|p| decode_uc(&p.uc))
        .is_ok_and(|uc| {
            uc.unicity_seal.epoch > origin.usable_epoch
                || uc.unicity_seal.root_chain_round_number > origin.root_round
        })
}

pub type ReceiptSource<'a> = dyn Fn(&[u8; 20], &RecoveryEvent) -> Result<Vec<u8>> + 'a;
pub type TrustRefresh<'a> = dyn Fn(&TrustInput) -> Result<TrustInput> + 'a;
pub struct RecoveryReceipt {
    pub encoded: Vec<u8>,
    pub block_number: u64,
    pub block_hash: Hash,
    pub tx_index: u64,
    pub log_index: u64,
}

#[cfg(feature = "host")]
pub fn recovery_rpc_source<'a, R: super::rpc::JsonRpc + ?Sized>(
    reader: &'a super::rpc::EvmReader<R>,
    tx_hash: Hash,
) -> impl Fn(&[u8; 20], &RecoveryEvent) -> Result<Vec<u8>> + 'a {
    move |emitter, event| {
        Ok(reader
            .recovery_receipt_proof(&tx_hash, emitter, event)?
            .encoded)
    }
}

pub struct GapCursor {
    pub next: u64,
    pub head: Hash,
}
pub struct GapPredecessor<'a> {
    pub seq: u64,
    pub receipt: &'a [u8],
    pub cursor: Option<GapCursor>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GapEntry {
    Advance,
    Redeem,
}
pub struct GapPacket {
    pub shape: RecoveryShape,
    pub calldata: Vec<u8>,
    pub event: Option<RecoveryEvent>,
    pub next: u64,
    pub head: Option<Hash>,
}

impl RecoverySession {
    /// Materialize consecutive exclusion proofs from certified vault seal receipts.
    pub fn certified_gaps(
        &self,
        trust: &TrustInput,
        start: u64,
        mut head: Hash,
        receipts: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>> {
        if start < self.verdict.min_segment
            || receipts.len() > 1024
            || start
                .checked_add(receipts.len() as u64)
                .map_or(true, |end| end > MAX_SEGMENT)
        {
            return fail_d(Rule::Shape, "certified gap range");
        }
        self.authority.accept(trust, &self.cfg)?;
        let mut paths = Vec::new();
        for (i, receipt) in receipts.iter().enumerate() {
            let seal = verify_seal_receipt(
                &self.cfg,
                &self.verdict.domain,
                &self.authority.checkpoint()?,
                receipt,
            )?;
            if seal.segment.index != start + i as u64 || seal.segment.before != head {
                return fail_d(Rule::SegmentLog, "nonconsecutive certified seals");
            }
            let path = GapTree::build(&seal.segment.z)
                .unwrap()
                .prove(&self.verdict.eta);
            let Some(path) = path else {
                return refuse(
                    WalletReason::AlreadyPaid,
                    "return appears in a certified sealed segment",
                );
            };
            paths.push(path);
            head = seal.segment.after;
        }
        Ok(paths)
    }

    pub fn gaps(
        &self,
        entry: GapEntry,
        trust: &TrustInput,
        prior: &GapPredecessor<'_>,
        gaps: &[Vec<u8>],
        start_head: Option<Hash>,
    ) -> Result<GapPacket> {
        let start = prior
            .cursor
            .as_ref()
            .map_or(self.verdict.min_segment, |c| c.next);
        let head = prior.cursor.as_ref().map(|c| c.head).or(start_head);
        let advance = entry == GapEntry::Advance;
        let Some(next) = start.checked_add(gaps.len() as u64) else {
            return fail_d(Rule::Shape, "cold gap framing");
        };
        if gaps.len() > 1024
            || (advance && gaps.is_empty())
            || prior.seq == 0
            || (advance && prior.seq == u64::MAX)
            || start < self.verdict.min_segment
            || next > MAX_SEGMENT
            || (prior.cursor.is_some() && start_head.is_some())
            || (prior.cursor.is_none() && (gaps.is_empty() == start_head.is_some()))
            || gaps
                .iter()
                .any(|gap| gap.len() != gap_proof_len(self.cfg.k))
        {
            return fail_d(Rule::Shape, "cold gap framing");
        }
        let verdict = verdict_abi(&self.verdict);
        let expected = if let Some(cursor) = &prior.cursor {
            self.event(
                EventKind::Gap,
                cat(&[&u256_64(prior.seq), &verdict, &u256_64(start), &cursor.head]),
            )
        } else {
            self.event(EventKind::Complete, cat(&[&u256_64(prior.seq), &verdict]))
        };
        self.verify_event(trust, prior.receipt, &expected)?;
        let after = if gaps.is_empty() {
            head
        } else {
            let paths: Vec<&[u8]> = gaps.iter().map(Vec::as_slice).collect();
            Some(fold_history(
                &self.verdict.domain,
                self.cfg.k,
                &self.verdict.eta,
                start,
                &head.unwrap(),
                &paths,
            )?)
        };
        let event = advance.then(|| {
            self.event(
                EventKind::Gap,
                cat(&[
                    &u256_64(prior.seq + 1),
                    &verdict,
                    &u256_64(next),
                    &after.unwrap(),
                ]),
            )
        });
        let mut body = self.header.clone();
        body.push(if prior.cursor.is_some() { 2 } else { 1 });
        body.extend_from_slice(&blob(prior.receipt));
        body.extend_from_slice(&(gaps.len() as u16).to_be_bytes());
        if let Some(start_head) = start_head {
            body.extend_from_slice(&start_head);
        }
        for gap in gaps {
            body.extend_from_slice(gap);
        }
        let signature: &[u8] = if advance {
            b"advanceGaps(bytes)"
        } else {
            b"redeemRecovered(bytes)"
        };
        let calldata = cold_call(signature, body)?;
        let shape = RecoveryShape {
            entry: if advance {
                RecoveryEntry::AdvanceGaps
            } else {
                RecoveryEntry::RedeemRecovered
            },
            calldata_bytes: calldata.len(),
            operations: 0,
            pages: 0,
            gaps: gaps.len(),
            receipt_bytes: prior.receipt.len(),
            opening_bytes: 0,
        };
        Ok(GapPacket {
            shape,
            calldata,
            event,
            next,
            head: after,
        })
    }

    /// Cut a gap suffix to the largest fitting advance. The caller retains the unconsumed suffix.
    pub fn advance_bounded(
        &self,
        trust: &TrustInput,
        prior: &GapPredecessor<'_>,
        gaps: &[Vec<u8>],
        start_head: Option<Hash>,
        admission: (&dyn RecoveryCalibration, &RecoveryLimits),
    ) -> Result<(GapPacket, RecoveryQuote)> {
        let (calibration, limits) = admission;
        self.check_calibration(calibration, limits)?;
        if prior.receipt.len() > RECEIPT_CAP {
            return fail_d(Rule::InputTooLarge, "cold receipt");
        }
        let prefix =
            42 + 1 + 4 + prior.receipt.len() + 2 + if prior.cursor.is_some() { 0 } else { 32 };
        let width = gap_proof_len(self.cfg.k);
        for count in (1..=1024.min(gaps.len())).rev() {
            let shape = RecoveryShape {
                entry: RecoveryEntry::AdvanceGaps,
                calldata_bytes: 68 + 32 * (prefix + count * width).div_ceil(32),
                operations: 0,
                pages: 0,
                gaps: count,
                receipt_bytes: prior.receipt.len(),
                opening_bytes: 0,
            };
            if let Some(quote) = quote_recovery(shape, calibration, limits) {
                return Ok((
                    self.gaps(GapEntry::Advance, trust, prior, &gaps[..count], start_head)?,
                    quote,
                ));
            }
        }
        fail_d(Rule::CapacityPreflight, "indivisible gap operation")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryContractRefusal {
    BadPacket,
    BadPredecessor,
    BadPage,
    BadStep,
}

/// Decode exact on-chain transport errors separately from local admission and provider refusals.
pub fn decode_recovery_refusal(data: &[u8]) -> Option<RecoveryContractRefusal> {
    use RecoveryContractRefusal::{BadPacket, BadPage, BadPredecessor, BadStep};
    [
        (b"BadPacket()".as_slice(), BadPacket),
        (b"BadPredecessor()".as_slice(), BadPredecessor),
        (b"BadPage()".as_slice(), BadPage),
        (b"BadStep()".as_slice(), BadStep),
    ]
    .into_iter()
    .find_map(|(signature, refusal)| (data == &he(&[signature])[..4]).then_some(refusal))
}
