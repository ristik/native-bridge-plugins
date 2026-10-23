//! The strict SDK token codec of the lineage relation (bft-core `bridgeprofile/sdktoken.go` and `certscan.go`): the whole token
//! `tag(39040,[2,[M,proof0],[[T1,proof1],...]])` and the inclusion proof `tag(39033,[1,CD,t,b(bitmap32||siblings32...),UC])`. The
//! relation reads an ancestor from these exact bytes (the burned parent inside a split justification) and verifies its projection.

use alloc::vec::Vec;

use crate::error::{NativeError as E, Result};
use crate::history::{decode_cd, decode_mint, decode_transfer, Cd, History, Mint, Transfer};
use crate::limits::{
    INCLUSION_VERSION, MAX_DECODED_TOKEN_BYTES, MAX_PROOF_UC_BYTES, TAG_INCLUSION, TAG_TOKEN,
    TOKEN_VERSION,
};
use crate::resources::native_uc_scan;
use crate::scan::{scan_counted, scan_native, Item, Kind};

/// B1's certificate byte cap (bft-core `b1ref.MaxUCBytes`).
const B1_MAX_UC_BYTES: usize = 24576;
/// The only seal signature width the SDK certificate codec accepts; native B1 also admits 64 bytes.
const SDK_SIGNATURE_LENGTH: usize = 65;
const TAG_UC: u64 = 39001;

/// What field `index` of the certificate must be: `tag(tag, [arity items])` whose item `required` has the given kind.
struct CertField {
    index: usize,
    tag: u64,
    arity: usize,
    required: usize,
    kind: fn(&Kind<'_>) -> bool,
}

const CERT_FIELDS: [CertField; 4] = [
    // input record: its summary value
    CertField {
        index: 1,
        tag: 39002,
        arity: 10,
        required: 5,
        kind: |k| matches!(k, Kind::Bytes(_)),
    },
    // shard tree certificate: its siblings
    CertField {
        index: 4,
        tag: 39003,
        arity: 3,
        required: 2,
        kind: |k| matches!(k, Kind::Array(_)),
    },
    // unicity tree certificate: its steps
    CertField {
        index: 5,
        tag: 39004,
        arity: 3,
        required: 2,
        kind: |k| matches!(k, Kind::Array(_)),
    },
    // seal: its signatures
    CertField {
        index: 6,
        tag: 39005,
        arity: 8,
        required: 7,
        kind: |k| matches!(k, Kind::Map(_)),
    },
];

/// The bounded certificate scan every token-carried certificate passes before anything proportional to its contents: the native
/// shape and sublimit scan intersected with the SDK codec subset. Signatures and quorum stay the verifier's.
pub fn scan_certificate(raw: &[u8]) -> Result<()> {
    if raw.len() > B1_MAX_UC_BYTES {
        return Err(E::CertScan);
    }
    let root = scan_native(raw).map_err(|_| E::CertScan)?;
    let uc = root
        .tag_content(TAG_UC)
        .map_err(|_| E::CertScan)?
        .array(7)
        .ok_or(E::CertScan)?;
    for f in &CERT_FIELDS {
        let body = uc[f.index]
            .tag_content(f.tag)
            .map_err(|_| E::CertScan)?
            .array(f.arity)
            .ok_or(E::CertScan)?;
        if !(f.kind)(&body[f.required].kind) {
            return Err(E::CertScan);
        }
    }
    let seal = uc[6]
        .tag_content(39005)
        .map_err(|_| E::CertScan)?
        .array(8)
        .ok_or(E::CertScan)?;
    match seal[1].kind {
        Kind::Uint(n) if (1..=65535).contains(&n) => {}
        _ => return Err(E::CertScan),
    }
    if let Kind::Map(sigs) = &seal[7].kind {
        for sig in sigs.iter().skip(1).step_by(2) {
            // 64 bytes (r||s) or 65 with an ignored recovery suffix, as both SDKs and native B1
            match sig.kind {
                Kind::Bytes(d)
                    if d.len() == SDK_SIGNATURE_LENGTH - 1 || d.len() == SDK_SIGNATURE_LENGTH => {}
                Kind::Bytes(_) => return Err(E::CertSigLength),
                _ => return Err(E::CertScan),
            }
        }
    }
    native_uc_scan(raw, B1_MAX_UC_BYTES).map_err(|_| E::CertScan)
}

/// A certified inclusion proof; pending or uncertified responses are not proofs and have no encoding here.
#[derive(Debug, Clone)]
pub struct InclusionProof {
    pub cd: Cd,
    /// the reference time: part of the certified leaf, never a UC timestamp
    pub t: u64,
    pub bitmap: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    /// the canonical native certificate, an inline CBOR item
    pub uc: Vec<u8>,
}

/// A strictly decoded SDK token: its mint, transfers and proofs, with the exact transaction bytes.
#[derive(Debug, Clone)]
pub struct SdkToken {
    pub mint: Mint,
    pub mint_proof: InclusionProof,
    pub transfers: Vec<Transfer>,
    pub proofs: Vec<InclusionProof>,
    mint_raw: Vec<u8>,
    transfers_raw: Vec<Vec<u8>>,
}

fn decode_proof(it: &Item<'_>, b: &[u8]) -> Result<InclusionProof> {
    // Arity 5: version, CD, t, path, UC. All certified-leaf fields mandatory.
    let k = it.tag_content(TAG_INCLUSION)?.array(5).ok_or(E::Shape)?;
    k[0].version(INCLUSION_VERSION)?;
    let cd = decode_cd(&k[1])?;
    let t = k[2].uint()?;
    let path = match k[3].kind {
        Kind::Bytes(p) => p,
        _ => return Err(E::Shape),
    };
    if path.len() < 32 || path.len() % 32 != 0 {
        return Err(E::Length);
    }
    let mut bitmap = [0u8; 32];
    bitmap.copy_from_slice(&path[..32]);
    let pop: usize = bitmap.iter().map(|x| x.count_ones() as usize).sum();
    if path.len() != 32 + 32 * pop {
        return Err(E::Length);
    }
    if k[4].end - k[4].start > MAX_PROOF_UC_BYTES {
        return Err(E::InputTooLarge);
    }
    if !matches!(k[4].kind, Kind::Tag(..)) {
        return Err(E::Shape);
    }
    let uc = k[4].raw(b);
    // A certificate outside the native/SDK intersection is never projected: its structure here, its signatures and quorum later.
    scan_certificate(uc)?;
    let siblings = path[32..]
        .chunks_exact(32)
        .map(|c| {
            let mut s = [0u8; 32];
            s.copy_from_slice(c);
            s
        })
        .collect();
    Ok(InclusionProof {
        cd,
        t,
        bitmap,
        siblings,
        uc: uc.to_vec(),
    })
}

/// Strictly decode an entire SDK token: every proof mandatory and complete; trailing bytes, extra slots and a separate reference-time
/// slot are refused. A token is bounded by its bytes alone: its transfers and items are those of the history the composition streams.
pub fn decode_token(b: &[u8]) -> Result<SdkToken> {
    if b.len() > MAX_DECODED_TOKEN_BYTES {
        return Err(E::InputTooLarge);
    }
    let (root, _) = scan_counted(b, usize::MAX, true)?;
    let c = root.tag_content(TAG_TOKEN)?.array(3).ok_or(E::Shape)?;
    c[0].version(TOKEN_VERSION)?;
    let g = c[1].array(2).ok_or(E::Shape)?;
    let list = c[2].any_array().ok_or(E::Shape)?;
    let mut t = SdkToken {
        mint: decode_mint(&g[0])?,
        mint_raw: g[0].raw(b).to_vec(),
        mint_proof: decode_proof(&g[1], b)?,
        transfers: Vec::new(),
        proofs: Vec::new(),
        transfers_raw: Vec::new(),
    };
    for p in list {
        let pair = p.array(2).ok_or(E::Shape)?;
        t.transfers.push(decode_transfer(&pair[0])?);
        t.proofs.push(decode_proof(&pair[1], b)?);
        t.transfers_raw.push(pair[0].raw(b).to_vec());
    }
    Ok(t)
}

impl SdkToken {
    /// The B2 projection: the same tagged transactions and CDs, each `t` taken solely from its proof.
    pub fn project(&self) -> History {
        History {
            mint: self.mint.clone(),
            mint_cd: self.mint_proof.cd.clone(),
            mint_t: self.mint_proof.t,
            transfers: self.transfers.clone(),
            cds: self.proofs.iter().map(|p| p.cd.clone()).collect(),
            times: self.proofs.iter().map(|p| p.t).collect(),
            mint_raw: self.mint_raw.clone(),
            transfers_raw: self.transfers_raw.clone(),
        }
    }
}
