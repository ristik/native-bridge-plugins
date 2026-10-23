//! BRIDGE_COMPOSE_V1 (0x0105), the native composition of B7 direct PR 2 (bft-core `bridgeprofile/native.go`): the input
//! encoding, the fixed 384-byte output and the append-only status table (`config/compose-status.json` in the corpus). The wrapper
//! reverts `BridgeRejected(uint256 status)` with these codes; a host decodes them with [`compose_status_name`].

use alloc::vec::Vec;

/// The precompile's address.
pub const COMPOSE_ADDRESS: [u8; 20] = {
    let mut a = [0u8; 20];
    a[18] = 0x01;
    a[19] = 0x05;
    a
};
/// `bytes32("UNICITY_BRIDGE_COMPOSE_V1")`, left aligned.
pub const COMPOSE_MARKER: [u8; 32] = *b"UNICITY_BRIDGE_COMPOSE_V1\0\0\0\0\0\0\0";
pub const COMPOSE_OUTPUT_BYTES: usize = 384;

/// Status code `i` is `COMPOSE_STATUS[i - 1]`; code 0 is success. Append-only, pinned against the corpus.
pub const COMPOSE_STATUS: &[&str] = &[
    "ErrTruncated",
    "ErrTrailing",
    "ErrNonCanonical",
    "ErrForbiddenCBOR",
    "ErrShape",
    "ErrTag",
    "ErrVersion",
    "ErrLength",
    "ErrIntRange",
    "ErrABIFraming",
    "ErrBadOperation",
    "ErrDeadline",
    "ErrInputTooLarge",
    "ErrTooManyTx",
    "ErrTooManyItems",
    "ErrTooDeep",
    "ErrTooManyPaths",
    "ErrJustificationTooLarge",
    "ErrLockProofTooLarge",
    "ErrCfgMismatch",
    "ErrPolicyHash",
    "ErrPolicyTuple",
    "ErrPolicyAnchors",
    "ErrPolicyLeafIndex",
    "ErrPolicyLeafCount",
    "ErrPolicyPartition",
    "ErrPredicate",
    "ErrMintShape",
    "ErrLockProofShape",
    "ErrLockProofCfg",
    "ErrMintJustif",
    "ErrMintSalt",
    "ErrMintType",
    "ErrMintData",
    "ErrTransferData",
    "ErrCDMismatch",
    "ErrUnlock",
    "ErrUnlockLength",
    "ErrUnlockScalars",
    "ErrUnlockRecovery",
    "ErrUnlockKey",
    "ErrMinterKey",
    "ErrRepeatedSID",
    "ErrNoTransfers",
    "ErrHasTransfers",
    "ErrBurnNotFinal",
    "ErrNotBurn",
    "ErrBurnReason",
    "ErrReturnData",
    "ErrReturnAmount",
    "ErrReturnRecip",
    "ErrLockInput",
    "ErrZeroDigest",
    "ErrDeadlineMismatch",
    "ErrDeadlineExpired",
    "ErrIROpening",
    "ErrIRShape",
    "ErrIRState",
    "ErrIRTime",
    "ErrPathBitmap",
    "ErrAnchorAuth",
    "ErrLeafProof",
];

/// The reason name of a status code: `ok` for 0, `None` for an unknown code.
pub fn compose_status_name(code: u64) -> Option<&'static str> {
    if code == 0 {
        return Some("ok");
    }
    COMPOSE_STATUS.get(usize::try_from(code - 1).ok()?).copied()
}

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn padded(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&word(b.len() as u64));
    out.extend_from_slice(b);
    out.resize(out.len() + (32 - b.len() % 32) % 32, 0);
}

/// `abi.encode(uint8 op, bytes cfg, bytes envelope)`: the canonical native input (its length is the schedule's B).
pub fn compose_input(op: u8, cfg: &[u8], envelope: &[u8]) -> Vec<u8> {
    let cfg_words = 32 + cfg.len().div_ceil(32) * 32;
    let mut out = Vec::with_capacity(96 + cfg_words + 32 + envelope.len().div_ceil(32) * 32);
    out.extend_from_slice(&word(u64::from(op)));
    out.extend_from_slice(&word(96));
    out.extend_from_slice(&word((96 + cfg_words) as u64));
    padded(&mut out, cfg);
    padded(&mut out, envelope);
    out
}

/// The status word of a 384-byte output, or `None` when the bytes are not an output (wrong length or marker, or a status above
/// 64 bits).
pub fn compose_output_status(out: &[u8]) -> Option<u64> {
    if out.len() != COMPOSE_OUTPUT_BYTES
        || out[..32] != COMPOSE_MARKER
        || out[32..56].iter().any(|&x| x != 0)
    {
        return None;
    }
    Some(u64::from_be_bytes(out[56..64].try_into().ok()?))
}

// ---- BRIDGE_COMPOSE_V2 (protocol 6, bft-core `native_lineage.go`) ----

/// `bytes32("UNICITY_BRIDGE_COMPOSE_V2")`, left aligned.
pub const COMPOSE_MARKER_V2: [u8; 32] = *b"UNICITY_BRIDGE_COMPOSE_V2\0\0\0\0\0\0\0";
/// Fifteen words: V1's twelve (the root's identity), then partTokenId, partAmount and splitDepth.
pub const COMPOSE_OUTPUT_BYTES_V2: usize = 15 * 32;

/// The split reasons appended to the V1 table, then the two certificate-codec reasons an embedded ancestor proof can raise.
pub const COMPOSE_STATUS_V2_APPENDED: &[&str] = &[
    "ErrSplitJustif",
    "ErrSplitProofCount",
    "ErrSplitProofShape",
    "ErrSplitManifest",
    "ErrSplitBurn",
    "ErrSplitProof",
    "ErrSplitSum",
    "ErrCertScan",
    "ErrCertSigLength",
];

/// The V2 reason name of a status code: `ok` for 0, `None` for an unknown code.
pub fn compose_status_name_v2(code: u64) -> Option<&'static str> {
    let v1 = COMPOSE_STATUS.len() as u64;
    if code <= v1 {
        return compose_status_name(code);
    }
    COMPOSE_STATUS_V2_APPENDED
        .get(usize::try_from(code - v1 - 1).ok()?)
        .copied()
}

/// A decoded successful V2 output (amounts minimal big-endian, as the relation returns them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeResultV2 {
    pub cfg: [u8; 32],
    pub nonce: u64,
    pub amount: Vec<u8>,
    pub token_id: [u8; 32],
    pub salt: [u8; 32],
    pub first_predicate_hash: [u8; 32],
    pub lock_digest: [u8; 32],
    pub release_to: [u8; 20],
    pub nullifier: [u8; 32],
    pub leaf_count: u64,
    pub part_token_id: [u8; 32],
    pub part_amount: Vec<u8>,
    pub split_depth: u64,
}

fn w32(out: &[u8], i: usize) -> [u8; 32] {
    out[32 * i..32 * i + 32].try_into().unwrap_or([0; 32])
}

fn small(w: &[u8; 32]) -> Option<u64> {
    w[..24]
        .iter()
        .all(|&x| x == 0)
        .then(|| u64::from_be_bytes(w[24..].try_into().unwrap_or([0; 8])))
}

fn minimal(w: &[u8; 32]) -> Vec<u8> {
    let i = w.iter().position(|&x| x != 0).unwrap_or(32);
    w[i..].to_vec()
}

/// Strictly decode a V2 output (bft-core `DecodeComposeOutputV2`): the marker, a status in the table, every field zero on a failure,
/// and on success words that fit (a 64-bit nonce, leaf count and depth, a 20-byte releaseTo). `None` for anything else.
pub fn decode_compose_output_v2(out: &[u8]) -> Option<(u64, Option<ComposeResultV2>)> {
    if out.len() != COMPOSE_OUTPUT_BYTES_V2 || out[..32] != COMPOSE_MARKER_V2 {
        return None;
    }
    let status = small(&w32(out, 1))?;
    compose_status_name_v2(status)?;
    if status != 0 {
        return out[64..].iter().all(|&x| x == 0).then_some((status, None));
    }
    if out[288..300].iter().any(|&x| x != 0) {
        return None;
    }
    let mut release_to = [0u8; 20];
    release_to.copy_from_slice(&out[300..320]);
    Some((
        0,
        Some(ComposeResultV2 {
            cfg: w32(out, 2),
            nonce: small(&w32(out, 3))?,
            amount: minimal(&w32(out, 4)),
            token_id: w32(out, 5),
            salt: w32(out, 6),
            first_predicate_hash: w32(out, 7),
            lock_digest: w32(out, 8),
            release_to,
            nullifier: w32(out, 10),
            leaf_count: small(&w32(out, 11))?,
            part_token_id: w32(out, 12),
            part_amount: minimal(&w32(out, 13)),
            split_depth: small(&w32(out, 14))?,
        }),
    ))
}
