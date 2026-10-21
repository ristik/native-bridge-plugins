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
