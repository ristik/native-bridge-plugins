//! Native bridge v2 (protocol 9) wallet plug-in, the Rust counterpart of the TypeScript plug-in
//! (`packages/native-bridge-plugin/src/nb2`, NB2-07 bft-core#1103). It ports the same calls and safety rules and adds nothing:
//! the pure verifier relation, the segment and gap-proof functions, the vault model, and (with `host`) the journal format of
//! `docs/nb2-journal.md`, the RPC adapters over a caller-supplied transport and the high-level API [`bridge::NativeBridgeV2`].
//!
//! Module for module it follows the TypeScript files of the same names. The pure modules are `alloc` only; the journal, the
//! RPC reader, the aggregator adapter and the bridge need `host` (JSON and in-process locks). Like the rest of this crate it
//! has no network capability of its own: the wallet supplies the HTTP transport, the aggregator client and the signers.

pub mod abi;
pub mod cbor;
pub mod config;
pub mod crypto;
pub mod deposit;
pub mod errors;
pub mod evm;
pub mod gas;
pub mod header;
pub mod mpt;
pub mod rlp;
pub mod rules;
pub mod segment;
pub mod split;
pub mod token;
pub mod tokenops;
pub mod trust;
pub mod util;
pub mod vaultmodel;
pub mod verify;

#[cfg(feature = "host")]
pub mod aggregator;
#[cfg(feature = "host")]
pub mod bridge;
#[cfg(feature = "host")]
pub mod journal;
#[cfg(feature = "host")]
pub mod rpc;

pub use errors::{Error, Nb2Error, Rule, WalletError, WalletReason};
