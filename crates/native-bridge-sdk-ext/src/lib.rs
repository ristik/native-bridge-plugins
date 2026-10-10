//! Native Unicity bridge extensions over the `unicity-token` SDK (tag v3.0.1), with no SDK change.
//!
//! The pure core is `alloc`-compatible. Verification is fully offline: a token plus a pinned
//! deployment allow-list and trust bundle is all a receipt check ever reads.

#![cfg_attr(not(feature = "host"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod deployment;
pub mod envelope;
pub mod error;
pub mod gas;
pub mod header;
pub mod history;
pub mod limits;
pub mod lockproof;
#[cfg(feature = "host")]
pub mod manifest;
pub mod mpt;
pub mod profile;
pub mod proof;
pub mod resources;
pub mod rlp;
pub mod scan;
pub mod token;
pub mod trust;
pub mod unlock;
pub mod verifier;

pub use error::{Family, NativeError, Result};

/// Native bridge protocol version (`NATIVE_BRIDGE_PROTO_VERSION=3`).
pub const NATIVE_BRIDGE_PROTO_VERSION: u8 = 3;
/// Bridge identity family.
pub const NATIVE_BRIDGE_FAMILY: &str = "unicity-native";
/// SDK the byte profile is built for.
pub const SDK_VERSION: &str = "3.0.1";
