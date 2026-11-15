//! Native Unicity bridge v2 (protocol 9) extensions over the `unicity-token` SDK, with no SDK change: module [`nb2`], the wallet
//! plug-in, over the shared trust input ([`trust`]) and native certificate scan ([`resources`]). The protocol 7 plug-in (lock proofs,
//! per-part nullifiers, the claim step) was removed with that bridge (bft-core#1106).
//!
//! The pure core is `alloc`-compatible. Verification is fully offline.

#![cfg_attr(not(feature = "host"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod error;
pub mod limits;
pub mod nb2;
pub mod resources;
pub mod trust;

pub use error::{Family, NativeError, Result};
