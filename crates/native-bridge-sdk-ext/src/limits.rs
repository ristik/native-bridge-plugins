//! The native certificate scan bounds of [`crate::resources`] (bft-go-base's CBOR limits and the B1 UC byte cap).
pub const MAX_CBOR_DEPTH: usize = 16;
pub const MAX_CBOR_ITEMS: usize = 32768;
pub const MAX_UC_BYTES: usize = 16 << 10;
