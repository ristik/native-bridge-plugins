# native-bridge-sdk-ext

Native Unicity bridge extensions over `unicity-token` (pinned by commit, `de79e6c1`, the staging
SDK with the trust-base history; no SDK changes). The pure core is `alloc`-compatible
(`--no-default-features`); feature `std` adds manifest loading. The trust input is
`TrustInput::from_bundle(bundle, genesis_pin)`. See `docs/plugins.md` at the repository root.

Module `nb2` is the native bridge v2 (protocol 9) wallet plug-in, the port of the TypeScript
`packages/native-bridge-plugin/src/nb2` (bft-core#1104): the same verifier relation, vault model, calls,
safety rules and journal format (`docs/nb2-journal.md`). Its pure modules are `alloc` only; the journal,
the RPC reader, the aggregator adapter and `nb2::bridge::NativeBridgeV2` need `host`. The wallet supplies
the HTTP transport (`nb2::rpc::HttpPost` or a whole `JsonRpc`), the aggregator client, the signers and a durable
journal store, which it checks with `nb2::journal::check_journal_store` (this crate has no filesystem capability).
`host` is for native targets only (std threads, clocks and the OS random source); the pure core builds for wasm.

License: MIT OR Apache-2.0.
