# native-bridge-sdk-ext

Native Unicity bridge extensions over `unicity-token` (pinned by commit, `de79e6c1`, the staging
SDK with the trust-base history; no SDK changes). The pure core is `alloc`-compatible
(`--no-default-features`); feature `std` adds manifest loading. The trust input is
`TrustInput::from_bundle(bundle, genesis_pin)`. See `docs/plugins.md` at the repository root.

License: MIT OR Apache-2.0.
