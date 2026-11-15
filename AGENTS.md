# Native bridge plug-ins

`protocol/interop.md` is the sole normative native byte contract (native bridge
v2, protocol 9; design in bft-core `docs/design/native-bridge-v2.md`). Changes to
bytes or derivations require a protocol version and semantic-profile update, and
the digests in `protocol/profile.json`. The code still implements protocol 7:
`protocol/legacy-v7/` and `protocol/vectors/` stay for its tests until
bft-core#1106 removes both.
Never copy external bridge trust logic or fork the state-transition SDKs.

Use `npm ci`, `npm run build`, `npm run typecheck`, `npm test`,
`cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked`, and `cargo check --locked --no-default-features`.
Protocol tooling: `python3 -m unittest discover -s tests/interop -v`;
`python3 tools/check_protocol.py`; `python3 tools/vectors.py check`.
The corpus is imported from the pinned oracle; never hand-edit it, silence
the check or substitute old-profile fixtures. Read protocol/vectors/README.md.

Publishing is disabled. No SDK checkouts, vault source, SP1 workspace or path
SDK dependencies belong here. Receipt verification has no network capability.
