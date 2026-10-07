# Native bridge plug-ins

`protocol/interop.md` is the sole normative native byte contract. Changes to
bytes or derivations require a protocol version and semantic-profile update.
Never copy external bridge trust logic or fork the state-transition SDKs.

Use `npm ci`, `npm run build`, `npm run typecheck`, `npm test`,
`cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked`, and `cargo check --locked --no-default-features`.
Protocol tooling: `python3 -m unittest discover -s tests/interop -v`;
`python3 tools/check_protocol.py`; `python3 tools/vectors.py check`.
The last command must fail while the candidate corpus is missing. Do not
silence it or substitute old-profile fixtures. Read protocol/vectors/README.md.

Publishing is disabled. No SDK checkouts, vault source, SP1 workspace or path
SDK dependencies belong here. Receipt verification has no network capability.
