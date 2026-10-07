# Native bridge plug-ins

Bridge-owned native UCT protocol and SDK extensions, licensed MIT OR Apache-2.0.
This is a development skeleton. It contains no working token verifier, deployed
vault or released corpus. Package publication is disabled.

| Path | Responsibility |
| --- | --- |
| `protocol/interop.md` | Sole normative native byte contract, protocol v2 |
| `protocol/manifest.schema.json` | Strict deployment registry schema v1 |
| `protocol/abi.json` | Frozen cross-stack ABI layout |
| `protocol/vectors/` | Sole released corpus; awaiting the PR2 candidate |
| `packages/native-bridge-plugin/` | TypeScript facade, version 0.1.0 |
| `crates/native-bridge-sdk-ext/` | alloc-compatible Rust extension, version 0.1.0 |
| `deployments/` | Frozen manifests (none installed yet) |
| `docs/spec/` | Trust boundary and implementation gates |
| `tests/interop/`, `tools/` | Schema, provenance, import and regeneration checks |

The layout follows `unicitynetwork/unicity-bridge` at
`deb2b86c0a1fa0398928cb88caac9feccda6f4e9`. Native custody stays in
unicity-pos-contracts; execution in ureth; the independent semantic oracle in
bft-core. External SDKs are dependencies, never copied or patched here.

This unreleased profile supports one fixed SDK RootTrustBase, unit validator
weights and SDK count quorum. Epoch evolution, arbitrary weights and trust-base
append/fetch are deferred to [common SDK work #421](https://github.com/ristik/bft-core/issues/421).
See [the exact SDK trust-document/UC contract](protocol/sdk-trust-base.md).

```sh
npm ci
npm run build && npm run typecheck && npm test
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo check --locked --no-default-features
python3.12 -m venv .venv
.venv/bin/pip install -r tools/requirements.txt
.venv/bin/python -m unittest discover -s tests/interop -v
.venv/bin/python tools/check_protocol.py
.venv/bin/python tools/vectors.py check
```

`corpus` CI intentionally fails until the candidate and its digest are imported.
See [vector workflow](protocol/vectors/README.md). PR1 remains draft until then.
CI does not claim PR3's independent SDK constructors, contract conformance,
ureth measurements or PR6's joined native round trip.
