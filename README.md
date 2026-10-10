# Native bridge plug-ins

Bridge-owned native UCT protocol and SDK extensions, licensed MIT OR Apache-2.0.
The TS and Rust SDK 3.0.1 extensions and shared corpus are implemented. Native
activation and a deployed bridge remain gated on joined acceptance. Package
publication is disabled.

| Path | Responsibility |
| --- | --- |
| `protocol/interop.md` | Sole normative native byte contract, protocol v3 |
| `protocol/manifest.schema.json` | Strict deployment registry schema v1 |
| `protocol/abi.json` | Frozen cross-stack ABI layout |
| `protocol/vectors/` | Sole released corpus, pinned to the merged oracle |
| `packages/native-bridge-plugin/` | TypeScript verifier/wallet adapter, version 0.1.0 |
| `crates/native-bridge-sdk-ext/` | alloc-compatible Rust extension, version 0.1.0 |
| `deployments/` | Frozen manifests (none installed yet) |
| `docs/spec/` | Trust boundary and implementation gates |
| `tests/interop/`, `tools/` | Schema, provenance, import and regeneration checks |
| `tests/joined/` | Pinned serial component harness; live acceptance blocked on B1 integration |

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

Corpus CI checks the released bytes and regenerates them with the pinned Go
oracle. See [vector workflow](protocol/vectors/README.md) and [plug-in usage](docs/plugins.md).
The [joined harness](tests/joined/README.md) distinguishes component evidence
from the pending private one-shard round trip; see the
[acceptance report](docs/acceptance/pr6.md).
