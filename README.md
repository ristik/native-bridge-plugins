# Native bridge plug-ins

Bridge-owned native UCT protocol and SDK extensions, licensed MIT OR Apache-2.0.
The wallet plug-ins of native bridge v2 (protocol 9; design in bft-core
`docs/design/native-bridge-v2.md`) over the SDK 4.0 trust-base history (JS SDK
`4.0.0-utb.c5840ef`, vendored; Rust `unicity-token` at `de79e6c1`). Package
publication is disabled. The protocol 6/7 bridge (lock proofs, per-part
nullifiers, the claim step, its corpus and harnesses) was removed by
bft-core#1106.

| Path | Responsibility |
| --- | --- |
| `protocol/interop.md` | Sole normative native byte contract: native bridge v2, protocol 9 (bft-core#1097) |
| `protocol/profile.json`, `protocol/abi.json` | v2 semantic profile and frozen vault/verifier ABI |
| `protocol/vectors/nb2/` | The shared v2 vector file (bft-core `nb2ref`) |
| `packages/native-bridge-plugin/` | TypeScript wallet plug-in (`./nb2`) and the shared trust input, version 0.1.0 |
| `crates/native-bridge-sdk-ext/` | alloc-compatible Rust port (`nb2`), version 0.1.0 |
| `tester/trust.ts` | The trust-base refresh helper the bft-core testnet driver uses |
| `tests/interop/`, `tools/` | Profile, ABI, dependency-pin and vector checks |

Native custody stays in unicity-pos-contracts; execution in ureth; the
reference relation in bft-core (`nb2ref`). External SDKs are dependencies,
never copied or patched here.

Certificates verify against the network's Unicity Trust Base history: one
RootTrustBaseV2 entry per root epoch, installed from a release bundle under its
genesis EntryID pin, with weighted quorum under each epoch's own committee. The
wallet appends newer entries through the SDK's trust-base fetch; receipt
verification itself fetches nothing. See
[the trust-base history and UC contract](protocol/trust-base.md), the
[wallet guide](docs/nb2-wallet-guide.md) and the [journal format](docs/nb2-journal.md).

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
```
