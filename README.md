# Native bridge plug-ins

Bridge-owned native UCT protocol and SDK extensions, licensed MIT OR Apache-2.0.
The wallet plug-ins of native bridge v2 (protocol 10; design in bft-core
`docs/design/nb2-continuation-v1.1.md`) over the SDK 4.0 trust-base history (JS SDK
`4.0.0-utb.c5840ef`, vendored; Rust `unicity-token` at `de79e6c1`). Package
publication is disabled. The protocol 6/7 bridge (lock proofs, per-part
nullifiers, the claim step, its corpus and harnesses) was removed by
bft-core#1106.

| Path | Responsibility |
| --- | --- |
| `protocol/interop.md` | Sole normative native byte contract: native bridge v2, protocol 10 (bft-core#1108) |
| `protocol/profile.json`, `protocol/abi.json` | v2 semantic profile and frozen vault/verifier ABI |
| `protocol/vectors/nb2-continuation-v1.1/` | T1 golden bytes and signed lineage transcripts |
| `packages/native-bridge-plugin/` | TypeScript wallet plug-in (`./nb2`) and the shared trust input, version 0.1.0 |
| `crates/native-bridge-sdk-ext/` | alloc-compatible Rust port (`nb2`), version 0.1.0 |
| `wallet/` | The reference command-line wallet (`nb2-wallet.ts`) on the TypeScript plug-in, and its core (`core.ts`) that the bft-core testnet lane drives |
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
[wallet integration guide](docs/nb2-wallet-guide.md) (with the reference wallet) and the [journal format](docs/nb2-journal.md).

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

## Paired-lane workloads

The [continuation transcripts](protocol/vectors/nb2-continuation-v1.1/README.md) provide offline evidence for
600 transfers and 20 splits. To certify fresh evidence under a paired development lane's authority, pass a
fresh, held protocol 10 root from that lane to the workload producer. Use a separate funded test root per run.
The owner file contains the 32-byte test signing key as hex. The root for the deep case must hold more than
20 base units so every split has two positive outputs. The final burn uses the supplied verified seal receipt
or starts at segment zero when the vault has never sealed.

```sh
npm exec -- tsx packages/native-bridge-plugin/scripts/nb2-lane-workload.ts \
  --gamma /path/to/gamma.bin --utb /path/to/utb.cbor \
  --root /path/to/held.nb2l \
  --owner /path/to/owner-key.hex --recipient 0x0000000000000000000000000000000000001234 \
  --aggregator http://127.0.0.1:8080 --history transfers-600 --output /path/to/return.nb2l
```

History accepts `transfers-600`, `one-split-600` and `depth-20`. Supply `--build test` for a small-parameter
development vault and `--seal /path/to/seal.cbor` for an authenticated nonzero starting index. The producer reserves the output up front and keeps its journal beside it in
`<output>.journal/`. Rerun with the same workload and output after an interruption. When a certificate needs a newer signer epoch, the producer reloads the pinned UTB history and rechecks the pending proof without sending another request. Update the UTB file from an authenticated history source. The producer waits up to two minutes per authority check, then leaves the journal ready
to resume. It checks destination ownership again before publishing. The producer prints the verdict and the exact signed mint and transfer byte totals per level. Both SDK extensions accept
the resulting flat evidence. The online wallet's recovery fee qualification is tracked under NB2-C T5 and T6.
