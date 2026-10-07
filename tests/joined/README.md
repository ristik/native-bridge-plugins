# Joined native bridge acceptance

The current pins deliver **component evidence only**. Full acceptance is BLOCKED
on B1 PR4 integration. The harness never reports PASS for a private round trip.
It neither starts a devnet nor deploys, activates or publishes anything.

`pins.json` records full merged commits, supported fixed-base/unit-weight scope,
blocked live scenarios and explicitly deferred SDK trust work. Source validation
requires exact clean checkouts; the plug-in implementation and released corpus
must match the accepted baseline. Harness changes do not alter protocol bytes.

Prepare clean worktrees named `nbp-pr6-{ureth,contracts,oracle,aggregator}` under
a source directory outside this repository at the commits in `pins.json`. Initialize the contracts'
submodules. Install Node >=22, Python with `tools/requirements.txt`, Go >=1.25,
Rust stable (rustfmt/clippy), and Foundry 1.8.1 / solc 0.8.37 on PATH.

```sh
npm ci --ignore-scripts
python3 -B -m unittest discover -s tests/joined -v
python3 -B tests/joined/mutate.py
python3 tests/joined/run.py --sources /path/to/worktrees --out /path/to/new-evidence
```

Exit **1** means a check failed; **2** means component checks finished but live
acceptance is blocked. `--skip-native` records Rust/B2/Foundry as NOT RUN, which
is insufficient even for the component CI gate. CI explicitly requires every
component step PASS while retaining the overall BLOCKED verdict. Logs, exact
commands, toolchains, source/harness pins and SHA-256 hashes are saved with the
report; the output directory must be new. All phases run serially with private
Go/Rust caches which are removed afterwards. The harness waits for existing
cargo/rustc/solc/Go builds before starting compiled components. No pinned lane
binary or another agent's worktree is removed.

The executable checks are:

* Released corpus integrity and regeneration with its own pinned Go generator;
  targeted `bridgeprofile`/`b1ref` oracle tests (no full bft-core suite).
* Actual TS/Rust plug-in suites: offline embedded backing, strict unlocks,
  fixed-epoch/unit-weight refusals, cumulative budgets, wallet recovery and
  same-base proof refresh. These use synthetic SDK certificates.
* `construct.ts` verifies mint, transfer and terminal burn from one SDK-built
  world. Later admitted roots and serialized reload preserve exact J/M/T/CD/t
  and nullifier. It exports the same obligations to the next two checks.
* `aggregator.go` links **aggregator-go ae08165**, decodes and re-encodes the
  SDK3 inclusion proofs, computes the leaf values and verifies all nine original
  and refreshed membership paths. Each path independently rejects txHash as
  value, changed t and wrong root with `errors.Is(ErrCertRootMismatch)`.
  This is real service implementation code, **not a running service test**.
* The ephemeral Rust driver builds the **merged ureth B2 library**, compares
  all 448+128*m result bytes against TS for prepare/mint/return/refresh and a
  flipped-unlock refusal, and checks exact-gas versus gas-1 OOG, framing and the
  outer byte cap. It does not register a node factory or execute a vault call.
* The contracts' unmodified golden generator runs via a Go overlay on the
  merged oracle. Its bytes must match the pinned contracts, and all 68 listed
  shared values must occur in the merged corpus. This explicitly handles the
  contracts' stale pre-merge provenance without changing either corpus.
* The pinned Foundry bridge suite checks accounting, replay, claim failures,
  reentrancy, authenticated IR-opening composition and limits using **labelled
  B1/B2 doubles**. These tests do not satisfy the deferred native-call gate.

Before live acceptance, replace the blocked integration with an executable
private one-shard deployment at a merged B1 integration pin, keeping the SDK3
aggregator requirement. Every devnet invocation must use
`/Users/risto/uni/agre/briefs/devnet-lock.sh nbp-pr6 <command...>`.
Do not reuse or stop another running lane. Record runtime/binary hashes,
chain/root genesis, registry slots/profile/system gas, vault and verifier code
hashes, the installed SDK trust document and deployment manifest. Only then
collect lock -> mint -> transfer -> burn -> redeem -> claim transaction receipts,
real 0x0100/0x0102/0x0104 calls, spent/credit/P/D/L state, permissionless redeem,
duplicate/conflicting burn refusal, failed claim rollback, same-base refresh,
pair restart/replay and reorg behavior, and measured gas/resource boundaries.
A wallet burn acknowledgement alone cannot prove settlement. Synthetic roots,
precompile doubles and direct library calls cannot fill these live evidence slots.

Arbitrary weights, committee rotation, trust-base append/fetch, interval closure,
old-J validity across rotation and full B1/SDK seal parity remain deferred,
unsupported cases. They must not be counted as passing coverage.
