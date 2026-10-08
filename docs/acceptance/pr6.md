# PR6 acceptance: fixed-base native bridge

Verdict: **BLOCKED — no private one-shard round trip, but the vault's native-call gate is closed
in-process.** The real vault, token verifier and SealRegistry run through the Unicity node's EVM factory
with B1 at 0x0100/0x0102 and the B2 kernel at 0x0104 executing natively (every call recorded as a native
precompile): lock -> verifyMint -> redeem -> claim, plus refusals. This is in-process execution, not a
devnet: there is no running node, no running SDK3 aggregator, no restart or reorg. No activation,
production deployment, merge or B4/B2 closure is claimed.

## Pins

| Component | Exact merged/source revision |
| --- | --- |
| Plug-ins (PRs 1/2) | `c70f2a76a1b250a98a0db0083d8b5fb6022acad4` |
| ureth node factory with B1 and B2 (#57 + #58 head; B1 PR4 is open, **re-pin after merge**) | `7e9a8ae0f6ed855f400b76e314b1c66ca0133295` |
| Vault/registry (contracts PRs 8/6) | `7e49fe1142ba7aca02fc4a33a3fe75b15a643d3a` |
| Go oracle (PRs 422/442) | `66fc865e1db7c5ef1e5ebdad2a0e2623d2c331e3` |
| SDK3 aggregator implementation | `ae081651ac7443496b5397baa8748e0b4280ba72` |

The ureth pin is the head of ristik/ureth#58 (B2 registration at 0x0104, stacked on #57 = B1 PR4, which
is itself under review); it contains the previously pinned B2 kernel (`7485a5cf`) unchanged. The corpus retains its own generator pin (`52fe1934…`) and is regenerated from
that exact commit. The current oracle pin additionally includes consumption of
the merged corpus. No consumer fixtures or protocol bytes were edited.
Full pins and unsupported/deferred scenarios are machine-readable in
[`pins.json`](../../tests/joined/pins.json).

## Executed evidence

The reproducible entry point is [`tests/joined/run.py`](../../tests/joined/run.py);
[its guide](../../tests/joined/README.md) states each evidence boundary. Every
component command runs serially and records its exit, log digest and toolchain.
Source checks reject floating revisions and dirty checkouts; four isolated
mutation probes catch source-pin, cleanliness, failed-step and false-acceptance
regressions. Green component commands still produce exit 2 / BLOCKED.

The [joined CI run](https://github.com/ristik/native-bridge-plugins/actions/runs/37662677997)
passed all 20 component commands on branch head `44bb3ccd114f3d6ce06d3780e5fa59c8cf2a807e`.
GitHub tested merge commit `c1936a7038b66df2df5460a520defcb1612ea97d`, whose
parents are that head and the accepted plug-in baseline. The full
[artifact](https://github.com/ristik/native-bridge-plugins/actions/runs/37662677997/artifacts/11501832944)
contains every log, the exact generated join bytes and resolved B2 build lock.
The [raw report](pr6-components.json) preserves commands, timings, toolchains,
harness input hashes and artifact digests. All recorded hashes were verified,
and the local TS join bytes reproduce the CI join byte-for-byte.

| Check | Result / evidence boundary |
| --- | --- |
| TS plug-in suite | CI: 92 passed / 3 skipped; local: 93 passed / 2 deferred skips |
| Network-disabled receipt | Passed locally; Linux CI sandbox unavailable and explicitly skipped |
| Rust suite | 150 passed / 4 ignored deferred scenarios; fmt, clippy and alloc-only check passed |
| SDK3 aggregator join | 9 codec/leaf/path positives; 27 isolated sentinel rejections |
| Merged B2 library | 5 exact-ABI cases; exact gas and gas-1 OOG; framing and outer input budget refusals |
| Go oracle | Targeted bridgeprofile and b1ref passed; released corpus regenerated exactly |
| Contract goldens | Byte-identical regeneration; all 68 shared values agree with merged corpus |
| Foundry bridge suite | 239 passed / 0 failed / 0 skipped, including custody invariants; native precompiles are doubles |
| Evidence guards | 6 tests passed; 4/4 isolated guard removals killed |
| Local Python interop | 39 passed |

The [local check logs](evidence/local-checks.log) preserve the platform-specific
receipt and guard results. Local compiled phases were stopped **while queued**
after the isolated CI run passed, avoiding a parallel build with another agent's
ureth compilation. No local native build is counted as completed.

The driver observed provisional B2 charges of 38,160 (prepare), 91,200 (mint)
and 133,280 (return/refresh/invalid unlock). These are deterministic library
charges, not full-transaction gas benchmarks or measured activation budgets.
CI's green result means **component checks passed with live acceptance blocked**.

The synthetic SDK world binds the real plug-in's offline certified EVM lock
proof to mint -> transfer -> burn. The resulting leaves and compact history
cross the language boundaries: aggregator-go's actual SDK3 codec/leaf/path code,
and ureth's actual merged B2 implementation. A later admitted synthetic root
plus a serialized token reload preserves J/M/T/CD/t and nullifier. This supplies
component construction/refresh evidence, not running-service, chain restart,
reorg, real vault lock or settled redemption evidence.

The contracts' goldens still carry pre-merge corpus/oracle provenance. The
harness checks their exact regenerated bytes on the merged oracle and compares
the 68 listed shared values with the merged corpus. Foundry B1/B2 doubles remain
explicitly classified as doubles; reference verdicts are not native calls.

## Native-call evidence (in-process)

Entry: `tests/joined/run.py` steps `native-contracts-build` .. `native-driver`; the driver is
`tests/joined/native/`. The raw report is [`pr6-native.json`](pr6-native.json) (sha256 of the run's
files: report `28f0ac57…`, genesis `9aea0e24…`, golden `124a3213…`). The harness run passed all 25 steps
(exit 2, BLOCKED).

What is real: the compiled `BridgeVault` and `TokenVerifier` at the contracts pin; the SealRegistry
runtime (code hash `0x28ebc47d…`) and a genesis produced by the production B1 path
(`q3format.NewHistory` -> `registrygenesis.GenerateB1`, 55 words) from the oracle's one-member root
authority; the registry clock advanced to root round 100 by one quiet update through the real registry's
privileged `open`/`finalize` (292,528 gas of a 34,789,324 reservation); `UnicityEvmFactory` from ureth#58,
whose inspector records each call to 0x0100, 0x0102 and 0x0104 with `was_precompile_called`.

| Step | Result | Gas (tx) / native calls |
| --- | --- | --- |
| lock (1 token, 1e18 wei) | stored lock digest equals the oracle's; kernel request equals the oracle's prepare request | 292,064; 0x0104 38,160 |
| verifyMint | returns nonce 1 | 1,615,801; 0x0104 89,920, 0x0100 1,258,052, 0x0102 5,950 |
| redeem by a third party | credits the certified recipient; nullifier equals the oracle's | 1,798,799; 0x0104 132,000, 0x0100 1,258,052, 0x0102 5,950 + 2 x 6,712 |
| claim | L = D = P = 1e18, vault balance 0, payee paid | 107,779 |

Refusals, each leaving vault state unchanged: duplicate burn and a conflicting burn (other recipient) after
the first (`AlreadyRedeemed`), and the first burn wins in either order; redeem before any lock
(`UnknownLock`); claim by a non-credited account (`InsufficientCredit`); claim to a reverting payee
(`PayoutFailed`, credit and P roll back); zero-value lock; a flipped membership sibling
(`LeafNotIncluded`); registry absent (fatal host error: the node cannot execute the transaction, never a
verdict). A single-byte flip scan over the 411-byte certificate: 410 refused (357 `UCRejected`, 53
malformed -> B1 halts and the call burns its forwarded gas, ~6.4M gas), **1 accepted: the final byte,
the signature recovery id**. B1 verifies against the registered key, so that byte is not authenticated;
this is the disclosed seal-signature difference below, not a new defect claim.

Measured minimal gas limits (bisected): lock 294,250; verifyMint 1,634,984; redeem 1,800,985; claim
109,980, against the profile's 7,000,000 ordinary capacity. A malformed certificate or a duplicate burn
still costs the submitter 6.4M / 1.73M gas respectively. These are in-process revm figures, not a node
benchmark or an activation price.

Each step must show its own native calls, not just somewhere in the report: lock -> 0x0104; verifyMint
and redeem -> 0x0104, 0x0100 and 0x0102 (redeem three times, one per leaf), every call a native precompile
call that succeeded. The driver and `check_native_report` both enforce this per step, and the recorded
kernel requests and results, the UC request and the RSMT requests equal the oracle's bytes. The certificate
refusal case asserts `UCRejected` (a verdict), using an authenticated offset.

Deviations from the merged contracts' golden: its `golden.json` pins fixture identities (verifier code
hash, root genesis, execution genesis, B1 profile hash), so it cannot drive a real vault. The harness
reruns the oracle's own golden generator with the verifier code hash replaced by the compiled runtime
hash and the **root genesis, execution genesis and B1 profile hash taken from the executed genesis**
(`rootGenesisId`, genesis hash, profile hash; `ty`/`aid` follow), and regenerates prepare / mint /
return and a conflicting burn; the driver asserts the three identities equal the registry's. The vault
and verifier constructors run in place at the oracle's fixed addresses (so `address(this)` and CREATE
addresses equal a real deployment there; `extcodesize(this)` is non-zero during the constructor, which
these contracts do not observe). The genesis' EVM partition description uses the production parameter
name `chain_id` where the oracle fixture says `chainId`. The lock backing inside the histories is the
oracle's synthetic EVM state proof, not an `eth_getProof` of the state executed here.

Open questions this tier cannot answer (contracts / B1 owners): (1) neither the vault nor the verifier
checks `cfg.rootGenesis` or `cfg.b1ProfileHash` against the registry's root genesis or `b1.profileHash`;
the identities above agree by construction of this run, but a vault configured with other values would
pass the same tier. (2) B1 does not authenticate the certificate's signature recovery-id byte, so two
encodings of one certificate verify; the vault keys on the nullifier, so there is no double credit, but
the owner should confirm that is intended or canonicalize it.

## Outstanding acceptance gates

| Gate | Status / required evidence |
| --- | --- |
| Vault -> real B1 0x0100/0x0102 and B2 0x0104 | **CLOSED in-process** (above). Not yet through a running node: RPC/Engine API routes, block build/import. |
| SDK3 running aggregator, private one-shard round trip | BLOCKED; run actual lock/mint/transfer/burn/redeem/claim on a live lane with real lock backing from the executed chain |
| Paired refresh/restart/replay/reorg | BLOCKED; prove canonical settlement state and no duplicate credit after interruption/reorg |
| Native gas/resource budgets and final deployment pins | PARTIAL: per-call and transaction gas measured in-process; production budgets, arm64 CPU, block/system-gas interaction and final pins remain. Carry in: a malformed certificate halts B1 and burns ~6.4M of the 7M ordinary capacity |

The merged B2 kernel previously had no factory (ureth `7485a5cf`, `b2/src/lib.rs`); ureth#58 registers it
next to B1 in `UnicityEvmFactory`, with the same inactivity (only the Unicity node builds that factory).

No devnet was started or changed and `briefs/devnet-lock.sh` was not needed: the native tier is
in-process. A future joined run must acquire it and use its own lane. No pinned `/private/tmp` lane
binary was removed. No full bft-core suite was run locally.

## Supported scope and limits

One provisioned fixed SDK RootTrustBase; distinct unit-weight validators; SDK
count quorum; one network/epoch; the SDK-decodable native certificate subset.
Non-unit configuration and epoch mismatch are rejection cases, not authority
migration support. SDK/native seal-signature differences remain disclosed.

**DEFERRED / unsupported:** arbitrary weights including `(98,1,1)`, rotating or
mixed historical/current committees, trust-base append/fetch/interval closure,
old-J validity across rotation and full B1/SDK seal acceptance-set parity. These
are common SDK trust-base work, not passing scenarios or prerequisites that this
private fixed-base harness claims to deliver.
