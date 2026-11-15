# Native bridge v2 vectors

`nb2-vectors.json` is the one vector file of the v2 profile (bft-core `docs/design/native-bridge-v2.md`,
protocol 9). Consumers import it by the digest in `nb2-vectors.json.sha256`. The bft-core Go reference generates it
(NB2-03, bft-core#1099):

```
go run ./nb2ref/cmd/nb2vectors -out <this directory>     # in a ristik/bft-core checkout
```

The output is a pure function of the code, and bft-core `nb2ref/testdata/nb2-vectors.json.sha256` pins the same digest.
While the file is generated, the reference replays every vector. A negative vector isolates one rule: every other
check of its input holds.

| Key | Contents |
|---|---|
| `rules` | every section 14 rule, its error signature and selector |
| `deployments` | Γ, D, K, B, its build (`production` or `test` admitted set), the trust-base bundle and genesis EntryID, the vault environment (`main`, `sharded`: production (K, B) = (64, 16); `k4`, `k8`: test) |
| `config` | Γ judged by the verifier (`ConfigShape`) and by the constructor (`BadConfig(field)`) |
| `verifier` | `verifyReturn(Γ, evidence)`: whole tokens with their deposit evidence, lineage and return; the verdict and its 192-byte ABI |
| `sealReceipts` | the wallet's `SegmentSealed` receipt check (`SealReceipt` and the rule it wraps) |
| `gapProofs`, `chainFolds`, `segmentLogs` | the gap tree, redeem step 3, the wallet's log check |
| `vault` | call sequences with a mock verifier's return data and the recipient's behaviour; events and final state per step; `harnessState` where no sequence can reach the state |
| `wallet` | seal companion answers (`EvidencePruned`), the capacity preflight and redemption refusals, and the `stateReadOnly` index check |
| `primitives` | minter scalars and the section 3 and 13 constants |

A rejection's `expect` carries the rule name, the custom error's arguments, the exact on-chain `revert` bytes (selector and
ABI arguments) and, where the on-chain primitive reports another name (`SealEpoch` and `NoEntryForEpoch` are
`QuorumNotMet` for aggregator UCs and `DepositUC` for the EVM UC), `onChainError`. Every vault step records the state
after it (accounting word, tag words, heads, live buffers) and its events; accepted seal receipts and segment logs record
their authenticated outputs.

Judge each deployment under its own build: production admits only (K, B) = (64, 16); a test build admits
K in {4, 8}, B in {2, 4} instead. Error names are the section 14 rules; `StateReadNotAdmitted`, `CompanionUnknown` and
`CompanionProvider` are wallet outcomes without a rule.
