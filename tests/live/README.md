# Live DN-B lane driver

Runs the private bridge round trip against a running devnet: `lock → mint → transfer → burn → redeem → claim`, with the TS plug-in as the client and
nothing synthetic in the loop. Component evidence (`tests/joined`) is unchanged; this is the live tier it listed as blocked.

* The chain: ureth with B1/B2 natives, the vault and verifier deployed by unicity-pos-contracts `BridgeDeploy`, four shard validators, four profile-2 roots, aggregator-go as a
  BFT shard. Bring-up and evidence: ristik/bft-core `scripts/dnb-devnet.sh all` and `docs/operations/dnb/`.
* `lane.ts <lane-config.json>` — the lock executes on the chain; the lock proof is `eth_getProof` of the lock slot bound to the archived certificate of its block
  (`dnb-tool lockproof`, bft-core `scripts/dnb-tool`); the mint, the transfer and the burn are certified by the live aggregator; the return proof is assembled by the plug-in
  after every proof is refreshed under one certificate; the redemption is submitted by a third party to every validator's pool inside the B1 window; the credited recipient claims.
  Controls in the live window: a flipped certificate byte, a claim by an uncredited account, and the same burn redeemed twice are refused.
* `postcheck.ts <lane-config.json>` — after restarts, the aggregator still serves every state of the previous token with its original CD and reference time.

Requires Foundry 1.8.1 (`cast`), Node ≥ 22 (`npm ci --ignore-scripts`), the devnet lock (`briefs/devnet-lock.sh`), and `DNB_TOOL` (built `dnb-tool`).
Timing matters: B1 authenticates a certificate only within `W_cert` root rounds of the registry clock, and refuses one newer than the clock.

## Two-shard acceptance rows (B3)

`rows.ts <lane-config.json>` runs the DN-B two-shard rows against `DNB_AGG_SHARDS=2 scripts/dnb-devnet.sh all` (aggregator-go in `bft-shard`
mode, shards `40` and `c0`; `lane-config.json` carries `aggUrls`). Needs `DNB_REPO` (bft-core checkout), `AGG_BIN`, `DNB_TOOL`, and an attested
unicity-reth (`URETH_SHA256`, `URETH_COMMIT`, `URETH_PROVENANCE`). Evidence: `rows-evidence.json` (rows), `rows-limits.json` (measured limits).
The run's last line is `ROWS COMPLETE: ... N failed ... M measured limits`; the exit code is 1 when any row FAILED. A measured limit does not fail the run.

**Passed live** (two shards, W_cert 15, measured send-to-execution latency 8-9 root rounds, so the margin is 10): one anchor; two anchors on two
shards; 16 leaves with two anchors (gas against the gate and the 7M budget); the 5th anchor refused (plug-in `ErrTooManyPaths`, chain
`BudgetExceeded()`); 17 leaves refused; malformed final anchor, asserted by revert selector and trace; restart/recovery of a pending redemption; and the wallet rows, which use the plug-in's host freshness contract on the same burned token
(already-old token refreshed then redeemed, delayed send expired then same-token retry, future-origin wait). A wallet row that does not redeem is a FAIL.

**gas-1 / gas+headroom on one token.** In the evidence run (rows commit `9409f7e`) the minimum limit M (bisected with `eth_call` at a pinned block and clock override; `eth_estimateGas` is not the minimum) was 3,122,232 against an estimate of 3,135,110. The send at M-1 failed (status 0x0, anchors in the window at its execution block, 3,075,844 of 3,122,231 gas used: the starved frame is an inner call under the 63/64 rule, so a failing send does not consume its whole limit) and the same token's refetched proofs redeemed at M + M/32 + 50k. The row's assertion was revised after that run (the "consumed the whole limit" condition was wrong for this shape and is now recorded, not asserted; `gassearch.test.ts` checks the verdict). It has not been re-run in its final form.

**A=3 passed live** (wallet row, concurrent shard writes, three anchors in the sent bundle, 4,463,064 gas, margin 8, per-fetch spread 6-8 rounds). **A=4 is not passed live: it remains a measured limit** (spread 10-11 rounds over three fetches against 7 allowed). The same-shard two-round and own-round A=3/A=4 shapes are also measured limits. A=4 is covered by the oracle corpus and the contract/plug-in tests only; the explicit gap carried to testnet is that A=4 needs four shards certifying about the same root round (or a longer W_cert); this devnet has two shards. A measured limit does not fail the run.

Other limits: the forged 64-signature worst certificate is covered by the oracle corpus and the contract tests, not live. The `inWindow` helper
rebuilds tokens (fresh lock and mint) and is a test-shape device, not wallet evidence; wallet evidence is only the rows named `wallet:`.
