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
mode, shards `40` and `c0`; `lane-config.json` carries `aggUrls`). Rows: anchors 1, 2, 2 on one shard, 3, 4 (several on one shard), the 5th refused
(by the plug-in and by the chain for the same bundle), 16 leaves (worst real bundle, gas against the gate and the 7M budget), 17 leaves refused,
malformed final anchor (flipped byte, bad CBOR head), gas-1 / gas+headroom, and restart/recovery of a pending redemption (aggregators, then every
validator, between redeem and claim). Needs `DNB_REPO` (bft-core checkout), `AGG_BIN`, `DNB_TOOL`. Evidence: `rows-evidence.json`.
Not yet run (needs a unicity-reth binary). Known limits: the exact minimum gas limit is not searched (one `U-1` and one `U+U/32+50k` attempt per
token, the B1 window allows no more); the forged 64-signature worst certificate is covered by the oracle corpus and the contract tests, not live.
