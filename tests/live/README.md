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
