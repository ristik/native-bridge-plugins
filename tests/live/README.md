# Live DN-B lane driver

## Any-age lane (protocol 4): `anyage.ts`

Three non-interleaved commands for the final any-age lane (bft-core `briefs/anyage-final-lane-plan.md`, steps L1a, L1b and L1c), on the
protocol-4 plug-in (partition-only policy, one `CERT_BATCH_V2` over the anchor table):

* `anyage.ts save <lane-config.json> [<out-dir>]` locks, mints and burns one token, certified by the live aggregator(s), and saves
  the return proof assembled once from the proofs returned at certification (never refreshed). It writes:
  * `token.cbor`, `envelope.bin` and `batch-request.bin`, with their sha256 in `saved.json`;
  * each anchor's seal epoch and round;
  * the registry words at the save block: usable epoch U, clock O, tip, and each anchor epoch's start, end and hasEnd.
* `anyage.ts verify <lane-config.json> <saved.json> --epoch current|historical` re-checks the saved bytes' sha256 and runs two
  `eth_call`s, then writes `verify-<epoch>.json`:
  * the native `CERT_BATCH_V2` verdict on the saved request, which must be `(2, true)`;
  * the vault's whole `redeem` relation as the third-party submitter, without sending.

  `current` requires every anchor epoch to be the usable epoch; `historical` requires every anchor epoch to be below it (after the
  root handoff). It prints each anchor's age O − r and the estimated gas.
* `anyage.ts release <lane-config.json> <saved.json>` sends the one redemption of the saved envelope, checks the credit and the
  recorded nullifier, claims to a payee, and writes `release.json` (receipt, gas, nullifier, balance delta, registry at the redeem
  block).
* `anyage.ts negatives <lane-config.json> <saved.json>`, after the release, sends nothing to the vault. It runs two refusals (bft-core #438):
  - A conflicting burn: the pre-burn state, burned again to another address, is submitted to the aggregator. The proof served for that state ID
    must still be the first burn's, and the plug-in must refuse to build a return proof of the conflicting burn.
  - A replay with a fresh proof: the redeemed burn is consolidated again under a seal newer than every saved anchor. The vault must refuse it
    as `PartAlreadyRedeemed(nonce, partId)` (protocol 6: spent per lock and part), so a replay is refused on the spent part whatever the age of its proof.

  - An unknown-key forgery: the same fresh proofs with the seal re-signed by freshly generated keys under the same signer IDs. The plug-in must
    refuse it (`ErrQuorumNotMet`) and the vault's composition must refuse its envelope (`BridgeRejected` with a nonzero V2 status) before any
    spent-state check; the replay above is the control. This is NOT a retired-committee forgery: the package has no root handoff, so the
    retired-key case is covered by the plug-in unit tests (`retired-key.test.ts`, `tests/retired_key.rs`) and listed as not covered live (#438).

  It writes `negatives.json`.

Shard routing is host knowledge: `lane-config.json` may carry `aggShards: [{shard, url}]`. A leaf goes to the deepest configured shard
whose prefix its state ID carries, otherwise to `aggUrl`. The anchor's shard and configuration come from the UC, and the verifier refuses
a UC whose shard does not cover the leaf. The lock proof is `dnb-tool lockproof` (bft-core) as for the protocol-3 lane: the archived EVM
certificate under the fixed SDK trust base. The lock must therefore be certified before the lane's root handoff, which L1a does.

## Removed protocol-3 drivers

`lane.ts`, `rows.ts` and `postcheck.ts` were the protocol-3 DN-B round trip, its two-shard B3 rows and the post-restart check. They stopped compiling
when the plug-ins moved to protocol 4 and were never ported. They were removed at protocol 6; their last versions are in this repository's history
before the removal commit, and the DN-B evidence that names them (bft-core `docs/operations/dnb/`) records the commits it ran.
What they covered now runs elsewhere:

* The round trip, the duplicate/conflicting burn, the replay and custody: `anyage.ts` (`save`/`verify`/`release`/`negatives`) in the bft-core CI
  combined lane and the TN-B package stages (`deploy/testnet/bridge/rehearse_bridge.py`).
* The two-shard histories, per-SID and consolidated: `anyage.ts consolidated` with `aggShards`.
* The minimal-gas search: `gassearch.ts` (unit-tested in `gassearch.test.ts`), used by `anyage.ts long-history`.
