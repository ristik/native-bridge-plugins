# Admitted and refused history shapes, and the exit of each admitted one

bft-core #438 asks that every history a wallet admits has an exit (a redemption), and that the admitted and refused shapes are written down. This
page lists them for protocol 6 (`profile-v6.json`), with the test or corpus case behind each line.

## Why an admitted history can be redeemed

A wallet admits a bridged token with the **receipt** relation, `NativeBridge.verifyNativeToken(token, 'receipt')`. That is the **return**
relation the composition (0x0105) applies, minus the terminal burn: one function, `verifyHistory(dep, history, wantBurn)`, under the same
bounds (`COMPOSED_HISTORY`: the history bytes up to the 2 MiB direct envelope, no transfer, leaf or item cap). An admitted history plus the
wallet's own well-formed burn is therefore return-valid by construction. What remains is whether the return fits the resources (next sections);
owner section 36 makes resources a matter of "direct exit unavailable", never of an admission refusal.

## Admitted shapes

Each line has a test (`packages/native-bridge-plugin/test/admitted-shapes.test.ts` unless named) that admits the held token as a receipt,
verifies the burned token as a return, and builds its return proof within the 2 MiB envelope and the 60M block capacity.

| Shape | Test | Also live |
|---|---|---|
| No transfer (minted, then burned) | `no transfer` | bft-core ci-lane combined, any-age L1 (`anyage.ts save`, SAVE_TRANSFERS unset: 0) |
| Signature transfers, any state mask | `signature transfers with any state mask` (masks 00, 01, 7f, 80, ff) | `roundtrip` (3 transfers) |
| A transfer with a deadline, certified before it | `a transfer with a deadline, certified before it` | — |
| Leaves in different rounds (one anchor per distinct certificate) | `leaves certified in different rounds` | `roundtrip` |
| Leaves in both shards of a sharded aggregation partition | `leaves in both shards of a depth-1 aggregation partition` | bft-core ci-lane combined (two aggregator shards) |
| A long history beyond the standalone kernel's 64 transfers, every leaf under its own certificate | `a long history beyond the standalone kernel bound` (100 transfers) | testnet-bridge `long-history` (250); ci-lane long history |
| Anchors under a later epoch, after rotations (refreshed) | `rotation-refresh.test.ts`, `retired-key.test.ts` (control) | — |
| Anchors under a historical committee, inside its closed interval | `lockproof.test.ts` (historical committee), `trust.test.ts` | ci-lane any-age `--epoch historical` |
| A consolidated bundle (one seal for every leaf) | `aggregator.test.ts`, `readiness.test.ts` | testnet-bridge `consolidated` |
| A split part, any depth (protocol 6 lineage) | `splitpart.test.ts`, `split.test.ts` (sealed `split/` corpus) | testnet-bridge `split` (depth 2) |

## Refused shapes

Refused at admission (receipt) and on return, offline, with the named reason. Both plug-ins replay the sealed corpus, so a corpus case is a test
of both.

| Shape | Reason | Test or corpus |
|---|---|---|
| A time, custom or any non-signature, non-burn predicate | `ErrPredicate` | corpus `history`, `wire`, `split/mutation` |
| Data on a non-terminal transfer | `ErrTransferData` | `verification.test.ts` |
| A burn that is not the last transaction (a transfer after a burn) | `ErrBurnNotFinal` | `verification.test.ts` |
| A burn where a receipt is expected / a return without a burn | `ErrUnexpectedBurn` / `ErrNotBurn` | `verification.test.ts`, `readiness.test.ts`, `wallet.test.ts` |
| A return with no transfer at all (the mint is not a burn) | `ErrNoTransfers` | `verification.test.ts`, corpus |
| A mint of another network or with a non-signature first owner | `ErrMintShape` | corpus `history`, `split/lineage`, `split/native` |
| Another token type claiming the asset | `ErrMintType` | `verification.test.ts` |
| A foreign mint or an unknown mint reason (no lock, no split justification) | `ErrMintJustif`, `ErrIssuanceReason` | `verification.test.ts`, `wallet.test.ts`, `splitpart.test.ts` |
| A transfer certified at or after its deadline | `ErrDeadlineExpired` | `verification.test.ts` |
| A state certified twice in one history | `ErrRepeatedSID` | corpus `split/lineage`, `split/native` |
| A leaf time later than its certificate | `ErrReferenceTimeFuture` | `verification.test.ts`, `splitpart.test.ts` |
| A certificate of another partition, or a shard that does not cover the leaf | `ErrNotAdmitted`, `ErrShardMismatch` | `aggregator.test.ts`, `resources.test.ts` |
| A seal outside its epoch's interval (including a retired committee's) / by keys of no current member | `ErrSealEpoch` / `ErrQuorumNotMet` | `retired-key.test.ts`, `tests/retired_key.rs`, `lockproof.test.ts` |
| A bad return reason, amount or recipient | `ErrReturnData`, `ErrReturnAmount`, `ErrReturnRecip` | `verification.test.ts`, `splitpart.test.ts` |
| A split parent returned instead of its part | `ErrNoTransfers` (the plug-in's and the composition's verdict, as recorded live) | `splitpart.test.ts`; testnet-bridge `split` negatives |
| Non-canonical or forbidden CBOR, a certificate outside the SDK-decodable subset | `ErrNonCanonical`, `ErrForbiddenCBOR`, `ErrCertStructure` | corpus `wire`; `lockproof.test.ts` |
| A token above 2 MiB | `ErrInputTooLarge` | `limits.test.ts`, `primitives.test.ts` |

Merges, partial returns (return a whole part: split first), and recursive tokens other than the split justification have no encoding in the
profile: they fail as one of the shape errors above (interop "Whole-token history and return").

## Resource limits: where an admitted history has no direct exit

Admission caps only the token's bytes (2 MiB). A return is bounded by the 2 MiB direct envelope and by its gas, which must fit the
deployment's ordinary block capacity (60M, D3; recorded in bft-core's `bridge-release.json`). Measured with `test/measure-shapes.ts`
(the plug-in's own envelope and gas estimate; the fixture tree holds the token's leaves only, so live paths are longer and these are lower
bounds):

| Bundle | Transfers | Token bytes | Envelope bytes | Gas estimate |
|---|---|---|---|---|
| Every leaf under its own certificate (original proofs) | 800 | 681,726 | 1,169,952 | 57,620,180 |
| | 850 | 724,126 | 1,242,752 | 61,137,580 (over 60M) |
| | 900 | 766,526 | 1,315,552 | 64,654,980 (over 60M) |
| One certificate for every leaf | 900 | 1,061,564 | 686,752 | 30,727,940 |
| | 1,700 | 2,049,500 | 1,341,088 | 58,117,988 |
| | 1,900 | refused at admission (`ErrInputTooLarge`) | — | — |

So:

- **Original proofs**: a history redeemed with the proofs it was certified with, every leaf in its own round, runs out of block gas at about
  830 transfers.
- **A fresh bundle**: the wallet's redemption re-fetches every leaf's proof (`readiness.ts`, each attempt) or consolidates, so the leaves come
  under the few seals of the fetch, not one each. With one seal, the return fits up to the admission cap (1,700 transfers: 58.1M). The margin
  there is small, and longer live paths add bytes and gas per leaf, so a token near the 2 MiB cap may still exceed the block. That is
  "direct exit unavailable" (owner section 36), not an invalid token; nothing is refused at admission for it.
- **Consolidation on a single aggregator** stops at 254 transfers (the SDK's 256 state IDs per endpoint batch; bft-core testnet-bridge
  2026-10-23). Above it the wallet uses the per-SID fetch, which is the fresh bundle above.

Not covered here: a live redemption above 250 transfers on the package, and the live path depth. Raising the consolidation batch is upstream
SDK work (owner decision).
