# Native bridge v2: the redeem gas estimate

The wallet preflight (`planReturn`, spec section 12.5) must know, before the irreversible burn, that the redeem will fit `userGasLimit`.
If the figure is too low, the wallet burns a part the chain then cannot redeem, and the value is stuck until bft-core#1108. This document
describes the figure both plug-ins use (`MeasuredGasModel`, model name `estimate-nb2-1179`; `packages/native-bridge-plugin/src/nb2/gas.ts`
`REDEEM_GAS` and `crates/native-bridge-sdk-ext/src/nb2/gas.rs` `redeem_gas`), how its constants were measured, and how far it can be
trusted.

**It is a measured conservative estimate, not a proven universal bound** (owner decision, 2026-11-18). Its structure follows the deployed
code: every loop of the verifier, its helper and the vault is counted from the token itself, and the native schedules are charged as the
chain charges them. But most per-unit prices are measured, not derived instruction by instruction. They are raised above every
measurement, and an explicit safety margin of 1/32 of the measured terms is added on top. The terms derived from the code and the terms
measured are listed in [What is derived and what is measured](#what-is-derived-and-what-is-measured).

It replaced `measured-nb2-05` (bft-core#1179). That model charged a fixed price per transfer and 136 gas per byte beyond a measured
shape. It overestimated real gas by 1.55 to 1.63 times and did not price distinct certificates, so it refused returns at about 205
transfers that the chain pays at about 310.

- [The estimate](#the-estimate)
- [What is derived and what is measured](#what-is-derived-and-what-is-measured)
- [Where it applies](#where-it-applies)
- [Calibration](#calibration)
- [Validation against the chain](#validation-against-the-chain)
- [Margin](#margin)
- [Limits](#limits)

## The estimate

```
limit = transaction + vault + batch + membership + sha256 + execution + memory + forwarding + safety + gasReserve
```

| Term | What it charges | How |
|---|---|---|
| transaction | 21,000 + every calldata byte | 16 per byte, every byte priced as nonzero |
| vault | `NB2VaultBase`'s replay, checks and payout | its worst measured call over every phase, for a never-used recipient: 530,000 (below); 6,000 per historical segment; its copy of the evidence into the verifier call (3 a word and the vault frame's memory expansion) |
| batch | CERT_BATCH_V2 (`0x0100`) | the ureth schedule exactly, `60,000 + 16C + 500k(k-1) + 1,100 + 29,900E + 7,200Q + 2,000A + 250P`, over the distinct claims in the verifier's own batching (`_flush`: balanced calls of at most 16 claims and 256 KiB) |
| membership | the RSMT membership (`0x0102`) | the schedule exactly, `2,000 + 16 x request bytes + 250 (1 + siblings)`, per inclusion proof |
| sha256 | SHA-256 (`0x02`) of every hashed transaction | `60 + 12` a word, exactly. A child's mint contains its parent token, so nesting is counted where it costs |
| execution | the verifier's and its helper's own execution | each loop's iterations counted from the token, priced per iteration (table below) |
| memory | the verifier frame's memory expansion | `3M + M²/512` (the Yellow Paper's `C_mem`) over an estimate `M` of its high-water, in words |
| forwarding | EIP-150 | the vault keeps 1/64 of what it forwards to the verifier, the verifier 1/64 of its largest call: the largest of its batch calls, its helper calls (one a UC, the pending burn's included) and J's receipt call |
| safety | the explicit safety margin | 1/32 of the measured terms (execution, memory, vault), about 3% |
| gasReserve | the pinned reserve | 500,000 |

**What it counts.** It counts everything in the token itself: every proof's UC, path and transaction; distinct claims by digest; the
key cache, the state-ID set and the claim set, replayed on the token's own keys, state IDs and claims; split edges and allocation
steps; every CBOR item each of the verifier's walks visits; every RLP item and head of the root's receipt. Two cases are estimated at
bounds instead of counted:

- **The pending burn** of a preflight is counted at the decoder bounds. Its UC is 24 KiB with 16 signatures of 128-byte non-ASCII
  node IDs, 256 shard tree siblings, 32 unicity tree steps and a 448-byte input record. Its path has 256 RSMT siblings. Its claim is
  new, in a new epoch. At an unknown claim digest it probes every occupied slot. Its CBOR items are priced as the dearest form. On the
  K = 4 lane this costs about 3.4M gas (the envelope's `preBurnBurnBound`). Its seal's keys are counted as sharing all but their last
  word.
- **Inputs it cannot read.** A UC that does not parse, or one with more than 16 signatures, gives null. The preflight reports that as
  `CapacityPreflight` (fail closed).

**The CBOR walks** (round 2). The verifier reads the evidence with two walks of `Nb2Cbor`: `scan` (the strict check, and the loose one
for data fields) and `skip` (an item's end). From the code, each walk visits:

- `scan`: the evidence `[1, part]` once (`_evidence`); every split justification once, and so every parent token once
  (`_splitJustification`); J once (`_rootMint`); every transaction's data field at most once (`_mintAmount`, `_returnData`, `_splitBurn`);
- `skip`: every parent token once more (`_splitJustification`'s `skip(k0)`); every token's genesis `[mint, proof]` (`_token`'s
  `skip(g)`), so the mint's UC; every proof's UC (`_proof`); every predicate's three fields (`_pred`).

A byte string's content is walked only by the check that opens it. So an item of a UC in the part is scanned once and skipped once; an
item of a token above a split is scanned once and skipped twice; an item of a parent's mint UC is skipped three times. The estimate
counts each walk's items from the bytes, as items, heads with argument bytes (`ai` 24 to 27), and nested items (a non-empty array or
map, a tag). It prices them per form, from microbenchmarks of the walks compiled under the verifier's own settings (`RefitWalk` below,
each form's marginal cost over 100 to 300 repetitions), the dearest form of each class raised 5%:

| Walk | per item | per argument head | per nested item | Measured |
|---|---:|---:|---:|---|
| scan | 410 | 230 | 185 | 348 a short byte string to 389 an integer or null; +219 the dearest argument; 474 an array, 527 a map, 503 a tag, 657 a long array, 706 a long map, 782 a long tag (each with its head) |
| skip | 260 | 90 | 0 | 173 a byte string to 249 a tag; +80 the dearest argument (329 a long tag) |

**Execution, per loop iteration** (gas; "measured" means the forge lab below):

| Unit | Gas | Source |
|---|---:|---|
| the verifier's base (one token, its J and receipt, Γ, the flush) | 159,000 | measured residual after the walks |
| inclusion proof (decode, unlock, state ID, leaf, helper call, claim, membership request) | 21,226 | measured residual after the walks, on 1 to 317 proofs |
| step of a token above the part | 0 | the walks now count what a parent costs again; the residual is covered by the per-step term (least cover over 33 split files) |
| split edge (split edge, split burn, sum proof base, one allocation step) | 16,407 | measured residual after the walks, least cover over 33 split files at 1 to 10 levels |
| allocation step | 2,000 | code (one SHA-256 of about 130 bytes and its parse) |
| CBOR walks | table above | walk sets from the code; per-form prices measured |
| hash-table probe (key cache, state IDs, claims) | 270 | measured |
| distinct claim | 0 | measured residual (the per-step term covers it: there are at most n + 1 claims for n proofs) |
| key decompression (modexp) | 2,100 | measured (`pKey` 1,955) |
| transaction word copied for hashing; RSMT sibling copied | 3; 3 | code (calldatacopy) |
| UC parsed by the helper: base | 19,100 | measured |
| a UC byte (all copies) | 7 | measured, plus 1 for the verifier's copies |
| a byte of the UC's input record | 27 | measured on real UCs |
| a seal signature; a shard tree sibling; a unicity tree step | 1,784; 1,798; 2,146 | measured on synthetic UCs; a sibling adds the verifier's `_inShard` at 250 a shard bit (measured 170 on 64- and 200-bit shards) |
| a byte of a node ID with a non-ASCII byte (the helper's byte-wise UTF-8 check) | 367 | measured per character width (round 3): `_utf8`'s slow path runs once a character, so a byte costs more the wider the character: 301 on 2-byte, 337 to 342 on 3-byte, 345 to 349 on 4-byte (U+10000, U+10FFFF); the dearest raised 5% |
| a word `_less` compares beyond the first, over the seal's consecutive keys | 320 | words counted from the keys (round 3: up to each pair's first differing word); measured 905 a compare of 128-byte keys sharing 124 bytes (3 more words), raised 5% |
| a byte of J | 10 | code (its copies and the trie nodes' and header's Keccak: at most 20 gas a word) |
| an RLP item of the header, a trie node or the receipt (`check()`) | 320, +190 in long form, +250 a list | measured per form (round 2): 182 a byte, 304 a short string, 482 a long string, 483 a short list, 541 an empty list, 618 a long list |
| a `head()` with its Item: each log up to the selected one, its topics, every child a `kids()` call walks | 1,070, +450 in long form | measured per form: at most 1,019 short and 1,371 long in `kids()`; about 1,440 for a long log in `receiptLog`'s walk |
| a `kids()` call (its array of Items) | 2,000 | code (an array of up to 20 four-word Items, zeroed) |
| cold accesses: the helper's code hash and code | 5,200 | the schedule (2 x 2,600; the lab runs warm) |

Each helper call's own memory expansion is added per UC (`C_mem` of three UC lengths). The receipt helper's frame adds the receipt walk's
allocations to its UC parse: 4 words an Item (`head()`), 1 + 5 max words a `kids()` array, the log's data and topics, the nodes'
positions, the key nibbles and header widths, and the largest node or header copied for its Keccak. The receipt is read from J for these
counts: every RLP item of the header, the trie nodes and the receipt with its form, the log index and the selected log's topics. Over 19
receipts whose preceding logs take every form (0 to 4 topics, 0 to 600 data bytes, up to 2,000 logs), the receipt walk's terms are 1.065
to 1.115 times the parser's measured gas (round 1's prices were 0.86 times it on 560 logs with 56-byte data).

**The memory estimate.** `M` follows the verifier's allocations. Solidity's allocator only grows, so the frame's high-water is its final
free pointer plus any scratch use beyond it. Every allocation is either fixed in size per proof, per token, per claim or per split edge, or
proportional to one of four byte counts: UC bytes, path bytes, claim bytes and J's bytes. From the code:

- a UC is copied three times in the verifier frame: the verifier's slice, the helper's ABI answer, and the claim decoded from it; each
  distinct claim once more, into the batch. That holds for J's EVM UC too, which `_receiptLog` slices, receives back in the answer (with
  the topics and data) and decodes as its claim, and which the batch then copies: four copies. The estimate charges the EVM UC 3.06 a word
  (it is in the UC bytes), 1.03 a claim word, and 2 a word of J (J contains the UC);
- the path is copied once, into the membership request;
- J's nodes and header are sliced, then encoded into the helper call;
- each allocation step of a split edge encodes 130 bytes.

So `M` adds:

- the verifier's hash tables, exactly: `pow2(2(n+1)) + pow2(2n) + (n+1) + 256` words for `n` proofs;
- 320 words;
- the byte-count parts, at the code's copy counts plus 2%: 3.06 a UC word, 1.21 a path word (the copy and the request's heads), 1.03 a
  claim word, and 2 a word of J;
- the fixed parts, measured, because their sizes do not depend on the data: 67.89 words a proof (its Step, Pred and encodings), 281.34 a
  token, and 6 an allocation step (`_sumVerify`'s 130-byte encoding, from the code);
- the largest scratch use that the allocations after it do not cover. A transaction is hashed from a copy at the free pointer, and every
  later proof allocates at least two copies of its UC over that copy.

**The vault** (round 2). The constant is now measured on `NB2VaultBase` itself at unicity-pos-contracts `884c4829`, not on the NB2-02
bake-off's generated vaults: the deployed runtime (the artifact deploy_nb2.py creates, its immutables from Γ), with the stateless echo
verifier, each redeem a cold transaction (`RefitVault`). Over segments 0, 1 and the steady state, for the production pair and the four test
pairs, the worst call is the previous endpoint at m = K-1 with every identifier in one bucket in sort-adversarial order, then the seal:
500,347 to an existing recipient and 525,551 to a never-used one (G_newaccount, 25,000), at K = 64, segment 1. The test pairs' worst is
159,062. The constant is 530,000. It still contains the transaction's intrinsic gas and the echo call, which the transaction and verifier
terms charge again. A historical segment costs 5,898 at K = 64 with its calldata (P = 64); the estimate charges 6,000 and the calldata.

## What is derived and what is measured

**Derived from the code or the schedule, exact or above:**

- transaction: 21,000 and 16 per calldata byte, above Cancun's 4/16 (on a fork with EIP-7623's floor the standard cost is still the larger:
  the verifier's execution is about 90 gas an evidence byte on every measured token);
- batch, membership, sha256: ureth's and Cancun's schedules over the code's own dimensions (distinct claims by digest, balanced calls);
- forwarding: EIP-150 over the code's call tree, rounded up at both levels;
- every count: proofs, siblings, transaction words, UC structure (signatures, shard tree siblings, unicity tree steps, input-record bytes,
  non-ASCII node-ID bytes), distinct claims, split edges and allocation steps, the hash-table probes replayed on the token's own keys,
  state IDs and claims, which CBOR items each walk visits and how often, every RLP item and head of the receipt, every `kids()` call;
- memory: the hash tables exactly; the copy counts of every data-proportional allocation; `C_mem` itself;
- the per-word copy and hash prices (3 a copied word, 10 a byte of J, 2,000 an allocation step, 2,000 a `kids()` array, 5,200 cold access).

**Measured, then raised:**

- the per-form prices of the CBOR walks and of the RLP walk (microbenchmarks of the deployed libraries under the verifier's compiler
  settings, raised 5%);
- the helper's prices per UC structure (least squares on real and synthetic UCs, raised 5%, intercept to the largest residual);
- the verifier's residual execution per proof, per split edge, per probe, and its base (least squares after the walks, raised 2% and 5%,
  intercept to the largest residual);
- the fixed parts of memory per proof and per token (raised 2%);
- the vault's worst call.

A measured price covers the shapes the lab measured and the forms between them; it is not an instruction-by-instruction worst case of
every branch. That is why the estimate adds the safety margin, why it applies to one deployment only (below), and why the lab and the
shared vectors keep the review's counterexamples as regressions.

## Where it applies

The constants are those of one deployment. The bridge reads, once, the verifier's runtime code (its hash checked against Γ), the vault's
(its hash checked against the manifest), and the code at the verifier's first CREATE address, where its constructor deploys the receipt
helper. The default estimate applies only when (`calibratedDeployment`):

- the verifier's runtime is the calibrated artifact (19,574 bytes, `CALIBRATED_DEPLOYMENT`) with **every occurrence** of each immutable
  holding the value this deployment must have: `admitsTestSet` unless (K, B) is the production pair; `RECEIPTS`, the verifier's first
  CREATE address; `RECEIPTS_CODEHASH`, the calibrated helper's code hash. The expected runtime is rebuilt from those values and compared
  in full, so an occurrence changed alone (the review's case: one helper-address use) is refused;
- the code at that address has the calibrated helper's hash, so the address the verifier calls is the one whose code was checked;
- the vault's runtime is the calibrated `NB2VaultBase` artifact (both builds share it) with every immutable derived from Γ: `D = H_U(Γ)`,
  the verifier, `Qmax`, `K`, `log2 K`, `log2 B` and Γ's length and twelve words;
- the manifest pins `nativeGasSchedule`, naming the native schedules the estimate assumes (`NATIVE_GAS_SCHEDULE`: CERT_BATCH_V2, the RSMT
  membership and SHA-256 with their coefficients). It is a declared pin: `release_nb2.py` restates it as a literal for the ureth it
  pins; neither the release nor the plug-in derives it from ureth or probes the chain, so the check proves only that the release was
  written for this estimate.

For any other deployment the default estimate is refused before the burn (`CapacityPreflight`). A wallet that supplies its own model is
responsible for it. The payout is to an account without code; a contract recipient's own execution is not estimated (the wallet warns
about a contract recipient).

## Calibration

Everything was measured on throwaway K = 4 generations, `tn-nb2-refit`, on the dev server, running the bft `02eaa34c` node images and
contracts `884c4829`, the release whose verifier is deployed.

- **The forge lab** runs the deployed verifier's bytecode on real evidence files, with constant stubs at `0x0100` and `0x0102`, whose
  schedules are then added exactly. It records the verifier's gas, its free pointer and its memory high-water. It covers 214 files:
  - 44 from the consolidation measurement (raw, consolidated before and after the burn, trimmed seals);
  - 92 from the lane: 1 to 315 transfers in 16 certificate groups; one batch; consolidated; a certificate per transfer; 151 and 261
    fresh owner keys; trimmed; 1, 2, 3, 6 and 10 split levels; small returns;
  - 10 synthetic part tokens (16 signatures; 128-byte ASCII or non-ASCII node IDs; 64- and 200-bit shards; 32 unicity tree steps; 24 KiB
    seals; everything at once);
  - 30 from the round-2 review: lane tokens at 1 to 7 split levels with every UC above the part rebuilt (4 or 16 signatures, 8, 16, 24 or
    32 unicity tree steps) and each child mint re-signed, and lane tokens with smaller UCs in the part;
  - 38 from the round-3 review: node IDs of 2-, 3- and 4-byte UTF-8 characters at their branch edges, with and without a 124-byte shared
    key prefix, in the part and above 1 to 10 split levels, and further variants above the splits (1 or 16 signatures, 0 or 32 steps, 200
    shard tree siblings, 1,400-byte signatures, everything at once).
- **The walk microbenchmarks** (`RefitWalk`): each CBOR form under `scan` (strict and loose) and `skip`, each RLP form under `check()` and
  `kids()`, compiled in `src/nb2/verifier` so that they take the verifier's settings (via-IR, optimizer runs 1).
- **The receipt parser** (`RefitRcpt`) on 31 receipts, short and long forms.
- **The helper's `certificate()`** on real UCs and on synthetic ones varying one structure at a time.
- **The vault** (`RefitVault`) as above.
- **The chain.** Every lane token was burned, and each burn measured by `eth_estimateGas` of its redeem at 0 to 17 historical segments;
  9 were paid live.

**How the constants are fitted.** The walks are subtracted from the lab's gas at each form's measured cost first. Each remaining part
(the helper, the memory, the unsplit execution) is a least-squares fit on the features its loops run over, every per-unit coefficient
raised (5% for the helper and the split terms, 2% for unsplit execution and memory) and the intercept raised to the largest residual. The
split terms are the least pair (per parent step, per edge) that covers every split file over the unsplit execution, raised by 5%.

On all 214 lab files the estimate's execution, memory and SHA-256 terms, without the safety margin, are 1.064 to 1.55 times the lab's
measured gas. The round-3 UTF-8 shapes, which round 2 underestimated by up to 5.8% (2.8% after the margin), are now 1.065 (U+10FFFF IDs)
to 1.095 times it; U+10000 IDs sharing a 124-byte prefix are 1.079. The review's counterexamples, which round 1 underestimated by up to 1.03M gas (3.7%), are now 1.097 to 1.140 times it:

| File | Lab gas | Estimate (exec + mem + sha) | Ratio | Round 1 |
|---|---:|---:|---:|---:|
| p-e2n-u32 (2 levels, 32 unicity tree steps above) | 59,027,168 | 64,896,534 | 1.099 | −1,031,376 |
| q-e3n-u32 | 40,429,940 | 45,906,263 | 1.135 | −625,550 |
| q-e5n-s16u8 (16 signatures, 8 steps) | 10,614,462 | 12,017,302 | 1.132 | −63,826 |
| q-e5n-u32 | 12,966,140 | 14,691,795 | 1.133 | −402,555 |
| q-e7n-s16u8 | 8,510,081 | 9,652,761 | 1.134 | −31,777 |
| q-e7n-u32 | 10,473,683 | 11,898,259 | 1.136 | −384,938 |

**Historical vectors.** `tests/nb2-gas/gas-vectors.json` records the measured protocol 9 build. The protocol 10 suites check flat evidence accounting with the independent T1 corpus. The deployed-artifact check gates the old bound to configuration version 1.
Six are lane tokens (1 and 10 transfers, 3 and 10 split levels, 151 fresh keys, trimmed seals); four are the synthetic part tokens (a
200-bit shard, 16 signatures with non-ASCII IDs, 16 signatures, 24 KiB seals over the batch's byte cap); four are the review's
counterexamples above the splits (2, 3 and 7 levels with 32 unicity tree steps, 5 levels with 16 signatures and 8 steps); one is the
round-3 review's 4-byte UTF-8 node IDs sharing a 124-byte prefix; two are receipts
(a deposit after 2,000 logs, and after 560 long-form logs with 56-byte data); two must fail closed (17 signatures, a non-text signature
key). Each is checked at redemption (P 0 and 17 at K = 4, P 17 at K = 64) and at the preflight (K = 4 and 64). The 15 that the lab
measured carry their lab gas, and both suites check that the estimate's execution, memory and SHA-256 terms are at or above it.

The scripts and the raw data are in `~/evidence/nb2-gas-refit/` on the dev server (`lab/`, `r2/lab/`: `fit4.py`, `features.jsonl`,
`labcheck.py`, `validate-r2.jsonl`, the walk, receipt and vault logs).

## Validation against the chain

Below, the estimate at redemption is without `gasReserve`. The real gas is `eth_estimateGas` of the redeem at that P (the deployed contracts
did not change, so round 1's measurements stand). The preflight is the limit `planReturn` computes on the part before its burn (the burn
at its bounds, P + 64 proofs, `gasReserve` included). Its verdict is against `userGasLimit` = 60M.

| Part | Transfers | Split levels | Certificates | P | Real | Estimate | Estimate / real | Preflight | Paid gasUsed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| a50, raw | 51 | 0 | 18 | 0 | 9,585,385 | 10,891,386 | 1.136 | 15,353,158 | |
| a100, raw | 101 | 0 | 26 | 0 | 18,351,112 | 20,363,456 | 1.110 | 24,955,069 | 18,082,571 (P 17) |
| a200, raw | 201 | 0 | 35 | 0 | 36,627,443 | 40,119,573 | 1.095 | 44,974,790 | |
| a280, raw | 281 | 0 | 39 | 0 | 52,358,159 | 57,120,161 | 1.091 | 62,191,330 (refused) | |
| a300, raw | 301 | 0 | 41 | 0 | 56,521,474 | 61,628,677 | 1.090 | 66,755,500 (refused) | 55,673,867 |
| b150k, consolidated | 151 | 0 | 2 | 0 | 25,811,210 | 28,504,443 | 1.104 | 33,216,253 | |
| b300k, consolidated | 301 | 0 | 2 | 0 | 53,605,886 | 58,585,137 | 1.093 | 63,681,678 (refused) | 52,801,263 |
| g250kt, consolidated and trimmed | 251 | 0 | 2 | 0 | 42,094,024 | 46,055,235 | 1.094 | 50,972,639 | 41,474,902 |
| k260, fresh keys | 261 | 0 | 39 | 0 | 59,401,954 | 64,425,856 | 1.085 | 69,453,788 (refused) | 58,506,740 |
| e1n | 152 | 1 | 21 | 0 | 28,892,312 | 32,023,257 | 1.108 | 36,756,820 | |
| e2n | 282 | 1 | 34 | 0 | 55,086,126 | 60,503,591 | 1.098 | 65,581,552 (refused) | |
| e3n | 153 | 2 | 24 | 0 | 30,631,535 | 34,470,363 | 1.125 | 39,029,701 | |
| e4n | 283 | 2 | 36 | 16 | 57,530,188 | 64,484,894 | 1.121 | 69,259,929 (refused) | 56,628,979 |
| e7n | 21 | 10 | 32 | 0 | 9,039,639 | 10,407,370 | 1.151 | 14,794,776 | 8,914,393 |

Over all 87 measurements (21 burns at P = 0 to 17, `validate-r2.jsonl`):

- the estimate at redemption is 1.085 to 1.69 times the real gas: about 1.09 at 250 to 300 transfers, and more for small tokens, where the
  vault's K = 64 worst call dominates;
- the preflight is 1.16 to 5.3 times the real gas;
- no measurement lies above its estimate.

**The live boundary** (the lane's `boundary` stage, bft-core#1179). It used fresh tokens in 16 certificate groups at the pinned limits and
executed every probe as it was judged: each admitted one burned and paid, each refused one refused again and shown unspent by the ledger.

- Round 1, on a tree grown by several thousand earlier transfers: admitted 282, refused 284. After the first reviews: 294 / 295, then
  286 / 288 on a fresh generation.
- Round 2 (this estimate, nbp `36e6fa16`), on a fresh generation: admitted 268 and refused 270. The ones admitted at 264 and 268 transfers
  (preflight 57.5M and 59.6M) were burned and paid, using 47,234,911 and 49,176,865 gas. The ones refused at 270, 273 and 279 were over
  `userGasLimit` by their own estimate (60.4M to 61.4M), were refused again and shown unspent.

Round 3's prices (UTF-8 widths, key compares) do not change these lane tokens at redemption (their node IDs are ASCII and differ within
a compare's first word); they add about 0.13M to the preflight's pending burn, so the admitted 268 (59.57M) stays under 60M and the boundary
does not move.

The boundary moved down from round 1's 286 because the estimate now prices the walks per item form, the vault for a fresh recipient, and
the safety margin.

The old model admitted about 205.

## Margin

The margin has four parts:

1. **Above the real gas, at redemption: about 9% at the boundary.** The per-form walk prices, the residual fits' raised coefficients and
   intercepts, and the vault's worst call to a fresh recipient.
2. **The safety margin: 1/32 of the measured terms, about 1.4M gas at the boundary.** It covers what the measurements may miss: shapes
   between and beyond the measured ones, branch combinations the microbenchmarks did not take, and the 1.5% tolerance of the node's
   `eth_estimateGas`.
3. **The pending burn at its bounds: about 3.4M gas, about 16 transfers at the boundary.** This keeps the preflight conservative before the
   burn exists. The burn's own UC, path and claim are unknown until it is certified, and its UC can come from a later epoch with more
   signatures.
4. **The reserve: 64 segments and `gasReserve`.** The preflight charges 64 segments beyond those already owed (about 8,100 gas each at
   K = 4, 10,100 at K = 64), plus the 500,000 reserve.

**The burn-to-redeem window.**

- Once the burn is certified, the evidence is fixed. The tree's growth and the boundary's drift (about 991 bytes a probe in the
  consolidation measurement) change which new tokens are admitted, not the gas of a burned part.
- What does change after the burn is P: every segment sealed while the burn waits adds one gap proof. The 64-segment reserve covers that.
- At redemption the wallet re-reads the chain, builds the history and simulates (`buildRedeem`). The preflight runs again in `burn()`
  right before the burn is signed, on fresh chain state. A plan made earlier is never reused.

## Limits

- **It is an estimate.** Its prices are measured and raised, with a safety margin; it is not a proof that every admissible token costs
  less. A token far outside the measured shapes (for instance many more items per proof than any lab file) is covered only as far as the
  per-form prices and the safety margin reach.
- **The constants are those of the deployed contracts** (`884c4829`, solc 0.8.37, via-IR, the verifier at `optimizer_runs = 1`) and of
  the named native schedules. The calibrated artifacts are those of a full-project build, `forge build` at the repository root of
  unicity-pos-contracts `884c4829`, as the bridge image builds them (19,574-byte verifier). Solc's via-IR output depends on the compile
  unit: `forge build src/nb2` alone gives an 18,886-byte verifier from the same sources and settings, which the gate refuses. The bridge enforces both (above). A new build or a repricing needs a new calibration and a new
  `CALIBRATED_DEPLOYMENT` or `NATIVE_GAS_SCHEDULE`.
- **The native schedules are ureth `unicity/main` at `7f625ea`** (`crates/unicity/b1` batch.rs and rsmt.rs). There, a registry word read
  is `READ_GAS` = 100, which ureth marks as provisional. The manifest's `nativeGasSchedule` is a declared pin, the release's statement of
  the chain's schedule; the plug-in does not probe the chain for it.
- **Shapes the lane cannot produce** are covered by the per-unit prices, measured on synthetic UCs: shard tree siblings, more unicity tree
  steps, more signatures, long or non-ASCII node IDs (2-, 3- and 4-byte characters, keys sharing long prefixes) and long summaries, above
  and below the splits. J's per-byte cost is from the code. A root chain whose node IDs are libp2p peer IDs produces ASCII IDs only.
- **The vault term is K = 64's worst call,** which is above every test-pair call. K = 128 or larger would need its own vault measurement.
- **The receipt walk's fixed part** (a receipt with no other logs) is about 250 gas above its terms; the verifier's base covers it.
- **The replayed probe and decompression counts** are checked against the verifier's code and through the lab's totals, not against the
  verifier's own counters.
- **A zero state ID** (the tables' sentinel) has no known preimage. Both plug-ins handle it as the verifier does, but no vector reaches it.

When the deployment is outside the measured artifacts, deposit estimates the actual sender, vault, calldata and
value with `eth_estimateGas`. It adds a 20% margin and checks the wallet gas limit before signing. A wallet-supplied
model can provide a deposit bound for its active deployment.

## ERC20 continuation admission

For the ERC20 release, the signing policy admits at most 16 operations in Start and eight in Resume. It retains 32 pages per Run, the 65,536-byte predecessor receipt cap, and at most 1,024 gaps per call. The 393,216-byte calldata ceiling, 524,288-byte signed Type 2 envelope ceiling, and 24,000,000 submitted gas ceiling apply alongside tighter chain, node and payer limits. The eight-operation cap is an admission policy. The continuation wire still allows 16 operations in Resume.

The SDK schedules all cuts before signing. Future predecessor receipts are priced up to the full receipt cap and sparse openings at their maximum width, including the hypothetical terminal burn pair at its decoder cap. The deployment's calibrated execution ranges must cover those shapes, including the ERC20 call caps and worst combination of scan and seal at settlement. The conservative gas quote retains 16 gas per calldata byte, the 20% execution margin, and the recovered settlement seal reserve.

The reserve uses `D = max(0, observed - signedStart) + 64 + duringProgress` and `N = ceil(D / (q - advancePeakSeals))`. The batch must clear more gaps than can arrive before its next usable proof, sustain twice peak seal throughput at the measured p99, and leave at most one arrival during final inclusion. The fee ceiling covers the Run window, `N` upper-bound advance windows, and final inclusion. `duringProgress` covers burn and Run certification, any qualified restore delay and any allowed ordinary attempts before fallback.

The reference wallet reads `signingWindows.progressWindowMs`, `signingWindows.maxRunCalls`, `signingWindows.advanceWindowMs`, and, when offering ordinary settlement, `signingWindows.ordinaryInclusionMs` from the release's recovery section. The qualified Run limit covers the burn, sequential Run proofs, covered restores and any pre-fallback attempts. The payer policy supplies `feeWindowMs` over which `maxFeePerGas` covers base fee and tip. It also supplies `ordinaryAttemptsBeforeFallback` when offering ordinary settlement.

Both SDKs price the ERC20 signed envelope at the declared nonce and fee ceilings. An ordinary call outside the per-call payer limits leaves the continuation route available. At signing the SDK checks the greater route plus the capped fees for ordinary attempts against the spendable balance and authorized budget, and checks nonce capacity for the full schedule. A payer with an outstanding return can spend its reserve on that return. During a Run replay, observed seals consume the arrival allowance already included at signing.
