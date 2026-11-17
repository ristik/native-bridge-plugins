# Native bridge v2: the redeem gas bound

The wallet preflight (`planReturn`, spec section 12.5) must know, before the irreversible burn, that the redeem will fit `userGasLimit`.
If the bound is too low, the wallet burns a part the chain then cannot redeem, and the value is stuck until bft-core#1108. So the bound
must be an **upper bound** of the redeem's gas for every admissible token, not a fit to its length. This document describes the bound
both plug-ins use (`MeasuredGasModel`, model name `bound-nb2-1179`; `packages/native-bridge-plugin/src/nb2/gas.ts` `REDEEM_GAS` and
`crates/native-bridge-sdk-ext/src/nb2/gas.rs` `redeem_gas`), how its constants were measured, and why it is an upper bound.

It replaced `measured-nb2-05` (bft-core#1179). That model charged a fixed price per transfer and 136 gas per byte beyond a measured
shape. It overestimated real gas by 1.55 to 1.63 times and did not price distinct certificates, so it refused returns at about 205
transfers that the chain pays at about 310.

- [The bound](#the-bound)
- [Why it is an upper bound](#why-it-is-an-upper-bound)
- [Calibration](#calibration)
- [Validation against the chain](#validation-against-the-chain)
- [Margin](#margin)
- [Limits of the argument](#limits-of-the-argument)

## The bound

```
limit = transaction + vault + batch + membership + sha256 + execution + memory + forwarding + gasReserve
```

| Term | What it charges | How |
|---|---|---|
| transaction | 21,000 + every calldata byte | 16 per byte, every byte priced as nonzero |
| vault | the vault's replay, checks and payout | its worst measured call over every phase (unicity-pos-contracts#80 `bench/nb2/RESULTS.md`, K = 64, B = 16: the first-generation segment 1's previous endpoint, one bucket, sealing: 507,215), 6,000 per historical segment, and its copy of the evidence into the verifier call (3 a word and the vault frame's memory expansion) |
| batch | CERT_BATCH_V2 (`0x0100`) | the ureth schedule exactly, `60,000 + 16C + 500k(k-1) + 1,100 + 29,900E + 7,200Q + 2,000A + 250P`, over the distinct claims in the verifier's own batching (`_flush`: balanced calls of at most 16 claims and 256 KiB) |
| membership | the RSMT membership (`0x0102`) | the schedule exactly, `2,000 + 16 x request bytes + 250 (1 + siblings)`, per inclusion proof |
| sha256 | SHA-256 (`0x02`) of every hashed transaction | `60 + 12` a word, exactly. A child's mint contains its parent token, so nesting is counted where it costs |
| execution | the verifier's and its helper's own execution | each loop priced per iteration (table below) |
| memory | the verifier frame's memory expansion | `3M + M²/512` (the Yellow Paper's `C_mem`) over a bound `M` of its high-water, in words |
| forwarding | EIP-150 | the vault keeps 1/64 of what it forwards to the verifier, the verifier 1/64 of its largest call: the largest of its batch calls, its helper calls (one a UC, the pending burn's included) and J's receipt call |
| gasReserve | the pinned reserve | 500,000 |

**What it counts.** It counts everything in the token itself: every proof's UC, path and transaction; distinct claims by digest; the
key cache, the state-ID set and the claim set, replayed on the token's own keys, state IDs and claims; split edges and allocation
steps; CBOR items, from the bytes; the root's J. Two cases are bounded instead of counted:

- **The pending burn** of a preflight is counted at the decoder bounds. Its UC is 24 KiB with 16 signatures of 128-byte non-ASCII
  node IDs, 256 shard tree siblings, 32 unicity tree steps and a 448-byte input record. Its path has 256 RSMT siblings. Its claim is
  new, in a new epoch. At an unknown claim digest it probes every occupied slot. On the K = 4 lane this costs about 3.0M gas.
- **Inputs it cannot read.** A UC that does not parse, or one with more than 16 signatures, gives null. The preflight reports that as
  `CapacityPreflight` (fail closed).

**Execution, per loop iteration** (gas; "measured" means the forge lab below):

| Unit | Gas | Source |
|---|---:|---|
| the verifier's base (one token, its J and receipt, Γ, the flush) | 158,000 | measured; J's bytes charged separately |
| inclusion proof (decode, unlock, state ID, leaf, helper call, claim, membership request) | 16,851 | measured |
| step of a token above the part (the walk's decode of each parent) | 15,435 | measured on 1 to 10 split levels |
| split edge (split edge, split burn, sum proof base, one allocation step) | 57,149 | measured |
| allocation step | 2,000 | code (one SHA-256 of about 130 bytes and its parse) |
| CBOR item scanned (the evidence once, every split justification and J once) | 757 | measured |
| hash-table probe (key cache, state IDs, claims) | 271 | measured |
| distinct claim (its digest, copy and batch) | 1,039 | measured |
| key decompression (modexp) | 2,100 | measured (`pKey` 1,955) |
| transaction word copied for hashing; RSMT sibling copied | 3; 3 | code (calldatacopy) |
| UC parsed by the helper: base | 19,100 | measured |
| a UC byte (all copies) | 7 | measured, plus 1 for the verifier's copies |
| a byte of the UC's input record | 27 | measured on real UCs |
| a seal signature; a shard tree sibling; a unicity tree step | 1,784; 1,798; 2,146 | measured on synthetic UCs; a sibling adds the verifier's `_inShard` at 250 a shard bit (measured 170 on 64- and 200-bit shards) |
| a byte of a node ID with a non-ASCII byte (the helper's byte-wise UTF-8 check) | 315 | measured |
| a byte of J | 10 | code (its copies and the trie nodes' and header's Keccak: at most 20 gas a word) |
| an RLP item of the header, a trie node or the receipt (`check()`) | 450 | measured at most 408 (lists of up to 5,000 items) |
| a `head()` with its Item: each log up to the selected one, its topics, every child a `kids()` call walks | 1,100 | measured at most 1,040 (receipts with up to 2,000 preceding logs) |
| a `kids()` call (its array of Items) | 2,000 | code (an array of up to 20 four-word Items, zeroed) |
| cold accesses: the helper's code hash and code | 5,200 | the schedule (2 x 2,600; the lab runs warm) |

Each helper call's own memory expansion is added per UC (`C_mem` of three UC lengths). The receipt helper's frame adds the receipt walk's
allocations to its UC parse: 4 words an Item (`head()`), 1 + 5 max words a `kids()` array, the log's data and topics, the nodes'
positions, the key nibbles and header widths, and the largest node or header copied for its Keccak. The receipt is read from J for these
counts: every RLP item of the header, the trie nodes and the receipt, the log index and the selected log's topics. A deposit after 2,000
logs (the review's receipt) is a shared vector.

**The memory bound.** `M` follows the verifier's allocations. Solidity's allocator only grows, so the frame's high-water is its final free
pointer plus any scratch use beyond it. Every allocation is either fixed in size per proof, per token, per claim or per split edge, or
proportional to one of four byte counts. The four are UC bytes, path bytes, claim bytes and J's bytes. Per proof, a UC is copied three
times: the verifier's slice, the ABI answer and the claim decoded from it. The path is copied once, into the membership request. Each
distinct claim is copied once, into the batch. J's nodes, UC and header are sliced, then encoded into the helper call. Each allocation
step of a split edge encodes 130 bytes. So `M` adds:

- the verifier's hash tables, exactly: `pow2(2(n+1)) + pow2(2n) + (n+1) + 256` words for `n` proofs;
- 320 words;
- the byte-count parts, at the code's copy counts plus 2%: 3.06 a UC word, 1.23 a path word (the copy and the request's heads), 1.03 a
  claim word (each distinct claim plus one), and 2 a word of J;
- the fixed parts, measured, because their sizes do not depend on the data: 67.44 words a proof (its Step, Pred and encodings), 285.23 a
  token, and 6 an allocation step (`_sumVerify`'s 130-byte encoding, from the code);
- the largest scratch use that the allocations after it do not cover. A transaction is hashed from a copy at the free pointer, and every
  later proof allocates at least two copies of its UC over that copy.

## Why it is an upper bound

The redeem's gas is the sum of what the transaction charges, the vault frame, the verifier frame, its helper frames and the native
calls. Each part is bounded separately:

1. **Native schedules and calldata are exact or above.**
   - The two native primitives and SHA-256 are charged as ureth charges them, from the same dimensions.
   - The batch's epochs and signatures are counted per call over distinct claims. Claims are counted distinct by digest, so two equal
     UCs make one claim.
   - Calldata at 16 a byte is at or above Cancun's 4/16. On a fork with EIP-7623's floor (10 a token, 40 a nonzero byte) the standard
     cost is still the larger: the verifier's execution is about 90 gas an evidence byte on every measured token.
2. **Memory is the exact formula over an upper bound of the high-water.** `C_mem` is monotone, and the expansion of a frame is
   `C_mem(high-water)`.
   - The verifier frame's high-water was measured on every lab file. It was read from the free pointer after a verification, and
     cross-checked by the expansion cost of a probe above it.
   - The bound is at or above it on all 146 files. Those include ten synthetic tokens whose UCs run from 485 bytes to 24 KiB through the
     verifier frame, so the three copies of a UC that the code makes are measured at every legal UC size (3.00 words a UC word; the bound
     takes 3.06). The hash tables, which jump at powers of two, are computed exactly.
   - The scratch rule is sound because Solidity's allocator only grows: an allocation after the scratch use overwrites it from the
     same start.
3. **Execution is linear in the loop counts, priced at or above each unit's measured cost.**
   - We read the verifier, its helper and the vault for loops. Every loop iterates over an input structure: proofs, items, siblings,
     signatures, steps, node-ID bytes, allocation steps, claims, tables, and in the receipt helper RLP items, logs, topics and `kids()`
     children. The receipt's are counted from J itself, not from its byte length: a receipt of many small logs costs per item, not per
     byte.
   - The only superlinear effects are three:
     - memory, priced explicitly (2);
     - the open-addressing tables, whose probes are replayed exactly on the token's own keys, state IDs and claims (only the pending
       burn's unknown claim is bounded, at every occupied slot);
     - nested hashing, which the SHA-256 term counts byte for byte.
   - Every coefficient is the measured marginal cost of its unit, raised (below), and each intercept is raised to the largest residual.
     So the bound is at or above the lab's gas for every measured file.
   - The two accesses that the lab runs warm (the helper's code hash and its code) are charged cold, 2,600 each.
4. **The vault** is its worst measured call over the bucket, sealing and generation states (K = 64, B = 16: 507,215, the first-generation
   segment 1). It includes the transaction's intrinsic gas and its call to a stub verifier, which the transaction term and the verifier
   terms charge again. The K = 4 lane's vault is cheaper. To that we add the per-segment replay and the copy of the evidence. The payout
   is to the recipient the benchmark used, an account without code: a contract recipient's own execution is not bounded (the wallet
   warns about a contract recipient).
5. **The build.** The constants are those of one verifier build. The bound is applied only to that build. The bridge reads the
   verifier's runtime code once, checks its hash against Γ, and compares it with the calibrated build: the code with its immutables
   zeroed (`CALIBRATED_VERIFIER`, the same for the test and production builds and every deployment), and the receipt helper's code hash
   it pins. For any other verifier the default bound is refused before the burn (`CapacityPreflight`). A wallet that supplies its own
   model is responsible for it.
6. **Forwarding.** EIP-150 withholds 1/64 at each call. The bound adds 1/63 of the verifier's charge, and 1/63 of the verifier's largest
   inner call: the largest of its batch calls, its helper `certificate()` calls (at the bound of each distinct UC, the pending burn's
   at the decoder bounds included) and its `receiptLog()` call (J's EVM UC, its receipt walk, J's bytes and that frame's memory).

## Calibration

Everything was measured on a throwaway K = 4 generation, `tn-nb2-refit`, on the dev server. It ran the bft `02eaa34c` node images and
contracts `884c4829`, the release whose verifier is deployed. Two complementary measurements were made:

- **The forge lab** runs the deployed verifier's bytecode on real evidence files.
  - It uses the same compiler, settings and source (`src/nb2/verifier`), with constant stubs at `0x0100` and `0x0102`. Their
    schedules are then added exactly.
  - It records the verifier's gas, its free pointer and its memory high-water.
  - It covers 146 evidence files:
    - 44 from the consolidation measurement (raw, consolidated before and after the burn, trimmed seals);
    - 92 from this run: 1 to 315 transfers in 16 certificate groups; one batch; consolidated; a certificate per transfer; 151 and 261
      fresh owner keys (past the 128-slot key cache); trimmed; 1, 2, 3, 6 and 10 split levels; small returns;
    - 10 synthetic: this run's tokens with every UC replaced, keeping each verdict an acceptance. The replacements are 16 signatures;
      16 signatures with 128-byte ASCII or non-ASCII node IDs; 64- and 200-bit shards (the prefix of each proof's state ID); 32 unicity
      tree steps; 24 KiB seals, a distinct claim each, at 52 and 102 proofs; and everything at once.
  - It also measured the helper's `certificate()` on real UCs and on synthetic ones. The synthetic UCs vary one structure at a time:
    1 to 16 signatures, 0 to 255 shard tree siblings, 0 to 32 unicity tree steps, 0 to 256 summary bytes, node IDs of 8 to 128
    ASCII or non-ASCII bytes. Each has its seal hash recomputed so the folds pass.
- **The chain.** Every token was burned (beyond the old preflight, with the bytes bound kept). Each burn was then measured by
  `eth_estimateGas` of its redeem at 0, 1, 4 and 16 to 17 historical segments, and 7 of them were paid live.

**How the constants are bounded.** Each part (the helper, the memory, the unsplit execution) is a least-squares fit on the features its
loops run over. Every per-unit coefficient is then raised: by 5% for the helper and the split terms, and by 2% for unsplit execution and
for memory. The intercept is raised to the largest residual. Unsplit execution is fit on the lane's shapes; the synthetic tokens check
it.

- The helper's fit residual is within 3,000 gas over the real and synthetic UCs.
- The unsplit execution's residual is within 19,000 gas over 129 files, from 1 to 317 proofs.
- The split terms are the least pair (per parent step, per edge) that covers every split file over the unsplit bound, raised by 5%.

On all 146 files, the bound's execution, memory and SHA-256 are 1.1% to 15% above the lab's measured gas. The 15% is a 24 KiB seal,
whose signature bytes are priced as UC bytes.

**Shared vectors.** `tests/nb2-gas/gas-vectors.json` holds 13 evidence files, and both plug-ins check every feature and term of each.
Six are real: 1 and 10 transfers, 3 and 10 split levels, 151 fresh keys, trimmed seals. Seven are synthetic: a 200-bit shard; 16
signatures with non-ASCII IDs; 16 signatures; 24 KiB seals over the batch's byte cap; a deposit after 2,000 logs (the review's
receipt); and two that must fail closed (17 signatures, and a
non-text signature key). Each file is checked at redemption (P 0 and 17 at K = 4, P 17 at K = 64) and at the preflight (K = 4 and 64).

The scripts and the raw data are in `~/evidence/nb2-gas-refit/` on the dev server (`lab/`, `fit3.py`, `features.jsonl`, `validate.jsonl`).

## Validation against the chain

Below, the bound at redemption is without `gasReserve`. The real gas is `eth_estimateGas` of the redeem at that P. The preflight is the
limit `planReturn` computes on the part before its burn (the burn at its bounds, P + 64 proofs, `gasReserve` included). Its verdict is
against `userGasLimit` = 60M.

| Part | Transfers | Split levels | Certificates | P | Real | Bound | Bound / real | Preflight | Paid gasUsed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| a50, raw | 51 | 0 | 18 | 0 | 9,585,385 | 10,195,994 | 1.064 | 14,392,278 | |
| a100, raw | 101 | 0 | 26 | 0 | 18,351,112 | 19,077,189 | 1.040 | 23,399,330 | 18,082,571 (P 17) |
| a200, raw | 201 | 0 | 35 | 0 | 36,627,443 | 37,613,142 | 1.027 | 42,191,002 | |
| a280, raw | 281 | 0 | 39 | 0 | 52,358,159 | 53,599,641 | 1.024 | 58,386,854 (admitted) | |
| a300, raw | 301 | 0 | 41 | 0 | 56,521,474 | 57,858,222 | 1.024 | 62,699,483 (refused) | 55,673,867 |
| a300, raw | 301 | 0 | 41 | 16 | 56,559,915 | 57,988,014 | 1.025 | 62,828,763 | |
| b150k, consolidated | 151 | 0 | 2 | 0 | 25,811,210 | 26,641,489 | 1.032 | 31,080,347 | |
| b300k, consolidated | 301 | 0 | 2 | 0 | 53,605,886 | 54,891,689 | 1.024 | 59,703,745 (admitted) | 52,801,263 |
| g250kt, consolidated and trimmed | 251 | 0 | 2 | 0 | 42,094,024 | 43,157,416 | 1.025 | 47,795,675 | 41,474,902 |
| k260, fresh keys | 261 | 0 | 39 | 0 | 59,401,954 | 60,870,106 | 1.025 | 65,615,337 (refused) | 58,506,740 |
| e1n | 152 | 1 | 21 | 0 | 28,892,312 | 29,616,368 | 1.025 | 34,076,090 | |
| e2n | 282 | 1 | 34 | 0 | 55,086,126 | 56,014,577 | 1.017 | 60,808,318 (refused) | |
| e3n | 153 | 2 | 24 | 0 | 30,631,535 | 31,520,216 | 1.029 | 35,810,897 | |
| e4n | 283 | 2 | 36 | 16 | 57,530,188 | 59,144,656 | 1.028 | 63,644,583 (refused) | 56,628,979 |
| e7n | 21 | 10 | 32 | 0 | 9,039,639 | 9,740,740 | 1.078 | 13,864,634 | 8,914,393 |

Over all 87 measurements (21 burns at P = 0 to 17, `validate.jsonl`):

- the bound at redemption is 1.017 to 1.57 times the real gas: about 1.02 at 250 to 300 transfers, and more for small tokens, where the
  vault's K = 64 worst call dominates;
- the preflight is 1.095 to 4.9 times the real gas;
- no measurement lies above its bound.

**The live boundary** (the lane's `boundary` stage on this generation, bft-core#1179). It used fresh tokens in 16 certificate groups at the
pinned limits:

- the preflight admitted 282 transfers and refused 284;
- every probe was executed as it was judged. The admitted ones at 279 and 282 transfers were burned and paid at 52,172,044 and 52,947,159
  gas used. The refused ones at 284, 285 and 289 were refused again, and the ledger showed each still unspent.

After the reviews of #82 (the forwarding, memory, shard-bit, cold-access, receipt-walk, build and vault fixes), the stage ran twice
more on fresh generations, with this release's source. The first rerun admitted 294 and refused 295. The last one, on the final model,
admitted 286 and refused 288; all five probes executed as judged. The ones admitted at 281, 284 and 286 transfers were burned and paid,
using 51,267,707 to 52,943,887 gas. The ones refused at 288 and 293 were refused again and shown unspent. Fresh tokens of one length vary
by about a transfer's step between builds, and the trees differed: the first run's had grown through several thousand measurement
transfers.

The old model admitted about 205.

## Margin

The margin has three parts:

1. **Above the real gas, at redemption: about 2% at the boundary.** This covers what the lab does not show:
   - shapes between the measured ones;
   - CBOR head widths;
   - the 1.5% tolerance of the node's `eth_estimateGas`, which the wallet's own limit at redemption already includes.

   It is small because the lab is exact: the bytecode and the EVM are the deployed ones, and the fit's residuals are a few thousandths
   of the gas.
2. **The pending burn at its bounds: about 3.0M gas, about 14 transfers at the boundary.** This is what keeps the preflight sound before
   the burn exists. The burn's own UC, path and claim are unknown until it is certified, and its UC can come from a later epoch with
   more signatures.
3. **The reserve: 64 segments and `gasReserve`.** The preflight charges 64 segments beyond those already owed (about 8,100 gas each at
   K = 4, 10,100 at K = 64), plus the 500,000 reserve.

**The burn-to-redeem window.**

- Once the burn is certified, the evidence is fixed. The tree's growth and the boundary's drift (about 991 bytes a probe in the
  consolidation measurement) change which new tokens are admitted, not the gas of a burned part.
- What does change after the burn is P: every segment sealed while the burn waits adds one gap proof. The 64-segment reserve covers that.
- At redemption the wallet re-reads the chain, builds the history and simulates (`buildRedeem`). The preflight runs again in `burn()`
  right before the burn is signed, on fresh chain state. A plan made earlier is never reused.

## Limits of the argument

- **The constants are those of the deployed verifier build** (contracts `884c4829`, solc 0.8.37, via-IR, `optimizer_runs = 1`). The
  bridge enforces it (above). A new build needs a new calibration and a new `CALIBRATED_VERIFIER`.
- **Shapes the lane cannot produce** are covered by the per-unit coefficients, which are measured on synthetic UCs. That means shard tree
  siblings, more unicity tree steps, more signatures, long or non-ASCII node IDs and long summaries. J's per-byte cost is from the code,
  not measured: J's shape is fixed on the lane.
- **The vault term is K = 64's worst call,** which is above every K = 4 call. K = 128 or larger would need its own vault measurement.
- **The native schedules are ureth `unicity/main` at `7f625ea`** (`crates/unicity/b1` batch.rs and rsmt.rs). There, a registry word
  read is `READ_GAS` = 100, which ureth marks as provisional until its cold-registry measurement. A repricing there changes the batch term
  and needs a new release of the bound.
- **The replayed probe and decompression counts** are checked against the verifier's code (the review of #82) and through the lab's
  totals. They are not checked against the verifier's own counters.
- **A zero state ID** (the tables' sentinel) has no known preimage. Both plug-ins handle it as the verifier does, but no vector reaches it.
