# Native bridge interoperability contract

Status: **native bridge v2, `NATIVE_BRIDGE_PROTO_VERSION=8`, development profile, frozen, not activated.** This document
is the sole normative native byte contract of the plug-ins. The design, the plain-language data flow, the safety
argument and the structural model are in ristik/bft-core `docs/design/native-bridge-v2.md` (NB2-01, bft-core#1097);
section numbers in brackets below (`[§n]`) point there. The two carry the same bytes; a difference is a bug, and the
bft-core document is the reference.

v2 replaces protocol 7 outright: lock records, per-lock accounting, lock-proof storage proofs, `0x0104`/`0x0105`
kernels, the anchor-table envelope and the deployment manifest schema v1 are gone. There is no migration, dual decoder
or compatibility. The protocol 7 artifacts in `protocol/legacy-v7/` and the corpus in `protocol/vectors/` remain only
because the old plug-in code still tests against them; they are not part of this profile and bft-core#1106 (NB2-10)
removes them with that code.

A few values are provisional until the gas bake-off, bft-core#1098 (NB2-02). They are marked **PARAM** and listed in
`profile.json` `parameters`. A PARAM changes numbers and widths, never the encodings around them.

## Canonical primitives

`C(x,...)` is deterministic CBOR of an array; `b(x)` a byte string; `tag(t,x)` a tagged item. `H` is raw SHA-256 (the
Unicity hash) and `K256` is EVM keccak256; they are never substituted. `||` is concatenation; `u8`, `u16`, `u64` are
fixed-width big-endian; `u256(x)` is a 32-byte big-endian word. `I(h)=0000||h` is the SHA-256 imprint.

Use shortest unsigned CBOR integers and lengths, definite items, exact arity and complete consumption. Reject maps,
floats, text strings, simple values other than null, indefinite lengths, extra fields and trailing data. Domain
literals are ASCII byte strings. Hashes, salts, IDs and identifiers are 32 bytes, addresses 20, compressed secp256k1
keys 33. An amount is a minimal positive unsigned big-endian bstr of 1..32 bytes (no leading zero); in the EVM ABI it
is uint256. Network is 1..65535, chain ID a nonzero u64, partitions nonzero u32. JS uses bigint or decimal strings,
never lossy number conversion. Identifiers compare as unsigned 256-bit big-endian integers.

EVM domain tags are `TAG(name) = K256(ASCII(name))`:

```
DEPOSIT_SECRET  = dfa87a7a4c6db3c7c307e4f2c3cc2d4a07e33d349f542b47f8e0bba49f62e645  // TAG("UNICITY_NB2_DEPOSIT_SECRET")
ARCHIVE_GENESIS = 45076af3d8858f1d7a9bb6e037bb5ca4270d0b4fa90f9397eb7adb905590a339  // TAG("UNICITY_NB2_ARCHIVE_GENESIS")
ARCHIVE_STEP    = c68efdc45f5c9a20bf6abfda6493e8e295d8e31495fd1e744cd4c35f74785dfa  // TAG("UNICITY_NB2_ARCHIVE_STEP")
```

New CBOR tags: `39051` receipt-backed mint reason `J`, `39052` segment return data `R`. Tags `39047`, `39048` and
`39049` are rejected wherever a v2 structure is expected.

## Configuration and domain [§4]

```
Γ = C(b("UNICITY_NB2_CFG"),1,network,b(rootGenesis32),b(executionGenesis32),chainId,
      evmPartition,b(evmShard),aggregatorPartition,b(vault20),b(asset32),b(ty32),b(aid32),
      b(semanticProfileHash32),b(verifier20),b(verifierCodeHash32),K,B,b(Qmax))
D = H(Γ)

Dstr  = networkDecimal+":"+rootGenesisHex+":"+executionGenesisHex+":"+chainIdDecimal
ty    = H(UTF8("unicity-bridge:unicity-native-nb2:"+Dstr))
aid   = H(UTF8("unicity-bridge-coin:unicity-native-nb2:"+Dstr))
asset = H(UTF8("unicity-nb2-asset:native-uct"))
```

Γ has arity 19. `evmShard` is the canonical native shard ID (1..33 bytes). `aggregatorPartition != evmPartition`.
`semanticProfileHash` is SHA-256 of the exact bytes of `protocol/profile.json`. `K` and `B` are powers of two with
`2 <= B <= K <= 256`, inside the admitted candidate set; `1 <= Qmax <= 2^144-1`. Decimals have no leading zeros; hex is
lowercase without `0x`. Type and coin exclude the vault; every token is bound to its own vault by `D` in its mint
reason.

**PARAM** `K` in {32, 64, 128}, default 64; `B` in {8, 16, 32}, default 16 (bft-core#1098).

The vault constructor takes the exact Γ bytes and rejects them (`BadConfig(field)`) unless `vault20 == address(this)`,
`chainId == block.chainid`, the verifier's code hash equals `verifierCodeHash32` and `K`, `B`, `Qmax` are admitted.
The verifier is stateless and receives Γ on every call. The vault is immutable: no owner, upgrade, pause,
administrative payout, `receive` or `fallback`.

The deployment manifest (schema by bft-core#1105, NB2-09) pins outside `D`: `vaultRuntimeCodeHash`,
`maxEncodedTxBytes` (`L_max`), `userGasLimit`, `gasReserve`, `returnReserveSegments`, `deploymentBlock` and
`stateReadOnly` (true only on test deployments). **PARAM** `L_max` in {131072, 524288}, default 524288 (owner decision,
measured by #1105).

## Deposit [§5]

```
r     = HMAC-SHA256(key=k_w, msg=C(b("UNICITY_NB2_DEPOSIT_INTENT"),b(D),i))
rho   = K256(DEPOSIT_SECRET || D || r)
deposit(bytes firstOwner, bytes32 rho) payable
firstOwner = d9 98 78 83 01 41 01 58 21 || key33                     // tag(39032,[1,b(01),b(key33)]), 42 bytes
event Deposited(uint64 indexed nonce, bytes32 domain, uint256 amount, bytes32 rho, bytes firstOwner)
salt_n = H(C(b("UNICITY_NB2_DEPOSIT_SALT"),b(D),n,b(r)))
id_n   = H(C(b(salt_n),network))
h0     = H(C(b(id_n),b(H("TOKENID"))))
```

`k_w` is the wallet's 32-byte bridge key, derived deterministically from its seed and backed up with it. `i` is a u64
intent counter, never reused, journaled durably with `D` **before** the deposit transaction is signed. Recovery scans
`i` from 0 to the journal high-water mark plus 64 and matches `rho` against `Deposited` events. Never derive `r` from a
public or small value; never reuse it.

The vault, under its reentrancy guard: `msg.value > 0` (`ZeroValue`); `firstOwner` exactly the 42 bytes above with
`key33[0]` in {02, 03} (`BadFirstOwner`); `msg.value <= Qmax - Q` (`LiabilityCap`); `n < 2^56-1`
(`DepositCounterExhausted`); then `n += 1`, `Q += msg.value` and the event. Deposit numbers start at 1. No refund, no
per-deposit storage, no ID derivation on chain.

## Mint reason and deposit proof [§6]

```
J = tag(39051,[1,b(D),n,b(r),DepositProof])
DepositProof = [1,b(evmPDR),b(evmUC),b(headerRLP),txIndex,logIndex,[b(receiptNodeRLP)...]]
M = tag(39041,[2,network,firstOwner,b(salt_n),b(ty),b(J),b(data),e])
data = tag(39050,[1,[[b(aid),b(v)]],null])
```

`J` body arity 5, `DepositProof` arity 7 and inline. `n` in [1, 2^56-1], indices below 2^32. The receipt is the value
of the last trie node, never carried twice. Bounds (`profile.json` `limits`) apply before any cryptography.

Verification, in order, each failure a named rule (bft-core §14): `J.D == D` (`MintDomain`); `evmUC` verified under
its seal epoch's trust-base entry for `evmPartition`/`evmShard` (`DepositUC`); `H(evmPDR)` equals the UC's shard
configuration hash and the PDR epoch the IR epoch (`DepositPDR`); `K256(headerRLP) == IR.blockHash` and
`header.stateRoot == IR.hash` (`DepositHeader`), the certificate of the block that executed the deposit; the receipt
path under `header.receiptsRoot` with key `RLP(txIndex)`, canonical nodes, full key consumption, no unused or duplicate
node (`ReceiptPath`); a legacy receipt or `type||RLP` with type 1..3 (`ReceiptType`); status 1 (`ReceiptStatus`);
`logs[logIndex]` exists (`LogIndex`), is from `vault20` (`LogEmitter`), has exactly the topics
`[topic0(Deposited), u256(n)]` (`LogTopics`) and exactly the 224-byte data `(D, v, rho, firstOwner)` with offset 0x80,
length 42 and zero padding, `v > 0` (`LogData`); `rho == K256(DEPOSIT_SECRET||D||r)` (`SecretOpening`); the mint's
salt is `salt_n` (`MintSalt`), type `ty` (`MintType`), first owner `firstOwner` (`MintOwner`) and data exactly `aid`
and `v` (`MintData`). A root mint whose reason is not `tag(39051,...)` is `MintReason`.

No per-receipt account or code proof: `D` binds the vault address and chain, the manifest pins the runtime code hash,
checked once at installation. An RPC log listing or a transaction inclusion proof is never deposit evidence.

## SDK wire (unchanged)

Pins: the ristik SDK lines (`integration/enshrined-evm`), JS `c5840ef5f59201c52ea6cf7034ee02cb48d54007`
(4.0.0-utb.c5840ef), Rust `de79e6c1e393a1846b75bca0640b9ec9a55aa143` (unicity-token). No other SDK fork or patch is
authorized.

```
P = tag(39032,[1,b(encode_uint(type)),b(params)])
M = tag(39041,[2,network,P0,b(salt32),b(ty32),b(J),b(data),e])
T = tag(39045,[2,Pnext,b(mask32),dataOrNull,e])
CD = tag(39031,[2,Psource,b(sourceHash32),b(txHash32),e,b(unlock65)])
Token = tag(39040,[2,[M,proof0],[[T1,proof1],...]])
proof = tag(39033,[1,CD,t,b(bitmap32||siblings32...),UC])
data = tag(39050,[1,[[b(aid32),b(amount)]],null])
```

Signature predicate type=1, params a valid compressed key33. Burn type=2, params raw `H(R)`. Built-in code bytes are
01/02, not strings. P is nested as a tagged item, not wrapped in a bstr. M data/J and T's nonnull data are bytes
containing the exact tagged encodings. The asset collection is inline, exactly one entry; no memo, nested token,
extra/foreign coin or merge exception. Intermediate T data MUST be null; a token's terminal burn carries its split
manifest or, for the returned part, exactly R. Mint arity is 8, transfer 5, CD 6, proof 5. CD deadline precedes unlock; proof referenceTime
follows CD. All certified proof fields are mandatory; pending responses are not proofs.

```
txHash = H(exact tagged M/T bytes)
outputHash = H(C(b(I(sourceHash)),b(mask)))  // mint mask=id
sid = H(C(Psource,b(sourceHash32)))
v = H(C(b(txHash32),t))
unlockMessage = H(C(b(sourceHash32),b(txHash32)))
minterScalar = H(C(b("I_AM_UNIVERSAL_MINTER_FOR_"),b(id)))
```

Reject an invalid minter scalar, never reduce it modulo n. Reconstruct each source owner/hash from the previous
output; the mint source is h0 and the public universal-minter signature predicate. Require CD source/tx fields and
deadline identical to the reconstructed transaction, including null. Token unlock is r32||s32||recoveryId: 1<=r<n,
1<=s<=n/2, ID 0..3. Recover using the supplied ID, require the recovered compressed key equal to the source key, then
compact verify. Never normalize s/ID. For explicit e require t<e, with equality rejecting. Always require
`t <= InputRecord.timestamp` of the proof's own authenticated UC. Never compare against wall time, EVM
block.timestamp or the current root round. Refresh and consolidation preserve exact M/T, CD and original t, and
rebuild only paths/UCs against an admitted root. RSMT membership uses raw v32.

Every UC, aggregator and EVM alike, is verified under the trust-base entry of its own seal epoch by the upstream seal
rule ([trust-base.md](trust-base.md), unchanged from protocol 7); `NoEntryForEpoch` is retryable once the history holds
the epoch. On chain the verifier reads the same history from the chain's permanent seal registry, at any age.

## Split lineage (unchanged formats)

```
Manifest = tag(39046,[b(root32)])
leaf     = H(0x10 || key32 || data32 || u256(v))        // key = child token ID
node     = H(0x11 || u8(depth) || hL || u256(sL) || hR || u256(sR))
Proof    = [[depth,b(hash32),b(sum)],...]               // leaf first
data     = H(C(b("UNICITY_SPLIT_OUTPUT"),b(parentId),network,b(P),b(salt),
               b(childId),b(ty),b(exactChildMintData)))
SplitJ   = tag(39044,[ParentToken,[Proof]])             // the child mint's reason
```

Sums are checked in 256 bits, `1 <= v < 2^256`; a key's side at a node is bit `depth` of the key, MSB first; a proof
has at most 256 steps with strictly decreasing depths. The verifier walks from the returned part to the root while
the mint reason is SplitJ; the root's reason must be `J`. One state-ID set covers the lineage (`RepeatedSID`). Every
non-returned token of the walk ends in its manifest burn (`SplitBurn`, `SplitManifest`); each edge's proof verifies
against the parent's manifest root (`SplitProof`) and sums to the parent's amount (`SplitSum`). Whole parts return
independently; no per-lock accounting exists.

## Return burn and redemption identifier [§8]

```
R    = tag(39052,[1,b(D),b(asset32),b(recipient20),b(v),a])
btid = H(C(b("UNICITY_NB2_BURN"),b(sidBurn),b(txHashBurn)))
eta  = H(C(b("UNICITY_NB2_REDEMPTION"),b(D),b(btid)))
bucket(eta) = eta >> (256 - log2 B)
```

R has arity 6. `a` in [0, 2^48-1] is the minimum segment index at which the burn may be paid. The final transfer has
predicate `Burn(H(R))` and data exactly R. `v` is the returned part's own amount; the recipient is nonzero and not the
vault. No archive hash, fee, deadline or redirection field. `eta` excludes paths, certificates, encodings and the
submitter.

## Segments and gap proofs [§10]

**PARAM** commitment: circular-gap tree (below), the default; bft-core#1098 compares it with compressed radix and
adjacent-leaf multiproofs. The archive chain and the event do not depend on this choice.

```
z_0 < ... < z_{K-1}                                    // the K ids of sealed segment j, strictly sorted
leaf_i = K256(0x00 || z_i || z_{(i+1) mod K})
node   = K256(0x01 || left || right)                   // ordered children, no padding
M_j    = root over leaf_0..leaf_{K-1}
H_0     = K256(ARCHIVE_GENESIS || D || u16(K))
H_{j+1} = K256(ARCHIVE_STEP || D || u64(j) || H_j || M_j)
proof   = u8(i) || l(32) || u(32) || s_0 .. s_{h-1}   // h = log2 K; exactly 65 + 32h bytes
```

Valid for `eta` when `i < K` and either `i < K-1, l < u, l < eta < u` or `i = K-1, l > u, (eta > l or eta < u)`, and
folding `x = K256(0x00||l||u)` with `s_k` (bit k of i: 0 means `K256(0x01||x||s_k)`, 1 means `K256(0x01||s_k||x)`)
gives `M_j`. Zero and `2^256-1` are ordinary identifiers.

## Vault state [§9]

```
A = n << 200 | c << 152 | m << 144 | Q      // 56, 48, 8, 144 bits
Σ = (A, T_0, T_1, H_c, H_{c-1}, S_0, S_1)
```

`c` is the current segment, `m < K` its population, `p = c mod 2` the current buffer. `S_p[i]` is the i-th identifier
paid into buffer p; tag word(s) `T_p` hold `bucket(S_p[i])` at bit offset `log2 B * (i mod t)` of word `floor(i/t)`,
`t = floor(256/log2 B)`. Live positions are `i < m` (current) and `i < K` (previous, when `c > 0`). Stale cells are
never cleared. **PARAM** layout: position tags (default) or the v2 sparse per-bucket layout (bft-core#1098); storage
slot numbers are not part of this contract.

## Redemption [§11]

```
redeem(bytes evidence, bytes32 claimedEta, uint64 claimedStart, bytes history)
evidence = C(1, Token)                                   // the returned part, inline tag 39040
history  = empty                                         // P = 0
         | startHead32 || proof_0 || ... || proof_{P-1}  // P >= 1
```

Check order and errors (frozen): reentrancy (`Reentrancy`); history length (`BadHistoryLength`); `a <= c`
(`FutureIndex`); `e = a + P` is `c` or, when `c > 0`, `c - 1` (`StaleEndpoint`); each proof for `claimedEta`
(`BadGapProof(position)`) folded from `startHead` through `j = a..e-1` to the stored `H_e` (`ChainMismatch`); the
current buffer, and the previous one when `e = c - 1`, holds no `claimedEta` among its live positions tagged
`bucket(claimedEta)` (`AlreadyPaid`); STATICCALL `verifyReturn(config(), evidence)` (`VerifierRefused(reason)`,
`VerifierBadReturn`); verdict `domain == D` (`DomainMismatch`), `asset` (`AssetMismatch`),
`(eta, minSegment) == (claimedEta, claimedStart)` (`ClaimMismatch`), recipient (`BadRecipient`), `amount > 0`
(`ZeroAmount`), `amount <= Q` (`LiabilityUnderflow`). Effects: append eta and its tag, `m += 1`, `Q -= amount`, emit
`Paid`; at `m = K` seal (`SegmentCounterExhausted` at `c = 2^48-1`); then pay `amount` to the recipient with a plain
value call (`PayoutFailed`). Nothing is granted before the verdict equality.

Sealing, in the same transaction: read the K identifiers, distribute by tag, sort each bucket with a bounded
worst-case sort, concatenate in bucket order, assert strict order, compute `M_c` and `H_{c+1}`, emit
`SegmentSealed(c, H_c, H_{c+1}, z_0||...||z_{K-1})`, then `H_{c-1} = H_c`, `H_c = H_{c+1}`, `c += 1`, `m = 0`. No
empty, early or timed seal.

```solidity
interface INativeBridgeVerifierV2 {
    function verifyReturn(bytes calldata gamma, bytes calldata evidence) external view
        returns (bytes32 domain, bytes32 eta, uint64 minSegment, bytes32 asset, address recipient, uint256 amount);
}
```

The verifier decodes Γ (`ConfigShape`) and the evidence (`EvidenceShape`), verifies the whole lineage, every
transaction, unlock and inclusion proof under the aggregator partition, the root's J, and the return burn (`NotBurn`,
`BurnNotFinal`, `BurnReason`, `ReturnData`, `ReturnDomain`, `ReturnAsset`, `ReturnAmount`, `ReturnRecipient`,
`ReturnIndex`), and returns the authenticated tuple. It reverts with `<RuleName>()`. [`abi.json`](abi.json) has every
selector, topic and data length.

## Wallet obligations [§12]

1. **Secret.** Journal `(D, i)` and back up `k_w` before submitting value. Build `J` only from a certified deposit
   block.
2. **Index (R1).** Before burning, fetch the newest `SegmentSealed(j)` receipt available as a `DepositProof` container
   with topics `[topic0(SegmentSealed), u256(j)]`, verify it exactly like a deposit receipt (`SealReceipt`), and sign
   `a = j + 1`, keeping `headAfter` as the future start head. With no receipt, sign `a = 0` (start head `H_0`). A plain
   `state()` read is allowed only when the manifest's `stateReadOnly` is true; a jump beyond the verified bound is
   refused (`ImplausibleIndex`).
3. **History.** Fetch one `SegmentSealed` log per segment `a..c-1` from any source; check length `32K`, strict order,
   `M_j` and the head link (`SegmentLog`). If eta is in a segment it was paid. Build the gap proofs. One rollover in
   flight is tolerated; after two, rebuild the history without changing the burn.
4. **Gas.** Gas limit = expected cost + `gasReserve` (worst seal + worst `2K-1` scan). **PARAM** 620,000 at K=64,
   B=16 (bft-core#1098).
5. **Size.** With `P_max = floor((L_max - L_T - L_O) / (65 + 32h))`: before burning refuse unless
   `P_max >= returnReserveSegments` (default 64; `CapacityPreflight`); at redemption refuse if `P > P_max` or the gas
   exceeds `userGasLimit` (`CapacityExceeded`). This release has no recovery for an oversized claim
   (bft-core#1108 is deferred).
6. **Recipient.** Default to a controlled EOA. Simulation of a contract recipient is not a guarantee.
7. **Burn and retry.** Verify full provenance first; persist the certified burn before reporting success; after a
   timeout look for `Paid(eta)` before retrying; refresh stale history; never alter the certified burn.

Error classification of a failed simulation: `AlreadyPaid` reconcile; `StaleEndpoint` rebuild history; `FutureIndex`
wait; `BadGapProof`/`ChainMismatch` repair the proof or start head, no new burn; `VerifierRefused` carries the
verifier's rule.

## Corpus

v2 vectors are generated once by the bft-core Go reference (NB2-03, bft-core#1099) as one file consumed by digest.
Until then this profile has no corpus; `protocol/vectors/` is the protocol 7 corpus of the legacy code.
