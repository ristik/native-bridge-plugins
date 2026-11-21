# Native bridge interoperability contract

Status: **NB2 continuation v1.1, `NATIVE_BRIDGE_PROTO_VERSION=10`, development profile.** The plug-ins implement the
configuration and lineage relation from §§1–2 and the authority and object bounds from §§4–5 and 7 of the
[NB2 continuation specification](https://github.com/ristik/bft-core/blob/d8800f36d/docs/design/nb2-continuation-v1.1.md).
Use a fresh generation and a deployment manifest that authenticates that release, its profile digest and execution history.
The protocol 10 decoder accepts only the flat wire below.

The gas bake-off (bft-core#1098, NB2-02; ristik/unicity-pos-contracts#80 `bench/nb2/RESULTS.md`) fixed `K = 64`,
`B = 16`, position-tag recent buffers, the circular-gap commitment and `gasReserve` 500,000. The remaining **PARAM**
marks are deployment values (`L_max`, `Qmax`, `returnReserveSegments`), listed in `profile.json` `parameters`.

Release prerequisite [§2]: a compatible end-to-end mint-admission remedy (#1039 / ISS-01) remains a prerequisite for
real-value activation; this profile does not solve the mint-request race. Removing that prerequisite requires an
explicit owner decision accepting the irreversible-deposit risk.

## Canonical primitives

`C(x,...)` is deterministic CBOR of an array; `b(x)` a byte string; `tag(t,x)` a tagged item. `H` is raw SHA-256 (the
Unicity hash) and `K256` is EVM keccak256; they are never substituted. `||` is concatenation; `u8`, `u16`, `u64` are
fixed-width big-endian; `u256(x)` is a 32-byte big-endian word. `I(h)=0000||h` is the SHA-256 imprint.

The NB2-defined arrays and fields admit only the CBOR item types specified for those fields, with definite lengths,
shortest heads, exact arity and complete consumption. These restrictions do not replace the native UC/UTB codecs:
certificates and trust-base objects, whether inline or carried inside byte strings, use their pinned native canonical
encoding (bft-go-base `v1.1.1-0.20261109140746-dbf94198f25e`, `profile.json` `nativeCodec`), including signature maps
and signer text keys. Decode and validate those objects with that encoding and its structural bounds; reject duplicate
map keys. Do not apply the NB2 array-only item whitelist recursively inside a native certificate. SDK
transaction/predicate encodings remain those of the pinned SDK revisions.

Each framed mint, inclusion proof, transfer pair and allocation is a separate CBOR decoding unit. A byte string
opened as CBOR starts another unit. The top item has depth zero. Every array, map or tag, including an empty
container, requires depth + 1 ≤ 16. Decode children at depth + 1. Transfer pairs include their inline UCs within
the same depth budget. Maps and text are limited to the canonical native certificate fields. A page or packet boundary
has no effect on a unit's depth. Receipt UCs are limited to 16,384 bytes and aggregator UCs to 24,576 bytes.

Domain literals are ASCII byte strings. Hashes, salts, IDs and identifiers are 32 bytes, addresses 20, compressed
secp256k1 keys 33. An amount is a minimal positive unsigned big-endian bstr of 1..32 bytes (no leading zero); in the EVM
ABI it is uint256; an empty amount is `IntRange`, more than 32 bytes `Length`, a leading zero `NonCanonical`. Network is 1..65535, chain ID a nonzero u64, partitions nonzero u32. JS uses bigint or decimal strings,
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
Γ = C(b("UNICITY_NB2_CFG"),2,network,b(rootGenesis32),b(executionGenesis32),chainId,
      evmPartition,b(evmShard),aggregatorPartition,b(vault20),b(asset32),b(ty32),b(aid32),
      b(semanticProfileHash32),b(verifier20),b(verifierCodeHash32),K,B,b(Qmax))
D = H(Γ)

Dstr  = networkDecimal+":"+rootGenesisHex+":"+executionGenesisHex+":"+chainIdDecimal
ty    = H(UTF8("unicity-bridge:unicity-native-nb2-11:"+Dstr))
aid   = H(UTF8("unicity-bridge-coin:unicity-native-nb2-11:"+Dstr))
asset = H(UTF8("unicity-nb2-asset:native-uct"))
```

Γ has arity 19. `evmShard` is the canonical native shard ID (1..33 bytes). `aggregatorPartition != evmPartition`.
`semanticProfileHash32` is SHA-256 of the exact published UTF-8 bytes of `protocol/profile.json`, including whitespace
and its final newline. Do not parse and reserialize or canonicalize JSON before hashing. The profile binds its
normative artifacts through their exact-file SHA-256 digests. Regenerate those digests and the profile digest after any
normative edit. `rootGenesis32` is the EntryID of the authenticated genesis trust-base entry. `(K, B)` lies in the
admitted set: production admits only `(K, B) = (64, 16)`; a test build admits `K` in {4, 8} × `B` in {2, 4} instead,
never both. `K` and `B` are vault constructor immutables. `1 <= Qmax <= 2^144-1`. Decimals have no leading zeros; hex
is lowercase without `0x`. Type and coin exclude the vault; every token is bound to its own vault by `D` in its mint
reason.

Fixed by bft-core#1098 (measured): `K = 64`, `B = 16` (`h = 6`, 4-bit tags, one tag word per buffer).

The vault constructor takes the exact Γ bytes and rejects them unless `vault20 == address(this)`,
`chainId == block.chainid`, the verifier's code hash equals `verifierCodeHash32`, `asset32`, `ty32` and `aid32` equal
their derivations above, and `K`, `B`, `Qmax` are admitted. 
A refusal is `BadConfig(field)`. Validation is staged, and the stage order is frozen. First the array: not an array of 19, trailing bytes, any scan error or more than 1024 bytes is 19. Then the fields in index order 0..18, reporting the first one that fails its own width, range and admitted-set rule. aggregatorPartition == evmPartition is field 8. (K, B) not admitted is 16 when K itself is not in the build's K set, and 17 otherwise. Only a Γ that decodes completely is checked against the deployment, in this order: asset32 (10), ty32 (11), aid32 (12), vault20 == address(this) (9), chainId == block.chainid (5), verifierCodeHash32 == EXTCODEHASH(verifier20) (15).
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

`k_w` is a 32-byte wallet bridge key derived deterministically from the wallet seed under a wallet-versioned
derivation scheme whose recovery metadata is backed up with the seed. `i` is a uint64 intent counter and is never
reused. Before signing a value-bearing deposit transaction, durably journal `(D, i)` and back up a recoverable
high-water mark covering that intent, or back up the intent's `r` directly. Recovery requires that backup in addition
to the seed. With a recovered high-water mark, scan every allocated intent through that mark and match `rho` against
certified `Deposited` events; an optional look-ahead does not replace the mark. Seed-only bounded recovery is not
guaranteed in the presence of arbitrary abandoned intents. Never derive `r` from public or low-entropy values. Reusing
`r` is prohibited wallet behavior; distinct deposit nonces still derive distinct root IDs.

The vault, under its reentrancy guard: `msg.value > 0` (`ZeroValue`); `firstOwner` exactly the 42 bytes above with a valid compressed secp256k1 point (`BadFirstOwner`); `msg.value <= Qmax - Q` (`LiabilityCap`); `n < 2^56-1`
(`DepositCounterExhausted`); then `n += 1`, `Q += msg.value` and the event. Deposit numbers start at 1. No refund, no
per-deposit storage, no ID derivation on chain.

## Mint reason and deposit proof [§6]

```
J = tag(39051,[1,b(D),n,b(r),DepositProof])
DepositProof = [1,b(evmUC),b(headerRLP),txIndex,logIndex,[b(receiptNodeRLP)...]]
M = tag(39041,[2,network,firstOwner,b(salt_n),b(ty),b(J),b(data),e])
data = tag(39050,[1,[[b(aid),b(v)]],null])
```

`J` body arity 5. `DepositProof` has arity 6 and is inline; any other arity, including the arity-7 protocol 8 draft
that carried a PDR, is rejected (`Shape`). `evmUC` is the complete canonical native UnicityCertificate.
`n` in [1, 2^56-1], indices below 2^32. The receipt is the value
of the last trie node, never carried twice. Bounds (`profile.json` `limits`, `evmUcBytes` 16,384 for `evmUC`) apply before any cryptography.
The root reason is bounded at 65,536 bytes and the entire signed root mint at 66,048 bytes.

Verification, in order, each failure a named rule (bft-core §14): `J.D == D` (`MintDomain`); `evmUC` verified under
the authenticated historical root authority of its own seal epoch for exactly Γ.`evmPartition` and Γ.`evmShard`
(`DepositUC`): no independently expected shard-configuration hash is supplied; the UC's own 32-byte ShardConfHash
MUST remain part of the authenticated shard-tree leaf, together with its InputRecord and TRHash (never nil or zero in
that computation); the complete shard/unicity paths and seal, and all structural, network, epoch-interval and quorum
checks, are verified; no PDR is supplied and no PDR-to-InputRecord epoch comparison is performed; every
EVM-certificate failure (encoding, network, epoch interval, structure, partition/shard, folds, quorum; deposit and
seal receipts alike) is `DepositUC`, except that wallets keep the retryable `NoEntryForEpoch` (on chain it is
`DepositUC` too);
`K256(headerRLP) == IR.blockHash` and `header.stateRoot == IR.hash` (`DepositHeader`), the certificate of the block
that executed the deposit, where `headerRLP` is the go-ethereum v1.14.11 Cancun header: the canonical RLP list of
exactly 20 fields ending at `parentBeaconBlockRoot` (no `requestsHash`), with zero difficulty, the empty uncle hash,
the empty withdrawals root, `blobGasUsed = excessBlobGas = 0`, a nonzero u64 base fee, `extraData` of at most 32 bytes,
`number <= 2^63-1` and an exact canonical re-encoding (anything else `DepositHeader`); the receipt
path under `header.receiptsRoot` with key `RLP(txIndex)`, canonical nodes, full key consumption, no unused or duplicate
node (`ReceiptPath`); a legacy receipt or `type||RLP` with type 1..3 (`ReceiptType`); status 1 (`ReceiptStatus`);
`logs[logIndex]` exists (`LogIndex`), is from `vault20` (`LogEmitter`), has exactly the topics
`[topic0(Deposited), u256(n)]` (`LogTopics`) and exactly the 224-byte data `(D, v, rho, firstOwner)` with offset 0x80,
length 42 and zero padding, `v > 0` (`LogData`); `rho == K256(DEPOSIT_SECRET||D||r)` (`SecretOpening`); the mint's
salt is `salt_n` (`MintSalt`), type `ty` (`MintType`), first owner `firstOwner` (`MintOwner`) and data exactly `aid`
and `v` (`MintData`). A root mint whose reason is not `tag(39051,...)` is `MintReason`.

No per-receipt account or code proof: `D` binds the vault address and chain, the manifest pins the runtime code hash,
checked once at installation. An RPC log listing or a transaction inclusion proof is never deposit evidence.

**Deployment binding and chain continuity.** Acceptance relies on the authenticated deployment binding Γ's root
genesis, partition/shard and execution genesis to one continuous EVM history, whose authorized assignment changes
preserve its execution identity and state. A configuration rotation does not change the authoritative vault address
or invalidate earlier certified receipts. A chain reset or replacement is a new authenticated deployment/domain, not a
continuation of this vault. D alone does not prove execution ancestry. Wallets MUST authenticate this deployment
binding and its pinned vault code (bft-core §4.3, §12.1); the on-chain verifier uses the corresponding
chain-authenticated historical authority. The same rule applies to seal receipts (wallet obligation 2).

## SDK transactions and flat token wire

Pins: the ristik SDK lines (`integration/enshrined-evm`), JS `c5840ef5f59201c52ea6cf7034ee02cb48d54007`
(4.0.0-utb.c5840ef), Rust `de79e6c1e393a1846b75bca0640b9ec9a55aa143` (unicity-token). No other SDK fork or patch is
authorized.

```
P = tag(39032,[1,b(encode_uint(type)),b(params)])
M = tag(39041,[2,network,P0,b(salt32),b(ty32),b(J),b(data),e])
T = tag(39045,[2,Pnext,b(mask32),dataOrNull,e])
CD = tag(39031,[2,Psource,b(sourceHash32),b(txHash32),e,b(unlock65)])
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
1<=s<=n/2, ID 0..3 under the SDK, but **ID 0 or 1 only for NB2** (below). Recover using the supplied ID, require the
recovered compressed key equal to the source key, then compact verify. Never normalize s/ID.

**NB2 unlock restriction.** An NB2-eligible token's unlock signatures
must all use recovery ID 0 or 1. Recovery IDs 2 and 3 are refused with `UnlockRecovery` in every implementation: wallets,
provenance and token admission in the plug-ins, the Go reference and the Solidity verifier. This deliberately narrows
the pinned SDK's unlock relation (which admits IDs 0..3) for bridge eligibility only; it is not unchanged SDK
semantics and not an error-name mapping. A token whose lineage contains an ID 2 or 3 unlock remains a valid native
token but cannot be returned through this bridge.

 For explicit e require t<e, with equality rejecting. Always require
`t <= InputRecord.timestamp` of the proof's own authenticated UC. Never compare against wall time, EVM
block.timestamp or the current root round. Refresh and consolidation preserve exact M/T, CD and original t, and
rebuild only paths/UCs against an admitted root. RSMT membership uses raw v32.

Every UC, aggregator and EVM alike, is verified under the trust-base entry of its own seal epoch by the upstream seal
rule ([trust-base.md](trust-base.md), its NB2 revision): a signature that fails the weighting rule contributes zero,
and no legacy pre-scan rejects a seal for a signature's length or recovery byte; `NoEntryForEpoch` is retryable once
the history holds the epoch. On chain the verifier reads the same history from the chain's permanent seal registry, at any age. Every EVM UC,
deposit and seal receipt alike, is judged under the deployment-binding and chain-continuity rule above; a validator
rotation never invalidates an earlier receipt.

## Split lineage and export

```text
blob(x) = u32(len(x)) || x
E       = ASCII("NB2L") || u16(0x0101) || u64(levelCount) || level[0] || …
level   = blob(allocation) || blob(M) || blob(proofM) || u64(transferCount) || entry[0] || …
entry   = blob(C(T, proofT))
Jchild  = tag(39044,[2,b(parentLink)])
manifest = tag(39046,[b(manifestRoot)])
parentLink = H("UNICITY/NB2/1.1/PARENT" || D || parentId || splitSID ||
               splitTxHash || manifestRoot || u256(parentAmount))
output = H(C(b("UNICITY_NB2_11_OUTPUT"),b(parentId),network,b(exact owner predicate),
             b(salt),b(childId),b(ty),b(exact mint data),deadline))
leaf = H(0x10 || childId || output || u256(value))
node = H(0x11 || u8(depth) || leftHash || u256(leftSum) || rightHash || u256(rightSum))
```

Export each part as E. Import consumes every byte and verifies all levels from root to leaf. Root allocation
is empty. Each child allocation is a complete CBOR array of up to 256 leaf-first `[depth,b(siblingHash),A(siblingSum)]`
steps in strictly decreasing depth order. A singleton proof is `80` hex. Depth identifies the bit counted from the MSB
of childId. Fold with checked u256 sums and require both the manifest root and the full amount of the authenticated
parent. Allocation is bounded at 20,480 bytes. A child mint is bounded at 512 bytes by the framing decoder.
Mint proof bytes plus the eight-byte transfer count are bounded at 40,960 bytes. Each transfer pair payload may
be at most 40,960 bytes. The native proof bitmap and siblings may occupy at most 8,224 bytes.

Choose child fields and build the radix tree over distinct child IDs first. Sign and certify the parent's split
transfer, binding its manifest bytes with a burn predicate. Verify the parent lineage and terminal split, and derive
parentLink from that verified spend. Then sign and certify each child mint with its fixed parentLink and export only
its selection of the allocation proof with the complete necessary ancestors. Every mint and transfer consumes a
certified source. The signed child mint is independent of the external proof presentation.

All ancestors end in a split. A held terminal level has a signature-owned mint with zero transfers or ends in
a signature-owned transfer with null data. Every level of a redemption has at least one transfer and the final
transfer is the return burn. A held import yields the authenticated owner, state, token ID and amount.

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

The commitment is the circular-gap tree, fixed by bft-core#1098 (measured). This section, history sizing and the
capacity formula instantiate it; a later change requires a separately versioned profile with cross-implementation
vectors. No decoder may guess an alternative history format from calldata.

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
never cleared. The layout is position tags, fixed by bft-core#1098 (measured); storage slot numbers are not part of
this contract. The external bounds are `n <= 2^56-1`, `c <= 2^48-1`, `Qmax <= 2^144-1`; wider physical fields would
not authorize wider values.

## Redemption [§11]

```
redeem(bytes evidence, bytes32 claimedEta, uint64 claimedStart, bytes history)
evidence = E                                            // the complete flat return lineage
history  = empty                                         // P = 0
         | startHead32 || proof_0 || ... || proof_{P-1}  // P >= 1
```

Check order and errors (frozen): reentrancy (`Reentrancy`); history length (`BadHistoryLength`); `a <= c`
(`FutureIndex`); `e = a + P` is `c` or, when `c > 0`, `c - 1` (`StaleEndpoint`); each proof for `claimedEta`
(`BadGapProof(position)`) folded from `startHead` through `j = a..e-1` to the stored `H_e` (`ChainMismatch`); the
current buffer, and the previous one when `e = c - 1`, holds no `claimedEta` among its live positions tagged
`bucket(claimedEta)` (`AlreadyPaid`); STATICCALL `verifyReturn(config(), evidence)` (`VerifierRefused(reason)` for
revert data of at most `MAX_VERIFIER_REVERT` = 1024 bytes; longer revert data, or return data other than exactly 192
canonical bytes, `VerifierBadReturn`; the vault reads `returndatasize()` first and never copies oversized data); verdict `domain == D` (`DomainMismatch`), `asset` (`AssetMismatch`),
`(eta, minSegment) == (claimedEta, claimedStart)` (`ClaimMismatch`), recipient (`BadRecipient`), `amount > 0`
(`ZeroAmount`), `amount <= Q` (`LiabilityUnderflow`). Effects: append eta and its tag, `Q -= amount`, emit `Paid`; if
`m + 1 == K` seal and store `m = 0`, otherwise store `m + 1` (`m == K` is never stored; `m < K` always holds); sealing
(`SegmentCounterExhausted` at `c = 2^48-1`); then pay `amount` to the recipient with a plain value call (`PayoutFailed`). Nothing is granted before the verdict equality. A recipient that re-enters `redeem` or
`deposit` from its receive hook gets the inner error `Reentrancy`; if the hook does not propagate it, the outer payout
succeeds.

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

The verifier requires an authenticated B1 evaluation origin for the configured deployment and UTB history.
Pass the origin's usable epoch and inclusive root round through the SDK trust input. They come from the trusted
deployment or registry checkpoint channel. Each admitted seal must satisfy both bounds in addition to its
own authenticated epoch interval. Count every supplied seal signature against the limit of 16 before signature
verification, including witnesses with no quorum weight.

The verifier authenticates each source under the network's historical authority, compares the exact certification
data and unlock, enforces the nullable deadline, checks RSMT membership and records the SID across the entire
lineage. The claim map covers the deposit UC and every aggregator UC. Uses with the same complete canonical seal,
partition and shard must have the same canonical claim. A different authorized seal presentation yields a different
key and still requires full verification. The package's held and split verifiers do not produce a payout verdict.
The recovery packet format and failure ordering are specified in §§3–6 of the continuation specification.

## Wallet obligations [§12]

1. **Secret.** Before submitting value, journal `(D, i)` and back up `k_w` together with the journal's high-water mark
   covering `i` (or the intent's `r`); local journaling alone is not a backup. Build `J` only from a certified deposit
   block.
2. **Index (R1).** Before burning, fetch the newest `SegmentSealed(j)` receipt available as a `DepositProof` container
   with topics `[topic0(SegmentSealed), u256(j)]`, verify it exactly like a deposit receipt, with the same UC rule
   (no PDR, the UC's own ShardConfHash in the authenticated leaf, exact Γ partition and shard) and deployment binding
   (`SealReceipt`, carrying the inner rule: retryable `NoEntryForEpoch` for a missing historical entry after the
   earlier checks pass, otherwise `DepositUC` for an EVM-certificate failure; extend the authenticated history and
   retry the missing-entry case), and sign
   `a = j + 1`, keeping `headAfter` as the future start head. With no receipt, sign `a = 0` (start head `H_0`). A plain
   `state()` read is allowed only when the manifest's `stateReadOnly` is true, and its `c` must lie in
   `[verified, verified + maxJump]` (`maxJump` 64 by default; else `ImplausibleIndex`). Without `stateReadOnly`, a
   `state()` read is not evidence and is refused without a rule name.
3. **History.** Fetch one `SegmentSealed` log per segment `a..c-1` from any source; check length `32K`, strict order,
   `M_j` and the head link (`SegmentLog`). If eta is in a segment it was paid. Build the gap proofs. One rollover in
   flight is tolerated; after two, rebuild the history without changing the burn.
4. **Gas.** Gas limit = expected cost + `gasReserve` = 500,000 (bft-core#1098, measured): the envelope of the most
   expensive redeem call minus the cheapest, including segments 0 and 1, rounded up; not the sum of the worst seal
   (229,830) and the worst scan (282,548). Worst single call 487,339; envelope 433,765 steady, 453,641 with segments
   0 and 1.
5. **Size and gas.** Before certifying the return burn, choose a by obligation 2 and obtain a current endpoint
   estimate c_obs with c_obs >= a. Set P_now = c_obs - a. Refuse with `CapacityPreflight` unless the complete
   prospective return, including its burn transaction and certification evidence, is admitted by every
   parser/component bound and fits both the encoded-transaction limit and userGasLimit with
   P_now + returnReserveSegments (default 64) historical proofs. Include gasReserve and all ABI padding, transaction
   framing and calldata gas. If any required evidence-size or gas bound cannot be established, refuse to burn. The
   displayed `P_max = floor((L_max - L_T - L_O) / (65 + 32h))` formula is a planning approximation; admission uses the
   complete encoded transaction or a conservative upper bound. An old seal receipt consumes capacity before the burn.
   If it leaves insufficient reserve, obtain a newer authenticated receipt or refuse. Freshness and future inclusion
   remain availability assumptions: even this check does not guarantee redemption against an indefinitely stale view
   or arbitrary subsequent traffic. `L_T` before the burn is a conservative upper bound: the held evidence plus the burn transfer with its exact `R`, its CD, and an inclusion proof at the decoder bounds (an RSMT path of up to 256 siblings and an aggregator UC up to `aggregatorUcBytes` = 24,576 bytes). At redemption refuse if `P > P_max` or the gas exceeds `userGasLimit`
   (`CapacityExceeded`). Packet planning and recovery fee qualification are release work under NB2-C T5 and T6.
6. **Recipient.** Default to a controlled EOA. Simulation of a contract recipient is not a guarantee.
7. **Receiving.** When receiving a token intended for return, verify its whole lineage against the NB2 unlock
   restriction and refuse or flag it if any unlock uses recovery ID 2 or 3, so a previous owner cannot hand over a
   token that can never be returned.
8. **Burn and retry.** Verify full provenance first; persist the certified burn before reporting success; after a
   timeout look for `Paid(eta)` before retrying; refresh stale history; never alter the certified burn.

9. **RPC.** Evidence comes from the ordinary execution RPC behind the deployment's public gateway, verified offline;
   bft-core §12.7 is the wallet RPC contract (methods, gateway limits, paging, retention and missing-evidence answers).
   `unicity_getSealCompanionV1` answers exactly `{"status":"found","companion":{...}}` on success, otherwise
   `{"status":"unavailable","horizon":H}` or `{"status":"unknown"}`.
   A node that no longer serves a companion, block or receipts the evidence needs is `EvidencePruned`: use another
   provider; it never changes a burn or an index.

Error classification of a failed simulation: `AlreadyPaid` reconcile; `StaleEndpoint` rebuild history; `FutureIndex`
wait; `BadGapProof`/`ChainMismatch` repair the proof or start head, no new burn; `VerifierRefused` carries the
verifier's rule. `VerifierBadReturn` means the verifier's rule was not relayed (revert data over 1024 bytes or malformed
return data): call `verifyReturn` directly or run the wallet's own verifier to read it.

## Corpus

`protocol/vectors/nb2-continuation-v1.1/` contains T1's golden bytes and signed transcripts from bft-core
commit `d8800f36d`. Both SDK extension suites verify the transcript lineage against its pinned UTB.
The transcript manifest digest is `41856353c08fa85b87ce59e470ac152213ac7de3031fb8a721989ae08755a651`.
`protocol/vectors/nb2/` retains protocol 9 vectors for common custody, receipt and primitive regression checks.
The old gas calibration is retained for historical comparison. The default measured gas model requires its
calibrated artifacts, so protocol 10 must use a qualified model supplied for its deployment before wallet burns.
