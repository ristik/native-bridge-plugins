# Native bridge interoperability contract

Status: protocol v5, development profile; implementation and activation gates
remain open. This document is the sole normative native byte contract.
This unreleased v5 draft incorporates the Unicity Trust Base trust model in
[trust-base.md](trust-base.md) (v4's fixed SDK 3.0.1 trust document is
abandoned, without compatibility), the any-age registry-backed certificate
batch of bft-core `briefs/b1-any-age-contract.md` (one `CERT_BATCH_V2` call over
the anchor table) and the aggregation-partition policy below; the v3 sharded
policy, per-anchor certificate calls and earlier assumptions are abandoned, with
no compatibility, migration or acceptance promise.
`NATIVE_BRIDGE_PROTO_VERSION=5` is independent of SDK Token.VERSION and the
external bridge's BRIDGE_PROTO_VERSION. Any byte/derivation change MUST bump
this version and semantic profile. Consensus parsers accept only this profile;
there is no pre-3.0 decoder, migration or dual-format interpretation.

## Canonical primitives

`C(x,...)` is deterministic CBOR of an array; `b(x)` a byte string;
`tag(t,x)` a tagged item; `H` raw SHA-256; `I(h)=0000||h` the SHA-256 imprint.
Domain literals are ASCII byte strings unless UTF8 is explicitly specified.
Use shortest unsigned CBOR integers/lengths, definite items, exact arity and
complete consumption. Reject normalization, extra fields, maps in these array
objects, indefinite lengths and trailing data. Hashes/salts/IDs are 32 bytes,
addresses 20 bytes, compressed secp256k1 keys 33 bytes.
Amount is minimal positive unsigned big-endian bstr, 1..32 bytes (no leading
zero). Arithmetic is uint256; chain ID and nonzero nonce are u64, network
is in 1..65535 (SDK NetworkId), partitions uint32. Cfg and mint wire
decoders reject network zero and values above 65535 with IntRange. JS uses bigint or decimal strings, never lossy number
conversion. `e` is null or uint64 in [1,2^64-1]; `t` is uint64 Unix seconds.

## Identity and immutable configuration

Bridge identity family is `unicity-native`; transport chainRef remains
`eip155:<chainIdDecimal>`. Let
`D=networkDecimal+":"+rootGenesisHex+":"+executionGenesisHex+":"+chainIdDecimal+":"+zeroAddressHex`.
Decimal integers have no leading zeros; genesis hashes are lowercase hex64,
zeroAddressHex is 40 zeros; none has a 0x prefix.

```
ty  = H(UTF8("unicity-bridge:unicity-native:" + D))
aid = H(UTF8("unicity-bridge-coin:unicity-native:" + D))
Cfg = C(b("UNICITY_BR_CFG"),network,b(rootGenesis),chainId,
        b(executionGenesis),evmPartition,b(evmShard),b(vault20),b(zero20),
        b(ty),b(aid),b(semanticProfileHash),b(tokenVerifier20),
        b(tokenVerifierCodeHash),b(b1ProfileHash),b(aggregatorPolicyHash))
cfg = H(Cfg)
Policy = C(b("UNICITY_BR_AGG_PARTITION"),2,aggregatorPartition)
aggregatorPolicyHash = H(Policy)
salt = H(C(b("UNICITY_BR_SALT"),b(cfg),nonce))
id = H(C(b(salt),network))
h0 = H(C(b(id),b(H("TOKENID"))))
rcpt = H(exact tagged P0 bytes)
K = [b(zero20),b(ty),b(aid),b(amount),b(id),b(rcpt)]
d = H(C(b("UNICITY_BR_LOCK"),b(cfg),nonce,K))
```

### Aggregation partition policy (AGG_PARTITION_V2)

The aggregator is one native partition, distinct from evmPartition, whose
certified shard configurations are authorized by the root quorum. The policy
names only that partition: no depth, shard list, configuration hash or
allow-list. Each anchor's UC authenticates its own historical shard and shard
configuration hash; its depth is that of its canonical native shard ID,
`d = 8*len(shard) - trailingZeroBits(lastByte) - 1` (lastByte nonzero, 1..33
bytes, 0<=d<=256). A shard ID is the native canonical encoding of the prefix
bits followed by one set terminator bit and zero padding, never empty bytes or
ASCII text. Shards of one history need not be prefix-free as one set: a parent
shard before a topology split and its child after it are both admitted, each
bound by its own UC. Reject a version other than 2, a zero partition or one
above 2^32-1, extra or missing fields, noncanonical encodings and any body above
512 bytes. Check SHA-256(policy body) against the immutable
Cfg.aggregatorPolicyHash before interpreting it. The v3 `UNICITY_BR_AGG_SHARDED`
and older `UNICITY_BR_AGG_ONE` bodies are rejected; there is no migration or
dual decoder. Endpoint URLs are untrusted routing hints and never part of the
policy. An unsupported token/hash/predicate format fails its pinned semantic
rule even with a valid UC; certified configurations select no token semantics.
EVM backing policy is separately pinned, never inferred from a submitted UC.
Type/coin exclude vault: approved replacement vaults share asset identity but
never inherit deployment trust. Config, salt, lock and redemption bind their
own vault. Reject lock digest d=0. The stateless TokenVerifier has no cfg/vault immutable,
avoiding a code-hash/configuration cycle. Runtime chain/vault MUST match Cfg.

## SDK wire

Pins: the ristik SDK lines (`integration/enshrined-evm`), JS
`cc9a95bcf5e043770dfd1ae79e54516cf424e859` (4.0.0-utb), Rust
`772be681c740442a35ecef35724a1545cf42b7f4` (unicity-token 4.0.0). The token,
predicate and certification wire below is unchanged from SDK 3.0.1; predicate
version and tags are unchanged. No other SDK fork or patch is authorized.

```
P = tag(39032,[1,b(encode_uint(type)),b(params)])
M = tag(39041,[2,network,P0,b(salt32),b(ty32),b(J),b(data),e])
T = tag(39045,[2,Pnext,b(mask32),dataOrNull,e])
CD = tag(39031,[2,Psource,b(sourceHash32),b(txHash32),e,b(unlock65)])
Token = tag(39040,[2,[M,proof0],[[T1,proof1],...]])
proof = tag(39033,[1,CD,t,b(bitmap32||siblings32...),UC])
data = tag(39050,[1,[[b(aid32),b(amount)]],null])
```

Signature predicate type=1, params=valid compressed key33. Burn type=2,
params=raw H(R). Built-in code bytes are 01/02, not strings. P is nested as a
tagged item, not wrapped in a bstr. M data/J and T's nonnull data are bytes
containing the exact tagged encodings. The asset collection is inline, exactly
one entry; no memo, nested token, extra/foreign coin, split or merge exception.
Intermediate T data MUST be null; terminal burn data MUST equal R.

Mint arity is 8, transfer 5, CD 6, proof 5. CD deadline precedes unlock;
proof referenceTime follows CD. Certified transactions have exactly two slots;
there is no third time slot. All certified proof fields are mandatory;
pending responses are not proofs. These replace pre-3.0 shapes outright.

```
txHash = H(exact tagged M/T bytes)
outputHash = H(C(b(I(sourceHash)),b(mask)))  // mint mask=id
sid = H(C(Psource,b(sourceHash32)))
v = H(C(b(txHash32),t))
unlockMessage = H(C(b(sourceHash32),b(txHash32)))
minterScalar = H(C(b("I_AM_UNIVERSAL_MINTER_FOR_"),b(id)))
```

Reject an invalid minter scalar, never reduce it modulo n. Reconstruct each
source owner/hash from the previous output; mint source is h0 and the public
universal-minter signature predicate. Require CD source/tx fields and deadline
identical to the reconstructed transaction, including null. Token unlock is
r32||s32||recoveryId: 1<=r<n, 1<=s<=n/2, ID 0..3. Recover using the supplied ID,
require recovered compressed key equal to the source key, then compact verify.
Never normalize s/ID. IDs 2/3 require actual matching recovery. This bridge
wrapper restriction applies to Rust as well; a range-only SDK check is
insufficient. B1 seal signatures have their separate native signing rules;
do not substitute those rules for token unlock recovery.

For explicit e require t<e, with equality rejecting. Always require
`t <= authenticated anchor InputRecord.timestamp`. Null does not synthesize a
service deadline. Never compare against current wall time, EVM block.timestamp
or current root round. Rust's wrapper adds the timestamp upper bound missing
from the inspected SDK. The authenticated t is the service's report, not proof
against dishonest aggregator backdating.

Refresh preserves exact M/T, CD and original t, and rebuilds only paths/UCs
against an admitted root. Archive t: a later certificate cannot reconstruct it.
RSMT membership uses raw v32, neither txHash nor an imprint. Editing e/J changes
txHash and invalidates certification. Old locks/tokens are not reinterpreted.

## Immutable embedded lock proof

```
J = tag(39049,[2,chainId,b(vault20),b(zero20),nonce,LockProof])
LockProof = [1,b(cfg32),b(trustBaseId32),b(evmPDR),b(evmUC),b(headerRLP),
             [b(accountNodeRLP)...],[b(storageNodeRLP)...]]
```

J's body arity is 6, LockProof 8; LockProof is inline, not bstr-wrapped.
Native tags stay 39049 lock / 39048 return; reject external 1330002, old
pointer-only reasons, null/unknown/split reasons and detached backing evidence.
PDR and UC are complete canonical native encodings. UC contains InputRecord,
shard-tree certificate, Unicity-tree certificate and quorum-signed root seal.
`trustBaseId` is the EntryID of the genesis entry of the network's Unicity
Trust Base history ([trust-base.md](trust-base.md)), not a document digest, an
epoch's entry or a stateHash. It MUST equal the manifest's
`trustBase.genesisEntryId` and the installed history's genesis; it never
authorizes keys or another history.

Receipt verification MUST have only token plus locally pinned configuration
and the installed trust-base history (a release bundle under its genesis
EntryID). It has no RPC, URL, node or witness-provider capability. Committees,
weights and thresholds (`floor(2W/3)+1`) are the history's entries'.

Bound and parse canonically before SDK allocation/crypto; match
chain/vault/native asset/cfg and allow-listed deployment. Every ordinary and
embedded UC is verified by the SDK under the entry of its own seal epoch:
network equal to the history's (`SealNetwork`), an epoch newer than the latest
held one `NoEntryForEpoch` (retryable), an epoch before the genesis or a root
round outside `[start_e, start_e+1)` `SealEpoch`, native structure
(`CertStructure`), tree root (`SealRoot`) and the native B1 seal rule under the
epoch's committee (`QuorumNotMet`). The embedded EVM UC uses the SDK certificate
verifier for its own partition (TS `verifyCertificate`, Rust
`verify_certificate_of_partition`). No plug-in weighted verifier, epoch
resolver or trust-base store.

Both ordinary and embedded UCs MUST be in the canonical native/SDK-decodable
intersection: seal signatures of 64 bytes or 65 with suffix 0/1 (the suffix is
ignored, as in both SDKs and native B1), byte-string IR summary, array-valued
shard siblings and Unicity steps (including empty arrays), valid signature maps,
SDK integer/key widths, and existing native/bridge bounds. Construction/import/
refresh fail `UnsupportedCertificateEncoding` outside this subset. Never rewrite
null to empty or mutate J. Strict token-unlock recovery remains separate and
unchanged.

After SDK UC verification, enforce the bridge-specific pinned EVM partition,
shard and configuration relation; hash PDR to UC's configuration commitment,
require PDR epoch = IR epoch and match pinned execution/genesis/fork settings.
Require `keccak256(headerRLP)==UC.InputRecord.blockHash` and
`header.stateRoot==UC.InputRecord.hash`, using pinned header encoding.

Verify account MPT key keccak256(vault20) under header.stateRoot. Canonical
account RLP codeHash MUST equal pinned vault runtime hash. Its storageRoot
verifies key `keccak256(keccak256(abi.encode(uint256(nonce),uint256(5))))`.
Canonical minimal RLP storage integer, left-padded to bytes32, MUST equal d
reconstructed from actual mint/recipient/asset/amount/ID/config. Check derived
salt/ID, signature P0 and positive amount. Enforce hex-prefix, embedded-node and
hash-reference rules, full key consumption, no duplicate/extraneous nodes or
unused suffixes. RSMT verification cannot verify an EVM MPT. No receipt proof
alternative exists. A root signature over an unrelated state root is inadequate.

Lock first, obtain certified proof, construct J, then hash/sign/certify M.
Lock digest excludes J/txHash, so there is no circularity. J cannot be refreshed
after certification. Historical proof establishes permanent lock existence,
not current spent=0. Certified single-spend history and live vault nonce guard
have distinct roles. Historical backing has no B1 certificate-age requirement.

J stays byte-identical after certification. A lock certificate of any epoch the
history holds verifies under that epoch's committee and interval, so backing
survives later rotations. Aggregator refresh may replace paths/UCs under any
held epoch while preserving M/T, CD and original t. Never install a history from
token input or union keys. Trust-base evolution is the SDK's: the wallet appends
newer entries (each witnessed by its predecessor) and retries `NoEntryForEpoch`;
the plug-ins fetch nothing. No bridge-owned epoch artifact, interval sidecar or
trust-history service exists. Native return B1 keeps its independent consensus,
registry, window and ABI.

## Whole-token history and return

No split, merge, partial return, time/custom predicate, recursive token, foreign
mint or burn-followed-by-transfer. P0 and all nonterminal owners are signature
predicates; first burn is terminal. The universal minter secret is public and
never authorizes issuance. Mandatory issuance policy claims exactly aid,
requires the exact J/data and binding certified lock. Other token types claiming
this coin remain unverified. Dispatcher allow-list is immutable and rejects
duplicate/ambiguous network/chain/vault entries. Registry installation is an
application trust decision; a manifest arriving with a token executes no code.

```
R = tag(39048,[1,chainId,b(vault20),b(zero20),b(ty),b(aid),
               b(recipient20),b(amount),b(zero20),b(empty),0])
btid = H(C(b("unicity-burn-transition:v1"),b(sidBurn),b(txHashBurn)))
eta = H(C(b("UNICITY_BR_NUL"),b(cfg),b(btid)))
history = C([M,CD0,t0],[[T1,CD1,t1],...])
```

R has 11 slots; recipient nonzero and not vault, amount equals genesis amount.
Last three fee/deadline slots are fixed as shown; request e is separate.
Projection tuples have three slots, unlike SDK certified transactions. Strictly
decode the entire token before export; obtain t only from its proof. All times
remain untrusted until leaf membership and anchor authentication succeed.
eta excludes t, paths, anchor round, unlock representation and submitter.

Burn construction uses BurnPredicate(H(R)), journals the full certified blob
before wallet acknowledgement, preserves original times and certificates and
provides recoverPendingBurns. Acknowledgement is durable handoff, not payout.
Return targets original vault and credits R.recipient, never submitter. Confirm
receipts and on-chain spent/credit before recording settlement.

## Cross-stack ABI

`abi.json` freezes field order/types/offsets. 0x0103 stays reserved. 0x0104 is
pure semantics, with canonical ABI `(uint8 operation,bytes Cfg,bytes payload)`:
0=prepareLock, payload C(nonce,b(amount),P0); 1=mint and 2=return, payload=history.
Mint requires zero transfers, return at least terminal burn. Unknown operations
reject. Kernel reconstructs all transaction/CD/source fields, enforces time
rules and strict recovery, rejects repeated SIDs and exports ordered leaves.
It does not authenticate aggregator admission or inclusion.

Output is `abi.encode(bytes32("UNICITY_TOKEN_SEMANTICS"),bool valid,Result)`.
Result order: cfg,nonce,amount,tokenId,salt,firstPredicateHash,lockDigest,
releaseTo,nullifier,Leaf[]. Leaf=(bytes32 sid,bytes32 txHash,uint64 referenceTime,
bytes32 leafValue). Prepare has zero leaves/zero release fields; mint one leaf
and zero release fields; return all leaves. Failure has valid=false and an
all-zero/empty Result. Output has exactly 448+128*m bytes. Require canonical
bool/address/u64 padding, marker, offsets, zero/false shape and complete
consumption; inactive-address empty success is rejection. Bound before copying.

Envelope is `abi.encode(bytes policyBody,bytes history,Anchor[],LeafProof[])`.
Anchor order=(uint32 partition,bytes shard,bytes32 shardConfHash,
bytes32 expectedStateRoot,bytes32 expectedIRHash,bytes uc,bytes inputRecord).
LeafProof=(uint16 anchorIndex,bytes32 bitmap,bytes32[] siblings). All earlier
Anchor fields retain order; the native inputRecord opening is appended after UC.
Reject aliases, noncanonical offsets/padding, trailing bytes and budget overflow.

Anchors (one anchor per distinct complete UC). Each anchor is one
complete canonical native UC with its claim fields and the two native openings.
Anchors have pairwise distinct UC bytes (byte-identical UCs are one anchor,
never two; a repeated or conflicting entry is rejected); several different UCs
of one shard, even of one root round, are separate anchors. Anchor count is not
bounded by the shard count, only by the profile parameter A_max below. Every
anchor's partition must be the policy partition and its shard a canonical
native shard ID; its shardConfHash, expectedStateRoot and expectedIRHash are
claim fields the batch authenticates against the UC (B1). The kernel result
orders exported leaves. Order anchors by first use in kernel leaf order:
scanning leaves in order, a leaf's anchorIndex is either an already-used index
or exactly the next unused one, and every anchor must be used. Require exactly
one LeafProof per leaf in kernel order, retaining duplicate-SID rejection, and
that the first d bits of each leaf's 32-byte SID equal the prefix bits of the
anchor it names (d that anchor's shard depth; never the current topology or a
transaction timestamp). Reject an out-of-range, skipped, unused, duplicated or
foreign anchor and any anchor table that is not exactly that function of the
exported leaves. Mint (one leaf) has exactly one anchor. Apply this to mint and
return alike. There is no convergence requirement: the plug-in submits whatever
(path, UC) pairs it holds.

The whole anchor table is authenticated by one `STATICCALL 0x0100`
(`CERT_BATCH_V2`): `version 2 | flags 0 | K | Claim[K]`, K the table length,
claims in table order, each `partition:u32 | shardLen:u16 | shard |
shardConfHash | expectedStateRoot | expectedIRHash | ucLen:u32 | uc`; `0x0101`
is never called. The call returns exactly 64 bytes `abi.encode(uint256(2),bool)`
and the composition requires `(2,true)`: one verdict for the table, no partial
success. Anchors may carry different root rounds, seals and epochs; B1 checks
each seal against its own epoch's permanent registry entry (any age: start <=
round <= the usable origin round O, and round < end for a closed epoch), with no
certificate-age window, common cut or EVM certificate at any anchor's round.
B1's own scan requires exactly d shard-tree siblings for the UC's own shard.

Opening is canonical tag(39002,[1,round,epoch,previousHash,stateHash,summary,
timestamp,blockHash,fees,executedTransactionsHash]) (arity 10). Version=1;
round/epoch/timestamp/fees unsigned u64; stateHash bstr32; other hash fields
null or bstr32; summary null or bstr within B1's summary limit. Enforce all
native B1 bounds, null/width/canonical rules. Require
H(inputRecord)==expectedIRHash and stateHash==expectedStateRoot.

Composition checks framing/budgets/Cfg/policy and obtains the kernel result,
then derives and checks the anchor table above and the gas gate below. The one
B1 0x0100 batch MUST authenticate both expected root and expected IR hash of
every anchor. Only after success may an anchor's opened timestamp authorize the
t<=timestamp comparison of the leaves routed to it (each leaf against its OWN
anchor only). For each ordered leaf call unchanged B1 0x0102 with sid, raw
leafValue and the root/path of that leaf's own anchor. Each 0x0102 result MUST be exactly 64 bytes encoding
(uint256(1),true), and the 0x0100 batch result (uint256(2),true); no partial success. The B1 profile hash is the
deployment's pinned any-age profile; do not invent one. Caller-supplied scalar
timestamps or unauthenticated IR hashes cannot authorize time checks.

## Resource and custody profile

Provisional intersected ceilings (unsupported/budget-exceeded rejects offline,
never fetches): J<=65536; UC<=16384 plus B1's tighter sublimits; PDR<=16384;
header<=2048; each MPT<=65 nodes; node<=1024; combined MPT bytes<=24576;
CBOR/RLP depth<=16, CBOR items<=32768; semantic history<=16384;
direct envelope<=65536; <=15 transfers including burn, <=16 leaves;
anchor UC<=8192, IR opening<=512, <=32 RSMT siblings per leaf, <=32 unicity
steps and exactly d shard-tree siblings per UC (d its own shard's depth, the
anchor's shard equal to the UC's); Cfg<=1024; bridge CBOR items J<=4096 (the
gate below); A<=A_max=16 distinct UC anchors
(a parser ceiling: the gas gate below decides each bundle); A<=L.
These bounds are the named parameters of `profile-v5.json` `limits`
(the single source for contract, oracle and plug-ins); a later profile version
may raise them, e.g. when multi-proof services land. The initial testnet
assumes few transactions per token.
<=2048 cumulative RSMT+shard-tree+unicity steps (each anchor counted once).
Bitmap popcount must equal the sibling count of every leaf path. Check
cumulative counts overflow-safely before allocation.

### Direct-call gas gate (7,000,000)

Native prices are the actual B1/B2 charges, with no shared or warm discount.
The one 0x0100 batch over the anchor table is charged
`G_batch = 60000 + 16*C + 500*K*(K-1) + 1100 + 29900*E + 6000*Q + 2000*A + 250*P`,
with C its request bytes, K the anchors, and E, S, Q, A, P its canonical
first-use grouping (distinct declared epochs; distinct complete seals and their
signature-map sizes; distinct claims and their shard-tree plus unicity steps),
computed from the request bytes alone (bft-core `b1ref.Group`). For leaf i with
`s_i` RSMT siblings: `G_leaf(i) = 2000 + 16*(136+32*s_i) + 250*(1+s_i)`. With
`B_kernel = 160 + pad32(B_cfg) + pad32(B_history)` the kernel request bytes and L
the exported leaf count: `G_kernel = 26000 + 20*B_kernel + 14000*L`. The
call-data allowance is `D_max = 4 + 128 + pad32(B_cfg) + pad32(B_env)` (the
two-bytes-argument TokenVerifier call) and the composing verifier's own
execution is 80 per envelope byte plus `G_items = 1000*J`, J the bridge CBOR
item occurrences: the item heads of the canonical Cfg, the policy body, every
anchor UC and every anchor IR opening, each encoded occurrence counted once
(tags and containers, scalar and string heads, every child and map key and
value; the contents of a byte string are opaque; an IR opening and the IR inside
its UC are two occurrences; repeated parser passes never add to J). J is also the
bridge's shared CBOR preflight budget: J<=4096, refused as BudgetExceeded as soon
as the next item would cross it, before any native call. Admission requires
`21000 + 16*D_max + 80*B_env + 1000*J + G_kernel + G_batch + sum_i G_leaf(i) + 1000000 <= 7000000`.
The fixed reserve covers Solidity scanning and copying, call and EIP-150
headroom and vault accounting. The gate is computed from complete bounded
scans, never from caller-declared costs, and is identical in the contract,
oracle and plug-ins. Every native call is forwarded exactly its computed
charge, so a malformed late call cannot consume the remaining transaction
budget. The gate is a conservative admission rule, not a measured fit: a bundle
inside the parser ceilings may still be BudgetExceeded. BudgetExceeded is
reported before any native call, never truncates history, omits leaves, selects
a latest UC or splits a redemption, and means "direct exit unavailable", not
"token invalid". The 7,000,000 transaction budget is the DN-B ordinary transaction capacity
(`maxGas` minus the system gas reserved for certificate transactions); it is
never raised implicitly (a larger ordinary capacity is a later profile version).
The parser ceilings do not promise that every admitted bundle passes the gate;
the gate admits or refuses each bundle. bft-core `briefs/b1-any-age-contract.md`
section 5 tabulates worked cases from signed native fixtures: with sixteen
8-sibling leaves, a 16,384-byte history and a 512-byte Cfg, one anchor of a
four-member committee gates at 4,301,234; sixteen anchors under one shared seal
at 6,759,824 (admitted) and under sixteen seals of distinct epochs at 7,568,324
(BudgetExceeded). Anything refused by the gate or above a ceiling is
BudgetExceeded or an input-size refusal before any native call.
Bounds are not additive entitlements or measured activation
prices. Freeze in canonical semantic profile/vectors before activation; native
x86-64/arm64 full-transaction measurements and final gas gates remain required.

### Assembly and refresh

The plug-in reconstructs every SID of the history and routes each to the
aggregator shard that serves its prefix (the policy names no topology).

Consolidated path (the default). Before assembling, the plug-in consolidates
the token with the state-transition SDK's built-in uc-consolidation flow (TS
`TokenProofClient.consolidate`, Rust `client::consolidate`): one `latest`
request to the shard of the newest proof returns that shard's proofs with its
partition view, authenticated against the enclosing UC with one seal-quorum
check; exact-root requests to the other participating shards return their
proofs from the same view; every proof is rechecked (binding, expiry, original
reference time <= the target IR timestamp). Each participating shard's
ordinary version 1 UC is derived from the authenticated view, so the anchor
table has one anchor per shard the leaves touch, all under one seal:
K = m <= min(L, 8), S = 1. The partition view V1 admits at most 8 shards
(`MaxPartitionViewLeaves`, an admission constant that a later view version may
raise; no other rule depends on it). The view never goes on chain: B1 and the
bridge verify each derived UC exactly as any UC, with no new trust assumption.
This is one deterministic consolidation attempt (two waves, no retry that
chases a newer seal), not convergence by repetition: the owner's section 14
rule stands, and the plug-in never re-queries until responses happen to share
a certificate. The master seal is an anchor like any other: its root round must
be covered by the registry's usable origin O, so a fresh one is waited for.

Per-SID path (the fallback). The plug-in assembles from per-SID proofs when
consolidation returns `unavailable`, whatever its reason and whether or not the
SDK marks it retryable (the SDK's reasons: `busy`, `limit_exceeded`,
`partition_view_unavailable`, `pending_publication`, `state_expired`,
`state_not_in_root`, `state_pending`, `state_unknown`, `target_not_retained`,
`unsupported_capability`, `unsupported_configuration`; a partition with more
shards than the view admits is one of them), and keeps the SDK's retryable flag
only as a hint for a later consolidation attempt. A failed consolidation is
not unavailability: every `ConsolidationError` (`cancelled`, `input`,
`integrity`, `invalid_response`, `rejected`, `server`, `timeout`, `transport`)
is the SDK's error, surfaced as it is and never a silent fallback. For each
used shard it fetches, concurrently, only the existing
aggregator `get_inclusion_proof.v2(stateId)` and keeps each response's path and
its UC as an inseparable pair, verifying locally the path against that UC's
root and the returned CD and t against the original history. A path is never
re-paired with a UC it does not independently verify against. The plug-in does
NOT re-query to make responses share a certificate: it builds the anchor table
from the distinct UCs it received, in first-use leaf order. A racing or
mismatched (path, UC) pair gets a bounded retry, then retryable unavailability
(never BudgetExceeded). The plug-in validates the complete envelope (including
the gas gate and every anchor's round against one observed EVM origin O) before
submission, and runs the same gate BEFORE creating a burn, refusing a burn
that cannot pass the gas gate (`txGasBudget`) even in the best case (the
consolidated bundle: K = min(m, L) anchors under one seal, S = 1, smallest
certificates, shortest paths), and the redemption path accepts up to
A_max distinct UCs (the per-SID fallback) whenever the gate passes (BudgetExceeded for an over-limit
bundle; no truncation or partial credit). Pending history and bundle
are persisted atomically for restart, aged pairs are revalidated or refetched.
There is no common cut, cross-shard synchronization or guarantee that fresh
proofs become available. Offline receipt verification is network-free and
accepts each transaction's own authenticated historical UC and round under the
historical-trust rules; refresh changes only external paths and UCs,
preserving exact M/T/CD/t/J.

Vault slots 0..7: lastNonce, locked L, credited D, paid P, entered,
lockDigest mapping base5, spentNullifier mapping base6, claimable mapping base7.
Nonce starts at 1, never wraps/reuses; locks remain permanently nonzero. No
administrative withdrawal. Each nonce has one spent word, zero->eta atomically
with recipient credit. Distinct competing burns contend on that same nonce.
`0<=P<=D<=L`, outstanding=L-D, claimable total=D-P,
balance=L-P+X with donations/forced value X>=0. Donations never authorize mint.
Claim requires caller credit>=amount>0 and to nonzero/not vault; under shared
guard debit credit/increase paid before CALL, revert all on failure. Only the
credited recipient redirects payment. Preserve custody on every verifier error.

## Deployment manifest and corpus

Schema v1 registry is keyed by tokenTypeHex (lowercase hex, no 0x).
`manifest.schema.json` defines structural rules; application installation also
MUST recompute identifiers, chainRef, Cfg/cfg, policy hashes, semantic-profile
hash and runtime/trust pins (the trust-base genesis EntryID; a release bundle by
exact-file digest), match
key to tokenTypeHex, reject ambiguous
network/chain/vault entries and inconsistent replacement records. JSON text is
never the Cfg preimage. Hash canonical published artifacts exactly, never an
unspecified JSON serialization. Artifact locations are installation metadata,
not verification dependencies. rpcUrls/proofEndpoints are optional untrusted
construction/submission/refresh sources and cannot repair missing embedded proof.
No invented deployment/runtime/configuration hashes are included in this PR.

The sole released corpus lives here; Go bridgeprofile is an independent oracle
and reference generator, not a second golden authority. Consumer pins require
protocol commit plus exact manifest digest, offline cache supported. Candidate
pins may break bootstrap cycles before merge; releases require merged pins.
Provenance, import and temporary regeneration rules are in vectors/README.md.
CI must reject missing/wrong corpus digests. Required families are config, wire,
unlock, policy, lock, history, proof, return and vault; cases carry preimages,
bytes, digests, semantic outcomes, leaf obligations, B1 requests/results,
version/profile and provenance. PR3 adds independent TS/Rust construction;
reading Go JSON in both stacks alone is not independent construction.
