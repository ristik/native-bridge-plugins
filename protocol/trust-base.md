# Unicity Trust Base trust input (native bridge v2)

The trust input is the network's Unicity Trust Base history: the append-only
chain of root trust-base entries (RootTrustBaseV2, tag 39000), one per root
epoch, each after the genesis witnessed by its predecessor's committee. The
plug-ins, the SDKs and the oracle install the same history from the same
release bundle and verify every certificate against it.

## Installation and identity

A release bundle is a complete GetTrustBase response (tag 39015, status OK, no
continuation) holding the genesis entry and every later entry in ascending,
contiguous epochs. Installation requires all of:

- the EntryID of the bundle's genesis entry equals the pin (else
  `TrustBaseDigest`);
- the bundle is canonical, complete and contiguous, and every later entry
  carries a strict quorum of its predecessor's members over its unsigned bytes
  (else `TrustBase`).

`EntryID = SHA-256(sigBytes)`, sigBytes being the entry with its signatures
encoded as CBOR null. An absent `stateHash` or `changeRecordHash` is CBOR null,
a present one exactly 32 bytes (bft-go-base#3); the shared UTB vectors pin the
rule for both SDKs.

Γ.rootGenesis32 is the EntryID of the authenticated genesis trust-base entry.
Γ.network must equal the installed history's network. A later entry or bundle
digest is not the identity. Γ.executionGenesis32 identifies the authenticated
execution genesis of the continuous EVM history bound to that trust input and
partition/shard by the deployment.

A digest and successful installation establish integrity, not authority:
provisioning authenticates the genesis out of band (the manifest, an
application release), and every later entry is authenticated only by its
predecessor's quorum.

## Certificate verification

Every unicity certificate, ordinary (aggregator inclusion proofs) and embedded
(the EVM UC of a deposit or seal receipt), is verified under the entry of its
own seal epoch e:

1. the seal's network is the history's (else `SealNetwork`);
2. e newer than the latest held entry is `NoEntryForEpoch`, of the
   *unavailable* family: retryable once the history holds e, never invalid;
3. e before the genesis is `SealEpoch`;
4. the root round is in e's interval `[start_e, start_e+1)`, the upper bound
   open while e is the latest held entry (else `SealEpoch`);
5. native certificate structure (bft-go-base `IsValid`: input record rules,
   32-byte technical record hash, seal shape) and the recomputed unicity-tree
   root equal to the seal hash (else `CertStructure` and `SealRoot`);
6. the seal under e's committee with the upstream seal rule: each supplied
   signature is judged alone and counts its member's weight only if it is
   exactly 65 bytes `r||s||v` (`1 <= r < n`, `1 <= s <= n/2`, `v` in 0..3) whose
   single recovery over SHA-256 of the seal bytes yields that member's key; an
   unknown signer and any other signature count zero and never fail the seal;
   at most 16 signatures; the counted weights reach e's threshold
   `floor(2W/3)+1` (else `QuorumNotMet`).

For NB2 the per-UC order is frozen as: encoding
(UnsupportedCertificateEncoding), step 1 (SealNetwork), step 5 (CertStructure,
SealRoot), then the authority verdict, steps 2–4 and 6 together (epoch entry,
round interval, quorum). On chain the generic certificate primitive returns
one result for the authority verdict, so its on-chain name is QuorumNotMet for
an aggregator UC and DepositUC for the EVM UC; NoEntryForEpoch and SealEpoch
are wallet-side refinements. For an EVM receipt UC, require the configured EVM
partition and shard; supply no independently expected ShardConfHash and no PDR.
Authenticate the UC's actual ShardConfHash, InputRecord and TRHash through the
complete shard/unicity paths and seal. Apply native certificate structural
checks, then the upstream per-signature weighting rule above. A signature that
fails that weighting rule contributes zero; legacy bridge pre-scans MUST NOT
introduce an additional rejection solely for its length or recovery byte. This
does not waive native certificate structural constraints. NoEntryForEpoch
remains retryable for wallets. Other EVM certificate-verification failures map to
DepositUC; aggregator certificate failures use the named NB2 certificate rules.
The deployment-binding and continuous-execution-history assumptions in
interop.md apply. Protocol 7's LockUC/CertSigLength compatibility notes are
historical and do not define NB2 acceptance.

A seal signature value may be any byte string: only an exact canonical 65-byte
recoverable signature of its member has weight, and the recovery byte is
binding (never discarded, normalized or replaced by the other parity). An empty
value is refused by the native seal validation. The witnesses of a trust-base
ENTRY are a different object and stay strict: a bad or unknown extra signature
refuses a successor entry.

## Evolution

Trust-base evolution is the SDK's and the wallet's. The wallet owns the one
history per network, persists it as a bundle, and on `NoEntryForEpoch` fetches
the entries after its latest held one from an aggregator
(`GET /api/v1/trustbases`, SDK fetch-and-retry loop), appends them (each
verified from its predecessor, held entries never replaced) and retries.
Receipt verification itself has no network capability: the plug-ins verify
against the history they are given and fetch nothing.

J stays byte-identical after certification. A deposit or seal receipt
certificate sealed in any epoch the history holds verifies under that epoch's
committee and interval, so historical backing survives later rotations. Refresh may replace aggregator
paths and certificates under any held epoch while preserving M/T, CD and the
original t.

## Fixtures

The corpus carries the dev release bundle (`config/trust-base.bundle.cbor`)
and its genesis EntryID (`config/trust-base.genesis.entryid`), and each trust
case names a bundle and the pin it is installed under. They are test data, not
an authenticated deployment. `tests/interop/utb-dev` is the shared dev fixture
both SDKs carry byte for byte (epochs 1..4, weighted from epoch 2).
