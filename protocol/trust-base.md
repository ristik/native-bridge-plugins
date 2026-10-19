# Unicity Trust Base trust input (protocol v5)

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

`trustBaseId` is the genesis EntryID. A lock proof's `trustBaseId` slot and
every manifest entry's `trustBase.genesisEntryId` name it. Two histories are
the same trust input exactly when they have the same network and genesis; the
latest held entry is not part of the identity, so a history that has grown is
still the one a proof names. The manifest's `trustBase.bundle` names a release
bundle an installation may start from by exact-file digest; it is installation
metadata, never the pin. A newer release bundle of the same history installs
under the same pin.

A digest and successful installation establish integrity, not authority:
provisioning authenticates the genesis out of band (the manifest, an
application release), and every later entry is authenticated only by its
predecessor's quorum.

## Certificate verification

Every unicity certificate, ordinary (aggregator inclusion proofs) and embedded
(the EVM lock certificate), is verified by the SDK under the entry of its own
seal epoch e:

1. the seal's network is the history's (else `SealNetwork`);
2. e newer than the latest held entry is `NoEntryForEpoch`, of the
   *unavailable* family: retryable once the history holds e, never invalid;
3. e before the genesis is `SealEpoch`;
4. the root round is in e's interval `[start_e, start_e+1)`, the upper bound
   open while e is the latest held entry (else `SealEpoch`);
5. native certificate structure (bft-go-base `IsValid`: input record rules,
   32-byte technical record hash, seal shape) and the recomputed unicity-tree
   root equal to the seal hash (else `CertStructure` and `SealRoot`);
6. the seal under e's committee with the native B1 rule: every signature is a
   valid one of a member of e (an unknown signer or an invalid signature fails
   the seal), at most 16 signatures, and the signers' weights reach e's
   threshold `floor(2W/3)+1` (else `QuorumNotMet`; on the embedded certificate
   the oracle names it `LockUC`).

TS uses `UnicityCertificateVerifier.verifyCertificate(history, uc,
{ partitionId })` for the embedded certificate and the SDK token verifier for
ordinary proofs; Rust uses `verify_certificate_of_partition` and
`verify_token_with_policy` with the history. The embedded certificate's own
partition is passed; the EVM partition, shard and configuration pins stay the
bridge's checks, on every call. No bridge-owned weighted verifier, epoch
resolver or trust-base store exists.

Seal signatures are 64 bytes (r||s) or 65 with a recovery suffix 0 or 1 that is
ignored, as in both SDKs and native B1; any other length or suffix is malformed.

## Evolution

Trust-base evolution is the SDK's and the wallet's. The wallet owns the one
history per network, persists it as a bundle, and on `NoEntryForEpoch` fetches
the entries after its latest held one from an aggregator
(`GET /api/v1/trustbases`, SDK fetch-and-retry loop), appends them (each
verified from its predecessor, held entries never replaced) and retries.
Receipt verification itself has no network capability: the plug-ins verify
against the history they are given and fetch nothing.

J stays byte-identical after certification. A lock certificate sealed in any
epoch the history holds verifies under that epoch's committee and interval, so
historical backing survives later rotations. Refresh may replace aggregator
paths and certificates under any held epoch while preserving M/T, CD and the
original t.

## Fixtures

The corpus carries the dev release bundle (`config/trust-base.bundle.cbor`)
and its genesis EntryID (`config/trust-base.genesis.entryid`), and each trust
case names a bundle and the pin it is installed under. They are test data, not
an authenticated deployment. `tests/interop/utb-dev` is the shared dev fixture
both SDKs carry byte for byte (epochs 1..4, weighted from epoch 2).
