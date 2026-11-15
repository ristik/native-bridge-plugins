# @unicitylabs/native-bridge-plugin

Native bridge v2 plug-in over `@unicitylabs/state-transition-sdk` `4.0.0-utb.c5840ef` (vendored). Not published (`private`). The
package root exports the shared bytes, errors and trust input (`TrustInput`, `withTrustRefresh`); the protocol 7 plug-in was removed
by bft-core#1106.

```ts
const trust = await TrustInput.fromBundle(bundleBytes, genesisEntryId); // tag-39015 release bundle
```

License: MIT OR Apache-2.0.

## Native bridge v2 (`@unicitylabs/native-bridge-plugin/nb2`)

The protocol 9 wallet API (bft-core#1103): `NativeBridgeV2` with `planDeposit`, `submitDeposit`, `collectDepositProof`, `mint`,
`transfer`, `split`, `planReturn`, `burn`, `buildRedeem`, `submitRedeem` and `reconcile`, over a gateway RPC, an aggregator and a
durable journal. Guide: [docs/nb2-wallet-guide.md](../../docs/nb2-wallet-guide.md); journal format:
[docs/nb2-journal.md](../../docs/nb2-journal.md). Tests replay the shared vectors (`protocol/vectors/nb2`) and run the reference
scenario against an offline simulator (`test/nb2`).
