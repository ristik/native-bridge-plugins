# @unicitylabs/native-bridge-plugin

Native bridge plug-in over `@unicitylabs/state-transition-sdk` `4.0.0-utb.c5840ef` (vendored) and
`@unicitylabs/bridge-core@0.1.0-bridge.2`. Not published (`private`); see `docs/plugins.md` at the
repository root.

```ts
const trust = await TrustInput.fromBundle(bundleBytes, genesisEntryId); // tag-39015 release bundle
const bridge = new NativeBridge(loadManifests(manifestJson), trust);
await bridge.verifyNativeTokenBytes(tokenBytes, 'receipt'); // fully offline
```

License: MIT OR Apache-2.0.

## Native bridge v2 (`@unicitylabs/native-bridge-plugin/nb2`)

The protocol 9 wallet API (bft-core#1103): `NativeBridgeV2` with `planDeposit`, `submitDeposit`, `collectDepositProof`, `mint`,
`transfer`, `split`, `planReturn`, `burn`, `buildRedeem`, `submitRedeem` and `reconcile`, over a gateway RPC, an aggregator and a
durable journal. Guide: [docs/nb2-wallet-guide.md](../../docs/nb2-wallet-guide.md); journal format:
[docs/nb2-journal.md](../../docs/nb2-journal.md). Tests replay the shared vectors (`protocol/vectors/nb2`) and run the reference
scenario against an offline simulator (`test/nb2`).
