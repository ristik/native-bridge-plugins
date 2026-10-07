# @unicitylabs/native-bridge-plugin

Native bridge plug-in over `@unicitylabs/state-transition-sdk@3.0.1` and
`@unicitylabs/bridge-core@0.1.0-bridge.2`. Not published (`private`); see `docs/plugins.md` at the
repository root.

```ts
const trust = TrustInput.fromJson(documentBytes, pinnedTrustBaseId);
const bridge = new NativeBridge(loadManifests(manifestJson), trust);
await bridge.verifyNativeTokenBytes(tokenBytes, 'receipt'); // fully offline
```

License: MIT OR Apache-2.0.
