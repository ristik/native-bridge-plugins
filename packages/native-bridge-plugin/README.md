# @unicitylabs/native-bridge-plugin 0.1.0

Private skeleton: exports only profile constants. No verifier or wallet policy
is implemented yet; callers must not treat this package as issuance authority.
PR3 adds createNativeBridgePlugin, bridgeTokenPlugin, verifyNativeToken,
mintBridgedToken, burnForReturn, buildReturnProof and claim, with strict wrappers
and a network-incapable verification API. Construction/submission has separate
optional transport. Native identity types stay local; do not cast unicity-native
into bridge-core's tron|eip155 ChainFamily. Standard BridgePayments defaults to
null deadlines; explicit native options bypass its deadline-less interface.

Verification uses one fixed unit-weight SDK RootTrustBase and the existing SDK
count quorum. Trust-base updates/fetching, arbitrary weights and epoch evolution
are deferred to common SDK work (#421), not implemented by this plug-in.
