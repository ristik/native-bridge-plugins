# native-bridge-sdk-ext 0.1.0

Private no_std skeleton with alloc-compatible SDK and explicitly owned crypto
dependencies. PR3 adds the pure semantics core, recovery equality, strict
history and embedded offline lock proof under one fixed unit-weight SDK trust
base, plus export. Existing SDK count-quorum verification stays unchanged.
Trust-base updates/fetching, weights and epoch evolution are deferred to common
SDK work (#421); optional host transport is construction-only. No SP1 or SDK patches.
