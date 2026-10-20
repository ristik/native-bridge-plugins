# Shared dev trust-base fixture

Byte-identical to `tests/fixtures/utb/dev/` in ristik/state-transition-sdk-js and `e2e/dev/` in
ristik/state-transition-sdk-rust, emitted by the UTB vector generator (`-dev-out`): a release bundle of epochs 1..4
(weighted committees from epoch 2), its genesis EntryID (the pin) and the genesis in bft-go-base JSON form.
Test data, never a real network trust base.
