# Trust and remaining gates

Root certification authenticates the admitted aggregator root, not independent
correctness or non-equivocation of every transition. The private one-shard
profile retains ADR 0012's aggregator trust and archive-availability assumption.
A public universal minter does not authorize issuance. Certified EVM account/
storage evidence and mandatory issuance policy bind backing; the vault's live
nonce guard contains competing return histories for a single lock.

Offline historical verification is relative to installed authenticated trust
history/checkpoints. Old key lists alone are not a fresh checkpoint and cannot
exclude long-range attacks after retired quorum compromise. Keep original J
and all reference times forever with active histories; committee rotation does
not rewrite transactions. Missing evidence/epoch rejects without online fetch.

PR1 defines bytes/schema/ABI/tooling and scaffolds packages. PR2 supplies the
independent Go oracle/candidate; PR3 implements TS/Rust wrappers and independent
constructors and finalizes corpus pins; PR4 implements/meter-tests ureth;
PR5 implements custody/composition against real B1/B2; PR6 joins the native
round trip. Corpus CI remains red and PR1 draft while the candidate is absent.

Before activation: canonical profile/limits hash, actual runtime/config/genesis
pins, independent constructors, actual ureth alloc configuration, unchanged B1
composition regressions, x86-64/arm64 measurements and real native round trip.
Joined aggregator must speak SDK3 leaf semantics (aggregator-go sha-ae08165 or
verified descendant). Oracle/test doubles and rugregator alone do not establish
acceptance. No production deployment or public multi-shard/exit guarantee.

The original SDK companion plan is superseded: no SDK fork/patch, SP1 patches,
external bridge-plugin trust implementation, generic split support or detached
lock witness is part of this profile. Use bridge-core structural contracts;
native identity stays local because its ChainFamily union excludes this family.

bft-core is private. Corpus regeneration CI needs a read-only
`BFT_CORE_READ_TOKEN` repository secret scoped to that repository. No credential
is committed or auto-installed. The missing-corpus gate fails before access is
attempted; provision the read-only credential when importing the candidate.
