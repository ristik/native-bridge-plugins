# Trust and remaining gates

Root certification authenticates the admitted aggregator root, not independent
correctness or non-equivocation of every transition. The private one-shard
profile retains ADR 0012's aggregator trust and archive-availability assumption.
A public universal minter does not authorize issuance. Certified EVM account/
storage evidence and mandatory issuance policy bind backing; the vault's live
nonce guard contains competing return histories for a single lock.

Offline receipt verifies against the network's Unicity Trust Base history,
installed from a release bundle under its genesis EntryID (the trustBaseId every
lock proof and manifest names). Each ordinary/embedded seal is verified by the
SDK under the entry of its own epoch: weighted quorum, the B1 seal rule, the
epoch's root-round interval. A seal of an epoch the history does not hold yet is
retryable (`NoEntryForEpoch`); the wallet appends newer entries, each witnessed
by its predecessor, and the plug-ins fetch nothing. Integrity of the bundle does
not authenticate the genesis; provisioning binds it to the native network/root
genesis. See [the byte and API contract](../../protocol/trust-base.md).

J is immutable. A lock certificate of any held epoch verifies under that epoch's
committee, so backing survives rotations; proof refresh may replace paths/UCs
under any held epoch, preserving M/T/CD/t. Native B1 return rules and live
window remain unchanged.

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

bft-core and native-bridge-plugins are public. Corpus regeneration CI checks out
the exact provenance commit anonymously; no repository secret is needed. No credential
is committed or auto-installed. The integrity gate verifies the imported sealed
corpus before regeneration.
