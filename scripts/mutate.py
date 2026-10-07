#!/usr/bin/env python3
"""Guard mutation check: disable each listed guard once, require a named test to fail, restore.

  python3 scripts/mutate.py rust   # needs CARGO_TARGET_DIR
  python3 scripts/mutate.py ts

A guard whose removal no test catches is reported (and is documented in the PR when it is a
deliberate redundancy with an SDK check)."""
import os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = "crates/native-bridge-sdk-ext/src/"
T = "packages/native-bridge-plugin/src/"

RUST = [
    (R + "unlock.rs", "if sig.normalize_s().is_some() {", "if false && sig.normalize_s().is_some() {"),
    (R + "unlock.rs", "if recovered != *key {", "if false && recovered != *key {"),
    (R + "history.rs", "if cd.tx_hash != tx_hash || cd.expires_at != tx_deadline {", "if cd.tx_hash != tx_hash {"),
    (R + "history.rs", "        if t >= e {", "        if false && t >= e {"),
    (R + "history.rs", "if BigUint::from_bytes_be(amt) != BigUint::from_bytes_be(&out.amount) {", "if false && BigUint::from_bytes_be(amt) != BigUint::from_bytes_be(&out.amount) {"),
    (R + "lockproof.rs", "if h(lp.pdr).as_slice() != uc.shard_configuration_hash.as_slice() {", "if false && h(lp.pdr).as_slice() != uc.shard_configuration_hash.as_slice() {"),
    (R + "lockproof.rs", "if code_hash != dep.vault_code_hash {", "if false && code_hash != dep.vault_code_hash {"),
    (R + "lockproof.rs", "if &padded != expected_digest {", "if false && &padded != expected_digest {"),
    (R + "mpt.rs", "if value.is_empty() || used != nodes.len() {", "if value.is_empty() {"),
    (R + "token.rs", "if leaf.reference_time > uc.input_record.timestamp {", "if false && leaf.reference_time > uc.input_record.timestamp {"),
    (R + "token.rs", "if uc.unicity_tree_certificate.partition_identifier != dep.policy.partition", "if false && uc.unicity_tree_certificate.partition_identifier != dep.policy.partition"),
    (R + "trust.rs", "if seal.epoch != self.base.epoch {", "if false && seal.epoch != self.base.epoch {"),
    (R + "trust.rs", "if (counted.len() as u64) < tb.quorum_threshold {", "if false && (counted.len() as u64) < tb.quorum_threshold {"),
    (R + "envelope.rs", "if h(&anchor.input_record) != anchor.expected_ir_hash {", "if false && h(&anchor.input_record) != anchor.expected_ir_hash {"),
    (R + "proof.rs", "if old.certification_data != new.certification_data\n            || old.reference_time != new.reference_time\n        {", "if false {"),
]

TS = [
    (T + "unlock.ts", "if (r === 0n || r >= N || s === 0n || s > HALF_N) fail('ErrUnlockScalars');", "if (r === 0n || r >= N || s === 0n) fail('ErrUnlockScalars');"),
    (T + "unlock.ts", "if (recovered === null || !eq(recovered, key33)) fail('ErrUnlockKey');", "if (recovered === null) fail('ErrUnlockKey');"),
    (T + "history.ts", "if (!eq(cd.txHash, txHash) || cd.expiresAt !== txDeadline) fail('ErrCDMismatch');", "if (!eq(cd.txHash, txHash)) fail('ErrCDMismatch');"),
    (T + "history.ts", "if (txDeadline !== null && t >= txDeadline) fail('ErrDeadlineExpired');", ""),
    (T + "history.ts", "if (be(amt) !== be(out.amount)) fail('ErrReturnAmount');", ""),
    (T + "lockproof.ts", "if (!eq(H(lp.pdr), uc.shardConfigurationHash)) fail('ErrEvmConfigHash');", ""),
    (T + "lockproof.ts", "if (!eq(hdr.stateRoot, uc.inputRecord.hash)) fail('ErrHeaderRoot');", ""),
    (T + "lockproof.ts", "if (!eq(code, dep.vaultCodeHash)) {", "if (false) {"),
    (T + "lockproof.ts", "if (!eq(padded, expectedDigest)) fail('ErrLockDigest');", ""),
    (T + "mpt.ts", "if (value.length === 0 || used !== nodes.length) fail('ErrMptMalformed');", "if (value.length === 0) fail('ErrMptMalformed');"),
    (T + "verifier.ts", "if (leaf.referenceTime > uc.inputRecord.timestamp) fail('ErrReferenceTimeFuture');", ""),
    (T + "verifier.ts", "if (uc.unicityTreeCertificate.partitionIdentifier !== BigInt(dep.policy.partition) ||", "if (false &&  uc.unicityTreeCertificate.partitionIdentifier !== BigInt(dep.policy.partition) ||"),
    (T + "trust.ts", "if (seal.epoch !== this.base.epoch) fail('ErrEpochMismatch');", ""),
    (T + "trust.ts", "if ((await rule.verify(this.base, uc.unicitySeal)).status !== VerificationStatus.OK) fail('ErrQuorumNotMet');", ""),
    (T + "envelope.ts", "if (!eq(H(a.inputRecord), a.expectedIRHash)) fail('ErrInputRecordMismatch');", ""),
    (T + "proof.ts", "if (!eq(old[i].certificationData.toCBOR(), fresh[i].certificationData.toCBOR()) || old[i].referenceTime !== fresh[i].referenceTime) {", "if (false) {"),
]


def run(kind):
    items = RUST if kind == "rust" else TS
    cmd = (["cargo", "test", "-j", "4", "-p", "native-bridge-sdk-ext", "--no-fail-fast"] if kind == "rust"
           else ["npx", "tsx", "--test"] + sorted(f"test/{f}" for f in os.listdir(os.path.join(ROOT, "packages/native-bridge-plugin/test")) if f.endswith(".test.ts")))
    cwd = ROOT if kind == "rust" else os.path.join(ROOT, "packages/native-bridge-plugin")
    survived = []
    only = os.environ.get('ONLY')
    for path, old, new in items:
        if only and only not in path + old:
            continue
        full = os.path.join(ROOT, path)
        src = open(full).read()
        if src.count(old) != 1:
            print(f"SKIP (pattern not unique/found): {path}: {old[:60]}")
            survived.append((path, old, "pattern"))
            continue
        open(full, "w").write(src.replace(old, new))
        try:
            r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        finally:
            open(full, "w").write(src)
        out = r.stdout + r.stderr
        failed = [l for l in out.splitlines() if l.startswith("test ") and l.endswith("FAILED") or l.startswith("✖")]
        status = "CAUGHT" if r.returncode != 0 and failed else ("COMPILE-ERROR" if r.returncode != 0 else "SURVIVED")
        print(f"{status:9} {path}: {old[:70]}")
        for l in failed[:2]:
            print("          ", l.strip()[:110])
        if status != "CAUGHT":
            survived.append((path, old, status))
    print(f"\n{len(items) - len(survived)}/{len(items)} guards caught")
    return 0 if not survived else 1


if __name__ == "__main__":
    sys.exit(run(sys.argv[1]))
