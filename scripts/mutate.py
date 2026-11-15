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
    (R + "trust.rs", "if seal.epoch != self.base.epoch {", "if false && seal.epoch != self.base.epoch {"),
    (R + "trust.rs", "if (counted.len() as u64) < tb.quorum_threshold {", "if false && (counted.len() as u64) < tb.quorum_threshold {"),
]

TS = [
    (T + "trust.ts", "if (!uc.unicitySeal.networkId.equals(this.network)) fail('ErrSealNetwork');", ""),
    (T + "trust.ts", "if (findNoTrustBaseEntry(r) !== null) return 'ErrNoEntryForEpoch';", ""),
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
