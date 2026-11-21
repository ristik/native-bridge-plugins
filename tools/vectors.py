#!/usr/bin/env python3
"""Check the independently produced NB2 continuation vectors and their manifests."""
import argparse
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "protocol/vectors/nb2-continuation-v1.1"
PINNED = {
    "MANIFEST": "3be02f4163a1a9e06d5b83c0a50ab8468c6a060c1352d3a969a96b477be28034",
    "transcripts/MANIFEST": "39657f1e66eec4c9b1c02e91feb109999cb7d64e8c60ade2110f70dfd8f9220e",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check():
    count = 0
    for name, expected in PINNED.items():
        manifest = ROOT / name
        if digest(manifest) != expected:
            raise ValueError(f"manifest digest mismatch for {name}")
        for entry in manifest.read_text().splitlines():
            expected, filename = entry.split(None, 1)
            if digest(manifest.parent / filename) != expected:
                raise ValueError(f"vector digest mismatch for {filename}")
            count += 1
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check"])
    parser.parse_args()
    print(f"Verified {check()} NB2 continuation fixture files")
