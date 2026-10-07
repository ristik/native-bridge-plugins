#!/usr/bin/env python3
"""Disable three independent corpus guards, verify named tests fail, restore."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
path = root / 'tools/vectors.py'
original = path.read_text()
mutations = [
    ("require(bool(HEX.fullmatch(expected)) and pin.strip() == expected, 'unexpected corpus digest')", 'test_wrong_consumer_pin_rejected'),
    ("require(not path.is_symlink(), f'symlink forbidden: {path}')", 'test_symlink_rejected'),
    ("require(bool(re.fullmatch(r'[0-9a-f]{40}', g['commit'])), 'generator requires full commit')", 'test_floating_oracle_rejected'),
]
try:
    for guard, test in mutations:
        assert original.count(guard) == 1, guard
        path.write_text(original.replace(guard, 'pass  # mutation: guard disabled'))
        run = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'test_vectors.CorpusTests.' + test], cwd=root / 'tests/interop', capture_output=True, text=True)
        if run.returncode == 0 or 'FAIL:' not in run.stderr:
            sys.exit(f'mutation not caught by assertion: {test}\n{run.stdout}{run.stderr}')
        print(f'caught: {test}')
        path.write_text(original)
finally:
    path.write_text(original)
