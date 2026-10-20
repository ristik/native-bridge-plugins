#!/usr/bin/env python3
"""Disable named corpus/trust-fixture guards independently; restore all sources."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
mutations = [
    ('tools/vectors.py', "require(bool(HEX.fullmatch(expected)) and pin.strip() == expected, 'unexpected corpus digest')", 'test_vectors.CorpusTests.test_wrong_consumer_pin_rejected'),
    ('tools/vectors.py', "require(not path.is_symlink(), f'symlink forbidden: {path}')", 'test_vectors.CorpusTests.test_symlink_rejected'),
    ('tools/vectors.py', "require(bool(re.fullmatch(r'[0-9a-f]{40}', g['commit'])), 'generator requires full commit')", 'test_vectors.CorpusTests.test_floating_oracle_rejected'),
    ('tools/vectors.py', "require(actual_profile.get('trustModel') == expected_profile['trustModel'], 'unsupported trust model')", 'test_vectors.CorpusTests.test_abandoned_trust_model_rejected'),
    ('tools/vectors.py', "require(actual_profile.get('normativeArtifactSha256') == expected_profile['normativeArtifactSha256'], 'normative artifact pins mismatch')", 'test_vectors.CorpusTests.test_old_normative_pins_rejected'),
    ('tools/vectors.py', "require(bool(re.fullmatch(rb'[0-9a-f]{64}\\n', pin)), 'trust-base pin must be lowercase hex plus newline')", 'test_vectors.CorpusTests.test_trust_pin_format_rejected'),
    ('tools/vectors.py', "require(pinned == {'bundle': bundle.hex(), 'pin': pin.decode().strip()}, 'trust-base fixture differs from the pinned fixture')", 'test_vectors.CorpusTests.test_trust_fixture_mutation_rejected'),
]
for relative, guard, test in mutations:
    path = root / relative
    original = path.read_text()
    try:
        assert original.count(guard) == 1, guard
        path.write_text(original.replace(guard, 'pass  # mutation: guard disabled'))
        run = subprocess.run([sys.executable, '-B', '-m', 'unittest', test], cwd=root / 'tests/interop', capture_output=True, text=True)
        if run.returncode == 0 or 'FAIL:' not in run.stderr:
            sys.exit(f'mutation not caught by assertion: {test}\n{run.stdout}{run.stderr}')
        print(f'caught: {test}')
    finally:
        path.write_text(original)
