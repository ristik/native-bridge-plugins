#!/usr/bin/env python3
"""Disable named corpus/fixed-profile guards independently; restore all sources."""
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
    ('tools/vectors.py', "require(files.get(key) == (ROOT / 'protocol/vectors' / key).read_bytes(), 'SDK trust fixture mismatch')", 'test_vectors.CorpusTests.test_sdk_document_fixture_mutation_rejected'),
    ('tools/check_protocol.py', "assert hashlib.sha256(data).hexdigest() == expected_digest, 'SDK document digest mismatch'", 'test_sdk_trust.FixedSdkTrustTests.test_digest_mismatch'),
    ('tools/check_protocol.py', "assert doc['version'] == '1', 'SDK document version'", 'test_sdk_trust.FixedSdkTrustTests.test_unsupported_document_version'),
    ('tools/check_protocol.py', "assert all(node['stake'] == '1' for node in doc['rootNodes']), 'non-unit stake unsupported'", 'test_sdk_trust.FixedSdkTrustTests.test_non_unit_weight_rejected'),
    ('tools/check_protocol.py', "assert n > 0 and doc['quorumThreshold'] == str(n - (n - 1) // 3), 'SDK count quorum mismatch'", 'test_sdk_trust.FixedSdkTrustTests.test_wrong_count_quorum_rejected'),
    ('tools/check_protocol.py', "assert isinstance(value, str) and value == str(int(value)) and 0 <= int(value) < 1 << 64, 'SDK epoch field outside uint64'", 'test_sdk_trust.FixedSdkTrustTests.test_epoch_overflow_rejected'),
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
