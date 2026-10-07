import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('protocol', ROOT / 'tools/check_protocol.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class FixedSdkTrustTests(unittest.TestCase):
    def setUp(self):
        self.data = (ROOT / 'protocol/vectors/config/sdk-root-trust-base.json').read_bytes()
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.document = json.loads(self.data)

    def test_exact_installed_bytes(self):
        self.assertEqual(self.digest, 'e503a064a16d43c5ad3d53bb8b859667781a349f26e7d4ca03446652741d3c08')
        self.assertEqual(len(self.data), 358)
        self.assertFalse(self.data.endswith(b'\n'))
        p.validate_sdk_trust_document(self.data, self.digest)

    def test_digest_mismatch(self):
        with self.assertRaisesRegex(AssertionError, 'SDK document digest mismatch'):
            p.validate_sdk_trust_document(self.data + b'\n', self.digest)

    def check_mutation(self, reason):
        data = json.dumps(self.document).encode()
        with self.assertRaisesRegex(AssertionError, reason):
            p.validate_sdk_trust_document(data, hashlib.sha256(data).hexdigest())

    def test_non_unit_weight_rejected(self):
        self.document['rootNodes'][0]['stake'] = '98'
        self.check_mutation('non-unit stake unsupported')

    def test_wrong_count_quorum_rejected(self):
        self.document['quorumThreshold'] = '2'
        self.check_mutation('SDK count quorum mismatch')

    def test_epoch_overflow_rejected(self):
        self.document['epoch'] = str(1 << 64)
        self.check_mutation('SDK epoch field outside uint64')

    def test_unsupported_document_version(self):
        self.document['version'] = '2'
        self.check_mutation('SDK document version')


if __name__ == '__main__':
    unittest.main()
