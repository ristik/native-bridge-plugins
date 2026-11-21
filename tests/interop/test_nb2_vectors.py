"""The native bridge v2 vector file (bft-core#1099): pinned digest, protocol and profile binding, rule coverage."""
import hashlib
import json
from pathlib import Path
import unittest
from tools.vectors import check

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / 'protocol/vectors/nb2'


class NB2VectorTests(unittest.TestCase):
    def setUp(self):
        self.raw = (DIR / 'nb2-vectors.json').read_bytes()
        self.doc = json.loads(self.raw)

    def test_digest(self):
        want = (DIR / 'nb2-vectors.json.sha256').read_text().strip()
        self.assertEqual(want, '74cdb261ba65c0b052a34bc7cd2dbcc91a5d0f7fc7cca01f3639a7d4990c11ed')
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), want)

    def test_profile_and_protocol(self):
        self.assertEqual(self.doc['nativeBridgeProtocolVersion'], 9)
        self.assertEqual(self.doc['semanticProfileHash'],
                         '0xa9da5f02d629fd81f4e4ce61566e69c234157b106749e18221598909097d144f')

    def test_every_reachable_rule_is_vectored(self):
        named = set()
        for section in ('verifier', 'sealReceipts', 'gapProofs', 'chainFolds', 'segmentLogs'):
            for v in self.doc[section]:
                named.add(v['expect'].get('error'))
                named.add(v.get('innerRule'))
        for v in self.doc['config']:
            named.update((v['verifier'].get('error'), v['constructor'].get('error')))
        for v in self.doc['vault']:
            for s in v['steps']:
                named.update((s['expect'].get('error'), s.get('innerError')))
        for v in self.doc['wallet']['capacity'] + self.doc['wallet']['stateReads'] + self.doc['wallet']['companions']:
            named.add(v['expect'].get('error'))
        for rule in self.doc['rules']:
            self.assertIn(rule['name'], named, rule['name'])


class ContinuationVectorTests(unittest.TestCase):
    def test_pinned_manifests_and_files(self):
        self.assertEqual(check(), 283)


if __name__ == '__main__':
    unittest.main()
