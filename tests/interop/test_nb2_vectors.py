"""The native bridge v2 vector file (bft-core#1099): pinned digest, protocol and profile binding, rule coverage."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / 'protocol/vectors/nb2'


class NB2VectorTests(unittest.TestCase):
    def setUp(self):
        self.raw = (DIR / 'nb2-vectors.json').read_bytes()
        self.doc = json.loads(self.raw)

    def test_digest(self):
        want = (DIR / 'nb2-vectors.json.sha256').read_text().strip()
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), want)

    def test_profile_and_protocol(self):
        profile = (ROOT / 'protocol/profile.json').read_bytes()
        self.assertEqual(self.doc['nativeBridgeProtocolVersion'], json.loads(profile)['nativeBridgeProtocolVersion'])
        self.assertEqual(self.doc['semanticProfileHash'], '0x' + hashlib.sha256(profile).hexdigest())

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


if __name__ == '__main__':
    unittest.main()
