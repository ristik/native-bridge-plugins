import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('vectors', ROOT / 'tools/vectors.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'source'
        self.root.mkdir()
        for family in v.FAMILIES:
            (self.root / family).mkdir()
            (self.root / family / 'synthetic.json').write_text('{"testOnly":true}\n')
        profile = (ROOT / 'protocol/profile-v2.json').read_bytes()
        for name in ('sdk-root-trust-base.json', 'sdk-root-trust-base.provenance.json'):
            (self.root / 'config' / name).write_bytes((ROOT / 'protocol/vectors/config' / name).read_bytes())
        (self.root / 'config/semantic-profile.json').write_bytes(profile)
        self.provenance = {'protocolVersion': 2, 'sdkVersion': '3.0.1', 'semanticProfileSha256': hashlib.sha256(profile).hexdigest(), 'generator': {'repository': v.REPOSITORY, 'commit': 'b'*40, 'command': ['go', 'run', './cmd/test-generator', '-out', '{output}']}}
        self.pin = v.seal(self.root, self.provenance)

    def test_import_and_check(self):
        dest = Path(self.tmp.name) / 'destination'
        v.import_corpus(self.root, dest, self.pin)
        self.assertEqual(v.inventory(self.root), v.inventory(dest))
        self.assertEqual(v.check(dest, self.pin), self.provenance)

    def test_mutated_fixture_rejected(self):
        (self.root / 'wire/synthetic.json').write_text('{}\n')
        with self.assertRaisesRegex(v.CorpusError, 'inventory/digest mismatch'):
            v.check(self.root)

    def test_missing_digest_rejected(self):
        (self.root / 'MANIFEST.sha256').unlink()
        with self.assertRaisesRegex(v.CorpusError, 'digest missing'):
            v.check(self.root)

    def test_wrong_consumer_pin_rejected(self):
        with self.assertRaisesRegex(v.CorpusError, 'unexpected corpus digest'):
            v.check(self.root, 'f'*64)

    def test_extra_file_rejected(self):
        (self.root / 'wire/extra.json').write_text('{}')
        with self.assertRaisesRegex(v.CorpusError, 'inventory/digest mismatch'):
            v.check(self.root)

    def test_deleted_file_rejected(self):
        (self.root / 'wire/synthetic.json').unlink()
        with self.assertRaisesRegex(v.CorpusError, 'missing family'):
            v.check(self.root)

    def test_symlink_rejected(self):
        original = self.root / 'wire/synthetic.json'
        outside = Path(self.tmp.name) / 'outside.json'
        outside.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(outside)
        with self.assertRaisesRegex(v.CorpusError, 'symlink forbidden'):
            v.check(self.root)

    def test_failed_import_preserves_destination(self):
        dest = Path(self.tmp.name) / 'destination'
        v.import_corpus(self.root, dest, self.pin)
        before = v.inventory(dest)
        (self.root / 'wire/synthetic.json').write_text('changed')
        with self.assertRaisesRegex(v.CorpusError, 'inventory/digest mismatch'):
            v.import_corpus(self.root, dest, self.pin)
        self.assertEqual(v.inventory(dest), before)
        v.check(dest, self.pin)

    def test_semantic_profile_pin_rejected(self):
        p = copy.deepcopy(self.provenance)
        p['semanticProfileSha256'] = 'f'*64
        with self.assertRaisesRegex(v.CorpusError, 'semantic profile artifact mismatch'):
            v.seal(self.root, p)

    def test_abandoned_trust_model_rejected(self):
        import json
        profile = json.loads((self.root / 'config/semantic-profile.json').read_bytes())
        profile['trustModel']['scope'] = 'native-epoch-indexed-v1'
        data = json.dumps(profile).encode()
        (self.root / 'config/semantic-profile.json').write_bytes(data)
        p = copy.deepcopy(self.provenance)
        p['semanticProfileSha256'] = v.digest(data)
        with self.assertRaisesRegex(v.CorpusError, 'unsupported trust model'):
            v.seal(self.root, p)

    def test_old_normative_pins_rejected(self):
        import json
        profile = json.loads((self.root / 'config/semantic-profile.json').read_bytes())
        profile['normativeArtifactSha256']['protocol/interop.md'] = 'f' * 64
        data = json.dumps(profile).encode()
        (self.root / 'config/semantic-profile.json').write_bytes(data)
        p = copy.deepcopy(self.provenance)
        p['semanticProfileSha256'] = v.digest(data)
        with self.assertRaisesRegex(v.CorpusError, 'normative artifact pins mismatch'):
            v.seal(self.root, p)

    def test_sdk_document_fixture_mutation_rejected(self):
        (self.root / 'config/sdk-root-trust-base.json').write_bytes(b'{}')
        with self.assertRaisesRegex(v.CorpusError, 'SDK trust fixture mismatch'):
            v.seal(self.root, self.provenance)

    def test_old_protocol_rejected(self):
        p = copy.deepcopy(self.provenance)
        p['protocolVersion'] = 1
        with self.assertRaisesRegex(v.CorpusError, 'unexpected protocol/SDK'):
            v.seal(self.root, p)

    def test_floating_oracle_rejected(self):
        p = copy.deepcopy(self.provenance)
        p['generator']['commit'] = 'main'
        with self.assertRaisesRegex(v.CorpusError, 'full commit'):
            v.seal(self.root, p)

    def test_manifest_digest_rejected(self):
        (self.root / 'MANIFEST.sha256').write_text('c'*64+'\n')
        with self.assertRaisesRegex(v.CorpusError, 'manifest digest mismatch'):
            v.check(self.root)

    def test_wrong_profile_version_rejected(self):
        (self.root / 'VERSION').write_text('1\n')
        with self.assertRaisesRegex(v.CorpusError, 'unexpected corpus VERSION'):
            v.check(self.root)


if __name__ == '__main__':
    unittest.main()
