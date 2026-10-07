import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('vectors', ROOT / 'tools/vectors.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


@unittest.skipUnless(shutil.which('go'), 'Go required for pinned generator integration')
class RegenerateTests(unittest.TestCase):
    def test_pinned_oracle_ignores_dirty_worktree_and_compares_bytes(self):
        with tempfile.TemporaryDirectory(prefix='nbp-generator-test-') as tmp:
            tmp = Path(tmp)
            oracle, corpus = tmp / 'oracle', tmp / 'corpus'
            (oracle / 'cmd/test-generator').mkdir(parents=True)
            (oracle / 'go.mod').write_text('module test.invalid/oracle\n\ngo 1.22\n')
            profile = (ROOT / 'protocol/profile-v2.json').read_bytes()
            files = {f'{family}/synthetic.json': '{}\n' for family in v.FAMILIES}
            files['config/semantic-profile.json'] = profile.decode()
            for name in ('sdk-root-trust-base.json', 'sdk-root-trust-base.provenance.json'):
                files['config/' + name] = (ROOT / 'protocol/vectors/config' / name).read_text()
            entries = ',\n'.join(json.dumps(name) + ':' + json.dumps(data) for name, data in files.items())
            program = 'package main\nimport ("os"; "path/filepath")\nfunc main() {\n'
            program += 'files := map[string]string{\n' + entries + ',\n}\n'
            program += 'for name, data := range files { path := filepath.Join(os.Args[1],name); if err := os.MkdirAll(filepath.Dir(path),0755); err != nil {panic(err)}; if err := os.WriteFile(path,[]byte(data),0644); err != nil {panic(err)} }\n}\n'
            (oracle / 'cmd/test-generator/main.go').write_text(program)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(oracle), *args], stderr=subprocess.DEVNULL, text=True).strip()
            git('init', '-q')
            git('add', '.')
            git('-c', 'user.name=Protocol test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'test oracle')
            commit = git('rev-parse', 'HEAD')
            for f in v.FAMILIES:
                (corpus / f).mkdir(parents=True)
                (corpus / f / 'synthetic.json').write_bytes(b'{}\n')
            (corpus / 'config/semantic-profile.json').write_bytes(profile)
            for name in ('sdk-root-trust-base.json', 'sdk-root-trust-base.provenance.json'):
                (corpus / 'config' / name).write_bytes((ROOT / 'protocol/vectors/config' / name).read_bytes())
            provenance = {'protocolVersion': 2, 'sdkVersion': '3.0.1', 'semanticProfileSha256': v.digest(profile), 'generator': {'repository': v.REPOSITORY, 'commit': commit, 'command': ['go', 'run', './cmd/test-generator', '{output}']}}
            v.seal(corpus, provenance)
            # A dirty companion checkout must never be executed.
            (oracle / 'cmd/test-generator/main.go').write_text('broken uncommitted source')
            v.regenerate(corpus, oracle)
            # Change/reseal a fixture: internally consistent artifact still fails
            # independent reconstruction against the pinned oracle commit.
            (corpus / 'wire/synthetic.json').write_bytes(b'{"tampered":true}\n')
            v.seal(corpus, provenance)
            with self.assertRaisesRegex(v.CorpusError, 'unexpected corpus digest'):
                v.regenerate(corpus, oracle)
