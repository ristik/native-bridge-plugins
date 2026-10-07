import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('joined', Path(__file__).with_name('run.py'))
joined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(joined)


class EvidenceGuards(unittest.TestCase):
    def test_component_green_never_means_live_acceptance(self):
        self.assertEqual(joined.acceptance_status([{'status': 'PASS'}]), ('BLOCKED', 2))
        self.assertEqual(joined.acceptance_status([{'status': 'NOT RUN'}]), ('BLOCKED', 2))
        self.assertEqual(joined.acceptance_status([]), ('BLOCKED', 2))

    def test_failed_component_cannot_be_hidden_by_blocker(self):
        self.assertEqual(joined.acceptance_status([{'status': 'PASS'}, {'status': 'FAIL'}]), ('FAIL', 1))

    def repo(self, p):
        def git(*args):
            return subprocess.check_output(['git', '-C', str(p), *args], text=True).strip()
        git('init', '-q')
        git('config', 'user.name', 'Acceptance test')
        git('config', 'user.email', 'test@invalid.example')
        (p / 'source').write_text('pinned\n')
        git('add', 'source')
        git('commit', '-qm', 'pin')
        return git('rev-parse', 'HEAD')

    def test_wrong_source_revision_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            self.repo(p)
            with self.assertRaisesRegex(ValueError, 'expected exact commit'):
                joined.validate_source(p, '0' * 40)

    def test_dirty_pinned_source_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            pin = self.repo(p)
            joined.validate_source(p, pin)
            (p / 'source').write_text('changed\n')
            with self.assertRaisesRegex(ValueError, 'dirty source checkout'):
                joined.validate_source(p, pin)

    def test_untracked_source_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            pin = self.repo(p)
            (p / 'injected.go').write_text('package injected\n')
            with self.assertRaisesRegex(ValueError, 'dirty source checkout'):
                joined.validate_source(p, pin)


if __name__ == '__main__':
    unittest.main()
