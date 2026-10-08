import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

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

    def test_compiler_wait_uses_untruncated_executable(self):
        with patch.object(joined.subprocess, 'check_output', side_effect=[
            '/Users/test/.rustup/toolchains/stable/bin/cargo test --no-run\n', '',
        ]) as ps, patch.object(joined.time, 'sleep') as sleep:
            joined.wait_for_compilers()
            sleep.assert_called_once_with(30)
            ps.assert_called_with(['ps', '-axo', 'args='], text=True)

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

    def native_report(self, mutate=lambda r: None):
        def call(target, native=True):
            return {'target': target, 'nativePrecompile': native}
        steps = [{'step': n, 'success': True, 'gasUsed': 1, 'nativeCalls': []} for n in joined.NATIVE_REQUIRED]
        steps[0]['nativeCalls'] = [call(t) for t in sorted(joined.NATIVE_TARGETS)]
        steps[4].update(success=False, expectedRefusal='AlreadyRedeemed')
        report = {'steps': steps}
        mutate(report)
        d = tempfile.mkdtemp()
        path = Path(d) / 'native-report.json'
        path.write_text(__import__('json').dumps(report))
        return path

    def test_native_report_accepts_a_complete_native_run(self):
        self.assertEqual(joined.check_native_report(self.native_report())['addresses'], sorted(joined.NATIVE_TARGETS))

    def test_native_report_refuses_a_double_in_place_of_a_native_call(self):
        def mutate(r):
            r['steps'][0]['nativeCalls'][0]['nativePrecompile'] = False
        with self.assertRaisesRegex(ValueError, 'did not execute as a native precompile'):
            joined.check_native_report(self.native_report(mutate))

    def test_native_report_refuses_missing_address_or_step(self):
        with self.assertRaisesRegex(ValueError, 'every native address'):
            joined.check_native_report(self.native_report(lambda r: r['steps'][0].update(nativeCalls=r['steps'][0]['nativeCalls'][:2])))
        with self.assertRaisesRegex(ValueError, 'lacks steps'):
            joined.check_native_report(self.native_report(lambda r: r['steps'].pop(1)))

    def test_native_report_refuses_a_succeeding_refusal(self):
        with self.assertRaisesRegex(ValueError, 'refusal step succeeded'):
            joined.check_native_report(self.native_report(lambda r: r['steps'][4].update(success=True)))


if __name__ == '__main__':
    unittest.main()
