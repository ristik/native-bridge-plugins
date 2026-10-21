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

    def test_deferred_tier_is_blocked_never_pass(self):
        tier = {'contracts-tier': 'contracts at protocol 3 until dev2\'s protocol-4 port'}
        reason = tier['contracts-tier']
        listed = [{'name': 'b2-join', 'status': 'PASS'}, {'name': 'contracts-regenerate', 'status': 'DEFERRED', 'reason': reason}]
        self.assertEqual(joined.acceptance_status(listed, tier), ('BLOCKED', 2))
        self.assertEqual(joined.acceptance_status([{'name': 'native-driver', 'status': 'DEFERRED', 'reason': reason}], tier), ('BLOCKED', 2))

    def test_unlisted_deferred_step_fails_the_run(self):
        tier = {'contracts-tier': 'contracts at protocol 3 until dev2\'s protocol-4 port'}
        reason = tier['contracts-tier']
        # a step outside every deferrable tier
        self.assertEqual(joined.acceptance_status([{'name': 'corpus-regenerate', 'status': 'DEFERRED', 'reason': reason}], tier), ('FAIL', 1))
        # a tier step while no tier is pinned as deferred
        self.assertEqual(joined.acceptance_status([{'name': 'contracts-regenerate', 'status': 'DEFERRED', 'reason': reason}], {}), ('FAIL', 1))
        # a tier step with another or no reason
        self.assertEqual(joined.acceptance_status([{'name': 'contracts-regenerate', 'status': 'DEFERRED', 'reason': 'later'}], tier), ('FAIL', 1))
        self.assertEqual(joined.acceptance_status([{'name': 'contracts-regenerate', 'status': 'DEFERRED'}], tier), ('FAIL', 1))

    def test_pinned_deferrals_name_known_tiers_and_the_contracts_tier_runs(self):
        self.assertEqual(set(joined.PINS.get('deferredSteps', {})) - set(joined.DEFERRABLE_TIERS), set())
        # protocol 4: nothing is deferred, so the contracts tier must run
        self.assertIsNone(joined.deferred_reason('contracts-regenerate'))
        self.assertIsNone(joined.deferred_reason('b2-join'))

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
        def calls(step):
            out = []
            for target, n in joined.NATIVE_STEP_CALLS.get(step, {}).items():
                out += [{'target': target, 'nativePrecompile': True, 'ok': True, 'gasUsed': 7} for _ in range(n)]
            return out
        steps = [{'step': n, 'success': True, 'gasUsed': 1, 'nativeCalls': calls(n)} for n in joined.NATIVE_REQUIRED]
        for s in steps:
            if s['step'] in joined.NATIVE_COMPOSE_STEPS:
                s['composeGas'] = 7
        steps[4].update(success=False, expectedRefusal='AlreadyRedeemed')
        report = {'steps': steps}
        mutate(report)
        d = tempfile.mkdtemp()
        path = Path(d) / 'native-report.json'
        path.write_text(__import__('json').dumps(report))
        return path

    def step(self, report, name):
        return next(s for s in report['steps'] if s['step'] == name)

    def test_native_report_accepts_a_complete_native_run(self):
        self.assertEqual(joined.check_native_report(self.native_report())['addresses'], sorted(joined.NATIVE_TARGETS))

    def test_native_report_refuses_a_double_in_place_of_a_native_call(self):
        def mutate(r):
            self.step(r, 'verifyMint')['nativeCalls'][0]['nativePrecompile'] = False
        with self.assertRaisesRegex(ValueError, 'did not execute as a native precompile'):
            joined.check_native_report(self.native_report(mutate))

    def test_native_report_refuses_a_failed_native_call(self):
        def mutate(r):
            self.step(r, 'redeem (third-party submitter)')['nativeCalls'][0]['ok'] = False
        with self.assertRaisesRegex(ValueError, 'call did not succeed'):
            joined.check_native_report(self.native_report(mutate))

    def test_native_coverage_is_per_step_not_a_union(self):
        # verifyMint loses its 0x0105 call; redeem still supplies that address elsewhere in the report.
        def mutate(r):
            calls = self.step(r, 'verifyMint')['nativeCalls']
            calls[:] = [c for c in calls if c['target'] != joined.NATIVE_COMPOSE]
        with self.assertRaisesRegex(ValueError, 'verifyMint: expected exactly 1 call.*0x0105'):
            joined.check_native_report(self.native_report(mutate))
        # a direct B1 call from the verifier besides the composition is refused (the PR 1 shape)
        def direct(r):
            self.step(r, 'redeem (third-party submitter)')['nativeCalls'].append({'target': joined.NATIVE_UC, 'nativePrecompile': True, 'ok': True})
        with self.assertRaisesRegex(ValueError, 'redeem.*expected exactly 0 call.*0x0100'):
            joined.check_native_report(self.native_report(direct))

    def test_native_report_refuses_an_empty_or_short_call_list(self):
        with self.assertRaisesRegex(ValueError, 'lock: expected exactly 1 call'):
            joined.check_native_report(self.native_report(lambda r: self.step(r, 'lock').update(nativeCalls=[])))
        def twice(r):
            calls = self.step(r, 'redeem (third-party submitter)')['nativeCalls']
            calls.append(dict(next(c for c in calls if c['target'] == joined.NATIVE_COMPOSE)))
        with self.assertRaisesRegex(ValueError, 'expected exactly 1 call'):
            joined.check_native_report(self.native_report(twice))

    def test_native_report_refuses_a_compose_charge_other_than_g_compose(self):
        with self.assertRaisesRegex(ValueError, 'not the recorded G_compose'):
            joined.check_native_report(self.native_report(lambda r: self.step(r, 'verifyMint').update(composeGas=8)))

    def test_native_report_refuses_a_missing_step(self):
        # Any exception is caught so that a bypassed guard (a KeyError further down) fails the assertions
        # below rather than erroring.
        with self.assertRaises(Exception) as caught:
            joined.check_native_report(self.native_report(lambda r: r['steps'].pop(1)))
        self.assertIsInstance(caught.exception, ValueError)
        self.assertIn('lacks steps', str(caught.exception))

    def test_native_report_refuses_a_failed_happy_path_step(self):
        for name in ('lock', 'verifyMint', 'redeem (third-party submitter)', 'claim'):
            with self.assertRaisesRegex(ValueError, f'{__import__("re").escape(name)} did not succeed'):
                joined.check_native_report(self.native_report(lambda r, n=name: self.step(r, n).update(success=False)))

    def test_native_report_refuses_a_succeeding_refusal(self):
        with self.assertRaisesRegex(ValueError, 'refusal step succeeded'):
            joined.check_native_report(self.native_report(lambda r: r['steps'][4].update(success=True)))

    def test_native_report_refuses_a_report_without_refusals(self):
        def mutate(r):
            for s in r['steps']:
                s.pop('expectedRefusal', None)
        with self.assertRaisesRegex(ValueError, 'no refusal step'):
            joined.check_native_report(self.native_report(mutate))


if __name__ == '__main__':
    unittest.main()
