#!/usr/bin/env python3
"""Spot-check source-pin, cleanliness and evidence-status guards, restoring each."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
p = root / 'tests/joined/run.py'
original = p.read_text()
mutations = [
    ("if git(path, 'rev-parse', 'HEAD') != expected:", 'if False:', 'test_wrong_source_revision_is_refused'),
    ("if git(path, 'status', '--porcelain', '--untracked-files=normal'):", 'if False:', 'test_dirty_pinned_source_is_refused'),
    ("if any(s['status'] == 'FAIL' for s in steps):", 'if False:', 'test_failed_component_cannot_be_hidden_by_blocker'),
    ("if missing:", 'if False:', 'test_native_report_refuses_a_missing_step'),
    ("if not steps[name]['success']:", 'if False:', 'test_native_report_refuses_a_failed_happy_path_step'),
    ("if len(calls) < n:", 'if False:', 'test_native_coverage_is_per_step_not_a_union'),
    ("if c.get('nativePrecompile') is not True:", 'if False:', 'test_native_report_refuses_a_double_in_place_of_a_native_call'),
    ("if c.get('ok') is not True:", 'if False:', 'test_native_report_refuses_a_failed_native_call'),
    ("if not refusals:", 'if False:', 'test_native_report_refuses_a_report_without_refusals'),
    ("if any(s['success'] for s in refusals):", 'if False:', 'test_native_report_refuses_a_succeeding_refusal'),
    ("return 'BLOCKED', 2", "return 'PASS', 0", 'test_component_green_never_means_live_acceptance'),
]
for guard, replacement, name in mutations:
    try:
        assert original.count(guard) == 1
        p.write_text(original.replace(guard, replacement))
        result = subprocess.run([sys.executable, '-B', '-m', 'unittest', f'test_harness.EvidenceGuards.{name}'],
                                cwd=p.parent, capture_output=True, text=True)
        if result.returncode == 0 or 'FAIL:' not in result.stderr:
            raise SystemExit(f'SURVIVED/ERROR {name}\n{result.stdout}{result.stderr}')
        print(f'KILLED {name}')
    finally:
        p.write_text(original)
