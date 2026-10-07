#!/usr/bin/env python3
"""Serial component acceptance. Exit 2 means live acceptance is still BLOCKED.

No devnet is started, stopped or changed. Future live runs must be separately
implemented on the integrated B1 pin and run under briefs/devnet-lock.sh.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / 'pins.json').read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


def validate_source(path, expected):
    if git(path, 'rev-parse', 'HEAD') != expected:
        raise ValueError(f'{path}: expected exact commit {expected}')
    if git(path, 'status', '--porcelain', '--untracked-files=normal'):
        raise ValueError(f'{path}: dirty source checkout')


def wait_for_compilers():
    # Do not compete with an agent building the full client on a 16 GB host.
    deadline = time.monotonic() + 3600
    while True:
        rows = subprocess.check_output(['ps', '-axo', 'args='], text=True).splitlines()
        active = [r for r in rows if Path(r.split()[0]).name in ('cargo', 'rustc', 'solc')
                  or (Path(r.split()[0]).name == 'go' and any(x in r for x in (' test ', ' build ', ' run ')))]
        if not active:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('another build is still active; retry serially')
        print('WAIT: another build is active; no parallel heavy builds', flush=True)
        time.sleep(30)


def compare_contracts(contracts, generated):
    pin = json.loads((contracts / 'script/bridge-golden/corpus-pin.json').read_text())
    original = contracts / pin['golden']['file']
    if generated.read_bytes() != original.read_bytes():
        raise ValueError('merged oracle does not reproduce the contracts golden bytes')
    if digest(original) != pin['golden']['sha256']:
        raise ValueError('contract golden bytes differ from their pin')
    golden = json.loads(original.read_text())
    corpus_root = ROOT / 'protocol/vectors'
    trust = digest(corpus_root / 'config/sdk-root-trust-base.json')
    for op in ('mint', 'return'):
        if trust not in golden[op]['history'].lower():
            raise ValueError('contract history has stale trust digest')
    corpus = ''.join(p.read_text().lower() for p in sorted(corpus_root.rglob('*.json')))
    for path in pin['golden']['sharedPaths']:
        value = golden
        for part in path.strip('/').split('/'):
            value = value[int(part)] if isinstance(value, list) else value[part]
        if value[2:].lower() not in corpus:
            raise ValueError(f'contract golden {path} differs from merged corpus')
    return {'goldenSha256': digest(original), 'sharedValues': len(pin['golden']['sharedPaths']),
            'mergedCorpusDigest': (corpus_root / 'MANIFEST.sha256').read_text().strip(),
            'note': 'contracts retain pre-merge provenance pins; compared to merged bytes and regenerated oracle here'}


def acceptance_status(steps):
    if any(s['status'] == 'FAIL' for s in steps):
        return 'FAIL', 1
    # These source pins have no integrated live runner. Component greens cannot
    # promote them to acceptance, even if someone empties the blockers map.
    return 'BLOCKED', 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', type=Path, default=ROOT.parent,
                        help='parent of nbp-pr6-{ureth,contracts,oracle,aggregator} pinned clean worktrees')
    parser.add_argument('--out', type=Path, required=True, help='new evidence directory (must not exist)')
    parser.add_argument('--skip-native', action='store_true', help='record Rust/B2/Foundry as NOT RUN')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = {k: args.sources.resolve() / f'nbp-pr6-{k}' for k in PINS['sources'] if k != 'plugins'}
    report = {'schema': 1, 'profile': PINS['profile'], 'status': 'RUNNING',
              'host': {'system': platform.system(), 'machine': platform.machine()},
              'pins': PINS['sources'], 'harnessHead': git(ROOT, 'rev-parse', 'HEAD'),
              'steps': [], 'blocked': PINS['blocked'], 'deferred': PINS['deferred'],
              'evidenceClass': 'component-only; synthetic certificates; no running aggregator or native vault calls'}
    report['inputs'] = {str(p.relative_to(ROOT)): digest(p) for p in sorted(HERE.rglob('*'))
                        if p.is_file() and '__pycache__' not in p.parts}

    def save():
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    def step(name, cmd, cwd=ROOT, env=None, stdout_file=None):
        if cmd[0] in ('go', 'cargo', 'forge') or name == 'corpus-regenerate':
            wait_for_compilers()
        print(f'RUN {name}', flush=True)
        log = out / f'{name}.log'
        started = time.monotonic()
        with log.open('wb') as f:
            if stdout_file:
                with stdout_file.open('wb') as output:
                    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=output, stderr=f)
                    while proc.poll() is None:
                        try:
                            proc.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            print(f'RUN {name}: still running; see {log}', flush=True)
            else:
                proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT)
                while proc.poll() is None:
                    try:
                        proc.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        print(f'RUN {name}: still running; see {log}', flush=True)
        entry = {'name': name, 'command': cmd, 'cwd': str(cwd), 'status': 'PASS' if proc.returncode == 0 else 'FAIL',
                 'exit': proc.returncode, 'seconds': round(time.monotonic() - started, 3),
                 'log': log.name, 'sha256': digest(log)}
        report['steps'].append(entry)
        save()
        print(f'{entry["status"]} {name}', flush=True)
        if proc.returncode:
            raise RuntimeError(f'{name} failed; see {log}')

    try:
        for key, path in sources.items():
            validate_source(path, PINS['sources'][key])
        if git(ROOT, 'merge-base', 'HEAD', PINS['sources']['plugins']) != PINS['sources']['plugins']:
            raise ValueError('plug-in baseline must be an ancestor of this harness')
        if git(ROOT, 'diff', PINS['sources']['plugins'], '--', 'packages', 'crates', 'protocol', 'package-lock.json'):
            raise ValueError('plug-in implementation/corpus differs from the accepted baseline')
        save()
        env = dict(os.environ, CARGO_BUILD_JOBS='2', GOMAXPROCS='2')
        with tempfile.TemporaryDirectory(prefix='nbp-pr6-cache-') as scratch:
            scratch = Path(scratch)
            env['GOCACHE'] = str(scratch / 'go-cache')
            env['CARGO_TARGET_DIR'] = str(scratch / 'rust-target')
            step('toolchains', ['python3', '-c',
                 'import subprocess; [subprocess.run(c, check=True) for c in '
                 '[["node","--version"],["npm","--version"],["go","version"],["cargo","--version"],["forge","--version"]]]'])
            step('corpus', ['python3', 'tools/vectors.py', 'check'])
            step('protocol', ['python3', 'tools/check_protocol.py'])
            step('ts-build', ['npm', 'run', 'build'])
            step('ts-typecheck', ['npm', 'run', 'typecheck'])
            step('joined-typecheck', ['node_modules/.bin/tsc', '-p', 'tests/joined/tsconfig.json'])
            step('ts-facade', ['node', '--test', 'tests/interop/package.test.mjs'])
            step('ts-plugin', ['npm', 'test', '--workspace', '@unicitylabs/native-bridge-plugin'])
            step('construct', ['node_modules/.bin/tsx', 'tests/joined/construct.ts', str(out / 'joined.json')])
            step('aggregator-join', ['go', 'run', str(HERE / 'aggregator.go'), str(out / 'joined.json')], sources['aggregator'], env)
            step('oracle', ['go', 'test', '-p', '1', './bridgeprofile', './b1ref', '-count=1'], sources['oracle'], env)
            step('corpus-regenerate', ['python3', 'tools/vectors.py', 'regenerate', '--oracle', str(sources['oracle'])], env=env)
            if args.skip_native:
                report['steps'].append({'name': 'native-components', 'status': 'NOT RUN', 'reason': '--skip-native'})
            else:
                step('driver-fmt', ['rustfmt', '--edition', '2021', '--check', str(HERE / 'b2/src/main.rs')], env=env)
                step('rust-fmt', ['cargo', 'fmt', '--all', '--', '--check'], env=env)
                step('rust-clippy', ['cargo', 'clippy', '--locked', '--all-targets', '--', '-D', 'warnings'], env=env)
                step('rust-tests', ['cargo', 'test', '--locked'], env=env)
                step('rust-alloc', ['cargo', 'check', '--locked', '--no-default-features'], env=env)
                driver = scratch / 'b2'
                shutil.copytree(HERE / 'b2', driver)
                template = (driver / 'Cargo.toml.in').read_text()
                (driver / 'Cargo.toml').write_text(template.replace('@B2_PATH@', json.dumps(str(sources['ureth'] / 'crates/unicity/b2'))))
                # Resolve from ureth's locked dependency graph, then retain the resolved lock as evidence.
                shutil.copyfile(sources['ureth'] / 'Cargo.lock', driver / 'Cargo.lock')
                step('b2-join', ['cargo', 'run', '--manifest-path', str(driver / 'Cargo.toml'), '--', str(out / 'joined.json')], env=env)
                shutil.copyfile(driver / 'Cargo.lock', out / 'b2-Cargo.lock')
                overlay = scratch / 'overlay.json'
                overlay.write_text(json.dumps({'Replace': {
                    str(sources['oracle'] / 'bridgeprofile/zz_nbp_pr6_golden_test.go'):
                    str(sources['contracts'] / 'script/bridge-golden/golden_pr5_test.go.txt')}}))
                golden_env = dict(env, BRIDGE_PR5_GOLDEN=str(out / 'contracts-golden.json'))
                step('contracts-regenerate', ['go', 'test', '-p', '1', '-overlay', str(overlay), './bridgeprofile',
                                              '-run', '^TestGenPR5Golden$', '-count=1'], sources['oracle'], golden_env)
                report['contractsComparison'] = compare_contracts(sources['contracts'], out / 'contracts-golden.json')
                step('contracts-doubles', ['forge', 'test', '--threads', '2', '--match-path', 'test/bridge/*.t.sol'], sources['contracts'], env)
        # Refuse evidence from sources modified while commands ran.
        for key, path in sources.items():
            validate_source(path, PINS['sources'][key])
        report['artifacts'] = {p.name: digest(p) for p in out.iterdir() if p.is_file() and p.name != 'report.json'}
    except (ValueError, RuntimeError, subprocess.CalledProcessError, OSError) as exc:
        report['steps'].append({'name': 'harness', 'status': 'FAIL', 'reason': str(exc)})
    report['status'], code = acceptance_status(report['steps'])
    save()
    print(f'{report["status"]}: {out / "report.json"}', flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
