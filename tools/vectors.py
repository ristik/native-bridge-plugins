#!/usr/bin/env python3
"""Content-addressed corpus import and pinned, isolated oracle regeneration."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = ('config', 'wire', 'unlock', 'policy', 'lock', 'history', 'proof', 'return', 'vault')
CONTROL = {'VERSION', 'provenance.json', 'SHA256SUMS', 'MANIFEST.sha256'}
PLACEHOLDERS = {'README.md'} | {f'{f}/.gitkeep' for f in FAMILIES}
HEX = re.compile(r'^[0-9a-f]{64}$')
REPOSITORY = 'https://github.com/ristik/bft-core.git'


class CorpusError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise CorpusError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def inventory(root):
    require(root.is_dir() and not root.is_symlink(), 'corpus root must be a real directory')
    files = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), f'symlink forbidden: {path}')
        if path.is_dir():
            continue
        name = path.relative_to(root).as_posix()
        require(path.is_file(), f'not a regular file: {name}')
        if name in PLACEHOLDERS or name in CONTROL:
            continue
        p = PurePosixPath(name)
        require(p.parts[0] in FAMILIES and len(p.parts) >= 2, f'unknown corpus path: {name}')
        require(bool(re.fullmatch(r'[a-zA-Z0-9_./-]+', name)) and not any(x.startswith('.') for x in p.parts), f'unsafe path: {name}')
        files[name] = path.read_bytes()
    return files


def provenance_check(provenance):
    require(set(provenance) == {'protocolVersion', 'sdkVersion', 'semanticProfileSha256', 'generator'}, 'provenance fields')
    require(provenance['protocolVersion'] == 3 and provenance['sdkVersion'] == '3.0.1', 'unexpected protocol/SDK version')
    require(bool(HEX.fullmatch(provenance['semanticProfileSha256'])), 'invalid semantic profile digest')
    g = provenance['generator']
    require(set(g) == {'repository', 'commit', 'command'}, 'generator fields')
    require(g['repository'] == REPOSITORY, 'unexpected generator repository')
    require(bool(re.fullmatch(r'[0-9a-f]{40}', g['commit'])), 'generator requires full commit')
    cmd = g['command']
    require(isinstance(cmd, list) and all(isinstance(x, str) for x in cmd), 'generator argv required')
    require(len(cmd) >= 4 and cmd[:2] == ['go', 'run'] and cmd[2].startswith('./cmd/'), 'expected Go oracle entry point')
    require(sum(x.count('{output}') for x in cmd) == 1, 'exactly one {output} destination required')
    require(not any('{' in x.replace('{output}', '') or '}' in x.replace('{output}', '') for x in cmd), 'unknown command template')


def fixed_profile_check(files):
    """Reject abandoned trust drafts even if their own digest is consistent."""
    expected_profile = json.loads((ROOT / 'protocol/profile-v3.json').read_bytes())
    actual_profile = json.loads(files['config/semantic-profile.json'])
    require(actual_profile.get('trustModel') == expected_profile['trustModel'], 'unsupported trust model')
    require(actual_profile.get('normativeArtifactSha256') == expected_profile['normativeArtifactSha256'], 'normative artifact pins mismatch')
    for name in ('sdk-root-trust-base.json', 'sdk-root-trust-base.provenance.json'):
        key = 'config/' + name
        require(files.get(key) == (ROOT / 'protocol/vectors' / key).read_bytes(), 'SDK trust fixture mismatch')


def seal(root, provenance):
    """Candidate producer helper; it does not make a candidate trusted."""
    provenance_check(provenance)
    files = inventory(root)
    for family in FAMILIES:
        require(any(n.startswith(family + '/') for n in files), f'missing family: {family}')
    require('config/semantic-profile.json' in files and digest(files['config/semantic-profile.json']) == provenance['semanticProfileSha256'], 'semantic profile artifact mismatch')
    fixed_profile_check(files)
    (root / 'VERSION').write_bytes(b'2\n')
    (root / 'provenance.json').write_bytes(canonical_json(provenance))
    files.update({n: (root / n).read_bytes() for n in ('VERSION', 'provenance.json')})
    sums = ''.join(f'{digest(data)}  {name}\n' for name, data in sorted(files.items())).encode()
    (root / 'SHA256SUMS').write_bytes(sums)
    (root / 'MANIFEST.sha256').write_text(digest(sums) + '\n')
    return digest(sums)


def check(root, expected=None):
    require((root / 'MANIFEST.sha256').is_file(), 'corpus digest missing; PR must remain draft')
    for name in CONTROL:
        require((root / name).is_file() and not (root / name).is_symlink(), f'missing/unsafe {name}')
    pin = (root / 'MANIFEST.sha256').read_text()
    require(bool(re.fullmatch(r'[0-9a-f]{64}\n', pin)), 'digest must be lowercase SHA-256 plus newline')
    if expected is not None:
        require(bool(HEX.fullmatch(expected)) and pin.strip() == expected, 'unexpected corpus digest')
    require((root / 'VERSION').read_bytes() == b'2\n', 'unexpected corpus VERSION')
    provenance = json.loads((root / 'provenance.json').read_bytes())
    provenance_check(provenance)
    require((root / 'provenance.json').read_bytes() == canonical_json(provenance), 'noncanonical provenance')
    files = inventory(root)
    for family in FAMILIES:
        require(any(n.startswith(family + '/') for n in files), f'missing family: {family}')
    require('config/semantic-profile.json' in files and digest(files['config/semantic-profile.json']) == provenance['semanticProfileSha256'], 'semantic profile artifact mismatch')
    fixed_profile_check(files)
    files.update({n: (root / n).read_bytes() for n in ('VERSION', 'provenance.json')})
    sums = ''.join(f'{digest(data)}  {name}\n' for name, data in sorted(files.items())).encode()
    require((root / 'SHA256SUMS').read_bytes() == sums, 'file inventory/digest mismatch')
    require(digest(sums) == pin.strip(), 'manifest digest mismatch')
    return provenance


def import_corpus(source, destination, expected):
    check(source, expected)
    require(source.resolve() != destination.resolve(), 'source and destination must differ')
    # Stage and validate the complete snapshot before replacing any tracked bytes.
    with tempfile.TemporaryDirectory(prefix='nbp-import-') as tmp:
        stage = Path(tmp) / 'corpus'
        shutil.copytree(source, stage)
        check(stage, expected)
        destination.mkdir(parents=True, exist_ok=True)
        inventory(destination)  # reject unexpected local files/symlinks before mutation
        for path in list(destination.iterdir()):
            if path.name == 'README.md':
                continue
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        for name in sorted(set(inventory(stage)) | CONTROL):
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(stage / name, target)
    check(destination, expected)


def regenerate(root, oracle):
    provenance = check(root)
    g = provenance['generator']
    # Archive the immutable commit: never execute a dirty companion worktree.
    resolved = subprocess.check_output(['git', '-C', str(oracle), 'rev-parse', g['commit'] + '^{commit}'], text=True).strip()
    require(resolved == g['commit'], 'oracle commit mismatch')
    with tempfile.TemporaryDirectory(prefix='nbp-regen-') as tmp:
        tmp = Path(tmp)
        checkout, out = tmp / 'oracle', tmp / 'vectors'
        checkout.mkdir()
        out.mkdir()
        # Fetch and detach only the provenance commit; ignore uncommitted files.
        subprocess.run(['git', 'init', '-q', str(checkout)], check=True)
        subprocess.run(['git', '-C', str(checkout), 'fetch', '-q', str(oracle.resolve()), resolved], check=True)
        subprocess.run(['git', '-C', str(checkout), 'checkout', '-q', '--detach', 'FETCH_HEAD'], check=True)
        env = dict(os.environ, GOCACHE=str(tmp / 'gocache'), GOMAXPROCS='4', GOFLAGS='-p=4')
        cmd = [x.replace('{output}', str(out)) for x in g['command']]
        subprocess.run(cmd, cwd=checkout, env=env, check=True)
        seal(out, provenance)
        check(out, (root / 'MANIFEST.sha256').read_text().strip())
        require(inventory(out) == inventory(root), 'regenerated corpus bytes differ')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    c = sub.add_parser('check')
    c.add_argument('--root', type=Path, default=ROOT / 'protocol/vectors')
    c.add_argument('--expected-digest')
    i = sub.add_parser('import')
    i.add_argument('source', type=Path)
    i.add_argument('--expected-digest', required=True)
    i.add_argument('--destination', type=Path, default=ROOT / 'protocol/vectors')
    s = sub.add_parser('seal')
    s.add_argument('source', type=Path)
    s.add_argument('--provenance', type=Path, required=True)
    r = sub.add_parser('regenerate')
    r.add_argument('--root', type=Path, default=ROOT / 'protocol/vectors')
    r.add_argument('--oracle', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'check':
            check(args.root, args.expected_digest)
        elif args.action == 'import':
            import_corpus(args.source, args.destination, args.expected_digest)
        elif args.action == 'seal':
            print(seal(args.source, json.loads(args.provenance.read_text())))
        else:
            regenerate(args.root, args.oracle)
    except (CorpusError, OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'vectors: {exc}\n')


if __name__ == '__main__':
    main()
