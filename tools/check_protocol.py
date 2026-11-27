#!/usr/bin/env python3
"""Native bridge v2 profile/ABI digest checks and exact dependency pin checks."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
# the installed SDKs, the ones protocol/interop.md pins: the ristik lines (integration/enshrined-evm)
SDK_JS_FORK_COMMIT = 'c5840ef5f59201c52ea6cf7034ee02cb48d54007'
SDK_JS_FORK_VERSION = '4.0.0-utb.c5840ef'
SDK_RUST_FORK_COMMIT = 'de79e6c1e393a1846b75bca0640b9ec9a55aa143'


def load(path):
    return json.loads((ROOT / path).read_text())


def check_v2_profile():
    """Native bridge v2 (protocol 10, bft-core#1097): the profile binds its normative artifacts by digest."""
    profile = load('protocol/profile.json')
    assert profile['nativeBridgeProtocolVersion'] == 10 and profile['identityFamily'] == 'unicity-native-nb2-11'
    assert profile['tags']['receiptBacking'] == 39051 and profile['tags']['segmentReturn'] == 39052
    assert profile['versions']['depositProof'] == 1 and profile['versions']['depositProofArity'] == 6
    assert profile['versions']['config'] == profile['versions']['splitJustification'] == 2
    assert profile['flatEvidence']['wireVersion'] == 0x0101
    assert profile['flatEvidence']['magic'] == 'NB2L'
    assert 'pdrBytes' not in profile['limits']
    assert set(profile['normativeArtifactSha256']) == set(profile['normativeArtifacts'])
    for name, expected in profile['normativeArtifactSha256'].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, f'v2 normative artifact digest mismatch: {name}'
    abi = load('protocol/abi.json')
    assert abi['nativeBridgeProtocolVersion'] == 10
    assert [f['name'] for f in abi['vault']['functions']] == ['deposit', 'redeem', 'domain', 'config', 'state']
    assert len({e['selector'] for e in abi['vault']['errors']}) == len(abi['vault']['errors'])
    assert 'NATIVE_BRIDGE_PROTO_VERSION=10' in (ROOT / 'protocol/interop.md').read_text()


def check_erc20_profile():
    path = 'protocol/profile-erc20.json'
    profile = load(path)
    assert profile['nativeBridgeProtocolVersion'] == 11
    assert profile['config'] == {'version': 3, 'arity': 22, 'maxBytes': 480, 'segments': 64, 'buckets': 16}
    for name, expected in profile['normativeArtifactSha256'].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, f'ERC20 normative artifact digest mismatch: {name}'
    abi = load('protocol/abi-erc20.json')
    assert abi['nativeBridgeProtocolVersion'] == 11
    assert abi['vault']['depositEvent']['indexed'] == ['nonce', 'token']
    digest = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    for impl in ('packages/native-bridge-plugin/src/nb2/bridge.ts', 'crates/native-bridge-sdk-ext/src/nb2/bridge.rs'):
        assert digest in (ROOT / impl).read_text(), f'ERC20 semantic profile digest mismatch: {impl}'
    vectors = 'protocol/vectors/erc20-nb2/'
    expected = load(vectors + 'generator.json')['sha256']
    assert hashlib.sha256((ROOT / (vectors + 'vectors.json')).read_bytes()).hexdigest() == expected, 'ERC20 vector digest mismatch'


def main():
    check_v2_profile()
    check_erc20_profile()
    package = load('packages/native-bridge-plugin/package.json')
    assert package['private'] and package['license'] == 'MIT OR Apache-2.0'
    deps = package['dependencies']
    sp = load('vendor/state-transition-sdk.provenance.json')
    assert sp['repository'] == 'https://github.com/ristik/state-transition-sdk-js.git'
    assert sp['commit'] == SDK_JS_FORK_COMMIT and sp['version'] == SDK_JS_FORK_VERSION
    assert deps['@unicitylabs/state-transition-sdk'] == f"file:../../vendor/{sp['tarball']}"
    assert deps['@unicitylabs/bridge-core'] == 'file:../../vendor/unicitylabs-bridge-core-0.1.0-bridge.2.tgz'
    # one SDK copy for the plug-in and bridge-core: the root declares it and overrides every nested request with it
    root = load('package.json')
    assert root['dependencies']['@unicitylabs/state-transition-sdk'] == f"file:vendor/{sp['tarball']}"
    assert root['overrides'] == {'@unicitylabs/state-transition-sdk': '$@unicitylabs/state-transition-sdk'}
    sb = (ROOT / 'vendor' / sp['tarball']).read_bytes()
    assert hashlib.sha256(sb).hexdigest() == sp['sha256'], 'SDK SHA-256 mismatch'
    assert 'sha512-' + base64.b64encode(hashlib.sha512(sb).digest()).decode() == sp['integrity'], 'SDK integrity mismatch'
    with tarfile.open(ROOT / 'vendor' / sp['tarball']) as archive:
        packed = json.load(archive.extractfile('package/package.json'))
    assert packed['name'] == '@unicitylabs/state-transition-sdk' and packed['version'] == SDK_JS_FORK_VERSION
    lock = load('package-lock.json')
    copies = [name for name in lock['packages'] if name.endswith('node_modules/@unicitylabs/state-transition-sdk')]
    assert copies == ['node_modules/@unicitylabs/state-transition-sdk'], 'more than one SDK copy'
    sdk = lock['packages']['node_modules/@unicitylabs/state-transition-sdk']
    assert sdk['version'] == SDK_JS_FORK_VERSION and sdk['integrity'] == sp['integrity']
    p = load('vendor/bridge-core.provenance.json')
    assert p['commit'] == 'deb2b86c0a1fa0398928cb88caac9feccda6f4e9'
    assert p['version'] == '0.1.0-bridge.2'
    tar = ROOT / 'vendor' / p['tarball']
    b = tar.read_bytes()
    assert hashlib.sha256(b).hexdigest() == p['sha256'], 'bridge-core SHA-256 mismatch'
    assert 'sha512-' + base64.b64encode(hashlib.sha512(b).digest()).decode() == p['integrity'], 'bridge-core integrity mismatch'
    core = lock['packages']['node_modules/@unicitylabs/bridge-core']
    assert core['version'] == p['version'] and core['integrity'] == p['integrity']
    with tarfile.open(tar) as archive:
        upstream = json.load(archive.extractfile('package/package.json'))
    assert upstream['name'] == '@unicitylabs/bridge-core' and upstream['version'] == p['version']
    cargo = tomllib.loads((ROOT / 'crates/native-bridge-sdk-ext/Cargo.toml').read_text())
    assert cargo['package']['publish'] == {'workspace': True}
    rust = cargo['dependencies']['unicity-token']
    assert rust == {'git': 'https://github.com/ristik/state-transition-sdk-rust.git', 'rev': SDK_RUST_FORK_COMMIT, 'default-features': False, 'features': ['alloc']}
    for path in ROOT.rglob('Cargo.toml'):
        if 'target' in path.parts:
            continue
        text = path.read_text()
        assert '[patch' not in text and 'path =' not in text, 'patch/path dependency forbidden'
    clock = tomllib.loads((ROOT / 'Cargo.lock').read_text())
    sdk_rust = [p for p in clock['package'] if p['name'] == 'unicity-token']
    # the pin is the commit: the crate's own version string on the staging line is 3.0.1 (the SDK reconcile did not bump it), so no version is asserted
    assert len(sdk_rust) == 1
    assert sdk_rust[0]['source'].endswith('#' + SDK_RUST_FORK_COMMIT)
    print('protocol/dependency/ABI checks passed (no full installation authorization)')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, ValueError, KeyError) as exc:
        sys.exit(f'protocol: {exc}')
