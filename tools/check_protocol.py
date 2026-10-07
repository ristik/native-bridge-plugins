#!/usr/bin/env python3
"""PR1 structural validation and exact dependency/ABI pin checks."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tomllib

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
JS_COMMIT = 'f5f0737306901215860aa920a6ab570b699efba8'
RUST_COMMIT = '635011b3d7066db6f3296e9cb8d2f24d4bd1fec7'


def load(path):
    return json.loads((ROOT / path).read_text())


def validator():
    schema = load('protocol/manifest.schema.json')
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_manifest(registry):
    """Schema plus cross-field identity checks; not full trust installation."""
    validator().validate(registry)
    for key, entry in registry.items():
        assert key == entry['tokenTypeHex'], 'registry key mismatch'
        chain = entry['evmChainId']
        assert 1 <= int(chain) <= (1 << 64) - 1, 'chain ID outside uint64'
        assert entry['chainRef'] == 'eip155:' + chain, 'chainRef mismatch'
        d = ':'.join([str(entry['networkId']), entry['rootGenesisHash'], entry['executionGenesisHash'], chain, entry['asset']])
        assert key == hashlib.sha256(('unicity-bridge:unicity-native:' + d).encode()).hexdigest(), 'token type mismatch'
        assert entry['coinIdHex'] == hashlib.sha256(('unicity-bridge-coin:unicity-native:' + d).encode()).hexdigest(), 'coin ID mismatch'
        trust = entry['trustBase']
        assert (trust['networkId'], trust['rootGenesisHash']) == (entry['networkId'], entry['rootGenesisHash']), 'trust anchor mismatch'
        vaults = set()
        for dep in [entry['activeDeployment'], *entry['replacedDeployments']]:
            vault = dep['vaultAddress']
            assert vault != '0' * 40 and vault not in vaults, 'zero/ambiguous vault'
            vaults.add(vault)
            assert dep['tokenVerifierAddress'] != '0' * 40, 'zero verifier'
            assert dep['aggregatorPolicy']['partition'] != dep['evmBackingPolicy']['partition'], 'partition collision'
            for data, expected in [(bytes.fromhex(dep['cfgHex']), dep['cfgHash']), (bytes.fromhex(dep['aggregatorPolicy']['bodyHex']), dep['aggregatorPolicy']['sha256'])]:
                assert hashlib.sha256(data).hexdigest() == expected, 'canonical bytes digest mismatch'
    # Full canonical Cfg/Policy parsing, artifact loading, runtime and epoch
    # authentication are mandatory installation gates implemented in PR3.


def main():
    validator()
    abi = load('protocol/abi.json')
    assert abi['protocolVersion'] == 2
    assert abi['leaf'] == ['bytes32 sid', 'bytes32 txHash', 'uint64 referenceTime', 'bytes32 leafValue']
    assert abi['anchor'] == ['uint32 partition', 'bytes shard', 'bytes32 shardConfHash', 'bytes32 expectedStateRoot', 'bytes32 expectedIRHash', 'bytes uc', 'bytes inputRecord']
    assert abi['outputFixedBytes'] == 448 and abi['leafStrideBytes'] == 128
    assert abi['operations'] == {'prepareLock': 0, 'mint': 1, 'return': 2}
    assert abi['outputOffsets']['firstLeaf'] == 448 and abi['resultOffsetValue'] == 96 and abi['leavesOffsetValue'] == 320
    profile = load('protocol/profile-v2.json')
    assert profile['nativeBridgeProtocolVersion'] == 2 and profile['sdkVersion'] == '3.0.1'
    assert profile['limits']['semanticBytes'] == 131072 and profile['limits']['justificationBytes'] == 65536
    assert 'NATIVE_BRIDGE_PROTO_VERSION=2' in (ROOT / 'protocol/interop.md').read_text()
    assert JS_COMMIT in (ROOT / 'protocol/interop.md').read_text()
    assert RUST_COMMIT in (ROOT / 'protocol/interop.md').read_text()
    package = load('packages/native-bridge-plugin/package.json')
    assert package['private'] and package['license'] == 'MIT OR Apache-2.0'
    deps = package['dependencies']
    assert deps['@unicitylabs/state-transition-sdk'] == '3.0.1'
    assert deps['@unicitylabs/bridge-core'] == 'file:../../vendor/unicitylabs-bridge-core-0.1.0-bridge.2.tgz'
    lock = load('package-lock.json')
    for name, record in lock['packages'].items():
        if name.endswith('node_modules/@unicitylabs/state-transition-sdk'):
            assert record['version'] == '3.0.1', 'unexpected nested SDK version'
    sdk = lock['packages']['node_modules/@unicitylabs/state-transition-sdk']
    assert sdk['version'] == '3.0.1' and sdk['integrity'].startswith('sha512-')
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
    assert rust == {'git': 'https://github.com/unicitynetwork/state-transition-sdk-rust.git', 'tag': 'v3.0.1', 'default-features': False, 'features': ['alloc']}
    for path in ROOT.rglob('Cargo.toml'):
        if 'target' in path.parts:
            continue
        text = path.read_text()
        assert '[patch' not in text and 'path =' not in text, 'patch/path dependency forbidden'
    clock = tomllib.loads((ROOT / 'Cargo.lock').read_text())
    sdk_rust = [p for p in clock['package'] if p['name'] == 'unicity-token']
    assert len(sdk_rust) == 1 and sdk_rust[0]['version'] == '3.0.1'
    assert sdk_rust[0]['source'].endswith('#' + RUST_COMMIT)
    for path in sorted((ROOT / 'deployments').glob('*.json')):
        validate_manifest(json.loads(path.read_text()))
    print('protocol/schema/dependency/ABI checks passed (no full installation authorization)')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, ValueError, KeyError) as exc:
        sys.exit(f'protocol: {exc}')
