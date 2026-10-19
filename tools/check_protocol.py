#!/usr/bin/env python3
"""PR1 structural validation and exact dependency/ABI pin checks."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import tarfile
import tomllib

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
# the SDK 3.0.1 commits protocol/interop.md names as the protocol-4 wire reference
JS_COMMIT = 'f5f0737306901215860aa920a6ab570b699efba8'
RUST_COMMIT = '635011b3d7066db6f3296e9cb8d2f24d4bd1fec7'
# the installed SDKs: the ristik forks (integration/enshrined-evm line), same token and predicate wire
SDK_JS_FORK_COMMIT = 'cc9a95bcf5e043770dfd1ae79e54516cf424e859'
SDK_JS_FORK_VERSION = '4.0.0-utb.cc9a95b'
SDK_RUST_FORK_COMMIT = '772be681c740442a35ecef35724a1545cf42b7f4'


def load(path):
    return json.loads((ROOT / path).read_text())


def validator():
    schema = load('protocol/manifest.schema.json')
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def cbor_head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 1 << 8:
        return bytes([major << 5 | 24, n])
    if n < 1 << 16:
        return bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    if n < 1 << 32:
        return bytes([major << 5 | 26]) + n.to_bytes(4, 'big')
    return bytes([major << 5 | 27]) + n.to_bytes(8, 'big')


def cbor_bytes(b):
    return cbor_head(2, len(b)) + b


def policy_body(partition):
    """Canonical C(b("UNICITY_BR_AGG_PARTITION"),2,partition): the partition only (AGG_PARTITION_V2)."""
    return cbor_head(4, 3) + cbor_bytes(b'UNICITY_BR_AGG_PARTITION') + cbor_head(0, 2) + cbor_head(0, partition)


def validate_policy(policy):
    """Policy shape: the partition-only body in its canonical encoding; no depth, shard list or configuration."""
    assert set(policy) == {'bodyHex', 'sha256', 'partition'}, 'policy carries fields the partition-only body does not have'
    assert policy_body(policy['partition']).hex() == policy['bodyHex'], 'policy body is not the canonical encoding'


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
            validate_policy(dep['aggregatorPolicy'])
            for data, expected in [(bytes.fromhex(dep['cfgHex']), dep['cfgHash']), (bytes.fromhex(dep['aggregatorPolicy']['bodyHex']), dep['aggregatorPolicy']['sha256'])]:
                assert hashlib.sha256(data).hexdigest() == expected, 'canonical bytes digest mismatch'
    # Full Cfg/Policy parsing, fixed SDK document loading/authentication, unit
    # stakes and matching count quorum are mandatory PR3 installation gates.


def validate_sdk_trust_document(data, expected_digest):
    """Fixed-profile document checks only; never authenticates authority or UCs."""
    assert hashlib.sha256(data).hexdigest() == expected_digest, 'SDK document digest mismatch'
    doc = json.loads(data)
    assert doc['version'] == '1', 'SDK document version'
    assert all(node['stake'] == '1' for node in doc['rootNodes']), 'non-unit stake unsupported'
    n = len(doc['rootNodes'])
    assert n > 0 and doc['quorumThreshold'] == str(n - (n - 1) // 3), 'SDK count quorum mismatch'
    for name in ('epoch', 'epochStartRound'):
        value = doc[name]
        assert isinstance(value, str) and value == str(int(value)) and 0 <= int(value) < 1 << 64, 'SDK epoch field outside uint64'
    return doc


def main():
    validator()
    abi = load('protocol/abi.json')
    assert abi['protocolVersion'] == 4
    assert abi['leaf'] == ['bytes32 sid', 'bytes32 txHash', 'uint64 referenceTime', 'bytes32 leafValue']
    assert abi['anchor'] == ['uint32 partition', 'bytes shard', 'bytes32 shardConfHash', 'bytes32 expectedStateRoot', 'bytes32 expectedIRHash', 'bytes uc', 'bytes inputRecord']
    assert abi['outputFixedBytes'] == 448 and abi['leafStrideBytes'] == 128
    assert abi['operations'] == {'prepareLock': 0, 'mint': 1, 'return': 2}
    assert abi['outputOffsets']['firstLeaf'] == 448 and abi['resultOffsetValue'] == 96 and abi['leavesOffsetValue'] == 320
    profile = load('protocol/profile-v4.json')
    assert profile['nativeBridgeProtocolVersion'] == 4 and profile['sdkVersion'] == '3.0.1'
    assert profile['limits']['semanticBytes'] == 16384 and profile['limits']['justificationBytes'] == 65536
    assert profile['trustModel']['scope'] == 'fixed-sdk-root-trust-base'
    assert profile['trustModel']['validatorStake'] == '1'
    assert profile['trustModel']['verification'] == 'existing-sdk-3.0.1'
    assert profile['trustModel']['deferredIssue'] == 'https://github.com/ristik/bft-core/issues/421'
    for name, expected in profile['normativeArtifactSha256'].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, 'normative artifact digest mismatch'
    fixture = ROOT / 'protocol/vectors/config/sdk-root-trust-base.json'
    provenance = load('protocol/vectors/config/sdk-root-trust-base.provenance.json')
    assert provenance['sha256'] == 'e5454ae4fe566b05dab8c1b15c88a05356b8816b1cd66a2b7adcce184af27fb5'
    assert len(fixture.read_bytes()) == provenance['byteLength'] == 524
    validate_sdk_trust_document(fixture.read_bytes(), provenance['sha256'])
    subprocess.run(['node', str(ROOT / 'tools/sdk_trust_fixture.mjs')], check=True)
    if (ROOT / 'protocol/vectors/MANIFEST.sha256').exists():
        subprocess.run(['node', str(ROOT / 'tools/sdk_trust_fixture.mjs'), '--corpus', str(ROOT / 'protocol/vectors')], check=True)
    assert 'NATIVE_BRIDGE_PROTO_VERSION=4' in (ROOT / 'protocol/interop.md').read_text()
    assert JS_COMMIT in (ROOT / 'protocol/interop.md').read_text()
    assert RUST_COMMIT in (ROOT / 'protocol/interop.md').read_text()
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
    assert len(sdk_rust) == 1 and sdk_rust[0]['version'] == '4.0.0'
    assert sdk_rust[0]['source'].endswith('#' + SDK_RUST_FORK_COMMIT)
    for path in sorted((ROOT / 'deployments').glob('*.json')):
        validate_manifest(json.loads(path.read_text()))
    print('protocol/schema/dependency/ABI checks passed (no full installation authorization)')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, ValueError, KeyError) as exc:
        sys.exit(f'protocol: {exc}')
