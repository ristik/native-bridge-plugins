#!/usr/bin/env python3
"""Native bridge v2 profile/ABI digest checks and exact dependency pin checks."""
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
# the installed SDKs, the ones protocol/interop.md pins: the ristik lines (integration/enshrined-evm)
SDK_JS_FORK_COMMIT = 'c5840ef5f59201c52ea6cf7034ee02cb48d54007'
SDK_JS_FORK_VERSION = '4.0.0-utb.c5840ef'
SDK_RUST_FORK_COMMIT = 'de79e6c1e393a1846b75bca0640b9ec9a55aa143'
REQUIRED_ERC20_EVIDENCE = {
    'protocol/calibration/erc20-1349-native.json',
    'protocol/calibration/erc20-1349-live.json',
}
QUALIFIED_ERC20_EVIDENCE = 'protocol/calibration/erc20-qualified-release.json'


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
    assert 'previewPayout(address,uint256)' in abi['vault']['functions']
    assert abi['vault']['payoutPreview'] == {'gasLimit': 350_000, 'successRevert': 'PayoutPreviewPassed()'}
    digest = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    for impl in ('packages/native-bridge-plugin/src/nb2/bridge.ts', 'crates/native-bridge-sdk-ext/src/nb2/bridge.rs'):
        assert digest in (ROOT / impl).read_text(), f'ERC20 semantic profile digest mismatch: {impl}'
    vectors = 'protocol/vectors/erc20-nb2/'
    generator = load(vectors + 'generator.json')
    assert hashlib.sha256((ROOT / (vectors + 'vectors.json')).read_bytes()).hexdigest() == generator['sha256'], 'ERC20 vector digest mismatch'
    deployed = generator['contracts']['sdkFixture']
    assert hashlib.sha256((ROOT / (vectors + deployed['file'])).read_bytes()).hexdigest() == deployed['sha256'], 'ERC20 deployed fixture digest mismatch'
    check_erc20_release(digest, profile)


def check_erc20_release(digest, profile):
    release = load('protocol/release-erc20-calibration.json')
    assert release['artifactVersion'] == 1 and release['semanticProfileSha256'] == digest
    assert release['admissionCaps'] == {
        'submittedGas': 24_000_000, 'calldataBytes': 393_216, 'signedBytes': 524_288,
        'predecessorReceiptBytes': 65_536, 'startOperations': 16, 'resumeOperations': 8,
        'pages': 32, 'maxGapsPerCall': 1024, 'balanceProbeGas': profile['gasCaps']['balanceProbe'],
        'tokenTransferGas': profile['gasCaps']['tokenTransfer'], 'reserveSegments': 64,
    }
    evidence = release['evidence']
    assert isinstance(evidence, dict) and REQUIRED_ERC20_EVIDENCE <= evidence.keys(), 'missing required ERC20 evidence pin'
    for name, expected in evidence.items():
        path = Path(name)
        assert path.parent == Path('protocol/calibration') and path.suffix == '.json'
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected, f'ERC20 calibration evidence digest mismatch: {name}'
    qualified = release['fundingQualified']
    assert type(qualified) is bool, 'invalid ERC20 funding qualification flag'
    bounds = release['qualifiedBounds']
    fields(bounds, {'calls', 'arrivals', 'inclusionAndFunding'}, 'qualifiedBounds')
    complete = all(bound is not None for bound in bounds.values())
    assert not qualified or complete, 'ERC20 funding qualification requires all release bounds'
    if any(bound is not None for bound in bounds.values()):
        deployment = release.get('deployment')
        check_erc20_deployment(deployment)
        check_erc20_bounds(bounds, release['admissionCaps'], int(deployment['chainId']))
    if qualified or QUALIFIED_ERC20_EVIDENCE in evidence:
        assert QUALIFIED_ERC20_EVIDENCE in evidence, 'missing deployment-specific ERC20 qualification evidence pin'
        record = load(QUALIFIED_ERC20_EVIDENCE)
        fields(record, {'deployment', 'semanticProfileSha256', 'qualifiedBoundsSha256', 'walletManifestSha256',
                        'supportingEvidence'}, 'qualification evidence')
        assert complete, 'qualification evidence requires complete release bounds'
        assert record['deployment'] == release['deployment'], 'qualification evidence deployment mismatch'
        assert record['semanticProfileSha256'] == digest, 'qualification evidence semantic profile mismatch'
        canonical = json.dumps(bounds, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        assert record['qualifiedBoundsSha256'] == hashlib.sha256(canonical).hexdigest(), 'qualification evidence bounds mismatch'
        hex_field(record['walletManifestSha256'], 64, 'walletManifestSha256')
        support = record['supportingEvidence']
        fields(support, set(bounds), 'qualification supporting evidence')
        for name in support.values():
            assert isinstance(name, str) and name in evidence and name != QUALIFIED_ERC20_EVIDENCE, 'missing qualification supporting evidence pin'


def fields(value, expected, label):
    assert isinstance(value, dict) and value.keys() == expected, f'invalid ERC20 {label} fields'


def uint(value, minimum, maximum, label):
    assert type(value) is int and minimum <= value <= maximum, f'invalid ERC20 {label}'
    return value


def decimal(value, minimum, maximum, label):
    assert isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,77}', value), f'invalid ERC20 {label}'
    return uint(int(value), minimum, maximum, label)


def hex_field(value, digits, label, prefix=''):
    assert isinstance(value, str) and re.fullmatch(prefix + rf'[0-9a-f]{{{digits}}}', value), f'invalid ERC20 {label}'
    assert int(value, 16) != 0, f'zero ERC20 {label}'


def check_erc20_deployment(deployment):
    addresses = {'vault', 'recovery', 'token'}
    hashes = {'executionGenesis', 'rootPin', 'pins', 'vaultRuntimeHash', 'recoveryRuntimeHash', 'tokenRuntimeHash'}
    fields(deployment, addresses | hashes | {'chainId', 'authorityProfileSha256'}, 'deployment')
    decimal(deployment['chainId'], 1, 2**64 - 1, 'chainId')
    for name in addresses | hashes:
        hex_field(deployment[name], 40 if name in addresses else 64, name, '0x')
    hex_field(deployment['authorityProfileSha256'], 64, 'authorityProfileSha256')


def erc20_envelope_bytes(chain_id, calldata, gas):
    def prefix(n):
        return 1 if n <= 55 else 1 + (n.bit_length() + 7) // 8

    def integer(n):
        return 1 if n < 128 else 1 + (n.bit_length() + 7) // 8

    # Type 2, maximum nonce and fee widths, zero value, no access list, 32-byte r and s.
    body = integer(chain_id) + 9 + 33 + 33 + integer(gas) + 21 + 1 + prefix(calldata) + calldata + 1 + 1 + 33 + 33
    return 1 + prefix(body) + body


def check_erc20_calls(calls, caps, chain_id):
    fields(calls, {'maxStartOperations', 'maxResumeOperations', 'advanceBatch', 'envelopes'}, 'calls')
    start = uint(calls['maxStartOperations'], 1, caps['startOperations'], 'Start operation cap')
    resume = uint(calls['maxResumeOperations'], 1, caps['resumeOperations'], 'Resume operation cap')
    batch = uint(calls['advanceBatch'], 1, caps['maxGapsPerCall'], 'advance batch')
    envelopes = calls['envelopes']
    fields(envelopes, {'start', 'resume', 'advanceGaps', 'redeemRecovered', 'ordinary'}, 'envelopes')
    lengths = {'start': start, 'resume': resume, 'advanceGaps': batch, 'redeemRecovered': batch}
    for entry in envelopes:
        rows = envelopes[entry]
        expected = lengths.get(entry, batch)
        assert isinstance(rows, list) and (len(rows) == expected or entry == 'ordinary' and not rows), f'incomplete ERC20 {entry} envelope'
        for row in rows:
            fields(row, {'calldataBytes', 'signedBytes', 'executionGas', 'submittedGas'}, f'{entry} call')
            calldata = uint(row['calldataBytes'], 68, caps['calldataBytes'], f'{entry} calldata')
            execution = uint(row['executionGas'], 1, caps['submittedGas'], f'{entry} execution gas')
            allowance = 500_000 if entry == 'redeemRecovered' else 0
            minimum = 21_000 + 16 * calldata + (6 * execution + 4) // 5 + allowance
            gas = uint(row['submittedGas'], minimum, caps['submittedGas'], f'{entry} submitted gas')
            uint(row['signedBytes'], erc20_envelope_bytes(chain_id, calldata, gas), caps['signedBytes'], f'{entry} signed bytes')


def check_erc20_bounds(bounds, caps, chain_id):
    calls, arrivals, funding = (bounds[k] for k in ('calls', 'arrivals', 'inclusionAndFunding'))
    if calls is not None:
        check_erc20_calls(calls, caps, chain_id)
    maximum = 2**64 - 1
    if arrivals is not None:
        names = {'maxObservedBacklog', 'duringProgress', 'peakSeals', 'elapsedMs', 'receiptP99Ms',
                 'advancePeakSeals', 'advanceWindowMs', 'finalInclusionMs', 'finalPeakSeals', 'qualifiedForMs'}
        fields(arrivals, names, 'arrivals')
        for name in names:
            uint(arrivals[name], int(name.endswith('Ms')), maximum, name)
        assert arrivals['finalPeakSeals'] <= 1, 'ERC20 final arrival bound exceeds one seal'
        assert arrivals['advanceWindowMs'] >= arrivals['receiptP99Ms'], 'ERC20 advance window is below p99'
    if funding is not None:
        names = {'maxRunCalls', 'maxNonce', 'startingNonce', 'feeWindowMs', 'progressWindowMs',
                 'ordinaryAttempts', 'ordinaryInclusionMs'}
        money = {'maximumFeePerGas', 'priorityFeePerGas', 'freeBalance', 'authorizedBudget'}
        fields(funding, names | money, 'inclusion and funding')
        for name in names:
            uint(funding[name], int(name in {'maxRunCalls', 'feeWindowMs', 'progressWindowMs'}), maximum, name)
        for name in money:
            decimal(funding[name], int(name != 'priorityFeePerGas'), 2**256 - 1, name)
        assert int(funding['priorityFeePerGas']) <= int(funding['maximumFeePerGas']), 'ERC20 tip exceeds fee ceiling'
        assert funding['startingNonce'] <= funding['maxNonce'], 'invalid ERC20 nonce window'
        assert funding['ordinaryAttempts'] * funding['ordinaryInclusionMs'] <= funding['progressWindowMs'], 'ERC20 ordinary attempts exceed progress window'
        assert (funding['ordinaryAttempts'] == 0) == (funding['ordinaryInclusionMs'] == 0), 'invalid ERC20 ordinary inclusion window'
    if calls is None or arrivals is None or funding is None:
        return
    q = calls['advanceBatch']
    net = q - arrivals['advancePeakSeals']
    assert net > 0 and q * arrivals['elapsedMs'] >= 2 * arrivals['peakSeals'] * arrivals['receiptP99Ms'], 'invalid ERC20 catch-up bound'
    need = arrivals['maxObservedBacklog'] + caps['reserveSegments'] + arrivals['duringProgress']
    advance_count = (need + net - 1) // net
    continuation_ms = advance_count * arrivals['advanceWindowMs'] + arrivals['finalInclusionMs']
    assert continuation_ms <= arrivals['qualifiedForMs'], 'insufficient ERC20 service horizon'
    assert funding['progressWindowMs'] + continuation_ms <= funding['feeWindowMs'], 'insufficient ERC20 fee horizon'
    envelopes = calls['envelopes']
    attempts = funding['ordinaryAttempts']
    assert bool(envelopes['ordinary']) == bool(attempts), 'inconsistent ERC20 ordinary policy'
    gas = lambda entry: max(row['submittedGas'] for row in envelopes[entry])
    run_gas = max(gas('start'), gas('resume'))
    recovery = gas('start') + (funding['maxRunCalls'] - 1) * run_gas + advance_count * gas('advanceGaps') + gas('redeemRecovered')
    ordinary = gas('ordinary') if attempts else 0
    required_budget = (max(recovery, ordinary) + attempts * ordinary) * int(funding['maximumFeePerGas'])
    assert required_budget <= min(int(funding['freeBalance']), int(funding['authorizedBudget'])), 'insufficient ERC20 funded reserve'
    required_nonces = funding['maxRunCalls'] + advance_count + 1 + attempts
    assert funding['startingNonce'] + required_nonces - 1 <= funding['maxNonce'], 'insufficient ERC20 nonce reserve'


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
