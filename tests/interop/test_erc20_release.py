"""Release qualification is a one-way gate over validated calibration data."""

from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools import check_protocol as checker


RELEASE = 'protocol/release-erc20-calibration.json'
DEPLOYMENT_FIXTURE = 'protocol/vectors/erc20-nb2/sdk-deployment.json.gz'


class Erc20ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.profile = checker.load('protocol/profile-erc20.json')
        self.release = checker.load(RELEASE)
        self.digest = self.release['semanticProfileSha256']
        self.fixture = json.loads(gzip.decompress((checker.ROOT / DEPLOYMENT_FIXTURE).read_bytes()))
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in self.release['evidence']:
            self.write_bytes(name, (checker.ROOT / name).read_bytes())
        mock = patch.object(checker, 'ROOT', self.root)
        mock.start()
        self.addCleanup(mock.stop)

    def write_bytes(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def check(self):
        self.write_bytes(RELEASE, json.dumps(self.release).encode())
        checker.check_erc20_release(self.digest, self.profile)

    def complete(self):
        asset = self.fixture['assets'][1]
        config = bytes.fromhex(asset['config'][2:])
        length = int.from_bytes(config[32:64], 'big')
        self.gamma = config[64:64 + length]
        log = self.fixture['activation']['logs'][1]['data'][2:]
        self.release['deployment'] = {
            'chainId': '31337',
            **{name: asset[name] for name in ('vault', 'recovery', 'token')},
            'executionGenesis': self.fixture['genesis']['hash'],
            'rootPin': '0x8d0759c87fd19a9677e12e605655dd90d8ce1ae78d713c032fd693c53df93366',
            'pins': '0x396fe025656869b30d83929df20dddc5dc848b2f23a1620a19c985ea45ce9687',
            'vaultRuntimeHash': '0x' + log[64:128],
            'recoveryRuntimeHash': '0x' + log[128:192],
            'tokenRuntimeHash': '0x' + 'ab' * 32,
            'gammaSha256': hashlib.sha256(self.gamma).hexdigest(),
            'authorityProfileSha256': 'cd' * 32,
        }
        call = {'calldataBytes': 100_000, 'signedBytes': 100_220, 'executionGas': 900_000, 'submittedGas': 3_500_000}
        run = {**call, 'calldataBytes': 230_000, 'signedBytes': 230_220, 'submittedGas': 5_000_000}
        self.release['qualifiedBounds'] = {
            'calls': {
                'maxStartOperations': 1, 'maxResumeOperations': 1, 'advanceBatch': 3,
                'envelopes': {name: [deepcopy(run if name in {'start', 'resume'} else call) for _ in range(count)] for name, count in {
                    'start': 1, 'resume': 1, 'advanceGaps': 3, 'redeemRecovered': 3, 'ordinary': 0,
                }.items()},
            },
            'arrivals': {
                'maxObservedBacklog': 3, 'duringProgress': 3, 'peakSeals': 2, 'elapsedMs': 30_000,
                'receiptP99Ms': 5_000, 'advancePeakSeals': 1, 'advanceWindowMs': 8_000,
                'finalInclusionMs': 9_000, 'finalPeakSeals': 1, 'qualifiedForMs': 300_000,
            },
            'inclusionAndFunding': {
                'maxRunCalls': 4, 'maxNonce': 255, 'startingNonce': 0, 'feeWindowMs': 500_000,
                'progressWindowMs': 180_000, 'ordinaryAttempts': 0, 'ordinaryInclusionMs': 0,
                'maximumFeePerGas': '2000000', 'priorityFeePerGas': '500000',
                'freeBalance': '1000000000000000000', 'authorizedBudget': '1000000000000000000',
            },
        }

    def make_manifest(self, *, funding=True, reserve=500_000):
        deployment = self.release['deployment']
        bounds = self.release['qualifiedBounds']
        timing = bounds['inclusionAndFunding']
        ranges = []
        for entry, rows in bounds['calls']['envelopes'].items():
            if entry == 'ordinary':
                continue
            run = entry in {'start', 'resume'}
            opening = {'start': 24_740, 'resume': 16_482}.get(entry, 0)
            for i, row in enumerate(rows):
                ranges.append({'minReceiptBytes': 0 if entry == 'start' else 1, 'execution': str(row['executionGas']),
                               'max': {'entry': 'run' if run else entry, 'operations': i + 1 if run else 0,
                                       'gaps': 0 if run else i + int(entry == 'advanceGaps'),
                                       'pages': 32 if run else 0, 'openingBytes': opening,
                                       'receiptBytes': 0 if entry == 'start' else 65_536,
                                       'calldataBytes': row['calldataBytes']}})
        return {
            'pins': {'gamma': '0x' + self.gamma.hex(), 'build': 'production', 'stateReadOnly': False,
                     'vaultRuntimeCodeHash': deployment['vaultRuntimeHash'], 'gasReserve': str(reserve),
                     'userGasLimit': '24000000', 'maxEncodedTxBytes': 524_288, 'returnReserveSegments': 64,
                     'deploymentBlock': int(self.fixture['activation']['blockNumber'], 16),
                     'erc20': {'fundingQualified': funding, 'factory': self.fixture['factory'],
                               'factoryRuntimeHash': '0x44c45c4feecc27a4fab03dcefea2c4297166783a2c51e87763ecc0034ae744f0',
                               'vaultInitcodeHash': self.fixture['vaultInitcodeHash'],
                               'recoveryInitcodeHash': self.fixture['recoveryInitcodeHash'],
                               'activationTx': self.fixture['activation']['transactionHash']}},
            'trust': {'bundle': 'trust-base.bundle.cbor'},
            'recovery': {'salt': self.fixture['generation'], 'address': deployment['recovery'],
                         'runtimeHash': deployment['recoveryRuntimeHash'], 'pins': deployment['pins'], 'ranges': ranges,
                         'backlog': {name: str(value) for name, value in bounds['arrivals'].items()
                                     if name not in {'maxObservedBacklog', 'advanceWindowMs'}},
                         'signingWindows': {'progressWindowMs': str(timing['progressWindowMs']), 'maxRunCalls': timing['maxRunCalls'],
                                            'advanceWindowMs': str(bounds['arrivals']['advanceWindowMs']),
                                            'ordinaryInclusionMs': str(timing['ordinaryInclusionMs'])}},
        }

    def pin_qualification(self, *, manifest=None, **overrides):
        bounds = self.release['qualifiedBounds']
        payload = json.dumps(bounds, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        if manifest is None:
            manifest = self.make_manifest()
        manifest_path = checker.QUALIFIED_ERC20_MANIFEST
        self.release['evidence'][manifest_path] = self.write_bytes(manifest_path, json.dumps(manifest).encode())
        record = {
            'deployment': self.release['deployment'],
            'semanticProfileSha256': self.digest,
            'qualifiedBoundsSha256': hashlib.sha256(payload).hexdigest(),
            'walletManifestSha256': self.release['evidence'][manifest_path],
            'supportingEvidence': dict.fromkeys(bounds, sorted(checker.REQUIRED_ERC20_EVIDENCE)[0]),
            **overrides,
        }
        path = checker.QUALIFIED_ERC20_EVIDENCE
        self.release['evidence'][path] = self.write_bytes(path, json.dumps(record).encode())

    def test_observational_profile_is_valid(self):
        self.check()

    def test_true_flag_refuses_null_and_empty_bounds(self):
        self.release['fundingQualified'] = True
        with self.assertRaisesRegex(AssertionError, 'requires all release bounds'):
            self.check()
        self.complete()
        self.release['qualifiedBounds'] = dict.fromkeys(self.release['qualifiedBounds'], {})
        with self.assertRaisesRegex(AssertionError, 'invalid ERC20 calls fields'):
            self.check()

    def test_missing_section_is_refused(self):
        del self.release['qualifiedBounds']['arrivals']
        with self.assertRaisesRegex(AssertionError, 'invalid ERC20 qualifiedBounds fields'):
            self.check()

    def test_either_missing_or_changed_evidence_pin_is_refused(self):
        original = self.release['evidence'].copy()
        for name, expected in original.items():
            with self.subTest(name=name):
                del self.release['evidence'][name]
                with self.assertRaisesRegex(AssertionError, 'missing required ERC20 evidence pin'):
                    self.check()
                self.release['evidence'][name] = expected
                path = self.root / name
                raw = path.read_bytes()
                path.write_bytes(raw + b' ')
                with self.assertRaisesRegex(AssertionError, 'calibration evidence digest mismatch'):
                    self.check()
                path.write_bytes(raw)

    def test_complete_candidate_can_stay_false(self):
        self.complete()
        self.check()
        self.pin_qualification()
        self.check()

    def test_promotion_requires_the_exact_wallet_manifest(self):
        self.complete()
        self.release['fundingQualified'] = True
        self.pin_qualification(manifest=self.make_manifest(funding=False))
        with self.assertRaisesRegex(AssertionError, 'must enable funding'):
            self.check()
        self.pin_qualification()
        manifest = checker.QUALIFIED_ERC20_MANIFEST
        del self.release['evidence'][manifest]
        with self.assertRaisesRegex(AssertionError, 'qualified ERC20 wallet manifest pin'):
            self.check()
        self.pin_qualification()
        self.write_bytes(manifest, (self.root / manifest).read_bytes() + b'\n')
        with self.assertRaisesRegex(AssertionError, 'evidence digest mismatch'):
            self.check()

    def test_true_flag_requires_deployment_specific_evidence(self):
        self.complete()
        self.release['fundingQualified'] = True
        with self.assertRaisesRegex(AssertionError, 'missing deployment-specific'):
            self.check()
        self.pin_qualification(deployment={**self.release['deployment'], 'chainId': '1'})
        with self.assertRaisesRegex(AssertionError, 'deployment mismatch'):
            self.check()
        self.pin_qualification(qualifiedBoundsSha256='01' * 32)
        with self.assertRaisesRegex(AssertionError, 'bounds mismatch'):
            self.check()
        self.pin_qualification()
        self.check()

    def test_promotion_refuses_malformed_manifest_and_mismatched_recovery(self):
        self.complete()
        self.release['fundingQualified'] = True
        cases = [
            ('recovery', 'pins', '0x' + '01' * 32, 'recovery pins differ from gamma'),
            ('recovery', 'runtimeHash', '0x' + '01' * 32, 'recoveryRuntimeHash mismatch'),
            ('recovery', 'ranges', [], 'incomplete ERC20 wallet manifest recovery ranges'),
            ('pins', 'gamma', '0x1234', 'ConfigShape'),
        ]
        for section, field, value, reason in cases:
            with self.subTest(field=field):
                manifest = self.make_manifest()
                manifest[section][field] = value
                self.pin_qualification(manifest=manifest)
                with self.assertRaisesRegex(AssertionError, reason):
                    self.check()
        manifest = self.make_manifest()
        resume = next(r for r in manifest['recovery']['ranges']
                      if r['max']['entry'] == 'run' and r['minReceiptBytes'] == 1)
        resume['max']['receiptBytes'] -= 1
        self.pin_qualification(manifest=manifest)
        with self.assertRaisesRegex(AssertionError, 'incomplete ERC20 wallet manifest recovery ranges'):
            self.check()

    def test_promotion_refuses_mismatched_windows_and_gamma_digest(self):
        self.complete()
        self.release['fundingQualified'] = True
        manifest = self.make_manifest()
        manifest['recovery']['signingWindows']['advanceWindowMs'] = '9000'
        self.pin_qualification(manifest=manifest)
        with self.assertRaisesRegex(AssertionError, 'signing window advanceWindowMs mismatch'):
            self.check()
        self.release['deployment']['gammaSha256'] = '01' * 32
        self.pin_qualification()
        with self.assertRaisesRegex(AssertionError, 'gammaSha256 mismatch'):
            self.check()

    def test_promotion_refuses_unquotable_run_shapes(self):
        self.complete()
        self.release['fundingQualified'] = True
        cases = [
            (0, 'openingBytes', 18_000, 'cannot quote Start'),
            (1, 'openingBytes', 16_481, 'cannot quote Resume'),
            (1, 'pages', 11, 'cannot quote the terminal Resume'),
        ]
        for minimum, field, value, reason in cases:
            with self.subTest(field=field, minimum=minimum):
                manifest = self.make_manifest()
                run = next(r for r in manifest['recovery']['ranges']
                           if r['max']['entry'] == 'run' and r['minReceiptBytes'] == minimum)
                run['max'][field] = value
                self.pin_qualification(manifest=manifest)
                with self.assertRaisesRegex(AssertionError, reason):
                    self.check()

        self.release['qualifiedBounds']['calls']['envelopes']['start'][0].update(
            calldataBytes=32_000, signedBytes=32_220)
        self.pin_qualification()
        with self.assertRaisesRegex(AssertionError, 'cannot quote Start'):
            self.check()

    def test_promotion_refuses_test_only_or_nonstandard_pins(self):
        self.complete()
        self.release['fundingQualified'] = True
        for field, value in [('stateReadOnly', True), ('maxEncodedTxBytes', 400_000)]:
            with self.subTest(pin=field):
                manifest = self.make_manifest()
                manifest['pins'][field] = value
                self.pin_qualification(manifest=manifest)
                with self.assertRaisesRegex(AssertionError, field):
                    self.check()

    def enable_ordinary(self, *, reserve=500_000, gaps=70, execution=900_001):
        bounds = self.release['qualifiedBounds']
        bounds['inclusionAndFunding'].update(ordinaryAttempts=1, ordinaryInclusionMs=9_000)
        evidence = 100_000
        history = 32 + 257 * gaps
        calldata = 196 + evidence + 32 * ((history + 31) // 32)
        minimum = 21_000 + 16 * calldata + (6 * execution + 4) // 5 + max(500_000, reserve)
        row = {'calldataBytes': calldata, 'signedBytes': calldata + 200, 'executionGas': execution, 'submittedGas': minimum}
        bounds['calls']['envelopes']['ordinary'][:] = [row.copy() for _ in range(3)]
        manifest = self.make_manifest(reserve=reserve)
        manifest['recovery']['ordinaryRanges'] = [
            {'maxEvidenceBytes': evidence, 'maxOperations': 16, 'maxGaps': str(gaps), 'execution': str(execution)},
        ]
        return manifest

    def test_minimum_ordinary_gas_uses_the_manifest_reserve_with_a_floor(self):
        self.complete()
        self.release['fundingQualified'] = True
        ordinary = self.release['qualifiedBounds']['calls']['envelopes']['ordinary']
        for reserve in [250_000, 700_000]:
            with self.subTest(reserve=reserve):
                manifest = self.enable_ordinary(reserve=reserve)
                self.pin_qualification(manifest=manifest)
                self.check()
                ordinary[1]['submittedGas'] -= 1
                self.pin_qualification(manifest=manifest)
                with self.assertRaisesRegex(AssertionError, 'ordinary submitted gas'):
                    self.check()

    def test_ordinary_requires_full_preflight_history(self):
        self.complete()
        self.release['fundingQualified'] = True
        self.pin_qualification(manifest=self.enable_ordinary(gaps=2))
        with self.assertRaisesRegex(AssertionError, 'cannot cover preflight history'):
            self.check()

    def test_each_ordinary_suffix_covers_every_declared_range(self):
        self.complete()
        self.release['fundingQualified'] = True
        manifest = self.enable_ordinary()
        manifest['recovery']['ordinaryRanges'].append(
            {'maxEvidenceBytes': 80_000, 'maxOperations': 20, 'maxGaps': '72', 'execution': '950001'})
        rows = self.release['qualifiedBounds']['calls']['envelopes']['ordinary']
        for row in rows:
            row['executionGas'] += 50_000
            row['submittedGas'] += 60_000
        for suffix, row in enumerate(rows):
            with self.subTest(suffix=suffix):
                row['calldataBytes'] -= 1
                self.pin_qualification(manifest=manifest)
                with self.assertRaisesRegex(AssertionError, f'exceeds reviewed envelope for suffix {suffix}'):
                    self.check()
                row['calldataBytes'] += 1
        rows[1]['executionGas'] -= 1
        self.pin_qualification(manifest=manifest)
        with self.assertRaisesRegex(AssertionError, 'exceeds reviewed envelope for suffix 1'):
            self.check()
        rows[1]['executionGas'] += 1
        self.pin_qualification(manifest=manifest)
        self.check()

    def test_invalid_values_cannot_be_qualified(self):
        self.complete()
        self.release['fundingQualified'] = True
        cases = [
            ('calls', 'advanceBatch', True, 'advance batch'),
            ('arrivals', 'finalPeakSeals', 2, 'exceeds one seal'),
            ('arrivals', 'advancePeakSeals', 3, 'catch-up bound'),
            ('inclusionAndFunding', 'authorizedBudget', '1', 'funded reserve'),
            ('inclusionAndFunding', 'maxNonce', 1, 'nonce reserve'),
        ]
        for section, key, value, reason in cases:
            with self.subTest(section=section, key=key):
                bound = self.release['qualifiedBounds'][section]
                original = bound[key]
                bound[key] = value
                self.pin_qualification()
                with self.assertRaisesRegex(AssertionError, reason):
                    self.check()
                bound[key] = original

    def test_every_suffix_and_signed_envelope_are_required(self):
        self.complete()
        envelopes = self.release['qualifiedBounds']['calls']['envelopes']
        missing = envelopes['redeemRecovered'].pop()
        with self.assertRaisesRegex(AssertionError, 'incomplete ERC20 redeemRecovered'):
            self.check()
        envelopes['redeemRecovered'].append(missing)
        missing['signedBytes'] = missing['calldataBytes']
        with self.assertRaisesRegex(AssertionError, 'redeemRecovered signed bytes'):
            self.check()
