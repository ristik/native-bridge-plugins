"""Release qualification is a one-way gate over validated calibration data."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools import check_protocol as checker


RELEASE = 'protocol/release-erc20-calibration.json'


class Erc20ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.profile = checker.load('protocol/profile-erc20.json')
        self.release = checker.load(RELEASE)
        self.digest = self.release['semanticProfileSha256']
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
        self.release['deployment'] = {
            'chainId': '31337',
            **{name: '0x' + '11' * 20 for name in ('vault', 'recovery', 'token')},
            **{name: '0x' + 'ab' * 32 for name in ('executionGenesis', 'rootPin', 'pins',
                                                  'vaultRuntimeHash', 'recoveryRuntimeHash', 'tokenRuntimeHash')},
            'authorityProfileSha256': 'cd' * 32,
        }
        call = {'calldataBytes': 100_000, 'signedBytes': 100_220, 'executionGas': 900_000, 'submittedGas': 3_500_000}
        self.release['qualifiedBounds'] = {
            'calls': {
                'maxStartOperations': 1, 'maxResumeOperations': 1, 'advanceBatch': 3,
                'envelopes': {name: [deepcopy(call) for _ in range(count)] for name, count in {
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

    def pin_qualification(self, **overrides):
        bounds = self.release['qualifiedBounds']
        payload = json.dumps(bounds, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        record = {
            'deployment': self.release['deployment'],
            'semanticProfileSha256': self.digest,
            'qualifiedBoundsSha256': hashlib.sha256(payload).hexdigest(),
            'walletManifestSha256': 'ef' * 32,
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
