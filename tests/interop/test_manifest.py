import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('protocol', ROOT / 'tools/check_protocol.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def synthetic_policy(partition, depth, h):
    shards = [{'shardHex': s, 'configurationHash': h} for s in {0: ['80'], 1: ['40', 'c0']}[depth]]
    body = p.policy_body(partition, depth, shards)
    return {'bodyHex': body.hex(), 'sha256': hashlib.sha256(body).hexdigest(), 'partition': partition, 'depth': depth, 'shards': shards}


def synthetic():
    # Schema/cross-field test data only: never an installable deployment.
    h, a = 'a'*64, '1'*40
    artifact = {'sha256': h}
    dep = {'vaultAddress': a, 'vaultRuntimeHash': h, 'cfgHex': '00', 'cfgHash': hashlib.sha256(b'\0').hexdigest(), 'tokenVerifierAddress': '2'*40, 'tokenVerifierRuntimeHash': h, 'semanticProfile': artifact, 'b1': {'profile': artifact, 'registryAddress': a, 'registryRuntimeHash': h, 'registryLayout': artifact, 'genesis': artifact}, 'lockLayoutVersion': 1, 'aggregatorPolicy': synthetic_policy(1, 1, h), 'evmBackingPolicy': {'partition': 2, 'shardHex': '80', 'configurationHash': h, 'pdr': artifact, 'executionProfile': artifact}}
    d = f'1:{h}:{h}:1:' + '0'*40
    ty = hashlib.sha256(('unicity-bridge:unicity-native:' + d).encode()).hexdigest()
    coin = hashlib.sha256(('unicity-bridge-coin:unicity-native:' + d).encode()).hexdigest()
    e = {'schemaVersion': 1, 'protocolVersion': 3, 'family': 'unicity-native', 'sdkVersion': '3.0.1', 'tokenTypeHex': ty, 'coinIdHex': coin, 'symbol': 'TEST', 'decimals': 18, 'plugin': {'npm': {'name': '@unicitylabs/native-bridge-plugin', 'version': '0.1.0', 'integrity': 'sha512-'+'A'*86+'=='}, 'rust': {'crate': 'native-bridge-sdk-ext', 'version': '0.1.0', 'revision': 'b'*40}, 'protocolCommit': 'b'*40, 'vectorManifestSha256': h}, 'networkId': 1, 'rootGenesisHash': h, 'executionGenesisHash': h, 'evmChainId': '1', 'chainRef': 'eip155:1', 'asset': '0'*40, 'activeDeployment': dep, 'replacedDeployments': [], 'trustBase': {'networkId': 1, 'rootGenesisHash': h, 'document': artifact, 'format': 'sdk-root-trust-base-json-v1'}}
    return {ty: e}


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.registry = synthetic()
        self.entry = next(iter(self.registry.values()))

    def test_structural_offline_manifest(self):
        p.validate_manifest(self.registry)

    def test_missing_embedded_policy_pin(self):
        del self.entry['activeDeployment']['evmBackingPolicy']['configurationHash']
        with self.assertRaises(ValidationError):
            p.validate_manifest(self.registry)

    def test_policy_depths_and_noncanonical(self):
        h = 'a' * 64
        for depth in (0, 1):
            self.entry['activeDeployment']['aggregatorPolicy'] = synthetic_policy(1, depth, h)
            p.validate_manifest(self.registry)
        pol = self.entry['activeDeployment']['aggregatorPolicy']
        for mutate in (lambda q: q.update(depth=2), lambda q: q.update(partition=0),
                       lambda q: q['shards'].reverse(), lambda q: q['shards'].pop(),
                       lambda q: q['shards'][0].update(shardHex='80'), lambda q: q.update(shardHex='80')):
            self.entry['activeDeployment']['aggregatorPolicy'] = copy.deepcopy(pol)
            mutate(self.entry['activeDeployment']['aggregatorPolicy'])
            with self.assertRaises((ValidationError, AssertionError)):
                p.validate_manifest(self.registry)
        bad = copy.deepcopy(pol)
        bad['bodyHex'] = bad['bodyHex'][:-2] + '00'
        bad['sha256'] = hashlib.sha256(bytes.fromhex(bad['bodyHex'])).hexdigest()
        self.entry['activeDeployment']['aggregatorPolicy'] = bad
        with self.assertRaisesRegex(AssertionError, 'canonical'):
            p.validate_manifest(self.registry)

    def test_old_protocol(self):
        self.entry['protocolVersion'] = 1
        with self.assertRaises(ValidationError):
            p.validate_manifest(self.registry)

    def test_unknown_fields(self):
        self.entry['activeDeployment']['fetchOnVerify'] = True
        with self.assertRaises(ValidationError):
            p.validate_manifest(self.registry)

    def test_numeric_chain_id(self):
        self.entry['evmChainId'] = 1
        with self.assertRaises(ValidationError):
            p.validate_manifest(self.registry)

    def test_chain_overflow(self):
        self.entry['evmChainId'] = str(1 << 64)
        with self.assertRaisesRegex(AssertionError, 'outside uint64'):
            p.validate_manifest(self.registry)

    def test_duplicate_vault(self):
        self.entry['replacedDeployments'] = [copy.deepcopy(self.entry['activeDeployment'])]
        with self.assertRaisesRegex(AssertionError, 'ambiguous vault'):
            p.validate_manifest(self.registry)

    def test_wrong_coin(self):
        self.entry['coinIdHex'] = 'f'*64
        with self.assertRaisesRegex(AssertionError, 'coin ID mismatch'):
            p.validate_manifest(self.registry)

    def test_bad_hash(self):
        self.entry['activeDeployment']['cfgHash'] = 'f'*64
        with self.assertRaisesRegex(AssertionError, 'bytes digest mismatch'):
            p.validate_manifest(self.registry)

    def test_sdk_network_range(self):
        for network in (0, 1, 65535, 65536):
            for trust_only in (False, True):
                with self.subTest(network=network, trust_only=trust_only):
                    registry = synthetic()
                    entry = next(iter(registry.values()))
                    entry['trustBase']['networkId'] = network
                    if not trust_only:
                        entry['networkId'] = network
                    if 1 <= network <= 65535:
                        p.validator().validate(registry)
                    else:
                        with self.assertRaises(ValidationError):
                            p.validator().validate(registry)

    def test_wrong_trust_network(self):
        self.entry['trustBase']['networkId'] = 2
        with self.assertRaisesRegex(AssertionError, 'trust anchor mismatch'):
            p.validate_manifest(self.registry)

    def test_old_epoch_bundle_rejected(self):
        self.entry['trustBase']['bundle'] = self.entry['trustBase'].pop('document')
        self.entry['trustBase']['format'] = 'native-epoch-indexed-v1'
        with self.assertRaises(ValidationError):
            p.validate_manifest(self.registry)

    def test_trust_document_digest_required(self):
        del self.entry['trustBase']['document']['sha256']
        with self.assertRaises(ValidationError):
            p.validate_manifest(self.registry)

    def test_trust_update_fields_rejected(self):
        self.entry['trustBase']['successor'] = 'f' * 64
        with self.assertRaises(ValidationError):
            p.validate_manifest(self.registry)

    def test_nonempty_aggregator_prefix(self):
        self.entry['activeDeployment']['aggregatorPolicy']['shardHex'] = 'c0'
        with self.assertRaises(ValidationError):
            p.validate_manifest(self.registry)

    def test_wrong_registry_key(self):
        e = self.registry.pop(next(iter(self.registry)))
        self.registry['f'*64] = e
        with self.assertRaisesRegex(AssertionError, 'registry key mismatch'):
            p.validate_manifest(self.registry)


if __name__ == '__main__':
    unittest.main()
