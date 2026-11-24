"""Release provider policy checks without a network or crypto dependency."""
import copy
import unittest
from unittest.mock import patch

from tools import check_release_provider as gate


class ProviderGateTests(unittest.TestCase):
    def test_known_affected_provider_is_blocked(self):
        allowed, reason = gate.provider_status('50.0.2', 'OpenSSL 4.0.3 29 Sep 2026')
        self.assertFalse(allowed)
        self.assertIn('November 2026', reason)

    def test_newer_provider_not_implicitly_approved(self):
        for provider in ('OpenSSL 4.0.4 17 Nov 2026', 'OpenSSL 4.1.1 17 Nov 2026',
                         'OpenSSL 9.0.0'):
            with self.subTest(provider=provider):
                self.assertFalse(gate.provider_status('99.0.0', provider)[0])

    def test_unknown_provider_is_blocked(self):
        for provider in ('LibreSSL 4.1.0', 'OpenSSL unknown', ''):
            with self.subTest(provider=provider):
                self.assertFalse(gate.provider_status('50.0.2', provider)[0])

    def test_exact_reviewed_pair_required(self):
        pair = ('synthetic-version', 'OpenSSL 4.0.4 17 Nov 2026')
        with patch.object(gate, 'APPROVED_PROVIDERS', frozenset({pair})):
            self.assertTrue(gate.provider_status(*pair)[0])
            self.assertFalse(gate.provider_status('different', pair[1])[0])
            self.assertFalse(gate.provider_status(pair[0], 'OpenSSL 4.0.4')[0])

    def test_point_validator_requires_explicit_approval(self):
        self.assertFalse(gate.validator_status('1.6.2')[0])
        self.assertFalse(gate.validator_status('99.0.0')[0])
        with patch.object(gate, 'APPROVED_POINT_VALIDATORS', frozenset({'synthetic'})):
            self.assertTrue(gate.validator_status('synthetic')[0])
            self.assertFalse(gate.validator_status('1.6.2')[0])

    def test_known_affected_pair_cannot_be_approved_by_allowlist(self):
        pair = ('50.0.2', 'OpenSSL 4.0.3 29 Sep 2026')
        with patch.object(gate, 'APPROVED_PROVIDERS', frozenset({pair})):
            self.assertFalse(gate.provider_status(*pair)[0])


class ArtifactApprovalTests(unittest.TestCase):
    def setUp(self):
        self.pins = {'cryptography': ('99.0', {'a' * 64, 'd' * 64}),
                     'pynacl': ('99.1', {'b' * 64}),
                     'cffi': ('99.2', {'c' * 64}),
                     'pycparser': ('99.3', {'e' * 64})}
        self.wheels = {name: {'version': pin[0], 'wheel': name + '-test.whl',
                              'sha256': sorted(pin[1])[0]} for name, pin in self.pins.items()}
        self.runtime = {'cryptography': '99.0', 'openssl': 'OpenSSL 4.0.4 synthetic',
                        'pynacl': '99.1', 'python_implementation': 'CPython',
                        'python_major_minor': '3.13', 'system': 'Linux', 'machine': 'x86_64'}
        self.digest = gate.approval_digest(gate.approval_record(self.pins, self.wheels, self.runtime))

    def test_real_allowlists_remain_empty(self):
        # This draft does not carry any release approval.
        self.assertFalse(gate.APPROVED_PROVIDERS)
        self.assertFalse(gate.APPROVED_POINT_VALIDATORS)
        self.assertFalse(gate.APPROVED_ENVIRONMENTS)

    def test_version_approval_alone_never_authorizes_artifacts(self):
        with patch.object(gate, 'APPROVED_PROVIDERS',
                          frozenset({('99.0', self.runtime['openssl'])})), \
                patch.object(gate, 'APPROVED_POINT_VALIDATORS', frozenset({'99.1'})):
            result = gate.release_decision(self.pins, self.wheels, self.runtime)
            self.assertFalse(result['provider_release_gate_passed'])
            self.assertIn('not release-approved', result['environment_reason'])

    def test_exact_reviewed_record_and_both_providers_required(self):
        with patch.object(gate, 'APPROVED_ENVIRONMENTS', frozenset({self.digest})):
            self.assertFalse(gate.release_decision(self.pins, self.wheels, self.runtime)
                             ['provider_release_gate_passed'])
            with patch.object(gate, 'APPROVED_PROVIDERS',
                              frozenset({('99.0', self.runtime['openssl'])})), \
                    patch.object(gate, 'APPROVED_POINT_VALIDATORS', frozenset({'99.1'})):
                self.assertTrue(gate.release_decision(self.pins, self.wheels, self.runtime)
                                ['provider_release_gate_passed'])

    def test_any_artifact_or_lock_or_runtime_change_requires_new_approval(self):
        with patch.object(gate, 'APPROVED_PROVIDERS',
                          frozenset({('99.0', self.runtime['openssl'])})), \
                patch.object(gate, 'APPROVED_POINT_VALIDATORS', frozenset({'99.1'})), \
                patch.object(gate, 'APPROVED_ENVIRONMENTS', frozenset({self.digest})):
            for change in ('wheel_digest', 'wheel_filename', 'transitive_digest',
                           'extra_locked_hash', 'machine', 'python', 'system'):
                with self.subTest(change=change):
                    pins, wheels, runtime = copy.deepcopy((self.pins, self.wheels, self.runtime))
                    if change == 'wheel_digest':
                        wheels['cryptography']['sha256'] = 'd' * 64
                    elif change == 'wheel_filename':
                        wheels['cryptography']['wheel'] = 'other.whl'
                    elif change == 'transitive_digest':
                        pins['cffi'][1].add('f' * 64)
                        wheels['cffi']['sha256'] = 'f' * 64
                    elif change == 'extra_locked_hash':
                        pins['pycparser'][1].add('f' * 64)
                    elif change == 'machine':
                        runtime['machine'] = 'aarch64'
                    elif change == 'python':
                        runtime['python_major_minor'] = '3.11'
                    else:
                        runtime['system'] = 'Windows'
                    self.assertFalse(gate.release_decision(pins, wheels, runtime)
                                     ['provider_release_gate_passed'])

    def test_canonical_record_digest_independent_of_mapping_order(self):
        reverse = lambda mapping: dict(reversed(list(mapping.items())))
        record = gate.approval_record(reverse(self.pins), reverse(self.wheels), reverse(self.runtime))
        self.assertEqual(gate.approval_digest(record), self.digest)

    def test_known_affected_provider_cannot_pass_all_artifact_approvals(self):
        runtime = dict(self.runtime, openssl='OpenSSL 4.0.3 synthetic')
        digest = gate.approval_digest(gate.approval_record(self.pins, self.wheels, runtime))
        with patch.object(gate, 'APPROVED_PROVIDERS',
                          frozenset({('99.0', runtime['openssl'])})), \
                patch.object(gate, 'APPROVED_POINT_VALIDATORS', frozenset({'99.1'})), \
                patch.object(gate, 'APPROVED_ENVIRONMENTS', frozenset({digest})):
            self.assertFalse(gate.release_decision(self.pins, self.wheels, runtime)
                             ['provider_release_gate_passed'])


if __name__ == '__main__':
    unittest.main()
