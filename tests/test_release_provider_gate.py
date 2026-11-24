"""Release provider policy checks without a network or crypto dependency."""
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


if __name__ == '__main__':
    unittest.main()
