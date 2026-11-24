"""Negative regression tests for the exact unsigned scope gate."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    'unsigned_scope_gate', Path(__file__).resolve().parents[1] / 'tools/check_unsigned_scope.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ScopeGateTests(unittest.TestCase):
    def index(self):
        return dict(gate.EXPECTED_BLOBS, **{name: '0' * 40 for name in gate.POLICY_PATHS})

    def test_exact_payload_accepted(self):
        gate.check_scope(self.index())

    def test_signing_and_unknown_file_rejected(self):
        for name in ('manifest_signatures.py', 'signing_keys.py', 'requirements-signing.txt',
                     'new_provider.py', 'tests_crypto/test_sign.py', 'new_runtime.dat'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                gate.check_scope(dict(self.index(), **{name: '0' * 40}))

    def test_changed_runtime_or_regression_rejected(self):
        for name in ('evidence_integrity.py', 'windows_root.py', 'tests/test_audit_remediation.py'):
            entries = self.index()
            entries[name] = '0' * 40
            with self.subTest(name=name), self.assertRaises(ValueError):
                gate.check_scope(entries)

    def test_missing_runtime_or_policy_rejected(self):
        for name in ('evidence_integrity.py', 'tools/check_unsigned_scope.py'):
            entries = self.index()
            del entries[name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                gate.check_scope(entries)
