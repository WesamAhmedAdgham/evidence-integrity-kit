"""Regression tests for ambiguous and non-standard JSON manifests."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from evidence_integrity import load_manifest

CLI = Path(__file__).resolve().parents[1] / 'evidence_integrity.py'


class ManifestJsonTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / 'a.txt').write_bytes(b'hello')
        self.path = self.root / 'manifest.json'
        self.valid = json.dumps({'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': 'a.txt', 'sha256': hashlib.sha256(b'hello').hexdigest()}]})

    def run_cli(self, raw):
        self.path.write_text(raw, encoding='utf-8')
        return subprocess.run([sys.executable, str(CLI), 'verify', '--root', str(self.root),
                               '--manifest', str(self.path)], capture_output=True, text=True, timeout=10)

    def assert_rejected(self, raw, message):
        result = self.run_cli(raw)
        self.assertEqual(result.returncode, 2, result)
        self.assertEqual(result.stdout, '')
        self.assertIn(message, result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_conflicting_top_level_key(self):
        self.assert_rejected(self.valid.replace('"version": 1', '"version": 2, "version": 1'),
                             'Duplicate JSON key')

    def test_duplicate_identical_key(self):
        self.assert_rejected(self.valid.replace('"version": 1', '"version": 1, "version": 1'),
                             'Duplicate JSON key')

    def test_nested_duplicate_path(self):
        self.assert_rejected(self.valid.replace('"path": "a.txt"', '"path": "b.txt", "path": "a.txt"'),
                             'Duplicate JSON key')

    def test_escaped_equivalent_key(self):
        self.assert_rejected(self.valid.replace('"version": 1', r'"vers\u0069on": 2, "version": 1'),
                             'Duplicate JSON key')

    def test_nonstandard_constants(self):
        for value in ('NaN', 'Infinity', '-Infinity'):
            with self.subTest(value=value):
                self.assert_rejected(self.valid[:-1] + ', "extra": ' + value + '}', 'Non-standard JSON constant')

    def test_valid_manifest(self):
        result = self.run_cli(self.valid)
        self.assertEqual(result.returncode, 0, result)
        self.assertTrue(json.loads(result.stdout)['ok'])
        self.assertEqual(load_manifest(self.path), json.loads(self.valid))

    def test_valid_extension_metadata(self):
        result = self.run_cli(self.valid[:-1] + ', "extra": {"label": "NaN", "number": 1.5}}')
        self.assertEqual(result.returncode, 0, result)

    def test_malformed_json(self):
        self.assert_rejected('{', 'Error:')


if __name__ == '__main__':
    unittest.main()
