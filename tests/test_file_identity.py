"""Deterministic pre-open file identity regression, synthetic data only."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence_integrity import generate, verify


class FileIdentityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.path = self.root / 'a.txt'
        self.path.write_bytes(b'synthetic')
        self.replacement = self.root / 'replacement.txt'
        self.replacement.write_bytes(b'synthetic')
        self.assertFalse(self.path.samefile(self.replacement))
        self.real_open = Path.open

    def swap_at_open(self, path, *args, **kwargs):
        if path == self.path:
            os.replace(self.replacement, self.path)
        return self.real_open(path, *args, **kwargs)

    def test_create_rejects_replacement_before_hashing(self):
        with patch.object(Path, 'open', lambda path, *a, **kw: self.swap_at_open(path, *a, **kw)), \
                patch('evidence_integrity.hashlib.file_digest', wraps=hashlib.file_digest) as digest:
            with self.assertRaisesRegex(ValueError, 'Evidence identity changed'):
                generate(self.root, ['a.txt'])
            digest.assert_not_called()
        self.assertFalse(self.replacement.exists())

    def test_verify_rejects_replacement_even_with_identical_content(self):
        manifest = generate(self.root, ['a.txt'])
        with patch.object(Path, 'open', lambda path, *a, **kw: self.swap_at_open(path, *a, **kw)), \
                patch('evidence_integrity.hashlib.file_digest', wraps=hashlib.file_digest) as digest:
            report = verify(self.root, manifest)
            digest.assert_not_called()
        self.assertFalse(report['ok'])
        self.assertEqual(report['files'][0]['status'], 'error')
        self.assertIn('Evidence identity changed', report['files'][0]['detail'])
        self.assertEqual(self.path.read_bytes(), b'synthetic')
        self.assertFalse(self.replacement.exists())

    def test_unchanged_file_remains_valid(self):
        manifest = generate(self.root, ['a.txt'])
        self.assertTrue(verify(self.root, manifest)['ok'])


if __name__ == '__main__':
    unittest.main()
