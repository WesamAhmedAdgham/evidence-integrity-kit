"""Portable lexical path policy, with synthetic evidence only."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence_integrity import generate, validate_relative_path, verify


class PortablePathTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / 'a.txt').write_bytes(b'a')
        self.manifest = generate(self.root, ['a.txt'])

    def test_reserved_device_names(self):
        for name in ('NUL', 'con.txt', 'PRN.doc', 'aux.log', 'COM1', 'lpt9.txt',
                     'COM¹.txt', 'LPT²', 'CONIN$', 'CONOUT$', 'CON .txt', 'a/NUL.txt'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_relative_path(name)

    def test_forbidden_characters_and_suffixes(self):
        for name in ('a.', 'a ', 'a./b', 'a /b', 'a<b', 'a>b', 'a"b', 'a|b',
                     'a?b', 'a*b', 'a:b', 'a\\b', 'a\n', 'a\x00', 'a\ud800'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_relative_path(name)

    def test_invalid_path_structure(self):
        for name in ('', '.', '..', '/a', 'a//b', 'a/../b', 'a/./b', 'a/', None, []):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_relative_path(name)

    def test_valid_names(self):
        for name in ('a.txt', '.hidden', 'my report.txt', 'nested/é.txt', 'COM10', 'auxiliary.txt'):
            with self.subTest(name=name):
                self.assertEqual(validate_relative_path(name), name.split('/'))

    def test_generate_rejects_late_invalid_path_before_io(self):
        with patch('evidence_integrity.evidence_path') as path, patch('evidence_integrity.digest') as digest:
            with self.assertRaises(ValueError):
                generate(self.root, ['a.txt', 'NUL.txt'])
            path.assert_not_called()
            digest.assert_not_called()

    def test_verify_rejects_late_invalid_path_before_io(self):
        for name in ('../outside', 'NUL.txt', 'a.', 'a\ud800'):
            with self.subTest(name=name):
                manifest = dict(self.manifest, files=self.manifest['files'] + [
                    {'path': name, 'sha256': 'a' * 64}])
                with patch('evidence_integrity.evidence_path') as path, patch('evidence_integrity.digest') as digest:
                    with self.assertRaises(ValueError):
                        verify(self.root, manifest)
                    path.assert_not_called()
                    digest.assert_not_called()

    def test_unicode_file_roundtrip(self):
        (self.root / 'é report.txt').write_bytes(b'synthetic')
        self.assertTrue(verify(self.root, generate(self.root, ['é report.txt']))['ok'])


if __name__ == '__main__':
    unittest.main()
