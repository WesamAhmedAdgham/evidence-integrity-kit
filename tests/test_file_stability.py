"""Detect observable evidence changes during hashing, using synthetic files."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence_integrity import generate, verify


class FileStabilityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / 'a.txt'
        self.path.write_bytes(b'synthetic')
        self.real_digest = hashlib.file_digest

    def append_after_read(self, stream, algorithm):
        result = self.real_digest(stream, algorithm)
        with self.path.open('ab') as writer:
            writer.write(b'changed')
        return result

    def test_create_rejects_change_during_digest(self):
        with patch('evidence_integrity.hashlib.file_digest', side_effect=self.append_after_read):
            with self.assertRaisesRegex(ValueError, 'Evidence changed during hashing'):
                generate(self.root, ['a.txt'])
        self.assertEqual(self.path.read_bytes(), b'syntheticchanged')

    def test_verify_rejects_change_even_if_hash_matches(self):
        manifest = generate(self.root, ['a.txt'])
        with patch('evidence_integrity.hashlib.file_digest', side_effect=self.append_after_read):
            report = verify(self.root, manifest)
        self.assertFalse(report['ok'])
        self.assertEqual(report['files'][0]['status'], 'error')
        self.assertIn('Evidence changed during hashing', report['files'][0]['detail'])
        self.assertEqual(self.path.read_bytes(), b'syntheticchanged')

    def test_stable_file_still_matches(self):
        manifest = generate(self.root, ['a.txt'])
        self.assertEqual(manifest['files'][0]['sha256'], hashlib.sha256(b'synthetic').hexdigest())
        self.assertTrue(verify(self.root, manifest)['ok'])


if __name__ == '__main__':
    unittest.main()
