"""Post-hash pathname identity checks with synthetic evidence."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence_integrity import generate, verify


class PostHashPathTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.folder = self.root / 'folder'
        self.folder.mkdir()
        self.path = self.folder / 'a.txt'
        self.path.write_bytes(b'synthetic')
        self.other = self.root / 'other'
        self.other.mkdir()
        (self.other / 'a.txt').write_bytes(b'replacement')
        self.real_digest = hashlib.file_digest

    def move_parent_after_read(self, stream, algorithm):
        result = self.real_digest(stream, algorithm)
        self.folder.rename(self.root / 'old')
        self.other.rename(self.folder)
        return result

    @unittest.skipUnless(os.name == 'posix', 'Open-parent rename fixture requires POSIX')
    def test_create_rejects_parent_replacement(self):
        with patch('evidence_integrity.hashlib.file_digest', side_effect=self.move_parent_after_read):
            with self.assertRaisesRegex(ValueError, 'Evidence path changed'):
                generate(self.root, ['folder/a.txt'])
        self.assertEqual(self.path.read_bytes(), b'replacement')

    @unittest.skipUnless(os.name == 'posix', 'Open-parent rename fixture requires POSIX')
    def test_verify_rejects_parent_replacement(self):
        manifest = generate(self.root, ['folder/a.txt'])
        with patch('evidence_integrity.hashlib.file_digest', side_effect=self.move_parent_after_read):
            report = verify(self.root, manifest)
        self.assertFalse(report['ok'])
        self.assertEqual(report['files'][0]['status'], 'error')
        self.assertIn('Evidence path changed', report['files'][0]['detail'])
        self.assertEqual(self.path.read_bytes(), b'replacement')

    def test_simulated_post_read_identity_mismatch(self):
        real_lstat = Path.lstat
        replacement = (self.other / 'a.txt').lstat()
        finished = False

        def read(stream, algorithm):
            nonlocal finished
            result = self.real_digest(stream, algorithm)
            finished = True
            return result

        def lstat(path, *args, **kwargs):
            if finished and path == self.path:
                return replacement
            return real_lstat(path, *args, **kwargs)

        with patch.object(Path, 'lstat', lstat), \
                patch('evidence_integrity.hashlib.file_digest', side_effect=read):
            with self.assertRaisesRegex(ValueError, 'Evidence path changed'):
                generate(self.root, ['folder/a.txt'])

    def test_stable_nested_path_remains_valid(self):
        manifest = generate(self.root, ['folder/a.txt'])
        self.assertTrue(verify(self.root, manifest)['ok'])


if __name__ == '__main__':
    unittest.main()
