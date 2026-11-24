"""Windows junction integration regression using only temporary synthetic files."""
import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from native_fixture_support import junction_fixture, link_fixture

from evidence_integrity import generate, verify


@unittest.skipUnless(os.name == 'nt', 'Windows junction integration requires Windows')
class JunctionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / 'evidence'
        self.root.mkdir()
        self.target = self.root / 'target'
        self.target.mkdir()
        (self.target / 'a.txt').write_bytes(b'synthetic')
        self.alias = self.root / 'alias'
        junction_fixture(self, self.alias, self.target)
        self.addCleanup(os.rmdir, self.alias)
        self.assertTrue(self.alias.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        self.assertTrue((self.alias / 'a.txt').samefile(self.target / 'a.txt'))

    def test_create_rejects_internal_junction_before_hashing(self):
        with patch('evidence_integrity.digest') as digest:
            with self.assertRaisesRegex(ValueError, 'Link not permitted'):
                generate(self.root, ['alias/a.txt'])
            digest.assert_not_called()

    def test_verify_rejects_internal_junction_before_hashing(self):
        manifest = {'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': 'alias/a.txt', 'sha256': hashlib.sha256(b'synthetic').hexdigest()}]}
        with patch('evidence_integrity.digest') as digest:
            report = verify(self.root, manifest)
            digest.assert_not_called()
        self.assertFalse(report['ok'])
        self.assertEqual(report['files'][0]['status'], 'error')
        self.assertIn('Link not permitted', report['files'][0]['detail'])

    def test_real_directory_remains_valid(self):
        self.assertTrue(verify(self.root, generate(self.root, ['target/a.txt']))['ok'])


if __name__ == '__main__':
    unittest.main()
