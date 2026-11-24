"""Conservative hard-link policy on stable local filesystems."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence_integrity import generate, verify


class HardLinkTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / 'evidence'
        self.root.mkdir()
        self.source = self.root / 'source.txt'
        self.source.write_bytes(b'synthetic')

    def make_link(self, source, target):
        try:
            os.link(source, target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f'Hard link creation unavailable: {exc}')
        self.assertGreater(source.stat().st_nlink, 1)

    def test_generate_rejects_link_to_outside_root(self):
        outside = self.base / 'outside.txt'
        outside.write_bytes(b'synthetic')
        self.make_link(outside, self.root / 'alias.txt')
        with patch('evidence_integrity.digest') as digest:
            with self.assertRaisesRegex(ValueError, 'exactly one hard link'):
                generate(self.root, ['alias.txt'])
            digest.assert_not_called()

    def test_generate_rejects_unlisted_alias_inside_root(self):
        self.make_link(self.source, self.root / 'alias.txt')
        with patch('evidence_integrity.digest') as digest:
            with self.assertRaisesRegex(ValueError, 'exactly one hard link'):
                generate(self.root, ['source.txt'])
            digest.assert_not_called()

    def test_verify_rejects_new_alias_after_manifest_creation(self):
        manifest = generate(self.root, ['source.txt'])
        self.make_link(self.source, self.base / 'outside_alias.txt')
        with patch('evidence_integrity.digest') as digest:
            report = verify(self.root, manifest)
            digest.assert_not_called()
        self.assertFalse(report['ok'])
        self.assertEqual(report['files'][0]['status'], 'error')
        self.assertIn('exactly one hard link', report['files'][0]['detail'])

    def test_verify_rejects_both_listed_aliases(self):
        self.make_link(self.source, self.root / 'alias.txt')
        expected = hashlib.sha256(b'synthetic').hexdigest()
        manifest = {'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': name, 'sha256': expected} for name in ('source.txt', 'alias.txt')]}
        with patch('evidence_integrity.digest') as digest:
            report = verify(self.root, manifest)
            digest.assert_not_called()
        self.assertFalse(report['ok'])
        self.assertEqual([item['status'] for item in report['files']], ['error', 'error'])

    def test_removing_alias_restores_normal_verification(self):
        alias = self.root / 'alias.txt'
        self.make_link(self.source, alias)
        alias.unlink()
        self.assertTrue(verify(self.root, generate(self.root, ['source.txt']))['ok'])

    def test_independent_identical_files_remain_valid(self):
        (self.root / 'copy.txt').write_bytes(b'synthetic')
        self.assertTrue(verify(self.root, generate(self.root, ['source.txt', 'copy.txt']))['ok'])


if __name__ == '__main__':
    unittest.main()
