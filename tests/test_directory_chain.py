"""Synthetic native and simulated regressions for descendant directory identities."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


class DirectoryChainTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.outer = self.root / 'outer'
        self.inner = self.outer / 'inner'
        self.inner.mkdir(parents=True)
        self.file = self.inner / 'a.txt'
        self.file.write_bytes(b'synthetic')
        (self.root / 'z.txt').write_bytes(b'synthetic second file')
        self.name = 'outer/inner/a.txt'

    def replace_outer_preserving_leaf(self):
        previous = self.file.stat()
        moved = self.root / 'old'
        self.outer.rename(moved)
        self.outer.mkdir()
        (moved / 'inner').rename(self.inner)
        self.assertTrue(os.path.samestat(previous, self.file.stat()))
        self.assertEqual(previous.st_mtime_ns, self.file.stat().st_mtime_ns)

    @unittest.skipUnless(os.name == 'posix', 'native directory move fixture requires POSIX')
    def test_native_reparent_before_hash_rejected(self):
        real_open = kit.open_evidence
        def swap(*args, **kwargs):
            self.replace_outer_preserving_leaf()
            return real_open(*args, **kwargs)
        with patch.object(kit, 'open_evidence', side_effect=swap), \
                patch.object(kit.hashlib, 'file_digest', wraps=kit.hashlib.file_digest) as digest:
            with self.assertRaisesRegex(ValueError, 'directory identity changed'):
                kit.generate(self.root, [self.name])
            digest.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'native directory move fixture requires POSIX')
    def test_native_reparent_during_hash_rejected(self):
        manifest = kit.generate(self.root, [self.name])
        real_digest = kit.hashlib.file_digest
        def swap(*args, **kwargs):
            result = real_digest(*args, **kwargs)
            self.replace_outer_preserving_leaf()
            return result
        with patch.object(kit.hashlib, 'file_digest', side_effect=swap):
            report = kit.verify(self.root, manifest)
        self.assertFalse(report['ok'])
        self.assertIn('directory identity changed', report['files'][0]['detail'])

    def test_reparent_between_files_is_rejected(self):
        manifest = kit.generate(self.root, [self.name, 'z.txt'])
        real_digest = kit.digest
        def swap(*args, **kwargs):
            result = real_digest(*args, **kwargs)
            if kwargs['name'] == 'z.txt':
                self.replace_outer_preserving_leaf()
            return result
        with patch.object(kit, 'digest', side_effect=swap):
            report = kit.verify(self.root, manifest)
        self.assertFalse(report['ok'])
        self.assertEqual([x['status'] for x in report['files']], ['error', 'match'])
        self.assertIn('directory identity changed', report['files'][0]['detail'])

    def test_generate_rejects_reparent_between_files(self):
        real_digest = kit.digest
        def swap(*args, **kwargs):
            result = real_digest(*args, **kwargs)
            if kwargs['name'] == 'z.txt':
                self.replace_outer_preserving_leaf()
            return result
        with patch.object(kit, 'digest', side_effect=swap):
            with self.assertRaisesRegex(ValueError, 'directory identity changed'):
                kit.generate(self.root, [self.name, 'z.txt'])

    def test_stable_nested_tree(self):
        self.assertEqual(len(kit.sample_directory_chain(self.root, self.name)), 2)
        self.assertEqual(kit.sample_directory_chain(self.root, 'z.txt'), ())
        self.assertTrue(kit.verify(self.root, kit.generate(self.root, [self.name, 'z.txt']))['ok'])

    def test_missing_or_invalid_directory_identity(self):
        with patch.object(Path, 'lstat') as sample:
            sample.return_value.st_mode = kit.stat.S_IFDIR
            sample.return_value.st_ino = 0
            sample.return_value.st_file_attributes = 0
            with self.assertRaisesRegex(ValueError, 'directory identity unavailable'):
                kit.sample_directory_chain(self.root, self.name)

    def test_unsupported_platform_does_not_fall_back(self):
        with patch.object(kit.os, 'name', 'unsupported'):
            with self.assertRaisesRegex(ValueError, 'Secure evidence opening unavailable'):
                with kit.pinned_root(self.root):
                    self.fail('Unsupported platform accepted')
            with self.assertRaisesRegex(ValueError, 'Secure evidence opening unavailable'):
                kit.open_evidence(self.file, root=self.root, name=self.name)


if __name__ == '__main__':
    unittest.main()
