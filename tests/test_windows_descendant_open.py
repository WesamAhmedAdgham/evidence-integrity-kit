"""Native Windows junction substitution after path validation; synthetic data."""
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from native_fixture_support import junction_fixture, link_fixture

import evidence_integrity as kit


@unittest.skipUnless(os.name == 'nt', 'Native Windows junction fixture required')
class WindowsDescendantTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / 'root'
        self.parent = self.root / 'parent'
        self.parent.mkdir(parents=True)
        self.path = self.parent / 'a.txt'
        self.path.write_bytes(b'synthetic evidence')
        self.moved = self.base / 'moved'
        self.original = self.path.stat()
        self.real_open = kit.open_evidence
        self.substituted = False

    def substitute_before_open(self, path, *args, **kwargs):
        # Move the original directory outside the root, then install a junction
        # to the very same file. Leaf identity alone cannot detect this route.
        try:
            self.parent.rename(self.moved)
        except OSError as exc:
            raise AssertionError('Fixture parent rename failed') from exc
        junction_fixture(self, self.parent, self.moved)
        self.addCleanup(os.rmdir, self.parent)
        self.assertTrue(self.parent.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        self.assertTrue(os.path.samestat(self.original, path.stat()))
        self.substituted = True
        return self.real_open(path, *args, **kwargs)

    def test_create_rejects_substituted_parent_before_hashing(self):
        with patch.object(kit, 'open_evidence', side_effect=self.substitute_before_open), \
                patch.object(kit.hashlib, 'file_digest', wraps=kit.hashlib.file_digest) as digest:
            with self.assertRaises((OSError, ValueError)):
                kit.generate(self.root, ['parent/a.txt'])
            self.assertTrue(self.substituted)
            digest.assert_not_called()

    def test_verify_rejects_substituted_parent_before_hashing(self):
        manifest = kit.generate(self.root, ['parent/a.txt'])
        with patch.object(kit, 'open_evidence', side_effect=self.substitute_before_open), \
                patch.object(kit.hashlib, 'file_digest', wraps=kit.hashlib.file_digest) as digest:
            report = kit.verify(self.root, manifest)
            self.assertTrue(self.substituted)
            self.assertFalse(report['ok'])
            self.assertEqual(report['files'][0]['status'], 'error')
            digest.assert_not_called()

    def test_stable_nested_file_remains_valid(self):
        manifest = kit.generate(self.root, ['parent/a.txt'])
        self.assertTrue(kit.verify(self.root, manifest)['ok'])

    def test_leaf_symlink_substitution_rejected_before_hashing(self):
        target = self.parent / 'original.txt'

        def substitute(path, *args, **kwargs):
            self.path.rename(target)
            link_fixture(self, 'symlink', lambda: self.path.symlink_to(target))
            self.assertTrue(self.path.is_symlink())
            self.assertTrue(os.path.samestat(self.original, self.path.stat()))
            self.substituted = True
            return self.real_open(path, *args, **kwargs)

        with patch.object(kit, 'open_evidence', side_effect=substitute), \
                patch.object(kit.hashlib, 'file_digest', wraps=kit.hashlib.file_digest) as digest:
            with self.assertRaises((OSError, ValueError)):
                kit.generate(self.root, ['parent/a.txt'])
            self.assertTrue(self.substituted)
            digest.assert_not_called()

    def test_parent_rename_denied_during_read_and_allowed_after(self):
        original_digest = kit.hashlib.file_digest
        attempted = []

        def check_sharing(stream, algorithm):
            with self.assertRaises(OSError) as raised:
                self.parent.rename(self.moved)
            self.assertIn(raised.exception.winerror, (5, 32))
            attempted.append(True)
            return original_digest(stream, algorithm)

        with patch.object(kit.hashlib, 'file_digest', side_effect=check_sharing):
            kit.generate(self.root, ['parent/a.txt'])
        self.assertEqual(attempted, [True])
        self.parent.rename(self.moved)
        self.assertTrue((self.moved / 'a.txt').is_file())

    def test_parent_guard_released_on_leaf_open_failure(self):
        missing = self.parent / 'missing.txt'
        with kit.pinned_root(self.root) as guard:
            with self.assertRaises(OSError):
                with kit.open_evidence(missing, root=self.root,
                                       name='parent/missing.txt', root_fd=guard):
                    self.fail('Missing leaf unexpectedly opened')
            self.parent.rename(self.moved)
            self.assertTrue(self.moved.is_dir())

    def test_binary_contents_are_not_text_translated(self):
        data = b'\x00\x1a\r\n\xff\x80'
        self.path.write_bytes(data)
        expected = kit.hashlib.sha256(data).hexdigest()
        manifest = kit.generate(self.root, ['parent/a.txt'])
        self.assertEqual(manifest['files'][0]['sha256'], expected)
        self.assertTrue(kit.verify(self.root, manifest)['ok'])
