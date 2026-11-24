"""POSIX descriptor-relative evidence opening, using temporary fixtures only."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


@unittest.skipUnless(os.name == 'posix', 'POSIX directory descriptors required')
class HandleTraversalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / 'evidence'
        self.folder = self.root / 'folder'
        self.folder.mkdir(parents=True)
        self.path = self.folder / 'a.txt'
        self.path.write_bytes(b'synthetic')
        self.real_open = kit.open_evidence

    def substitute_directory(self, target, path, *args, **kwargs):
        moved = self.base / 'moved'
        target.rename(moved)
        try:
            target.symlink_to(moved, target_is_directory=True)
            try:
                return self.real_open(path, *args, **kwargs)
            finally:
                target.unlink()
        finally:
            moved.rename(target)

    def test_transient_parent_link_rejected_before_hash(self):
        with patch.object(kit, 'open_evidence', side_effect=lambda *a, **kw: self.substitute_directory(self.folder, *a, **kw)), \
                patch.object(kit.hashlib, 'file_digest', wraps=kit.hashlib.file_digest) as digest:
            with self.assertRaises(OSError):
                kit.generate(self.root, ['folder/a.txt'])
            digest.assert_not_called()
        self.assertEqual(self.path.read_bytes(), b'synthetic')

    def test_transient_root_link_rejected_before_hash(self):
        manifest = kit.generate(self.root, ['folder/a.txt'])
        with patch.object(kit, 'open_evidence', side_effect=lambda *a, **kw: self.substitute_directory(self.root, *a, **kw)), \
                patch.object(kit.hashlib, 'file_digest', wraps=kit.hashlib.file_digest) as digest:
            report = kit.verify(self.root, manifest)
            self.assertFalse(report['ok'])
            self.assertEqual(report['files'][0]['status'], 'error')
            digest.assert_not_called()
        self.assertEqual(self.path.read_bytes(), b'synthetic')

    def test_regular_nested_file(self):
        self.assertTrue(kit.verify(self.root, kit.generate(self.root, ['folder/a.txt']))['ok'])
