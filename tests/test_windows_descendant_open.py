"""Native Windows junction substitution after path validation; synthetic data."""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
        result = subprocess.run(
            ['cmd.exe', '/d', '/c', 'mklink', '/J', str(self.parent), str(self.moved)],
            capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, repr(result.stdout + result.stderr))
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
