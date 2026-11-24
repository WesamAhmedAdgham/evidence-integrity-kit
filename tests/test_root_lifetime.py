"""Root identity and descriptor lifetime regressions (synthetic fixtures)."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


@unittest.skipUnless(os.name == 'posix', 'POSIX directory descriptors required')
class RootLifetimeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / 'root'
        self.other = self.base / 'other'
        for folder in (self.root, self.other):
            folder.mkdir()
            for name in ('a.txt', 'b.txt'):
                (folder / name).write_bytes(name.encode())
        self.real_digest = kit.digest

    def swap_after_first(self, *args, **kwargs):
        result = self.real_digest(*args, **kwargs)
        if kwargs['name'] == 'a.txt':
            self.root.rename(self.base / 'old')
            self.other.rename(self.root)
        return result

    def test_create_rejects_root_replacement_between_files(self):
        with patch.object(kit, 'digest', side_effect=self.swap_after_first):
            with self.assertRaisesRegex(ValueError, 'Evidence root'):
                kit.generate(self.root, ['a.txt', 'b.txt'])

    def test_verify_rejects_root_replacement_between_files(self):
        manifest = kit.generate(self.root, ['a.txt', 'b.txt'])
        with patch.object(kit, 'digest', side_effect=self.swap_after_first):
            with self.assertRaisesRegex(ValueError, 'Evidence root'):
                kit.verify(self.root, manifest)

    def test_stable_root_multiple_files(self):
        manifest = kit.generate(self.root, ['a.txt', 'b.txt'])
        self.assertTrue(kit.verify(self.root, manifest)['ok'])

    def test_root_descriptor_closed_on_success(self):
        handles = []

        def record(*args, **kwargs):
            handles.append(kwargs['root_fd'])
            return self.real_digest(*args, **kwargs)

        with patch.object(kit, 'digest', side_effect=record):
            kit.generate(self.root, ['a.txt', 'b.txt'])
        self.assertEqual(len(handles), 2)
        self.assertEqual(handles[0], handles[1])
        with self.assertRaises(OSError):
            os.fstat(handles[0])

    def test_root_descriptor_closed_on_failure(self):
        handles = []

        def fail(*args, **kwargs):
            handles.append(kwargs['root_fd'])
            raise ValueError('synthetic failure')

        with patch.object(kit, 'digest', side_effect=fail):
            with self.assertRaisesRegex(ValueError, 'synthetic failure'):
                kit.generate(self.root, ['a.txt'])
        self.assertEqual(len(handles), 1)
        with self.assertRaises(OSError):
            os.fstat(handles[0])
