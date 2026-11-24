"""Snapshot mode preflight and actual openat2 negative tests."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit
import linux_snapshot as snap

UUID = '12345678-1234-1234-1234-123456789abc'


class SnapshotPreflightTests(unittest.TestCase):
    def test_modes_mutually_exclusive(self):
        with patch.object(kit, 'resolve_path') as resolve:
            with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
                kit.generate(Path('unused'), ['a'], deny_write=True, snapshot_uuid=UUID)
            resolve.assert_not_called()

    def test_unsupported_platform_fails_before_root(self):
        manifest = {'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': 'a', 'sha256': '0' * 64}]}
        with patch.object(snap.sys, 'platform', 'darwin'), patch.object(kit, 'resolve_path') as resolve:
            for operation, arg in ((kit.generate, ['a']), (kit.verify, manifest)):
                with self.assertRaisesRegex(ValueError, 'unavailable on this platform'):
                    operation(Path('unused'), arg, snapshot_uuid=UUID)
            resolve.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux' and snap.platform.machine().lower() == 'x86_64',
                         'Linux x86-64 snapshot fixture required')
    def test_snapshot_uuid_and_privilege_preflight(self):
        with patch.object(snap.os, 'geteuid', return_value=1000):
            self.assertEqual(str(snap.validate_request(UUID)), UUID)
            for value in ('', 'bad', UUID.upper(), '00000000-0000-0000-0000-000000000000'):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'Canonical'):
                    snap.validate_request(value)
        with patch.object(snap.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(ValueError, 'without root'):
                snap.validate_request(UUID)

    @unittest.skipUnless(sys.platform == 'linux' and snap.platform.machine().lower() == 'x86_64',
                         'Linux x86-64 openat2 fixture required')
    def test_native_openat2_and_mount_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'a').write_bytes(b'AAAA')
            (root / 'alias').symlink_to('a')
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fd = snap.open_path(parent, 'a')
                try:
                    self.assertTrue(os.path.samestat(os.fstat(fd), (root / 'a').stat()))
                    self.assertEqual(snap.mount_id(fd), snap.mount_id(parent))
                finally:
                    os.close(fd)
                with self.assertRaises(OSError):
                    snap.open_path(parent, 'alias')
                with self.assertRaises(ValueError):
                    snap.open_path(parent, '../a')
            finally:
                os.close(parent)

    @unittest.skipUnless(sys.platform == 'linux' and snap.platform.machine().lower() == 'x86_64',
                         'Linux x86-64 snapshot fixture required')
    def test_ordinary_directory_not_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(snap.os, 'geteuid', return_value=1000):
                with self.assertRaises((OSError, ValueError)):
                    kit.generate(Path(td), ['a'], snapshot_uuid=UUID)
