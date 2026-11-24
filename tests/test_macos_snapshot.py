"""APFS mode preflight and native statfs checks."""
import ctypes
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit
import macos_snapshot as snap

SOURCE = 'fixture@/dev/disk99s1'


class APFSPreflightTests(unittest.TestCase):
    def test_apfs_modes_mutually_exclusive(self):
        with patch.object(kit, 'resolve_path') as resolve:
            for kwargs in ({'deny_write': True}, {'snapshot_uuid': 'invalid'}):
                with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
                    kit.generate(Path('unused'), ['a'], apfs_source=SOURCE, **kwargs)
            resolve.assert_not_called()

    def test_unsupported_apfs_fails_before_root(self):
        with patch.object(snap.sys, 'platform', 'linux'), patch.object(kit, 'resolve_path') as resolve:
            with self.assertRaisesRegex(ValueError, 'unavailable on this platform'):
                kit.generate(Path('unused'), ['a'], apfs_source=SOURCE)
            resolve.assert_not_called()

    def test_statfs_layout(self):
        self.assertEqual(ctypes.sizeof(snap.StatFs), 2168)
        self.assertEqual(snap.StatFs.flags.offset, 64)
        self.assertEqual(snap.StatFs.mntfromname.offset, 1112)

    @unittest.skipUnless(sys.platform == 'darwin' and snap.platform.machine().lower() == 'arm64',
                         'Native macOS arm64 fixture required')
    def test_apfs_source_and_privilege_preflight(self):
        with patch.object(snap.os, 'geteuid', return_value=501):
            self.assertEqual(snap.validate_request(SOURCE), SOURCE)
            for value in ('', 'fixture', 'fixture@/dev/null', 'a/b@/dev/disk1s1'):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'Canonical'):
                    snap.validate_request(value)
        with patch.object(snap.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(ValueError, 'without root'):
                snap.validate_request(SOURCE)

    @unittest.skipUnless(sys.platform == 'darwin' and snap.platform.machine().lower() == 'arm64',
                         'Native macOS arm64 fixture required')
    def test_ordinary_live_directory_not_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises((ValueError, OSError)):
                kit.generate(Path(td), ['a'], apfs_source=SOURCE)
