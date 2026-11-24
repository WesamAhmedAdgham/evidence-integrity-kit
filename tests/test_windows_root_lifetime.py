"""Native Windows root replacement regressions; synthetic temporary files only."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


@unittest.skipUnless(os.name == 'nt', 'Native Windows root fixture required')
class WindowsRootLifetimeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / 'root'
        self.replacement = self.base / 'replacement'
        self.old = self.base / 'old'
        for directory in (self.root, self.replacement):
            directory.mkdir()
            for name in ('a.txt', 'b.txt'):
                (directory / name).write_bytes(name.encode('ascii'))
        self.original_identity = self.root.stat()
        self.assertFalse(self.root.samefile(self.replacement))
        self.real_digest = kit.digest
        self.attempted = False
        self.swapped = False
        self.blocked = False

    def swap_after_first(self, *args, **kwargs):
        result = self.real_digest(*args, **kwargs)
        if kwargs['name'] == 'a.txt':
            self.attempted = True
            try:
                self.root.rename(self.old)
            except OSError as exc:
                # A future root handle may deny rename/delete sharing.
                # Only accept a Windows sharing/access refusal and confirm
                # that the original directory is still at its original path.
                if getattr(exc, 'winerror', None) not in (5, 32):
                    raise AssertionError('Unexpected fixture rename failure') from exc
                self.assertTrue(os.path.samestat(self.original_identity, self.root.stat()))
                self.assertFalse(self.old.exists())
                self.blocked = True
                return result
            try:
                self.replacement.rename(self.root)
            except OSError as exc:
                raise AssertionError('Fixture could not install replacement root') from exc
            self.assertFalse(os.path.samestat(self.original_identity, self.root.stat()))
            self.swapped = True
        return result

    def test_create_does_not_accept_replacement_root(self):
        with patch.object(kit, 'digest', side_effect=self.swap_after_first):
            try:
                kit.generate(self.root, ['a.txt', 'b.txt'])
            except (OSError, ValueError):
                rejected = True
            else:
                rejected = False
        self.assertTrue(self.attempted, 'Fixture did not reach replacement attempt')
        self.assertTrue(self.swapped or self.blocked)
        if self.swapped:
            self.assertTrue(rejected, 'Create accepted two independent roots')

    def test_verify_does_not_accept_replacement_root(self):
        manifest = kit.generate(self.root, ['a.txt', 'b.txt'])
        with patch.object(kit, 'digest', side_effect=self.swap_after_first):
            try:
                report = kit.verify(self.root, manifest)
            except (OSError, ValueError):
                rejected = True
            else:
                rejected = not report['ok']
        self.assertTrue(self.attempted, 'Fixture did not reach replacement attempt')
        self.assertTrue(self.swapped or self.blocked)
        if self.swapped:
            self.assertTrue(rejected, 'Verify accepted two independent roots')

    def test_stable_windows_root(self):
        manifest = kit.generate(self.root, ['a.txt', 'b.txt'])
        self.assertTrue(kit.verify(self.root, manifest)['ok'])

    def test_root_rename_denied_while_guard_active_and_allowed_after(self):
        with kit.pinned_root(self.root) as guard:
            self.assertIsNotNone(guard)
            with self.assertRaises(OSError) as raised:
                self.root.rename(self.old)
            self.assertIn(raised.exception.winerror, (5, 32))
            self.assertTrue(os.path.samestat(self.original_identity, self.root.stat()))
        self.root.rename(self.old)
        self.assertTrue(self.old.is_dir())

    def test_root_guard_released_after_exception(self):
        with self.assertRaisesRegex(ValueError, 'synthetic failure'):
            with kit.pinned_root(self.root) as guard:
                self.assertIsNotNone(guard)
                raise ValueError('synthetic failure')
        self.root.rename(self.old)
        self.assertTrue(self.old.is_dir())

    def test_missing_root_guard_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'root handle required'):
            kit.open_evidence(self.root / 'a.txt', root=self.root,
                              name='a.txt', root_fd=None)
