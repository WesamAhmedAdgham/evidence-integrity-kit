"""Bounded Windows deny-write cohort tests, using synthetic local evidence."""
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


class DenyWritePreflightTests(unittest.TestCase):
    def test_budget_exact_boundary(self):
        with patch.object(kit.os, 'name', 'nt'), patch.object(kit, 'MAX_WINDOWS_GUARD_COMPONENTS', 2):
            kit.check_windows_guard_budget(['a/b'])
            with self.assertRaisesRegex(ValueError, 'retained handle budget exceeded'):
                kit.check_windows_guard_budget(['a/b', 'c'])

    @unittest.skipIf(os.name == 'nt', 'Non-Windows fail-closed check')
    def test_non_windows_rejects_before_root_resolution(self):
        manifest = {'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': 'a', 'sha256': '0' * 64}]}
        with patch.object(kit, 'resolve_path') as resolve:
            for operation, arg in ((kit.generate, ['a']), (kit.verify, manifest)):
                with self.assertRaisesRegex(ValueError, 'unavailable on this platform'):
                    operation(Path('unused'), arg, deny_write=True)
            resolve.assert_not_called()


@unittest.skipUnless(os.name == 'nt', 'Native Windows sharing fixture required')
class WindowsDenyWriteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.parent = self.root / 'nested'
        self.parent.mkdir()
        self.a = self.parent / 'a'
        self.b = self.root / 'b'
        self.a.write_bytes(b'AAAA')
        self.b.write_bytes(b'BBBB')
        self.names = ['nested/a', 'b']
        self.manifest = kit.generate(self.root, self.names)

    def attempt(self, path, action):
        code = (
            "import sys; from pathlib import Path; p=Path(sys.argv[1]); "
            "action=sys.argv[2]\n"
            "try:\n"
            " if action=='write':\n"
            "  with p.open('r+b') as f: f.write(b'ZZZZ')\n"
            " else: p.rename(p.with_name(p.name+'.moved'))\n"
            "except OSError as e:\n"
            " print(e.winerror); sys.exit(1)\n"
        )
        return subprocess.run([sys.executable, '-c', code, str(path), action],
                              capture_output=True, text=True, timeout=15)

    def assert_denied(self, path, action):
        result = self.attempt(path, action)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(result.stdout.strip(), ('5', '32'))

    def test_all_leaves_and_parent_pinned_before_first_hash_and_through_last(self):
        original = hashlib.file_digest
        calls = []
        def probe(reader, algorithm):
            calls.append(True)
            self.assert_denied(self.a, 'write')
            self.assert_denied(self.b, 'write')
            self.assert_denied(self.a, 'rename')
            self.assert_denied(self.parent, 'rename')
            return original(reader, algorithm)
        with patch.object(kit.hashlib, 'file_digest', side_effect=probe):
            report = kit.verify(self.root, self.manifest, deny_write=True)
        self.assertTrue(report['ok'])
        self.assertEqual(calls, [True, True])
        self.assertEqual(report['protection']['mode'], 'windows-deny-write')
        self.assertEqual(self.a.read_bytes(), b'AAAA')
        self.assertEqual(self.b.read_bytes(), b'BBBB')
        self.assertEqual(self.attempt(self.a, 'write').returncode, 0)
        self.assertEqual(self.attempt(self.parent, 'rename').returncode, 0)

    def test_preexisting_writer_aborts_before_hash_and_releases_earlier_leaf(self):
        with self.a.open('r+b'):
            with patch.object(kit.hashlib, 'file_digest') as digest:
                with self.assertRaises(OSError) as error:
                    kit.verify(self.root, self.manifest, deny_write=True)
                self.assertIn(error.exception.winerror, (5, 32))
                digest.assert_not_called()
            self.assertEqual(self.attempt(self.b, 'write').returncode, 0)

    def test_after_last_hash_and_at_final_revalidation_writes_denied(self):
        real = kit.check_guarded_evidence
        calls = []
        def probe(*args):
            real(*args)
            calls.append(args[1])
            # Two initial checks, four per-hash checks, two final checks.
            if len(calls) >= 7:
                self.assert_denied(self.a, 'write')
                self.assert_denied(self.b, 'write')
        with patch.object(kit, 'check_guarded_evidence', side_effect=probe):
            report = kit.verify(self.root, self.manifest, deny_write=True)
        self.assertTrue(report['ok'])
        self.assertEqual(len(calls), 8)

    def test_create_matches_legacy_and_mismatch_report_is_not_success(self):
        self.assertEqual(kit.generate(self.root, self.names, deny_write=True), self.manifest)
        self.a.write_bytes(b'ZZZZ')
        report = kit.verify(self.root, self.manifest, deny_write=True)
        self.assertFalse(report['ok'])
        self.assertEqual([x['status'] for x in report['files']], ['match', 'mismatch'])

    def test_acquisition_failure_releases_handles_without_hashing(self):
        self.a.unlink()
        with patch.object(kit.hashlib, 'file_digest') as digest:
            with self.assertRaises(OSError):
                kit.verify(self.root, self.manifest, deny_write=True)
            digest.assert_not_called()
        self.assertEqual(self.attempt(self.b, 'write').returncode, 0)

    def test_hash_failure_releases_all_handles(self):
        with patch.object(kit.hashlib, 'file_digest', side_effect=ValueError('synthetic failure')):
            with self.assertRaisesRegex(ValueError, 'synthetic failure'):
                kit.verify(self.root, self.manifest, deny_write=True)
        self.assertEqual(self.attempt(self.a, 'write').returncode, 0)
        self.assertEqual(self.attempt(self.b, 'write').returncode, 0)
