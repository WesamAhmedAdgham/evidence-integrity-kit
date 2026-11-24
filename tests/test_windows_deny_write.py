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
        # Use native CreateFileW so sharing violations retain the exact
        # Win32 error rather than a CRT errno-only PermissionError.
        code = """import ctypes as c
from ctypes import wintypes as w
from pathlib import Path
import sys
p = Path(sys.argv[1])
if sys.argv[2] in ('write', 'dir-open'):
    k = c.WinDLL('kernel32', use_last_error=True)
    create = k.CreateFileW
    create.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    create.restype = w.HANDLE
    close = k.CloseHandle
    close.argtypes, close.restype = [w.HANDLE], w.BOOL
    write = k.WriteFile
    write.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
    write.restype = w.BOOL
    directory = sys.argv[2] == 'dir-open'
    h = create(str(p), 2 if directory else 0x40000000, 7, None, 3,
               0x02000000 if directory else 0, None)
    if h is None or h == c.c_void_p(-1).value:
        print(c.get_last_error())
        sys.exit(1)
    try:
        if not directory:
            count = w.DWORD()
            if not write(h, c.create_string_buffer(b'ZZZZ'), 4, c.byref(count), None) or count.value != 4:
                sys.exit(3)
    finally:
        if not close(h):
            sys.exit(4)
else:
    try:
        p.rename(p.with_name(p.name + '.moved'))
    except OSError as e:
        print(e.winerror)
        sys.exit(1)
"""
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
            self.assert_denied(self.parent, 'dir-open')
            self.assert_denied(self.root, 'dir-open')
            return original(reader, algorithm)
        with patch.object(kit.hashlib, 'file_digest', side_effect=probe):
            report = kit.verify(self.root, self.manifest, deny_write=True)
        self.assertTrue(report['ok'])
        self.assertEqual(calls, [True, True])
        self.assertEqual(report['protection']['mode'], 'windows-deny-write')
        self.assertEqual(self.a.read_bytes(), b'AAAA')
        self.assertEqual(self.b.read_bytes(), b'BBBB')
        self.assertEqual(self.attempt(self.a, 'write').returncode, 0)
        self.assertEqual(self.attempt(self.parent, 'dir-open').returncode, 0)
        self.assertEqual(self.attempt(self.root, 'dir-open').returncode, 0)
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


    def test_cli_guarded_acquisition_failure_has_no_success_output(self):
        manifest = self.root.parent / ('unused-' + self.root.name + '.json')
        self.addCleanup(manifest.unlink, missing_ok=True)
        import json
        manifest.write_text(json.dumps(self.manifest), encoding='ascii')
        cli = Path(kit.__file__).resolve()
        with self.a.open('r+b'):
            result = subprocess.run(
                [sys.executable, str(cli), 'verify', '--windows-deny-write',
                 '--root', str(self.root), '--manifest', str(manifest)],
                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertIn('Error:', result.stderr)
        self.assertNotIn('Traceback', result.stderr)


    def test_existing_writable_mapping_refuses_before_hash(self):
        import mmap
        with self.a.open('r+b') as stream:
            mapping = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_WRITE)
        with mapping:
            with patch.object(kit.hashlib, 'file_digest') as digest:
                with self.assertRaises(OSError) as error:
                    kit.verify(self.root, self.manifest, deny_write=True)
                self.assertIn(error.exception.winerror, (5, 32))
                digest.assert_not_called()
        self.assertTrue(kit.verify(self.root, self.manifest, deny_write=True)['ok'])

    def test_native_volume_scope_uses_handles_and_rejects_mismatch(self):
        import uuid
        import windows_root as native
        actual = native.local_ntfs_scope
        with native.pinned_windows_root(self.root, deny_write=True) as root_fd:
            scope = actual(root_fd[0])
            self.assertIsInstance(scope, uuid.UUID)
        calls = []
        def changed(handle):
            real_scope = actual(handle)
            calls.append(real_scope)
            if len(calls) == 2:
                return uuid.UUID(int=real_scope.int ^ 1)
            return real_scope
        with patch.object(native, 'local_ntfs_scope', side_effect=changed), \
                patch.object(kit.hashlib, 'file_digest') as digest:
            with self.assertRaisesRegex(ValueError, 'crosses local NTFS volume'):
                kit.verify(self.root, self.manifest, deny_write=True)
            digest.assert_not_called()
        self.assertEqual(len(calls), 2)
        self.assertTrue(kit.verify(self.root, self.manifest, deny_write=True)['ok'])


    def test_guarded_relative_opens_never_use_absolute_descendant_open(self):
        import windows_root as native
        real_dir = native.directory_handle
        from contextlib import contextmanager

        @contextmanager
        def root_only(path, **kwargs):
            self.assertEqual(Path(path), self.root)
            with real_dir(path, **kwargs) as handle:
                yield handle

        with patch.object(native, 'directory_handle', side_effect=root_only), \
                patch.object(native, 'checked_file_fd', side_effect=AssertionError('absolute leaf open')), \
                patch.object(native, 'relative_handle', wraps=native.relative_handle) as relative:
            report = kit.verify(self.root, self.manifest, deny_write=True)
        self.assertTrue(report['ok'])
        self.assertEqual(report['protection']['traversal'], 'native-relative-descendants')
        self.assertIn('nested', [call.args[1] for call in relative.call_args_list])
        self.assertIn('a', [call.args[1] for call in relative.call_args_list])

    def test_relative_open_rejects_invalid_components(self):
        import windows_root as native
        with native.pinned_windows_root(self.root, deny_write=True) as guard:
            for part in ('', '.', '..', 'nested/a', 'nested\\a', 'C:a', 'a:stream', 'a\x00'):
                with self.subTest(part=part):
                    with self.assertRaises(ValueError):
                        native.relative_handle(guard[0], part, directory=False)

    def test_relative_open_rejects_junction_and_leaf_symlink(self):
        import windows_root as native
        from native_fixture_support import junction_fixture, link_fixture
        junction = self.root / 'junction'
        link = self.root / 'link'
        junction_fixture(self, junction, self.parent)
        self.addCleanup(os.rmdir, junction)
        link_fixture(self, 'symlink', lambda: link.symlink_to(self.a))
        self.addCleanup(link.unlink)
        with native.pinned_windows_root(self.root, deny_write=True) as guard:
            with self.assertRaises((OSError, ValueError)):
                with native.relative_directory(guard[0], 'junction'):
                    self.fail('Junction opened')
            with self.assertRaises((OSError, ValueError)):
                with native.relative_leaf(guard[0], 'link'):
                    self.fail('Symlink opened')
        self.assertTrue(kit.verify(self.root, self.manifest, deny_write=True)['ok'])

    def test_relative_open_supports_utf16_non_bmp_and_binary_data(self):
        name = 'nested/caf\u00e9-\U0001f600.bin'
        data = b'\x00\x1a\r\n\xff'
        (self.root / name).write_bytes(data)
        manifest = kit.generate(self.root, [name], deny_write=True)
        self.assertEqual(manifest['files'][0]['sha256'], hashlib.sha256(data).hexdigest())
        self.assertTrue(kit.verify(self.root, manifest, deny_write=True)['ok'])
