"""Prove the deferred APFS capability is absent, not skipped."""
import contextlib
import io
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


class ReleaseScopeTests(unittest.TestCase):
    def test_deferred_apfs_payload_absent(self):
        root = Path(kit.__file__).resolve().parent
        for path in ('macos_snapshot.py', 'tests/test_macos_snapshot.py',
                     'tools/check_apfs_fixture.py', 'tools/test_macos_apfs_snapshot.sh'):
            self.assertFalse((root / path).exists(), path)

    def test_deferred_flag_rejected_before_control_or_evidence_access(self):
        args = [
            ['create', '--root', 'unused', 'a'],
            ['verify', '--root', 'unused', '--manifest', 'unused.json'],
            ['verify-signed', '--root', 'unused', '--manifest', 'unused.json',
             '--signature', 'unused.sig', '--public-key', 'unused.pem'],
        ]
        with patch.object(kit, 'generate') as generate, patch.object(kit, 'verify') as verify, \
                patch.object(kit, 'verify_signed') as signed, patch.object(kit, 'load_manifest') as load:
            for command in args:
                for flags in (['--macos-apfs-snapshot', 'test@/dev/disk99s1'],
                              ['--assume-stable-tree', '--macos-apfs-snapshot', 'test@/dev/disk99s1']):
                    with self.subTest(command=command, flags=flags), \
                            contextlib.redirect_stdout(io.StringIO()) as out, \
                            contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                        kit.main(command + flags)
                    self.assertEqual(exc.exception.code, 2)
                    self.assertEqual(out.getvalue(), '')
            for operation in (generate, verify, signed, load):
                operation.assert_not_called()
