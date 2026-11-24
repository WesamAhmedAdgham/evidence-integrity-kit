"""Explicit evidence protection choice; no accidental CLI downgrade."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


class ProtectionChoiceTests(unittest.TestCase):
    def arguments(self):
        return [
            ['create', '--root', 'unused', 'a'],
            ['verify', '--root', 'unused', '--manifest', 'unused.json'],
            ['verify-signed', '--root', 'unused', '--manifest', 'unused.json',
             '--signature', 'unused.sig', '--public-key', 'unused.pem'],
        ]

    def test_omission_and_conflict_rejected_before_any_operation(self):
        with patch.object(kit, 'generate') as generate, patch.object(kit, 'verify') as verify, \
                patch.object(kit, 'verify_signed') as signed, patch.object(kit, 'load_manifest') as load:
            for args in self.arguments():
                for flags in ([], ['--assume-stable-tree', '--windows-deny-write'],
                              ['--linux-btrfs-snapshot', 'x', '--macos-apfs-snapshot', 'y']):
                    with self.subTest(args=args, flags=flags), contextlib.redirect_stderr(io.StringIO()), \
                            contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as exc:
                        kit.main(args + flags)
                    self.assertEqual(exc.exception.code, 2)
                    self.assertEqual(out.getvalue(), '')
            for call in (generate, verify, signed, load):
                call.assert_not_called()

    def test_explicit_stable_tree_report_and_wire_compatibility(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'a').write_bytes(b'synthetic')
            expected = kit.generate(root, ['a'])
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(kit.main(['create', '--assume-stable-tree', '--root', td, 'a']), 0)
            self.assertEqual(json.loads(out.getvalue()), expected)
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps(expected), encoding='ascii')
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(kit.main(['verify', '--assume-stable-tree', '--root', td,
                                           '--manifest', str(manifest)]), 0)
            report = json.loads(out.getvalue())
            self.assertTrue(report['ok'])
            self.assertEqual(report['protection'], {'mode': 'assumed-stable-tree',
                             'isolation_verified': False, 'scope': 'sampled-checks-only'})
            self.assertNotIn('protection', kit.verify(root, expected))

    def test_explicit_native_error_does_not_invoke_sampled_hashing(self):
        with patch.object(kit, 'windows_guarded_digests', side_effect=ValueError('guard failed')), \
                patch.object(kit, 'check_windows_guard_budget'), \
                patch.dict('sys.modules', {'windows_root': __import__('types').SimpleNamespace(
                    lexical_guarded_root=lambda root: Path(root))}), \
                patch.object(kit, 'digest') as digest:
            with tempfile.TemporaryDirectory() as td, contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(kit.main(['create', '--windows-deny-write', '--root', td, 'a']), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertIn('guard failed', err.getvalue())
            digest.assert_not_called()
