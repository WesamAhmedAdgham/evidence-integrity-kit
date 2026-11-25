"""Reject impossible evidence trees before any filesystem resolution."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


def manifest(names):
    return {'version': 1, 'algorithm': 'sha256', 'files': [
        {'path': name, 'sha256': 'a' * 64} for name in names]}


class ReleasePreflightTests(unittest.TestCase):
    def test_file_directory_conflicts_in_both_orders(self):
        for paths in (['a', 'a/b'], ['a/b', 'a'],
                      ['dir/a', 'dir/a/b/c'], ['dir/a/b/c', 'dir/a'],
                      ['a', 'A/b'], ['a/b', 'A']):
            for operation, arg in ((kit.generate, paths), (kit.verify, manifest(paths))):
                with self.subTest(paths=paths, operation=operation.__name__), \
                        patch.object(kit, 'resolve_path') as resolve, \
                        patch.object(kit, 'evidence_path') as evidence, \
                        patch.object(kit, 'digest') as digest:
                    with self.assertRaisesRegex(ValueError, 'Portable path collision'):
                        operation(Path('unused'), arg)
                    resolve.assert_not_called()
                    evidence.assert_not_called()
                    digest.assert_not_called()

    def test_strict_and_unsigned_manifest_reject_impossible_tree(self):
        for strict in (False, True):
            for names in (['a', 'a/b'], ['a/b', 'a']):
                with self.subTest(strict=strict, names=names), self.assertRaisesRegex(
                        ValueError, 'file is also a directory'):
                    kit.validate_manifest(manifest(names), strict=strict)

    def test_siblings_and_exact_duplicates_keep_existing_semantics(self):
        self.assertEqual(len(kit.validate_manifest(manifest(['a/b', 'a/c', 'ab']))), 3)
        with self.assertRaisesRegex(ValueError, 'Duplicate path'):
            kit.validate_manifest(manifest(['a/b', 'a/b']))

    def test_malformed_manifest_precedes_root_resolution(self):
        with patch.object(kit, 'resolve_path') as resolve:
            with self.assertRaisesRegex(ValueError, 'Unsupported manifest format'):
                kit.verify(Path('unused'), {})
            resolve.assert_not_called()

    def test_cli_resolve_runtime_error_is_controlled(self):
        for args in (['create', '--assume-stable-tree', '--root', 'unused', 'a'],
                     ['verify', '--assume-stable-tree', '--root', 'unused', '--manifest', 'unused.json']):
            with self.subTest(args=args), patch.object(Path, 'resolve', side_effect=RuntimeError(
                    'Symlink loop')), patch.object(kit, 'load_manifest', return_value=manifest(['a'])):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(kit.main(args), 2)
                self.assertEqual(out.getvalue(), '')
                self.assertIn('Unable to resolve path', err.getvalue())
                self.assertNotIn('Traceback', err.getvalue())

    def test_closed_output_pipe_returns_operational_error(self):
        cli = Path(kit.__file__).resolve()
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'a').write_bytes(b'synthetic evidence')
            reader, writer = os.pipe()
            os.close(reader)
            with os.fdopen(writer, 'wb') as sink:
                result = subprocess.run(
                    [sys.executable, str(cli), 'create', '--assume-stable-tree',
                     '--root', temp, 'a'],
                    stdout=sink, stderr=subprocess.PIPE, text=True, timeout=10,
                )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr.strip(), 'Error: Unable to write output')

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink fixture')
    def test_real_symlink_loop_root_is_controlled(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            loop = root / 'loop'
            loop.symlink_to('loop')
            control = root / 'manifest.json'
            control.write_text(json.dumps(manifest(['a'])), encoding='utf-8')
            for args in (['create', '--assume-stable-tree', '--root', str(loop), 'a'],
                         ['verify', '--assume-stable-tree', '--root', str(loop), '--manifest', str(control)]):
                with self.subTest(args=args):
                    out, err = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        self.assertEqual(kit.main(args), 2)
                    self.assertEqual(out.getvalue(), '')
                    self.assertIn('Error:', err.getvalue())
                    self.assertNotIn('Traceback', err.getvalue())


if __name__ == '__main__':
    unittest.main()
