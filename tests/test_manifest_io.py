"""Regression tests for bounded manifest I/O (synthetic fixtures only)."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence_integrity import MAX_MANIFEST_BYTES, load_manifest, main


class ManifestIOTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / 'manifest.json'
        (self.root / 'a.txt').write_bytes(b'hello')

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_exact_input_limit(self):
        raw = b'{}' + b' ' * (MAX_MANIFEST_BYTES - 2)
        self.path.write_bytes(raw)
        self.assertEqual(load_manifest(self.path), {})

    def test_input_one_byte_over_limit(self):
        self.path.write_bytes(b'{}' + b' ' * (MAX_MANIFEST_BYTES - 1))
        with patch('evidence_integrity.json.loads') as decoder:
            with self.assertRaisesRegex(ValueError, 'byte limit'):
                load_manifest(self.path)
            decoder.assert_not_called()

    def test_read_is_bounded(self):
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'open') as op:
            stream = op.return_value.__enter__.return_value
            stream.read.return_value = b'{}'
            self.assertEqual(load_manifest(self.path), {})
            stream.read.assert_called_once_with(MAX_MANIFEST_BYTES + 1)
            op.assert_called_once_with('rb')

    def test_multibyte_limit_counts_bytes(self):
        self.path.write_bytes('{"x":"é"}'.encode('utf-8'))
        with patch('evidence_integrity.MAX_MANIFEST_BYTES', 9):
            with self.assertRaisesRegex(ValueError, 'byte limit'):
                load_manifest(self.path)

    def test_oversized_cli_rejects_without_stdout(self):
        self.path.write_bytes(b'{}' + b' ' * (MAX_MANIFEST_BYTES - 1))
        code, out, err = self.run_main(['verify', '--root', str(self.root), '--manifest', str(self.path)])
        self.assertEqual((code, out), (2, ''))
        self.assertIn('byte limit', err)

    def test_nonregular_directory(self):
        with self.assertRaisesRegex(ValueError, 'regular file'):
            load_manifest(self.root)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO creation unavailable')
    def test_fifo_rejected_before_open(self):
        os.mkfifo(self.path)
        with patch.object(Path, 'open', side_effect=AssertionError('must not open FIFO')):
            with self.assertRaisesRegex(ValueError, 'regular file'):
                load_manifest(self.path)

    def test_create_portable_size_boundary(self):
        args = ['create', '--root', str(self.root), 'a.txt']
        code, out, err = self.run_main(args)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(json.loads(out)['files'][0]['path'], 'a.txt')
        portable_size = len(out.replace('\n', '\r\n').encode('ascii'))
        with patch('evidence_integrity.MAX_MANIFEST_BYTES', portable_size):
            self.assertEqual(self.run_main(args), (0, out, ''))
            self.path.write_bytes(out.replace('\n', '\r\n').encode('ascii'))
            self.assertEqual(load_manifest(self.path), json.loads(out))
        with patch('evidence_integrity.MAX_MANIFEST_BYTES', portable_size - 1):
            code, out, err = self.run_main(args)
            self.assertEqual((code, out), (2, ''))
            self.assertIn('split the file list', err)


if __name__ == '__main__':
    unittest.main()
