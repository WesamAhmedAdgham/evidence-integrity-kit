"""Manifest open-time validation regressions using synthetic files only."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


class ManifestOpenTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'mkfifo'), 'POSIX FIFO fixture required')
    def test_fifo_substitution_does_not_block(self):
        script = '''
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import evidence_integrity as kit

with tempfile.TemporaryDirectory() as temp:
    path = Path(temp) / 'manifest.json'
    path.write_bytes(b'{}')
    original = Path.stat
    swapped = False

    def substitute(self, *args, **kwargs):
        global swapped
        checked = original(self, *args, **kwargs)
        if self == path and not swapped:
            swapped = True
            path.unlink()
            os.mkfifo(path)
        return checked

    with patch.object(Path, 'stat', substitute), patch.object(kit.json, 'loads') as decoder:
        try:
            kit.load_manifest(path)
        except ValueError as exc:
            assert 'regular file' in str(exc), str(exc)
        else:
            raise AssertionError('FIFO substitution accepted')
        decoder.assert_not_called()
    assert swapped
'''
        result = subprocess.run([sys.executable, '-c', script],
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, repr(result.stdout + result.stderr))

    def test_opened_nonregular_descriptor_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'manifest.json'
            path.write_bytes(b'{}')
            directory = Path(temp).stat()
            with patch('evidence_integrity.open_evidence') as opener, \
                    patch('evidence_integrity.os.fstat', return_value=directory), \
                    patch('evidence_integrity.json.loads') as decoder:
                stream = opener.return_value.__enter__.return_value
                with self.assertRaisesRegex(ValueError, 'regular file'):
                    kit.load_manifest(path)
                stream.read.assert_not_called()
                decoder.assert_not_called()

    def test_regular_manifest_still_loads(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'manifest.json'
            path.write_bytes(b'{}')
            self.assertEqual(kit.load_manifest(path), {})
