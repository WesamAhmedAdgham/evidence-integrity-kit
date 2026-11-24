"""Bounded POSIX FIFO substitution regression using synthetic evidence."""
import os
import subprocess
import sys
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'mkfifo'), 'POSIX FIFO fixture required')
class SafeOpenTests(unittest.TestCase):
    def run_swap(self, command):
        script = '''
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import evidence_integrity as kit

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp).resolve()
    path = root / 'a.txt'
    path.write_bytes(b'synthetic')
    manifest = kit.generate(root, ['a.txt'])
    original = kit.evidence_path

    def substitute(root, name):
        checked = original(root, name)
        path.unlink()
        os.mkfifo(path)
        return checked

    with patch.object(kit, 'evidence_path', side_effect=substitute), \\
            patch.object(kit.hashlib, 'file_digest') as digest:
        if COMMAND == 'create':
            try:
                kit.generate(root, ['a.txt'])
            except (ValueError, OSError):
                pass
            else:
                raise AssertionError('FIFO substitution accepted')
        else:
            report = kit.verify(root, manifest)
            assert not report['ok'], report
            assert report['files'][0]['status'] == 'error', report
        digest.assert_not_called()
'''
        completed = subprocess.run(
            [sys.executable, '-c', 'COMMAND = ' + repr(command) + '\n' + script],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=5)
        self.assertEqual(completed.returncode, 0, repr(completed.stdout + completed.stderr))

    def test_create_fifo_substitution_does_not_block(self):
        self.run_swap('create')

    def test_verify_fifo_substitution_does_not_block(self):
        self.run_swap('verify')


if __name__ == '__main__':
    unittest.main()
