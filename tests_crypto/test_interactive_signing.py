"""Exercise the actual POSIX terminal and signed CLI, with no prompt mock."""
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519

import evidence_integrity as kit

CLI = Path(__file__).resolve().parents[1] / 'evidence_integrity.py'


@unittest.skipUnless(os.name == 'posix', 'Native POSIX PTY fixture required')
class InteractiveSigningTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / 'evidence'
        self.root.mkdir()
        (self.root / 'a.bin').write_bytes(b'\x00\xff\r\n')
        self.manifest = self.base / 'manifest.json'
        self.manifest.write_bytes(json.dumps(kit.generate(self.root, ['a.bin'])).encode('ascii'))
        self.private = self.base / 'private.pem'
        self.public = self.base / 'public.pem'
        self.password = secrets.token_hex(24).encode('ascii')
        key = ed25519.Ed25519PrivateKey.generate()
        self.private.write_bytes(key.private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(self.password)))
        self.public.write_bytes(key.public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))

    def run_interactive(self, password):
        import pty
        import select
        import termios

        master, slave = pty.openpty()
        proc = None
        transcript = bytearray()
        try:
            original = termios.tcgetattr(slave)
            self.assertTrue(original[3] & termios.ECHO)
            proc = subprocess.Popen(
                [sys.executable, str(CLI), 'sign', '--manifest', str(self.manifest),
                 '--private-key', str(self.private)],
                stdin=slave, stderr=slave, stdout=subprocess.PIPE, start_new_session=True)
            deadline = time.monotonic() + 15
            # Wait for both the real prompt and disabled kernel terminal echo.
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.05)[0]:
                    transcript.extend(os.read(master, 4096))
                if (b'Private key passphrase: ' in transcript and
                        not termios.tcgetattr(slave)[3] & termios.ECHO):
                    break
                if proc.poll() is not None:
                    self.fail('Signing exited before secure terminal prompt')
            else:
                self.fail('Timed out waiting for no-echo terminal prompt')
            os.write(master, password + b'\n')
            out, _ = proc.communicate(timeout=15)
            while select.select([master], [], [], 0)[0]:
                transcript.extend(os.read(master, 4096))
            # Do not display synthetic password or terminal transcript in failures.
            self.assertFalse(password in transcript, 'Passphrase appeared in terminal output')
            self.assertFalse(password in out, 'Passphrase appeared in stdout')
            self.assertEqual(termios.tcgetattr(slave), original, 'Terminal settings not restored')
            return proc.returncode, out, bytes(transcript)
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
            os.close(slave)
            os.close(master)

    def test_real_terminal_sign_and_verify_no_echo(self):
        code, out, _ = self.run_interactive(self.password)
        self.assertEqual(code, 0)
        self.assertRegex(out, rb'^[0-9a-f]{128}\n$')
        signature = self.base / 'manifest.sig'
        signature.write_bytes(out)
        result = subprocess.run(
            [sys.executable, str(CLI), 'verify-signed', '--assume-stable-tree', '--root', str(self.root),
             '--manifest', str(self.manifest), '--signature', str(signature),
             '--public-key', str(self.public)], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)['ok'])

    def test_real_terminal_wrong_password_no_echo_or_output(self):
        wrong = secrets.token_hex(24).encode('ascii')
        code, out, transcript = self.run_interactive(wrong)
        self.assertEqual((code, out), (2, b''))
        self.assertTrue(b'Unable to unlock encrypted private key' in transcript)
