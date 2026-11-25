"""Native Windows console signing, using an isolated new console and synthetic data.

The child fixture owns its console and only writes events to that console's
input buffer. No system-wide keyboard automation or external secrets.
"""
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

CLI = Path(__file__).resolve().parents[1] / 'evidence_integrity.py'


def exercise_console(base, scenario):
    import ctypes as c
    from ctypes import wintypes as w
    import hashlib

    class Coord(c.Structure):
        _fields_ = [('x', w.SHORT), ('y', w.SHORT)]

    class Rect(c.Structure):
        _fields_ = [('left', w.SHORT), ('top', w.SHORT),
                    ('right', w.SHORT), ('bottom', w.SHORT)]

    class BufferInfo(c.Structure):
        _fields_ = [('size', Coord), ('cursor', Coord), ('attributes', w.WORD),
                    ('window', Rect), ('maximum', Coord)]

    class KeyEvent(c.Structure):
        _fields_ = [('down', w.BOOL), ('repeat', w.WORD), ('virtual_key', w.WORD),
                    ('scan', w.WORD), ('character', w.WCHAR), ('control', w.DWORD)]

    class Event(c.Union):
        _fields_ = [('key', KeyEvent), ('padding', c.c_byte * 16)]

    class InputRecord(c.Structure):
        _fields_ = [('kind', w.WORD), ('event', Event)]

    if c.sizeof(KeyEvent) != 16 or c.sizeof(InputRecord) != 20 or c.sizeof(BufferInfo) != 22:
        raise RuntimeError('Unexpected Win32 console structure ABI')
    k = c.WinDLL('kernel32', use_last_error=True)

    def bind(name, args, result=w.BOOL):
        f = getattr(k, name)
        f.argtypes, f.restype = args, result
        return f

    get_handle = bind('GetStdHandle', [w.DWORD], w.HANDLE)
    mode = bind('GetConsoleMode', [w.HANDLE, c.POINTER(w.DWORD)])
    info = bind('GetConsoleScreenBufferInfo', [w.HANDLE, c.POINTER(BufferInfo)])
    read = bind('ReadConsoleOutputCharacterW',
                [w.HANDLE, c.POINTER(w.WCHAR), w.DWORD, Coord, c.POINTER(w.DWORD)])
    write = bind('WriteConsoleInputW',
                 [w.HANDLE, c.POINTER(InputRecord), w.DWORD, c.POINTER(w.DWORD)])

    def require(ok, stage):
        if not ok:
            raise OSError(c.get_last_error(), stage)

    input_handle = get_handle(-10 & 0xffffffff)
    output_handle = get_handle(-11 & 0xffffffff)
    error_handle = get_handle(-12 & 0xffffffff)
    original_mode = w.DWORD()
    require(mode(input_handle, c.byref(original_mode)), 'Isolated console input unavailable')
    output_mode = w.DWORD()
    require(mode(output_handle, c.byref(output_mode)), 'Isolated console output unavailable')
    require(mode(error_handle, c.byref(output_mode)), 'Isolated console stderr unavailable')
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise RuntimeError('Fixture did not receive native console streams')

    def screen():
        buffer = BufferInfo()
        require(info(output_handle, c.byref(buffer)), 'Get console screen info failed')
        count = int(buffer.size.x) * (int(buffer.cursor.y) + 1)
        if not 0 < count <= 1000000:
            raise RuntimeError('Unexpected console buffer size')
        chars = c.create_unicode_buffer(count)
        actual = w.DWORD()
        require(read(output_handle, chars, count, Coord(0, 0), c.byref(actual)),
                'Read console screen failed')
        return chars[:actual.value]

    def enter(phrase):
        records = []
        for ch in phrase + '\r':
            for down in (True, False):
                item = InputRecord()
                item.kind = 1  # KEY_EVENT
                vk = 13 if ch == '\r' else (ord('V') if ch == '\x16' else ord(ch.upper()))
                item.event.key = KeyEvent(down, 1, vk, 0, ch, 8 if ch == '\x16' else 0)
                records.append(item)
        events = (InputRecord * len(records))(*records)
        actual = w.DWORD()
        require(write(input_handle, events, len(events), c.byref(actual)),
                'Write synthetic console input failed')
        if actual.value != len(events):
            raise RuntimeError('Incomplete synthetic console input')

    root = base / 'evidence'
    root.mkdir()
    data = b'\x00\xff\r\n'
    (root / 'a.bin').write_bytes(data)
    manifest = base / 'manifest.json'
    manifest.write_bytes(json.dumps({'version': 1, 'algorithm': 'sha256', 'files': [
        {'path': 'a.bin', 'sha256': hashlib.sha256(data).hexdigest()}]}).encode('ascii'))
    private, public = base / 'private.pem', base / 'public.pem'
    password = secrets.token_hex(24)
    entered = '\x16' if scenario == 'paste-control' else (
        secrets.token_hex(24) if scenario == 'wrong' else password)
    key = ed25519.Ed25519PrivateKey.generate()
    private.write_bytes(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                          ser.BestAvailableEncryption(password.encode('ascii'))))
    public.write_bytes(key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    signature = base / 'manifest.sig'
    before = screen()
    with signature.open('wb') as out:
        child = subprocess.Popen(
            [sys.executable, str(CLI), 'sign', '--manifest', str(manifest),
             '--private-key', str(private)], stdout=out)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if 'Private key passphrase: ' in screen() and 'Private key passphrase: ' not in before:
                    break
                if child.poll() is not None:
                    raise RuntimeError('Signing exited before native console prompt')
                time.sleep(0.05)
            else:
                raise RuntimeError('Native console prompt timeout')
            enter(entered)
            code = child.wait(timeout=15)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    transcript = screen()
    raw_signature = signature.read_bytes()
    final_mode = w.DWORD()
    require(mode(input_handle, c.byref(final_mode)), 'Final console mode unavailable')
    # Persist only nonsensitive assertions and outcome, not the screen or password.
    report = {'sign_exit': code, 'no_echo': entered not in transcript and entered.encode('ascii') not in raw_signature,
              'mode_restored': final_mode.value == original_mode.value,
              'signature_empty': not raw_signature,
              'unlock_error': 'Unable to unlock encrypted private key' in transcript,
              'paste_error': 'Unexpected paste control character in passphrase;' in transcript}
    if scenario == 'correct' and code == 0:
        verified = subprocess.run(
            [sys.executable, str(CLI), 'verify-signed', '--assume-stable-tree', '--root', str(root),
             '--manifest', str(manifest), '--signature', str(signature),
             '--public-key', str(public)], capture_output=True, timeout=15)
        report['verify_exit'] = verified.returncode
        report['verified'] = (verified.returncode == 0 and
                              json.loads(verified.stdout)['ok'] is True)
    return report


@unittest.skipUnless(os.name == 'nt', 'Native Windows console fixture required')
class WindowsConsoleSigningTests(unittest.TestCase):
    def run_console(self, scenario):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            # Do not redirect these streams: CREATE_NEW_CONSOLE provides real
            # console handles to this isolated fixture process.
            child = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), '--console-fixture',
                 str(base), scenario],
                creationflags=subprocess.CREATE_NEW_CONSOLE)
            try:
                code = child.wait(timeout=65)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
            report = json.loads((base / 'result.json').read_text(encoding='utf-8'))
            self.assertEqual(code, 0, report)
            self.assertTrue(report['no_echo'])
            self.assertTrue(report['mode_restored'])
            return report

    def test_native_windows_console_sign_verify_no_echo(self):
        result = self.run_console('correct')
        self.assertEqual(result['sign_exit'], 0)
        self.assertFalse(result['signature_empty'])
        self.assertEqual(result['verify_exit'], 0)
        self.assertTrue(result['verified'])

    def test_native_windows_console_wrong_passphrase_no_echo(self):
        result = self.run_console('wrong')
        self.assertEqual(result['sign_exit'], 2)
        self.assertTrue(result['signature_empty'])
        self.assertTrue(result['unlock_error'])


    def test_native_windows_console_paste_control_rejected(self):
        result = self.run_console('paste-control')
        self.assertEqual(result['sign_exit'], 2)
        self.assertTrue(result['signature_empty'])
        self.assertTrue(result['paste_error'])
        self.assertFalse(result['unlock_error'])


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--console-fixture' and os.name == 'nt':
        directory = Path(sys.argv[2])
        try:
            result = exercise_console(directory, sys.argv[3])
        except Exception as exc:
            # No transcript, password, or exception text containing input.
            result = {'fixture_error_type': type(exc).__name__,
                      'winerror': getattr(exc, 'winerror', None)}
            (directory / 'result.json').write_text(json.dumps(result), encoding='utf-8')
            raise SystemExit(1)
        (directory / 'result.json').write_text(json.dumps(result), encoding='utf-8')
    else:
        unittest.main()
