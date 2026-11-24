"""End-to-end signed CLI tests with temporary synthetic evidence and keys."""
import contextlib
import hashlib
import io
import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519

import evidence_integrity as kit
import manifest_signatures as sig
import signing_keys as keys

CLI = Path(__file__).resolve().parents[1] / 'evidence_integrity.py'


class SignedCLITests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / 'evidence'
        self.root.mkdir()
        self.name = 'caf\u00e9.bin'
        self.file = self.root / self.name
        self.file.write_bytes(b'\x00\x1a\r\n\xff')
        self.manifest = self.base / 'manifest.json'
        self.signature = self.base / 'manifest.sig'
        self.public = self.base / 'public.pem'
        self.private = self.base / 'private.pem'
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.password = secrets.token_hex(24).encode('ascii')
        self.public.write_bytes(self.key.public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
        self.private.write_bytes(self.key.private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
            ser.BestAvailableEncryption(self.password)))
        self.raw = (json.dumps(kit.generate(self.root, [self.name]),
                               ensure_ascii=False, indent=2).replace('\n', '\r\n')
                    + '\r\n').encode('utf-8')
        self.manifest.write_bytes(self.raw)
        self.signature.write_bytes(sig.sign_manifest_bytes(self.raw, self.key))
        self.sign_args = ['sign', '--manifest', str(self.manifest),
                          '--private-key', str(self.private)]
        self.verify_args = ['verify-signed', '--root', str(self.root),
                            '--manifest', str(self.manifest), '--signature',
                            str(self.signature), '--public-key', str(self.public)]

    def run_main(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = kit.main(args)
        return code, out.getvalue(), err.getvalue()

    def assert_failure(self, result, message):
        code, out, err = result
        self.assertEqual((code, out), (2, ''))
        self.assertIn(message, err)
        self.assertNotIn('Traceback', err)

    def test_sign_and_subprocess_verify_roundtrip(self):
        original_private = self.private.read_bytes()
        with patch.object(keys, 'prompt_passphrase', return_value=self.password):
            code, out, err = self.run_main(self.sign_args)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(out.encode('ascii'), sig.sign_manifest_bytes(self.raw, self.key))
        self.assertEqual(self.manifest.read_bytes(), self.raw)
        self.assertEqual(self.private.read_bytes(), original_private)
        self.signature.write_bytes(out.encode('ascii'))
        result = subprocess.run([sys.executable, str(CLI), *self.verify_args],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        report = json.loads(result.stdout)
        self.assertTrue(report['ok'])
        self.assertEqual(report['files'], [{'path': self.name, 'status': 'match'}])
        public_raw = self.key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        self.assertEqual(report['authentication'], {
            'protocol': 'evidence-integrity-kit-ed25519-v1',
            'verified': True, 'public_key_sha256': hashlib.sha256(public_raw).hexdigest()})

    def test_changed_manifest_rejected_before_decode_or_evidence(self):
        self.manifest.write_bytes(self.raw + b' ')
        with patch.object(kit, 'decode_manifest') as decode, patch.object(kit, 'verify') as verify:
            self.assert_failure(self.run_main(self.verify_args), 'signature invalid')
            decode.assert_not_called()
            verify.assert_not_called()

    def test_wrong_public_key_rejected_before_decode(self):
        self.public.write_bytes(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
        with patch.object(kit, 'decode_manifest') as decode, patch.object(kit, 'verify') as verify:
            self.assert_failure(self.run_main(self.verify_args), 'signature invalid')
            decode.assert_not_called()
            verify.assert_not_called()

    def test_stripped_signature_never_falls_back(self):
        self.signature.unlink()
        with patch.object(kit, 'decode_manifest') as decode, patch.object(kit, 'verify') as verify:
            code, out, err = self.run_main(self.verify_args)
            self.assertEqual((code, out), (2, ''))
            self.assertTrue(err.startswith('Error:'))
            decode.assert_not_called()
            verify.assert_not_called()

    def test_required_signature_and_key_arguments(self):
        for flag in ('--signature', '--public-key'):
            args = self.verify_args.copy()
            index = args.index(flag)
            del args[index:index + 2]
            with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    kit.main(args)
                self.assertEqual(error.exception.code, 2)

    def test_malformed_and_oversize_signature_rejected_before_decode(self):
        for raw, message in ((b'0' * 127, 'signature encoding'),
                             (b'x' * 131, 'Signature exceeds')):
            self.signature.write_bytes(raw)
            with patch.object(kit, 'decode_manifest') as decode, patch.object(kit, 'verify') as verify:
                self.assert_failure(self.run_main(self.verify_args), message)
                decode.assert_not_called()
                verify.assert_not_called()

    def test_authentication_and_decode_use_exact_same_retained_buffer(self):
        original = sig.verify_manifest_signature
        seen = []

        def authenticate(raw, signature, public):
            original(raw, signature, public)
            seen.append(raw)
            replacement = self.base / 'replacement.json'
            replacement.write_bytes(b'{}')
            os.replace(replacement, self.manifest)

        with patch.object(sig, 'verify_manifest_signature', side_effect=authenticate), \
                patch.object(kit, 'read_manifest_bytes', wraps=kit.read_manifest_bytes) as read, \
                patch.object(kit, 'decode_manifest', wraps=kit.decode_manifest) as decode:
            code, out, err = self.run_main(self.verify_args)
        self.assertEqual((code, err), (0, ''))
        self.assertTrue(json.loads(out)['ok'])
        read.assert_called_once_with(self.manifest)
        decode.assert_called_once()
        self.assertIs(decode.call_args.args[0], seen[0])
        self.assertEqual(self.manifest.read_bytes(), b'{}')

    def test_valid_signature_does_not_bypass_strict_schema(self):
        invalid = (b'{"version":1,"version":1}', b'{', b'{"version":2}',
                   self.raw.replace(b'"version": 1', b'"version": 1, "extra": true'),
                   self.raw.replace(b'caf\xc3\xa9.bin', b'../outside.bin'))
        for raw in invalid:
            self.manifest.write_bytes(raw)
            self.signature.write_bytes(sig.sign_manifest_bytes(raw, self.key))
            with self.subTest(raw=raw), patch.object(kit, 'verify') as verify:
                code, out, err = self.run_main(self.verify_args)
                self.assertEqual((code, out), (2, ''))
                self.assertTrue(err.startswith('Error:'))
                verify.assert_not_called()

    def test_sign_rejects_invalid_manifest_before_prompt(self):
        self.manifest.write_bytes(b'{}')
        with patch.object(keys, 'prompt_passphrase') as prompt:
            self.assert_failure(self.run_main(self.sign_args), 'Unsupported manifest')
            prompt.assert_not_called()

    def test_authenticated_manifest_with_changed_or_missing_evidence(self):
        self.file.write_bytes(b'changed')
        for expected in ('mismatch', 'error'):
            code, out, err = self.run_main(self.verify_args)
            self.assertEqual((code, err), (1, ''))
            report = json.loads(out)
            self.assertFalse(report['ok'])
            self.assertTrue(report['authentication']['verified'])
            self.assertEqual(report['files'][0]['status'], expected)
            if expected == 'mismatch':
                self.file.unlink()

    def test_noninteractive_sign_refused_without_signature(self):
        result = subprocess.run([sys.executable, str(CLI), *self.sign_args],
                                input='', capture_output=True, text=True, timeout=15)
        self.assertEqual((result.returncode, result.stdout), (2, ''))
        self.assertIn('Interactive non-echoing terminal', result.stderr)

    def test_unsigned_report_unchanged(self):
        code, out, err = self.run_main(['verify', '--root', str(self.root),
                                       '--manifest', str(self.manifest)])
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(json.loads(out), {'ok': True,
                         'files': [{'path': self.name, 'status': 'match'}]})


    def test_guarded_signed_cli_never_downgrades(self):
        args = self.verify_args + ['--windows-deny-write']
        code, out, err = self.run_main(args)
        if os.name == 'nt':
            self.assertEqual((code, err), (0, ''))
            report = json.loads(out)
            self.assertTrue(report['ok'])
            self.assertTrue(report['authentication']['verified'])
            self.assertEqual(report['protection']['mode'], 'windows-deny-write')
            self.file.write_bytes(b'changed')
            code, out, err = self.run_main(args)
            self.assertEqual((code, err), (1, ''))
            report = json.loads(out)
            self.assertFalse(report['ok'])
            self.assertTrue(report['authentication']['verified'])
        else:
            self.assert_failure((code, out, err), 'unavailable on this platform')

    def test_guarded_signed_cli_authenticates_before_guard(self):
        self.manifest.write_bytes(self.raw + b' ')
        with patch.object(kit, 'windows_guarded_digests') as acquire, \
                patch.object(kit, 'verify') as verify:
            self.assert_failure(self.run_main(self.verify_args + ['--windows-deny-write']),
                                'signature invalid')
            verify.assert_not_called()
            acquire.assert_not_called()
