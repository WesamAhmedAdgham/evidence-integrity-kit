"""Exercise production manifest verification with an evaluation-only loader hook."""
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import evidence_integrity as kit
import manifest_signatures as sig
import signing_keys as keys
from evaluation import candidate_admission as candidate


class AdmissionIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve() / 'evidence'
        self.root.mkdir()
        self.control = self.root.parent / 'control'
        self.control.mkdir()
        content = b'synthetic evidence only'
        (self.root / 'file.txt').write_bytes(content)
        self.raw = json.dumps({'version': 1, 'algorithm': 'sha256',
                               'files': [{'path': 'file.txt',
                                          'sha256': hashlib.sha256(content).hexdigest()}]}).encode()
        self.manifest = self.control / 'manifest.json'
        self.signature = self.control / 'manifest.sig'
        self.public = self.control / 'public.pem'
        self.manifest.write_bytes(self.raw)
        signer = ed25519.Ed25519PrivateKey.generate()
        self.signature.write_bytes(sig.sign_manifest_bytes(self.raw, signer))
        self.public.write_bytes(signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def invoke(self, signed=True):
        args = ['verify-signed' if signed else 'verify', '--assume-stable-tree',
                '--root', str(self.root), '--manifest', str(self.manifest)]
        if signed:
            args += ['--signature', str(self.signature), '--public-key', str(self.public)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = kit.main(args)
        return code, out.getvalue(), err.getvalue()

    @staticmethod
    def pem(point):
        der = keys.ED25519_SPKI_PREFIX + point
        return (b'-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(der) +
                b'\n-----END PUBLIC KEY-----\n')

    def assert_rejected_before_evidence(self, message, *, before_signature=True):
        with patch.object(keys, 'load_public_key', side_effect=candidate.load_public_key), \
                patch.object(kit, 'decode_manifest') as decode, \
                patch.object(kit, 'verify') as verify, \
                patch.object(sig, 'verify_manifest_signature',
                             wraps=sig.verify_manifest_signature) as authenticate:
            code, out, err = self.invoke()
            self.assertEqual((code, out), (2, ''))
            self.assertIn(message, err)
            decode.assert_not_called()
            verify.assert_not_called()
            if before_signature:
                authenticate.assert_not_called()
            else:
                authenticate.assert_called_once()

    def test_generated_key_authenticates_real_manifest_and_evidence(self):
        with patch.object(keys, 'load_public_key', side_effect=candidate.load_public_key):
            code, out, err = self.invoke()
        self.assertEqual((code, err), (0, ''))
        report = json.loads(out)
        self.assertTrue(report['ok'])
        self.assertTrue(report['authentication']['verified'])

    def test_invalid_points_rejected_before_generic_key_provider(self):
        with patch.object(candidate, '_BASE_LOAD') as provider:
            for point in (bytes(32), b'\x01' + bytes(31), b'\xff' * 32):
                with self.subTest(point=point.hex()):
                    self.public.write_bytes(self.pem(point))
                    self.assert_rejected_before_evidence('Invalid Ed25519 public point')
            provider.assert_not_called()

    def test_malformed_envelope_rejected_before_validator(self):
        self.public.write_bytes(b'not PEM')
        with patch.object(candidate, '_validator') as validate:
            self.assert_rejected_before_evidence('Invalid key PEM envelope')
            validate.assert_not_called()

    def test_unavailable_validator_is_fail_closed(self):
        for exc in (ImportError('synthetic missing'), OSError('synthetic load failure'),
                    RuntimeError('synthetic runtime failure')):
            with self.subTest(exception=type(exc).__name__), \
                    patch.object(candidate, '_validator', side_effect=exc), \
                    patch.object(candidate, '_BASE_LOAD') as provider:
                self.assert_rejected_before_evidence('point validation unavailable')
                provider.assert_not_called()

    def test_invalid_validator_result_is_fail_closed(self):
        for result in (False, None, 1):
            with self.subTest(result=result), \
                    patch.object(candidate, '_validator', return_value=lambda _: result):
                self.assert_rejected_before_evidence('Invalid Ed25519 public point')

    def test_wrong_signature_with_valid_key_never_reaches_json(self):
        self.signature.write_bytes(sig.sign_manifest_bytes(
            self.raw + b' ', ed25519.Ed25519PrivateKey.generate()))
        self.assert_rejected_before_evidence('Manifest signature invalid', before_signature=False)

    def test_unsigned_operation_does_not_need_validator(self):
        with patch.object(keys, 'load_public_key', side_effect=candidate.load_public_key), \
                patch.object(candidate, '_validator', side_effect=ImportError('synthetic missing')) as validate:
            code, out, err = self.invoke(signed=False)
            self.assertEqual((code, err), (0, ''))
            self.assertTrue(json.loads(out)['ok'])
            validate.assert_not_called()
