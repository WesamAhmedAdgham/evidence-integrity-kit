"""Even authenticated manifests must describe a possible evidence tree."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519

import evidence_integrity as kit
import manifest_signatures as sig


class SignedTreePreflightTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.manifest = self.root / 'manifest.json'
        self.signature = self.root / 'manifest.sig'
        self.public = self.root / 'public.pem'
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.public.write_bytes(self.key.public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))

    def write_conflict(self, names):
        raw = json.dumps({'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': name, 'sha256': 'a' * 64} for name in names]}).encode('utf-8')
        self.manifest.write_bytes(raw)
        return raw

    def test_signing_refuses_conflict_before_private_key_access(self):
        for names in (['a', 'a/b'], ['a/b', 'a']):
            self.write_conflict(names)
            with self.subTest(names=names), patch('signing_keys.read_private_key') as private, \
                    patch.object(sig, 'sign_manifest_bytes') as sign:
                with self.assertRaisesRegex(ValueError, 'file is also a directory'):
                    kit.sign_manifest_file(self.manifest, self.root / 'unused.pem')
                private.assert_not_called()
                sign.assert_not_called()

    def test_valid_signature_cannot_bypass_tree_preflight(self):
        for names in (['a', 'a/b'], ['a/b', 'a']):
            raw = self.write_conflict(names)
            self.signature.write_bytes(sig.sign_manifest_bytes(raw, self.key))
            with self.subTest(names=names), patch.object(kit, 'verify') as verify, \
                    patch.object(sig, 'verify_manifest_signature', wraps=sig.verify_manifest_signature) as authenticate:
                with self.assertRaisesRegex(ValueError, 'file is also a directory'):
                    kit.verify_signed(self.root / 'unused', self.manifest, self.signature, self.public)
                authenticate.assert_called_once()
                verify.assert_not_called()


if __name__ == '__main__':
    unittest.main()
