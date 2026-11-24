"""Control inputs must not reach key parsing or signature verification after observed races."""
import os
import secrets
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519

import evidence_integrity as kit
import signing_keys as keys
import manifest_signatures as sig


class SignedControlInputTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        key = ed25519.Ed25519PrivateKey.generate()
        password = secrets.token_hex(24).encode('ascii')
        self.inputs = {
            'Public key': key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo),
            'Private key': key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                             ser.BestAvailableEncryption(password)),
            'Signature': sig.sign_manifest_bytes(b'{}', key),
        }
        self.real_open = kit.open_evidence

    def exercise(self, label, change):
        path = self.root / 'control'
        replacement = self.root / 'replacement'
        path.write_bytes(self.inputs[label])
        replacement.write_bytes(self.inputs[label])
        changed = []

        @contextmanager
        def opener(requested, *args, **kwargs):
            if change == 'replace':
                os.replace(replacement, path)
                changed.append(True)
            with self.real_open(requested, *args, **kwargs) as stream:
                wrapper = Mock(wraps=stream)

                def read(size):
                    raw = stream.read(size)
                    if change == 'append':
                        with path.open('ab') as writer:
                            writer.write(b' ')
                        changed.append(True)
                    return raw

                wrapper.read.side_effect = read
                yield wrapper

        with patch.object(kit, 'open_evidence', side_effect=opener), \
                patch.object(keys, 'load_public_key') as public, \
                patch.object(keys, 'prompt_passphrase') as prompt, \
                patch.object(sig, 'verify_manifest_signature') as authenticate:
            expected = 'identity changed' if change == 'replace' else 'changed during reading'
            with self.assertRaisesRegex(ValueError, label + ' ' + expected):
                if label == 'Public key':
                    keys.read_public_key(path)
                elif label == 'Private key':
                    keys.read_private_key(path)
                else:
                    raw = kit.read_control_bytes(path, limit=sig.MAX_SIGNATURE_FILE_BYTES,
                                                 label='Signature')
                    sig.verify_manifest_signature(b'{}', raw, None)
            public.assert_not_called()
            prompt.assert_not_called()
            authenticate.assert_not_called()
        self.assertEqual(changed, [True])

    def test_public_key_replacement_rejected(self):
        self.exercise('Public key', 'replace')

    def test_private_key_replacement_rejected(self):
        self.exercise('Private key', 'replace')

    def test_signature_replacement_rejected(self):
        self.exercise('Signature', 'replace')

    def test_public_key_mutation_rejected(self):
        self.exercise('Public key', 'append')

    def test_private_key_mutation_rejected(self):
        self.exercise('Private key', 'append')

    def test_signature_mutation_rejected(self):
        self.exercise('Signature', 'append')
