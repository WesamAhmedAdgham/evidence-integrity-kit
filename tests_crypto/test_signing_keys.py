"""Key handling tests; generate synthetic keys and passwords at runtime."""
import base64
import getpass
import hashlib
import secrets
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519, ec

import signing_keys as keys
import manifest_signatures as sig


class KeyLoadingTests(unittest.TestCase):
    def setUp(self):
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.password = secrets.token_hex(24).encode('ascii')
        self.public = self.key.public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        self.private = self.key.private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
            ser.BestAvailableEncryption(self.password))
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_public_key_and_fingerprint(self):
        raw = self.key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        for pem in (self.public, self.public.rstrip(b'\n'), self.public.replace(b'\n', b'\r\n')):
            loaded = keys.load_public_key(pem)
            self.assertEqual(keys.public_key_fingerprint(loaded), hashlib.sha256(raw).hexdigest())

    def test_encrypted_private_key_signing_roundtrip(self):
        for pem in (self.private, self.private.replace(b'\n', b'\r\n')):
            loaded = keys.load_private_key(pem, self.password)
            signed = sig.sign_manifest_bytes(b'{}', loaded)
            sig.verify_manifest_signature(b'{}', signed, keys.load_public_key(self.public))

    def test_wrong_password_sanitized(self):
        wrong = secrets.token_hex(24).encode('ascii')
        with self.assertRaisesRegex(ValueError, '^Unable to unlock encrypted private key$') as error:
            keys.load_private_key(self.private, wrong)
        self.assertNotIn(wrong.decode('ascii'), str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)

    def test_empty_or_nonbytes_password_rejected(self):
        for password in (None, b'', 'not bytes', bytearray(b'x')):
            with self.subTest(kind=type(password)):
                with self.assertRaisesRegex(ValueError, 'passphrase required'):
                    keys.load_private_key(self.private, password)

    def test_unencrypted_key_rejected_even_with_encrypted_label(self):
        raw = self.key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                     ser.NoEncryption())
        with self.assertRaisesRegex(ValueError, 'PEM envelope'):
            keys.load_private_key(raw, self.password)
        disguised = raw.replace(b'PRIVATE KEY', b'ENCRYPTED PRIVATE KEY')
        with self.assertRaisesRegex(ValueError, 'Unable to unlock'):
            keys.load_private_key(disguised, self.password)

    def test_other_key_types_rejected(self):
        other = ec.generate_private_key(ec.SECP256R1())
        public = other.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        private = other.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                      ser.BestAvailableEncryption(self.password))
        with self.assertRaisesRegex(ValueError, 'Ed25519 public key required'):
            keys.load_public_key(public)
        with self.assertRaisesRegex(ValueError, 'Ed25519 private key required'):
            keys.load_private_key(private, self.password)

    def test_pem_rejects_multiple_blocks_and_unrelated_data(self):
        for raw in (self.public * 2, self.private, b'prefix\n' + self.public,
                    self.public + b'extra', b'\xef\xbb\xbf' + self.public,
                    self.public + b'\n', self.public.replace(b'\n', b'\r')):
            with self.subTest(length=len(raw)):
                with self.assertRaisesRegex(ValueError, 'PEM envelope'):
                    keys.load_public_key(raw)
        with self.assertRaisesRegex(ValueError, 'PEM envelope'):
            keys.load_private_key(self.private * 2, self.password)

    def test_malformed_base64_and_der(self):
        prefix, suffix = b'-----BEGIN PUBLIC KEY-----\n', b'\n-----END PUBLIC KEY-----\n'
        for body in (b'***', b'AAAA====', b'Zg=', b'Zh==', b'AAAA'):
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    keys.load_public_key(prefix + body + suffix)
        der = keys.pem_payload(self.public, keys.PUBLIC_LABEL) + b'\x00'
        with self.assertRaises(ValueError):
            keys.load_public_key(prefix + base64.b64encode(der) + suffix)

    def test_direct_and_file_size_limits(self):
        oversize = b'x' * (keys.MAX_KEY_BYTES + 1)
        path = self.root / 'oversized.pem'
        path.write_bytes(oversize)
        with self.assertRaisesRegex(ValueError, 'size or type'):
            keys.load_public_key(oversize)
        with self.assertRaisesRegex(ValueError, 'Public key exceeds'):
            keys.read_public_key(path)
        with patch.object(keys, 'prompt_passphrase') as prompt:
            with self.assertRaisesRegex(ValueError, 'Private key exceeds'):
                keys.read_private_key(path)
            prompt.assert_not_called()

    def test_explicit_key_file_readers_and_prompt(self):
        public_path, private_path = self.root / 'public.pem', self.root / 'private.pem'
        public_path.write_bytes(self.public)
        private_path.write_bytes(self.private)
        with patch.object(keys, 'prompt_passphrase', return_value=self.password) as prompt:
            key = keys.read_private_key(private_path)
        prompt.assert_called_once_with()
        sig.verify_manifest_signature(b'{}', sig.sign_manifest_bytes(b'{}', key),
                                      keys.read_public_key(public_path))

    def test_invalid_private_input_refused_before_prompt(self):
        path = self.root / 'invalid.pem'
        path.write_bytes(self.public)
        with patch.object(keys, 'prompt_passphrase') as prompt:
            with self.assertRaisesRegex(ValueError, 'PEM envelope'):
                keys.read_private_key(path)
            prompt.assert_not_called()

    def test_redirected_prompt_refuses_without_reading(self):
        with patch.object(keys.sys.stdin, 'isatty', return_value=False), \
                patch.object(keys.getpass, 'getpass') as prompt:
            with self.assertRaisesRegex(ValueError, 'Interactive non-echoing terminal'):
                keys.prompt_passphrase()
            prompt.assert_not_called()

    def test_prompt_warning_refuses_echo_fallback(self):
        def unsafe(*args, **kwargs):
            warnings.warn('Cannot control echo', getpass.GetPassWarning)
            self.fail('Prompt continued after warning')
        with patch.object(keys.sys.stdin, 'isatty', return_value=True), \
                patch.object(keys.sys.stderr, 'isatty', return_value=True), \
                patch.object(keys.getpass, 'getpass', side_effect=unsafe):
            with self.assertRaisesRegex(ValueError, 'Secure private key passphrase input failed'):
                keys.prompt_passphrase()

    def test_interactive_prompt_encoding_and_cancellation(self):
        phrase = secrets.token_hex(12) + '\u00e9'
        with patch.object(keys.sys.stdin, 'isatty', return_value=True), \
                patch.object(keys.sys.stderr, 'isatty', return_value=True), \
                patch.object(keys.getpass, 'getpass', return_value=phrase) as prompt:
            self.assertEqual(keys.prompt_passphrase(), phrase.encode('utf-8'))
            prompt.assert_called_once_with('Private key passphrase: ', stream=keys.sys.stderr)
            for error in (EOFError, KeyboardInterrupt):
                prompt.side_effect = error
                with self.assertRaisesRegex(ValueError, 'Secure private key passphrase input failed'):
                    keys.prompt_passphrase()


    def test_interactive_paste_control_rejected_without_unlock(self):
        path = self.root / 'private.pem'
        path.write_bytes(self.private)
        for phrase in ('\x16', 'prefix\x16suffix'):
            with self.subTest(length=len(phrase)), \
                    patch.object(keys.sys.stdin, 'isatty', return_value=True), \
                    patch.object(keys.sys.stderr, 'isatty', return_value=True), \
                    patch.object(keys.getpass, 'getpass', return_value=phrase), \
                    patch.object(keys, '_load_encrypted_private_der') as unlock:
                with self.assertRaisesRegex(ValueError, '^Unexpected paste control character in passphrase;') as error:
                    keys.read_private_key(path)
                self.assertNotIn(phrase, str(error.exception))
                unlock.assert_not_called()


    def test_real_provider_roundtrip_at_profile_iteration_boundaries(self):
        # Independent test-only DER encoder and standard provider primitives.
        # No production encryption or key-generation API is introduced.
        from cryptography.hazmat.primitives import hashes, padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        def tlv(tag, value):
            n = len(value)
            raw = n.to_bytes(max(1, (n.bit_length()+7)//8), 'big')
            return bytes([tag]) + (bytes([n]) if n < 128 else bytes([128|len(raw)])+raw) + value

        def seq(*values):
            return tlv(0x30, b''.join(values))

        def oid(value):
            return tlv(6, bytes.fromhex(value))

        plaintext = self.key.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8,
                                           ser.NoEncryption())
        expected = self.key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        for iterations, explicit_length, null in ((2048, False, True), (1000000, True, False)):
            with self.subTest(iterations=iterations):
                salt, iv = secrets.token_bytes(16), secrets.token_bytes(16)
                k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                              iterations=iterations).derive(self.password)
                padder = padding.PKCS7(128).padder()
                padded = padder.update(plaintext) + padder.finalize()
                encryptor = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor()
                ciphertext = encryptor.update(padded) + encryptor.finalize()
                count = iterations.to_bytes((iterations.bit_length()+8)//8, 'big')
                pbkdf = seq(tlv(4, salt), tlv(2, count),
                            b'\x02\x01\x20' if explicit_length else b'',
                            seq(oid('2a864886f70d0209'), b'\x05\x00' if null else b''))
                params = seq(seq(oid('2a864886f70d01050c'), pbkdf),
                             seq(oid('60864801650304012a'), tlv(4, iv)))
                der = seq(seq(oid('2a864886f70d01050d'), params), tlv(4, ciphertext))
                pem = b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' + base64.b64encode(der) + b'\n-----END ENCRYPTED PRIVATE KEY-----\n'
                loaded = keys.load_private_key(pem, self.password)
                self.assertEqual(loaded.public_key().public_bytes(ser.Encoding.Raw,
                                                                ser.PublicFormat.Raw), expected)
                sig.verify_manifest_signature(b'{}', sig.sign_manifest_bytes(b'{}', loaded),
                                              keys.load_public_key(self.public))
