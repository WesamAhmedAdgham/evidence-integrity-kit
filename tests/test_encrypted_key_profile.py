"""Synthetic DER profile and provider integration regressions."""
import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from encrypted_key_profile import (
    PBES2, PBKDF2, HMAC_SHA256, AES256_CBC, MIN_ITERATIONS,
    MAX_ITERATIONS, validate_encrypted_key_profile,
)
import signing_keys as keys


def tlv(tag, data):
    n = len(data)
    if n < 128:
        size = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        size = bytes([128 | len(raw)]) + raw
    return bytes([tag]) + size + data


def seq(*parts):
    return tlv(0x30, b''.join(parts))


def integer(n):
    return tlv(2, n.to_bytes(max(1, (n.bit_length() + 8) // 8), 'big'))


def profile(*, iterations=MIN_ITERATIONS, salt=b'synthetic-salt-1',
            prf=HMAC_SHA256, cipher=AES256_CBC, iv=b'i' * 16,
            ciphertext=b'c' * 64, key_length=b'', integer_bytes=None,
            kdf=PBKDF2, extra=b'', prf_params=b'\x05\x00'):
    return seq(seq(tlv(6, PBES2),
                   seq(seq(tlv(6, kdf),
                           seq(tlv(4, salt),
                               integer(iterations) if integer_bytes is None else integer_bytes,
                               key_length, seq(tlv(6, prf), prf_params))),
                       seq(tlv(6, cipher), tlv(4, iv)))),
               tlv(4, ciphertext), extra)


def pem(der):
    return b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' + base64.b64encode(der) + b'\n-----END ENCRYPTED PRIVATE KEY-----\n'


class EncryptedKeyProfileTests(unittest.TestCase):
    def test_iteration_boundaries_and_optional_parameters(self):
        for der in (profile(), profile(iterations=MAX_ITERATIONS),
                    profile(key_length=integer(32)), profile(prf_params=b'')):
            validate_encrypted_key_profile(der)

    def test_excessive_or_weak_work_rejected(self):
        for n in (0, 1, MIN_ITERATIONS - 1, MAX_ITERATIONS + 1, 2**31 - 1):
            with self.subTest(n=n), self.assertRaisesRegex(ValueError, 'unbounded PKCS#8'):
                validate_encrypted_key_profile(profile(iterations=n))

    def test_unsupported_algorithms_and_parameters(self):
        for kw in (dict(prf=b'\x2a'), dict(cipher=b'\x2a'), dict(kdf=b'\x2a'),
                   dict(salt=b'x'*7), dict(salt=b'x'*65), dict(iv=b'i'*15),
                   dict(ciphertext=b'c'*17), dict(ciphertext=b'c'*4112),
                   dict(key_length=integer(31)), dict(prf_params=b'\x05\x01\x00'),
                   dict(extra=b'\x05\x00')):
            with self.subTest(kw=list(kw)), self.assertRaises(ValueError):
                validate_encrypted_key_profile(profile(**kw))

    def test_malformed_der_lengths_integers_and_trailing_data(self):
        valid = profile()
        for der in (valid[:-1], valid+b'\x00', b'\x30\x80'+valid+b'\x00\x00',
                    b'\x30\x83\x00\x00\x01\x00',
                    profile(integer_bytes=b'\x02\x02\x00\x01'),
                    profile(integer_bytes=b'\x02\x01\xff'),
                    profile(integer_bytes=b'\x02\x00'),
                    profile(integer_bytes=b'\x02\x81\x01\x01')):
            with self.subTest(der=der[:8]), self.assertRaises(ValueError):
                validate_encrypted_key_profile(der)

    def test_invalid_profile_refused_before_prompt_and_provider(self):
        raw = pem(profile(iterations=MAX_ITERATIONS + 1))
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'synthetic.pem'
            path.write_bytes(raw)
            with patch.object(keys, 'prompt_passphrase') as prompt, \
                    patch.object(keys, 'serialization_provider') as provider:
                with self.assertRaisesRegex(ValueError, 'unbounded PKCS#8'):
                    keys.read_private_key(path)
                with self.assertRaisesRegex(ValueError, 'unbounded PKCS#8'):
                    keys.load_private_key(raw, b'synthetic')
                prompt.assert_not_called()
                provider.assert_not_called()

    def test_every_truncated_prefix_and_noncanonical_outer_length_rejected(self):
        der = profile()
        for i in range(len(der)):
            with self.subTest(length=i), self.assertRaises(ValueError):
                validate_encrypted_key_profile(der[:i])
        # The fixture uses short-form or one-byte long-form length. Rewrite
        # that length with an unnecessary leading zero, preserving payload.
        n = der[1]
        if n < 128:
            malformed = b'\x30\x81' + bytes([n]) + der[2:]
        else:
            malformed = b'\x30\x82\x00' + der[2:]
        with self.assertRaises(ValueError):
            validate_encrypted_key_profile(malformed)

    def test_public_key_noncanonical_spki_rejected_before_provider(self):
        prefix = bytes.fromhex('302a300506032b6570032100')
        der = prefix + bytes(range(32))
        def public_pem(data):
            return b'-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(data) + b'\n-----END PUBLIC KEY-----\n'
        with patch.object(keys, 'serialization_provider') as provider:
            for bad in (der[:-1], der+b'\x00', der[:8]+b'\x71'+der[9:],
                        der[:11]+b'\x01'+der[12:],
                        b'\x30\x81\x2a'+der[2:]):
                with self.subTest(length=len(bad)), self.assertRaisesRegex(ValueError, 'canonical SPKI'):
                    keys.load_public_key(public_pem(bad))
            provider.assert_not_called()

    def test_passphrase_byte_limit_before_provider(self):
        with patch.object(keys, 'serialization_provider') as provider:
            with self.assertRaisesRegex(ValueError, 'passphrase exceeds byte limit'):
                keys.load_private_key(pem(profile()), b'x'*(keys.MAX_PASSPHRASE_BYTES+1))
            provider.assert_not_called()
        self.assertEqual(keys.validate_passphrase(b'x'*keys.MAX_PASSPHRASE_BYTES),
                         b'x'*keys.MAX_PASSPHRASE_BYTES)
        for phrase in ('x'*1025, '\u00e9'*513):
            with patch.object(keys.sys.stdin, 'isatty', return_value=True), \
                    patch.object(keys.sys.stderr, 'isatty', return_value=True), \
                    patch.object(keys.getpass, 'getpass', return_value=phrase):
                with self.assertRaisesRegex(ValueError, 'passphrase exceeds byte limit'):
                    keys.prompt_passphrase()
