"""Primitive known-answer and protocol tests; public RFC fixture key only."""
import hashlib
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import serialization

import manifest_signatures as sig

# RFC 8032 section 7.1 TEST 1. This published seed is never a production key.
SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
PUBLIC = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
RFC_SIGNATURE = bytes.fromhex(
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
    '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
RAW = (b'{"version":1,"algorithm":"sha256","files":[{"path":"a.txt","sha256":"'
       + b'a' * 64 + b'"}]}\r\n')
# Independently generated with openssl pkeyutl -sign -rawin, OpenSSL 3.5.5,
# using the RFC seed encoded as PKCS#8 DER and the exact v1 domain + RAW bytes.
PROTOCOL_SIGNATURE = bytes.fromhex(
    '73132ce8f9724c8ce06d5573b43917d1a72566cf17a9cce4dbee057931529b121'
    'ee63568a28513302468a5a5e07f230e16e8da964c0c33034cc070a3fd450905')


class Ed25519PrimitiveTests(unittest.TestCase):
    def setUp(self):
        self.key = ed25519.Ed25519PrivateKey.from_private_bytes(SEED)
        self.public = ed25519.Ed25519PublicKey.from_public_bytes(PUBLIC)

    def test_rfc8032_known_answer(self):
        self.assertEqual(self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw), PUBLIC)
        self.assertEqual(self.key.sign(b''), RFC_SIGNATURE)
        self.public.verify(RFC_SIGNATURE, b'')

    def test_independent_protocol_known_answer(self):
        self.assertEqual(sig.signed_message(RAW),
                         b'Evidence Integrity Kit signed manifest v1\x00' + RAW)
        expected = PROTOCOL_SIGNATURE.hex().encode('ascii') + b'\n'
        self.assertEqual(sig.sign_manifest_bytes(RAW, self.key), expected)
        self.assertEqual(sig.sign_manifest_bytes(RAW, self.key), expected)
        sig.verify_manifest_signature(RAW, expected, self.public)

    def test_line_endings_and_changed_bytes_fail_authentication(self):
        signed = sig.sign_manifest_bytes(RAW, self.key)
        for changed in (RAW.replace(b'\r\n', b'\n'), RAW + b' ',
                        RAW.replace(b'a.txt', b'b.txt')):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, 'signature invalid'):
                    sig.verify_manifest_signature(changed, signed, self.public)

    def test_wrong_key_and_tampered_signature_fail(self):
        signed = sig.sign_manifest_bytes(RAW, self.key)
        wrong = ed25519.Ed25519PrivateKey.generate().public_key()
        with self.assertRaisesRegex(ValueError, 'signature invalid'):
            sig.verify_manifest_signature(RAW, signed, wrong)
        altered = bytes([PROTOCOL_SIGNATURE[0] ^ 1]) + PROTOCOL_SIGNATURE[1:]
        with self.assertRaisesRegex(ValueError, 'signature invalid'):
            sig.verify_manifest_signature(RAW, sig.encode_signature(altered), self.public)

    def test_signature_encoding_accepts_only_three_defined_endings(self):
        raw = PROTOCOL_SIGNATURE.hex().encode('ascii')
        for ending in (b'', b'\n', b'\r\n'):
            self.assertEqual(sig.decode_signature(raw + ending), PROTOCOL_SIGNATURE)
        for malformed in (b' ' + raw, raw.upper(), raw + b'\n\n', raw + b'\r',
                          b'\xef\xbb\xbf' + raw, raw[:-1], raw + b'x',
                          b'g' + raw[1:], bytearray(raw)):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(ValueError, 'signature encoding'):
                    sig.decode_signature(malformed)

    def test_invalid_raw_signature_length_and_type(self):
        for invalid in (b'', b'x' * 63, b'x' * 65, bytearray(b'x' * 64)):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, 'signature length or type'):
                    sig.encode_signature(invalid)

    def test_wrong_key_types_rejected(self):
        wrong = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaisesRegex(ValueError, 'private key required'):
            sig.sign_manifest_bytes(RAW, wrong)
        with self.assertRaisesRegex(ValueError, 'public key required'):
            sig.verify_manifest_signature(RAW, sig.encode_signature(PROTOCOL_SIGNATURE),
                                          wrong.public_key())

    def test_manifest_buffer_bounds_before_provider(self):
        with patch.object(sig, 'MAX_MANIFEST_BYTES', 2), \
                patch.object(sig, 'provider') as provider:
            for raw in (b'{} ', bytearray(b'{}'), '{}'):
                with self.subTest(raw=raw):
                    with self.assertRaisesRegex(ValueError, 'Invalid manifest byte buffer'):
                        sig.sign_manifest_bytes(raw, self.key)
                    with self.assertRaisesRegex(ValueError, 'Invalid manifest byte buffer'):
                        sig.verify_manifest_signature(raw, sig.encode_signature(PROTOCOL_SIGNATURE),
                                                      self.public)
            provider.assert_not_called()
