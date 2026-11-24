"""Isolated defensive Ed25519 point-admission evaluation; not runtime code."""
import importlib.metadata
import random
import unittest
from pathlib import Path
import sys

import nacl
from nacl.bindings import crypto_core_ed25519_is_valid_point, crypto_core_ed25519_add
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends.openssl.backend import backend


class CandidateValidatorTests(unittest.TestCase):
    def test_exact_candidate_version(self):
        self.assertEqual(importlib.metadata.version('PyNaCl'), '1.6.2')
        self.assertEqual(nacl.__version__, '1.6.2')
        self.assertEqual(importlib.metadata.version('cryptography'), '50.0.2')
        self.assertTrue(Path(nacl.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()))
        print('OpenSSL:', backend.openssl_version_text(), 'PyNaCl:', nacl.__version__)

    def test_generated_keys_and_rfc8032_public_key(self):
        published = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        self.assertTrue(crypto_core_ed25519_is_valid_point(published))
        for _ in range(128):
            key = ed25519.Ed25519PrivateKey.generate()
            public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertTrue(crypto_core_ed25519_is_valid_point(public))
            key.public_key().verify(key.sign(b'synthetic evaluation'), b'synthetic evaluation')

    def test_invalid_and_small_order_encodings(self):
        for point in (bytes(32), b'\x01' + bytes(31), b'\xff' * 32,
                      (2**255-20).to_bytes(32, 'little'),
                      (2**255-19).to_bytes(32, 'little')):
            with self.subTest(point=point.hex()):
                self.assertFalse(crypto_core_ed25519_is_valid_point(point))

    def test_mixed_order_points_rejected(self):
        # Use library point addition on synthetic keys and the order-two point.
        # No custom curve arithmetic or signature generation with invalid keys.
        torsion = (2**255-20).to_bytes(32, 'little')
        for _ in range(32):
            key = ed25519.Ed25519PrivateKey.generate()
            public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            mixed = crypto_core_ed25519_add(public, torsion)
            self.assertNotEqual(public, mixed)
            self.assertFalse(crypto_core_ed25519_is_valid_point(mixed))

    def test_seeded_random_encodings_are_classified(self):
        rng = random.Random(20261124)
        accepted = 0
        for _ in range(1024):
            result = crypto_core_ed25519_is_valid_point(rng.randbytes(32))
            self.assertIsInstance(result, bool)
            accepted += result
        print('Random input classification:', accepted, 'accepted of 1024; not an independent correctness oracle')
