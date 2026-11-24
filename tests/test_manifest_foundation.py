"""Regression coverage for separate control reads and pure manifest validation."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


class ManifestFoundationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.path = self.root / 'manifest.json'
        self.raw = b'{\r\n  "name": "\xc3\xa9"\r\n}\r\n'
        self.path.write_bytes(self.raw)

    def test_read_preserves_exact_bytes_without_decoding(self):
        with patch.object(kit.json, 'loads') as decoder:
            raw = kit.read_manifest_bytes(self.path)
        decoder.assert_not_called()
        self.assertIsInstance(raw, bytes)
        self.assertEqual(raw, self.raw)

    def test_decode_uses_retained_buffer_without_reopening(self):
        raw = kit.read_manifest_bytes(self.path)
        replacement = self.root / 'replacement.json'
        replacement.write_bytes(b'{"changed": true}')
        os.replace(replacement, self.path)
        with patch.object(kit, 'open_evidence', side_effect=AssertionError('unexpected open')), \
                patch.object(Path, 'stat', side_effect=AssertionError('unexpected stat')):
            self.assertEqual(kit.decode_manifest(raw), {'name': '\u00e9'})

    def test_raw_reader_does_not_parse_malformed_json(self):
        self.path.write_bytes(b'{')
        self.assertEqual(kit.read_manifest_bytes(self.path), b'{')
        with self.assertRaises(ValueError):
            kit.decode_manifest(b'{')

    def test_direct_decoder_rejects_oversize_before_parse(self):
        with patch.object(kit, 'MAX_MANIFEST_BYTES', 2), \
                patch.object(kit.json, 'loads') as decoder:
            with self.assertRaisesRegex(ValueError, 'byte limit'):
                kit.decode_manifest(b'{} ')
            decoder.assert_not_called()

    def test_decoder_requires_immutable_bytes(self):
        for raw in ('{}', bytearray(b'{}'), memoryview(b'{}')):
            with self.subTest(kind=type(raw)):
                with self.assertRaisesRegex(ValueError, 'must be bytes'):
                    kit.decode_manifest(raw)

    def test_control_reader_exact_limit_and_overflow(self):
        self.path.write_bytes(b'\x00\xff\r\n')
        self.assertEqual(kit.read_control_bytes(self.path, limit=4, label='Signature'),
                         b'\x00\xff\r\n')
        with self.assertRaisesRegex(ValueError, 'Signature exceeds 3 byte limit'):
            kit.read_control_bytes(self.path, limit=3, label='Signature')

    def test_invalid_control_limit_rejected_without_io(self):
        for limit in (-1, True, 1.5):
            with self.subTest(limit=limit), patch.object(Path, 'stat') as sample:
                with self.assertRaisesRegex(ValueError, 'Invalid control input byte limit'):
                    kit.read_control_bytes(self.path, limit=limit, label='Signature')
                sample.assert_not_called()

    def test_pure_preflight_preserves_order_and_never_accesses_evidence(self):
        manifest = {'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': 'b.txt', 'sha256': 'b' * 64},
            {'path': 'a.txt', 'sha256': 'a' * 64}]}
        with patch.object(Path, 'stat', side_effect=AssertionError('unexpected stat')), \
                patch.object(kit, 'evidence_path', side_effect=AssertionError('unexpected path')), \
                patch.object(kit, 'digest', side_effect=AssertionError('unexpected hash')):
            self.assertEqual(kit.validate_manifest(manifest, strict=True),
                             [('b.txt', 'b' * 64), ('a.txt', 'a' * 64)])

    def test_strict_preflight_rejects_extensions_unsigned_keeps_compatibility(self):
        entry = {'path': 'a.txt', 'sha256': 'a' * 64}
        manifest = {'version': 1, 'algorithm': 'sha256', 'files': [entry]}
        for candidate in (dict(manifest, extra=True),
                          dict(manifest, files=[dict(entry, extra=True)])):
            with self.subTest(candidate=candidate):
                self.assertEqual(kit.validate_manifest(candidate), [('a.txt', 'a' * 64)])
                with self.assertRaisesRegex(ValueError, 'Unexpected signed manifest'):
                    kit.validate_manifest(candidate, strict=True)

    def test_strict_preflight_retains_path_and_digest_checks(self):
        manifest = {'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': '../outside.txt', 'sha256': 'a' * 64}]}
        with self.assertRaisesRegex(ValueError, 'Invalid portable relative path'):
            kit.validate_manifest(manifest, strict=True)
        manifest['files'][0] = {'path': 'a.txt', 'sha256': 'bad'}
        with self.assertRaisesRegex(ValueError, 'Invalid manifest entry'):
            kit.validate_manifest(manifest, strict=True)
