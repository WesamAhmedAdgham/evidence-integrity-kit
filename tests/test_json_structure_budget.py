"""Regression tests for bounded JSON admission using synthetic inputs only."""
import json
import random
import unittest
from unittest.mock import patch

import evidence_integrity as eik


class JsonBudgetTests(unittest.TestCase):
    def test_largest_entry_count_with_portable_names(self):
        doc = {'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': f'folder/f{i:05}', 'sha256': 'a' * 64}
            for i in range(10000)]}
        for indent in (None, 2):
            self.assertEqual(eik.decode_manifest(json.dumps(doc, indent=indent).encode()), doc)

    def test_dense_input_rejected_before_decoder(self):
        n = (eik.MAX_MANIFEST_BYTES - 2) // 3
        raw = b'[' + b'{},' * (n - 1) + b'{}]'
        with patch.object(eik.json, 'loads') as decode:
            with self.assertRaisesRegex(ValueError, 'structure budget'):
                eik.decode_manifest(raw)
            decode.assert_not_called()

    def test_exact_structure_boundary(self):
        n = eik.MAX_JSON_STRUCTURE
        self.assertEqual(len(eik.decode_manifest(b'[' + b'0,' * (n-1) + b'0]')), n)
        with self.assertRaisesRegex(ValueError, 'structure budget'):
            eik.decode_manifest(b'[' + b'0,' * n + b'0]')

    def test_exact_depth_boundary(self):
        n = eik.MAX_JSON_DEPTH
        eik.decode_manifest(b'[' * n + b'0' + b']' * n)
        with self.assertRaisesRegex(ValueError, 'nesting budget'):
            eik.decode_manifest(b'[' * (n+1) + b'0' + b']' * (n+1))

    def test_large_string_does_not_consume_structural_budget(self):
        raw = b'"' + b'{},:[]' * ((eik.MAX_MANIFEST_BYTES - 2)//6) + b'"'
        self.assertEqual(eik.decode_manifest(raw), raw[1:-1].decode())

    def test_exact_byte_boundary(self):
        raw = b'"' + b'a' * (eik.MAX_MANIFEST_BYTES - 2) + b'"'
        self.assertEqual(len(eik.decode_manifest(raw)), eik.MAX_MANIFEST_BYTES - 2)
        with self.assertRaises(ValueError):
            eik.decode_manifest(raw + b' ')

    def test_existing_strict_rejections_preserved(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}',
                    b'"\\q"', b'{"a":1,}', b'[{]}', b'\xff', b'{}{}',
                    b'{"a":1,"\\u0061":2}', b'"unfinished', b']'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                eik.decode_manifest(raw)

    def test_generated_valid_documents(self):
        rng = random.Random(20261124)
        alphabet = 'a{}[],:\\"\n\tالعربيةé🐈'
        def gen(depth=0):
            kind = rng.randrange(5 if depth < 5 else 3)
            if kind == 0:
                return ''.join(rng.choices(alphabet, k=rng.randrange(40)))
            if kind == 1:
                return rng.randint(-100000, 100000)
            if kind == 2:
                return rng.choice([True, False, None])
            if kind == 3:
                return [gen(depth+1) for _ in range(rng.randrange(6))]
            return {str(i)+rng.choice(alphabet): gen(depth+1)
                    for i in range(rng.randrange(6))}
        for _ in range(10000):
            obj = gen()
            raw = json.dumps(obj, ensure_ascii=rng.choice([True, False])).encode()
            self.assertEqual(eik.decode_manifest(raw), obj)

    def test_fail_closed_on_bad_type(self):
        for raw in ('{}', bytearray(b'{}'), None):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                eik.decode_manifest(raw)
