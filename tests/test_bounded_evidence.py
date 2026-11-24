"""Regression tests for bounded hashing and identity aliases (synthetic data)."""
import hashlib
import io
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


class SizedReadTests(unittest.TestCase):
    def test_exact_sizes_and_hashes(self):
        for size in (0, 1, 8191, 8192, 262144, 262145, 1048577):
            with self.subTest(size=size):
                data = b'x' * size
                reader = kit.SizedEvidenceReader(io.BytesIO(data), size)
                self.assertEqual(hashlib.file_digest(reader, 'sha256').digest(),
                                 hashlib.sha256(data).digest())
                self.assertEqual(reader.remaining, 0)
                self.assertTrue(reader.eof_checked)

    def test_partial_progress_is_permitted(self):
        class Partial(io.BytesIO):
            def readinto(self, buffer):
                return super().readinto(memoryview(buffer)[:2])
        data = b'synthetic data'
        reader = kit.SizedEvidenceReader(Partial(data), len(data))
        self.assertEqual(hashlib.file_digest(reader, 'sha256').digest(),
                         hashlib.sha256(data).digest())

    def test_premature_eof_rejected(self):
        reader = kit.SizedEvidenceReader(io.BytesIO(b'abc'), 4)
        with self.assertRaisesRegex(ValueError, 'incomplete or invalid read'):
            hashlib.file_digest(reader, 'sha256')

    def test_continuously_growing_input_is_bounded(self):
        class Endless:
            def __init__(self):
                self.requested = 0
            def readinto(self, buffer):
                self.requested += len(buffer)
                buffer[:] = b'x' * len(buffer)
                return len(buffer)
            def read(self, size):
                self.requested += size
                return b'x' * size
        stream = Endless()
        size = 1048577
        with self.assertRaisesRegex(ValueError, 'expected end of file'):
            hashlib.file_digest(kit.SizedEvidenceReader(stream, size), 'sha256')
        self.assertEqual(stream.requested, size + 1)

    def test_invalid_progress_rejected(self):
        for result in (None, -1, True, 5):
            with self.subTest(result=result):
                class Invalid:
                    def readinto(self, buffer):
                        return result
                reader = kit.SizedEvidenceReader(Invalid(), 4)
                with self.assertRaisesRegex(ValueError, 'incomplete or invalid read'):
                    reader.readinto(bytearray(4))


class EvidenceIntegrationTests(unittest.TestCase):
    def test_real_file_growth_and_truncation_are_errors(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            file = root / 'evidence.bin'
            original = b'abcdef'
            real_open = kit.open_evidence
            for mutation in ('append', 'truncate'):
                for operation in ('generate', 'verify'):
                    with self.subTest(mutation=mutation, operation=operation):
                        file.write_bytes(original)
                        manifest = kit.generate(root, ['evidence.bin'])
                        class Mutator:
                            def __init__(self, stream):
                                self.stream = stream
                                self.mutated = False
                            def fileno(self):
                                return self.stream.fileno()
                            def read(self, size):
                                return self.stream.read(size)
                            def readinto(self, buffer):
                                if not self.mutated:
                                    with file.open('r+b') as writer:
                                        if mutation == 'append':
                                            writer.seek(0, 2)
                                            writer.write(b'!')
                                        else:
                                            writer.truncate(2)
                                    self.mutated = True
                                return self.stream.readinto(buffer)
                        @contextmanager
                        def substitute(*args, **kwargs):
                            with real_open(*args, **kwargs) as stream:
                                yield Mutator(stream)
                        with patch.object(kit, 'open_evidence', substitute):
                            if operation == 'generate':
                                with self.assertRaisesRegex(ValueError, 'changed during hashing'):
                                    kit.generate(root, ['evidence.bin'])
                            else:
                                result = kit.verify(root, manifest)
                                self.assertFalse(result['ok'])
                                self.assertEqual(result['files'][0]['status'], 'error')
                                self.assertIn('changed during hashing', result['files'][0]['detail'])

    def test_same_sampled_identity_is_rejected_before_second_digest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'one.bin').write_bytes(b'same')
            (root / 'two.bin').write_bytes(b'same')
            manifest = kit.generate(root, ['one.bin', 'two.bin'])
            real_path = kit.evidence_path
            def alias(base, name):
                return real_path(base, 'one.bin' if name == 'two.bin' else name)
            with patch.object(kit, 'evidence_path', side_effect=alias):
                with patch.object(kit, 'digest', wraps=kit.digest) as digest:
                    with self.assertRaisesRegex(ValueError, 'identity alias'):
                        kit.generate(root, ['one.bin', 'two.bin'])
                    self.assertEqual(digest.call_count, 1)
                with patch.object(kit, 'digest', wraps=kit.digest) as digest:
                    result = kit.verify(root, manifest)
                    self.assertEqual(digest.call_count, 1)
                    self.assertFalse(result['ok'])
                    self.assertEqual([x['status'] for x in result['files']], ['match', 'error'])
                    self.assertIn('identity alias', result['files'][1]['detail'])

    def test_distinct_files_with_identical_bytes_remain_supported(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in ('one.bin', 'two.bin'):
                (root / name).write_bytes(b'same')
            self.assertTrue(kit.verify(root, kit.generate(root, ['one.bin', 'two.bin']))['ok'])


if __name__ == '__main__':
    unittest.main()
