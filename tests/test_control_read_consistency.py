"""Reject inconsistent byte counts before parsing control files."""
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


class ControlInputTests(unittest.TestCase):
    def test_short_valid_json_prefix_is_not_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'manifest.json'
            path.write_bytes(b'{}    ')
            real_open = kit.open_evidence
            @contextmanager
            def substitute(*args, **kwargs):
                with real_open(*args, **kwargs) as stream:
                    class Short:
                        def fileno(self):
                            return stream.fileno()
                        def read(self, size):
                            return stream.read(2)
                    yield Short()
            with patch.object(kit, 'open_evidence', substitute):
                with patch.object(kit, 'decode_manifest') as decode:
                    with self.assertRaisesRegex(ValueError, 'byte count differs'):
                        kit.load_manifest(path)
                    decode.assert_not_called()

    def test_sampled_oversize_is_rejected_even_if_read_is_short(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'control'
            path.write_bytes(b'abcdef')
            real_open = kit.open_evidence
            @contextmanager
            def substitute(*args, **kwargs):
                with real_open(*args, **kwargs) as stream:
                    class Short:
                        def fileno(self):
                            return stream.fileno()
                        def read(self, size):
                            return stream.read(2)
                    yield Short()
            with patch.object(kit, 'open_evidence', substitute):
                with self.assertRaisesRegex(ValueError, 'byte limit'):
                    kit.read_control_bytes(path, limit=4, label='Control')

    def test_more_bytes_than_sampled_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'control'
            path.write_bytes(b'abc')
            real_open = kit.open_evidence
            @contextmanager
            def substitute(*args, **kwargs):
                with real_open(*args, **kwargs) as stream:
                    class Long:
                        def fileno(self):
                            return stream.fileno()
                        def read(self, size):
                            return stream.read(size) + b'!'
                    yield Long()
            with patch.object(kit, 'open_evidence', substitute):
                with self.assertRaisesRegex(ValueError, 'byte count differs'):
                    kit.read_control_bytes(path, limit=10, label='Control')

    def test_numeric_overflow_is_not_accepted_as_infinity(self):
        for raw in (b'{"extra":1e999}', b'{"nested":[-1e999]}'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, 'Non-finite JSON number'):
                    kit.decode_manifest(raw)
        self.assertEqual(kit.decode_manifest(b'{"extra":1.25e2}'), {'extra': 125.0})


if __name__ == '__main__':
    unittest.main()
