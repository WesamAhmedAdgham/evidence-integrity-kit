"""Manifest identity and stability regression tests with synthetic files."""
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

import evidence_integrity as kit


class ManifestStabilityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.path = self.root / 'manifest.json'
        self.path.write_bytes(b'{}')
        self.other = self.root / 'other.json'
        self.other.write_bytes(b'{}')
        self.real_open = kit.open_evidence

    def test_replacement_before_open_rejected(self):
        def swap(path):
            os.replace(self.other, path)
            return self.real_open(path)

        with patch('evidence_integrity.open_evidence', side_effect=swap), \
                patch('evidence_integrity.json.loads') as decoder:
            with self.assertRaisesRegex(ValueError, 'Manifest identity changed'):
                kit.load_manifest(self.path)
            decoder.assert_not_called()
        self.assertFalse(self.other.exists())

    def test_append_after_read_rejected_before_decode(self):
        @contextmanager
        def opener(path):
            with self.real_open(path) as stream:
                def read(size):
                    raw = stream.read(size)
                    with path.open('ab') as writer:
                        writer.write(b' ')
                    return raw
                wrapper = Mock(wraps=stream)
                wrapper.read.side_effect = read
                yield wrapper

        with patch('evidence_integrity.open_evidence', side_effect=opener), \
                patch('evidence_integrity.json.loads') as decoder:
            with self.assertRaisesRegex(ValueError, 'Manifest changed during reading'):
                kit.load_manifest(self.path)
            decoder.assert_not_called()
        self.assertEqual(self.path.read_bytes(), b'{} ')

    def test_simulated_post_read_path_replacement_rejected(self):
        real_stat = Path.stat
        replacement = self.other.stat()
        finished = False

        @contextmanager
        def opener(path):
            with self.real_open(path) as stream:
                def read(size):
                    nonlocal finished
                    raw = stream.read(size)
                    finished = True
                    return raw
                wrapper = Mock(wraps=stream)
                wrapper.read.side_effect = read
                yield wrapper

        def stat_path(path, *args, **kwargs):
            if finished and path == self.path:
                return replacement
            return real_stat(path, *args, **kwargs)

        with patch('evidence_integrity.open_evidence', side_effect=opener), \
                patch.object(Path, 'stat', stat_path), \
                patch('evidence_integrity.json.loads') as decoder:
            with self.assertRaisesRegex(ValueError, 'Manifest path changed'):
                kit.load_manifest(self.path)
            decoder.assert_not_called()

    def test_regular_hard_link_remains_supported(self):
        alias = self.root / 'alias.json'
        os.link(self.path, alias)
        self.assertEqual(kit.load_manifest(alias), {})
