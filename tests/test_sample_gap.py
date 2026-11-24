"""Reject observable same-inode changes between metadata sampling points."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


class MetadataGapTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.path = self.root / 'a.txt'
        self.path.write_bytes(b'{}')
        self.real_open = kit.open_evidence

    def append_at_open(self, path, *args, **kwargs):
        with path.open('ab') as stream:
            stream.write(b' ')
        return self.real_open(path, *args, **kwargs)

    def test_evidence_change_before_open(self):
        with patch('evidence_integrity.open_evidence', side_effect=self.append_at_open):
            with self.assertRaisesRegex(ValueError, 'Evidence changed'):
                kit.generate(self.root, ['a.txt'])

    def test_manifest_change_before_open(self):
        with patch('evidence_integrity.open_evidence', side_effect=self.append_at_open):
            with self.assertRaisesRegex(ValueError, 'Manifest changed'):
                kit.load_manifest(self.path)

    def test_manifest_change_before_final_path_check(self):
        original = Path.stat
        samples = 0

        def sample(path, *args, **kwargs):
            nonlocal samples
            if path == self.path:
                samples += 1
                if samples == 2:
                    with path.open('ab') as stream:
                        stream.write(b' ')
            return original(path, *args, **kwargs)

        with patch.object(Path, 'stat', sample):
            with self.assertRaisesRegex(ValueError, 'Manifest changed'):
                kit.load_manifest(self.path)
        self.assertEqual(self.path.read_bytes(), b'{} ')

    def test_evidence_change_before_final_path_check(self):
        original = kit.evidence_path
        samples = 0

        def sample(root, name):
            nonlocal samples
            samples += 1
            if samples == 2:
                with self.path.open('ab') as stream:
                    stream.write(b' ')
            return original(root, name)

        manifest = kit.generate(self.root, ['a.txt'])
        with patch('evidence_integrity.evidence_path', side_effect=sample):
            report = kit.verify(self.root, manifest)
        self.assertFalse(report['ok'])
        self.assertEqual(report['files'][0]['status'], 'error')
        self.assertIn('Evidence changed', report['files'][0]['detail'])
        self.assertEqual(self.path.read_bytes(), b'{} ')

    def test_stable_file(self):
        manifest = kit.generate(self.root, ['a.txt'])
        self.assertTrue(kit.verify(self.root, manifest)['ok'])
        self.assertEqual(kit.load_manifest(self.path), {})
