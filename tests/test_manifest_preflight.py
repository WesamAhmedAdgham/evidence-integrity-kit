"""Reject malformed manifest structure before evidence I/O."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence_integrity import generate, verify


class ManifestPreflightTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / 'a.txt').write_bytes(b'a')
        (self.root / 'b.txt').write_bytes(b'b')
        self.manifest = generate(self.root, ['a.txt', 'b.txt'])

    def assert_no_evidence_io(self, entry, message):
        self.manifest['files'].append(entry)
        with patch('evidence_integrity.evidence_path') as path, patch('evidence_integrity.digest') as digest:
            with self.assertRaisesRegex(ValueError, message):
                verify(self.root, self.manifest)
            path.assert_not_called()
            digest.assert_not_called()

    def test_late_invalid_hash(self):
        self.assert_no_evidence_io({'path': 'c.txt', 'sha256': 'bad'}, 'Invalid manifest entry')

    def test_late_duplicate_path(self):
        self.assert_no_evidence_io(dict(self.manifest['files'][0]), 'Duplicate path')

    def test_late_non_object(self):
        self.assert_no_evidence_io(None, 'Invalid manifest entry')

    def test_late_missing_path(self):
        self.assert_no_evidence_io({'sha256': 'a' * 64}, 'Invalid manifest entry')

    def test_valid_structure_preserves_order_and_statuses(self):
        self.manifest['files'].reverse()
        (self.root / 'a.txt').unlink()
        (self.root / 'b.txt').write_bytes(b'changed')
        result = verify(self.root, self.manifest)
        self.assertFalse(result['ok'])
        self.assertEqual([(x['path'], x['status']) for x in result['files']],
                         [('b.txt', 'mismatch'), ('a.txt', 'error')])


if __name__ == '__main__':
    unittest.main()
