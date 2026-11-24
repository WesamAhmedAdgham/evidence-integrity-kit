"""Conservative case and Unicode path collision preflight."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence_integrity import generate, verify


class PathCollisionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def assert_rejected_without_io(self, names):
        manifest = {'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': name, 'sha256': 'a' * 64} for name in names]}
        for operation, arg in ((generate, names), (verify, manifest)):
            with self.subTest(operation=operation.__name__), \
                    patch('evidence_integrity.evidence_path') as path, \
                    patch('evidence_integrity.digest') as digest:
                with self.assertRaisesRegex(ValueError, 'Portable path collision'):
                    operation(self.root, arg)
                path.assert_not_called()
                digest.assert_not_called()

    def test_case_collision(self):
        self.assert_rejected_without_io(['A.txt', 'a.txt'])

    def test_canonical_unicode_collision(self):
        self.assert_rejected_without_io(['é.txt', 'e\u0301.txt'])

    def test_casefold_expansion(self):
        self.assert_rejected_without_io(['Straße.txt', 'STRASSE.txt'])

    def test_directory_prefix_collision(self):
        self.assert_rejected_without_io(['Dir/a.txt', 'dir/b.txt'])

    def test_unicode_directory_prefix_collision(self):
        self.assert_rejected_without_io(['é/a.txt', 'e\u0301/b.txt'])

    def test_shared_exact_prefix_and_distinct_names(self):
        (self.root / 'Dir').mkdir()
        for name in ('Dir/a.txt', 'Dir/b.txt'):
            (self.root / name).write_bytes(name.encode())
        manifest = generate(self.root, ['Dir/b.txt', 'Dir/a.txt'])
        self.assertEqual([x['path'] for x in manifest['files']], ['Dir/a.txt', 'Dir/b.txt'])
        self.assertTrue(verify(self.root, manifest)['ok'])


if __name__ == '__main__':
    unittest.main()
