import hashlib
import tempfile
import unittest
from pathlib import Path
from evidence_integrity import generate, verify


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'a.txt').write_bytes(b'hello')
        (self.root / 'b.txt').write_bytes(b'world')

    def test_expected_sha256(self):
        m = generate(self.root, ['a.txt'])
        self.assertEqual(m['files'][0]['sha256'], hashlib.sha256(b'hello').hexdigest())

    def test_roundtrip(self):
        self.assertTrue(verify(self.root, generate(self.root, ['a.txt', 'b.txt']))['ok'])

    def test_tamper(self):
        m = generate(self.root, ['a.txt'])
        (self.root / 'a.txt').write_bytes(b'changed')
        self.assertEqual(verify(self.root, m)['files'][0]['status'], 'mismatch')

    def test_missing(self):
        m = generate(self.root, ['a.txt'])
        (self.root / 'a.txt').unlink()
        self.assertEqual(verify(self.root, m)['files'][0]['status'], 'error')

    def test_traversal(self):
        for path in ['../a.txt', '/a.txt', 'C:/a.txt', 'x\\a.txt', './a.txt', 'x//a.txt']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                generate(self.root, [path])

    def test_duplicate_generate(self):
        with self.assertRaises(ValueError):
            generate(self.root, ['a.txt', 'a.txt'])

    def test_duplicate_manifest(self):
        m = generate(self.root, ['a.txt'])
        m['files'] *= 2
        with self.assertRaises(ValueError):
            verify(self.root, m)

    def test_invalid_hash(self):
        m = generate(self.root, ['a.txt'])
        m['files'][0]['sha256'] = 'bad'
        with self.assertRaises(ValueError):
            verify(self.root, m)

    def test_invalid_version(self):
        m = generate(self.root, ['a.txt'])
        m['version'] = True
        with self.assertRaises(ValueError):
            verify(self.root, m)

    def test_order(self):
        self.assertEqual(generate(self.root, ['b.txt', 'a.txt']), generate(self.root, ['a.txt', 'b.txt']))

    def test_symlink(self):
        try:
            (self.root / 'link.txt').symlink_to(self.root / 'a.txt')
        except OSError:
            self.skipTest('Symlink creation unavailable')
        with self.assertRaises(ValueError):
            generate(self.root, ['link.txt'])

    def test_empty(self):
        with self.assertRaises(ValueError):
            generate(self.root, [])

    def test_nested(self):
        (self.root / 'nested').mkdir()
        (self.root / 'nested' / 'x.txt').write_bytes(b'x')
        self.assertTrue(verify(self.root, generate(self.root, ['nested/x.txt']))['ok'])


if __name__ == '__main__':
    unittest.main()
