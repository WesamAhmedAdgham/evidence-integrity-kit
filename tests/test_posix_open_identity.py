"""Native POSIX descriptor-versus-namespace checks, synthetic fixtures only."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


@unittest.skipUnless(os.name == 'posix', 'POSIX descriptor traversal required')
class PosixOpenIdentityTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name).resolve()
        self.parent = self.root / 'outer'
        self.inner = self.parent / 'inner'
        self.inner.mkdir(parents=True)
        self.leaf = self.inner / 'a.txt'
        self.leaf.write_bytes(b'synthetic')
        self.name = 'outer/inner/a.txt'

    def exercise(self, trigger):
        acquired = []
        original = self.leaf.stat()
        real_open = os.open
        moved = self.root / 'moved'
        triggered = []
        def intercept(path, *args, **kwargs):
            fd = real_open(path, *args, **kwargs)
            acquired.append(fd)
            if path == trigger:
                self.parent.rename(moved)
                self.parent.mkdir()
                (moved / 'inner').rename(self.inner)
                triggered.append(True)
                self.assertTrue(os.path.samestat(original, self.leaf.stat()))
            return fd
        with kit.pinned_root(self.root) as root_fd:
            with patch.object(os, 'open', side_effect=intercept):
                with self.assertRaisesRegex(ValueError, 'opened directory identity changed'):
                    kit.open_evidence(self.leaf, root=self.root, name=self.name,
                                      root_fd=root_fd)
            self.assertEqual(triggered, [True])
            self.assertTrue(os.path.samestat(os.fstat(root_fd), self.root.stat()))
            for fd in set(acquired):
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_swap_immediately_after_directory_open(self):
        self.exercise('outer')

    def test_swap_immediately_after_leaf_open(self):
        self.exercise('a.txt')

    def test_stable_path_with_all_handles(self):
        self.assertTrue(kit.verify(self.root, kit.generate(self.root, [self.name]))['ok'])


class PathDepthTests(unittest.TestCase):
    def test_portable_depth_limit_before_io(self):
        accepted = '/'.join(['a'] * kit.MAX_PATH_COMPONENTS)
        self.assertEqual(len(kit.validate_relative_path(accepted)), kit.MAX_PATH_COMPONENTS)
        rejected = accepted + '/a'
        manifest = {'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': rejected, 'sha256': 'a' * 64}]}
        for operation, arg in ((kit.generate, [rejected]), (kit.verify, manifest)):
            with patch.object(kit, 'resolve_path') as resolve:
                with self.assertRaisesRegex(ValueError, 'component limit'):
                    operation(Path('unused'), arg)
                resolve.assert_not_called()


if __name__ == '__main__':
    unittest.main()
