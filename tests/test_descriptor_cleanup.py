"""Exercise POSIX traversal resource ownership and fail-closed capabilities."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


@unittest.skipUnless(os.name == 'posix', 'POSIX directory descriptors required')
class DescriptorCleanupTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        folder = self.root / 'one' / 'two'
        folder.mkdir(parents=True)
        (folder / 'a.txt').write_bytes(b'synthetic')

    def exercise_open(self, name, succeeds):
        acquired = []
        real_open, real_dup = os.open, os.dup

        def track_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            acquired.append(fd)
            return fd

        def track_dup(*args, **kwargs):
            fd = real_dup(*args, **kwargs)
            acquired.append(fd)
            return fd

        with kit.pinned_root(self.root) as root_fd:
            with patch.object(os, 'open', side_effect=track_open), \
                    patch.object(os, 'dup', side_effect=track_dup):
                if succeeds:
                    with kit.open_evidence(self.root / name, root=self.root,
                                           name=name, root_fd=root_fd) as stream:
                        self.assertEqual(stream.read(), b'synthetic')
                else:
                    with self.assertRaises(FileNotFoundError):
                        kit.open_evidence(self.root / name, root=self.root,
                                          name=name, root_fd=root_fd)
            self.assertGreaterEqual(len(acquired), 2)
            self.assertNotIn(root_fd, acquired)
            self.assertTrue(os.path.samestat(os.fstat(root_fd), self.root.stat()))
            for fd in set(acquired):
                with self.subTest(fd=fd):
                    with self.assertRaises(OSError):
                        os.fstat(fd)
        with self.assertRaises(OSError):
            os.fstat(root_fd)

    def test_success_closes_all_traversal_descriptors(self):
        self.exercise_open('one/two/a.txt', True)

    def test_missing_intermediate_closes_all_traversal_descriptors(self):
        self.exercise_open('one/missing/a.txt', False)

    def test_missing_leaf_closes_all_traversal_descriptors(self):
        self.exercise_open('one/two/missing.txt', False)

    def test_missing_dir_fd_capability_fails_before_hashing(self):
        with patch.object(os, 'supports_dir_fd', set()), \
                patch.object(kit, 'digest') as digest:
            with self.assertRaisesRegex(ValueError, 'Secure relative evidence opening unavailable'):
                kit.generate(self.root, ['one/two/a.txt'])
            digest.assert_not_called()

    def test_missing_required_flag_fails_before_hashing(self):
        for flag in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK'):
            with self.subTest(flag=flag), patch.object(os, flag), \
                    patch.object(kit, 'digest') as digest:
                delattr(os, flag)
                with self.assertRaisesRegex(ValueError, 'Secure relative evidence opening unavailable'):
                    kit.generate(self.root, ['one/two/a.txt'])
                digest.assert_not_called()

    def test_missing_root_descriptor_cannot_fall_back(self):
        with self.assertRaisesRegex(ValueError, 'Evidence root descriptor required'):
            kit.open_evidence(self.root / 'one/two/a.txt', root=self.root,
                              name='one/two/a.txt')
