"""Audit-derived regressions; all inputs are synthetic."""
import errno
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit
from native_fixture_support import link_fixture


class AuditBudgetTests(unittest.TestCase):
    def test_exact_aggregate_budget_boundaries(self):
        for constant, accepted, rejected in (
                ('MAX_ENTRIES', ['a', 'b'], ['a', 'b', 'c']),
                ('MAX_TOTAL_COMPONENTS', ['a/b'], ['a/b/c']),
                ('MAX_TOTAL_PATH_CHARS', ['ab'], ['abc'])):
            with self.subTest(constant=constant), patch.object(kit, constant, 2):
                kit.check_path_budget(accepted)
                with self.assertRaisesRegex(ValueError, 'path budget exceeded'):
                    kit.check_path_budget(rejected)

    def test_codex_deep_manifest_rejected_before_trie_or_root(self):
        names = [f'{i}/' + '/'.join(['a'] * 127) for i in range(1000)]
        manifest = {'version': 1, 'algorithm': 'sha256', 'files': [
            {'path': name, 'sha256': 'a' * 64} for name in names]}
        for operation, arg in ((kit.generate, names), (kit.verify, manifest)):
            with patch.object(kit, 'check_path_collisions') as trie, \
                    patch.object(kit, 'resolve_path') as resolve:
                with self.assertRaisesRegex(ValueError, 'path budget exceeded'):
                    operation(Path('unused'), arg)
                trie.assert_not_called()
                resolve.assert_not_called()

    def test_fixture_permission_denial_is_explicit_and_ci_is_strict(self):
        def denied():
            raise PermissionError(errno.EACCES, 'synthetic denied')
        with patch.dict(os.environ, {'EIK_REQUIRE_NATIVE_FIXTURES': '0'}):
            with self.assertRaisesRegex(unittest.SkipTest, 'capability unavailable'):
                link_fixture(self, 'hard link', denied)
        with patch.dict(os.environ, {'EIK_REQUIRE_NATIVE_FIXTURES': '1'}):
            with self.assertRaisesRegex(AssertionError, 'capability unavailable'):
                link_fixture(self, 'hard link', denied)

    def test_unexpected_fixture_failure_is_not_skipped(self):
        def missing():
            raise FileNotFoundError(errno.ENOENT, 'synthetic missing')
        with patch.dict(os.environ, {'EIK_REQUIRE_NATIVE_FIXTURES': '0'}):
            with self.assertRaises(FileNotFoundError):
                link_fixture(self, 'hard link', missing)


@unittest.skipUnless(os.name == 'nt', 'Native Windows ChangeTime regression')
class WindowsAuditMutationTests(unittest.TestCase):
    def test_restored_mtime_mutation_after_second_digest_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            first = root / 'a'
            first.write_bytes(b'AAAA')
            (root / 'b').write_bytes(b'BBBB')
            manifest = kit.generate(root, ['a', 'b'])
            before = first.stat()
            real_digest = kit.digest
            changed = []
            def mutation(*args, **kwargs):
                value = real_digest(*args, **kwargs)
                if kwargs['name'] == 'b':
                    first.write_bytes(b'ZZZZ')
                    os.utime(first, ns=(before.st_atime_ns, before.st_mtime_ns))
                    changed.append(True)
                return value
            with patch.object(kit, 'digest', side_effect=mutation):
                report = kit.verify(root, manifest)
            self.assertEqual(changed, [True])
            self.assertEqual(first.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertNotEqual(hashlib.sha256(first.read_bytes()).hexdigest(),
                                manifest['files'][0]['sha256'])
            self.assertFalse(report['ok'])
            self.assertEqual(report['files'][0]['status'], 'error')
            self.assertIn('Evidence changed before operation completion',
                          report['files'][0]['detail'])


if __name__ == '__main__':
    unittest.main()
