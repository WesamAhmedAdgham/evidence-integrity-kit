"""Detect observable changes to previously processed files in one operation."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import evidence_integrity as kit


class MultiFileConsistencyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.first = self.root / 'a.txt'
        self.first.write_bytes(b'synthetic first')
        (self.root / 'b.txt').write_bytes(b'synthetic second')
        self.replacement = self.root / 'replacement.txt'
        self.replacement.write_bytes(self.first.read_bytes())
        self.original_identity = self.first.stat()
        self.assertFalse(self.first.samefile(self.replacement))
        self.real_digest = kit.digest
        self.changed = False

    def mutate_after_first(self, kind):
        def action(*args, **kwargs):
            result = self.real_digest(*args, **kwargs)
            if kwargs['name'] == 'a.txt' and not self.changed:
                if kind == 'append':
                    with self.first.open('ab') as stream:
                        stream.write(b' changed')
                    self.assertEqual(self.first.read_bytes(), b'synthetic first changed')
                else:
                    os.replace(self.replacement, self.first)
                    self.assertFalse(os.path.samestat(self.original_identity, self.first.stat()))
                    self.assertEqual(self.first.read_bytes(), b'synthetic first')
                self.changed = True
            return result
        return action

    def check_create(self, kind):
        with patch.object(kit, 'digest', side_effect=self.mutate_after_first(kind)):
            try:
                kit.generate(self.root, ['a.txt', 'b.txt'])
            except (OSError, ValueError):
                rejected = True
            else:
                rejected = False
        self.assertTrue(self.changed, 'Fixture did not change first file')
        self.assertTrue(rejected, 'Create accepted an observably changed file set')

    def check_verify(self, kind):
        manifest = kit.generate(self.root, ['a.txt', 'b.txt'])
        with patch.object(kit, 'digest', side_effect=self.mutate_after_first(kind)):
            try:
                report = kit.verify(self.root, manifest)
            except (OSError, ValueError):
                rejected = True
            else:
                rejected = not report['ok']
        self.assertTrue(self.changed, 'Fixture did not change first file')
        self.assertTrue(rejected, 'Verify accepted an observably changed file set')

    def test_create_rejects_change_to_previously_hashed_file(self):
        self.check_create('append')

    def test_verify_rejects_change_to_previously_hashed_file(self):
        self.check_verify('append')

    def test_create_rejects_identical_content_replacement(self):
        self.check_create('replace')

    def test_verify_rejects_identical_content_replacement(self):
        self.check_verify('replace')

    def test_stable_multi_file_roundtrip(self):
        manifest = kit.generate(self.root, ['b.txt', 'a.txt'])
        self.assertEqual([entry['path'] for entry in manifest['files']], ['a.txt', 'b.txt'])
        self.assertTrue(kit.verify(self.root, manifest)['ok'])

    def test_verify_reports_changed_entry_without_reordering_or_rehashing(self):
        manifest = kit.generate(self.root, ['a.txt', 'b.txt'])
        with patch.object(kit, 'digest', side_effect=self.mutate_after_first('append')) as digest:
            report = kit.verify(self.root, manifest)
        self.assertTrue(self.changed)
        self.assertFalse(report['ok'])
        self.assertEqual(digest.call_count, 2)
        self.assertEqual([(item['path'], item['status']) for item in report['files']],
                         [('a.txt', 'error'), ('b.txt', 'match')])
        self.assertIn('Evidence changed before operation completion', report['files'][0]['detail'])

    def test_verify_reports_previously_hashed_file_removed(self):
        manifest = kit.generate(self.root, ['a.txt', 'b.txt'])

        def remove(*args, **kwargs):
            result = self.real_digest(*args, **kwargs)
            if kwargs['name'] == 'a.txt':
                self.first.unlink()
                self.changed = True
            return result

        with patch.object(kit, 'digest', side_effect=remove):
            report = kit.verify(self.root, manifest)
        self.assertTrue(self.changed)
        self.assertFalse(self.first.exists())
        self.assertFalse(report['ok'])
        self.assertEqual([(item['path'], item['status']) for item in report['files']],
                         [('a.txt', 'error'), ('b.txt', 'match')])

    def test_create_reports_previously_hashed_file_removed(self):
        def remove(*args, **kwargs):
            result = self.real_digest(*args, **kwargs)
            if kwargs['name'] == 'a.txt':
                self.first.unlink()
                self.changed = True
            return result

        with patch.object(kit, 'digest', side_effect=remove):
            with self.assertRaises(FileNotFoundError):
                kit.generate(self.root, ['a.txt', 'b.txt'])
        self.assertTrue(self.changed)
        self.assertFalse(self.first.exists())
