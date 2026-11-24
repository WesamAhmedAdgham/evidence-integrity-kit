"""Synthetic installation-report regressions; no package downloads."""
import copy
import tempfile
import unittest
from pathlib import Path

from tools.verify_signing_environment import load_lock, verify_report


class SigningReportTests(unittest.TestCase):
    def setUp(self):
        self.pins = {'example': ('1.2', {'a' * 64})}
        self.report = {'version': '1', 'install': [{
            'metadata': {'name': 'example', 'version': '1.2'},
            'download_info': {
                'url': 'https://files.pythonhosted.org/packages/example-1.2-py3-none-any.whl',
                'archive_info': {'hashes': {'sha256': 'a' * 64}},
            },
        }]}

    def test_locked_wheel_report(self):
        self.assertEqual(verify_report(self.report, self.pins)['example'],
                         {'version': '1.2', 'wheel': 'example-1.2-py3-none-any.whl',
                          'sha256': 'a' * 64})

    def test_unapproved_hash_version_and_source(self):
        for change in ('hash', 'version', 'host', 'sdist', 'http'):
            with self.subTest(change=change):
                report = copy.deepcopy(self.report)
                item = report['install'][0]
                if change == 'hash':
                    item['download_info']['archive_info']['hashes']['sha256'] = 'b' * 64
                elif change == 'version':
                    item['metadata']['version'] = '1.3'
                elif change == 'host':
                    item['download_info']['url'] = 'https://other.example/example.whl'
                elif change == 'sdist':
                    item['download_info']['url'] = 'https://files.pythonhosted.org/example.tar.gz'
                else:
                    item['download_info']['url'] = 'http://files.pythonhosted.org/example.whl'
                with self.assertRaises(ValueError):
                    verify_report(report, self.pins)

    def test_missing_duplicate_and_extra_dependencies(self):
        for install in ([], self.report['install'] * 2,
                        self.report['install'] + [{'metadata': {'name': 'other', 'version': '1'}}]):
            with self.subTest(install=install), self.assertRaises(ValueError):
                verify_report({'version': '1', 'install': install}, self.pins)

    def test_committed_lock_matches_expected_packages(self):
        root = Path(__file__).resolve().parents[1]
        pins = load_lock(root / 'requirements-signing.txt')
        self.assertEqual(set(pins), {'cryptography', 'cffi', 'pycparser', 'pynacl'})
        self.assertEqual(sum(len(entry[1]) for entry in pins.values()), 13)

    def test_malformed_or_duplicate_lock_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'lock.txt'
            line = 'example==1.2 --hash=sha256:' + 'a' * 64
            for raw in (line + '\n' + line, line + '\n--extra-index-url https://other.example',
                        'example>=1.2', ''):
                with self.subTest(raw=raw):
                    path.write_text(raw, encoding='utf-8')
                    with self.assertRaises(ValueError):
                        load_lock(path)


if __name__ == '__main__':
    unittest.main()
