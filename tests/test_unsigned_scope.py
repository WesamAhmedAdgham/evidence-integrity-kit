"""Verify the unsigned distribution does not expose signing operations."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class UnsignedScopeTests(unittest.TestCase):
    def test_no_signing_modules_or_dependency_lock(self):
        for name in ('manifest_signatures.py', 'signing_keys.py', 'requirements-signing.txt',
                     'tests_crypto', 'linux_snapshot.py', 'macos_snapshot.py'):
            self.assertFalse((ROOT / name).exists(), name)

    def test_cli_works_without_site_packages_and_rejects_signing(self):
        cli = ROOT / 'evidence_integrity.py'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'a').write_bytes(b'synthetic')
            args = [sys.executable, '-S', str(cli)]
            created = subprocess.run(args + ['create', '--root', td, 'a'],
                                     capture_output=True, timeout=15)
            self.assertEqual(created.returncode, 0, created.stderr)
            manifest = root / 'manifest.json'
            manifest.write_bytes(created.stdout)
            verified = subprocess.run(args + ['verify', '--root', td, '--manifest', str(manifest)],
                                      capture_output=True, timeout=15)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertTrue(json.loads(verified.stdout)['ok'])
            for command in ('sign', 'verify-signed'):
                rejected = subprocess.run(args + [command], capture_output=True, timeout=15)
                self.assertEqual(rejected.returncode, 2)
                self.assertEqual(rejected.stdout, b'')
