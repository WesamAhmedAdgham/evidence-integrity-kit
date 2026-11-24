"""Check the committed dependency allowlist without fetching anything."""
import re
import unittest
from pathlib import Path


class DependencyLockTests(unittest.TestCase):
    def test_exact_pins_and_wheel_hash_allowlist(self):
        root = Path(__file__).resolve().parents[1]
        lines = [line for line in (root / 'requirements-signing.txt').read_text().splitlines()
                 if line.strip() and not line.startswith('#')]
        requirements = ' '.join(line.strip().rstrip('\\') for line in lines)
        pattern = re.compile(r'(\w+)==([\d.]+)((?:\s+--hash=sha256:[0-9a-f]{64})+)')
        matches = list(pattern.finditer(requirements))
        self.assertEqual([(m[1], m[2]) for m in matches],
                         [('cryptography', '50.0.2'), ('cffi', '2.1.1'), ('pycparser', '3.0')])
        counts = [len(re.findall(r'--hash=sha256:[0-9a-f]{64}', m[3])) for m in matches]
        self.assertEqual(counts, [3, 6, 1])
        hashes = re.findall(r'--hash=sha256:([0-9a-f]{64})', requirements)
        self.assertEqual(len(set(hashes)), 10)
        self.assertEqual(pattern.sub('', requirements).strip(), '')
        workflow = (root / '.github' / 'workflows' / 'tests.yml').read_text()
        self.assertIn('--require-hashes', workflow)
        self.assertIn('--only-binary=:all:', workflow)
        self.assertIn('--force-reinstall', workflow)
