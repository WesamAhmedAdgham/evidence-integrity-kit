"""Exercise optional-provider failure without installing or importing crypto."""
import subprocess
import sys
import unittest
from pathlib import Path


class OptionalCryptoTests(unittest.TestCase):
    def test_provider_missing_fails_closed(self):
        script = '''
import sys
import manifest_signatures as sig
assert 'cryptography' not in sys.modules
sys.modules['cryptography'] = None
for operation in (
    lambda: sig.sign_manifest_bytes(b'{}', None),
    lambda: sig.verify_manifest_signature(b'{}', b'0' * 128, None),
):
    try:
        operation()
    except ValueError as exc:
        assert 'provider unavailable' in str(exc), str(exc)
    else:
        raise AssertionError('missing provider accepted')
'''
        result = subprocess.run([sys.executable, '-S', '-c', script],
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, repr(result.stdout + result.stderr))
