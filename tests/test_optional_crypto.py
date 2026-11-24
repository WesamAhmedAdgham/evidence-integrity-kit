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

    def test_unsigned_cli_works_without_crypto_and_signed_cli_fails_closed(self):
        script = '''
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
import evidence_integrity as kit

sys.modules['cryptography'] = None
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    (root / 'a.txt').write_bytes(b'synthetic')
    manifest = root / 'manifest.json'
    manifest.write_text(json.dumps(kit.generate(root, ['a.txt'])), encoding='utf-8')
    signature = root / 'manifest.sig'
    signature.write_bytes(b'0' * 128)
    public = root / 'public.pem'
    # Public RFC 8032 test key SPKI; no secret material.
    import base64
    der = bytes.fromhex('302a300506032b6570032100' +
                        'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
    public.write_bytes(b'-----BEGIN PUBLIC KEY-----\\n' + base64.b64encode(der) +
                       b'\\n-----END PUBLIC KEY-----\\n')
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        assert kit.main(['verify', '--assume-stable-tree', '--root', str(root), '--manifest', str(manifest)]) == 0
    assert json.loads(out.getvalue())['ok']
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        assert kit.main(['verify-signed', '--assume-stable-tree', '--root', str(root), '--manifest', str(manifest),
                         '--signature', str(signature), '--public-key', str(public)]) == 2
    assert not out.getvalue()
    assert 'provider unavailable' in err.getvalue(), err.getvalue()
'''
        result = subprocess.run([sys.executable, '-S', '-c', script],
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, repr(result.stdout + result.stderr))
