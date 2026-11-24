"""Actual signed CLI roundtrip on a provisioned native snapshot."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evidence_integrity as kit
from manifest_signatures import sign_manifest_bytes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

flag, value, root = sys.argv[1:]
root = Path(root)
kwargs = {'snapshot_uuid': value} if flag == '--linux-btrfs-snapshot' else {'apfs_source': value}
cli = Path(kit.__file__).resolve()
with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    raw = json.dumps(kit.generate(root, ['nested/a', 'b'], **kwargs)).encode('ascii')
    manifest, signature, public = (base / 'manifest.json', base / 'manifest.sig', base / 'key.pem')
    key = ed25519.Ed25519PrivateKey.generate()
    manifest.write_bytes(raw)
    signature.write_bytes(sign_manifest_bytes(raw, key))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo))
    args = [sys.executable, str(cli), 'verify-signed', '--root', str(root),
            '--manifest', str(manifest), '--signature', str(signature), '--public-key', str(public),
            flag, value]
    valid = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if valid.returncode != 0:
        raise AssertionError(valid.stderr)
    report = json.loads(valid.stdout)
    if not report['ok'] or not report['authentication']['verified'] or report['protection']['mode'] != flag[2:]:
        raise AssertionError('Native signed protection report mismatch')
    manifest.write_bytes(raw + b' ')
    invalid = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if invalid.returncode != 2 or invalid.stdout or 'signature invalid' not in invalid.stderr:
        raise AssertionError('Changed signed manifest not rejected')
print('Native signed snapshot CLI: valid and tampered manifest PASS')
