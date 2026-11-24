"""Diagnostic evidence collection, not a dependency approval or runtime feature."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import quote, urlsplit
from urllib.request import urlopen
from urllib.error import HTTPError

from tools.verify_signing_environment import load_lock

REPOSITORIES = {
    'cryptography': 'https://github.com/pyca/cryptography',
    'pynacl': 'https://github.com/pyca/pynacl',
}
MAX_METADATA = 8 * 1024 * 1024
MAX_WHEEL = 32 * 1024 * 1024


def fetch(url, host, limit):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.netloc != host:
        raise ValueError('Unexpected URL origin')
    with urlopen(url, timeout=45) as response:
        final = urlsplit(response.geturl())
        if final.scheme != 'https' or final.netloc != host:
            raise ValueError('Unexpected redirect origin')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Response exceeds diagnostic bound')
    return data


def select_wheels(metadata, hashes):
    rows = [row for row in metadata['urls']
            if row.get('digests', {}).get('sha256') in hashes]
    if len(rows) != len(hashes) or {r['digests']['sha256'] for r in rows} != hashes:
        raise ValueError('Lock does not map one-to-one to published files')
    for row in rows:
        filename = row['filename']
        if (row['packagetype'] != 'bdist_wheel' or row.get('yanked')
                or not filename.endswith('.whl') or Path(filename).name != filename
                or '/' in filename or '\\' in filename):
            raise ValueError('Unexpected artifact type/name or yanked file')
    return sorted(rows, key=lambda row: row['filename'])


def main():
    pins = load_lock(Path('evaluation/requirements-validator.txt'))
    records = []
    failed = False
    with tempfile.TemporaryDirectory(prefix='eik-provenance-') as temp:
        for name, (version, hashes) in sorted(pins.items()):
            metadata = json.loads(fetch(
                f'https://pypi.org/pypi/{name}/{version}/json', 'pypi.org', MAX_METADATA))
            for row in select_wheels(metadata, hashes):
                filename = row['filename']
                digest = row['digests']['sha256']
                data = fetch(row['url'], 'files.pythonhosted.org', MAX_WHEEL)
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError('Downloaded artifact does not match lock')
                path = Path(temp) / filename
                path.write_bytes(data)
                rec = {'package': name, 'version': version, 'filename': filename,
                       'sha256': digest, 'byte_digest_verified': True,
                       'expected_repository': REPOSITORIES.get(name),
                       'publisher_verified': False}
                url = f'https://pypi.org/integrity/{name}/{version}/{quote(filename, safe="")}/provenance'
                try:
                    provenance = json.loads(fetch(url, 'pypi.org', MAX_METADATA))
                except HTTPError as exc:
                    if exc.code != 404:
                        raise
                    rec['status'] = 'missing_attestation'
                    failed = True
                else:
                    rec['provenance_bundle_count'] = len(provenance.get('attestation_bundles', []))
                    if name not in REPOSITORIES:
                        rec['status'] = 'expected_publisher_not_configured'
                        failed = True
                    else:
                        # Official CLI checks the downloaded local artifact against
                        # PyPI provenance with an independently selected repository.
                        result = subprocess.run(
                            [sys.executable, '-m', 'pypi_attestations', 'verify', 'pypi',
                             '--repository', REPOSITORIES[name], str(path)],
                            capture_output=True, text=True, timeout=120, check=False)
                        rec['verifier_exit_code'] = result.returncode
                        rec['publisher_verified'] = result.returncode == 0
                        rec['status'] = 'diagnostic_verified' if result.returncode == 0 else 'verification_failed'
                        failed |= result.returncode != 0
                        print(result.stdout, result.stderr, flush=True)
                print(json.dumps(rec, sort_keys=True), flush=True)
                records.append(rec)
    if len(records) != sum(len(hashes) for _, hashes in pins.values()):
        raise ValueError('Incomplete artifact inventory')
    print(json.dumps({'artifacts': len(records),
                      'diagnostic_verified': sum(r['publisher_verified'] for r in records),
                      'missing_attestations': sum(r['status'] == 'missing_attestation' for r in records),
                      'release_approval': False}, sort_keys=True))
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
