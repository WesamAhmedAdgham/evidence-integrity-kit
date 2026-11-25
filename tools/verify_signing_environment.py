"""CI-only verification of the exact hash-locked signing installation.

This records supply-chain evidence; it is not a vulnerability scanner or an
independent attestation. Runtime CLI operations do not use this script.
"""
import argparse
import importlib.metadata
import json
import platform
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


def load_lock(path):
    lines = [line.strip().rstrip('\\') for line in path.read_text(encoding='utf-8').splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    raw = ' '.join(lines)
    pattern = re.compile(r'([a-zA-Z0-9_-]+)==([0-9.]+)((?:\s+--hash=sha256:[0-9a-f]{64})+)')
    pins = {}
    for match in pattern.finditer(raw):
        name, version, hashes = match.groups()
        name = name.lower()
        if name in pins:
            raise ValueError('Duplicate dependency pin')
        pins[name] = (version, set(re.findall(r'--hash=sha256:([0-9a-f]{64})', hashes)))
    if pattern.sub('', raw).strip() or not pins:
        raise ValueError('Unsupported lock format')
    return pins


def verify_report(report, pins):
    if report.get('version') != '1' or not isinstance(report.get('install'), list):
        raise ValueError('Unsupported pip installation report')
    observed = {}
    for item in report['install']:
        meta = item['metadata']
        name = meta['name'].lower()
        version = meta['version']
        if name not in pins or name in observed or version != pins[name][0]:
            raise ValueError('Unexpected dependency or version in pip report')
        source = item['download_info']
        url = urlsplit(source['url'])
        filename = unquote(url.path.rsplit('/', 1)[-1])
        digest = source['archive_info']['hashes']['sha256']
        if (url.scheme != 'https' or url.netloc != 'files.pythonhosted.org' or
                url.query or url.fragment or not filename.endswith('.whl') or
                digest not in pins[name][1]):
            raise ValueError('Unexpected wheel source or SHA-256 in pip report')
        observed[name] = {'version': version, 'wheel': filename, 'sha256': digest}
    if set(observed) != set(pins):
        raise ValueError('Missing dependency in pip installation report')
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--lock', required=True, type=Path)
    args = parser.parse_args()
    pins = load_lock(args.lock)
    observed = verify_report(json.loads(args.report.read_text(encoding='utf-8')), pins)
    for name, (version, _) in pins.items():
        if importlib.metadata.version(name) != version:
            raise ValueError('Installed distribution version does not match lock')
    from cryptography.hazmat.backends.openssl.backend import backend
    print(json.dumps({
        'python': platform.python_version(),
        'platform': platform.system(),
        'machine': platform.machine(),
        'cryptography_openssl': backend.openssl_version_text(),
        'wheels': observed,
    }, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
