"""Verify explicitly listed evidence files against SHA-256 manifests."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HEX = re.compile(r'[0-9a-f]{64}')
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


# Use a conservative portable subset of Windows and POSIX filenames.
WINDOWS_DEVICES = frozenset({'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'} |
                            {prefix + digit for prefix in ('COM', 'LPT')
                             for digit in '123456789¹²³'})


def validate_relative_path(name):
    if not isinstance(name, str) or not name:
        raise ValueError('Invalid relative path')
    parts = name.split('/')
    for part in parts:
        if (part in ('', '.', '..') or part.endswith(('.', ' ')) or
                any(c in '<>:"\\|?*' or ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF
                    for c in part) or
                part.split('.', 1)[0].rstrip(' ').upper() in WINDOWS_DEVICES):
            raise ValueError(f'Invalid portable relative path: {name!r}')
    return parts


def evidence_path(root, name):
    parts = validate_relative_path(name)
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
            raise ValueError(f'Link not permitted: {name!r}')
    if not path.resolve().is_relative_to(root) or not path.is_file():
        raise ValueError(f'Not a regular evidence file: {name!r}')
    return path


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def generate(root, names):
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or not names:
        raise ValueError('A directory and unique file paths are required')
    for name in names:
        validate_relative_path(name)
    if len(set(names)) != len(names):
        raise ValueError('A directory and unique file paths are required')
    return {'version': 1, 'algorithm': 'sha256', 'files': [
        {'path': name, 'sha256': digest(evidence_path(root, name))}
        for name in sorted(names)]}


def verify(root, manifest):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Evidence root must be a directory')
    if not isinstance(manifest, dict) or type(manifest.get('version')) is not int or manifest['version'] != 1 or manifest.get('algorithm') != 'sha256':
        raise ValueError('Unsupported manifest format')
    entries = manifest.get('files')
    if not isinstance(entries, list) or not entries:
        raise ValueError('Manifest must contain at least one file')
    seen = set()
    # Validate every entry before touching any evidence file.
    validated = []
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str) or not isinstance(item.get('sha256'), str) or not HEX.fullmatch(item['sha256']):
            raise ValueError('Invalid manifest entry')
        name = item['path']
        validate_relative_path(name)
        if name in seen:
            raise ValueError(f'Duplicate path: {name!r}')
        seen.add(name)
        validated.append((name, item['sha256']))
    results = []
    for name, expected_digest in validated:
        try:
            status = 'match' if digest(evidence_path(root, name)) == expected_digest else 'mismatch'
        except (OSError, ValueError) as exc:
            results.append({'path': name, 'status': 'error', 'detail': str(exc)})
        else:
            results.append({'path': name, 'status': status})
    return {'ok': all(r['status'] == 'match' for r in results), 'files': results}


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate JSON key: {key!r}')
        result[key] = value
    return result


def reject_nonfinite_constant(value):
    raise ValueError(f'Non-standard JSON constant: {value}')


def load_manifest(path):
    if not path.is_file():
        raise ValueError('Manifest must be a regular file')
    with path.open('rb') as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError(f'Manifest exceeds {MAX_MANIFEST_BYTES} byte limit')
    try:
        return json.loads(raw.decode('utf-8'),
                          object_pairs_hook=reject_duplicate_keys,
                          parse_constant=reject_nonfinite_constant)
    except RecursionError as exc:
        raise ValueError('Manifest JSON nesting exceeds decoder limit') from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create', help='Print a manifest for explicit file paths')
    create.add_argument('--root', required=True, type=Path)
    create.add_argument('files', nargs='+')
    check = commands.add_parser('verify', help='Compare evidence against a manifest')
    check.add_argument('--root', required=True, type=Path)
    check.add_argument('--manifest', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'create':
            result = generate(args.root, args.files)
            code = 0
        else:
            result = verify(args.root, load_manifest(args.manifest))
            code = 0 if result['ok'] else 1
        output = json.dumps(result, indent=2, ensure_ascii=True)
        # ASCII serialization; allow for CRLF translation on Windows, including the final newline.
        if args.command == 'create' and len(output) + output.count('\n') + 2 > MAX_MANIFEST_BYTES:
            raise ValueError(f'Generated manifest exceeds {MAX_MANIFEST_BYTES} byte limit; split the file list')
        print(output)
        return code
    except (OSError, ValueError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
