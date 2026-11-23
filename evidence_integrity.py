"""Verify explicitly listed evidence files against SHA-256 manifests."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

HEX = re.compile(r'[0-9a-f]{64}')


def evidence_path(root, name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name or '\x00' in name:
        raise ValueError('Invalid relative path')
    parts = name.split('/')
    if any(p in ('', '.', '..') for p in parts):
        raise ValueError(f'Invalid relative path: {name!r}')
    path = root
    for part in PurePosixPath(name).parts:
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
    if not root.is_dir() or not names or len(set(names)) != len(names):
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
    results = []
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str) or not isinstance(item.get('sha256'), str) or not HEX.fullmatch(item['sha256']):
            raise ValueError('Invalid manifest entry')
        name = item['path']
        if name in seen:
            raise ValueError(f'Duplicate path: {name!r}')
        seen.add(name)
        try:
            status = 'match' if digest(evidence_path(root, name)) == item['sha256'] else 'mismatch'
        except (OSError, ValueError) as exc:
            results.append({'path': name, 'status': 'error', 'detail': str(exc)})
        else:
            results.append({'path': name, 'status': status})
    return {'ok': all(r['status'] == 'match' for r in results), 'files': results}


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
            result = verify(args.root, json.loads(args.manifest.read_text(encoding='utf-8')))
            code = 0 if result['ok'] else 1
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return code
    except (OSError, ValueError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
