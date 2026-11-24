"""Verify explicitly listed evidence files against SHA-256 manifests."""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from contextlib import contextmanager
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


def check_path_collisions(name, prefixes):
    node = prefixes
    for part in validate_relative_path(name):
        normalized = unicodedata.normalize('NFC', part)
        key = unicodedata.normalize('NFC', normalized.casefold())
        previous, children = node.setdefault(key, (part, {}))
        if previous != part:
            raise ValueError(f'Portable path collision in {name!r}: {previous!r} and {part!r}')
        node = children


def evidence_path(root, name):
    parts = validate_relative_path(name)
    path = root
    for part in parts:
        path = path / part
        metadata = path.lstat()
        if (stat.S_ISLNK(metadata.st_mode) or
                getattr(metadata, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError(f'Link not permitted: {name!r}')
    if not path.resolve().is_relative_to(root) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f'Not a regular evidence file: {name!r}')
    if metadata.st_nlink != 1:
        raise ValueError(f'Evidence file must have exactly one hard link: {name!r}')
    return path, metadata


def check_root_identity(root, root_fd):
    if os.name == 'nt':
        from windows_root import check_windows_root
        check_windows_root(root, root_fd)
        return
    if root_fd is None:
        return
    expected = os.fstat(root_fd)
    current = root.lstat()
    if (not stat.S_ISDIR(current.st_mode) or not expected.st_ino or
            not current.st_ino or not os.path.samestat(expected, current)):
        raise ValueError('Evidence root identity changed or unavailable')


@contextmanager
def pinned_root(root):
    if os.name == 'nt':
        from windows_root import pinned_windows_root
        with pinned_windows_root(root) as guard:
            yield guard
        return
    if os.name != 'posix':
        yield None
        return
    if (os.open not in os.supports_dir_fd or
            not all(hasattr(os, flag) for flag in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK'))):
        raise ValueError('Secure relative evidence opening unavailable on this POSIX platform')
    expected = root.lstat()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if not expected.st_ino or not opened.st_ino or not os.path.samestat(expected, opened):
            raise ValueError('Evidence root identity changed or unavailable')
        check_root_identity(root, fd)
        yield fd
        check_root_identity(root, fd)
    finally:
        os.close(fd)


def open_evidence(path, *, root=None, name=None, root_fd=None):
    if os.name == 'posix':
        if root is not None:
            if root_fd is None:
                raise ValueError('Evidence root descriptor required')
            check_root_identity(root, root_fd)
            parts = validate_relative_path(name)
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            fd = os.dup(root_fd)
            try:
                for part in parts[:-1]:
                    next_fd = os.open(part, directory_flags, dir_fd=fd)
                    os.close(fd)
                    fd = next_fd
                return open(parts[-1], 'rb', opener=lambda leaf, flags: os.open(
                    leaf, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd))
            finally:
                os.close(fd)
        # A substituted manifest FIFO must not block before descriptor validation.
        return open(path, 'rb', opener=lambda name, flags: os.open(name, flags | os.O_NONBLOCK))
    if os.name == 'nt' and root is not None:
        from windows_root import guarded_windows_file
        check_root_identity(root, root_fd)
        return guarded_windows_file(root, validate_relative_path(name), root_fd)
    return path.open('rb')


def content_metadata_changed(first, second):
    # Compare only size and mtime across pathname and descriptor samples;
    # other stat fields may have platform-dependent representations.
    return (first.st_size, first.st_mtime_ns) != (second.st_size, second.st_mtime_ns)


def digest(path, expected, *, root, name, root_fd):
    with open_evidence(path, root=root, name=name, root_fd=root_fd) as stream:
        before = os.fstat(stream.fileno())
        if not expected.st_ino or not before.st_ino or not os.path.samestat(expected, before):
            raise ValueError(f'Evidence identity changed or unavailable: {path.name!r}')
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f'Opened evidence is not a regular single-link file: {path.name!r}')
        if content_metadata_changed(expected, before):
            raise ValueError(f'Evidence changed before hashing: {name!r}')
        result = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        fields = ('st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError(f'Evidence changed during hashing: {path.name!r}')
        check_root_identity(root, root_fd)
        _, current = evidence_path(root, name)
        if not current.st_ino or not os.path.samestat(after, current):
            raise ValueError(f'Evidence path changed during hashing: {name!r}')
        if content_metadata_changed(after, current):
            raise ValueError(f'Evidence changed after hashing: {name!r}')
        return result


def revalidate_processed_file(root, name, expected, root_fd):
    """Compare pathname samples without reopening file contents."""
    check_root_identity(root, root_fd)
    _, current = evidence_path(root, name)
    fields = ('st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if (not expected.st_ino or not current.st_ino or
            not os.path.samestat(expected, current) or
            any(getattr(expected, field) != getattr(current, field) for field in fields)):
        raise ValueError(f'Evidence changed before operation completion: {name!r}')


def generate(root, names):
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or not names:
        raise ValueError('A directory and unique file paths are required')
    prefixes = {}
    for name in names:
        check_path_collisions(name, prefixes)
    if len(set(names)) != len(names):
        raise ValueError('A directory and unique file paths are required')
    files = []
    processed = []
    with pinned_root(root) as root_fd:
        for name in sorted(names):
            check_root_identity(root, root_fd)
            path, expected = evidence_path(root, name)
            value = digest(path, expected, root=root, name=name, root_fd=root_fd)
            files.append({'path': name, 'sha256': value})
            processed.append((name, expected))
        for name, expected in processed:
            revalidate_processed_file(root, name, expected, root_fd)
    return {'version': 1, 'algorithm': 'sha256', 'files': files}


def validate_manifest(manifest, *, strict=False):
    """Validate the schema without accessing the evidence filesystem."""
    if not isinstance(manifest, dict) or type(manifest.get('version')) is not int or manifest['version'] != 1 or manifest.get('algorithm') != 'sha256':
        raise ValueError('Unsupported manifest format')
    if strict and set(manifest) != {'version', 'algorithm', 'files'}:
        raise ValueError('Unexpected signed manifest fields')
    entries = manifest.get('files')
    if not isinstance(entries, list) or not entries:
        raise ValueError('Manifest must contain at least one file')
    seen = set()
    prefixes = {}
    # Validate every entry before touching any evidence file.
    validated = []
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str) or not isinstance(item.get('sha256'), str) or not HEX.fullmatch(item['sha256']):
            raise ValueError('Invalid manifest entry')
        if strict and set(item) != {'path', 'sha256'}:
            raise ValueError('Unexpected signed manifest entry fields')
        name = item['path']
        check_path_collisions(name, prefixes)
        if name in seen:
            raise ValueError(f'Duplicate path: {name!r}')
        seen.add(name)
        validated.append((name, item['sha256']))
    return validated


def verify(root, manifest):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Evidence root must be a directory')
    validated = validate_manifest(manifest)
    results = []
    processed = []
    with pinned_root(root) as root_fd:
        for name, expected_digest in validated:
            check_root_identity(root, root_fd)
            try:
                path, expected = evidence_path(root, name)
                value = digest(path, expected, root=root, name=name, root_fd=root_fd)
                status = 'match' if value == expected_digest else 'mismatch'
            except (OSError, ValueError) as exc:
                results.append({'path': name, 'status': 'error', 'detail': str(exc)})
            else:
                if status == 'match':
                    processed.append((len(results), name, expected))
                results.append({'path': name, 'status': status})
        for index, name, expected in processed:
            try:
                revalidate_processed_file(root, name, expected, root_fd)
            except (OSError, ValueError) as exc:
                results[index] = {'path': name, 'status': 'error', 'detail': str(exc)}
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


def read_control_bytes(path, *, limit, label):
    """Read bounded binary control input with sampled identity/stability checks."""
    if type(limit) is not int or limit < 0:
        raise ValueError('Invalid control input byte limit')
    expected = path.stat()
    if not stat.S_ISREG(expected.st_mode):
        raise ValueError(f'{label} must be a regular file')
    with open_evidence(path) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f'{label} must be a regular file')
        if not expected.st_ino or not before.st_ino or not os.path.samestat(expected, before):
            raise ValueError(f'{label} identity changed or unavailable')
        if content_metadata_changed(expected, before):
            raise ValueError(f'{label} changed before reading')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError(f'{label} changed during reading')
        current = path.stat()
        if not current.st_ino or not os.path.samestat(after, current):
            raise ValueError(f'{label} path changed during reading')
        if content_metadata_changed(after, current):
            raise ValueError(f'{label} changed after reading')
    if len(raw) > limit:
        raise ValueError(f'{label} exceeds {limit} byte limit')
    return raw


def read_manifest_bytes(path):
    return read_control_bytes(path, limit=MAX_MANIFEST_BYTES, label='Manifest')


def decode_manifest(raw):
    """Parse only the supplied immutable bytes; never reopen a pathname."""
    if not isinstance(raw, bytes):
        raise ValueError('Manifest input must be bytes')
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError(f'Manifest exceeds {MAX_MANIFEST_BYTES} byte limit')
    try:
        return json.loads(raw.decode('utf-8'),
                          object_pairs_hook=reject_duplicate_keys,
                          parse_constant=reject_nonfinite_constant)
    except RecursionError as exc:
        raise ValueError('Manifest JSON nesting exceeds decoder limit') from exc



def load_manifest(path):
    return decode_manifest(read_manifest_bytes(path))

def sign_manifest_file(manifest_path, private_key_path):
    from manifest_signatures import sign_manifest_bytes
    from signing_keys import read_private_key

    raw = read_manifest_bytes(manifest_path)
    validate_manifest(decode_manifest(raw), strict=True)
    key = read_private_key(private_key_path)
    return sign_manifest_bytes(raw, key)


def verify_signed(root, manifest_path, signature_path, public_key_path):
    from manifest_signatures import MAX_SIGNATURE_FILE_BYTES, verify_manifest_signature
    from signing_keys import read_public_key, public_key_fingerprint

    raw = read_manifest_bytes(manifest_path)
    signature = read_control_bytes(signature_path, limit=MAX_SIGNATURE_FILE_BYTES,
                                   label='Signature')
    key = read_public_key(public_key_path)
    verify_manifest_signature(raw, signature, key)
    manifest = decode_manifest(raw)
    validate_manifest(manifest, strict=True)
    fingerprint = public_key_fingerprint(key)
    result = verify(root, manifest)
    result['authentication'] = {
        'protocol': 'evidence-integrity-kit-ed25519-v1',
        'verified': True,
        'public_key_sha256': fingerprint,
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create', help='Print a manifest for explicit file paths')
    create.add_argument('--root', required=True, type=Path)
    create.add_argument('files', nargs='+')
    check = commands.add_parser('verify', help='Compare evidence against a manifest')
    check.add_argument('--root', required=True, type=Path)
    check.add_argument('--manifest', required=True, type=Path)
    sign = commands.add_parser('sign', help='Sign validated manifest bytes with an encrypted Ed25519 key')
    sign.add_argument('--manifest', required=True, type=Path)
    sign.add_argument('--private-key', required=True, type=Path)
    signed = commands.add_parser('verify-signed', help='Authenticate a manifest before checking evidence')
    signed.add_argument('--root', required=True, type=Path)
    signed.add_argument('--manifest', required=True, type=Path)
    signed.add_argument('--signature', required=True, type=Path)
    signed.add_argument('--public-key', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'create':
            result = generate(args.root, args.files)
            code = 0
        elif args.command == 'sign':
            signature = sign_manifest_file(args.manifest, args.private_key)
            print(signature.decode('ascii'), end='')
            return 0
        elif args.command == 'verify-signed':
            result = verify_signed(args.root, args.manifest, args.signature, args.public_key)
            code = 0 if result['ok'] else 1
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
