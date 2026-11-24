"""Verify explicitly listed evidence files against SHA-256 manifests."""
import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import unicodedata
from contextlib import ExitStack, contextmanager
from pathlib import Path

HEX = re.compile(r'[0-9a-f]{64}')
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PATH_COMPONENTS = 128
MAX_ENTRIES = 10000
MAX_TOTAL_COMPONENTS = 32768
MAX_TOTAL_PATH_CHARS = 262144


# Use a conservative portable subset of Windows and POSIX filenames.
WINDOWS_DEVICES = frozenset({'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'} |
                            {prefix + digit for prefix in ('COM', 'LPT')
                             for digit in '123456789¹²³'})


def validate_relative_path(name):
    if not isinstance(name, str) or not name:
        raise ValueError('Invalid relative path')
    # Bound traversal descriptors and trie depth before opening evidence.
    if name.count('/') >= MAX_PATH_COMPONENTS:
        raise ValueError('Evidence path exceeds component limit')
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
        # None is a terminal marker; normalized component keys are always strings.
        if None in node:
            raise ValueError(f'Portable path collision: file is also a directory in {name!r}')
        normalized = unicodedata.normalize('NFC', part)
        key = unicodedata.normalize('NFC', normalized.casefold())
        previous, children = node.setdefault(key, (part, {}))
        if previous != part:
            raise ValueError(f'Portable path collision in {name!r}: {previous!r} and {part!r}')
        node = children
    if node and None not in node:
        raise ValueError(f'Portable path collision: file is also a directory in {name!r}')
    node[None] = True


def resolve_path(path, *, strict=False):
    # Python 3.11/3.12 can raise RuntimeError for symbolic-link loops;
    # newer Python versions report an OSError or return a non-strict path.
    try:
        return path.resolve(strict=strict)
    except RuntimeError as exc:
        raise ValueError('Unable to resolve path') from exc


def evidence_path(root, name):
    parts = validate_relative_path(name)
    path = root
    for part in parts:
        path = path / part
        metadata = path.lstat()
        if (stat.S_ISLNK(metadata.st_mode) or
                getattr(metadata, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError(f'Link not permitted: {name!r}')
    if not resolve_path(path).is_relative_to(root) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f'Not a regular evidence file: {name!r}')
    if metadata.st_nlink != 1:
        raise ValueError(f'Evidence file must have exactly one hard link: {name!r}')
    return path, metadata


def sample_directory_chain(root, name):
    """Sample every descendant directory identity, excluding the separately pinned root."""
    path = root
    identities = []
    for part in validate_relative_path(name)[:-1]:
        path = path / part
        metadata = path.lstat()
        if (stat.S_ISLNK(metadata.st_mode) or
                getattr(metadata, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError(f'Link not permitted: {name!r}')
        if not stat.S_ISDIR(metadata.st_mode) or not metadata.st_ino:
            raise ValueError(f'Evidence directory identity unavailable or invalid: {name!r}')
        identities.append((metadata.st_dev, metadata.st_ino))
    return tuple(identities)


def check_directory_chain(root, name, expected):
    if sample_directory_chain(root, name) != expected:
        raise ValueError(f'Evidence path changed: directory identity changed: {name!r}')


def check_root_identity(root, root_fd):
    if os.name == 'nt':
        from windows_root import check_windows_root
        check_windows_root(root, root_fd)
        return
    if root_fd is None:
        raise ValueError('Evidence root descriptor required')
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
        raise ValueError('Secure evidence opening unavailable on this platform')
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


def check_posix_directory_handles(directories):
    for path, fd in directories:
        opened = os.fstat(fd)
        current = path.lstat()
        if (not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(current.st_mode) or
                not opened.st_ino or not current.st_ino or
                not os.path.samestat(opened, current)):
            raise ValueError('Evidence path changed: opened directory identity changed')


def open_evidence(path, *, root=None, name=None, root_fd=None):
    if os.name == 'posix':
        if root is not None:
            if root_fd is None:
                raise ValueError('Evidence root descriptor required')
            check_root_identity(root, root_fd)
            parts = validate_relative_path(name)
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            # Retain all directory descriptors until the leaf is open. Compare
            # the actual opened objects, not just two pathname samples.
            with ExitStack() as stack:
                fd = os.dup(root_fd)
                stack.callback(os.close, fd)
                opened_directories = []
                prefix = root
                for part in parts[:-1]:
                    prefix = prefix / part
                    fd = os.open(part, directory_flags, dir_fd=fd)
                    stack.callback(os.close, fd)
                    opened_directories.append((prefix, fd))
                    check_posix_directory_handles(opened_directories)
                stream = open(parts[-1], 'rb', opener=lambda leaf, flags: os.open(
                    leaf, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd))
                try:
                    check_root_identity(root, root_fd)
                    check_posix_directory_handles(opened_directories)
                except BaseException:
                    stream.close()
                    raise
                return stream
        # A substituted manifest FIFO must not block before descriptor validation.
        return open(path, 'rb', opener=lambda name, flags: os.open(name, flags | os.O_NONBLOCK))
    if os.name == 'nt' and root is not None:
        from windows_root import guarded_windows_file
        check_root_identity(root, root_fd)
        return guarded_windows_file(root, validate_relative_path(name), root_fd)
    if root is not None:
        raise ValueError('Secure evidence opening unavailable on this platform')
    return path.open('rb')


def content_metadata_changed(first, second):
    # Compare only size and mtime across pathname and descriptor samples;
    # other stat fields may have platform-dependent representations.
    return (first.st_size, first.st_mtime_ns) != (second.st_size, second.st_mtime_ns)


class SizedEvidenceReader:
    """Expose only the sampled file size plus one EOF probe to file_digest."""
    def __init__(self, stream, size):
        if type(size) is not int or size < 0:
            raise ValueError('Invalid evidence size')
        self.stream = stream
        self.remaining = size
        self.eof_checked = False

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.remaining == 0:
            extra = self.stream.read(1)
            if extra != b'':
                raise ValueError('Evidence changed during hashing: expected end of file')
            self.eof_checked = True
            return 0
        view = memoryview(buffer)[:min(len(buffer), self.remaining)]
        count = self.stream.readinto(view)
        if type(count) is not int or not 0 < count <= len(view):
            raise ValueError('Evidence changed during hashing: incomplete or invalid read')
        self.remaining -= count
        return count


def register_identity(metadata, name, identities):
    """Reject multiple listed paths resolving to the same sampled file identity."""
    if not metadata.st_ino:
        raise ValueError(f'Evidence identity unavailable: {name!r}')
    identity = (metadata.st_dev, metadata.st_ino)
    previous = identities.get(identity)
    if previous is not None and previous != name:
        raise ValueError(f'Evidence file identity alias: {previous!r} and {name!r}')
    identities[identity] = name


def digest(path, expected, *, root, name, root_fd):
    directories = sample_directory_chain(root, name)
    with open_evidence(path, root=root, name=name, root_fd=root_fd) as stream:
        before = os.fstat(stream.fileno())
        if not expected.st_ino or not before.st_ino or not os.path.samestat(expected, before):
            raise ValueError(f'Evidence identity changed or unavailable: {path.name!r}')
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f'Opened evidence is not a regular single-link file: {path.name!r}')
        if content_metadata_changed(expected, before):
            raise ValueError(f'Evidence changed before hashing: {name!r}')
        check_directory_chain(root, name, directories)
        reader = SizedEvidenceReader(stream, before.st_size)
        result = hashlib.file_digest(reader, 'sha256').hexdigest()
        if reader.remaining or not reader.eof_checked:
            raise ValueError('Evidence changed during hashing: incomplete read')
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
        check_directory_chain(root, name, directories)
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


def check_path_budget(names):
    """Bound aggregate trie and report growth before filesystem access."""
    count = components = chars = 0
    for name in names:
        if not isinstance(name, str):
            raise ValueError('Invalid relative path')
        count += 1
        components += name.count('/') + 1
        chars += len(name)
        if (count > MAX_ENTRIES or components > MAX_TOTAL_COMPONENTS or
                chars > MAX_TOTAL_PATH_CHARS):
            raise ValueError('Evidence path budget exceeded')


def sample_native_change(root, name, expected, root_fd):
    if os.name != 'nt':
        return None
    from windows_root import guarded_windows_file, file_change_time
    # Native no-reparse opening; do not rely on Windows st_ctime.
    with guarded_windows_file(root, validate_relative_path(name), root_fd) as stream:
        opened = os.fstat(stream.fileno())
        if (not opened.st_ino or not os.path.samestat(expected, opened) or
                not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                content_metadata_changed(expected, opened)):
            raise ValueError(f'Evidence changed before operation completion: {name!r}')
        return file_change_time(stream)


def check_native_change(root, name, expected, root_fd, baseline):
    if sample_native_change(root, name, expected, root_fd) != baseline:
        raise ValueError(f'Evidence changed before operation completion: {name!r}')


def generate(root, names):
    if not names:
        raise ValueError('A directory and unique file paths are required')
    check_path_budget(names)
    prefixes = {}
    for name in names:
        check_path_collisions(name, prefixes)
    if len(set(names)) != len(names):
        raise ValueError('A directory and unique file paths are required')
    root = resolve_path(Path(root), strict=True)
    if not root.is_dir():
        raise ValueError('A directory and unique file paths are required')
    files = []
    processed = []
    identities = {}
    with pinned_root(root) as root_fd:
        for name in sorted(names):
            check_root_identity(root, root_fd)
            directories = sample_directory_chain(root, name)
            path, expected = evidence_path(root, name)
            register_identity(expected, name, identities)
            native_change = sample_native_change(root, name, expected, root_fd)
            value = digest(path, expected, root=root, name=name, root_fd=root_fd)
            check_directory_chain(root, name, directories)
            files.append({'path': name, 'sha256': value})
            processed.append((name, expected, directories, native_change))
        for name, expected, directories, native_change in processed:
            revalidate_processed_file(root, name, expected, root_fd)
            check_directory_chain(root, name, directories)
            check_native_change(root, name, expected, root_fd, native_change)
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
    if len(entries) > MAX_ENTRIES:
        raise ValueError('Evidence path budget exceeded')
    # Validate types before the aggregate budget; no trie allocated yet.
    check_path_budget(item.get('path') if isinstance(item, dict) else None for item in entries)
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
    validated = validate_manifest(manifest)
    root = resolve_path(Path(root), strict=True)
    if not root.is_dir():
        raise ValueError('Evidence root must be a directory')
    results = []
    processed = []
    identities = {}
    with pinned_root(root) as root_fd:
        for name, expected_digest in validated:
            check_root_identity(root, root_fd)
            try:
                directories = sample_directory_chain(root, name)
                path, expected = evidence_path(root, name)
                register_identity(expected, name, identities)
                native_change = sample_native_change(root, name, expected, root_fd)
                value = digest(path, expected, root=root, name=name, root_fd=root_fd)
                check_directory_chain(root, name, directories)
                status = 'match' if value == expected_digest else 'mismatch'
            except (OSError, ValueError) as exc:
                results.append({'path': name, 'status': 'error', 'detail': str(exc)})
            else:
                if status == 'match':
                    processed.append((len(results), name, expected, directories, native_change))
                results.append({'path': name, 'status': status})
        for index, name, expected, directories, native_change in processed:
            try:
                revalidate_processed_file(root, name, expected, root_fd)
                check_directory_chain(root, name, directories)
                check_native_change(root, name, expected, root_fd, native_change)
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


def finite_json_float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError('Non-finite JSON number')
    return parsed


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
    if len(raw) > limit or before.st_size > limit:
        raise ValueError(f'{label} exceeds {limit} byte limit')
    if len(raw) != before.st_size:
        raise ValueError(f'{label} byte count differs from sampled size')
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
                          parse_constant=reject_nonfinite_constant,
                          parse_float=finite_json_float)
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
