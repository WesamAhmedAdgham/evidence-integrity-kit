"""Read-only diagnostic comparison of unattested wheels and source archives.

No package installation, extraction, import, or execution. Byte comparisons
are not publisher attestations or proof that compiled code was built from source.
"""
import base64
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import zipfile

from evaluation.provenance_diagnostic import fetch, select_wheels, MAX_METADATA, MAX_WHEEL
from tools.verify_signing_environment import load_lock

SOURCE = {
    'cffi': ('2.1.1', 'dd31f52ea1086513bb9df30f8fcee9b8918323ae067a3d5b78bc826a000712be', 'src/cffi/'),
    'pycparser': ('3.0', '600f49d217304a5902ac3c37e1281c9fe94e4d0489de643a9504c5cdfdfc6b29', 'pycparser/'),
}
CFFI_COMMIT = 'fd33e7700f0ebafe6f30bd5053f13327221b77a2'
PYCPARSER_COMMIT = '77de509f0268f44ee587b5a4d9f0d680e269fcae'
MAX_UNPACKED = 32 * 1024 * 1024
MAX_MEMBERS = 10000


def safe_name(name):
    if (not name or '\\' in name or '\x00' in name or name.startswith('/')
            or any(p in ('', '.', '..') for p in name.rstrip('/').split('/'))):
        raise ValueError('Unsafe archive member name')
    return name.rstrip('/')


def checked_size(count, total):
    if count > MAX_MEMBERS or total > MAX_UNPACKED:
        raise ValueError('Archive inspection budget exceeded')


def source_files(data, *, links=None):
    result, seen = {}, set()
    root, total, count = None, 0, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r|gz') as archive:
        for member in archive:
            count += 1
            name = safe_name(member.name)
            if name in seen:
                raise ValueError('Duplicate source archive member')
            seen.add(name)
            parts = name.split('/')
            if root is None:
                root = parts[0]
            if parts[0] != root:
                raise ValueError('Source archive has multiple roots')
            total += member.size
            checked_size(count, total)
            if member.isdir():
                continue
            if member.issym() and links is not None and len(parts) >= 2:
                # Inventory a Git source symlink as metadata only. Never resolve,
                # extract, follow, or compare it as regular file content.
                links['/'.join(parts[1:])] = member.linkname
                continue
            if not member.isfile() or len(parts) < 2:
                raise ValueError(f'Unsupported source archive member: {name!r}, type={member.type!r}')
            stream = archive.extractfile(member)
            raw = stream.read(member.size + 1)
            if len(raw) != member.size:
                raise ValueError('Source archive member size mismatch')
            result['/'.join(parts[1:])] = hashlib.sha256(raw).hexdigest()
    if not result:
        raise ValueError('Empty source archive')
    return result


def wheel_files(data):
    result, seen = {}, set()
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        checked_size(len(members), 0)
        for member in members:
            name = safe_name(member.filename)
            if name in seen:
                raise ValueError('Duplicate wheel member')
            seen.add(name)
            total += member.file_size
            checked_size(len(members), total)
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError('Unexpected wheel symlink')
            if member.is_dir():
                continue
            raw = archive.read(member)
            if len(raw) != member.file_size:
                raise ValueError('Wheel member size mismatch')
            result[name] = raw
    records = [name for name in result if name.endswith('.dist-info/RECORD')]
    if len(records) != 1:
        raise ValueError('Expected exactly one wheel RECORD')
    record = records[0]
    listed = set()
    for row in csv.reader(io.StringIO(result[record].decode('utf-8'), newline='')):
        if len(row) != 3:
            raise ValueError('Invalid wheel RECORD row')
        name, digest, size = row
        safe_name(name)
        if name in listed or name not in result:
            raise ValueError('Duplicate or missing wheel RECORD member')
        listed.add(name)
        if name == record:
            if digest or size:
                raise ValueError('Unexpected self-digest in RECORD')
            continue
        raw = result[name]
        expected = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
        if digest != expected or size != str(len(raw)):
            raise ValueError('Wheel RECORD digest or size mismatch')
    if listed != set(result):
        raise ValueError('Wheel contains unrecorded files')
    return {name: hashlib.sha256(raw).hexdigest() for name, raw in result.items()}


def compare_package(files, source, package, source_prefix, *, all_files=False):
    prefix = package + '/'
    wheel = {name[len(prefix):]: digest for name, digest in files.items()
             if name.startswith(prefix) and (all_files or name.endswith(('.py', '.h', '.c')))}
    reference = {name[len(source_prefix):]: digest for name, digest in source.items()
                 if name.startswith(source_prefix) and (all_files or name.endswith(('.py', '.h', '.c')))}
    if not wheel or not reference:
        raise ValueError('Empty package source comparison')
    return {
        'matched': sorted(name for name in wheel if reference.get(name) == wheel[name]),
        'different': sorted(name for name in wheel if name in reference and reference[name] != wheel[name]),
        'wheel_only': sorted(set(wheel) - set(reference)),
        'source_only': sorted(set(reference) - set(wheel)),
    }


def pure_wheel_layout(files, source, package, version):
    """Inspect the complete install layout of this pure package, not just code.

    The known wheel may contain package files and standard dist-info metadata
    only. No .data relocation, .pth startup hooks, other packages or binaries.
    This is an inventory check, not semantic authentication of metadata.
    """
    prefix = package + '/'
    dist = f'{package}-{version}.dist-info/'
    package_files = {name for name in source if name.startswith(prefix)}
    required = package_files | {dist + name for name in ('METADATA', 'WHEEL', 'RECORD')}
    license_paths = {dist + 'LICENSE', dist + 'licenses/LICENSE'}
    allowed = required | license_paths | {dist + 'top_level.txt'}
    licenses = sorted(set(files) & license_paths)
    license_matches = (len(licenses) == 1 and 'LICENSE' in source and
                       files[licenses[0]] == source['LICENSE'])
    return {'unexpected': sorted(set(files) - allowed),
            'missing': sorted(required - set(files)),
            'license_paths': licenses, 'license_matches_sdist': license_matches,
            'metadata_semantics_verified': False}


def native_inventory(files):
    return {name: digest for name, digest in files.items()
            if any(marker in name.lower() for marker in ('.so', '.pyd', '.dll', '.dylib', '.exe'))}


def main():
    pins = load_lock(Path('evaluation/requirements-validator.txt'))
    audited = 0
    mismatch = False
    for name, (version, digest, prefix) in SOURCE.items():
        if pins[name][0] != version:
            raise ValueError('Source version does not match evaluation lock')
        meta = json.loads(fetch(f'https://pypi.org/pypi/{name}/{version}/json', 'pypi.org', MAX_METADATA))
        sdists = [row for row in meta['urls'] if row['packagetype'] == 'sdist'
                  and row['digests']['sha256'] == digest and not row.get('yanked')]
        if len(sdists) != 1:
            raise ValueError('Pinned source distribution not found')
        raw = fetch(sdists[0]['url'], 'files.pythonhosted.org', MAX_WHEEL)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Source distribution digest mismatch')
        source = source_files(raw)
        if name == 'cffi':
            # GitHub metadata reports the exact commit signed; the independent
            # maintainer key and source archive identity still need review.
            upstream = fetch('https://codeload.github.com/python-cffi/cffi/tar.gz/' + CFFI_COMMIT,
                             'codeload.github.com', MAX_WHEEL)
            upstream_links = {}
            git = source_files(upstream, links=upstream_links)
            keys = {k for k in set(source) | set(git)
                    if k.startswith(('src/cffi/', 'src/c/')) and k.endswith(('.py', '.h', '.c'))}
            changed = sorted(k for k in keys if k in source and k in git and source[k] != git[k])
            only_source = sorted(k for k in keys if k in source and k not in git)
            only_git = sorted(k for k in keys if k in git and k not in source)
            matched = sorted(k for k in keys if k in source and k in git and source[k] == git[k])
            if not matched:
                raise ValueError('Empty CFFI upstream comparison')
            print(json.dumps({'upstream_commit': CFFI_COMMIT, 'archive_sha256': hashlib.sha256(upstream).hexdigest(),
                              'matched_source_files': matched, 'different': changed,
                              'sdist_only': only_source, 'git_only': only_git,
                              'upstream_symlinks_not_followed': upstream_links,
                              'independently_authenticated': False}, sort_keys=True), flush=True)
            relevant_links = [name for name in upstream_links
                              if name.startswith(('src/cffi/', 'src/c/'))]
            mismatch |= bool(changed or only_source or only_git or relevant_links)
        if name == 'pycparser':
            # release_v3.00 is a lightweight tag to an unsigned commit.
            # Compare all package files, including non-Python package data.
            # GitHub transport/source agreement is not publisher authentication.
            upstream = fetch('https://codeload.github.com/eliben/pycparser/tar.gz/' + PYCPARSER_COMMIT,
                             'codeload.github.com', MAX_WHEEL)
            upstream_links = {}
            git = source_files(upstream, links=upstream_links)
            comparison = compare_package(source, git, name, prefix, all_files=True)
            relevant_links = sorted(k for k in upstream_links if k.startswith(prefix))
            license_matches = ('LICENSE' in source and source['LICENSE'] == git.get('LICENSE'))
            mismatch |= not license_matches
            mismatch |= bool(comparison['different'] or comparison['wheel_only'] or
                             comparison['source_only'] or relevant_links)
            print(json.dumps({'package': name, 'upstream_commit': PYCPARSER_COMMIT,
                              'archive_sha256': hashlib.sha256(upstream).hexdigest(),
                              'sdist_vs_git_package': comparison,
                              'license_matches_upstream': license_matches,
                              'upstream_package_symlinks_not_followed': relevant_links,
                              'independently_authenticated': False}, sort_keys=True), flush=True)
        for row in select_wheels(meta, pins[name][1]):
            data = fetch(row['url'], 'files.pythonhosted.org', MAX_WHEEL)
            if hashlib.sha256(data).hexdigest() != row['digests']['sha256']:
                raise ValueError('Wheel digest mismatch')
            files = wheel_files(data)
            comparison = compare_package(files, source, name, prefix, all_files=(name == 'pycparser'))
            native = native_inventory(files)
            layout = None
            if name == 'pycparser':
                layout = pure_wheel_layout(files, source, name, version)
                mismatch |= bool(layout['unexpected'] or layout['missing'] or
                                 not layout['license_matches_sdist'] or native)
            mismatch |= bool(comparison['different'] or comparison['wheel_only'] or comparison['source_only'])
            print(json.dumps({'package': name, 'filename': row['filename'], 'sha256': row['digests']['sha256'],
                              'record_verified': True, 'source_sha256': digest, 'comparison': comparison,
                              'native_inventory': native, 'pure_wheel_layout': layout,
                              'publisher_verified': False,
                              'release_approval': False}, sort_keys=True), flush=True)
            audited += 1
    if audited != 7:
        raise ValueError('Unexpected unattested wheel count')
    print(json.dumps({'audited': audited, 'source_differences': mismatch,
                      'native_build_provenance_proven': False, 'release_approval': False}, sort_keys=True))
    # All seven still lack publisher attestations; do not imply release acceptance.
    return 1


if __name__ == '__main__':
    sys.exit(main())
