"""Synthetic fixtures for the read-only archive audit."""
import base64
import hashlib
import io
import tarfile
import unittest
import zipfile

from evaluation.source_audit import source_files, wheel_files, compare_package, native_inventory, pure_wheel_layout


def make_wheel(raw=b'x', recorded=b'x', extra=False):
    out = io.BytesIO()
    record = 'pkg-1.dist-info/RECORD'
    digest = base64.urlsafe_b64encode(hashlib.sha256(recorded).digest()).decode().rstrip('=')
    with zipfile.ZipFile(out, 'w') as z:
        z.writestr('pkg/a.py', raw)
        z.writestr(record, f'pkg/a.py,sha256={digest},{len(recorded)}\n{record},,\n')
        if extra:
            z.writestr('pkg/extra.py', b'y')
    return out.getvalue()


def make_source(path='pkg-1/pkg/a.py', content=b'x'):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as t:
        m = tarfile.TarInfo(path)
        m.size = len(content)
        t.addfile(m, io.BytesIO(content))
    return out.getvalue()


class SourceAuditTests(unittest.TestCase):
    def test_matching_record_and_source(self):
        wheel = wheel_files(make_wheel())
        src = source_files(make_source())
        self.assertEqual(compare_package(wheel, src, 'pkg', 'pkg/'),
                         {'matched': ['a.py'], 'different': [], 'wheel_only': [], 'source_only': []})
        self.assertEqual(native_inventory(wheel), {})

    def test_record_tampering_and_unlisted_file(self):
        for bad in (make_wheel(raw=b'y'), make_wheel(extra=True)):
            with self.assertRaises(ValueError):
                wheel_files(bad)

    def test_path_traversal(self):
        with self.assertRaises(ValueError):
            source_files(make_source('pkg-1/../a.py'))

    def test_source_difference_and_native_inventory(self):
        wheel = wheel_files(make_wheel())
        src = source_files(make_source(content=b'y'))
        self.assertEqual(compare_package(wheel, src, 'pkg', 'pkg/')['different'], ['a.py'])
        self.assertEqual(native_inventory({'pkg/a.so.1': 'hash', 'pkg/a.py': 'hash'}), {'pkg/a.so.1': 'hash'})

    def test_upstream_symlink_inventory_does_not_follow(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as t:
            m = tarfile.TarInfo('pkg-1/pkg/a.py')
            m.size = 1
            t.addfile(m, io.BytesIO(b'x'))
            link = tarfile.TarInfo('pkg-1/pkg/link.py')
            link.type = tarfile.SYMTYPE
            link.linkname = '../../outside.py'
            t.addfile(link)
        with self.assertRaises(ValueError):
            source_files(out.getvalue())
        links = {}
        files = source_files(out.getvalue(), links=links)
        self.assertEqual(set(files), {'pkg/a.py'})
        self.assertEqual(links, {'pkg/link.py': '../../outside.py'})

    def test_hardlink_remains_rejected(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as t:
            m = tarfile.TarInfo('pkg-1/pkg/a.py')
            m.size = 1
            t.addfile(m, io.BytesIO(b'x'))
            link = tarfile.TarInfo('pkg-1/pkg/link.py')
            link.type = tarfile.LNKTYPE
            link.linkname = 'pkg-1/pkg/a.py'
            t.addfile(link)
        with self.assertRaises(ValueError):
            source_files(out.getvalue(), links={})

    def test_complete_package_comparison_includes_noncode_data(self):
        files = {'pkg/a.py': 'same', 'pkg/_ast.cfg': 'wheel', 'pkg/extra.dat': 'extra'}
        source = {'pkg/a.py': 'same', 'pkg/_ast.cfg': 'source', 'pkg/missing.txt': 'missing'}
        self.assertEqual(compare_package(files, source, 'pkg', 'pkg/'),
                         {'matched': ['a.py'], 'different': [], 'wheel_only': [], 'source_only': []})
        self.assertEqual(compare_package(files, source, 'pkg', 'pkg/', all_files=True),
                         {'matched': ['a.py'], 'different': ['_ast.cfg'],
                          'wheel_only': ['extra.dat'], 'source_only': ['missing.txt']})

    def test_pure_wheel_complete_layout(self):
        dist = 'pkg-1.dist-info/'
        source = {'pkg/a.py': 'a', 'pkg/data.cfg': 'b', 'LICENSE': 'license'}
        files = {'pkg/a.py': 'a', 'pkg/data.cfg': 'b',
                 dist + 'METADATA': 'metadata', dist + 'WHEEL': 'wheel',
                 dist + 'RECORD': 'record', dist + 'licenses/LICENSE': 'license'}
        result = pure_wheel_layout(files, source, 'pkg', '1')
        self.assertEqual(result['unexpected'], [])
        self.assertEqual(result['missing'], [])
        self.assertTrue(result['license_matches_sdist'])
        self.assertFalse(result['metadata_semantics_verified'])
        for path in ('startup.pth', 'other/__init__.py', 'pkg-1.data/scripts/run',
                     dist + 'entry_points.txt', 'pkg/unexpected.py'):
            with self.subTest(path=path):
                self.assertEqual(pure_wheel_layout(dict(files, **{path: 'x'}),
                                 source, 'pkg', '1')['unexpected'], [path])
        for path in ('pkg/data.cfg', dist + 'METADATA', dist + 'RECORD'):
            self.assertEqual(pure_wheel_layout({k: v for k, v in files.items() if k != path},
                             source, 'pkg', '1')['missing'], [path])
        for change in ({dist + 'licenses/LICENSE': 'different'}, {dist + 'LICENSE': 'license'}):
            self.assertFalse(pure_wheel_layout(dict(files, **change), source,
                             'pkg', '1')['license_matches_sdist'])
        self.assertFalse(pure_wheel_layout({k: v for k, v in files.items()
                         if k != dist + 'licenses/LICENSE'}, source,
                         'pkg', '1')['license_matches_sdist'])
