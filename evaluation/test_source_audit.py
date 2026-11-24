"""Synthetic fixtures for the read-only archive audit."""
import base64
import hashlib
import io
import tarfile
import unittest
import zipfile

from evaluation.source_audit import source_files, wheel_files, compare_package, native_inventory


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
