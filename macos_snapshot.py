"""Experimental mounted APFS snapshot capability checks; no provisioning."""
import ctypes
import os
import platform
import re
import stat
import sys
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass

MNT_RDONLY = 0x00000001
MNT_NODEV = 0x00000010
MNT_LOCAL = 0x00001000
MNT_SNAPSHOT = 0x40000000
REQUIRED_FLAGS = MNT_RDONLY | MNT_NODEV | MNT_LOCAL | MNT_SNAPSHOT


def validate_request(source):
    if (sys.platform != 'darwin' or platform.machine().lower() != 'arm64' or
            ctypes.sizeof(ctypes.c_void_p) != 8):
        raise ValueError('APFS snapshot mode unavailable on this platform')
    if (not isinstance(source, str) or len(source) > 512 or
            not re.fullmatch(r'[A-Za-z0-9._-]{1,255}@/dev/disk[0-9]+(?:s[0-9]+)+', source)):
        raise ValueError('Canonical APFS snapshot mount source required')
    if os.geteuid() == 0:
        raise ValueError('APFS snapshot mode must run without root privileges')
    return source


class StatFs(ctypes.Structure):
    # Darwin arm64 struct statfs, 64-bit inode ABI. Validate against the SDK.
    _fields_ = [('bsize', ctypes.c_uint32), ('iosize', ctypes.c_int32),
                ('blocks', ctypes.c_uint64), ('bfree', ctypes.c_uint64),
                ('bavail', ctypes.c_uint64), ('files', ctypes.c_uint64),
                ('ffree', ctypes.c_uint64), ('fsid', ctypes.c_int32 * 2),
                ('owner', ctypes.c_uint32), ('type', ctypes.c_uint32),
                ('flags', ctypes.c_uint32), ('subtype', ctypes.c_uint32),
                ('fstypename', ctypes.c_char * 16), ('mntonname', ctypes.c_char * 1024),
                ('mntfromname', ctypes.c_char * 1024), ('reserved', ctypes.c_uint32 * 8)]


@dataclass(frozen=True)
class Scope:
    device: int
    fsid: tuple
    source: str
    mount_path: str
    flags: int
    owner: int


def descriptor_scope(fd):
    if ctypes.sizeof(StatFs) != 2168:
        raise ValueError('Unsupported Darwin statfs ABI')
    function = ctypes.CDLL(None, use_errno=True).fstatfs
    function.argtypes = [ctypes.c_int, ctypes.POINTER(StatFs)]
    function.restype = ctypes.c_int
    info = StatFs()
    if function(fd, ctypes.byref(info)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if info.fstypename != b'apfs' or info.flags & REQUIRED_FLAGS != REQUIRED_FLAGS:
        raise ValueError('APFS snapshot mode requires a local read-only nodev snapshot mount')
    if info.owner != 0 or not any(info.fsid):
        raise ValueError('APFS snapshot mount owner or identity unavailable')
    if not info.mntonname or not info.mntfromname:
        raise ValueError('APFS snapshot mount source or path unavailable')
    return Scope(os.fstat(fd).st_dev, tuple(info.fsid), os.fsdecode(info.mntfromname),
                 os.fsdecode(info.mntonname), info.flags, info.owner)


def root_scope(fd, expected, *, root=None):
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        raise ValueError('APFS snapshot root must be a directory')
    scope = descriptor_scope(fd)
    if scope.source != expected:
        raise ValueError('APFS snapshot source does not match trusted expectation')
    if root is None or os.fspath(root) != scope.mount_path:
        raise ValueError('APFS evidence root must be the mounted snapshot root')
    return scope


def check_root_scope(fd, scope):
    if root_scope(fd, scope.source, root=scope.mount_path) != scope:
        raise ValueError('APFS snapshot scope changed')


def check_file_scope(fd, scope, *, native=True):
    metadata = os.fstat(fd)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or not metadata.st_ino or
            descriptor_scope(fd) != scope):
        raise ValueError('Evidence is not a single-link file in the APFS snapshot scope')
    return metadata


@contextmanager
def open_snapshot_leaf(root_fd, name, scope):
    from evidence_integrity import validate_relative_path
    parts = validate_relative_path(name)
    with ExitStack() as stack:
        parent = root_fd
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            stack.callback(os.close, child)
            if descriptor_scope(child) != scope:
                raise ValueError('APFS evidence directory crosses snapshot mount scope')
            parent = child
        expected = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(expected.st_mode) or expected.st_nlink != 1 or
                expected.st_dev != scope.device):
            raise ValueError('Evidence is not a single-link file in the APFS snapshot scope')
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            opened = check_file_scope(fd, scope)
            if not os.path.samestat(expected, opened):
                raise ValueError('APFS snapshot evidence descriptor identity changed')
            stream = os.fdopen(fd, 'rb')
        except BaseException:
            os.close(fd)
            raise
        with stream:
            yield stream, opened
