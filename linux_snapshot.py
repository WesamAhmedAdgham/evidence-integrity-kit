"""Experimental Btrfs snapshot verification. No snapshot provisioning."""
import ctypes
import os
import platform
import re
import stat
import struct
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass

# Linux x86-64 UAPI: verified against linux/btrfs.h and linux/openat2.h.
BTRFS_IOC_SUBVOL_GETFLAGS = 0x80089419
BTRFS_IOC_GET_SUBVOL_INFO = 0x81f8943c
BTRFS_SUBVOL_RDONLY = 2
SUBVOL_INFO_SIZE = 504
SYS_OPENAT2 = 437
RESOLVE_STRICT = 0x0f  # NO_XDEV | NO_MAGICLINKS | NO_SYMLINKS | BENEATH


def validate_request(value):
    if (sys.platform != 'linux' or platform.machine().lower() != 'x86_64' or
            struct.calcsize('P') != 8 or sys.byteorder != 'little' or
            not all(hasattr(os, flag) for flag in ('O_PATH', 'O_CLOEXEC', 'O_NOFOLLOW', 'O_NONBLOCK'))):
        raise ValueError('Btrfs snapshot mode unavailable on this platform')
    if not isinstance(value, str):
        raise ValueError('Canonical Btrfs snapshot UUID required')
    try:
        expected = uuid.UUID(value)
    except ValueError:
        raise ValueError('Canonical Btrfs snapshot UUID required') from None
    if str(expected) != value or not expected.int:
        raise ValueError('Canonical Btrfs snapshot UUID required')
    if os.geteuid() == 0:
        raise ValueError('Btrfs snapshot mode must run without root privileges')
    return expected


@dataclass(frozen=True)
class Scope:
    device: int
    mount: int
    tree_id: int
    generation: int
    snapshot_uuid: uuid.UUID
    parent_uuid: uuid.UUID


def mount_id(fd):
    with open(f'/proc/self/fdinfo/{fd}', 'rb') as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise ValueError('Snapshot fdinfo exceeds limit')
    values = re.findall(rb'^mnt_id:[ \t]*([0-9]{1,20})[ \t]*$', raw, re.MULTILINE)
    if len(values) != 1 or int(values[0]) <= 0:
        raise ValueError('Snapshot descriptor mount identity unavailable')
    return int(values[0])


def subvolume_info(fd):
    import fcntl
    raw = bytearray(SUBVOL_INFO_SIZE)
    fcntl.ioctl(fd, BTRFS_IOC_GET_SUBVOL_INFO, raw, True)
    tree_id = struct.unpack_from('=Q', raw, 0)[0]
    generation = struct.unpack_from('=Q', raw, 280)[0]
    snapshot = uuid.UUID(bytes=bytes(raw[296:312]))
    parent = uuid.UUID(bytes=bytes(raw[312:328]))
    if not tree_id or not generation or not snapshot.int or not parent.int:
        raise ValueError('Btrfs snapshot identity or parent UUID unavailable')
    return tree_id, generation, snapshot, parent


def root_scope(fd, expected):
    import fcntl
    metadata = os.fstat(fd)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_ino != 256 or metadata.st_uid != 0):
        raise ValueError('Btrfs snapshot mode requires a root-owned subvolume root')
    flags = bytearray(8)
    fcntl.ioctl(fd, BTRFS_IOC_SUBVOL_GETFLAGS, flags, True)
    if struct.unpack('=Q', flags)[0] != BTRFS_SUBVOL_RDONLY:
        raise ValueError('Btrfs snapshot is not read-only at subvolume level')
    info = subvolume_info(fd)
    if info[2] != expected:
        raise ValueError('Btrfs snapshot UUID does not match trusted expectation')
    return Scope(metadata.st_dev, mount_id(fd), *info)


def check_root_scope(fd, scope):
    if root_scope(fd, scope.snapshot_uuid) != scope:
        raise ValueError('Btrfs snapshot scope changed')


def check_file_scope(fd, scope, *, native):
    metadata = os.fstat(fd)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or
            not metadata.st_ino or metadata.st_dev != scope.device or mount_id(fd) != scope.mount):
        raise ValueError('Evidence is not a single-link file in the snapshot scope')
    if native and subvolume_info(fd) != (
            scope.tree_id, scope.generation, scope.snapshot_uuid, scope.parent_uuid):
        raise ValueError('Evidence crosses Btrfs snapshot subvolume scope')
    return metadata


class OpenHow(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64), ('resolve', ctypes.c_uint64)]


def open_path(root_fd, name):
    from evidence_integrity import validate_relative_path
    validate_relative_path(name)
    syscall = ctypes.CDLL(None, use_errno=True).syscall
    syscall.restype = ctypes.c_long
    how = OpenHow(os.O_PATH | os.O_CLOEXEC, 0, RESOLVE_STRICT)
    fd = syscall(ctypes.c_long(SYS_OPENAT2), ctypes.c_int(root_fd),
                 ctypes.c_char_p(os.fsencode(name)), ctypes.byref(how),
                 ctypes.c_size_t(ctypes.sizeof(how)))
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return fd


@contextmanager
def open_snapshot_leaf(root_fd, name, scope):
    # O_PATH avoids opening special files for I/O before type validation.
    # The intentional procfs reopen refers to the held object, not its pathname.
    descriptor = open_path(root_fd, name)
    try:
        expected = check_file_scope(descriptor, scope, native=False)
        fd = os.open(f'/proc/self/fd/{descriptor}', os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            opened = check_file_scope(fd, scope, native=True)
            if not os.path.samestat(expected, opened):
                raise ValueError('Snapshot evidence descriptor identity changed')
            stream = os.fdopen(fd, 'rb')
        except BaseException:
            os.close(fd)
            raise
        with stream:
            yield stream, opened
    finally:
        os.close(descriptor)
