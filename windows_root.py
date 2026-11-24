"""Native Windows evidence guards; this module is imported only on Windows."""
import ctypes
import msvcrt
import os
from contextlib import ExitStack, contextmanager
from ctypes import wintypes


# Win32 fileapi.h, minwinbase.h, winnt.h.
GENERIC_READ = 0x80000000
FILE_TYPE_DISK = 0x0001
FILE_LIST_DIRECTORY = 0x0001
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_READ = 0x0001
FILE_SHARE_WRITE = 0x0002
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_DIRECTORY = 0x0010
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
FILE_BASIC_INFO_CLASS = 0
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
FILE_ID_INFO_CLASS = 18
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class FileBasicInfo(ctypes.Structure):
    _fields_ = [('creation', ctypes.c_int64), ('access', ctypes.c_int64),
                ('write', ctypes.c_int64), ('change', ctypes.c_int64),
                ('attributes', wintypes.DWORD)]


def file_change_time(stream):
    """Read native metadata ChangeTime; Python st_ctime is creation time on Windows."""
    basic = FileBasicInfo()
    handle = msvcrt.get_osfhandle(stream.fileno())
    if not _info(handle, FILE_BASIC_INFO_CLASS, ctypes.byref(basic), ctypes.sizeof(basic)):
        raise ctypes.WinError(ctypes.get_last_error())
    if basic.change <= 0:
        raise ValueError('Native evidence change time unavailable')
    return basic.change


class FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [('attributes', wintypes.DWORD), ('tag', wintypes.DWORD)]


class FileIdInfo(ctypes.Structure):
    _fields_ = [('volume', ctypes.c_uint64), ('identifier', ctypes.c_ubyte * 16)]


_kernel = ctypes.WinDLL('kernel32', use_last_error=True)
_create = _kernel.CreateFileW
_create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
_create.restype = wintypes.HANDLE
_info = _kernel.GetFileInformationByHandleEx
_info.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
_info.restype = wintypes.BOOL
_close = _kernel.CloseHandle
_close.argtypes = [wintypes.HANDLE]
_close.restype = wintypes.BOOL
_file_type = _kernel.GetFileType
_file_type.argtypes = [wintypes.HANDLE]
_file_type.restype = wintypes.DWORD


@contextmanager
def directory_handle(path):
    # Request directory listing access, not just attributes, so the handle
    # participates in sharing checks. Deliberately omit FILE_SHARE_DELETE.
    handle = _create(os.fspath(path), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING,
                     FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None)
    if handle == INVALID_HANDLE_VALUE or handle is None:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield handle
    finally:
        if not _close(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def directory_identity(handle):
    attributes = FileAttributeTagInfo()
    if not _info(handle, FILE_ATTRIBUTE_TAG_INFO_CLASS,
                 ctypes.byref(attributes), ctypes.sizeof(attributes)):
        raise ctypes.WinError(ctypes.get_last_error())
    if (not attributes.attributes & FILE_ATTRIBUTE_DIRECTORY or
            attributes.attributes & FILE_ATTRIBUTE_REPARSE_POINT):
        raise ValueError('Evidence root must be a directory without reparse points')
    identity = FileIdInfo()
    if not _info(handle, FILE_ID_INFO_CLASS, ctypes.byref(identity), ctypes.sizeof(identity)):
        raise ctypes.WinError(ctypes.get_last_error())
    identifier = bytes(identity.identifier)
    if not any(identifier):
        raise ValueError('Evidence root identity unavailable')
    return identity.volume, identifier


def check_windows_root(root, guard):
    if guard is None:
        raise ValueError('Windows evidence root handle required')
    handle, expected = guard
    if directory_identity(handle) != expected:
        raise ValueError('Evidence root identity changed or unavailable')
    with directory_handle(root) as current:
        if directory_identity(current) != expected:
            raise ValueError('Evidence root identity changed or unavailable')


@contextmanager
def pinned_windows_root(root):
    expected = root.lstat()
    with directory_handle(root) as handle:
        guard = handle, directory_identity(handle)
        current = root.lstat()
        if not expected.st_ino or not current.st_ino or not os.path.samestat(expected, current):
            raise ValueError('Evidence root identity changed or unavailable')
        check_windows_root(root, guard)
        yield guard
        check_windows_root(root, guard)


def checked_file_fd(path, flags, *, deny_write=False):
    """Open a read-only leaf without following its final reparse point."""
    share = FILE_SHARE_READ if deny_write else FILE_SHARE_READ | FILE_SHARE_WRITE
    handle = _create(os.fspath(path), GENERIC_READ,
                     share, None, OPEN_EXISTING,
                     FILE_FLAG_OPEN_REPARSE_POINT, None)
    if handle == INVALID_HANDLE_VALUE or handle is None:
        raise ctypes.WinError(ctypes.get_last_error())
    transferred = False
    try:
        if _file_type(handle) != FILE_TYPE_DISK:
            raise ValueError('Evidence must be a disk file')
        attributes = FileAttributeTagInfo()
        if not _info(handle, FILE_ATTRIBUTE_TAG_INFO_CLASS,
                     ctypes.byref(attributes), ctypes.sizeof(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError('Evidence leaf must be a regular file without reparse points')
        # On success, the CRT descriptor owns the handle; Python's open()
        # owns the descriptor returned by this opener.
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
        transferred = True
        return fd
    finally:
        if not transferred and not _close(handle):
            raise ctypes.WinError(ctypes.get_last_error())


@contextmanager
def guarded_windows_file(root, parts, guard, *, deny_write=False):
    """Hold checked directory handles while opening and reading one leaf.

    This uses absolute Win32 paths with pinned prefixes, not NT
    RootDirectory-relative opens. Callers must supply validated components.
    """
    check_windows_root(root, guard)
    with ExitStack() as stack:
        directories = []
        path = root
        for part in parts[:-1]:
            path = path / part
            handle = stack.enter_context(directory_handle(path))
            directories.append((path, handle, directory_identity(handle)))

        def check_directories():
            check_windows_root(root, guard)
            for directory, handle, expected in directories:
                if directory_identity(handle) != expected:
                    raise ValueError('Evidence directory identity changed')
                with directory_handle(directory) as current:
                    if directory_identity(current) != expected:
                        raise ValueError('Evidence directory identity changed')

        check_directories()
        opener = (lambda leaf, flags: checked_file_fd(leaf, flags, deny_write=True)) if deny_write else checked_file_fd
        with open(path / parts[-1], 'rb', opener=opener) as stream:
            check_directories()
            yield stream
            check_directories()
