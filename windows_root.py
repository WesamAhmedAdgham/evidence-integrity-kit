"""Native Windows evidence guards; this module is imported only on Windows."""
import ctypes
import msvcrt
import os
import uuid
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
VOLUME_NAME_GUID = 0x1
FILE_NAME_OPENED = 0x8
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
_final_path = _kernel.GetFinalPathNameByHandleW
_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
_final_path.restype = wintypes.DWORD
_volume_info = _kernel.GetVolumeInformationByHandleW
_volume_info.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                         ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
_volume_info.restype = wintypes.BOOL


def local_ntfs_scope(handle):
    """Conservatively require a local NTFS volume GUID on the actual handle."""
    fs = ctypes.create_unicode_buffer(32)
    if not _volume_info(handle, None, 0, None, None, None, fs, len(fs)):
        raise ctypes.WinError(ctypes.get_last_error())
    if fs.value.upper() != 'NTFS':
        raise ValueError('Windows deny-write mode requires local NTFS')
    # Volume GUID paths are not provided for network shares. Bound this query
    # by the Win32 extended-path limit; fail rather than allocate unboundedly.
    path = ctypes.create_unicode_buffer(32768)
    count = _final_path(handle, path, len(path), VOLUME_NAME_GUID | FILE_NAME_OPENED)
    if not count:
        raise ctypes.WinError(ctypes.get_last_error())
    if count >= len(path):
        raise ValueError('Windows guarded volume path exceeds limit')
    prefix = '\\\\?\\Volume{'
    name = path.value
    if not name.casefold().startswith(prefix.casefold()):
        raise ValueError('Windows deny-write mode requires a local volume GUID')
    guid, separator, _ = name[len(prefix):].partition('}\\')
    if not separator:
        raise ValueError('Windows guarded volume GUID unavailable')
    try:
        return uuid.UUID(guid)
    except ValueError:
        raise ValueError('Windows guarded volume GUID invalid') from None


@contextmanager
def directory_handle(path, *, deny_write=False):
    # Request directory listing access, not just attributes, so the handle
    # participates in sharing checks. Deliberately omit FILE_SHARE_DELETE.
    share = FILE_SHARE_READ if deny_write else FILE_SHARE_READ | FILE_SHARE_WRITE
    handle = _create(os.fspath(path), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                     share, None, OPEN_EXISTING,
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
    return native_file_identity(handle)


def native_file_identity(handle):
    identity = FileIdInfo()
    if not _info(handle, FILE_ID_INFO_CLASS, ctypes.byref(identity), ctypes.sizeof(identity)):
        raise ctypes.WinError(ctypes.get_last_error())
    identifier = bytes(identity.identifier)
    if not any(identifier):
        raise ValueError('Native evidence identity unavailable')
    return identity.volume, identifier


def file_guard_state(stream):
    """Check the same held leaf's native identity, type, attributes and change time."""
    handle = msvcrt.get_osfhandle(stream.fileno())
    attributes = FileAttributeTagInfo()
    if _file_type(handle) != FILE_TYPE_DISK:
        raise ValueError('Evidence must be a disk file')
    if not _info(handle, FILE_ATTRIBUTE_TAG_INFO_CLASS, ctypes.byref(attributes), ctypes.sizeof(attributes)):
        raise ctypes.WinError(ctypes.get_last_error())
    if attributes.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT):
        raise ValueError('Evidence leaf must be a regular file without reparse points')
    return native_file_identity(handle), file_change_time(stream), attributes.attributes


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
def pinned_windows_root(root, *, deny_write=False):
    expected = root.lstat()
    context = directory_handle(root, deny_write=True) if deny_write else directory_handle(root)
    with context as handle:
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
def guarded_windows_file(root, parts, guard, *, deny_write=False, volume_scope=None):
    """Hold checked directory handles while opening and reading one leaf.

    This uses absolute Win32 paths with pinned prefixes, not NT
    RootDirectory-relative opens. Callers must supply validated components.
    """
    if deny_write and volume_scope is None:
        raise ValueError('Windows deny-write volume scope required')
    check_windows_root(root, guard)
    with ExitStack() as stack:
        directories = []
        path = root
        for part in parts[:-1]:
            path = path / part
            context = directory_handle(path, deny_write=True) if deny_write else directory_handle(path)
            handle = stack.enter_context(context)
            if deny_write and local_ntfs_scope(handle) != volume_scope:
                raise ValueError('Guarded evidence directory crosses local NTFS volume')
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
            if deny_write and local_ntfs_scope(msvcrt.get_osfhandle(stream.fileno())) != volume_scope:
                raise ValueError('Guarded evidence leaf crosses local NTFS volume')
            check_directories()
            yield stream
            check_directories()
