"""Native Windows evidence guards; this module is imported only on Windows."""
import ctypes
import msvcrt
import os
import re
import uuid
from pathlib import Path
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
SYNCHRONIZE = 0x00100000
OBJ_CASE_INSENSITIVE = 0x40
NT_FILE_OPEN = 1
FILE_SYNCHRONOUS_IO_NONALERT = 0x20
NT_FILE_OPEN_REPARSE_POINT = 0x00200000
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


class UnicodeString(ctypes.Structure):
    _fields_ = [('Length', wintypes.USHORT), ('MaximumLength', wintypes.USHORT),
                ('Buffer', wintypes.LPWSTR)]


class ObjectAttributes(ctypes.Structure):
    _fields_ = [('Length', wintypes.ULONG), ('RootDirectory', wintypes.HANDLE),
                ('ObjectName', ctypes.POINTER(UnicodeString)), ('Attributes', wintypes.ULONG),
                ('SecurityDescriptor', ctypes.c_void_p), ('SecurityQualityOfService', ctypes.c_void_p)]


class IoStatusBlock(ctypes.Structure):
    # The first member is a union of NTSTATUS and a pointer.
    _fields_ = [('StatusOrPointer', ctypes.c_void_p), ('Information', ctypes.c_size_t)]


def relative_handle(parent, part, *, directory, deny_write=True):
    """Open exactly one validated component relative to a held directory.

    No absolute path fallback. A type-neutral no-follow open is checked
    before transferring ownership or reading file content.
    """
    from evidence_integrity import validate_relative_path
    if validate_relative_path(part) != [part]:
        raise ValueError('Native relative open requires exactly one component')
    if not directory and not deny_write:
        raise ValueError('Native relative leaf must deny write sharing')
    directory_identity(parent)
    encoded = part.encode('utf-16-le')
    if len(encoded) > 510:
        raise ValueError('Native relative component exceeds NTFS name limit')
    buffer = ctypes.create_unicode_buffer(part)
    name = UnicodeString(len(encoded), len(encoded) + 2,
                         ctypes.cast(buffer, wintypes.LPWSTR))
    attrs = ObjectAttributes(ctypes.sizeof(ObjectAttributes), parent,
                             ctypes.pointer(name), OBJ_CASE_INSENSITIVE, None, None)
    ios = IoStatusBlock()
    out = wintypes.HANDLE()
    # Load this optional native entry point only in explicitly guarded mode.
    try:
        nt = ctypes.WinDLL('ntdll')
        create = nt.NtCreateFile
        convert = nt.RtlNtStatusToDosError
    except (AttributeError, OSError):
        raise ValueError('Native relative evidence opening unavailable') from None
    create.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.ULONG,
                       ctypes.POINTER(ObjectAttributes), ctypes.POINTER(IoStatusBlock),
                       ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG,
                       wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG]
    create.restype = wintypes.LONG
    convert.argtypes, convert.restype = [wintypes.LONG], wintypes.ULONG
    access = (FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES if directory else GENERIC_READ) | SYNCHRONIZE
    share = FILE_SHARE_READ if deny_write else FILE_SHARE_READ | FILE_SHARE_WRITE
    status = create(ctypes.byref(out), access, ctypes.byref(attrs), ctypes.byref(ios),
                    None, 0, share, NT_FILE_OPEN,
                    FILE_SYNCHRONOUS_IO_NONALERT | NT_FILE_OPEN_REPARSE_POINT, None, 0)
    if status != 0:
        if status > 0 and out.value not in (None, INVALID_HANDLE_VALUE):
            _close(out)
        raise ctypes.WinError(convert(status))
    if out.value in (None, INVALID_HANDLE_VALUE):
        raise ValueError('Native relative evidence handle unavailable')
    handle = out.value
    try:
        if directory:
            directory_identity(handle)
        else:
            checked_leaf_identity(handle)
        return handle
    except BaseException:
        _close(handle)
        raise


@contextmanager
def relative_directory(parent, part, *, deny_write=True):
    handle = relative_handle(parent, part, directory=True, deny_write=deny_write)
    try:
        yield handle
    finally:
        if not _close(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def checked_leaf_identity(handle):
    attributes = FileAttributeTagInfo()
    if _file_type(handle) != FILE_TYPE_DISK:
        raise ValueError('Evidence must be a disk file')
    if not _info(handle, FILE_ATTRIBUTE_TAG_INFO_CLASS, ctypes.byref(attributes), ctypes.sizeof(attributes)):
        raise ctypes.WinError(ctypes.get_last_error())
    if attributes.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT):
        raise ValueError('Evidence leaf must be a regular file without reparse points')
    return native_file_identity(handle), attributes.attributes


@contextmanager
def relative_leaf(parent, part):
    handle = relative_handle(parent, part, directory=False)
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        _close(handle)
        raise
    try:
        stream = os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise
    with stream:
        yield stream


def local_ntfs_location(handle):
    """Return local NTFS GUID and handle-derived path within that volume."""
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
    guid, separator, suffix = name[len(prefix):].partition('}\\')
    if not separator:
        raise ValueError('Windows guarded volume GUID unavailable')
    try:
        return uuid.UUID(guid), suffix
    except ValueError:
        raise ValueError('Windows guarded volume GUID invalid') from None


def local_ntfs_scope(handle):
    return local_ntfs_location(handle)[0]


@contextmanager
def directory_handle(path, *, deny_write=False, synchronize=False):
    # Request directory listing access, not just attributes, so the handle
    # participates in sharing checks. Deliberately omit FILE_SHARE_DELETE.
    share = FILE_SHARE_READ if deny_write else FILE_SHARE_READ | FILE_SHARE_WRITE
    access = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | (SYNCHRONIZE if deny_write or synchronize else 0)
    handle = _create(os.fspath(path), access,
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


def lexical_guarded_root(root):
    """Bound a drive-letter path without following junctions or symlinks."""
    from evidence_integrity import validate_relative_path, MAX_PATH_COMPONENTS
    path = Path(root)
    if '..' in path.parts or (path.drive and not path.is_absolute()) or (path.root and not path.drive):
        raise ValueError('Windows guarded root must use an unambiguous local drive path')
    path = Path(os.path.abspath(path))
    if not re.fullmatch(r'[A-Za-z]:\\', path.anchor):
        raise ValueError('Windows guarded root requires a local drive-letter anchor')
    parts = path.parts[1:]
    if not parts or len(parts) > MAX_PATH_COMPONENTS:
        raise ValueError('Windows guarded root depth unavailable or exceeds limit')
    for part in parts:
        if validate_relative_path(part) != [part]:
            raise ValueError('Invalid Windows guarded root component')
    return path


@contextmanager
def pinned_relative_root(root):
    """Pin drive-root and ancestors without denying unrelated ancestor writes.

    The evidence root itself denies writes. No descendant of the drive
    anchor is acquired by an absolute path. Root pathname checks supplement
    relative identity checks; drive mapping and privileged metadata changes
    are still outside the trusted namespace model.
    """
    root = lexical_guarded_root(root)
    parts = root.parts[1:]
    with ExitStack() as stack:
        anchor = stack.enter_context(directory_handle(root.anchor, synchronize=True))
        anchor_identity = directory_identity(anchor)
        volume, suffix = local_ntfs_location(anchor)
        if suffix:
            raise ValueError('Windows guarded drive anchor is not a volume root')
        parent = anchor
        chain = []
        for index, part in enumerate(parts):
            deny = index == len(parts) - 1
            child = stack.enter_context(relative_directory(parent, part, deny_write=deny))
            if local_ntfs_scope(child) != volume:
                raise ValueError('Guarded evidence root crosses local NTFS volume')
            chain.append((parent, part, child, directory_identity(child), deny))
            parent = child
        guard = parent, chain[-1][3]

        def recheck():
            if directory_identity(anchor) != anchor_identity or local_ntfs_location(anchor) != (volume, ''):
                raise ValueError('Windows guarded drive anchor changed')
            # Confirm the currently named drive still resolves to the same root.
            with directory_handle(root.anchor) as current:
                if directory_identity(current) != anchor_identity or local_ntfs_location(current) != (volume, ''):
                    raise ValueError('Windows guarded drive mapping changed')
            for ancestor, part, child, identity, deny in chain:
                if directory_identity(child) != identity:
                    raise ValueError('Windows guarded root ancestor changed')
                with relative_directory(ancestor, part, deny_write=deny) as current:
                    if directory_identity(current) != identity:
                        raise ValueError('Windows guarded root ancestor edge changed')
            check_windows_root(root, guard)

        recheck()
        yield guard
        recheck()


@contextmanager
def pinned_windows_root(root, *, deny_write=False):
    if deny_write:
        with pinned_relative_root(root) as guard:
            yield guard
        return
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

    Guarded mode uses NT RootDirectory-relative opens for descendants;
    compatibility mode retains absolute Win32 opens. Callers validate names.
    """
    if deny_write and volume_scope is None:
        raise ValueError('Windows deny-write volume scope required')
    if deny_write:
        with relative_guarded_file(root, parts, guard, volume_scope) as stream:
            yield stream
        return
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
        with open(path / parts[-1], 'rb', opener=checked_file_fd) as stream:
            check_directories()
            yield stream
            check_directories()



@contextmanager
def relative_guarded_file(root, parts, guard, volume_scope):
    """Retain native parent handles; recheck each edge relative to its parent."""
    check_windows_root(root, guard)
    with ExitStack() as stack:
        parent = guard[0]
        directories = []
        for part in parts[:-1]:
            handle = stack.enter_context(relative_directory(parent, part))
            if local_ntfs_scope(handle) != volume_scope:
                raise ValueError('Guarded evidence directory crosses local NTFS volume')
            directories.append((parent, part, handle, directory_identity(handle)))
            parent = handle

        def check_edges():
            check_windows_root(root, guard)
            for ancestor, part, handle, expected in directories:
                if directory_identity(handle) != expected:
                    raise ValueError('Guarded evidence directory identity changed')
                with relative_directory(ancestor, part) as current:
                    if directory_identity(current) != expected:
                        raise ValueError('Guarded evidence relative directory changed')

        check_edges()
        with relative_leaf(parent, parts[-1]) as stream:
            held = msvcrt.get_osfhandle(stream.fileno())
            if local_ntfs_scope(held) != volume_scope:
                raise ValueError('Guarded evidence leaf crosses local NTFS volume')
            expected = checked_leaf_identity(held)

            def check_leaf():
                if checked_leaf_identity(held) != expected:
                    raise ValueError('Guarded evidence leaf identity changed')
                with relative_leaf(parent, parts[-1]) as current:
                    if checked_leaf_identity(msvcrt.get_osfhandle(current.fileno())) != expected:
                        raise ValueError('Guarded evidence relative leaf changed')

            check_edges()
            check_leaf()
            yield stream
            check_edges()
            check_leaf()
