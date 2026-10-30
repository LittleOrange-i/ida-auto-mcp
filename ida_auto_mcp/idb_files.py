"""Look at an IDA database's files before opening it.

While IDA has a database open, its unpacked components (.id0, .id1, .id2,
.nam, .til) sit next to the packed .i64 and IDA keeps the .id0 locked. An
.id0 that is not locked but whose B-tree header still marks it open was left
behind by an IDA that stopped without closing the database, e.g. a crash.
IDA then silently reopens the packed database if there is one, discarding
those leftovers, or else reuses them.

The lock probe and the header check follow the database state probe in
Hex-Rays' ida-nexus (MIT License, see THIRD_PARTY_NOTICES.md).
"""

import errno
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

UNPACKED_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til")

# .id0 B-tree header: a byte that is 1 while the tree is open, then a signature
_OPEN_FLAG_OFFSET = 18
_SIGNATURE = b"B-tree v2"
_HEADER_SIZE = _OPEN_FLAG_OFFSET + 1 + len(_SIGNATURE)


@dataclass
class DatabaseFiles:
    """The files of the database IDA would use for one input file.

    state is one of: "missing" (no database yet), "packed", "in_use" (another
    IDA has it open), "crashed" (leftovers of an unclosed database),
    "unpacked" (closed without packing) or "unknown" (see detail).
    """

    idb: Path
    unpacked: list[Path]
    state: str
    detail: str = ""


def database_stem(path: Path) -> Path:
    """The common base of a database's files.

    IDA keeps the database of a.exe in a.exe.i64, with unpacked components
    a.exe.id0 and so on; an .i64 or .idb path names the database itself.
    """
    if path.suffix.lower() in (".i64", ".idb"):
        return path.with_suffix("")
    return path


def probe(path: Path) -> DatabaseFiles:
    """Classify the database of an input file without opening it in IDA."""
    stem = database_stem(path)
    idb = Path(f"{stem}.i64")
    if not idb.exists() and Path(f"{stem}.idb").exists():
        idb = Path(f"{stem}.idb")
    unpacked = [
        part
        for part in (Path(f"{stem}{suffix}") for suffix in UNPACKED_SUFFIXES)
        if part.exists()
    ]

    id0 = Path(f"{stem}.id0")
    if not id0.exists():
        return DatabaseFiles(idb, unpacked, "packed" if idb.exists() else "missing")
    locked, header, error = _read_header(id0)
    if locked:
        return DatabaseFiles(idb, unpacked, "in_use")
    if header is None:
        return DatabaseFiles(idb, unpacked, "unknown", error or "cannot read .id0")
    open_flag = header[_OPEN_FLAG_OFFSET : _OPEN_FLAG_OFFSET + 1]
    if header[_OPEN_FLAG_OFFSET + 1 :] != _SIGNATURE or open_flag not in (b"\0", b"\1"):
        return DatabaseFiles(idb, unpacked, "unknown", f"unexpected {id0.name} header")
    return DatabaseFiles(idb, unpacked, "crashed" if open_flag == b"\1" else "unpacked")


def back_up_unpacked(files: DatabaseFiles) -> Path:
    """Copy the unpacked components into a new folder next to the database."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for attempt in range(100):
        suffix = f"-{attempt}" if attempt else ""
        backup = files.idb.with_name(f"{files.idb.name}.crash-{stamp}{suffix}")
        try:
            backup.mkdir()
            break
        except FileExistsError:
            continue
    else:
        raise FileExistsError(f"cannot create a backup folder next to {files.idb}")
    for part in files.unpacked:
        shutil.copy2(part, backup / part.name)
    return backup


def _read_header(id0: Path) -> tuple[bool, bytes | None, str | None]:
    """(locked, header, error) for an .id0, without disturbing IDA's lock."""
    if os.name == "nt":
        return _read_header_windows(id0)
    return _read_header_posix(id0)


def _read_header_windows(id0: Path) -> tuple[bool, bytes | None, str | None]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    read_file = kernel32.ReadFile
    read_file.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    read_file.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    generic_read_write = 0x80000000 | 0x40000000
    share_all = 0x1 | 0x2 | 0x4
    open_existing = 3
    # Asking for write access fails with a sharing violation while IDA has
    # the file open
    handle = create_file(
        str(id0), generic_read_write, share_all, None, open_existing, 0, None
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        code = ctypes.get_last_error()
        if code == 32:  # ERROR_SHARING_VIOLATION
            return True, None, None
        return False, None, f"cannot open {id0.name} (Windows error {code})"
    try:
        buffer = ctypes.create_string_buffer(_HEADER_SIZE)
        read = wintypes.DWORD()
        if not read_file(handle, buffer, _HEADER_SIZE, ctypes.byref(read), None):
            code = ctypes.get_last_error()
            return False, None, f"cannot read {id0.name} (Windows error {code})"
        return False, buffer.raw[: read.value], None
    finally:
        close_handle(handle)


def _read_header_posix(id0: Path) -> tuple[bool, bytes | None, str | None]:
    import fcntl

    try:
        fd = os.open(id0, os.O_RDONLY)
    except OSError as e:
        return False, None, f"cannot open {id0.name}: {e}"
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                return True, None, None
            return False, None, f"cannot lock {id0.name}: {e}"
        try:
            return False, os.read(fd, _HEADER_SIZE), None
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
