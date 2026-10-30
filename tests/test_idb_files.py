"""Tests for the database file probe and the loader options. No IDA
installation is needed.

    python -m unittest discover -s tests -v
"""

import os
import tempfile
import unittest
from pathlib import Path

from ida_auto_mcp import idb_files
from ida_auto_mcp.session import LoadOptions


def id0_header(open_flag: int) -> bytes:
    return bytes(18) + bytes([open_flag]) + b"B-tree v2" + bytes(100)


class HeldOpen:
    """Hold a file the way IDA holds an open .id0."""

    def __init__(self, path: Path):
        self.path = path

    def __enter__(self):
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateFileW.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            kernel32.CreateFileW.restype = wintypes.HANDLE
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            # Read access, sharing reads only, like IDA
            self.handle = kernel32.CreateFileW(
                str(self.path), 0x80000000, 0x1, None, 3, 0, None
            )
            self.kernel32 = kernel32
        else:
            import fcntl

            self.fd = os.open(self.path, os.O_RDONLY)
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        if os.name == "nt":
            self.kernel32.CloseHandle(self.handle)
        else:
            os.close(self.fd)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.dir = Path(self._dir.name)
        self.binary = self.dir / "a.exe"
        self.binary.write_bytes(b"MZ")

    def tearDown(self):
        self._dir.cleanup()

    def test_database_stem(self):
        self.assertEqual(idb_files.database_stem(Path("x/a.exe")), Path("x/a.exe"))
        self.assertEqual(idb_files.database_stem(Path("x/a.exe.i64")), Path("x/a.exe"))
        self.assertEqual(idb_files.database_stem(Path("x/a.exe.IDB")), Path("x/a.exe"))

    def test_missing_and_packed(self):
        self.assertEqual(idb_files.probe(self.binary).state, "missing")
        (self.dir / "a.exe.i64").write_bytes(b"IDA2")
        files = idb_files.probe(self.binary)
        self.assertEqual(files.state, "packed")
        self.assertEqual(files.idb, self.dir / "a.exe.i64")
        self.assertEqual(idb_files.probe(self.dir / "a.exe.i64").state, "packed")

    def test_crashed_unpacked_and_unknown(self):
        id0 = self.dir / "a.exe.id0"
        id0.write_bytes(id0_header(1))
        (self.dir / "a.exe.nam").write_bytes(b"names")
        files = idb_files.probe(self.binary)
        self.assertEqual(files.state, "crashed")
        self.assertEqual({p.name for p in files.unpacked}, {"a.exe.id0", "a.exe.nam"})
        id0.write_bytes(id0_header(0))
        self.assertEqual(idb_files.probe(self.binary).state, "unpacked")
        id0.write_bytes(b"garbage")
        self.assertEqual(idb_files.probe(self.binary).state, "unknown")

    def test_in_use(self):
        id0 = self.dir / "a.exe.id0"
        id0.write_bytes(id0_header(1))
        with HeldOpen(id0):
            self.assertEqual(idb_files.probe(self.binary).state, "in_use")
        self.assertEqual(idb_files.probe(self.binary).state, "crashed")

    def test_back_up_unpacked(self):
        (self.dir / "a.exe.i64").write_bytes(b"IDA2")
        (self.dir / "a.exe.id0").write_bytes(id0_header(1))
        (self.dir / "a.exe.til").write_bytes(b"types")
        files = idb_files.probe(self.binary)
        backup = idb_files.back_up_unpacked(files)
        self.assertTrue(backup.name.startswith("a.exe.i64.crash-"))
        self.assertEqual(
            sorted(p.name for p in backup.iterdir()), ["a.exe.id0", "a.exe.til"]
        )
        # The originals stay for IDA
        self.assertTrue((self.dir / "a.exe.id0").exists())
        self.assertNotEqual(idb_files.back_up_unpacked(files), backup)


class LoadOptionsTests(unittest.TestCase):
    def test_switches(self):
        options = LoadOptions(
            processor="arm",
            file_type="Binary file",
            base_address=0x8000000,
            entry_point=0x8000100,
        )
        self.assertEqual(
            options.switches(), '-parm -T"Binary file" -b800000 -i8000100'
        )
        self.assertEqual(LoadOptions(file_type="ELF").switches(), "-TELF")

    def test_empty_options_are_false(self):
        self.assertFalse(LoadOptions())
        self.assertTrue(LoadOptions(base_address=0))

    def test_values_cannot_add_switches(self):
        for kwargs in (
            {"processor": "arm -Sevil.py"},
            {"processor": "-Sevil.py"},
            {"file_type": 'Binary" -Sevil.py'},
            {"file_type": "Binary -Sevil.py"},
            {"file_type": "-Sevil"},
        ):
            with self.assertRaises(ValueError, msg=repr(kwargs)):
                LoadOptions(**kwargs)

    def test_addresses_are_checked(self):
        with self.assertRaises(ValueError):
            LoadOptions(base_address=0x8000001)
        with self.assertRaises(ValueError):
            LoadOptions(base_address=-16)
        with self.assertRaises(ValueError):
            LoadOptions(entry_point=-1)


if __name__ == "__main__":
    unittest.main()
