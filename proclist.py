import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = -1
MAX_PATH = 260
MAX_MODULE_NAME32 = 255


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]


kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_char * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", ctypes.c_char * MAX_PATH),
    ]


kernel32.Module32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]
kernel32.Module32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]


def list_modules(pid):
    """Return [(name, base_addr, size), ...] for every module loaded in pid.

    Sorted by base address so callers can binary/linear search for the
    module that contains a given absolute address.
    """
    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
    )
    if snapshot == INVALID_HANDLE_VALUE or not snapshot:
        return []

    mods = []
    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    try:
        ok = kernel32.Module32First(snapshot, ctypes.byref(entry))
        while ok:
            name = entry.szModule.decode("mbcs", errors="replace")
            base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
            mods.append((name, int(base), int(entry.modBaseSize)))
            ok = kernel32.Module32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    mods.sort(key=lambda m: m[1])
    return mods


def module_for_address(modules, address):
    """Given a sorted list_modules() result, find which module (if any)
    contains `address`. Returns (name, base) or None."""
    for name, base, size in modules:
        if base <= address < base + size:
            return name, base
    return None


def list_processes():
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE or not snapshot:
        return []

    procs = []
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    try:
        ok = kernel32.Process32First(snapshot, ctypes.byref(entry))
        while ok:
            name = entry.szExeFile.decode("mbcs", errors="replace")
            procs.append((int(entry.th32ProcessID), name))
            ok = kernel32.Process32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    procs.sort(key=lambda p: p[1].lower())
    return procs
