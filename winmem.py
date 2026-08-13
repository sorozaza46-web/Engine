# --- START OF FILE Engine-main/winmem.py ---

import ctypes
from ctypes import wintypes

# Win32 API Yüklemeleri
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

# İzin Sabitleri
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_ALL_NEEDED = (
    PROCESS_QUERY_INFORMATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE
    | PROCESS_VM_OPERATION
)

# Bellek Türleri ve Koruma Sabitleri
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000
_TYPE_NAMES = {MEM_PRIVATE: "private", MEM_MAPPED: "mapped", MEM_IMAGE: "image"}
ALL_KINDS = ("private", "image", "mapped")

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

WRITABLE = (
    PAGE_READWRITE
    | PAGE_WRITECOPY
    | PAGE_EXECUTE_READWRITE
    | PAGE_EXECUTE_WRITECOPY
)
READABLE = WRITABLE | PAGE_READONLY | PAGE_EXECUTE_READ

PTR_SIZE = ctypes.sizeof(ctypes.c_void_p)

# Debug API Sabitleri ve Struct Yapıları (YENİ EKLENDİ)
DEBUG_PROCESS = 0x00000001
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_DEBUG_EVENT = 1
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_BREAKPOINT = 0x80000003

class EXCEPTION_RECORD(ctypes.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD),
    ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_void_p * 15),
]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", wintypes.DWORD),
    ]

class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO)]

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]

kernel32.DebugActiveProcess.restype = wintypes.BOOL
kernel32.DebugActiveProcess.argtypes = [wintypes.DWORD]

kernel32.WaitForDebugEvent.restype = wintypes.BOOL
kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD]

kernel32.ContinueDebugEvent.restype = wintypes.BOOL
kernel32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]

kernel32.DebugActiveProcessStop.restype = wintypes.BOOL
kernel32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]

class _MBI64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]


class _MBI32(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulong),
        ("AllocationBase", ctypes.c_ulong),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


MEMORY_BASIC_INFORMATION = _MBI64 if PTR_SIZE == 8 else _MBI32
MAX_ADDRESS = 0x7FFFFFFFFFFF if PTR_SIZE == 8 else 0x7FFFFFFF

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]

kernel32.IsWow64Process.restype = wintypes.BOOL
kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.POINTER(ctypes.c_ulong)),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]


kernel32.GetNativeSystemInfo.restype = None
kernel32.GetNativeSystemInfo.argtypes = [ctypes.POINTER(SYSTEM_INFO)]

HOST_IS_64BIT = PTR_SIZE == 8


# --- Fonksiyonlar ---

def catch_memory_access(pid, target_addr, watch_size, is_64, on_hit, stop_event, on_status=None):
    """
    Hedef sürece debugger olarak bağlanır. Donanımsal kesmeler (EXCEPTION_SINGLE_STEP) 
    üzerinden erişimleri yakalar. (Tam doğru kullanım için DR0-DR3 ayarlanması gerekir).
    """
    if not kernel32.DebugActiveProcess(pid):
        if on_status:
            on_status("[!] Sürece debug modunda bağlanılamadı. Uygulamayı Yönetici (Administrator) olarak açın.")
        return

    if on_status:
        on_status(f"[*] Debugger başarıyla bağlandı. 0x{target_addr:X} izleniyor...")
        on_status("[!] Not: Tam HW Breakpoint kontrolü Python'da karmaşıktır. Mevcut debug döngüsü devrede.")

    dbg_event = DEBUG_EVENT()
    
    try:
        while not stop_event.is_set():
            # Debug eventleri 100ms zaman aşımıyla dinle
            if kernel32.WaitForDebugEvent(ctypes.byref(dbg_event), 100):
                continue_status = DBG_CONTINUE
                
                # Sadece istisnaları (Exceptions) kontrol et
                if dbg_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                    code = dbg_event.u.Exception.ExceptionRecord.ExceptionCode
                    addr = dbg_event.u.Exception.ExceptionRecord.ExceptionAddress
                    
                    if code in (EXCEPTION_SINGLE_STEP, EXCEPTION_BREAKPOINT):
                        if addr:
                            on_hit(int(addr))
                    else:
                        continue_status = DBG_EXCEPTION_NOT_HANDLED

                # Oyunu veya uygulamayı çalıştırmaya devam et
                kernel32.ContinueDebugEvent(dbg_event.dwProcessId, dbg_event.dwThreadId, continue_status)
    finally:
        # Stop edildiğinde oyunun çökmemesi için debugger bağlantısını kopardığımızdan emin olun
        kernel32.DebugActiveProcessStop(pid)
        if on_status:
            on_status("[*] İzleme durduruldu ve debug bağlantısı sorunsuz kesildi.")


def enable_debug_privilege():
    """Süreç belleğine erişim için SeDebugPrivilege yetkisini etkinleştirir."""
    SE_PRIVILEGE_ENABLED = 0x00000002
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * 1),
        ]

    try:
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(token),
        ):
            return False
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ok = advapi32.AdjustTokenPrivileges(
            token, False, ctypes.byref(tp), 0, None, None
        )
        kernel32.CloseHandle(token)
        return bool(ok)
    except Exception:
        return False


def open_process(pid):
    """Belirtilen PID'ye sahip süreci açar ve bir handle döndürür."""
    handle = kernel32.OpenProcess(PROCESS_ALL_NEEDED, False, int(pid))
    if not handle:
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, int(pid)
        )
    return handle or None


def close_process(handle):
    """Açık olan süreç handle'ını kapatır."""
    if handle:
        kernel32.CloseHandle(handle)


def read_bytes(handle, address, size):
    """Belirtilen adresten veri okur."""
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buf, size, ctypes.byref(read)
    )
    if not ok and read.value == 0:
        return None
    return bytes(buf[: read.value])


def write_bytes(handle, address, data):
    """Belirtilen adrese veri yazar."""
    size = len(data)
    buf = (ctypes.c_char * size).from_buffer_copy(data)
    written = ctypes.c_size_t(0)
    ok = kernel32.WriteProcessMemory(
        handle, ctypes.c_void_p(address), buf, size, ctypes.byref(written)
    )
    return bool(ok) and written.value == size


def iter_regions(handle, kinds=ALL_KINDS, writable_only=False):
    """Hedef sürecin bellek bölgelerini (regions) tarar."""
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)
    wanted = WRITABLE if writable_only else READABLE
    while address < MAX_ADDRESS:
        ret = kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size
        )
        if not ret:
            break
        base = int(mbi.BaseAddress)
        size = int(mbi.RegionSize)
        if size == 0:
            break
        protect = int(mbi.Protect)
        kind = _TYPE_NAMES.get(int(mbi.Type))
        if (
            int(mbi.State) == MEM_COMMIT
            and kind in kinds
            and not (protect & PAGE_GUARD)
            and not (protect & PAGE_NOACCESS)
            and (protect & wanted)
        ):
            yield base, size, protect, kind
        address = base + size


def os_is_64bit():
    """İşletim sisteminin 64-bit olup olmadığını kontrol eder."""
    si = SYSTEM_INFO()
    kernel32.GetNativeSystemInfo(ctypes.byref(si))
    return si.wProcessorArchitecture in (9, 12, 6)


def target_is_64bit(handle):
    """Hedef sürecin 64-bit olup olmadığını kontrol eder."""
    if not os_is_64bit():
        return False
    wow64 = wintypes.BOOL()
    if not kernel32.IsWow64Process(handle, ctypes.byref(wow64)):
        return None
    return not bool(wow64.value)