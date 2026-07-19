import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

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


def open_process(pid):
    handle = kernel32.OpenProcess(PROCESS_ALL_NEEDED, False, int(pid))
    if not handle:
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, int(pid)
        )
    return handle or None


def close_process(handle):
    if handle:
        kernel32.CloseHandle(handle)


def read_bytes(handle, address, size):
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buf, size, ctypes.byref(read)
    )
    if not ok and read.value == 0:
        return None
    return bytes(buf[: read.value])


def write_bytes(handle, address, data):
    size = len(data)
    buf = (ctypes.c_char * size).from_buffer_copy(data)
    written = ctypes.c_size_t(0)
    ok = kernel32.WriteProcessMemory(
        handle, ctypes.c_void_p(address), buf, size, ctypes.byref(written)
    )
    return bool(ok) and written.value == size


def iter_regions(handle, kinds=ALL_KINDS, writable_only=False):
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
    si = SYSTEM_INFO()
    kernel32.GetNativeSystemInfo(ctypes.byref(si))
    return si.wProcessorArchitecture in (9, 12, 6)


def target_is_64bit(handle):
    if not os_is_64bit():
        return False
    wow64 = wintypes.BOOL()
    if not kernel32.IsWow64Process(handle, ctypes.byref(wow64)):
        return None
    return not bool(wow64.value)


def enable_debug_privilege():
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


# =====================================================================
# Debug API / hardware breakpoints
# =====================================================================

TH32CS_SNAPTHREAD = 0x00000004

THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040
THREAD_ACCESS_NEEDED = (
    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION
)

CREATE_PROCESS_DEBUG_EVENT = 3
CREATE_THREAD_DEBUG_EVENT = 2
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9
EXCEPTION_DEBUG_EVENT = 1

EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_BREAKPOINT = 0x80000003

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

CONTEXT_i386 = 0x00010000
CONTEXT_AMD64 = 0x00100000
CONTEXT_DEBUG_REGISTERS_32 = CONTEXT_i386 | 0x00000010
CONTEXT_DEBUG_REGISTERS_64 = CONTEXT_AMD64 | 0x00000010


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
    ]


class EXCEPTION_RECORD32(ctypes.Structure):
    pass


EXCEPTION_RECORD32._fields_ = [
    ("ExceptionCode", wintypes.DWORD),
    ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.c_void_p),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_void_p * 15),
]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD32),
        ("dwFirstChance", wintypes.DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wintypes.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]


class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("_pad", ctypes.c_byte * 256),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", _DEBUG_EVENT_UNION),
    ]


class FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.DWORD),
        ("StatusWord", wintypes.DWORD),
        ("TagWord", wintypes.DWORD),
        ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.DWORD),
        ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.DWORD),
        ("RegisterArea", ctypes.c_byte * 80),
        ("Cr0NpxState", wintypes.DWORD),
    ]


class CONTEXT32(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", wintypes.DWORD),
        ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", wintypes.DWORD),
        ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD),
        ("Edi", wintypes.DWORD),
        ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD),
        ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD),
        ("Ebp", wintypes.DWORD),
        ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD),
        ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD),
        ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


CONTEXT64_SIZE = 1232


class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("_rest", ctypes.c_byte * (CONTEXT64_SIZE - 256)),
    ]


def alloc_context64():
    size = ctypes.sizeof(CONTEXT64)
    buf = (ctypes.c_byte * (size + 16))()
    addr = ctypes.addressof(buf)
    aligned = (addr + 15) & ~15
    ctx = CONTEXT64.from_address(aligned)
    return buf, ctx


kernel32.DebugActiveProcess.argtypes = [wintypes.DWORD]
kernel32.DebugActiveProcess.restype = wintypes.BOOL
kernel32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
kernel32.DebugActiveProcessStop.restype = wintypes.BOOL
kernel32.DebugSetProcessKillOnExit.argtypes = [wintypes.BOOL]
kernel32.DebugSetProcessKillOnExit.restype = wintypes.BOOL
kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD]
kernel32.WaitForDebugEvent.restype = wintypes.BOOL
kernel32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
kernel32.ContinueDebugEvent.restype = wintypes.BOOL
kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE
kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
kernel32.SuspendThread.restype = wintypes.DWORD
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
kernel32.GetThreadContext.restype = wintypes.BOOL
kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
kernel32.SetThreadContext.restype = wintypes.BOOL


def list_thread_ids(pid):
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if not snapshot or snapshot == -1:
        return []
    tids = []
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(THREADENTRY32)
    try:
        ok = kernel32.Thread32First(snapshot, ctypes.byref(entry))
        while ok:
            if entry.th32OwnerProcessID == pid:
                tids.append(entry.th32ThreadID)
            ok = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return tids


kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]


def _dr7_bits(size_bytes, is64):
    rw = 0b01
    if size_bytes == 1:
        length = 0b00
    elif size_bytes == 2:
        length = 0b01
    elif size_bytes == 8 and is64:
        length = 0b10
    else:
        length = 0b11
    local_enable = 0b1
    return local_enable | (rw << 16) | (length << 18)


def _set_hw_breakpoint_on_thread(tid, address, size_bytes, is64):
    handle = kernel32.OpenThread(THREAD_ACCESS_NEEDED, False, tid)
    if not handle:
        return False
    try:
        kernel32.SuspendThread(handle)
        try:
            if is64:
                buf, ctx = alloc_context64()
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_64
                if not kernel32.GetThreadContext(handle, ctypes.addressof(ctx)):
                    return False
                ctx.Dr0 = address & 0xFFFFFFFFFFFFFFFF
                ctx.Dr7 = _dr7_bits(size_bytes, True)
                ok = kernel32.SetThreadContext(handle, ctypes.addressof(ctx))
            else:
                ctx = CONTEXT32()
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_32
                if not kernel32.GetThreadContext(handle, ctypes.byref(ctx)):
                    return False
                ctx.Dr0 = address & 0xFFFFFFFF
                ctx.Dr7 = _dr7_bits(size_bytes, False)
                ok = kernel32.SetThreadContext(handle, ctypes.byref(ctx))
            return bool(ok)
        finally:
            kernel32.ResumeThread(handle)
    finally:
        kernel32.CloseHandle(handle)


def _clear_hw_breakpoints_on_thread(tid, is64):
    handle = kernel32.OpenThread(THREAD_ACCESS_NEEDED, False, tid)
    if not handle:
        return
    try:
        kernel32.SuspendThread(handle)  # DÜZELTME: Thread dondurulmadan context değiştirilemez!
        try:
            if is64:
                buf, ctx = alloc_context64()
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_64
                if kernel32.GetThreadContext(handle, ctypes.addressof(ctx)):
                    ctx.Dr7 = 0
                    kernel32.SetThreadContext(handle, ctypes.addressof(ctx))
            else:
                ctx = CONTEXT32()
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_32
                if kernel32.GetThreadContext(handle, ctypes.byref(ctx)):
                    ctx.Dr7 = 0
                    kernel32.SetThreadContext(handle, ctypes.byref(ctx))
        finally:
            kernel32.ResumeThread(handle)  # DÜZELTME: Thread'i geri devam ettir
    finally:
        kernel32.CloseHandle(handle)


def catch_memory_access(pid, address, size_bytes, is64, timeout_ms=20000, on_status=None):
    def status(msg):
        if on_status:
            try: on_status(msg)
            except Exception: pass

    if not kernel32.DebugActiveProcess(pid):
        status("DebugActiveProcess başarısız (yönetici olarak çalıştırmayı deneyin).")
        return None

    kernel32.DebugSetProcessKillOnExit(False)

    tids = list_thread_ids(pid)
    for tid in tids:
        _set_hw_breakpoint_on_thread(tid, address, size_bytes, is64)

    hit_addr = None
    import time as _time
    deadline = _time.time() + (timeout_ms / 1000.0)

    try:
        while _time.time() < deadline:
            remaining_ms = max(1, int((deadline - _time.time()) * 1000))
            ev = DEBUG_EVENT()
            if not kernel32.WaitForDebugEvent(ctypes.byref(ev), min(remaining_ms, 500)):
                continue

            code = ev.dwDebugEventCode
            cont_status = DBG_CONTINUE

            if code == CREATE_THREAD_DEBUG_EVENT:
                new_tid = ev.dwThreadId
                _set_hw_breakpoint_on_thread(new_tid, address, size_bytes, is64)

            elif code == EXCEPTION_DEBUG_EVENT:
                exc_code = ev.u.Exception.ExceptionRecord.ExceptionCode
                if exc_code == EXCEPTION_SINGLE_STEP:
                    handle = kernel32.OpenThread(THREAD_ACCESS_NEEDED, False, ev.dwThreadId)
                    if handle:
                        try:
                            if is64:
                                buf, ctx = alloc_context64()
                                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_64
                                if kernel32.GetThreadContext(handle, ctypes.addressof(ctx)):
                                    hit_addr = ctx.Rip
                                    # DÜZELTME: Oyunu devam ettirmeden önce Breakpoint'i KALDIR!
                                    ctx.Dr0 = 0
                                    ctx.Dr7 = 0
                                    kernel32.SetThreadContext(handle, ctypes.addressof(ctx))
                            else:
                                ctx = CONTEXT32()
                                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_32
                                if kernel32.GetThreadContext(handle, ctypes.byref(ctx)):
                                    hit_addr = ctx.Eip
                                    # DÜZELTME: Oyunu devam ettirmeden önce Breakpoint'i KALDIR!
                                    ctx.Dr0 = 0
                                    ctx.Dr7 = 0
                                    kernel32.SetThreadContext(handle, ctypes.byref(ctx))
                        finally:
                            kernel32.CloseHandle(handle)
                    cont_status = DBG_CONTINUE
                else:
                    cont_status = DBG_EXCEPTION_NOT_HANDLED

            kernel32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont_status)

            if hit_addr is not None:
                break
    finally:
        for tid in list_thread_ids(pid):
            _clear_hw_breakpoints_on_thread(tid, is64)
        kernel32.DebugActiveProcessStop(pid)

    if hit_addr is None:
        status("Zaman aşımı: erişim yakalanamadı. Oyun içinde değeri değiştirmeyi deneyin.")
    return hit_addr