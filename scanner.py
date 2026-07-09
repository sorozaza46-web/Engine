import struct
from array import array

import winmem

PAGE = 0x1000

VALUE_TYPES = {
    "4 Bytes": ("<i", 4, "i"),
    "Float": ("<f", 4, "f"),
}

EXACT = "Exact Value"
CHANGED = "Changed"
UNCHANGED = "Unchanged"
INCREASED = "Increased"
DECREASED = "Decreased"
SCAN_MODES = [EXACT, CHANGED, UNCHANGED, INCREASED, DECREASED]

CHUNK = 4 * 1024 * 1024
MAX_RESULTS = 10_000_000


def scan_stream(read_fn, base, size, needle, width, chunk=CHUNK, append=None):
    overlap = width - 1
    pos = base
    end = base + size
    carry = b""
    carry_addr = 0
    while pos < end:
        want = min(chunk, end - pos)
        data = read_fn(pos, want)
        rlen = len(data) if data else 0
        if rlen:
            if carry and carry_addr + len(carry) == pos:
                buf = carry + data
                buf_base = carry_addr
            else:
                buf = data
                buf_base = pos
            idx = buf.find(needle)
            while idx != -1:
                addr = buf_base + idx
                if addr % width == 0:
                    if append(addr):
                        return True
                idx = buf.find(needle, idx + 1)
            if overlap and len(buf) >= overlap:
                carry = buf[-overlap:]
                carry_addr = buf_base + len(buf) - overlap
            else:
                carry = b""
        if rlen == want:
            pos += rlen
        else:
            pos = ((pos + rlen) // PAGE + 1) * PAGE
            carry = b""
    return False


class Scanner:
    def __init__(self):
        self.handle = None
        self.type_name = "4 Bytes"
        self.truncated = False
        self._addrs = array("Q")
        self._prevs = None
        self._prev_value = 0
        self.scan_kinds = winmem.ALL_KINDS
        self.writable_only = True

    def attach(self, handle, type_name):
        self.handle = handle
        self.type_name = type_name
        self.reset()

    def reset(self):
        self._addrs = array("Q")
        self._prevs = None
        self.truncated = False

    @property
    def count(self):
        return len(self._addrs)

    def _fmt(self):
        fmt, width, _tc = VALUE_TYPES[self.type_name]
        return fmt, width

    def _prev_of(self, i):
        return self._prev_value if self._prevs is None else self._prevs[i]

    def iter_all(self):
        if self._prevs is None:
            pv = self._prev_value
            for a in self._addrs:
                yield a, pv
        else:
            yield from zip(self._addrs, self._prevs)

    def head(self, limit):
        out = []
        for i in range(min(limit, len(self._addrs))):
            out.append((self._addrs[i], self._prev_of(i)))
        return out

    def find_addr(self, addr):
        try:
            return self._addrs.index(addr)
        except ValueError:
            return -1

    def read_value(self, address):
        fmt, width = self._fmt()
        data = winmem.read_bytes(self.handle, address, width)
        if not data or len(data) < width:
            return None
        return struct.unpack(fmt, data)[0]

    def write_value(self, address, value):
        fmt, _ = self._fmt()
        return winmem.write_bytes(self.handle, address, struct.pack(fmt, value))

    def first_scan(self, value, progress=None):
        fmt, width = self._fmt()
        needle = struct.pack(fmt, value)
        addrs = array("Q")
        self.truncated = False

        def append(addr):
            addrs.append(addr)
            if len(addrs) >= MAX_RESULTS:
                self.truncated = True
                return True
            return False

        def read_fn(addr, n):
            return winmem.read_bytes(self.handle, addr, n)

        for base, size, _protect, _kind in winmem.iter_regions(
            self.handle, self.scan_kinds, self.writable_only
        ):
            stopped = scan_stream(read_fn, base, size, needle, width, CHUNK, append)
            if progress:
                progress(len(addrs))
            if stopped:
                break

        self._addrs = addrs
        self._prevs = None
        self._prev_value = value
        return len(addrs)

    def next_scan(self, mode, value=None, progress=None):
        _, tc = self._fmt()[0], VALUE_TYPES[self.type_name][2]
        new_addrs = array("Q")
        new_prevs = array(tc)
        for i, addr in enumerate(self._addrs):
            cur = self.read_value(addr)
            if cur is None:
                continue
            if _matches(mode, cur, self._prev_of(i), value):
                new_addrs.append(addr)
                new_prevs.append(cur)
            if progress and (i & 0x3FFF) == 0:
                progress(len(new_addrs))
        self._addrs = new_addrs
        self._prevs = new_prevs
        self.truncated = False
        return len(new_addrs)


def _matches(mode, cur, prev, value):
    if mode == EXACT:
        return cur == value
    if mode == CHANGED:
        return cur != prev
    if mode == UNCHANGED:
        return cur == prev
    if mode == INCREASED:
        return cur > prev
    if mode == DECREASED:
        return cur < prev
    return False


def parse_value(text, type_name):
    text = text.strip()
    if type_name == "Float":
        return float(text)
    return int(text, 0)
