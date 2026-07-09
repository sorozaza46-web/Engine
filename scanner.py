import struct
import re
from array import array
import winmem

PAGE = 0x1000
CHUNK = 4 * 1024 * 1024
MAX_RESULTS = 10_000_000

EXACT = "Exact Value"
CHANGED = "Changed"
UNCHANGED = "Unchanged"
INCREASED = "Increased"
DECREASED = "Decreased"
SCAN_MODES = [EXACT, CHANGED, UNCHANGED, INCREASED, DECREASED]


class Scanner:
    def __init__(self):
        self.handle = None
        self.type_name = "4 Bytes"  
        self.truncated = False
        self._addrs = array("Q")
        self._prevs = []  
        self._types = []  
        self.scan_kinds = winmem.ALL_KINDS
        self.writable_only = True

    def attach(self, handle, type_name):
        self.handle = handle
        self.type_name = type_name
        self.reset()

    def reset(self):
        self._addrs = array("Q")
        self._prevs = []
        self._types = []
        self.truncated = False

    @property
    def count(self):
        return len(self._addrs)

    def iter_all(self):
        for i in range(len(self._addrs)):
            t = self._types[i] if self._types else self.type_name
            yield self._addrs[i], self._prevs[i], t

    def _prepare_needles(self, text):
        needles = []
        text_str = str(text).strip()

        if self.type_name in ("4 Bytes", "All Types"):
            try:
                val = int(text_str, 0)
                if -2147483648 <= val <= 2147483647:
                    needles.append(("4 Bytes", struct.pack("<i", val), 4, False))
            except ValueError: pass

        if self.type_name in ("Float", "All Types"):
            try:
                val = float(text_str)
                needles.append(("Float", struct.pack("<f", val), 4, False))
            except ValueError: pass

        if self.type_name in ("String (ASCII)", "All Types") and text_str:
            needles.append(("String (ASCII)", text_str.encode('ascii', errors='ignore'), 1, False))

        if self.type_name in ("String (UTF-16)", "All Types") and text_str:
            needles.append(("String (UTF-16)", text_str.encode('utf-16le', errors='ignore'), 2, False))

        if self.type_name in ("Hex / AOB", "All Types"):
            clean = re.sub(r'\s+', '', text_str).upper()
            if all(c in '0123456789ABCDEF?' for c in clean) and len(clean) >= 2:
                if '?' in clean:
                    reg_parts = []
                    for i in range(0, len(clean), 2):
                        pair = clean[i:i+2]
                        if '?' in pair: reg_parts.append(b'.')
                        else: reg_parts.append(re.escape(bytes.fromhex(pair)))
                    needles.append(("Hex / AOB", re.compile(b''.join(reg_parts), re.DOTALL), 1, True))
                else:
                    try: needles.append(("Hex / AOB", bytes.fromhex(clean), 1, False))
                    except ValueError: pass

        return needles

    def first_scan(self, text_value):
        self.reset()
        needles = self._prepare_needles(text_value)
        if not needles: return 0

        addrs = array("Q")
        prevs = []
        types = []

        def append_match(addr, name, raw_len, data, idx):
            if len(addrs) >= MAX_RESULTS:
                self.truncated = True
                return True
            addrs.append(addr)
            if "String" in name:
                prevs.append(data[idx:idx+raw_len].decode('ascii', errors='replace'))
            elif name == "Hex / AOB":
                prevs.append(data[idx:idx+raw_len].hex().upper())
            elif name == "Float":
                prevs.append(struct.unpack("<f", data[idx:idx+4])[0])
            else:
                prevs.append(struct.unpack("<i", data[idx:idx+4])[0])
            
            if self.type_name == "All Types": types.append(name)
            return False

        for base, size, _, _ in winmem.iter_regions(self.handle, self.scan_kinds, self.writable_only):
            pos = base
            end = base + size
            while pos < end:
                want = min(CHUNK, end - pos)
                data = winmem.read_bytes(self.handle, pos, want)
                if not data:
                    pos = ((pos + CHUNK) // PAGE + 1) * PAGE
                    continue

                for name, pattern, align, is_regex in needles:
                    if is_regex:
                        for match in pattern.finditer(data):
                            idx = match.start()
                            addr = pos + idx
                            if addr % align == 0:
                                if append_match(addr, name, len(match.group()), data, idx): break
                    else:
                        idx = data.find(pattern)
                        while idx != -1:
                            addr = pos + idx
                            if addr % align == 0:
                                if append_match(addr, name, len(pattern), data, idx): break
                            idx = data.find(pattern, idx + 1)
                pos += len(data)

        self._addrs = addrs
        self._prevs = prevs
        self._types = types
        return len(addrs)

    def read_bytes_raw(self, address, size):
        if not self.handle: return b""
        return winmem.read_bytes(self.handle, address, size) or b""

    def read_value_dynamic(self, address, type_name):
        if type_name == "4 Bytes":
            d = winmem.read_bytes(self.handle, address, 4)
            return struct.unpack("<i", d)[0] if d and len(d) == 4 else None
        elif type_name == "Float":
            d = winmem.read_bytes(self.handle, address, 4)
            return struct.unpack("<f", d)[0] if d and len(d) == 4 else None
        elif type_name == "String (ASCII)":
            d = winmem.read_bytes(self.handle, address, 16)
            if not d: return None
            return d.split(b'\x00')[0].decode('ascii', errors='ignore')
        elif type_name == "String (UTF-16)":
            d = winmem.read_bytes(self.handle, address, 32)
            if not d: return None
            return d.split(b'\x00\x00')[0].decode('utf-16le', errors='ignore')
        elif type_name == "Hex / AOB":
            d = winmem.read_bytes(self.handle, address, 4)
            return d.hex().upper() if d else None
        return None

    def write_value_dynamic(self, address, text_val, type_name):
        try:
            if type_name == "4 Bytes": buf = struct.pack("<i", int(text_val, 0))
            elif type_name == "Float": buf = struct.pack("<f", float(text_val))
            elif type_name == "String (ASCII)": buf = text_val.encode('ascii', errors='ignore') + b'\x00'
            elif type_name == "String (UTF-16)": buf = text_val.encode('utf-16le', errors='ignore') + b'\x00\x00'
            elif type_name == "Hex / AOB": buf = bytes.fromhex(text_val.replace(" ", ""))
            else: return False
            return winmem.write_bytes(self.handle, address, buf)
        except Exception: return False

    def next_scan(self, mode, text_value=None):
        new_addrs = array("Q")
        new_prevs = []
        new_types = []

        for i, addr in enumerate(self._addrs):
            t = self._types[i] if self._types else self.type_name
            cur = self.read_value_dynamic(addr, t)
            if cur is None: continue

            matched = False
            prev = self._prevs[i]

            if mode == EXACT:
                if t in ("4 Bytes", "Float"):
                    try: matched = (cur == float(text_value) if t == "Float" else cur == int(text_value, 0))
                    except ValueError: pass
                else: matched = (str(text_value).lower() in str(cur).lower())
            elif mode == CHANGED: matched = (cur != prev)
            elif mode == UNCHANGED: matched = (cur == prev)
            elif mode == INCREASED and t in ("4 Bytes", "Float"): matched = (cur > prev)
            elif mode == DECREASED and t in ("4 Bytes", "Float"): matched = (cur < prev)

            if matched:
                new_addrs.append(addr)
                new_prevs.append(cur)
                if self._types: new_types.append(t)

        self._addrs = new_addrs
        self._prevs = new_prevs
        self._types = new_types
        return len(new_addrs)
                
