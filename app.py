# --- START OF FILE Engine-main/app.py ---

import sys
import threading
import json
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import re
import struct
import time
from array import array
import ctypes
from ctypes import wintypes

# Capstone Gerçek Disassembler Entegrasyonu
try:
    from capstone import *
    from capstone.x86 import *
except ImportError:
    Cs = None
    X86_OP_MEM = 3  # stable capstone enum value, used as a safe fallback

import proclist
import scanner
import winmem

# Optional - lets the pointer scanner check millions of candidate slots
# with vectorized C-speed comparisons instead of a Python-level loop.
try:
    import numpy as np
except ImportError:
    np = None


def _enable_dpi_awareness():
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _system_dpi():
    try:
        hdc = ctypes.windll.user32.GetDC(0)
        dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)
        ctypes.windll.user32.ReleaseDC(0, hdc)
        return dpi or 96
    except Exception:
        return 96


_enable_dpi_awareness()

BG = "#1e1f22"
PANEL = "#26282c"
ROW_ALT = "#212327"
FIELD = "#161719"
FG = "#e6e8ea"
MUTED = "#9aa0a6"
BORDER = "#34373c"
SEL = "#2d4f6e"
HEAD = "#2c2e33"
THUMB = "#3f434a"
BLUE = "#4b8bbe"
YELLOW = "#FFD43B"
OK = "#7ee787"

UIFONT = ("Segoe UI", 9)
HEADFONT = ("Segoe UI", 9, "bold")
MONO = ("Consolas", 10)

SYSTEM_DLL_BLACKLIST = {
    "libcef.dll", "ntdll.dll", "kernel32.dll", "user32.dll", "gdi32.dll",
    "msvcrt.dll", "imm32.dll", "combase.dll", "rpcrt4.dll", "ws2_32.dll",
    "shell32.dll", "ole32.dll", "oleaut32.dll", "shlwapi.dll", "kernelbase.dll",
    "d3d11.dll", "dxgi.dll", "d3d9.dll", "d3d12.dll", "openal32.dll", "openal.dll",
    "nvoglv64.dll", "amd_ags_x64.dll", "vulkan-1.dll"
}


def resolve_pointer_path(handle, pid, base_str, offsets_list):
    """
    Dinamik olarak base_str (örn: 'game.exe+0x1A20') ve offset zincirini ([0x20, 0x10])
    çözerek bellekteki nihai canlı hedef adresi hesaplar.
    """
    try:
        if not handle or not pid:
            return None

        modules = proclist.list_modules(pid)
        base_addr = 0

        if "+" in base_str:
            parts = base_str.split("+", 1)
            mod_name = parts[0].strip().lower()
            mod_offset = int(parts[1].strip(), 16)
            for m_name, m_base, _ in modules:
                if m_name.lower() == mod_name:
                    base_addr = m_base + mod_offset
                    break
        else:
            base_addr = int(base_str, 0)

        if not base_addr:
            return None

        is_64 = winmem.target_is_64bit(handle)
        ptr_size = 8 if is_64 else 4
        unpack_fmt = "<Q" if is_64 else "<I"

        curr = base_addr
        for idx, off in enumerate(offsets_list):
            raw = winmem.read_bytes(handle, curr, ptr_size)
            if not raw or len(raw) < ptr_size:
                return None
            ptr_val = struct.unpack(unpack_fmt, raw)[0]
            curr = ptr_val + off

        return curr
    except Exception:
        return None


def dark_titlebar(window):
    if sys.platform != "win32":
        return False
    try:
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id()) or window.winfo_id()
        enable = ctypes.c_int(1)
        dwm = ctypes.windll.dwmapi
        for attr in (20, 19):
            if dwm.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(enable), ctypes.sizeof(enable)) == 0:
                ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0027)
                return True
    except Exception:
        pass
    return False


def make_logo(parent, px=46, bg=BG):
    c = tk.Canvas(parent, width=px, height=px, bg=bg, highlightthickness=0, bd=0)
    s = px / 100.0
    GREEN = "#6fbf4f"
    seam = max(1, px * 0.02)

    def poly(points, fill, outline=bg, width=seam):
        flat = [v * s for xy in points for v in xy]
        c.create_polygon(flat, smooth=True, fill=fill, outline=outline, width=width)

    def line(points, fill, width):
        flat = [v * s for xy in points for v in xy]
        c.create_line(flat, smooth=True, fill=fill, width=width, capstyle="round")

    poly([(50, 24), (58, 42), (44, 60), (56, 80), (50, 94), (34, 86), (19, 60), (23, 39)], BLUE)
    poly([(50, 24), (78, 39), (82, 60), (66, 86), (50, 94), (56, 80), (44, 60), (58, 42)], YELLOW)
    for tip in ((42, 8), (50, 5), (57, 9)):
        line([(50, 24), tip], GREEN, max(2, px * 0.045))
    return c


def stripe(tree):
    tree.tag_configure("odd", background=PANEL)
    tree.tag_configure("even", background=ROW_ALT)


def row_tag(i):
    return "even" if i % 2 else "odd"


class ProcessDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.withdraw()
        self.title("Attach to process")
        self.geometry("440x480")
        self.configure(bg=BG)
        self.transient(master)
        self.result = None

        self._all = proclist.list_processes()

        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._refill())
        ent = ttk.Entry(top, textvariable=self.filter_var)
        ent.pack(side="left", fill="x", expand=True, padx=4)
        ent.focus_set()
        ent.icursor("end")
        ent.bind("<Return>", lambda _e: self._choose())
        ttk.Button(top, text="Refresh", command=self._reload).pack(side="left")

        wrap = ttk.Frame(self, padding=(6, 0))
        wrap.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(wrap, columns=("pid", "name"), show="headings", selectmode="browse")
        self.tree.heading("pid", text="PID", anchor="e")
        self.tree.heading("name", text="Process", anchor="w")
        self.tree.column("pid", width=80, anchor="e")
        self.tree.column("name", width=320, anchor="w")
        stripe(self.tree)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda _e: self._choose())

        btns = ttk.Frame(self, padding=6)
        btns.pack(fill="x")
        ttk.Button(btns, text="Attach", style="Accent.TButton", command=self._choose).pack(side="right")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right", padx=4)

        self._refill()
        dark_titlebar(self)
        self.deiconify()
        self.grab_set()
        self.wait_window(self)

    def _reload(self):
        self._all = proclist.list_processes()
        self._refill()

    def _refill(self):
        WINDOWS_BLACKLIST = {
            "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe", 
            "services.exe", "lsass.exe", "smss.exe", "system", "idle",
            "explorer.exe", "taskhostw.exe", "spoolsv.exe", "runtimebroker.exe",
            "searchindexer.exe", "ctfmon.exe", "fontdrvhost.exe", "dwm.exe",
            "lsiso.exe", "sihost.exe", "conhost.exe", "smartscreen.exe"
        }

        needle = self.filter_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        i = 0
        for pid, name in self._all:
            if not name or name.lower() in WINDOWS_BLACKLIST:
                continue
                
            if needle in name.lower() or needle in str(pid):
                self.tree.insert("", "end", tags=(row_tag(i),), values=(pid, name))
                i += 1

    def _choose(self):
        sel = self.tree.selection()
        if not sel: return
        pid, name = self.tree.item(sel[0], "values")
        self.result = (int(pid), name)
        self.destroy()


class _AskString(tk.Toplevel):
    def __init__(self, master, title, prompt, initial=""):
        super().__init__(master)
        self.withdraw()
        self.title(title)
        self.configure(bg=BG)
        self.resizable(False, False)
        self.transient(master)
        self.result = None

        frm = ttk.Frame(self, padding=14)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text=prompt).pack(anchor="w")
        self.var = tk.StringVar(value=initial)
        ent = ttk.Entry(frm, textvariable=self.var, width=36)
        ent.pack(fill="x", pady=(8, 12))
        ent.focus_set()
        ent.icursor("end")
        ent.bind("<Return>", lambda _e: self._ok())
        ent.bind("<Escape>", lambda _e: self.destroy())

        btns = ttk.Frame(frm)
        btns.pack(fill="x")
        ttk.Button(btns, text="OK", style="Accent.TButton", command=self._ok).pack(side="right")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right", padx=6)

        self.geometry(f"+{master.winfo_rootx() + 60}+{master.winfo_rooty() + 90}")
        dark_titlebar(self)
        self.deiconify()
        self.grab_set()
        self.wait_window(self)

    def _ok(self):
        self.result = self.var.get()
        self.destroy()


def ask_string(master, title, prompt, initial=""):
    return _AskString(master, title, prompt, initial).result


class AddAddressDialog(tk.Toplevel):
    """
    Manuel Adres veya Multi-Level Pointer ekleme penceresi.
    Canlı çözümleme (Live preview) yaparak kullanıcının doğru adresi/değeri
    girdiğini anlık olarak gösterir.
    """
    def __init__(self, master_app):
        super().__init__(master_app)
        self.withdraw()
        self.title("Manuel Adres / Pointer Ekle")
        self.geometry("520x460")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.transient(master_app)

        self.app = master_app
        
        frm = ttk.Frame(self, padding=14)
        frm.pack(fill="both", expand=True)

        # 1. Açıklama
        ttk.Label(frm, text="Açıklama (Description):").pack(anchor="w")
        self.desc_var = tk.StringVar(value="Yeni Pointer / Adres")
        ent_desc = ttk.Entry(frm, textvariable=self.desc_var)
        ent_desc.pack(fill="x", pady=(3, 10))

        # 2. Veri Tipi
        ttk.Label(frm, text="Veri Tipi (Type):").pack(anchor="w")
        self.type_var = tk.StringVar(value=self.app.type_var.get() if self.app.type_var.get() != "All Types" else "4 Bytes")
        combo_type = ttk.Combobox(frm, textvariable=self.type_var, values=["4 Bytes", "Float", "Double", "String (ASCII)", "String (UTF-16)", "Hex / AOB"], state="readonly")
        combo_type.pack(fill="x", pady=(3, 10))
        combo_type.bind("<<ComboboxSelected>>", lambda _e: self._update_preview())

        # 3. Pointer Checkbox
        self.is_ptr_var = tk.BooleanVar(value=True)
        chk_ptr = ttk.Checkbutton(frm, text="📌 Bu bir Pointer (İşaretçi Zinciri)", variable=self.is_ptr_var, command=self._toggle_mode)
        chk_ptr.pack(anchor="w", pady=(0, 10))

        # 4. Giriş Alanları Paneli
        self.input_frame = ttk.Frame(frm)
        self.input_frame.pack(fill="x", pady=(0, 10))

        # Normal Adres Alanı
        self.lbl_addr = ttk.Label(self.input_frame, text="Statik Adres (Hex):")
        self.addr_var = tk.StringVar(value="0x")
        self.addr_var.trace_add("write", lambda *_: self._update_preview())
        self.ent_addr = ttk.Entry(self.input_frame, textvariable=self.addr_var)

        # Pointer Base Alanı
        self.lbl_base = ttk.Label(self.input_frame, text="Base Address (Örn: game.exe+0x1FD680 veya 0x7FF...):")
        default_base = f"{self.app.proc_name}+0x" if self.app.proc_name else "0x"
        self.base_var = tk.StringVar(value=default_base)
        self.base_var.trace_add("write", lambda *_: self._update_preview())
        self.ent_base = ttk.Entry(self.input_frame, textvariable=self.base_var)

        # Pointer Offsetler Alanı
        self.lbl_offsets = ttk.Label(self.input_frame, text="Offsetler (Virgülle veya boşlukla ayırın, Örn: 0x18, 0x0, 0x14):")
        self.offsets_var = tk.StringVar(value="0x0")
        self.offsets_var.trace_add("write", lambda *_: self._update_preview())
        self.ent_offsets = ttk.Entry(self.input_frame, textvariable=self.offsets_var)

        # 5. Canlı Önizleme / Doğrulama Kutusu
        preview_box = ttk.LabelFrame(frm, text="Canlı Doğrulama (Live Verification)", padding=8)
        preview_box.pack(fill="x", pady=(0, 14))

        self.preview_lbl_addr = ttk.Label(preview_box, text="🎯 Çözümlenen Canlı Adres: --", font=HEADFONT, foreground=MUTED)
        self.preview_lbl_addr.pack(anchor="w")

        self.preview_lbl_val = ttk.Label(preview_box, text="💎 Okunan Canlı Değer: --", font=HEADFONT, foreground=MUTED)
        self.preview_lbl_val.pack(anchor="w", pady=(3, 0))

        # 6. Butonlar
        btns = ttk.Frame(frm)
        btns.pack(fill="x", side="bottom")
        ttk.Button(btns, text="Ekle (Add to Table)", style="Accent.TButton", command=self._confirm).pack(side="right")
        ttk.Button(btns, text="İptal", command=self.destroy).pack(side="right", padx=6)

        self._toggle_mode()
        self.geometry(f"+{master_app.winfo_rootx() + 80}+{master_app.winfo_rooty() + 80}")
        dark_titlebar(self)
        self.deiconify()
        self.grab_set()

    def _toggle_mode(self):
        for widget in self.input_frame.winfo_children():
            widget.pack_forget()

        if self.is_ptr_var.get():
            self.lbl_base.pack(anchor="w")
            self.ent_base.pack(fill="x", pady=(3, 8))
            self.lbl_offsets.pack(anchor="w")
            self.ent_offsets.pack(fill="x", pady=(3, 0))
        else:
            self.lbl_addr.pack(anchor="w")
            self.ent_addr.pack(fill="x", pady=(3, 0))

        self._update_preview()

    def _parse_offsets(self):
        txt = self.offsets_var.get()
        matches = re.findall(r'0x[0-9a-fA-F]+|-?\b\d+\b', txt)
        res = []
        for m in matches:
            try:
                res.append(int(m, 0))
            except ValueError:
                pass
        return res

    def _update_preview(self):
        if not self.app.scanner.handle:
            self.preview_lbl_addr.config(text="🎯 Süreç Bağlı Değil (Attach to process)", foreground="#d0686b")
            self.preview_lbl_val.config(text="💎 Canlı Değer: --", foreground=MUTED)
            return

        t_name = self.type_var.get()

        if self.is_ptr_var.get():
            base_str = self.base_var.get().strip()
            offsets = self._parse_offsets()
            if not base_str:
                self.preview_lbl_addr.config(text="🎯 Base adresi yazın...", foreground=MUTED)
                self.preview_lbl_val.config(text="💎 Canlı Değer: --", foreground=MUTED)
                return

            resolved = resolve_pointer_path(self.app.scanner.handle, self.app.current_pid, base_str, offsets)
            if resolved:
                val = self.app.scanner.read_value_dynamic(resolved, t_name)
                val_str = self.app._fmt_value(val) if val is not None else "??"
                self.preview_lbl_addr.config(text=f"🎯 Çözümlenen Canlı Adres: 0x{resolved:X}", foreground=OK)
                self.preview_lbl_val.config(text=f"💎 Okunan Canlı Değer: {val_str}", foreground=YELLOW)
            else:
                self.preview_lbl_addr.config(text="🎯 [!] Pointer çözülemedi (Base veya Offset geçersiz)", foreground="#d0686b")
                self.preview_lbl_val.config(text="💎 Canlı Değer: ??", foreground=MUTED)
        else:
            addr_str = self.addr_var.get().strip()
            try:
                addr = int(addr_str, 0)
                val = self.app.scanner.read_value_dynamic(addr, t_name)
                val_str = self.app._fmt_value(val) if val is not None else "??"
                self.preview_lbl_addr.config(text=f"🎯 Hedef Adres: 0x{addr:X}", foreground=OK)
                self.preview_lbl_val.config(text=f"💎 Okunan Canlı Değer: {val_str}", foreground=YELLOW)
            except ValueError:
                self.preview_lbl_addr.config(text="🎯 [!] Geçersiz Hex Adres formatı", foreground="#d0686b")
                self.preview_lbl_val.config(text="💎 Canlı Değer: --", foreground=MUTED)

    def _confirm(self):
        desc = self.desc_var.get().strip() or "Manual Address"
        t_name = self.type_var.get()

        if self.is_ptr_var.get():
            base_str = self.base_var.get().strip()
            offsets = self._parse_offsets()
            if not base_str:
                messagebox.showerror("Hata", "Lütfen geçerli bir Base Adres girin.")
                return

            self.app._add_pointer_table_row(base_str, offsets, t_name, desc)
            self.app._set_status(f"Pointer başarıyla tabloya eklendi: {base_str}")
        else:
            addr_str = self.addr_var.get().strip()
            try:
                addr = int(addr_str, 0)
            except ValueError:
                messagebox.showerror("Hata", "Lütfen geçerli bir Hex Adres girin.")
                return

            self.app._add_table_row(addr, t_name, desc)
            self.app._set_status(f"Adres başarıyla tabloya eklendi: 0x{addr:X}")

        self.destroy()


class SheetOnion(tk.Tk):
    DISPLAY_LIMIT = 2000

    def __init__(self):
        super().__init__()
        try:
            self.tk.call("tk", "scaling", _system_dpi() / 72.0)
        except Exception:
            pass
        self.title("Sheet Onion - Advanced Memory Scanner & Pointer Engine")
        self.geometry("1000x900")
        self.minsize(680, 480)
        self.configure(bg=BG)

        self.scanner = scanner.Scanner()
        self.proc_name = None
        self.current_pid = None
        self.scanning = False

        winmem.enable_debug_privilege()

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

        self._apply_theme()
        self._build_toolbar()
        self._build_results()
        self._build_table()
        self._build_statusbar()
        self._build_context_menu()
        self._set_status("Not attached. Click 'Attach to process' to start.")

        # Kısayollar
        self.bind("<Control-s>", lambda _e: self._save_table())
        self.bind("<Control-o>", lambda _e: self._load_table())

        self.freeze_running = True
        self.freeze_thread = threading.Thread(target=self._freeze_loop, daemon=True)
        self.freeze_thread.start()

        dark_titlebar(self)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._tick()

    def _apply_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=FG, fieldbackground=FIELD,
                        bordercolor=BG, lightcolor=BG, darkcolor=BG,
                        troughcolor=FIELD, focuscolor=BG, insertcolor=FG,
                        borderwidth=0, relief="flat", font=UIFONT)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("TLabelframe", background=BG, borderwidth=0, relief="flat")
        style.configure("TLabelframe.Label", background=BG, foreground=MUTED, font=HEADFONT)
        style.configure("TRadiobutton", background=BG, foreground=FG, focuscolor=BG)
        style.map("TRadiobutton", background=[("active", BG)], indicatorcolor=[("selected", BLUE), ("!selected", FIELD)])
        style.configure("TButton", background=PANEL, foreground=FG, borderwidth=0, relief="flat", padding=(10, 5), focuscolor=BG)
        style.map("TButton", background=[("pressed", "#3a3e44"), ("active", "#34373c"), ("disabled", "#222427")], foreground=[("disabled", "#5c5f63")])
        style.configure("Accent.TButton", background=BLUE, foreground="#0c1116", font=HEADFONT, padding=(12, 5))
        style.map("Accent.TButton", background=[("pressed", "#3d76a3"), ("active", "#5a9bcd"), ("disabled", "#2a3d4d")], foreground=[("disabled", "#7d8a93")])
        style.configure("TCheckbutton", background=BG, foreground=FG, focuscolor=BG)
        style.map("TCheckbutton", background=[("active", BG)], indicatorcolor=[("selected", BLUE), ("!selected", FIELD)])

        for name in ("TEntry", "TCombobox"):
            style.configure(name, fieldbackground=FIELD, foreground=FG, bordercolor=BORDER, borderwidth=1, relief="flat", insertcolor=FG, arrowcolor=MUTED, padding=4)
            style.map(name, bordercolor=[("focus", BLUE)])
        style.map("TCombobox", fieldbackground=[("readonly", FIELD)], foreground=[("readonly", FG)], selectbackground=[("readonly", FIELD)], selectforeground=[("readonly", FG)])

        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG, borderwidth=0, relief="flat", rowheight=25, font=MONO)
        style.map("Treeview", background=[("selected", SEL)], foreground=[("selected", "#ffffff")])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.configure("Treeview.Heading", background=HEAD, foreground=MUTED, relief="flat", borderwidth=0, padding=(8, 7), font=HEADFONT)
        style.map("Treeview.Heading", background=[("active", "#34373c")], foreground=[("active", FG)])

        style.layout("Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
        style.configure("Vertical.TScrollbar", background=THUMB, troughcolor=BG, bordercolor=BG, borderwidth=0, relief="flat", width=12)
        style.map("Vertical.TScrollbar", background=[("active", "#4c515a")])
        style.configure("Status.TLabel", background="#141517", foreground=MUTED, font=UIFONT)

        self.option_add("*TCombobox*Listbox.background", PANEL)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", SEL)
        self.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        self.option_add("*TCombobox*Listbox.font", MONO)
        self.option_add("*TCombobox*Listbox.borderWidth", 0)

    def _build_statusbar(self):
        self.status = ttk.Label(self, style="Status.TLabel", anchor="w", padding=5)
        self.status.grid(row=3, column=0, sticky="ew")

    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=8)
        bar.grid(row=0, column=0, sticky="ew")
        bar.columnconfigure(5, weight=1)

        self.attach_btn = ttk.Button(bar, text="Attach to process", command=self.attach)
        self.attach_btn.grid(row=0, column=0, sticky="w")
        self.proc_label = ttk.Label(bar, text="[ no process ]", foreground="#d0686b")
        self.proc_label.grid(row=0, column=1, columnspan=4, sticky="w", padx=8)

        ttk.Label(bar, text="Pattern / Value:").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.value_var = tk.StringVar()
        self.value_entry = ttk.Entry(bar, textvariable=self.value_var, width=22)
        self.value_entry.grid(row=1, column=1, sticky="w", pady=(10, 0))
        self.value_entry.bind("<Return>", lambda _e: self._scan_clicked())

        ttk.Label(bar, text="Type:").grid(row=1, column=2, sticky="e", pady=(10, 0), padx=(5,0))
        self.type_var = tk.StringVar(value="4 Bytes")
        
        self.type_combo = ttk.Combobox(bar, textvariable=self.type_var, 
                                       values=["4 Bytes", "Float", "Double", "String (ASCII)", "String (UTF-16)", "Hex / AOB", "All Types"],
                                       state="readonly", width=14)
        self.type_combo.grid(row=1, column=3, sticky="w", pady=(10, 0), padx=2)

        ttk.Label(bar, text="Scan:").grid(row=1, column=4, sticky="e", pady=(10, 0))
        self.mode_var = tk.StringVar(value=scanner.EXACT)
        self.mode_combo = ttk.Combobox(bar, textvariable=self.mode_var, values=scanner.SCAN_MODES, state="readonly", width=12)
        self.mode_combo.grid(row=1, column=5, sticky="w", padx=4, pady=(10, 0))

        btns = ttk.Frame(bar)
        btns.grid(row=2, column=0, columnspan=6, sticky="w", pady=(12, 0))
        self.first_btn = ttk.Button(btns, text="First Scan", style="Accent.TButton", command=self._scan_clicked)
        self.first_btn.pack(side="left")
        self.next_btn = ttk.Button(btns, text="Next Scan", style="Accent.TButton", command=self._next_clicked, state="disabled")
        self.next_btn.pack(side="left", padx=6)
        self.new_btn = ttk.Button(btns, text="New Scan", command=self._new_scan, state="disabled")
        self.new_btn.pack(side="left")

        make_logo(bar, 46).grid(row=0, column=6, rowspan=3, sticky="ne", padx=(8, 0))

    def _build_results(self):
        frame = ttk.LabelFrame(self, text="Scan results", padding=4)
        frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=(4, 4))

        top = ttk.Frame(frame)
        top.pack(fill="x")
        self.count_label = ttk.Label(top, text="Found: 0", foreground=MUTED)
        self.count_label.pack(side="left")
        ttk.Label(top, text="Filter addr:").pack(side="left", padx=(16, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._populate_results())
        ttk.Entry(top, textvariable=self.filter_var, width=18).pack(side="left")

        wrap = ttk.Frame(frame)
        self.results_tree = ttk.Treeview(wrap, columns=("addr", "type", "value"), show="headings")
        for col, txt, w, anchor in (("addr", "Address", 180, "w"), ("type", "Type", 120, "w"), ("value", "Value", 200, "e")):
            self.results_tree.heading(col, text=txt, anchor=anchor)
            self.results_tree.column(col, width=w, anchor=anchor)
        stripe(self.results_tree)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=sb.set)
        self.results_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        
        self.results_tree.bind("<Double-1>", self._results_double)
        self.results_tree.bind("<Button-3>", self._show_results_context_menu)

        b_panel = ttk.Frame(frame)
        b_panel.pack(side="bottom", fill="x", pady=(6, 0))
        ttk.Button(b_panel, text="↓  Add selected to table", command=self._add_selected_to_table).pack(side="left")
        ttk.Button(b_panel, text="✍  Change all found values", command=self._change_all_found).pack(side="left", padx=8)
        wrap.pack(side="top", fill="both", expand=True, pady=(6, 0))

    def _build_table(self):
        frame = ttk.LabelFrame(self, text="Saved addresses & Live Dynamic Pointers", padding=4)
        frame.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))

        wrap = ttk.Frame(frame)
        self.table = ttk.Treeview(wrap, columns=("freeze", "desc", "addr", "type", "value"), show="headings")
        for col, txt, w, anchor in (("freeze", "Freeze", 70, "center"), ("desc", "Description", 220, "w"), ("addr", "Address / Pointer (Canlı)", 250, "w"), ("type", "Type", 110, "center"), ("value", "Value", 180, "e")):
            self.table.heading(col, text=txt, anchor=anchor)
            self.table.column(col, width=w, anchor=anchor)
        stripe(self.table)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=sb.set)
        self.table.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.table.bind("<Double-1>", self._table_double)
        self.table.bind("<Button-3>", self._show_table_popup)
        self.table.bind("<space>", self._toggle_freeze_space)

        # Tablo Alt Panel (2 Satır Buton Grubu)
        btns = ttk.Frame(frame)
        btns.pack(side="bottom", fill="x", pady=(6, 0))
        
        # 1. Satır: Temel Tablo İşlemleri & Kayıt/Yükleme
        r1 = ttk.Frame(btns)
        r1.pack(fill="x", pady=(0, 4))
        ttk.Button(r1, text="➕ Add Address / Pointer", style="Accent.TButton", command=self._add_manual).pack(side="left")
        ttk.Button(r1, text="✍ Edit value", command=self._do_edit_value).pack(side="left", padx=4)
        ttk.Button(r1, text="🗑 Remove", command=self._remove_table_row).pack(side="left")
        ttk.Button(r1, text="🧹 Clear All", command=self._clear_table).pack(side="left", padx=4)

        ttk.Button(r1, text="💾 Save Table", command=self._save_table).pack(side="right", padx=(4, 0))
        ttk.Button(r1, text="📂 Load Table", command=self._load_table).pack(side="right")

        # 2. Satır: Pointer Haritası & Canlı Eleme Paneli
        r2 = ttk.Frame(btns)
        r2.pack(fill="x")
        ttk.Label(r2, text="Pointer Haritası & Canlı Eleme:", foreground=MUTED, font=HEADFONT).pack(side="left", padx=(0, 8))
        ttk.Button(r2, text="🧭 Pointer Haritası Yükle", command=self._load_pointer_map_to_table).pack(side="left")
        ttk.Button(r2, text="🎯 Değere Göre Ele (Filtrele)", command=self._filter_pointers_in_table).pack(side="left", padx=6)
        
        wrap.pack(side="top", fill="both", expand=True, pady=(6, 0))

        self._rows = {}
        self._inline_editor = None

    def _clear_table(self):
        if not self._rows: return
        self.table.delete(*self.table.get_children())
        self._rows.clear()
        self._set_status("Tablo temizlendi.")

    def _add_manual(self):
        if not self._require_attached(): return
        AddAddressDialog(self)

    def _load_pointer_map_to_table(self):
        file_path = filedialog.askopenfilename(
            title="Kaydedilmiş Pointer Haritasını Ana Tabloya Yükle",
            filetypes=[("Pointer Map (*.json)", "*.json"), ("All Files (*.*)", "*.*")]
        )
        if not file_path: return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            paths = data.get("paths", [])
            target_type = data.get("target_type", "4 Bytes")
            if not paths:
                messagebox.showwarning("Sheet Onion", "Seçilen dosyada geçerli pointer zinciri bulunamadı.")
                return

            if self._rows:
                resp = messagebox.askyesnocancel(
                    "Pointer Haritası Yükleme",
                    f"Dosyada {len(paths)} adet pointer zinciri bulundu.\n\nMevcut tablonuz temizlensin mi?\n(Evet: Temizle ve Yükle | Hayır: Tablonun Sonuna Ekle | İptal)"
                )
                if resp is None: return
                if resp is True: self._clear_table()

            added_count = 0
            for idx, p in enumerate(paths):
                base = p.get("base", "")
                offsets_list = p.get("offsets_list", [])
                desc = f"Aday #{idx + 1} ({base})"
                self._add_pointer_table_row(base, offsets_list, target_type, desc)
                added_count += 1

            self._set_status(f"{added_count} adet pointer ana tabloya yüklendi. Canlı adres değişimlerini izleyebilirsiniz.")
            messagebox.showinfo(
                "Sheet Onion - Pointer Haritası",
                f"{added_count} adet pointer aday zinciri ana tabloya canlı olarak eklendi!\n\n"
                "• Her birinin o anki canlı RAM adresi (P->0x...) ve canlı değeri otomatik çözülmektedir.\n"
                "• Oyunda değeri değiştirip '🎯 Değere Göre Ele' butonuna basarak yanlış olanları anında eleyebilirsiniz."
            )
        except Exception as e:
            messagebox.showerror("Hata", f"Pointer haritası yüklenemedi:\n{e}")

    def _filter_pointers_in_table(self):
        if not self._rows:
            messagebox.showwarning("Sheet Onion", "Tabloda elenecek hiçbir adres/pointer yok.")
            return

        ptr_items = [item for item, info in self._rows.items() if info.get("is_pointer")]
        if not ptr_items:
            messagebox.showwarning("Sheet Onion", "Tabloda hiç pointer adayı bulunamadı.")
            return

        expected_val = ask_string(
            self,
            "Pointer Eleme / Filtreleme",
            f"Tablodaki {len(ptr_items)} pointer adayı kontrol edilecek.\n\nOyundaki güncel beklenen değeri yazın (Örn: 90):"
        )
        if expected_val is None or not str(expected_val).strip():
            return

        expected_val = str(expected_val).strip()
        removed_count = 0
        survived_count = 0
        epsilon = 0.001

        try:
            exp_float = float(expected_val)
        except ValueError:
            exp_float = None

        for item in list(ptr_items):
            info = self._rows.get(item)
            if not info: continue

            t_name = info.get("type", "4 Bytes")
            target_addr = info.get("resolved_addr")
            
            if not target_addr:
                self._rows.pop(item, None)
                self.table.delete(item)
                removed_count += 1
                continue

            live_val = self.scanner.read_value_dynamic(target_addr, t_name)
            if live_val is None:
                self._rows.pop(item, None)
                self.table.delete(item)
                removed_count += 1
                continue

            match = False
            if t_name in ("Float", "Double") and exp_float is not None:
                match = abs(float(live_val) - exp_float) <= epsilon
            elif t_name == "4 Bytes":
                try:
                    match = int(live_val) == int(expected_val, 0)
                except ValueError:
                    match = str(live_val).strip() == expected_val
            else:
                match = str(live_val).strip().lower() == expected_val.lower()

            if match:
                survived_count += 1
            else:
                self._rows.pop(item, None)
                self.table.delete(item)
                removed_count += 1

        self._set_status(f"Eleme bitti: {removed_count} sahte pointer elendi, {survived_count} sağlam kaldı!")
        messagebox.showinfo(
            "Sheet Onion - Eleme Sonucu",
            f"Canlı Eleme Tamamlandı!\n\n"
            f"❌ Elenen (Silinen) Sahte Pointer: {removed_count}\n"
            f"✅ Sağlam Kalan Pointer: {survived_count}"
        )

    def _add_pointer_table_row(self, ptr_base, ptr_offsets, type_name, desc):
        tag = row_tag(len(self.table.get_children()))
        offset_str = "".join(f"[{hex(x)}]" for x in ptr_offsets)
        item = self.table.insert("", "end", tags=(tag,), values=("[  ]", desc, f"P->{ptr_base}{offset_str}", type_name, "?"))
        self._rows[item] = {
            "addr": 0,
            "type": type_name,
            "frozen": False,
            "freeze_val": None,
            "is_pointer": True,
            "ptr_base": ptr_base,
            "ptr_offsets": ptr_offsets,
            "resolved_addr": None
        }
        return item

    def _save_table(self):
        if not self._rows:
            messagebox.showwarning("Sheet Onion", "Kaydedilecek hiçbir adres bulunamadı!")
            return

        file_path = filedialog.asksaveasfilename(
            title="Tabloyu Kaydet (Cheat Table)",
            defaultextension=".json",
            filetypes=[("Sheet Onion Table (*.json)", "*.json"), ("All Files (*.*)", "*.*")]
        )
        if not file_path: return

        data = []
        for item in self.table.get_children():
            info = self._rows.get(item)
            if not info: continue
            vals = self.table.item(item, "values")
            desc = vals[1] if len(vals) > 1 else ""
            
            row_data = {
                "description": desc,
                "type": info["type"],
                "frozen": info.get("frozen", False),
                "freeze_val": info.get("freeze_val"),
                "is_pointer": info.get("is_pointer", False)
            }
            if info.get("is_pointer"):
                row_data["ptr_base"] = info.get("ptr_base")
                row_data["ptr_offsets"] = info.get("ptr_offsets")
            else:
                row_data["address"] = f"0x{info['addr']:X}"

            data.append(row_data)

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump({"version": "2.0", "entries": data}, f, indent=4, ensure_ascii=False)
            self._set_status(f"Tablo başarıyla kaydedildi: {file_path}")
            messagebox.showinfo("Sheet Onion", f"Tablo başarıyla kaydedildi!\nToplam {len(data)} adres dosyaya yazıldı.")
        except Exception as e:
            messagebox.showerror("Hata", f"Tablo kaydedilirken bir hata oluştu:\n{e}")

    def _load_table(self):
        file_path = filedialog.askopenfilename(
            title="Tablo Yükle (Cheat Table)",
            filetypes=[("Sheet Onion Table (*.json)", "*.json"), ("All Files (*.*)", "*.*")]
        )
        if not file_path: return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = json.load(f)

            entries = content.get("entries", [])
            if not entries and isinstance(content, list):
                entries = content

            if not entries:
                messagebox.showwarning("Sheet Onion", "Dosyada yüklenebilecek adres bulunamadı.")
                return

            if self._rows:
                resp = messagebox.askyesnocancel("Tablo Yükle", "Mevcut tablonuzdaki adresler temizlensin mi?\n\n(Evet: Temizle ve Yükle | Hayır: Üzerine Ekle | İptal)")
                if resp is None: return
                if resp is True:
                    self.table.delete(*self.table.get_children())
                    self._rows.clear()

            loaded_count = 0
            for entry in entries:
                type_name = entry.get("type", "4 Bytes")
                desc = entry.get("description", "")
                frozen = entry.get("frozen", False)
                freeze_val = entry.get("freeze_val")

                if entry.get("is_pointer"):
                    ptr_base = entry.get("ptr_base", "")
                    ptr_offsets = entry.get("ptr_offsets", [])
                    item = self._add_pointer_table_row(ptr_base, ptr_offsets, type_name, desc)
                else:
                    addr_val = entry.get("address", 0)
                    addr = int(addr_val, 0) if isinstance(addr_val, str) else int(addr_val)
                    item = self._add_table_row(addr, type_name, desc)

                if frozen:
                    self._rows[item]["frozen"] = True
                    self._rows[item]["freeze_val"] = freeze_val
                    self.table.set(item, "freeze", "[ X ]")

                loaded_count += 1

            self._set_status(f"{loaded_count} adres başarıyla yüklendi: {file_path}")
            messagebox.showinfo("Sheet Onion", f"{loaded_count} adet adres başarıyla tabloya yüklendi!")
        except Exception as e:
            messagebox.showerror("Hata", f"Tablo yüklenirken hata oluştu:\n{e}")

    def _build_context_menu(self):
        self.popup_menu = tk.Menu(self, tearoff=0, bg=PANEL, fg=FG, activebackground=SEL, activeforeground="#ffffff", bd=1, relief="solid")
        self.popup_menu.add_command(label="Toggle Freeze (Lock Value)", command=self._toggle_freeze_context)
        self.popup_menu.add_separator()
        self.popup_menu.add_command(label="Find out what accesses this address", command=self._find_offsets)
        self.popup_menu.add_command(label="✦ Generate/Scan Pointer Map", command=self._auto_find_pointer)
        self.popup_menu.add_command(label="Browse this memory region", command=self._browse_memory)
        self.popup_menu.add_separator()
        
        self.aob_submenu = tk.Menu(self.popup_menu, tearoff=0, bg=PANEL, fg=FG, activebackground=SEL, activeforeground="#ffffff")
        self.popup_menu.add_cascade(label="📦 Generate AOB Signature", menu=self.aob_submenu)
        self._attach_aob_commands(self.aob_submenu, is_table=True)
        
        self.popup_menu.add_separator()
        self.popup_menu.add_command(label="Edit Value", command=self._do_edit_value)
        self.popup_menu.add_command(label="Remove", command=self._remove_table_row)

    def _attach_aob_commands(self, menu_obj, is_table=False):
        sizes = [8, 10, 32, 64]
        for s in sizes:
            menu_obj.add_command(
                label=f"🎯 {s}-Byte AOB Bul - Maskelenmiş (??)", 
                command=lambda size=s, t=is_table: self._trigger_aob_generation(size, use_wildcards=True, from_table=t)
            )
            menu_obj.add_command(
                label=f"📄 {s}-Byte AOB Bul - Ham (Birebir)", 
                command=lambda size=s, t=is_table: self._trigger_aob_generation(size, use_wildcards=False, from_table=t)
            )
            if s != 64:
                menu_obj.add_separator()

    def _trigger_aob_generation(self, size, use_wildcards, from_table=False):
        if from_table:
            sel = self.table.selection()
            if not sel: return
            info = self._rows.get(sel[0])
            if not info: return
            addr = info["resolved_addr"] if info.get("is_pointer") else info.get("addr")
            if not addr:
                messagebox.showerror("AOB Error", "Pointer adresi henüz çözümlenemedi.")
                return
        else:
            sel = self.results_tree.selection()
            if not sel: return
            values = self.results_tree.item(sel[0], "values")
            if not values: return
            addr = int(values[0], 16)
            
        self._generate_aob_by_size(addr, size, use_wildcards)

    def _show_table_popup(self, event):
        item = self.table.identify_row(event.y)
        if item:
            self.table.selection_set(item)
            self.popup_menu.post(event.x_root, event.y_root)

    def _generate_aob_by_size(self, addr, size, use_wildcards=True):
        if not self.scanner.handle: return
        
        buf = winmem.read_bytes(self.scanner.handle, addr, size)
        if not buf:
            messagebox.showerror("AOB Error", "Hafıza bölgesi okunamadı. Süreç sonlandırılmış olabilir.")
            return
        
        aob_parts = []
        mask_threshold = int(size * 0.70)
        
        for idx, b in enumerate(buf):
            if use_wildcards and ((idx >= mask_threshold and b == 0x00) or (b == 0xCC)): 
                aob_parts.append("??")
            else:
                aob_parts.append(f"{b:02X}")
                
        real_aob = " ".join(aob_parts)
        self.clipboard_clear()
        self.clipboard_append(real_aob)
        
        mode_txt = "Maskelenmiş (??)" if use_wildcards else "Ham (Birebir)"
        self._set_status(f"AOB ({size}-Byte {mode_txt}) Copied!")
        
        msg = f"{size}-Byte {mode_txt} AOB imzası başarıyla üretildi ve panoya kopyalandı:\n\n{real_aob}"
        messagebox.showinfo("Sheet Onion - AOB Engine", msg)

    def _show_results_context_menu(self, event):
        item = self.results_tree.identify_row(event.y)
        if not item: return
        
        self.results_tree.selection_set(item)
        res_menu = tk.Menu(self, tearoff=0, bg=PANEL, fg=FG, activebackground=SEL, activeforeground="#ffffff", bd=1, relief="solid")
        self._attach_aob_commands(res_menu, is_table=False)
        res_menu.post(event.x_root, event.y_root)

    def _find_offsets(self):
        sel = self.table.selection()
        if not sel: return
        item = sel[0]
        info = self._rows.get(item)
        if info and self.current_pid:
            addr = info["resolved_addr"] if info.get("is_pointer") else info.get("addr")
            if addr:
                OffsetViewerDialog(self, self.scanner.handle, self.current_pid, addr, info["type"])

    def _auto_find_pointer(self):
        sel = self.table.selection()
        if not sel: return
        item = sel[0]
        info = self._rows.get(item)
        if info and self.current_pid:
            addr = info["resolved_addr"] if info.get("is_pointer") else info.get("addr")
            if addr:
                PointerScannerDialog(self, self.scanner.handle, self.current_pid, addr, info["type"])

    def _browse_memory(self):
        sel = self.table.selection()
        if not sel: return
        item = sel[0]
        info = self._rows.get(item)
        if info:
            addr = info["resolved_addr"] if info.get("is_pointer") else info.get("addr")
            if addr:
                MemoryBrowserDialog(self, self.scanner, addr)

    def _set_status(self, text): self.status.config(text=text)
    def _require_attached(self):
        if not self.scanner.handle:
            messagebox.showwarning("Sheet Onion", "Attach to a process first.")
            return False
        return True

    def _fmt_value(self, v):
        if isinstance(v, float): 
            return f"{v:.6f}".rstrip('0').rstrip('.')
        return str(v)

    def attach(self):
        dlg = ProcessDialog(self)
        if not dlg.result: return
        pid, name = dlg.result
        handle = winmem.open_process(pid)
        if not handle:
            messagebox.showerror("Sheet Onion", f"Could not open {name} (pid {pid}).\n\nTry running Sheet Onion as Administrator.")
            return

        tgt64 = winmem.target_is_64bit(handle)
        if tgt64 and not winmem.HOST_IS_64BIT:
            winmem.close_process(handle)
            messagebox.showerror("Sheet Onion", f"{name} is a 64-bit process but you're running 32-bit Python.")
            return

        if self.scanner.handle: winmem.close_process(self.scanner.handle)
        
        self.scanner.writable_only = True
        self.scanner.scan_kinds = ("private",)
        
        self.scanner.attach(handle, self.type_var.get())
        bits = "64-bit" if tgt64 else ("32-bit" if tgt64 is False else "?")
        self.proc_name = name
        self.current_pid = pid
        self.proc_label.config(text=f"{name} (pid {pid})  -  {bits}", foreground=OK)
        self._clear_results()
        self.new_btn.config(state="normal")
        self._set_status(f"Attached to {name}. Enter a value and First Scan.")

    def _scan_clicked(self):
        if not self._require_attached() or self.scanning: return
        val_str = self.value_var.get()
        if not val_str:
            messagebox.showerror("Sheet Onion", "Enter a value/pattern to scan.")
            return
            
        self.scanner.type_name = self.type_var.get()
        self._begin_scan("Scanning memory...")

        def work():
            n = self.scanner.first_scan(val_str)
            self.after(0, lambda: self._end_scan(n))
        threading.Thread(target=work, daemon=True).start()

    def _next_clicked(self):
        if not self._require_attached() or self.scanning: return
        mode = self.mode_var.get()
        val_str = self.value_var.get() if mode == scanner.EXACT else None
        self._begin_scan("Filtering results...")

        def work():
            n = self.scanner.next_scan(mode, val_str)
            self.after(0, lambda: self._end_scan(n))
        threading.Thread(target=work, daemon=True).start()

    def _begin_scan(self, msg):
        self.scanning = True
        for b in (self.first_btn, self.next_btn, self.new_btn, self.attach_btn): b.config(state="disabled")
        self._set_status(msg)
        self.config(cursor="watch")

    def _end_scan(self, count):
        self.scanning = False
        self.attach_btn.config(state="normal")
        self.first_btn.config(state="normal")
        self.new_btn.config(state="normal")
        self.next_btn.config(state="normal" if count else "disabled")
        self.config(cursor="")
        self._populate_results()
        extra = "  (truncated)" if self.scanner.truncated else ""
        self._set_status(f"Scan complete: {count} result(s).{extra}")

    def _new_scan(self):
        self.scanner.reset()
        self._clear_results()
        self.next_btn.config(state="disabled")
        self._set_status("New scan. Enter a value and First Scan.")

    def _clear_results(self):
        self.results_tree.delete(*self.results_tree.get_children())
        self.count_label.config(text="Found: 0")

    def _populate_results(self):
        self.results_tree.delete(*self.results_tree.get_children())
        total = self.scanner.count
        needle = self.filter_var.get().strip().lower().replace("0x", "")

        rows = []
        for addr, val, t_found in self.scanner.iter_all():
            if not needle or needle in f"{addr:x}":
                rows.append((addr, val, t_found))
                if len(rows) >= self.DISPLAY_LIMIT: 
                    break

        for i, (addr, val, type_found) in enumerate(rows):
            self.results_tree.insert("", "end", tags=(row_tag(i),), values=(f"{addr:X}", type_found, self._fmt_value(val)))
        self.count_label.config(text=f"Found: {total}")

    def _change_all_found(self):
        if not self._require_attached() or self.scanner.count == 0: 
            return
        new_val = ask_string(self, "Change All", f"Enter new value for all {self.scanner.count} addresses:")
        if new_val is None: return
        
        success_count = 0
        for addr, _, type_found in self.scanner.iter_all():
            if self.scanner.write_value_dynamic(addr, new_val, type_found):
                success_count += 1
        self._populate_results()
        self._set_status(f"Successfully changed {success_count} values to '{new_val}'.")

    def _results_double(self, event):
        item = self.results_tree.identify_row(event.y)
        if not item: return
        self.results_tree.selection_set(item)
        self._add_selected_to_table()

    def _add_selected_to_table(self):
        added = []
        for item in self.results_tree.selection():
            addr_hex, type_found, _value = self.results_tree.item(item, "values")
            added.append(self._add_table_row(int(addr_hex, 16), type_found, ""))
        if added: 
            self.table.selection_set(added)

    def _add_table_row(self, addr, type_name, desc):
        tag = row_tag(len(self.table.get_children()))
        item = self.table.insert("", "end", tags=(tag,), values=("[  ]", desc, f"0x{addr:X}", type_name, "?"))
        self._rows[item] = {"addr": addr, "type": type_name, "frozen": False, "freeze_val": None, "is_pointer": False}
        return item

    def _remove_table_row(self):
        for item in self.table.selection():
            self._rows.pop(item, None)
            self.table.delete(item)

    def _toggle_freeze(self, item):
        if item in self._rows:
            info = self._rows[item]
            info["frozen"] = not info["frozen"]
            if info["frozen"]:
                current_values = self.table.item(item, "values")
                val_now = current_values[4]
                info["freeze_val"] = val_now if val_now not in ("?", "??") else "100"
                self.table.set(item, "freeze", "[ X ]")
            else:
                info["freeze_val"] = None
                self.table.set(item, "freeze", "[  ]")

    def _toggle_freeze_space(self, event):
        sel = self.table.selection()
        if sel: self._toggle_freeze(sel[0])

    def _toggle_freeze_context(self):
        sel = self.table.selection()
        if sel: self._toggle_freeze(sel[0])

    def _table_double(self, event):
        item = self.table.identify_row(event.y)
        if not item: return
        col = self.table.identify_column(event.x)
        
        if col == "#1": 
            self._toggle_freeze(item)
        elif col == "#2": 
            self._edit_description(item, col)
        elif col == "#3": 
            pass
        else:
            self.table.selection_set(item)
            self._do_edit_value()

    def _edit_description(self, item, column):
        self._close_inline_editor()
        bbox = self.table.bbox(item, column)
        if not bbox: return
        x, y, w, h = bbox
        var = tk.StringVar(value=self.table.set(item, "desc"))
        ent = ttk.Entry(self.table, textvariable=var)
        ent.place(x=x, y=y, width=w, height=h)
        ent.focus_set()
        ent.icursor("end")
        self._inline_editor = ent

        def commit(_e=None):
            if self._inline_editor is None: return
            self.table.set(item, "desc", var.get())
            self._close_inline_editor()

        ent.bind("<Return>", commit)
        ent.bind("<FocusOut>", commit)
        ent.bind("<Escape>", lambda _e: self._close_inline_editor())

    def _close_inline_editor(self):
        ed = getattr(self, "_inline_editor", None)
        if ed is not None:
            self._inline_editor = None
            ed.destroy()

    def _do_edit_value(self):
        sel = self.table.selection()
        if not sel: return
        item = sel[0]
        info = self._rows.get(item)
        if not info or not self.scanner.handle: return
        
        target_addr = info.get("resolved_addr") if info.get("is_pointer") else info.get("addr")
        if not target_addr:
            messagebox.showerror("Sheet Onion", "Pointer adresi şu an çözümlenemiyor (oyun açık mı?).")
            return

        cur = self.table.item(item, "values")[4]
        new = ask_string(self, "Set value", f"New value ({info['type']}):", initial="" if cur in ("?", "??") else cur)
        if new is None: return
        
        ok = self.scanner.write_value_dynamic(target_addr, new, info["type"])
        if ok and info["frozen"]:
            info["freeze_val"] = new
        if not ok: 
            messagebox.showerror("Sheet Onion", "Write failed.")

    def _freeze_loop(self):
        while self.freeze_running:
            if self.scanner.handle:
                for item, info in list(self._rows.items()):
                    if info.get("frozen") and info.get("freeze_val") is not None:
                        try:
                            target_addr = info["resolved_addr"] if info.get("is_pointer") else info.get("addr")
                            if target_addr:
                                self.scanner.write_value_dynamic(target_addr, info["freeze_val"], info["type"])
                        except Exception:
                            pass
            time.sleep(0.1)

    def _tick(self):
        if self.scanner.handle and not self.scanning:
            for item, info in list(self._rows.items()):
                target_addr = info.get("addr", 0)
                if info.get("is_pointer"):
                    resolved = resolve_pointer_path(self.scanner.handle, self.current_pid, info["ptr_base"], info["ptr_offsets"])
                    if resolved:
                        target_addr = resolved
                        info["resolved_addr"] = resolved
                    else:
                        target_addr = None
                        info["resolved_addr"] = None

                if target_addr:
                    val = self.scanner.read_value_dynamic(target_addr, info["type"])
                    text = "??" if val is None else self._fmt_value(val)
                    addr_str = f"P->0x{target_addr:X}" if info.get("is_pointer") else f"0x{target_addr:X}"
                else:
                    text = "??"
                    addr_str = "P->(Geçersiz)" if info.get("is_pointer") else "??"

                cur = self.table.item(item, "values")
                if cur and (cur[4] != text or cur[2] != addr_str):
                    self.table.item(item, values=(cur[0], cur[1], addr_str, cur[3], text))
        self.after(500, self._tick)

    def _on_close(self):
        self.freeze_running = False
        if self.scanner.handle: winmem.close_process(self.scanner.handle)
        self.destroy()


class PointerScannerDialog(tk.Toplevel):
    def __init__(self, master, process_handle, pid, target_addr, type_name):
        super().__init__(master)
        self.title("✦ Sheet Onion - Multi-Level Pointer & Elimination Engine")
        self.geometry("920x620")
        self.configure(bg=BG)
        self.transient(master)

        self.master_app = master
        self.process_handle = process_handle
        self.pid = pid
        self.target_addr = target_addr
        self.type_name = type_name
        self.found_paths = [] 

        top_bar = ttk.Frame(self, padding=10)
        top_bar.pack(fill="x")

        lbl = ttk.Label(top_bar, text=f"Pointer Engine -> Hedef: 0x{target_addr:X} ({type_name})", font=HEADFONT)
        lbl.pack(side="left")

        self.only_game_mods = tk.BooleanVar(value=True)
        chk = ttk.Checkbutton(top_bar, text="🎮 Sadece Oyun Modülleri (.exe / Engine DLLs)", variable=self.only_game_mods)
        chk.pack(side="right")

        wrap = ttk.Frame(self, padding=(10, 0, 10, 10))
        wrap.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(wrap, columns=("base", "offsets", "live_val"), show="headings")
        for col, txt, w, anchor in (("base", "Statik Base Pointer Adresi", 340, "w"), ("offsets", "Offsets", 180, "center"), ("live_val", "Live Value", 160, "e")):
            self.tree.heading(col, text=txt, anchor=anchor)
            self.tree.column(col, width=w, anchor=anchor)
        stripe(self.tree)
        
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._save_pointer)

        # Alt Buton Panelleri (2 Satır)
        b_panel_top = ttk.Frame(self, padding=(10, 5))
        b_panel_top.pack(fill="x")
        
        self.status_lbl = ttk.Label(b_panel_top, text="Hazır. 'Scan Pointer Map' basarak tarayın veya dosyadaki listeyi yükleyip eleyin.", foreground=MUTED)
        self.status_lbl.pack(side="left")

        b_panel_bot = ttk.Frame(self, padding=10)
        b_panel_bot.pack(fill="x")

        # Sol Butonlar: Dosya Dışa/İçe Aktar
        ttk.Button(b_panel_bot, text="💾 Pointer Listesini Kaydet", command=self._export_pointer_list).pack(side="left")
        ttk.Button(b_panel_bot, text="📂 Pointer Listesi Yükle", command=self._import_pointer_list).pack(side="left", padx=6)

        # Sağ Butonlar: Eleme ve Tarama
        self.scan_btn = ttk.Button(b_panel_bot, text="Scan Pointer Map", style="Accent.TButton", command=self._start_pointer_scan_thread)
        self.scan_btn.pack(side="right", padx=4)

        self.rescan_btn = ttk.Button(b_panel_bot, text="🔍 Ele / Rescan", command=self._do_rescan, state="disabled")
        self.rescan_btn.pack(side="right", padx=4)
        
        self.rescan_var = tk.StringVar()
        self.rescan_entry = ttk.Entry(b_panel_bot, textvariable=self.rescan_var, width=12)
        self.rescan_entry.pack(side="right", padx=4)
        ttk.Label(b_panel_bot, text="New Value:").pack(side="right")

        self.cancel_btn = ttk.Button(b_panel_bot, text="⏹ İptal", command=self._cancel_scan, state="disabled")
        self.cancel_btn.pack(side="right", padx=4)

        self._scan_cancelled = False

        dark_titlebar(self)

    def _cancel_scan(self):
        self._scan_cancelled = True
        self.status_lbl.config(text="İptal ediliyor...", foreground=MUTED)

    def _start_pointer_scan_thread(self):
        self.scan_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self._scan_cancelled = False
        threading.Thread(target=self._resolve_pointer_real, daemon=True).start()

    def _is_module_valid(self, mod_name):
        if not self.only_game_mods.get():
            return True
        return mod_name.lower() not in SYSTEM_DLL_BLACKLIST

    def _resolve_pointer_real(self):
        if not self.process_handle: return

        self.found_paths = []
        is_64 = winmem.target_is_64bit(self.process_handle)
        ptr_size = 8 if is_64 else 4
        np_dtype = "<u8" if is_64 else "<u4"
        array_typecode = "Q" if is_64 else "I"

        modules = proclist.list_modules(self.pid)
        max_offset = 0x8000
        
        # --- SEVİYE 1 (LEVEL 1) TARAMA ---
        self.after(0, lambda: self.status_lbl.config(text="Seviye 1 (Level 1) Pointer taraması yapılıyor...", foreground=YELLOW))
        
        l1_candidates = self._scan_memory_for_pointers([self.target_addr], max_offset, ptr_size, np_dtype, array_typecode)
        
        static_paths = []
        dynamic_l1 = []
        
        for cand in l1_candidates:
            hit = proclist.module_for_address(modules, cand["base_addr"])
            if hit:
                mod_name, mod_base = hit
                if self._is_module_valid(mod_name):
                    base_label = f"{mod_name}+0x{cand['base_addr'] - mod_base:X}"
                    static_paths.append({
                        "base": base_label,
                        "offsets": f"[0x{cand['offset']:X}]",
                        "offsets_list": [cand['offset']],
                        "real_ptr_addr": cand["base_addr"],
                        "offset_val": cand["offset"]
                    })
            else:
                dynamic_l1.append(cand)
                
        # --- SEVİYE 2 (LEVEL 2) TARAMA ---
        dynamic_l1 = dynamic_l1[:2500]
        
        if not self._scan_cancelled and dynamic_l1:
            self.after(0, lambda: self.status_lbl.config(text=f"Seviye 2 (Level 2) Taraması ({len(dynamic_l1)} dinamik adres için) yapılıyor...", foreground=YELLOW))
            
            l1_addrs = [c["base_addr"] for c in dynamic_l1]
            l2_candidates = self._scan_memory_for_pointers(l1_addrs, max_offset, ptr_size, np_dtype, array_typecode)
            
            for cand2 in l2_candidates:
                hit2 = proclist.module_for_address(modules, cand2["base_addr"])
                if hit2:
                    mod_name, mod_base = hit2
                    if self._is_module_valid(mod_name):
                        base_label = f"{mod_name}+0x{cand2['base_addr'] - mod_base:X}"
                        
                        pointed_l1 = cand2["target_val"]
                        l1_info = next((d for d in dynamic_l1 if d["base_addr"] == pointed_l1), None)
                        
                        if l1_info:
                            static_paths.append({
                                "base": base_label,
                                "offsets": f"[0x{cand2['offset']:X}, 0x{l1_info['offset']:X}]",
                                "offsets_list": [cand2['offset'], l1_info['offset']],
                                "real_ptr_addr": cand2["base_addr"],
                                "offset_val": l1_info["offset"]
                            })

        # Oyunun ana modülüne öncelik ver
        proc_name_lower = (self.master_app.proc_name or "").lower()
        static_paths.sort(key=lambda x: (0 if proc_name_lower in x["base"].lower() else 1))

        self.found_paths = static_paths[:200]
        self.after(0, self._finish_pointer_scan)
        
    def _scan_memory_for_pointers(self, target_addrs, max_offset, ptr_size, np_dtype, array_typecode):
        discovered = []
        if not target_addrs: return discovered
        
        MAX_CANDIDATES = 1_000_000
        regions = list(winmem.iter_regions(self.process_handle, winmem.ALL_KINDS, False))
        CHUNK = 16 * 1024 * 1024

        for base, size, _, _ in regions:
            if self._scan_cancelled or len(discovered) >= MAX_CANDIDATES:
                break
            pos = base
            end = base + size
            while pos < end:
                if self._scan_cancelled or len(discovered) >= MAX_CANDIDATES:
                    break
                want = min(CHUNK, end - pos)
                data = winmem.read_bytes(self.process_handle, pos, want)
                if not data:
                    pos += 0x1000
                    continue

                usable_len = len(data) - (len(data) % ptr_size)
                if usable_len > 0:
                    if np is not None:
                        arr = np.frombuffer(data, dtype=np_dtype, count=usable_len // ptr_size)
                        
                        for t_addr in target_addrs:
                            lo = t_addr - max_offset
                            hi = t_addr
                            hits = np.nonzero((arr >= lo) & (arr <= hi))[0]
                            for j in hits.tolist():
                                val = int(arr[j])
                                loc = pos + j * ptr_size
                                discovered.append({"base_addr": loc, "offset": t_addr - val, "target_val": t_addr})
                                if len(discovered) >= MAX_CANDIDATES: break
                            if len(discovered) >= MAX_CANDIDATES: break
                    else:
                        arr = array(array_typecode, data[:usable_len])
                        for t_addr in target_addrs:
                            lo = t_addr - max_offset
                            hi = t_addr
                            for j, val in enumerate(arr):
                                if lo <= val <= hi:
                                    loc = pos + j * ptr_size
                                    discovered.append({"base_addr": loc, "offset": t_addr - val, "target_val": t_addr})
                                    if len(discovered) >= MAX_CANDIDATES: break
                            if len(discovered) >= MAX_CANDIDATES: break

                pos += len(data)
                
        return discovered

    def _finish_pointer_scan(self):
        live_val = self.master_app.scanner.read_value_dynamic(self.target_addr, self.type_name)
        val_str = self.master_app._fmt_value(live_val) if live_val is not None else "??"
        
        self._refresh_tree_ui(val_str)
        self.scan_btn.config(state="normal")
        self.cancel_btn.config(state="disabled")
        self.rescan_btn.config(state="normal" if self.found_paths else "disabled")
        
        if self._scan_cancelled:
            self.status_lbl.config(text=f"İptal edildi. {len(self.found_paths)} statik pointer bulundu.", foreground=MUTED)
        elif self.found_paths:
            self.status_lbl.config(text=f"Tarama Tamamlandı! {len(self.found_paths)} adet statik pointer bulundu.", foreground=OK)
        else:
            self.status_lbl.config(text="Hiç statik pointer bulunamadı. Değeri değiştirip tekrar taramayı deneyin.", foreground=YELLOW)

    def _do_rescan(self):
        target_val = self.rescan_var.get().strip()
        if not target_val:
            messagebox.showwarning("Sheet Onion", "Eleme/Filtreleme için oyundaki yeni güncel değeri yazın.")
            return

        valid_paths = []
        for p in self.found_paths:
            resolved_dst = resolve_pointer_path(self.process_handle, self.pid, p["base"], p["offsets_list"])
            if resolved_dst:
                live_val = self.master_app.scanner.read_value_dynamic(resolved_dst, self.type_name)
                live_val_str = self.master_app._fmt_value(live_val) if live_val is not None else "??"
                
                if live_val_str == target_val:
                    valid_paths.append(p)

        old_count = len(self.found_paths)
        self.found_paths = valid_paths
        self._refresh_tree_ui(target_val)
        self.status_lbl.config(text=f"Eleme bitti! {old_count} pointer'dan {len(valid_paths)} sağlam adres kaldı.", foreground=OK)
        messagebox.showinfo("Sheet Onion", f"Eleme tamamlandı!\n\nÖnceki Aday Sayısı: {old_count}\nSağlam Kalan Pointer: {len(valid_paths)}")

    def _export_pointer_list(self):
        if not self.found_paths:
            messagebox.showwarning("Sheet Onion", "Dışa aktarılacak pointer listesi boş!")
            return

        file_path = filedialog.asksaveasfilename(
            title="Pointer Listesini / Haritasını Kaydet",
            defaultextension=".json",
            filetypes=[("Pointer Map (*.json)", "*.json"), ("All Files (*.*)", "*.*")]
        )
        if not file_path: return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump({
                    "target_type": self.type_name,
                    "target_addr": f"0x{self.target_addr:X}",
                    "paths": self.found_paths
                }, f, indent=4, ensure_ascii=False)
            messagebox.showinfo("Sheet Onion", f"Toplam {len(self.found_paths)} pointer zinciri başarıyla kaydedildi!")
        except Exception as e:
            messagebox.showerror("Hata", f"Kaydetme başarısız: {e}")

    def _import_pointer_list(self):
        file_path = filedialog.askopenfilename(
            title="Kaydedilmiş Pointer Haritasını Yükle",
            filetypes=[("Pointer Map (*.json)", "*.json"), ("All Files (*.*)", "*.*")]
        )
        if not file_path: return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            paths = data.get("paths", [])
            if not paths:
                messagebox.showwarning("Sheet Onion", "Dosyada geçerli pointer bulunamadı.")
                return

            self.found_paths = paths
            self._refresh_tree_ui("?? (Eleme Bekleniyor)")
            self.rescan_btn.config(state="normal")
            self.status_lbl.config(text=f"{len(paths)} pointer dosyadan yüklendi. Oyundaki yeni değeri girip 'Ele / Rescan' yapın.", foreground=YELLOW)
            messagebox.showinfo("Sheet Onion", f"{len(paths)} pointer yüklendi!\nŞimdi oyundaki yeni değeri yazarak 'Ele / Rescan' butonuna basın.")
        except Exception as e:
            messagebox.showerror("Hata", f"Yükleme başarısız: {e}")

    def _refresh_tree_ui(self, val_to_show):
        self.tree.delete(*self.tree.get_children())
        for i, p in enumerate(self.found_paths):
            self.tree.insert("", "end", tags=(row_tag(i),), values=(p["base"], p["offsets"], val_to_show))

    def _save_pointer(self, event):
        sel = self.tree.selection()
        if not sel: return
        item_idx = self.tree.index(sel[0])
        if item_idx < len(self.found_paths):
            p = self.found_paths[item_idx]
            self.master_app._add_pointer_table_row(p["base"], p["offsets_list"], self.type_name, f"Ptr -> {p['base']}")
            messagebox.showinfo("Sheet Onion", f"Kalıcı Pointer başarıyla ana tabloya eklendi!\n\nBase: {p['base']}\nOffsets: {p['offsets']}\n\nBu adres oyunu kapatsanız da otomatik çözülecektir.")


def _capstone_disp_info(insn):
    for holder in (insn, getattr(insn, "x86", None)):
        if holder is None:
            continue
        off = getattr(holder, "disp_offset", None)
        size = getattr(holder, "disp_size", None)
        if off is not None and size:
            return off, size
    return None, None


def _capstone_imm_info(insn):
    for holder in (insn, getattr(insn, "x86", None)):
        if holder is None:
            continue
        off = getattr(holder, "imm_offset", None)
        size = getattr(holder, "imm_size", None)
        if off is not None and size:
            return off, size
    return None, None


def _mem_operand_is_pure_absolute(insn):
    try:
        operands = insn.operands
    except Exception:
        try:
            operands = insn.x86.operands
        except Exception:
            return False
    for op in operands:
        if op.type == X86_OP_MEM:
            mem = op.mem
            if getattr(mem, "base", 0) == 0 and getattr(mem, "index", 0) == 0:
                return True
    return False


def build_code_aob(process_handle, code_addr, is64, total_size=16):
    log = []
    if Cs is None:
        return None, log, "Capstone kütüphanesi yüklü değil, kod çözülemiyor."

    raw = winmem.read_bytes(process_handle, code_addr, total_size + 32)
    if not raw:
        return None, log, "Komut adresindeki bellek okunamadı (süreç kapanmış olabilir)."

    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
    md.detail = True

    out_bytes = []
    covered = 0
    any_insn = False

    try:
        for insn in md.disasm(raw, code_addr):
            any_insn = True
            log.append(f"0x{insn.address:X}: {insn.mnemonic} {insn.op_str}   [{insn.bytes.hex(' ').upper()}]")

            mask_ranges = []
            
            disp_offset, disp_size = _capstone_disp_info(insn)
            if disp_offset is not None and _mem_operand_is_pure_absolute(insn):
                mask_ranges.append((disp_offset, disp_size))

            mnemonic = insn.mnemonic.lower()
            if mnemonic.startswith("call") or mnemonic.startswith("j"):
                imm_offset, imm_size = _capstone_imm_info(insn)
                if imm_offset is not None and imm_size == 4:
                    mask_ranges.append((imm_offset, imm_size))

            for k, b in enumerate(insn.bytes):
                masked = any(off <= k < off + ln for off, ln in mask_ranges)
                out_bytes.append("??" if masked else f"{b:02X}")

            covered += insn.size
            if covered >= total_size:
                break
    except Exception as e:
        return None, log, f"Disassemble hatası: {e}"

    if not any_insn or not out_bytes:
        return None, log, "Komut çözümlenemedi (adres kod bölgesinde olmayabilir)."

    return " ".join(out_bytes), log, None


class OffsetViewerDialog(tk.Toplevel):
    def __init__(self, master, process_handle, pid, addr, type_name):
        super().__init__(master)
        self.title("Find out what accesses this address")
        self.geometry("860x620")
        self.configure(bg=BG)
        self.transient(master)

        self.process_handle = process_handle
        self.pid = pid
        self.target_addr = addr
        self.type_name = type_name
        
        self.short_aob = None
        self.long_aob = None
        self.running = True
        self.stop_event = None
        self.hit_map = {}

        size_map = {"4 Bytes": 4, "Float": 4, "Double": 8,
                    "String (ASCII)": 1, "String (UTF-16)": 2, "Hex / AOB": 1}
        self.watch_size = size_map.get(type_name, 4)

        ttk.Label(self, text=f"Hedef Adres: 0x{addr:X}  ({type_name})", font=HEADFONT, padding=(10, 10, 10, 0)).pack(anchor="w")
        ttk.Label(
            self, padding=(10, 4, 10, 4), wraplength=820, justify="left", foreground=MUTED,
            text="'Yakalamayı Başlat' butonuna basın, ardından oyuna geçip değeri değiştirin/erişin. "
                 "Hata ayıklayıcı erişen komutları ve offsetleri listeleyecektir."
        ).pack(fill="x")

        self.status_lbl = ttk.Label(self, text="Hazır. İzlemeyi başlatmak için butona basın.", padding=(10, 0, 10, 6))
        self.status_lbl.pack(anchor="w")

        paned = ttk.Panedwindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=5)

        list_frame = ttk.Frame(paned)
        paned.add(list_frame, weight=2)

        self.tree = ttk.Treeview(list_frame, columns=("count", "addr", "insn", "bytes"), show="headings", selectmode="browse")
        self.tree.heading("count", text="Count", anchor="center")
        self.tree.heading("addr", text="Instruction Address", anchor="w")
        self.tree.heading("insn", text="Assembly Instruction (ve Offset)", anchor="w")
        self.tree.heading("bytes", text="Opcodes (Bytes)", anchor="w")
        
        self.tree.column("count", width=80, anchor="center")
        self.tree.column("addr", width=150, anchor="w")
        self.tree.column("insn", width=420, anchor="w")
        self.tree.column("bytes", width=200, anchor="w")
        stripe(self.tree)

        sb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select_match)

        text_frame = ttk.Frame(paned)
        paned.add(text_frame, weight=3)
        self.text = tk.Text(text_frame, bg=FIELD, fg=FG, insertbackground=FG, font=MONO, bd=1, relief="solid", state="disabled")
        self.text.pack(fill="both", expand=True)

        btns = ttk.Frame(self, padding=10)
        btns.pack(fill="x")
        self.start_btn = ttk.Button(btns, text="▶ Yakalamayı Başlat", style="Accent.TButton", command=self._start)
        self.start_btn.pack(side="left")

        self.save_report_btn = ttk.Button(btns, text="💾 Offsetleri Kaydet", command=self._save_offset_report)
        self.save_report_btn.pack(side="left", padx=(8, 0))

        self.copy_short_btn = ttk.Button(btns, text="📋 Kısa AOB (~16 Byte)", command=self._copy_short, state="disabled")
        self.copy_short_btn.pack(side="left", padx=(8, 0))

        self.copy_long_btn = ttk.Button(btns, text="📋 Uzun AOB (~32 Byte)", command=self._copy_long, state="disabled")
        self.copy_long_btn.pack(side="left", padx=(8, 0))

        ttk.Button(btns, text="Kapat", command=self._on_close).pack(side="right")

        if Cs is None:
            self._log("[!] Capstone kütüphanesi yüklenemedi - kod analizi devre dışı.")

        dark_titlebar(self)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _save_offset_report(self):
        if not self.hit_map:
            messagebox.showwarning("Sheet Onion", "Kaydedilecek yakalanmış bir komut/offset bulunamadı.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Offset Raporunu Kaydet",
            defaultextension=".txt",
            filetypes=[("Text File (*.txt)", "*.txt"), ("All Files (*.*)", "*.*")]
        )
        if not file_path: return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(f"=== Sheet Onion - Offset & Instruction Raporu ===\n")
                f.write(f"Hedef Adres: 0x{self.target_addr:X} ({self.type_name})\n\n")
                for addr, info in self.hit_map.items():
                    f.write(f"Count: {info['count']} | 0x{addr:X}: {info['mnemonic']} {info['op_str']}\n")
                    f.write(f"Bytes: {' '.join(f'{b:02X}' for b in info['bytes'])}\n\n")
            messagebox.showinfo("Sheet Onion", "Offset raporu başarıyla kaydedildi!")
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor kaydedilemedi: {e}")

    def _log(self, msg):
        if not self.winfo_exists():
            return
        self.text.config(state="normal")
        self.text.insert("end", msg + "\n")
        self.text.config(state="disabled")
        self.text.see("end")

    def _start(self):
        if not self.process_handle:
            self._log("[!] Süreç bağlantısı yok.")
            return
        
        self.hit_map.clear()
        self.tree.delete(*self.tree.get_children())
        self.stop_event = threading.Event()
        
        self.start_btn.config(text="⏹ Yakalamayı Durdur", command=self._stop)
        self.copy_short_btn.config(state="disabled")
        self.copy_long_btn.config(state="disabled")
        self.status_lbl.config(text="Canlı izleme aktif! Oyunda değeri değiştirin/erişin.", foreground=YELLOW)
        
        threading.Thread(target=self._run, daemon=True).start()

    def _stop(self):
        if self.stop_event:
            self.stop_event.set()
        self.status_lbl.config(text="Canlı izleme durduruldu.", foreground=OK)
        self.start_btn.config(text="▶ Yakalamayı Başlat", command=self._start)

    def _run(self):
        is64 = winmem.target_is_64bit(self.process_handle)
        if is64 is None:
            self.after(0, lambda: self._finish_error("Hedef mimari tespit edilemedi."))
            return

        def on_hit_callback(hit_addr):
            if not self.running: return
            self.after(0, lambda addr=hit_addr: self._handle_hit(addr))

        winmem.catch_memory_access(
            self.pid, self.target_addr, self.watch_size, bool(is64),
            on_hit=on_hit_callback,
            stop_event=self.stop_event,
            on_status=lambda m: self.after(0, self._log, m),
        )

    def _handle_hit(self, hit_addr):
        if not self.running: return

        if hit_addr in self.hit_map:
            item_info = self.hit_map[hit_addr]
            item_info["count"] += 1
            item_id = item_info["id"]
            self.tree.item(item_id, values=(
                item_info["count"],
                f"0x{hit_addr:X}",
                f"{item_info['mnemonic']} {item_info['op_str']}",
                " ".join(f"{b:02X}" for b in item_info["bytes"])
            ))
        else:
            is64 = winmem.target_is_64bit(self.process_handle)
            raw = winmem.read_bytes(self.process_handle, hit_addr, 15)
            mnemonic = "???"
            op_str = ""
            insn_bytes = b""

            if raw and Cs is not None:
                md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
                md.detail = True
                try:
                    for insn in md.disasm(raw, hit_addr):
                        mnemonic = insn.mnemonic
                        op_str = insn.op_str
                        insn_bytes = bytes(insn.bytes)
                        
                        extracted_offset = None
                        base_register = None
                        
                        for op in insn.operands:
                            if op.type == X86_OP_MEM:
                                if op.mem.base != 0:
                                    base_register = insn.reg_name(op.mem.base).upper()
                                    extracted_offset = op.mem.disp
                                    break
                                    
                        if extracted_offset is not None:
                            op_str += f"   --> [Offset: 0x{extracted_offset:X}, Base: {base_register}]"

                        break
                except Exception:
                    pass

            bytes_str = " ".join(f"{b:02X}" for b in insn_bytes)
            item_id = self.tree.insert("", "end", values=(
                1,
                f"0x{hit_addr:X}",
                f"{mnemonic} {op_str}",
                bytes_str
            ))
            self.hit_map[hit_addr] = {
                "id": item_id,
                "count": 1,
                "mnemonic": mnemonic,
                "op_str": op_str,
                "bytes": insn_bytes
            }

    def _on_select_match(self, event):
        sel = self.tree.selection()
        if not sel: return
        item = sel[0]
        vals = self.tree.item(item, "values")
        if not vals: return

        match_addr_hex = vals[1]
        match_addr = int(match_addr_hex, 16)
        is64 = winmem.target_is_64bit(self.process_handle)

        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.status_lbl.config(text="Seçilen komut için AOB hesaplanıyor...", foreground=YELLOW)

        short_aob, disasm_lines, err = build_code_aob(self.process_handle, match_addr, is64, total_size=16)
        long_aob, _, _ = build_code_aob(self.process_handle, match_addr, is64, total_size=32)

        for line in disasm_lines:
            self._log(line)

        if err:
            self._log(f"\n[!] Hata: {err}")
            self.copy_short_btn.config(state="disabled")
            self.copy_long_btn.config(state="disabled")
        else:
            self.short_aob = short_aob
            self.long_aob = long_aob

            self._log("\n--- ÜRETİLEN KOD İMZALARI (AOB) ---")
            self._log(f"[KISA AOB (~16 Byte)]:\n{short_aob}\n")
            self._log(f"[UZUN AOB (~32 Byte)]:\n{long_aob}\n")

            self.copy_short_btn.config(state="normal")
            self.copy_long_btn.config(state="normal")
            self.status_lbl.config(text="AOB hazır! Panoya kopyalayabilirsiniz.", foreground=OK)

            self.clipboard_clear()
            self.clipboard_append(self.long_aob)

        self.text.config(state="disabled")

    def _finish_error(self, msg):
        self.status_lbl.config(text=msg, foreground="#d0686b")
        self._log(f"[!] {msg}")
        self.start_btn.config(text="▶ Yakalamayı Başlat", command=self._start)

    def _copy_short(self):
        if self.short_aob:
            self.clipboard_clear()
            self.clipboard_append(self.short_aob)
            self.status_lbl.config(text="Kısa AOB panoya kopyalandı.", foreground=OK)

    def _copy_long(self):
        if self.long_aob:
            self.clipboard_clear()
            self.clipboard_append(self.long_aob)
            self.status_lbl.config(text="Uzun AOB panoya kopyalandı.", foreground=OK)

    def _on_close(self):
        self.running = False
        if self.stop_event:
            self.stop_event.set()
        self.destroy()


class MemoryBrowserDialog(tk.Toplevel):
    def __init__(self, master, scanner_obj, base_addr):
        super().__init__(master)
        self.title("Memory Hex Browser - Live")
        self.geometry("680x600")
        self.configure(bg=BG)
        self.transient(master)
        
        self.scanner = scanner_obj
        self.base_addr = base_addr
        self.prev_data = {}

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Base Address (Hex):").pack(side="left")
        
        self.addr_var = tk.StringVar(value=f"{base_addr:X}")
        self.ent = ttk.Entry(top, textvariable=self.addr_var, width=16)
        self.ent.pack(side="left", padx=6)
        ttk.Button(top, text="Refresh View", command=self._refresh_view).pack(side="left")
        
        wrap = ttk.Frame(self, padding=10)
        wrap.pack(fill="both", expand=True)
        
        self.view = tk.Text(wrap, bg=FIELD, fg=FG, font=MONO, bd=1, relief="solid")
        self.view.tag_configure("changed", foreground=YELLOW)
        self.view.pack(fill="both", expand=True)
        
        self._refresh_view()
        dark_titlebar(self)

    def _refresh_view(self):
        if not self.winfo_exists(): return
        try:
            addr = int(self.addr_var.get(), 16)
        except ValueError: 
            return
            
        self.view.config(state="normal")
        self.view.delete("1.0", "end")
        
        if not self.scanner.handle:
            self.view.insert("end", "Error: Process not attached.")
            self.view.config(state="disabled")
            return
            
        for i in range(40):
            curr_addr = addr + (i * 16)
            buf = winmem.read_bytes(self.scanner.handle, curr_addr, 16)
            if not buf:
                self.view.insert("end", f"{curr_addr:08X}  ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??\n")
                continue
            
            line_str = f"{curr_addr:08X}  "
            self.view.insert("end", line_str)
            
            for idx, b in enumerate(buf):
                pos = f"{curr_addr + idx}"
                byte_hex = f"{b:02X} "
                if pos in self.prev_data and self.prev_data[pos] != b:
                    self.view.insert("end", byte_hex, "changed")
                else:
                    self.view.insert("end", byte_hex)
                self.prev_data[pos] = b
            
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in buf)
            self.view.insert("end", f" |{ascii_part}|\n")
            
        self.view.config(state="disabled")
        self.after(2000, self._refresh_view)


def main():
    app = SheetOnion()
    app.mainloop()


if __name__ == "__main__":
    main()

# --- END OF FILE Engine-main/app.py ---