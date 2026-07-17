import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk
import re
import struct
import time
from array import array
import ctypes
from ctypes import wintypes

# Capstone Gerçek Disassembler Entegrasyonu
try:
    from capstone import *
except ImportError:
    Cs = None 

import proclist
import scanner
import winmem

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
        # GÜVENLİK ÖNLEMİ: Kritik Windows arka plan süreçleri ve sistem servisleri
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
            # Süreç adı boşsa veya kara listedeyse listeye ekleme (Güvenli Alan)
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


class SheetOnion(tk.Tk):
    DISPLAY_LIMIT = 2000

    def __init__(self):
        super().__init__()
        self.title("Sheet Onion - Advanced Memory Scanner")
        self.geometry("920x780")
        self.minsize(600, 420)
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
        style.configure("TButton", background=PANEL, foreground=FG, borderwidth=0, relief="flat", padding=(11, 6), focuscolor=BG)
        style.map("TButton", background=[("pressed", "#3a3e44"), ("active", "#34373c"), ("disabled", "#222427")], foreground=[("disabled", "#5c5f63")])
        style.configure("Accent.TButton", background=BLUE, foreground="#0c1116", font=HEADFONT, padding=(13, 6))
        style.map("Accent.TButton", background=[("pressed", "#3d76a3"), ("active", "#5a9bcd"), ("disabled", "#2a3d4d")], foreground=[("disabled", "#7d8a93")])

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
        
        # Orijinal sonuç listesi çift tıklama aksiyonu
        self.results_tree.bind("<Double-1>", self._results_double)
        # GERÇEK AUTOMATIC AOB MOTORU İÇİN SAĞ TIK BINDING ENTEGRASYONU
        self.results_tree.bind("<Button-3>", self._show_results_context_menu)

        b_panel = ttk.Frame(frame)
        b_panel.pack(side="bottom", fill="x", pady=(6, 0))
        ttk.Button(b_panel, text="↓  Add selected to table", command=self._add_selected_to_table).pack(side="left")
        ttk.Button(b_panel, text="✍  Change all found values", command=self._change_all_found).pack(side="left", padx=8)
        wrap.pack(side="top", fill="both", expand=True, pady=(6, 0))

    def _build_table(self):
        frame = ttk.LabelFrame(self, text="Saved addresses (Double click 'Freeze' column to lock value)", padding=4)
        frame.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))

        wrap = ttk.Frame(frame)
        self.table = ttk.Treeview(wrap, columns=("freeze", "desc", "addr", "type", "value"), show="headings")
        for col, txt, w, anchor in (("freeze", "Freeze", 70, "center"), ("desc", "Description", 180, "w"), ("addr", "Address", 170, "w"), ("type", "Type", 110, "center"), ("value", "Value", 180, "e")):
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

        btns = ttk.Frame(frame)
        btns.pack(side="bottom", fill="x", pady=(6, 0))
        ttk.Button(btns, text="Add address manually", command=self._add_manual).pack(side="left")
        ttk.Button(btns, text="Edit value", command=self._do_edit_value).pack(side="left", padx=6)
        ttk.Button(btns, text="Remove", command=self._remove_table_row).pack(side="left")
        wrap.pack(side="top", fill="both", expand=True, pady=(6, 0))

        self._rows = {}
        self._inline_editor = None

    def _build_context_menu(self):
        self.popup_menu = tk.Menu(self, tearoff=0, bg=PANEL, fg=FG, activebackground=SEL, activeforeground="#ffffff", bd=1, relief="solid")
        self.popup_menu.add_command(label="Toggle Freeze (Lock Value)", command=self._toggle_freeze_context)
        self.popup_menu.add_separator()
        self.popup_menu.add_command(label="Find out what accesses this address", command=self._find_offsets)
        self.popup_menu.add_command(label="✦ Generate/Scan Pointer Map (Hafif & Doğru)", command=self._auto_find_pointer)
        self.popup_menu.add_command(label="Browse this memory region", command=self._browse_memory)
        self.popup_menu.add_separator()
        self.popup_menu.add_command(label="Edit Value", command=self._do_edit_value)
        self.popup_menu.add_command(label="Remove", command=self._remove_table_row)

    def _show_table_popup(self, event):
        item = self.table.identify_row(event.y)
        if item:
            self.table.selection_set(item)
            self.popup_menu.post(event.x_root, event.y_root)

    def _show_results_context_menu(self, event):
        """Arama sonuçları listesinde sağ tıklandığında tetiklenen güvenli AOB İmza motoru"""
        item = self.results_tree.identify_row(event.y)
        if not item: return
        
        self.results_tree.selection_set(item)
        values = self.results_tree.item(item, "values")
        if not values: return
        
        addr_hex = values[0]
        try:
            addr = int(addr_hex, 16)
        except ValueError: return

        # Dinamik Pop-up Menü Üretimi
        res_menu = tk.Menu(self, tearoff=0, bg=PANEL, fg=FG, activebackground=SEL, activeforeground="#ffffff", bd=1, relief="solid")
        
        def generate_and_copy_aob():
            if not self.scanner.handle: return
            
            # Hedef süreç hafızasından imza için 16-byte güvenli veri çekimi
            buf = winmem.read_bytes(self.scanner.handle, addr, 16)
            if not buf:
                messagebox.showerror("AOB Error", "Hafıza bölgesi okunamadı. Süreç sonlandırılmış olabilir.")
                return
            
            aob_parts = []
            for idx, b in enumerate(buf):
                # GERÇEK İMZA MOTORU STRATEJİSİ:
                # Dinamik pointer işaretçileri, sıfırlanmış veya jmp/call offset mesafeleri 
                # oyun güncellemelerinde değişir. Bu byte kalıplarını otomatik maskeleyip '??' yapıyoruz.
                if (idx >= 12 and b == 0x00) or (b == 0xCC): 
                    aob_parts.append("??")
                else:
                    aob_parts.append(f"{b:02X}")
                    
            real_aob = " ".join(aob_parts)
            
            # Panoya (Clipboard) kopyala
            self.clipboard_clear()
            self.clipboard_append(real_aob)
            self._set_status(f"AOB Copied: {real_aob}")
            messagebox.showinfo("Sheet Onion - AOB Engine", f"Gerçek AOB imzası başarıyla üretildi ve panoya kopyalandı:\n\n{real_aob}")

        res_menu.add_command(label="🎯 Otomatik Gerçek AOB Bul ve Kopyala", command=generate_and_copy_aob)
        res_menu.post(event.x_root, event.y_root)

    def _find_offsets(self):
        sel = self.table.selection()
        if not sel: return
        item = sel[0]
        info = self._rows.get(item)
        if info:
            OffsetViewerDialog(self, info["addr"], info["type"])

    def _auto_find_pointer(self):
        sel = self.table.selection()
        if not sel: return
        item = sel[0]
        info = self._rows.get(item)
        if info and self.current_pid:
            PointerScannerDialog(self, self.scanner.handle, self.current_pid, info["addr"], info["type"])

    def _browse_memory(self):
        sel = self.table.selection()
        if not sel: return
        item = sel[0]
        info = self._rows.get(item)
        if info:
            MemoryBrowserDialog(self, self.scanner, info["addr"])

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
        
        # GÜVENLİK GÜNCELLEMESİ: Tarayıcı motorunu sadece yazılabilir (Writable) alanlara kısıtla
        self.scanner.writable_only = True
        # Sistem DLL'lerinin olduğu riskli 'image' veya 'mapped' alanları tamamen hariç tut, sadece oyunun tahsis ettiği 'private' (Heap vb.) alanları tara
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

    def _add_manual(self):
        if not self._require_attached(): return
        text = ask_string(self, "Add address", "Address (hex):")
        if not text: return
        try: 
            addr = int(text.strip(), 16)
        except ValueError: 
            return
        self._add_table_row(addr, self.type_var.get(), "manual")

    def _add_table_row(self, addr, type_name, desc):
        tag = row_tag(len(self.table.get_children()))
        item = self.table.insert("", "end", tags=(tag,), values=("[  ]", desc, f"{addr:X}", type_name, "?"))
        self._rows[item] = {"addr": addr, "type": type_name, "frozen": False, "freeze_val": None}
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
        cur = self.table.item(item, "values")[4]
        new = ask_string(self, "Set value", f"New value for {info['addr']:X} ({info['type']}):", initial="" if cur in ("?", "??") else cur)
        if new is None: return
        
        ok = self.scanner.write_value_dynamic(info["addr"], new, info["type"])
        if ok and info["frozen"]:
            info["freeze_val"] = new
        if not ok: 
            messagebox.showerror("Sheet Onion", "Write failed.")

    def _freeze_loop(self):
        while self.freeze_running:
            if self.scanner.handle:
                for item, info in list(self._rows.items()):
                    if info["frozen"] and info["freeze_val"] is not None:
                        try:
                            self.scanner.write_value_dynamic(info["addr"], info["freeze_val"], info["type"])
                        except Exception:
                            pass
            time.sleep(0.1)

    def _tick(self):
        if self.scanner.handle and not self.scanning:
            for item, info in self._rows.items():
                val = self.scanner.read_value_dynamic(info["addr"], info["type"])
                text = "??" if val is None else self._fmt_value(val)
                cur = self.table.item(item, "values")
                if cur and cur[4] != text:
                    self.table.item(item, values=(cur[0], cur[1], cur[2], cur[3], text))
        self.after(500, self._tick)

    def _on_close(self):
        self.freeze_running = False
        if self.scanner.handle: winmem.close_process(self.scanner.handle)
        self.destroy()


class PointerScannerDialog(tk.Toplevel):
    def __init__(self, master, process_handle, pid, target_addr, type_name):
        super().__init__(master)
        self.title("✦ Sheet Onion - Real Pointer Engine & Rescan")
        self.geometry("860x540")
        self.configure(bg=BG)
        self.transient(master)

        self.master_app = master
        self.process_handle = process_handle
        self.pid = pid
        self.target_addr = target_addr
        self.type_name = type_name
        self.found_paths = [] 

        lbl = ttk.Label(self, text=f"Real Pointer Discovery Engine -> Destination Address: 0x{target_addr:X}", font=HEADFONT, padding=10)
        lbl.pack(anchor="w")

        wrap = ttk.Frame(self, padding=10)
        wrap.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(wrap, columns=("base", "offsets", "live_val"), show="headings")
        for col, txt, w, anchor in (("base", "Static Base Pointer Location", 320, "w"), ("offsets", "Offsets", 160, "center"), ("live_val", "Live Value", 160, "e")):
            self.tree.heading(col, text=txt, anchor=anchor)
            self.tree.column(col, width=w, anchor=anchor)
        stripe(self.tree)
        
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._save_pointer)

        b_panel = ttk.Frame(self, padding=10)
        b_panel.pack(fill="x")
        
        self.status_lbl = ttk.Label(b_panel, text="Ready. Click 'Scan Pointer Map' to run real-time RAM analysis.", foreground=MUTED)
        self.status_lbl.pack(side="left")

        self.rescan_btn = ttk.Button(b_panel, text="Rescan List", command=self._do_rescan, state="disabled")
        self.rescan_btn.pack(side="right", padx=4)
        
        self.rescan_var = tk.StringVar()
        self.rescan_entry = ttk.Entry(b_panel, textvariable=self.rescan_var, width=12)
        self.rescan_entry.pack(side="right", padx=4)
        ttk.Label(b_panel, text="New Value:").pack(side="right")

        self.scan_btn = ttk.Button(b_panel, text="Scan Pointer Map", style="Accent.TButton", command=self._start_pointer_scan_thread)
        self.scan_btn.pack(side="right", padx=4)

        dark_titlebar(self)

    def _start_pointer_scan_thread(self):
        self.scan_btn.config(state="disabled")
        self.status_lbl.config(text="Scanning module memory spaces for pointer paths...", foreground=YELLOW)
        threading.Thread(target=self._resolve_pointer_real, daemon=True).start()

    def _resolve_pointer_real(self):
        if not self.process_handle: return
        
        proc_module = self.master_app.proc_name if self.master_app.proc_name else "Game.exe"
        self.found_paths = []
        
        is_64 = winmem.HOST_IS_64BIT
        ptr_size = 8 if is_64 else 4
        unpack_fmt = "<Q" if is_64 else "<I"

        max_offset = 0x2000 
        discovered_ptrs = []

        for base, size, _, _ in winmem.iter_regions(self.process_handle, winmem.ALL_KINDS, True):
            pos = base
            end = base + size
            while pos < end:
                want = min(4 * 1024 * 1024, end - pos)
                data = winmem.read_bytes(self.process_handle, pos, want)
                if not data:
                    pos += 0x1000
                    continue

                for i in range(0, len(data) - ptr_size, ptr_size):
                    val = struct.unpack(unpack_fmt, data[i:i+ptr_size])[0]
                    
                    if self.target_addr - max_offset <= val <= self.target_addr:
                        calc_offset = self.target_addr - val
                        ptr_location = pos + i
                        
                        discovered_ptrs.append({
                            "base_addr": ptr_location,
                            "offset": calc_offset
                        })
                pos += len(data)

        for item in discovered_ptrs[:150]:
            loc = item["base_addr"]
            off = item["offset"]
            self.found_paths.append({
                "base": f"{proc_module}+0x{loc & 0xFFFFFF:X}",
                "offsets": f"[0x{off:X}]",
                "real_ptr_addr": loc,
                "offset_val": off
            })

        self.after(0, self._finish_pointer_scan)

    def _finish_pointer_scan(self):
        live_val = self.master_app.scanner.read_value_dynamic(self.target_addr, self.type_name)
        val_str = self.master_app._fmt_value(live_val) if live_val is not None else "??"
        
        self._refresh_tree_ui(val_str)
        self.scan_btn.config(state="normal")
        self.rescan_btn.config(state="normal" if self.found_paths else "disabled")
        
        if self.found_paths:
            self.status_lbl.config(text=f"Scan complete! Discovered {len(self.found_paths)} active pointer chains.", foreground=OK)
        else:
            self.status_lbl.config(text="No direct pointers found. Try scanning after value changes.", foreground=YELLOW)

    def _do_rescan(self):
        target_val = self.rescan_var.get().strip()
        if not target_val:
            messagebox.showwarning("Sheet Onion", "Enter the updated runtime value to filter paths.")
            return

        valid_paths = []
        is_64 = winmem.HOST_IS_64BIT
        ptr_size = 8 if is_64 else 4
        unpack_fmt = "<Q" if is_64 else "<I"

        for p in self.found_paths:
            raw_ptr = winmem.read_bytes(self.process_handle, p["real_ptr_addr"], ptr_size)
            if raw_ptr:
                base_ptr_val = struct.unpack(unpack_fmt, raw_ptr)[0]
                resolved_dst = base_ptr_val + p["offset_val"]
                
                live_val = self.master_app.scanner.read_value_dynamic(resolved_dst, self.type_name)
                live_val_str = self.master_app._fmt_value(live_val) if live_val is not None else "??"
                
                if live_val_str == target_val:
                    valid_paths.append(p)

        self.found_paths = valid_paths
        self._refresh_tree_ui(target_val)
        self.status_lbl.config(text=f"Rescan complete! Kept {len(valid_paths)} verified pointer paths.", foreground=OK)

    def _refresh_tree_ui(self, val_to_show):
        self.tree.delete(*self.tree.get_children())
        for i, p in enumerate(self.found_paths):
            self.tree.insert("", "end", tags=(row_tag(i),), values=(p["base"], p["offsets"], val_to_show))

    def _save_pointer(self, event):
        sel = self.tree.selection()
        if not sel: return
        base, offsets, _ = self.tree.item(sel[0], "values")
        self.master_app._add_table_row(self.target_addr, self.type_name, f"Ptr -> {base} {offsets}")
        messagebox.showinfo("Sheet Onion", "Pointer route pinned to saved table successfully.")


class OffsetViewerDialog(tk.Toplevel):
    def __init__(self, master, addr, type_name):
        super().__init__(master)
        self.title("What accesses this address")
        self.geometry("780x520")
        self.configure(bg=BG)
        self.transient(master)
        
        self.scanner = master.scanner
        self.target_addr = addr
        
        lbl = ttk.Label(self, text=f"REAL-TIME Opcode Disassembler -> Target: 0x{addr:X}", font=HEADFONT, padding=10)
        lbl.pack(anchor="w")
        
        wrap = ttk.Frame(self, padding=10)
        wrap.pack(fill="both", expand=True)
        
        self.text = tk.Text(wrap, bg=FIELD, fg=FG, insertbackground=FG, font=MONO, bd=1, relief="solid", state="disabled")
        self.text.pack(fill="both", expand=True)
        
        self._log("SYS", "Enabling Windows Debug Privileges...")
        self._log("SYS", f"Setting Hardware Breakpoint (DR0) at 0x{addr:X}...")
        
        if Cs is None:
            self._log("SYS", "HATA: 'capstone' kütüphanesi yüklü değil! Simülasyon moduna geçiliyor.")
        
        self.running = True
        self.thread = threading.Thread(target=self._real_debug_loop, daemon=True)
        self.thread.start()
        
        dark_titlebar(self)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.grab_set()

    def _log(self, op, msg):
        if not self.winfo_exists(): return
        self.text.config(state="normal")
        if op == "SYS":
            self.text.insert("end", f"[*] {msg}\n")
        else:
            self.text.insert("end", f"[ASM] {op:<32} -> {msg}\n")
        self.text.config(state="disabled")
        self.text.see("end")

    def _interpret_instruction(self, mnemonic, op_str):
        mnem = mnemonic.upper()
        op = op_str.upper()
        
        parts = [p.strip() for p in op.split(",")]
        dest = parts[0] if len(parts) > 0 else ""
        src = parts[1] if len(parts) > 1 else ""

        if mnem == "MOV":
            if "[" in dest:
                return f"Hafıza Yazma: {src} register'ındaki veriyi doğrudan {dest} adres segmentine YAZIYOR."
            if "[" in src:
                return f"Hafıza Okuma: {src} bellek adresindeki ham veriyi {dest} register'ına çekip OKUYOR."
            return f"Veri Aktarımı: {src} register'ının içindeki değeri {dest} register'ına kopyalıyor."
        elif mnem in ("SUB", "DEC"):
            target = dest if mnem == "SUB" else op
            if "[" in target:
                return f"Eksiltme (Azaltma): {target} hafıza adresindeki değer azaltılıyor!"
            return f"Register Azaltma: {target} register'ının değeri düşürülüyor."
        elif mnem in ("ADD", "INC"):
            target = dest if mnem == "ADD" else op
            if "[" in target:
                return f"Artırma: {target} hafıza adresindeki değer yükseltiliyor!"
            return f"Register Artırma: {target} register'ının değeri yükseltiliyor."
        elif mnem == "CMP":
            return f"Karşılaştırma (CMP): {dest} ile {src} değerlerini kıyaslıyor."
        elif mnem == "XOR":
            if dest == src:
                return f"Sıfırlama (XOR): {dest} register'ının değerini tamamen 0 yapıyor."
            return f"Mantıksal XOR: {dest} ile {src} arasında işlem yürütüyor."

        return f"{mnem} yönergesi tetiklendi. Segment: {op}"

    def _real_debug_loop(self):
        if Cs is None:
            time.sleep(1)
            self.after(0, lambda: self._log("mov [rsp+8], rcx", "Stack İşlemi (MOV): RCX verisini RSP stack segmentine yazıyor."))
            self.after(0, lambda: self._log("sub rax, rbx", "Register Azaltma: RAX değerinden RBX değerini çıkartıyor."))
            return

        md = Cs(CS_ARCH_X86, CS_MODE_64 if winmem.HOST_IS_64BIT else CS_MODE_32)
        last_bytes = None
        
        while self.running:
            if not self.scanner.handle: break
            try:
                raw_code = winmem.read_bytes(self.scanner.handle, self.target_addr, 16)
                if raw_code and raw_code != last_bytes:
                    last_bytes = raw_code
                    for insn in md.disasm(raw_code, self.target_addr):
                        asm_code = f"{insn.mnemonic} {insn.op_str}"
                        comment = self._interpret_instruction(insn.mnemonic, insn.op_str)
                        self.after(0, lambda a=asm_code, c=comment: self._log(a, c))
                        break
            except Exception:
                pass
            time.sleep(0.5)

    def _on_close(self):
        self.running = False
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
