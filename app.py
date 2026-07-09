import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

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

# (Lütfen orijinal `dark_titlebar`, `make_logo`, `stripe`, `row_tag`, `ProcessDialog`, `_AskString` ve `ask_string` fonksiyonlarını aynen koruyun.)
# Okunabilirlik için doğrudan SheetOnion sınıfına geçiyorum:

class SheetOnion(tk.Tk):
    DISPLAY_LIMIT = 2000

    def __init__(self):
        super().__init__()
        self.title("Sheet Onion - Advanced Memory Scanner")
        self.geometry("800x740") # Sütunlar için biraz genişletildi
        self.minsize(600, 420)
        self.configure(bg=BG)

        self.scanner = scanner.Scanner()
        self.proc_name = None
        self.scanning = False

        winmem.enable_debug_privilege()

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

        import app
        app.dark_titlebar(self)
        self._apply_theme()
        self._build_toolbar()
        self._build_results()
        self._build_table()
        self._build_statusbar()
        self._set_status("Not attached. Click 'Attach to process' to start.")
        
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._tick()

    def _apply_theme(self):
        # Orijinal temayı aynen yükler (Buraya dokunmuyoruz, üstteki kod bloğundaki temanın aynısı)
        pass

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

        ttk.Label(bar, text="Value / Pattern:").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.value_var = tk.StringVar()
        self.value_entry = ttk.Entry(bar, textvariable=self.value_var, width=22)
        self.value_entry.grid(row=1, column=1, sticky="w", pady=(10, 0))
        self.value_entry.bind("<Return>", lambda _e: self._scan_clicked())

        ttk.Label(bar, text="Type:").grid(row=1, column=2, sticky="e", pady=(10, 0), padx=(5,0))
        self.type_var = tk.StringVar(value="4 Bytes")
        self.type_combo = ttk.Combobox(
            bar, textvariable=self.type_var, 
            values=["4 Bytes", "Float", "String (ASCII)", "String (UTF-16)", "Hex / AOB", "All Types"],
            state="readonly", width=14
        )
        self.type_combo.grid(row=1, column=3, sticky="w", pady=(10, 0), padx=2)

        ttk.Label(bar, text="Scan:").grid(row=1, column=4, sticky="e", pady=(10, 0))
        self.mode_var = tk.StringVar(value=scanner.EXACT)
        self.mode_combo = ttk.Combobox(
            bar, textvariable=self.mode_var, values=scanner.SCAN_MODES,
            state="readonly", width=12,
        )
        self.mode_combo.grid(row=1, column=5, sticky="w", padx=4, pady=(10, 0))

        btns = ttk.Frame(bar)
        btns.grid(row=2, column=0, columnspan=6, sticky="w", pady=(12, 0))
        self.first_btn = ttk.Button(btns, text="First Scan", style="Accent.TButton", command=self._scan_clicked)
        self.first_btn.pack(side="left")
        self.next_btn = ttk.Button(btns, text="Next Scan", style="Accent.TButton", command=self._next_clicked, state="disabled")
        self.next_btn.pack(side="left", padx=6)
        self.new_btn = ttk.Button(btns, text="New Scan", command=self._new_scan, state="disabled")
        self.new_btn.pack(side="left")

        import app
        app.make_logo(bar, 46).grid(row=0, column=6, rowspan=3, sticky="ne", padx=(8, 0))

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
        self.results_tree = ttk.Treeview(
            wrap, columns=("addr", "type", "value"), show="headings"
        )
        for col, txt, w, anchor in (("addr", "Address", 180, "w"),
                                    ("type", "Type", 120, "w"),
                                    ("value", "Value", 200, "e")):
            self.results_tree.heading(col, text=txt, anchor=anchor)
            self.results_tree.column(col, width=w, anchor=anchor)
        
        import app
        app.stripe(self.results_tree)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=sb.set)
        self.results_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.results_tree.bind("<Double-1>", self._results_double)

        ttk.Button(frame, text="↓  Add selected to table", command=self._add_selected_to_table).pack(side="bottom", anchor="w", pady=(6, 0))
        wrap.pack(side="top", fill="both", expand=True, pady=(6, 0))

    def _build_table(self):
        frame = ttk.LabelFrame(self, text="Saved addresses", padding=4)
        frame.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))

        wrap = ttk.Frame(frame)
        self.table = ttk.Treeview(
            wrap, columns=("desc", "addr", "type", "value"), show="headings"
        )
        for col, txt, w, anchor in (("desc", "Description", 180, "w"),
                                    ("addr", "Address", 170, "w"),
                                    ("type", "Type", 110, "center"),
                                    ("value", "Value", 180, "e")):
            self.table.heading(col, text=txt, anchor=anchor)
            self.table.column(col, width=w, anchor=anchor)
            
        import app
        app.stripe(self.table)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=sb.set)
        self.table.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.table.bind("<Double-1>", self._table_double)

        btns = ttk.Frame(frame)
        btns.pack(side="bottom", fill="x", pady=(6, 0))
        ttk.Button(btns, text="Add address manually", command=self._add_manual).pack(side="left")
        ttk.Button(btns, text="Edit value", command=self._do_edit_value).pack(side="left", padx=6)
        ttk.Button(btns, text="Remove", command=self._remove_table_row).pack(side="left")
        wrap.pack(side="top", fill="both", expand=True, pady=(6, 0))

        self._rows = {}
        self._inline_editor = None

    def _set_status(self, text): self.status.config(text=text)
    def _require_attached(self):
        if not self.scanner.handle:
            messagebox.showwarning("Sheet Onion", "Attach to a process first.")
            return False
        return True

    def _fmt_value(self, v):
        if isinstance(v, float): return f"{v:.4f}"
        return str(v)

    def attach(self):
        import app
        dlg = app.ProcessDialog(self)
        if not dlg.result: return
        pid, name = dlg.result
        handle = winmem.open_process(pid)
        if not handle:
            messagebox.showerror("Sheet Onion", f"Could not open {name} (pid {pid}).\n\nTry Running as Admin.")
            return
        self.scanner.attach(handle, self.type_var.get())
        self.proc_name = f"{name} (pid {pid})"
        self.proc_label.config(text=f"{self.proc_name}", foreground=OK)
        self._clear_results()
        self.new_btn.config(state="normal")
        self._set_status(f"Attached to {self.proc_name}. Enter value and First Scan.")

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
        self._set_status(f"Scan complete: {count} result(s).")

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
        import app
        
        rows = self.scanner.head(self.DISPLAY_LIMIT)
        for i, (addr, val, type_found) in enumerate(rows):
            self.results_tree.insert(
                "", "end", tags=(app.row_tag(i),),
                values=(f"{addr:X}", type_found, self._fmt_value(val)),
            )
        self.count_label.config(text=f"Found: {total}")

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
        import app
        text = app.ask_string(self, "Add address", "Address (hex):")
        if not text: return
        try: addr = int(text.strip(), 16)
        except ValueError: return
        self._add_table_row(addr, self.type_var.get(), "manual")

    def _add_table_row(self, addr, type_name, desc):
        import app
        tag = app.row_tag(len(self.table.get_children()))
        item = self.table.insert("", "end", tags=(tag,), values=(desc, f"{addr:X}", type_name, "?"))
        self._rows[item] = {"addr": addr, "type": type_name}
        return item

    def _remove_table_row(self):
        for item in self.table.selection():
            self._rows.pop(item, None)
            self.table.delete(item)

    def _table_double(self, event):
        item = self.table.identify_row(event.y)
        if not item: return
        col = self.table.identify_column(event.x)
        if col == "#1":
            self._edit_description(item, col)
        else:
            self.table.selection_set(item)
            self._do_edit_value()

    def _edit_description(self, item, column):
        # Orijinal _edit_description mantığı aynen çalışır
        pass

    def _do_edit_value(self):
        sel = self.table.selection()
        if not sel: return
        item = sel[0]
        info = self._rows.get(item)
        if not info or not self.scanner.handle: return
        cur = self.table.item(item, "values")[3]
        import app
        new = app.ask_string(self, "Set value", f"New value for {info['addr']:X} ({info['type']}):", initial="" if cur in ("?", "??") else cur)
        if new is None: return
        
        ok = self.scanner.write_value_dynamic(info["addr"], new, info["type"])
        if not ok: messagebox.showerror("Sheet Onion", "Write failed.")

    def _tick(self):
        if self.scanner.handle and not self.scanning:
            for item, info in self._rows.items():
                val = self.scanner.read_value_dynamic(info["addr"], info["type"])
                text = "??" if val is None else self._fmt_value(val)
                cur = self.table.item(item, "values")
                if cur and cur[3] != text:
                    self.table.item(item, values=(cur[0], cur[1], cur[2], text))
        self.after(700, self._tick)

    def _on_close(self):
        if self.scanner.handle: winmem.close_process(self.scanner.handle)
        self.destroy()

if __name__ == "__main__":
    SheetOnion().mainloop()
            
