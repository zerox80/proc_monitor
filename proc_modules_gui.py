#!/usr/bin/env python3
"""Inspect file-backed Linux process mappings, copy details and export JSON."""

import json
import os
import subprocess
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


SYSTEM_PREFIXES = ("/usr/lib", "/lib", "/lib64", "/usr/lib64")


def read_cmdline(pid: int) -> str:
    try:
        data = Path(f"/proc/{pid}/cmdline").read_bytes()
        parts = [p.decode(errors="replace") for p in data.split(b"\0") if p]
        return " ".join(parts) if parts else f"[{pid}]"
    except OSError:
        return ""


def read_comm(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text(errors="replace").strip()
    except OSError:
        return "?"


def read_uid(pid: int):
    try:
        return Path(f"/proc/{pid}").stat().st_uid
    except OSError:
        return None


def exe_path(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def mapped_files(pid: int, executable_only=True):
    """Group mappings by file while preserving every matching memory region.

    OSError is deliberately passed to the caller so an inaccessible process
    can be distinguished from a readable process with no matching mappings.
    """
    results = {}
    with open(f"/proc/{pid}/maps", "r", errors="replace") as source:
        for line in source:
            parts = line.rstrip("\n").split(None, 5)
            if len(parts) < 6:
                continue
            address, perms, offset, device, inode, raw_path = parts
            if not raw_path.startswith("/") or (executable_only and "x" not in perms):
                continue
            path = raw_path.removesuffix(" (deleted)")
            start, end = address.split("-", 1)
            module = results.setdefault(path, {
                "name": Path(path).name,
                "path": path,
                "deleted": False,
                "mappings": [],
            })
            module["deleted"] = module["deleted"] or raw_path.endswith(" (deleted)")
            module["mappings"].append({
                "permissions": perms,
                "start": f"0x{start}",
                "end": f"0x{end}",
                "offset": f"0x{offset}",
                "device": device,
                "inode": int(inode),
            })
    return sorted(results.values(), key=lambda module: module["path"].lower())


def is_system_path(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in SYSTEM_PREFIXES)


def module_kind(path: str, executable: str) -> str:
    if path == executable.removesuffix(" (deleted)"):
        return "MAIN"
    if Path(path).suffix.lower() == ".node":
        return "NODE"
    if ".so" in Path(path).name:
        return "SO"
    return "ELF/FILE"


class ProcModuleViewer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Process Explorer · Linux")
        self.geometry("1440x900")
        self.minsize(1120, 760)
        self._configure_theme()

        self.current_pid = None
        self.process_rows = []
        self.process_info = {}
        self.modules = []
        self.visible_modules = []
        self.module_items = {}
        self.module_error = ""
        self.loaded_at = None
        self.sort_column = "name"
        self.sort_reverse = False
        self.sidebar_visible = True
        self.sidebar_width = 480

        self.search_var = tk.StringVar()
        self.module_search_var = tk.StringVar()
        self.only_exec_var = tk.BooleanVar(value=True)
        self.hide_system_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Bereit")
        self.exe_var = tk.StringVar()
        self.command_var = tk.StringVar()
        self.file_name_var = tk.StringVar()
        self.selection_var = tk.StringVar(value="Datei auswählen, um alle Details zu sehen")
        self.process_count_var = tk.StringVar(value="0 Prozesse")
        self.module_count_var = tk.StringVar(value="0 Dateien")

        self._build_ui()
        self.search_var.trace_add("write", lambda *_: self.populate_process_tree())
        self.module_search_var.trace_add("write", lambda *_: self.populate_module_tree())
        self.bind("<F5>", lambda _event: self.refresh_processes())
        self.bind("<Control-e>", lambda _event: self.export_json())
        self.bind("<Control-E>", lambda _event: self.export_json())
        self.refresh_processes()

    def _configure_theme(self):
        self.colors = {"background": "#edf2f8", "card": "#ffffff", "ink": "#20324a",
                       "muted": "#687b92", "accent": "#2563eb", "border": "#d7e1ee"}
        self.configure(background=self.colors["background"])
        self.option_add("*Font", ("DejaVu Sans", 10))
        self.option_add("*Menu.background", "#ffffff")
        self.option_add("*Menu.foreground", "#20324a")
        self.option_add("*Menu.activeBackground", "#dbeafe")
        self.option_add("*Menu.activeForeground", "#143b76")
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background="#edf2f8", foreground="#20324a", font=("DejaVu Sans", 10))
        style.configure("TFrame", background="#edf2f8")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("TLabel", background="#ffffff")
        style.configure("Muted.TLabel", foreground="#687b92", font=("DejaVu Sans", 9))
        style.configure("Section.TLabel", font=("DejaVu Sans", 11, "bold"))
        style.configure("Count.TLabel", foreground="#2563eb", font=("DejaVu Sans", 9, "bold"))
        style.configure("TButton", background="#eaf0f8", foreground="#20324a", padding=(12, 5),
                        borderwidth=0, relief="flat", font=("DejaVu Sans", 9))
        style.map("TButton", background=[("active", "#dce7f6"), ("pressed", "#ccdaf0")])
        style.configure("Accent.TMenubutton", background="#2563eb", foreground="#ffffff",
                        padding=(14, 8), borderwidth=0, font=("DejaVu Sans", 9, "bold"))
        style.map("Accent.TMenubutton", background=[("active", "#1d4ed8")])
        style.configure("Header.TButton", background="#294361", foreground="#ffffff", padding=(14, 8))
        style.map("Header.TButton", background=[("active", "#36577b")])
        style.configure("TEntry", fieldbackground="#f8fafd", foreground="#20324a", padding=4,
                        bordercolor="#d7e1ee", lightcolor="#d7e1ee", darkcolor="#d7e1ee")
        style.map("TEntry", fieldbackground=[("readonly", "#f8fafd")],
                  bordercolor=[("focus", "#2563eb")])
        style.configure("TCheckbutton", background="#ffffff", padding=(0, 4), font=("DejaVu Sans", 9))
        style.map("TCheckbutton", background=[("active", "#ffffff")])
        style.configure("TLabelframe", background="#ffffff", bordercolor="#d7e1ee", borderwidth=1,
                        relief="solid")
        style.configure("TLabelframe.Label", background="#ffffff", foreground="#687b92",
                        font=("DejaVu Sans", 9, "bold"))
        style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff", foreground="#20324a",
                        rowheight=32, borderwidth=0, font=("DejaVu Sans", 9))
        style.map("Treeview", background=[("selected", "#dbeafe")], foreground=[("selected", "#163d75")])
        style.configure("Treeview.Heading", background="#edf3fb", foreground="#536a86", padding=(8, 9),
                        borderwidth=0, relief="flat", font=("DejaVu Sans", 9, "bold"))
        style.map("Treeview.Heading", background=[("active", "#e2ebf8")])
        style.configure("TScrollbar", background="#cfdae9", troughcolor="#f2f6fb", borderwidth=0,
                        arrowsize=12)
        style.configure("TPanedwindow", background="#edf2f8", sashwidth=12)
        style.configure("Status.TLabel", background="#edf2f8", foreground="#687b92", font=("DejaVu Sans", 9))

    @staticmethod
    def _scrollable_tree(parent, columns, selectmode):
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode=selectmode, height=1)
        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    def _build_ui(self):
        header = tk.Frame(self, background="#142b45", padx=22, pady=16)
        header.pack(fill="x")
        branding = tk.Frame(header, background="#142b45")
        branding.pack(side="left")
        tk.Label(branding, text="PROCESS EXPLORER", background="#142b45", foreground="#ffffff",
                 font=("DejaVu Sans", 18, "bold"), anchor="w").pack(anchor="w")
        tk.Label(branding, text="Linux  /  Prozesse, Module und Dateidetails", background="#142b45",
                 foreground="#a9bfd8", font=("DejaVu Sans", 9)).pack(anchor="w", pady=(4, 0))
        ttk.Button(header, text="Aktualisieren  ·  F5", style="Header.TButton",
                   command=self.refresh_processes).pack(side="right")
        self.sidebar_toggle = ttk.Button(header, text="◀ Prozesse einklappen", style="Header.TButton",
                                         command=self.toggle_sidebar)
        self.sidebar_toggle.pack(side="right", padx=(0, 8))

        ttk.Label(self, textvariable=self.status_var, style="Status.TLabel", anchor="w", padding=(18, 7)).pack(fill="x", side="bottom")
        paned = self.paned = ttk.Panedwindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=16, pady=(16, 4))
        left = self.process_sidebar = ttk.Frame(paned, style="Card.TFrame", padding=14, width=self.sidebar_width)
        right = ttk.Frame(paned, style="Card.TFrame", padding=14, width=1050)
        left.pack_propagate(False)
        right.pack_propagate(False)
        paned.add(left, weight=0)
        paned.add(right, weight=3)
        ttk.Label(left, text="Prozesse", style="Section.TLabel").pack(anchor="w")
        ttk.Label(left, textvariable=self.process_count_var, style="Muted.TLabel").pack(anchor="w", pady=(3, 12))
        ttk.Label(left, text="Name, PID oder Befehlszeile suchen", style="Muted.TLabel").pack(anchor="w", pady=(0, 5))
        ttk.Entry(left, textvariable=self.search_var).pack(fill="x", pady=(0, 12))
        self.proc_tree = self._scrollable_tree(left, ("pid", "name", "cmd"), "browse")
        for column, title, width in (("pid", "PID", 70), ("name", "Name", 180), ("cmd", "Befehlszeile", 480)):
            self.proc_tree.heading(column, text=title)
            self.proc_tree.column(column, width=width, minwidth=60, stretch=False,
                                  anchor="e" if column == "pid" else "w")
        self.proc_tree.bind("<<TreeviewSelect>>", self.on_process_select)
        self.proc_tree.tag_configure("even", background="#f7faff")
        self.proc_tree.tag_configure("odd", background="#ffffff")

        details = ttk.LabelFrame(right, text=" AKTIVER PROZESS ", padding=10)
        details.pack(fill="x", pady=(0, 14))
        details.columnconfigure(1, weight=1)
        self.proc_label = ttk.Label(details, text="Einen Prozess auswählen", style="Section.TLabel")
        self.proc_label.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))
        for row, title, variable, command in (
            (1, "Programm:", self.exe_var, self.copy_executable),
            (2, "Befehlszeile:", self.command_var, self.copy_command),
        ):
            ttk.Label(details, text=title).grid(row=row, column=0, sticky="w", padx=(0, 6))
            ttk.Entry(details, textvariable=variable, state="readonly").grid(row=row, column=1, sticky="ew", pady=2)
            ttk.Button(details, text="Kopieren", command=command).grid(row=row, column=2, padx=(6, 0))

        module_top = ttk.Frame(right, style="Card.TFrame")
        module_top.pack(fill="x", pady=(0, 6))
        ttk.Label(module_top, text="Module", style="Section.TLabel").pack(side="left")
        ttk.Label(module_top, textvariable=self.module_count_var, style="Count.TLabel").pack(side="left", padx=12)
        ttk.Entry(module_top, textvariable=self.module_search_var, width=24).pack(side="right")
        ttk.Label(module_top, text="Filter:").pack(side="right", padx=(8, 6))
        filters = ttk.Frame(right, style="Card.TFrame")
        filters.pack(fill="x", pady=(0, 10))
        ttk.Checkbutton(filters, text="Nur ausführbare Mappings", variable=self.only_exec_var,
                        command=self.refresh_modules).pack(side="left")
        ttk.Checkbutton(filters, text="System-Libs ausblenden", variable=self.hide_system_var,
                        command=self.populate_module_tree).pack(side="left", padx=(14, 0))
        ttk.Button(filters, text="Neu laden", command=self.refresh_modules).pack(side="right")

        self.mod_tree = self._scrollable_tree(right, ("kind", "name", "path", "perms", "start", "deleted"), "extended")
        self.module_headings = {}
        for column, title, width in (
            ("kind", "Typ", 85), ("name", "Vollständiger Dateiname", 300),
            ("path", "Vollständiger Pfad", 620), ("perms", "Rechte", 95),
            ("start", "Startadresse", 150), ("deleted", "Gelöscht", 75),
        ):
            self.module_headings[column] = title
            self.mod_tree.heading(column, text=title, command=lambda col=column: self.sort_modules(col))
            self.mod_tree.column(column, width=width, minwidth=60, stretch=False)
        self.mod_tree.heading("name", text=self.module_headings["name"] + " ↑")
        self.mod_tree.bind("<<TreeviewSelect>>", self.on_module_select)
        self.mod_tree.bind("<Double-1>", self.on_module_double_click)
        self.mod_tree.bind("<Button-3>", self.show_module_menu)
        self.mod_tree.bind("<Control-c>", self.copy_paths_shortcut)
        self.mod_tree.bind("<Control-C>", self.copy_paths_shortcut)
        self.mod_tree.bind("<Control-a>", self.select_all_modules)
        self.mod_tree.bind("<Control-A>", self.select_all_modules)
        self.mod_tree.bind("<Return>", lambda _event: self.show_file_details())
        self.mod_tree.tag_configure("even", background="#f7faff")
        self.mod_tree.tag_configure("odd", background="#ffffff")

        selected = ttk.LabelFrame(right, text=" DATEIDETAILS ", padding=10)
        selected.pack(fill="x", pady=(14, 0))
        selected.columnconfigure(1, weight=1)
        ttk.Label(selected, text="Dateiname:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(selected, textvariable=self.file_name_var, state="readonly").grid(row=0, column=1, sticky="ew")
        ttk.Button(selected, text="Name kopieren", command=self.copy_selected_name).grid(row=0, column=2, padx=(6, 0))
        ttk.Label(selected, text="Pfad:").grid(row=1, column=0, sticky="nw", pady=(6, 0))
        self.path_text = tk.Text(selected, height=2, width=1, wrap="char", relief="flat", borderwidth=0,
                                 background="#f8fafd", foreground="#20324a", selectbackground="#dbeafe",
                                 selectforeground="#163d75", highlightthickness=1, highlightbackground="#d7e1ee",
                                 font=("DejaVu Sans Mono", 9), padx=8, pady=6, state="disabled")
        self.path_text.grid(row=1, column=1, sticky="ew", pady=(6, 0))
        path_scroll = ttk.Scrollbar(selected, orient="vertical", command=self.path_text.yview)
        path_scroll.grid(row=1, column=2, sticky="ns", pady=(6, 0))
        self.path_text.configure(yscrollcommand=path_scroll.set)
        ttk.Label(selected, textvariable=self.selection_var, style="Muted.TLabel").grid(row=2, column=0, columnspan=3, sticky="w", pady=(7, 0))

        buttons = ttk.Frame(right, style="Card.TFrame")
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Pfad(e) kopieren", command=self.copy_selected_path).pack(side="left")
        ttk.Button(buttons, text="Details…", command=self.show_file_details).pack(side="left", padx=6)
        ttk.Button(buttons, text="Ordner öffnen", command=self.open_selected_folder).pack(side="left")
        export_button = ttk.Menubutton(buttons, text="JSON exportieren…", style="Accent.TMenubutton")
        export_button.pack(side="right")
        export_menu = tk.Menu(export_button, tearoff=False)
        export_menu.add_command(label="Angezeigte Module…  Strg+E", command=self.export_json)
        export_menu.add_command(label="Ausgewählte Module…", command=lambda: self.export_json(selected_only=True))
        export_button.configure(menu=export_menu)

        self.module_menu = tk.Menu(self, tearoff=False)
        self.module_menu.add_command(label="Vollständige Details anzeigen", command=self.show_file_details)
        self.module_menu.add_separator()
        self.module_menu.add_command(label="Dateiname(n) kopieren", command=self.copy_selected_name)
        self.module_menu.add_command(label="Pfad(e) kopieren  Strg+C", command=self.copy_selected_path)
        self.module_menu.add_command(label="Auswahl als JSON kopieren", command=self.copy_selected_json)
        self.module_menu.add_separator()
        self.module_menu.add_command(label="Auswahl als JSON exportieren…", command=lambda: self.export_json(selected_only=True))
        self.module_menu.add_command(label="Alle angezeigten Pfade kopieren", command=self.copy_all_paths)
        self.module_menu.add_separator()
        self.module_menu.add_command(label="Ordner öffnen", command=self.open_selected_folder)

    def toggle_sidebar(self):
        if self.sidebar_visible:
            width = self.paned.sashpos(0)
            if width > 0:
                self.sidebar_width = width
            self.paned.forget(self.process_sidebar)
            self.sidebar_visible = False
            self.sidebar_toggle.configure(text="▶ Prozesse ausklappen")
            self.minsize(1000, 760)
            self.mod_tree.focus_set()
        else:
            self.process_sidebar.configure(width=self.sidebar_width)
            self.minsize(max(1000, self.sidebar_width + 640), 760)
            self.paned.insert(0, self.process_sidebar, weight=0)
            self.sidebar_visible = True
            self.sidebar_toggle.configure(text="◀ Prozesse einklappen")
            # The window may have been resized while the sidebar was hidden.
            # Finish geometry changes before restoring the user's divider position.
            self.update_idletasks()
            if self.paned.winfo_width() > 1:
                self.paned.sashpos(0, self.sidebar_width)


    def refresh_processes(self):
        rows = []
        my_uid = os.getuid()
        for name in os.listdir("/proc"):
            if name.isdigit():
                pid = int(name)
                if read_uid(pid) == my_uid:
                    rows.append((pid, read_comm(pid), read_cmdline(pid)))
        self.process_rows = sorted(rows, key=lambda row: (row[1].lower(), row[0]))
        self.populate_process_tree()
        if self.current_pid is not None:
            self.refresh_modules()
        else:
            self.status_var.set(f"{len(rows)} Prozesse gefunden · Prozess auswählen")

    def populate_process_tree(self):
        query = self.search_var.get().strip().lower()
        self.proc_tree.delete(*self.proc_tree.get_children())
        shown = 0
        for pid, name, command in self.process_rows:
            if not query or query in f"{pid} {name} {command}".lower():
                self.proc_tree.insert("", "end", iid=str(pid), values=(pid, name, command),
                                      tags=("even" if shown % 2 == 0 else "odd",))
                shown += 1
        self.process_count_var.set(f"{shown} von {len(self.process_rows)} · eigener Benutzer")
        pid_item = str(self.current_pid)
        if self.current_pid is not None and self.proc_tree.exists(pid_item):
            self.proc_tree.selection_set(pid_item)
            self.proc_tree.focus(pid_item)
        elif self.current_pid is not None:
            self.current_pid = None
            self.process_info = {}
            self.modules = []
            self.module_error = ""
            self.loaded_at = None
            self.exe_var.set("")
            self.command_var.set("")
            self.proc_label.configure(text="Einen Prozess auswählen")
            self.populate_module_tree()
            self.status_var.set("Kein Prozess ausgewählt · einen Prozess auswählen")

    def on_process_select(self, _event=None):
        selection = self.proc_tree.selection()
        if selection:
            pid = int(selection[0])
            if pid != self.current_pid:
                self.current_pid = pid
                self.refresh_modules()

    def refresh_modules(self):
        self.modules = []
        self.module_error = ""
        self.loaded_at = None
        if self.current_pid is None:
            self.populate_module_tree()
            return
        pid = self.current_pid
        executable = exe_path(pid)
        self.process_info = {"pid": pid, "name": read_comm(pid),
                             "executable": executable, "command_line": read_cmdline(pid)}
        self.proc_label.configure(text=f"{self.process_info['name']}  ·  PID {pid}")
        self.exe_var.set(executable)
        self.command_var.set(self.process_info["command_line"])
        try:
            self.modules = mapped_files(pid, self.only_exec_var.get())
        except PermissionError:
            self.module_error = "Keine Berechtigung zum Lesen der Mappings"
        except (FileNotFoundError, ProcessLookupError):
            self.module_error = "Prozess wurde beendet oder ist nicht mehr verfügbar"
        except OSError as error:
            self.module_error = f"Mappings konnten nicht gelesen werden: {error}"
        else:
            self.loaded_at = datetime.now(timezone.utc).isoformat()
            for module in self.modules:
                module["kind"] = module_kind(module["path"], executable)
        self.populate_module_tree()

    def populate_module_tree(self):
        previous = {module["path"] for module in self.selected_modules()}
        query = self.module_search_var.get().strip().lower()
        self.visible_modules = [module for module in self.modules
                                if (not self.hide_system_var.get() or not is_system_path(module["path"]))
                                and (not query or query in f"{module['kind']} {module['name']} {module['path']}".lower())]
        self.visible_modules.sort(key=self._sort_key, reverse=self.sort_reverse)
        self.module_count_var.set(f"{len(self.visible_modules)} / {len(self.modules)} Dateien")
        self.mod_tree.delete(*self.mod_tree.get_children())
        self.module_items = {}
        restore = []
        for index, module in enumerate(self.visible_modules):
            item = str(index)
            self.module_items[item] = module
            self.mod_tree.insert("", "end", iid=item, tags=("even" if index % 2 == 0 else "odd",), values=(
                module["kind"], module["name"], module["path"],
                self._permissions(module), module["mappings"][0]["start"],
                "Ja" if module["deleted"] else "",
            ))
            if module["path"] in previous:
                restore.append(item)
        if restore:
            self.mod_tree.selection_set(restore)
            self.mod_tree.focus(restore[0])
        self.on_module_select()
        if self.module_error:
            self.status_var.set(f"PID {self.current_pid}: {self.module_error}")
        elif self.current_pid is not None:
            self.status_var.set(f"PID {self.current_pid}: {len(self.visible_modules)} von {len(self.modules)} Dateien angezeigt · Strg+C kopiert Pfade · Doppelklick zeigt Details")

    @staticmethod
    def _permissions(module):
        return ", ".join(dict.fromkeys(mapping["permissions"] for mapping in module["mappings"]))

    def _sort_key(self, module):
        if self.sort_column == "start":
            return int(module["mappings"][0]["start"], 16)
        if self.sort_column == "perms":
            return self._permissions(module)
        return str(module[self.sort_column]).lower()

    def sort_modules(self, column):
        self.sort_reverse = not self.sort_reverse if column == self.sort_column else False
        self.sort_column = column
        for key, title in self.module_headings.items():
            suffix = (" ↓" if self.sort_reverse else " ↑") if key == column else ""
            self.mod_tree.heading(key, text=title + suffix)
        self.populate_module_tree()

    def selected_modules(self):
        selected = set(self.mod_tree.selection())
        return [self.module_items[item] for item in self.mod_tree.get_children()
                if item in selected and item in self.module_items]

    def selected_module_path(self):
        modules = self.selected_modules()
        return modules[0]["path"] if modules else None

    def on_module_select(self, _event=None):
        modules = self.selected_modules()
        module = modules[0] if modules else None
        self.file_name_var.set(module["name"] if module else "")
        self.path_text.configure(state="normal")
        self.path_text.delete("1.0", "end")
        if module:
            self.path_text.insert("1.0", module["path"])
        self.path_text.configure(state="disabled")
        if module:
            suffix = " · Datei wurde gelöscht" if module["deleted"] else ""
            self.selection_var.set(f"{len(modules)} ausgewählt · {module['kind']} · {len(module['mappings'])} Mappings · {self._permissions(module)}{suffix}")
        else:
            self.selection_var.set("Datei auswählen, um alle Details zu sehen")

    def select_all_modules(self, _event=None):
        self.mod_tree.selection_set(self.mod_tree.get_children())
        return "break"

    def copy_paths_shortcut(self, _event=None):
        self.copy_selected_path()
        return "break"

    def on_module_double_click(self, event):
        if self.mod_tree.identify_region(event.x, event.y) in ("cell", "tree"):
            self.show_file_details()

    def show_module_menu(self, event):
        item = self.mod_tree.identify_row(event.y)
        if not item:
            return
        if item not in self.mod_tree.selection():
            self.mod_tree.selection_set(item)
        self.mod_tree.focus(item)
        self.on_module_select()
        try:
            self.module_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.module_menu.grab_release()

    def _copy_text(self, text, description):
        if not text:
            self.status_var.set("Keine Daten zum Kopieren vorhanden")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set(f"{description} in die Zwischenablage kopiert")

    def copy_selected_path(self):
        modules = self.selected_modules()
        self._copy_text("\n".join(module["path"] for module in modules), f"{len(modules)} Pfad(e)")

    def copy_selected_name(self):
        modules = self.selected_modules()
        self._copy_text("\n".join(module["name"] for module in modules), f"{len(modules)} Dateiname(n)")

    def copy_all_paths(self):
        self._copy_text("\n".join(module["path"] for module in self.visible_modules),
                        f"{len(self.visible_modules)} angezeigte Pfad(e)")

    def copy_executable(self):
        self._copy_text(self.exe_var.get(), "Programmpfad")

    def copy_command(self):
        self._copy_text(self.command_var.get(), "Befehlszeile")

    def json_payload(self, modules, scope):
        return {
            "schema_version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "snapshot_at": self.loaded_at,
            "process": dict(self.process_info),
            "scope": scope,
            "filters": {"executable_only": self.only_exec_var.get(),
                        "hide_system": self.hide_system_var.get(),
                        "search": self.module_search_var.get().strip()},
            "module_count": len(modules),
            "modules": modules,
        }

    def copy_selected_json(self):
        modules = self.selected_modules()
        if not modules:
            self.status_var.set("Bitte zuerst eine oder mehrere Dateien auswählen")
            return
        self._copy_text(json.dumps(self.json_payload(modules, "selected"), ensure_ascii=False, indent=2),
                        f"{len(modules)} Datei(en) als JSON")

    def export_json(self, selected_only=False):
        if self.current_pid is None:
            self.status_var.set("Bitte zuerst einen Prozess auswählen")
            return
        if self.module_error:
            messagebox.showwarning("Export nicht verfügbar", self.module_error, parent=self)
            return
        modules = self.selected_modules() if selected_only else list(self.visible_modules)
        if selected_only and not modules:
            self.status_var.set("Bitte zuerst eine oder mehrere Dateien auswählen")
            return
        filename = filedialog.asksaveasfilename(
            parent=self, title="Module als JSON exportieren", defaultextension=".json",
            initialfile=f"process-{self.current_pid}-modules{'-selection' if selected_only else ''}.json",
            filetypes=[("JSON-Dateien", "*.json"), ("Alle Dateien", "*")],
        )
        if not filename:
            return
        payload = self.json_payload(modules, "selected" if selected_only else "visible")
        try:
            Path(filename).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError as error:
            messagebox.showerror("Export fehlgeschlagen", str(error), parent=self)
            return
        self.status_var.set(f"{len(modules)} Datei(en) als JSON exportiert: {filename}")

    def show_file_details(self):
        modules = self.selected_modules()
        if not modules:
            self.status_var.set("Bitte zuerst eine Datei auswählen")
            return
        module = modules[0]
        window = tk.Toplevel(self)
        window.title(f"Dateidetails · {module['name']}")
        window.geometry("880x530")
        window.minsize(580, 350)
        window.transient(self)
        frame = ttk.Frame(window, padding=12, style="Card.TFrame")
        frame.pack(fill="both", expand=True)
        text = tk.Text(frame, wrap="char", padx=12, pady=12, font=("DejaVu Sans Mono", 10),
                       background="#f8fafd", foreground="#20324a", relief="flat", borderwidth=0,
                       selectbackground="#dbeafe", selectforeground="#163d75")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(fill="both", expand=True)
        lines = [f"Dateiname: {module['name']}", f"Pfad: {module['path']}",
                 f"Typ: {module['kind']}", f"Gelöscht: {'Ja' if module['deleted'] else 'Nein'}",
                 f"PID: {self.current_pid}", "", "Speicherbereiche:"]
        for mapping in module["mappings"]:
            lines.append(f"{mapping['start']} – {mapping['end']}  {mapping['permissions']}  Offset {mapping['offset']}  Gerät {mapping['device']}  Inode {mapping['inode']}")
        text.insert("1.0", "\n".join(lines))
        text.configure(state="disabled")
        buttons = ttk.Frame(window, padding=(12, 0, 12, 12))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Name kopieren", command=lambda: self._copy_text(module["name"], "Dateiname")).pack(side="left")
        ttk.Button(buttons, text="Pfad kopieren", command=lambda: self._copy_text(module["path"], "Pfad")).pack(side="left", padx=6)
        ttk.Button(buttons, text="Schließen", command=window.destroy).pack(side="right")
        window.bind("<Escape>", lambda _event: window.destroy())

    def open_selected_folder(self):
        path = self.selected_module_path()
        if not path:
            self.status_var.set("Bitte zuerst eine Datei auswählen")
            return
        folder = str(Path(path).parent)
        if not Path(folder).is_dir():
            messagebox.showwarning("Ordner nicht verfügbar", f"Der Ordner ist lokal nicht erreichbar:\n{folder}", parent=self)
            return
        try:
            subprocess.Popen(["xdg-open", folder])
        except OSError as error:
            messagebox.showerror("Ordner konnte nicht geöffnet werden", str(error), parent=self)


if __name__ == "__main__":
    app = ProcModuleViewer()
    app.mainloop()
