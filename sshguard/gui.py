from __future__ import annotations

import csv
import json
import queue
import threading
import tkinter as tk
import psutil
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .quarantine import (
    expired_items,
    pending_notifications,
    permanently_delete,
    quarantine_file,
    quarantined_items,
    restore_file,
)
from .scanner import assess_file, iter_files
from .system_monitor import connection_records, process_records


PRIVACY_SCORE = 100


class SecurityApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SSH Guard - Local Security Monitor")
        self.geometry("1100x700")
        self.minsize(850, 520)
        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._rows: list[tuple[str, int, str, str, str]] = []
        self._table_refresh_pending = False
        self.files_var = tk.StringVar(value="0")
        self.risk_var = tk.StringVar(value="0")
        self.high_var = tk.StringVar(value="0")
        self._configure_styles()
        self._build_ui()
        self.after(500, self._show_quarantine_notifications)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#edf5f8")
        style.configure("App.TFrame", background="#edf5f8")
        style.configure("Header.TFrame", background="#dcecf2")
        style.configure("Title.TLabel", background="#dcecf2", foreground="#16324f", font=("Segoe UI", 24, "bold"))
        style.configure("Subtitle.TLabel", background="#dcecf2", foreground="#526b7a", font=("Segoe UI", 10))
        style.configure("TLabel", background="#edf5f8", foreground="#243b53", font=("Segoe UI", 10))
        style.configure("Card.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("CardTitle.TLabel", background="#ffffff", foreground="#6b7c8c", font=("Segoe UI", 9, "bold"))
        style.configure("Metric.TLabel", background="#ffffff", foreground="#16324f", font=("Segoe UI", 18, "bold"))
        style.configure("Status.TLabel", background="#edf5f8", foreground="#18794e", font=("Segoe UI", 10, "bold"))
        style.configure("TLabelframe", background="#edf5f8", foreground="#243b53", bordercolor="#c5d5dc")
        style.configure("TLabelframe.Label", background="#edf5f8", foreground="#256b8b", font=("Segoe UI", 10, "bold"))
        style.configure("TNotebook", background="#edf5f8", borderwidth=0)
        style.configure("TNotebook.Tab", background="#dcecf2", foreground="#526b7a", padding=(18, 9), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#3b82c4")], foreground=[("selected", "#ffffff")])
        style.configure("TButton", background="#ffffff", foreground="#24445c", padding=(14, 8), borderwidth=1, font=("Segoe UI", 10, "bold"))
        style.map("TButton", background=[("active", "#dcecf2"), ("disabled", "#e4ecef")])
        style.configure("Accent.TButton", background="#3b82c4", foreground="#ffffff", padding=(16, 9))
        style.map("Accent.TButton", background=[("active", "#256b8b")])
        style.configure("TEntry", fieldbackground="#ffffff", foreground="#243b53", insertcolor="#16324f", padding=8)
        style.configure("TCombobox", fieldbackground="#ffffff", foreground="#243b53", padding=6)
        style.configure("TRadiobutton", background="#edf5f8", foreground="#243b53", padding=(4, 5))
        style.map("TRadiobutton", background=[("active", "#dcecf2")], foreground=[("active", "#16324f")])
        style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff", foreground="#243b53", rowheight=32, font=("Segoe UI", 10), borderwidth=0)
        style.configure("Treeview.Heading", background="#dcecf2", foreground="#256b8b", font=("Segoe UI", 10, "bold"), padding=8)
        style.map("Treeview", background=[("selected", "#8fc6e8")], foreground=[("selected", "#16324f")])
        self.configure(background="#edf5f8")

    def _build_ui(self) -> None:
        header = ttk.Frame(self, padding=(28, 20), style="Header.TFrame")
        header.pack(fill="x")
        header_actions = ttk.Frame(header, style="Header.TFrame")
        header_actions.pack(side="right")
        ttk.Button(header_actions, text="●  Live activity", command=self._open_activity, style="Accent.TButton").pack(
            padx=(8, 0)
        )
        ttk.Label(header, text="SSH Guard", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Local-only security scanning. Review findings before moving anything to quarantine.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(3, 0))

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        dashboard_page = ttk.Frame(self.tabs, padding=16)
        scan_page = ttk.Frame(self.tabs, padding=4)
        live_page = ttk.Frame(self.tabs, padding=16)
        quarantine_page = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(dashboard_page, text="Dashboard")
        self.tabs.add(scan_page, text="Scan files")
        self.tabs.add(live_page, text="Live activity")
        self.tabs.add(quarantine_page, text="Quarantine")
        self._build_dashboard_page(dashboard_page)
        self._build_live_page(live_page)
        self._build_quarantine_page(quarantine_page)

        controls = ttk.LabelFrame(scan_page, text=" 1  Choose a scan scope ", padding=18)
        controls.pack(fill="x", padx=18, pady=(12, 12))
        self.scan_type = tk.StringVar(value="quick")
        self.scan_scope_widgets: list[ttk.Widget] = []
        self.scan_scope_widgets.append(ttk.Radiobutton(
            controls, text="Quick scan (Downloads, Desktop)", variable=self.scan_type, value="quick"
        ))
        self.scan_scope_widgets[-1].grid(row=0, column=0, sticky="w", padx=(0, 18))
        self.scan_scope_widgets.append(ttk.Radiobutton(
            controls, text="Full scan (choose folder)", variable=self.scan_type, value="full"
        ))
        self.scan_scope_widgets[-1].grid(row=0, column=1, sticky="w", padx=(0, 18))
        self.scan_scope_widgets.append(ttk.Radiobutton(
            controls, text="Custom folder", variable=self.scan_type, value="custom"
        ))
        self.scan_scope_widgets[-1].grid(row=0, column=2, sticky="w")
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(controls, textvariable=self.path_var, width=70)
        self.path_entry.grid(
            row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0)
        )
        self.browse_button = ttk.Button(controls, text="Browse", command=self._browse)
        self.browse_button.grid(row=1, column=2, padx=(8, 0), pady=(10, 0))
        self.start_button = ttk.Button(controls, text="Start scan", command=self._start_scan, style="Accent.TButton")
        self.start_button.grid(row=1, column=3, padx=(18, 0), pady=(10, 0))
        self.stop_button = ttk.Button(controls, text="Stop", command=self._stop_scan, state="disabled")
        self.stop_button.grid(row=1, column=4, padx=(8, 0), pady=(10, 0))
        controls.columnconfigure(1, weight=1)

        overview = ttk.Frame(scan_page, padding=(18, 0, 18, 12), style="App.TFrame")
        overview.pack(fill="x")
        cards = ttk.Frame(overview, style="App.TFrame")
        cards.pack(fill="x")
        self._add_card(cards, "PRIVACY", "100 / 100", "Local-only • no upload", "#16803c")
        self._add_card(cards, "FILES SCANNED", self.files_var, "Files checked", "#102a43")
        self._add_card(cards, "RISK FILES", self.risk_var, "Needs review", "#b54708")
        self._add_card(cards, "HIGH RISK", self.high_var, "Urgent attention", "#b42318")
        progress = ttk.LabelFrame(overview, text=" Scan progress ", padding=10)
        progress.pack(fill="x", pady=(14, 0))
        self.progress = ttk.Progressbar(progress, mode="determinate")
        self.progress.pack(fill="x")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(progress, textvariable=self.status_var, style="Status.TLabel").pack(anchor="w", pady=(5, 0))
        self.current_var = tk.StringVar(value="Current file: —")
        ttk.Label(progress, textvariable=self.current_var).pack(anchor="w", pady=(3, 0))

        results = ttk.LabelFrame(scan_page, text=" 2  Review scan results ", padding=14)
        results.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        toolbar = ttk.Frame(results)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Label(toolbar, text="Filter findings:").pack(side="left")
        self.filter_var = tk.StringVar(value="All files")
        filter_box = ttk.Combobox(
            toolbar,
            textvariable=self.filter_var,
            values=("All files", "Risk files", "High risk", "Medium / low risk", "Unreadable"),
            state="readonly",
            width=20,
        )
        filter_box.pack(side="left", padx=(6, 12))
        filter_box.bind("<<ComboboxSelected>>", lambda _event: self._refresh_table())
        self.quarantine_button = ttk.Button(
            toolbar, text="Quarantine selected", command=self._quarantine_selected, style="Accent.TButton"
        )
        self.quarantine_button.pack(side="left", padx=(12, 0))
        ttk.Button(toolbar, text="Export report", command=self._export_report).pack(side="left", padx=(12, 0))
        ttk.Label(
            toolbar,
            text="Quarantine keeps files for 15 days; deletion always requires confirmation.",
        ).pack(side="left", padx=(12, 0))
        columns = ("severity", "score", "file", "detected")
        self.table = ttk.Treeview(results, columns=columns, show="headings")
        for column, title, width in (
            ("severity", "Severity", 100),
            ("score", "Score", 70),
            ("file", "File path", 350),
            ("detected", "What was detected", 500),
        ):
            self.table.heading(column, text=title)
            self.table.column(column, width=width, anchor="w")
        scrollbar = ttk.Scrollbar(results, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.tag_configure("high", foreground="#b42318")
        self.table.tag_configure("medium", foreground="#b54708")
        self.table.tag_configure("clean", foreground="#16803c")
        self.table.tag_configure("unreadable", foreground="#667085")
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.after(100, self._drain_events)

    def _build_dashboard_page(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Security dashboard", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(
            parent,
            text="Choose what you want to inspect. SSH Guard observes this computer only.",
            style="Status.TLabel",
        ).pack(anchor="w", pady=(4, 18))
        cards = ttk.Frame(parent, style="App.TFrame")
        cards.pack(fill="x")
        self._add_card(cards, "PRIVACY", "100 / 100", "Local-only • no upload", "#16803c")
        self._add_card(cards, "FILES SCANNED", self.files_var, "Latest scan", "#102a43")
        self._add_card(cards, "RISK FILES", self.risk_var, "Needs review", "#b54708")
        self._add_card(cards, "HIGH RISK", self.high_var, "Urgent attention", "#b42318")
        choices = ttk.LabelFrame(parent, text="Open a security view", padding=14)
        choices.pack(fill="x", pady=(22, 0))
        ttk.Button(choices, text="Scan files", command=lambda: self.tabs.select(1)).pack(
            side="left", padx=(0, 10)
        )
        ttk.Button(choices, text="Live processes, RAM & ports", command=self._open_activity).pack(
            side="left", padx=10
        )
        ttk.Button(choices, text="Quarantined files", command=lambda: self.tabs.select(3)).pack(
            side="left", padx=10
        )

    def _build_live_page(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Live activity", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(
            parent,
            text="Processes are sorted by memory use. The detailed view refreshes every two seconds.",
        ).pack(anchor="w", pady=(4, 18))
        ttk.Button(parent, text="Open live activity monitor", command=self._open_activity).pack(anchor="w")

    def _build_quarantine_page(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Quarantine", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(
            parent,
            text="Files moved here are retained for 15 days. Select a file to restore it.",
        ).pack(anchor="w", pady=(4, 12))
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Button(toolbar, text="Refresh", command=self._refresh_quarantine).pack(side="left")
        ttk.Button(toolbar, text="Restore selected", command=self._restore_selected).pack(side="left", padx=8)
        columns = ("name", "original", "quarantined", "expires")
        self.quarantine_table = ttk.Treeview(parent, columns=columns, show="headings")
        for column, heading, width in (
            ("name", "File", 230),
            ("original", "Original location", 380),
            ("quarantined", "Quarantined", 180),
            ("expires", "Expires", 180),
        ):
            self.quarantine_table.heading(column, text=heading)
            self.quarantine_table.column(column, width=width, anchor="w")
        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.quarantine_table.yview)
        self.quarantine_table.configure(yscrollcommand=scroll.set)
        self.quarantine_table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._refresh_quarantine()

    def _refresh_quarantine(self) -> None:
        if not hasattr(self, "quarantine_table"):
            return
        for item in self.quarantine_table.get_children():
            self.quarantine_table.delete(item)
        for record in quarantined_items():
            self.quarantine_table.insert(
                "",
                "end",
                iid=record["id"],
                values=(
                    Path(record["quarantine_path"]).name,
                    record["original_path"],
                    record["quarantined_at"][:10],
                    record["delete_after"][:10],
                ),
            )

    def _restore_selected(self) -> None:
        selected = self.quarantine_table.selection()
        if not selected:
            messagebox.showinfo("Select a file", "Select a quarantined file first.")
            return
        records = {record["id"]: record for record in quarantined_items()}
        restored = 0
        errors: list[str] = []
        for item_id in selected:
            try:
                restore_file(records[item_id])
                restored += 1
            except (OSError, KeyError) as exc:
                errors.append(str(exc))
        self._refresh_quarantine()
        if errors:
            messagebox.showwarning("Restore incomplete", "\n".join(errors[:5]))
        elif restored:
            messagebox.showinfo("Restored", f"{restored} file(s) restored to their original locations.")

    def _open_activity(self) -> None:
        if getattr(self, "_activity_window", None) is not None and self._activity_window.winfo_exists():
            self._activity_window.lift()
            return
        window = tk.Toplevel(self)
        self._activity_window = window
        window.title("SSH Guard - Live System Activity")
        window.geometry("1100x650")
        window.minsize(800, 450)
        window.configure(background="#f5f7fa")
        window.protocol("WM_DELETE_WINDOW", window.destroy)

        header = ttk.Frame(window, padding=(18, 14), style="Header.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Live system activity", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Local observation only. No remote ports are probed and no connections are changed.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(3, 0))

        toolbar = ttk.Frame(window, padding=12, style="App.TFrame")
        toolbar.pack(fill="x")
        activity_status = tk.StringVar(value="Refreshing every 2 seconds")
        ttk.Label(toolbar, textvariable=activity_status, style="Status.TLabel").pack(side="left")
        ttk.Button(toolbar, text="Refresh now", command=lambda: refresh()).pack(side="right")

        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        connections_tab = ttk.Frame(notebook, padding=8)
        processes_tab = ttk.Frame(notebook, padding=8)
        notebook.add(connections_tab, text="Connections & ports")
        notebook.add(processes_tab, text="Running processes")

        connection_table = self._activity_table(
            connections_tab,
            ("status", "local", "remote", "pid", "process", "alert"),
            ("Status", "Local endpoint", "Remote endpoint", "PID", "Process", "Alert"),
            (100, 160, 160, 70, 220, 260),
        )
        process_table = self._activity_table(
            processes_tab,
            ("pid", "name", "parent", "cpu", "memory", "executable", "command"),
            ("PID", "Process", "Parent PID", "CPU %", "RAM MB", "Executable", "Command line"),
            (70, 160, 90, 80, 90, 300, 350),
        )

        def refresh() -> None:
            if not window.winfo_exists():
                return
            try:
                connections = connection_records()
                processes = process_records()
                self._replace_activity_rows(
                    connection_table,
                    [
                        (
                            item.status,
                            item.local,
                            item.remote,
                            item.pid or "—",
                            item.process,
                            "Listening / review" if item.status == "LISTEN" else (
                                "Review process" if item.suspicious else "Observed"
                            ),
                        )
                        for item in connections
                    ],
                    "alert" if any(item.suspicious for item in connections) else "ok",
                )
                self._replace_activity_rows(
                    process_table,
                    [
                        (
                            item.pid,
                            item.name,
                            item.parent_pid or "—",
                            f"{item.cpu_percent:.1f}",
                            f"{item.memory_mb:.1f}",
                            item.executable,
                            item.command_line or "—",
                        )
                        for item in processes
                    ],
                    "ok",
                )
                activity_status.set(
                    f"Updated: {len(connections)} connections/ports • {len(processes)} processes"
                )
            except (OSError, psutil.Error) as exc:
                activity_status.set(f"Some system data is unavailable: {exc}")
            window.after(2000, refresh)

        refresh()

    @staticmethod
    def _activity_table(parent, columns, headings, widths):
        table = ttk.Treeview(parent, columns=columns, show="headings")
        for column, heading, width in zip(columns, headings, widths):
            table.heading(column, text=heading)
            table.column(column, width=width, anchor="w")
        table.tag_configure("alert", foreground="#b42318")
        table.tag_configure("ok", foreground="#243b53")
        scroll = ttk.Scrollbar(parent, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scroll.set)
        table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return table

    @staticmethod
    def _replace_activity_rows(table, rows, tag):
        for item in table.get_children():
            table.delete(item)
        for row in rows:
            table.insert("", "end", values=row, tags=(tag,))

    def _add_card(self, parent: ttk.Frame, title: str, value: str | tk.StringVar, subtitle: str, color: str) -> None:
        card = ttk.Frame(parent, padding=(14, 10), style="Card.TFrame")
        card.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
        if isinstance(value, tk.StringVar):
            ttk.Label(card, textvariable=value, style="Metric.TLabel", foreground=color).pack(anchor="w", pady=(2, 0))
        else:
            ttk.Label(card, text=value, style="Metric.TLabel", foreground=color).pack(anchor="w", pady=(2, 0))
        ttk.Label(card, text=subtitle, style="CardTitle.TLabel").pack(anchor="w")

    def _browse(self) -> None:
        selected = filedialog.askdirectory(title="Choose a folder to scan")
        if selected:
            self.path_var.set(selected)
            self.scan_type.set("custom")

    def _resolve_path(self) -> Path | None:
        home = Path.home()
        if self.scan_type.get() == "quick":
            paths = [home / "Downloads", home / "Desktop"]
            existing = [path for path in paths if path.is_dir()]
            if not existing:
                messagebox.showwarning("No folders found", "Downloads and Desktop were not found.")
                return None
            return existing[0]
        if self.scan_type.get() == "full":
            return Path(self.path_var.get()) if self.path_var.get() else Path.home()
        return Path(self.path_var.get()) if self.path_var.get() else None

    def _start_scan(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        root = self._resolve_path()
        if root is None or not root.is_dir():
            messagebox.showerror("Choose a folder", "Select an existing folder before starting.")
            return
        for item in self.table.get_children():
            self.table.delete(item)
        self._rows.clear()
        self._update_summary()
        self.progress.configure(value=0, mode="indeterminate")
        self.progress.start(12)
        self._stop_event.clear()
        self._set_scan_controls(False)
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_var.set(f"Preparing scan: {root}")
        self.current_var.set("Current file: discovering files…")
        self._worker = threading.Thread(target=self._scan_worker, args=(root,), daemon=True)
        self._worker.start()

    def _stop_scan(self) -> None:
        if self._worker and self._worker.is_alive():
            self._stop_event.set()
            self.status_var.set("Stopping safely…")
            self.stop_button.configure(state="disabled")

    def _set_scan_controls(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for widget in self.scan_scope_widgets:
            widget.configure(state=state)
        self.path_entry.configure(state=state)
        self.browse_button.configure(state=state)

    def _scan_worker(self, root: Path) -> None:
        scanned = 0
        try:
            for index, path in enumerate(iter_files(root), start=1):
                if self._stop_event.is_set():
                    self._events.put(("stopped", scanned))
                    return
                self._events.put(("current", str(path)))
                result = assess_file(path, compute_hash=False)
                detected = "; ".join(item.reason for item in result.findings) or "No indicators detected"
                tag = {
                    "HIGH": "high",
                    "MEDIUM": "medium",
                    "LOW": "medium",
                    "CLEAN": "clean",
                    "UNREADABLE": "unreadable",
                }.get(result.severity, "unreadable")
                self._events.put(("row", (result.severity, result.score, str(result.path), detected, tag)))
                scanned = index
                self._events.put(("progress", scanned))
            self._events.put(("done", scanned))
        except Exception as exc:
            self._events.put(("error", str(exc)))

    def _drain_events(self) -> None:
        processed = 0
        try:
            while processed < 200:
                event, payload = self._events.get_nowait()
                processed += 1
                if event == "row":
                    self._rows.append(payload)
                    self._update_summary()
                    self._schedule_table_refresh()
                elif event == "current":
                    self.current_var.set(f"Current file: {payload}")
                elif event == "progress":
                    self.status_var.set(f"Scanning {payload:,} files discovered")
                elif event == "done":
                    self.progress.stop()
                    self.progress.configure(mode="determinate", maximum=max(1, int(payload)), value=payload)
                    self.start_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
                    self._set_scan_controls(True)
                    self.current_var.set("Current file: —")
                    self.status_var.set(f"Complete: {payload:,} files checked")
                elif event == "stopped":
                    self.progress.stop()
                    self.progress.configure(mode="determinate", maximum=max(1, int(payload)), value=payload)
                    self.start_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
                    self._set_scan_controls(True)
                    self.current_var.set("Current file: —")
                    self.status_var.set(f"Stopped safely after {payload:,} files")
                elif event == "error":
                    self.progress.stop()
                    self.start_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
                    self._set_scan_controls(True)
                    self.current_var.set("Current file: —")
                    self.status_var.set("Scan failed")
                    messagebox.showerror("Scan failed", str(payload))
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _schedule_table_refresh(self) -> None:
        if self._table_refresh_pending:
            return
        self._table_refresh_pending = True
        self.after(250, self._refresh_table_batch)

    def _refresh_table_batch(self) -> None:
        self._table_refresh_pending = False
        self._refresh_table()

    def _update_summary(self) -> None:
        self.files_var.set(f"{len(self._rows):,}")
        risk = sum(row[0] not in {"CLEAN", "UNREADABLE"} for row in self._rows)
        high = sum(row[0] == "HIGH" for row in self._rows)
        self.risk_var.set(f"{risk:,}")
        self.high_var.set(f"{high:,}")

    def _refresh_table(self) -> None:
        selected_paths = {
            self.table.item(item, "values")[2] for item in self.table.selection()
        }
        for item in self.table.get_children():
            self.table.delete(item)
        selected_items = []
        choice = self.filter_var.get()
        for row in self._rows:
            severity, score, path, detected, tag = row
            is_risk = severity not in {"CLEAN", "UNREADABLE"}
            if choice == "Risk files" and not is_risk:
                continue
            if choice == "High risk" and severity != "HIGH":
                continue
            if choice == "Medium / low risk" and severity not in {"MEDIUM", "LOW"}:
                continue
            if choice == "Unreadable" and severity != "UNREADABLE":
                continue
            item = self.table.insert("", "end", values=(severity, score, path, detected), tags=(tag,))
            if path in selected_paths:
                selected_items.append(item)
        for item in selected_items:
            self.table.selection_add(item)

    def _quarantine_selected(self) -> None:
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo("Select files", "Select one or more files in the results table first.")
            return
        paths = [Path(self.table.item(item, "values")[2]) for item in selected]
        if not messagebox.askyesno(
            "Move files to quarantine?",
            f"Move {len(paths)} selected file(s) to the SSH Guard quarantine folder?\n\n"
            "Files are not deleted. They are retained for 15 days.",
        ):
            return
        moved = 0
        errors: list[str] = []
        for path in paths:
            try:
                quarantine_file(path)
                moved += 1
                self._rows = [row for row in self._rows if row[2] != str(path)]
            except (OSError, ValueError) as exc:
                errors.append(f"{path}: {exc}")
        self._refresh_table()
        if errors:
            messagebox.showwarning("Some files were not moved", "\n".join(errors[:5]))
        elif moved:
            messagebox.showinfo("Quarantined", f"{moved} file(s) moved to the local quarantine folder.")

    def _export_report(self) -> None:
        if not self._rows:
            messagebox.showinfo("Nothing to export", "Run a scan before exporting a report.")
            return
        destination = filedialog.asksaveasfilename(
            title="Export SSH Guard report",
            defaultextension=".json",
            filetypes=(("JSON report", "*.json"), ("CSV report", "*.csv")),
        )
        if not destination:
            return
        records = [
            {"severity": row[0], "score": row[1], "path": row[2], "detected": row[3]}
            for row in self._rows
        ]
        try:
            if destination.lower().endswith(".csv"):
                with open(destination, "w", newline="", encoding="utf-8") as stream:
                    writer = csv.DictWriter(stream, fieldnames=records[0].keys())
                    writer.writeheader()
                    writer.writerows(records)
            else:
                with open(destination, "w", encoding="utf-8") as stream:
                    json.dump(records, stream, indent=2)
            messagebox.showinfo("Report exported", f"Saved {len(records):,} records to:\n{destination}")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def _show_quarantine_notifications(self) -> None:
        notices = pending_notifications()
        expired = expired_items()
        if notices:
            messagebox.showwarning(
                "Quarantine expiry reminder",
                f"{len(notices)} quarantined file(s) will expire in 7 days. "
                "Review them before permanent deletion.",
            )
        if expired and messagebox.askyesno(
            "Quarantine files expired",
            f"{len(expired)} quarantined file(s) are older than 15 days. "
            "Permanently delete them now?",
        ):
            for record in expired:
                permanently_delete(record)


def main() -> None:
    SecurityApp().mainloop()
