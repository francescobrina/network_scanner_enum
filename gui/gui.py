"""Responsive, opt-in AI-assisted, dark-themed desktop UI."""
from __future__ import annotations
import json
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

from ai_assistant import chat_endpoint, explain_scan
from scanners.diagnostics import FAST_PORTS, STANDARD_PORTS, scan_ports


class QueueOutput:
    """Keep legacy code from modifying Tk on a worker thread."""
    def __init__(self, messages):
        self.messages = messages

    def insert(self, _index, value):
        self.messages.put(("text", str(value)))


class NetworkScannerGUI:
    MODES = ("Fast Scan", "Standard Ports", "OS Detection", "SMB Enumeration", "FTP Enumeration")
    BG, PANEL, SIDEBAR = "#0B1120", "#151F32", "#101A2B"
    TEXT, MUTED, ACCENT = "#E7EDF9", "#9BAAC4", "#31B4E9"
    GREEN, AMBER, RED = "#4ADEA2", "#F6C56D", "#FB8091"

    def __init__(self, master):
        self.master = master
        master.title("Network Scanner Enumerator  |  0.3.0")
        master.geometry("1110x755")
        master.minsize(850, 615)
        master.configure(bg=self.BG)
        self.events = queue.Queue()
        self.stop = threading.Event()
        self.running = False
        self.ai_running = False
        self.report = None
        self._style()
        self._layout()
        master.after(80, self._poll)

    def _style(self):
        s = ttk.Style(self.master)
        if "clam" in s.theme_names():
            s.theme_use("clam")
        s.configure(".", background=self.BG, foreground=self.TEXT,
                    fieldbackground=self.PANEL, font=("Segoe UI", 10))
        s.configure("Main.TFrame", background=self.BG)
        s.configure("Side.TFrame", background=self.SIDEBAR)
        s.configure("Card.TFrame", background=self.PANEL)
        s.configure("Side.TLabel", background=self.SIDEBAR, foreground=self.MUTED)
        s.configure("Heading.TLabel", background=self.BG, foreground=self.TEXT,
                    font=("Segoe UI", 21, "bold"))
        s.configure("Sub.TLabel", background=self.BG, foreground=self.MUTED)
        s.configure("CardTitle.TLabel", background=self.PANEL, foreground=self.TEXT,
                    font=("Segoe UI", 11, "bold"))
        s.configure("CardValue.TLabel", background=self.PANEL, foreground=self.ACCENT,
                    font=("Segoe UI", 23, "bold"))
        s.configure("CardSmall.TLabel", background=self.PANEL, foreground=self.MUTED)
        s.configure("SideTitle.TLabel", background=self.SIDEBAR, foreground=self.TEXT,
                    font=("Segoe UI", 12, "bold"))
        s.configure("TEntry", fieldbackground=self.PANEL, foreground=self.TEXT,
                    bordercolor="#364560", padding=7)
        s.configure("TCombobox", fieldbackground=self.PANEL, foreground=self.TEXT,
                    background=self.PANEL, arrowcolor=self.TEXT, padding=6)
        s.map("TCombobox", fieldbackground=[("readonly", self.PANEL)],
              foreground=[("readonly", self.TEXT)])
        s.configure("TCheckbutton", background=self.SIDEBAR, foreground=self.TEXT)
        s.map("TCheckbutton", background=[("active", self.SIDEBAR)])
        s.configure("Accent.TButton", padding=9, background=self.ACCENT,
                    foreground=self.BG, font=("Segoe UI", 10, "bold"))
        s.map("Accent.TButton", background=[("active", "#68D3F2"), ("disabled", "#365064")])
        s.configure("TButton", padding=8, background="#25334C", foreground=self.TEXT)
        s.map("TButton", background=[("active", "#354965"), ("disabled", "#192537")])
        s.configure("TProgressbar", background=self.ACCENT, troughcolor=self.SIDEBAR)
        s.configure("Treeview", background=self.PANEL, foreground=self.TEXT,
                    fieldbackground=self.PANEL, rowheight=29,
                    bordercolor=self.PANEL)
        s.configure("Treeview.Heading", background="#223149", foreground=self.TEXT,
                    font=("Segoe UI", 10, "bold"), padding=7)
        s.map("Treeview", background=[("selected", "#245574")],
              foreground=[("selected", "#FFFFFF")])

    def _layout(self):
        self.master.columnconfigure(1, weight=1)
        self.master.rowconfigure(0, weight=1)

        side = ttk.Frame(self.master, style="Side.TFrame", padding=18, width=292)
        side.grid(row=0, column=0, sticky="ns")
        side.grid_propagate(False)
        side.columnconfigure(0, weight=1)
        def heading(text):
            ttk.Label(side, text=text, style="SideTitle.TLabel").pack(anchor="w", pady=(15, 5))
        ttk.Label(side, text="NETWORK TOOLS  /  OSS", style="SideTitle.TLabel").pack(anchor="w", pady=(3, 12))
        heading("Target")
        self.target = ttk.Entry(side)
        self.target.insert(0, "127.0.0.1")
        self.target.pack(fill="x")
        heading("Scan type")
        self.mode = tk.StringVar(value=self.MODES[0])
        ttk.Combobox(side, values=self.MODES, textvariable=self.mode,
                     state="readonly").pack(fill="x")
        self.permission = tk.BooleanVar(value=False)
        tk.Checkbutton(side, text="I have permission to scan this host",
                       variable=self.permission, wraplength=245, justify="left",
                       bg=self.SIDEBAR, fg=self.TEXT, selectcolor=self.PANEL,
                       activebackground=self.SIDEBAR, activeforeground=self.TEXT,
                       highlightthickness=0).pack(anchor="w", pady=(15, 5))
        self.start_button = ttk.Button(side, text="▶  Start diagnostics",
                                       style="Accent.TButton", command=self.start)
        self.start_button.pack(fill="x", pady=(8, 5))
        self.cancel_button = ttk.Button(side, text="Stop scan", command=self.cancel,
                                        state="disabled")
        self.cancel_button.pack(fill="x", pady=5)
        self.export_button = ttk.Button(side, text="Export JSON report",
                                        command=self.export, state="disabled")
        self.export_button.pack(fill="x", pady=5)
        heading("Progress")
        self.progress = ttk.Progressbar(side, maximum=100)
        self.progress.pack(fill="x", pady=6)
        self.status = tk.StringVar(value="Ready for authorized diagnostics")
        ttk.Label(side, textvariable=self.status, style="Side.TLabel",
                  wraplength=245).pack(anchor="w", pady=6)
        ttk.Label(side, text="No account required · Local-first\nMIT open source · IPv4 / IPv6",
                  style="Side.TLabel", justify="left").pack(side="bottom", anchor="w", pady=5)

        body = ttk.Frame(self.master, style="Main.TFrame", padding=20)
        body.grid(row=0, column=1, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(2, weight=3)
        body.rowconfigure(3, weight=2)
        ttk.Label(body, text="Network overview", style="Heading.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(body, text="Read-only diagnostics, structured results and private AI explanations",
                  style="Sub.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 12))

        summary = ttk.Frame(body, style="Main.TFrame")
        summary.grid(row=2, column=0, sticky="nsew")
        summary.columnconfigure((0, 1, 2), weight=1)
        summary.rowconfigure(1, weight=1)
        self.count_labels = {}
        for idx, (key, label) in enumerate((("checked", "PORTS CHECKED"), ("open", "OPEN PORTS"),
                                             ("duration", "SCAN SECONDS"))):
            card = ttk.Frame(summary, style="Card.TFrame", padding=(14, 10))
            card.grid(row=0, column=idx, sticky="ew", padx=(0 if idx == 0 else 7, 0), pady=(0, 12))
            ttk.Label(card, text=label, style="CardSmall.TLabel").pack(anchor="w")
            value = ttk.Label(card, text="—", style="CardValue.TLabel")
            value.pack(anchor="w")
            self.count_labels[key] = value

        table_frame = ttk.Frame(summary, style="Card.TFrame", padding=9)
        table_frame.grid(row=1, column=0, columnspan=3, sticky="nsew")
        ttk.Label(table_frame, text="TCP service inventory", style="CardTitle.TLabel").pack(anchor="w", pady=(2, 8))
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(1, weight=1)
        self.tree = ttk.Treeview(table_frame, columns=("port", "status", "service", "latency"),
                                 show="headings", height=9)
        for key, title, width in (("port", "TCP PORT", 95), ("status", "STATUS", 105),
                                   ("service", "SERVICE", 160), ("latency", "LATENCY (MS)", 115)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, stretch=True)
        self.tree.tag_configure("open", foreground=self.GREEN)
        self.tree.tag_configure("closed", foreground=self.MUTED)
        self.tree.tag_configure("timeout", foreground=self.AMBER)
        self.tree.tag_configure("error", foreground=self.RED)
        self.tree.pack(fill="both", expand=True)

        bottom = ttk.Frame(body, style="Main.TFrame")
        bottom.grid(row=3, column=0, sticky="nsew", pady=(14, 0))
        bottom.columnconfigure(0, weight=1)
        bottom.rowconfigure(1, weight=1)
        ttk.Label(bottom, text="Analysis & activity", style="Sub.TLabel").grid(row=0, column=0, sticky="w")
        notebook = ttk.Notebook(bottom)
        notebook.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        ai_box = ttk.Frame(notebook, style="Card.TFrame", padding=10)
        notebook.add(ai_box, text="AI EXPLANATION")
        log_box = ttk.Frame(notebook, style="Card.TFrame", padding=10)
        notebook.add(log_box, text="SCAN ACTIVITY")
        self.notebook = notebook
        self.log_tab = log_box
        self.activity = ScrolledText(log_box, height=7, bg=self.BG, fg=self.TEXT,
                                     insertbackground=self.TEXT, relief="flat",
                                     wrap="word", font=("Consolas", 10))
        self.activity.pack(fill="both", expand=True)
        ai_box.columnconfigure(1, weight=1)
        ttk.Label(ai_box, text="API URL", style="CardSmall.TLabel").grid(row=0, column=0, sticky="w")
        self.endpoint = ttk.Entry(ai_box)
        self.endpoint.insert(0, "http://127.0.0.1:1234/v1")
        self.endpoint.grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Label(ai_box, text="Model", style="CardSmall.TLabel").grid(row=1, column=0, sticky="w", pady=5)
        self.model = ttk.Entry(ai_box)
        self.model.insert(0, "enter-model-id-from-LM-Studio")
        self.model.grid(row=1, column=1, sticky="ew", padx=8, pady=5)
        self.ai_consent = tk.BooleanVar(value=False)
        consent = tk.Checkbutton(ai_box, text="Send only sanitized port data to the selected endpoint",
                                 variable=self.ai_consent, bg=self.PANEL, fg=self.TEXT,
                                 selectcolor=self.SIDEBAR, activebackground=self.PANEL,
                                 activeforeground=self.TEXT, highlightthickness=0)
        consent.grid(row=2, column=0, columnspan=2, sticky="w")
        self.ai_button = ttk.Button(ai_box, text="Explain scan with AI", command=self.analyze_ai,
                                    state="disabled")
        self.ai_button.grid(row=3, column=0, columnspan=2, sticky="ew", pady=7)
        self.ai_text = ScrolledText(ai_box, height=4, bg=self.BG, fg=self.TEXT,
                                    insertbackground=self.TEXT, relief="flat",
                                    wrap="word", font=("Segoe UI", 10))
        self.ai_text.grid(row=4, column=0, columnspan=2, sticky="nsew")
        ai_box.rowconfigure(4, weight=1)
        self._set_ai("After a scan, connect LM Studio, enter its model ID and opt in. "
                     "AI does not execute scans; results are advisory, not vulnerability findings.")
        self.log = []

    def _set_ai(self, value):
        self.ai_text.configure(state="normal")
        self.ai_text.delete("1.0", "end")
        self.ai_text.insert("end", value)
        self.ai_text.configure(state="disabled")

    def start(self):
        if self.running:
            return
        if not self.target.get().strip():
            messagebox.showerror("Target required", "Enter an IP address or hostname.")
            return
        if not self.permission.get():
            messagebox.showerror("Authorization required", "Confirm scan authorization.")
            return
        self.running = True
        self.stop.clear()
        self.report = None
        self.log.clear()
        self.activity.configure(state="normal")
        self.activity.delete("1.0", "end")
        self.activity.configure(state="disabled")
        if self.mode.get() in ("OS Detection", "SMB Enumeration", "FTP Enumeration"):
            self.notebook.select(self.log_tab)
        self.progress["value"] = 0
        for k in self.count_labels:
            self.count_labels[k].configure(text="—")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status.set("Scanning authorized target…")
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.export_button.configure(state="disabled")
        self.ai_button.configure(state="disabled")
        threading.Thread(target=self._worker, args=(self.target.get().strip(), self.mode.get()),
                         daemon=True).start()

    def _worker(self, target, mode):
        try:
            if mode in ("Fast Scan", "Standard Ports"):
                ports = FAST_PORTS if mode == "Fast Scan" else STANDARD_PORTS
                result = scan_ports(target, ports, authorized=True, cancel_event=self.stop,
                                    progress=lambda count, total: self.events.put(
                                        ("progress", 100 * count / total)))
                self.events.put(("report", result))
            else:
                from scanners.diagnostics import normalize_target, resolve_target
                ip = resolve_target(normalize_target(target))
                output = QueueOutput(self.events)
                if mode == "OS Detection":
                    from scanners.os_scanner import OSDetector
                    OSDetector().detect_os(ip, output)
                elif mode == "SMB Enumeration":
                    from scanners.smb_scanner import SMBEnumerator
                    SMBEnumerator().enum_smb(ip, output)
                elif mode == "FTP Enumeration":
                    from scanners.ftp_scanner import FTPEnumerator
                    FTPEnumerator().enum_ftp(ip, output)
        except Exception as exc:
            self.events.put(("error", str(exc)))
        finally:
            self.events.put(("scan_done", None))

    def _render_report(self, report):
        self.report = report
        self.count_labels["checked"].configure(text=str(len(report.results)))
        self.count_labels["open"].configure(text=str(sum(r.state == "open" for r in report.results)))
        self.count_labels["duration"].configure(text=f"{report.duration_s:.1f}")
        for result in report.results:
            ms = f"{result.latency_ms:.1f}" if result.latency_ms is not None else "—"
            self.tree.insert("", "end",
                             values=(result.port, result.state.upper(), result.service, ms),
                             tags=(result.state,))
        self.export_button.configure(state="normal")
        self.ai_button.configure(state="normal")
        self.status.set("Scan finished" if report.completed else "Partial scan: cancelled")

    def _poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "progress":
                    self.progress["value"] = value
                elif kind == "report":
                    self._render_report(value)
                elif kind == "text":
                    self.log.append(value)
                    self.activity.configure(state="normal")
                    self.activity.insert("end", value)
                    self.activity.see("end")
                    self.activity.configure(state="disabled")
                    self.status.set(value.strip()[:100])
                elif kind == "error":
                    self.status.set("Error: " + value[:100])
                    self.activity.configure(state="normal")
                    self.activity.insert("end", "ERROR: " + value + "\n")
                    self.activity.configure(state="disabled")
                elif kind == "ai_result":
                    self._set_ai(value)
                elif kind == "ai_done":
                    self.ai_running = False
                    self.ai_button.configure(state="normal" if self.report is not None else "disabled")
                elif kind == "scan_done":
                    self.running = False
                    self.start_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
        except queue.Empty:
            pass
        try:
            self.master.after(80, self._poll)
        except tk.TclError:
            pass

    def cancel(self):
        self.stop.set()
        self.cancel_button.configure(state="disabled")
        self.status.set("Cancellation requested; in-flight connections may finish")

    def export(self):
        if self.report is None:
            return
        destination = filedialog.asksaveasfilename(defaultextension=".json",
                                                    filetypes=[("JSON", "*.json")])
        if destination:
            try:
                with open(destination, "w", encoding="utf-8") as f:
                    json.dump(self.report.to_dict(), f, indent=2, ensure_ascii=False)
                self.status.set("Report exported")
            except OSError as exc:
                messagebox.showerror("Export error", str(exc))

    def analyze_ai(self):
        if self.report is None or self.ai_running:
            return
        if not self.ai_consent.get():
            messagebox.showerror("Consent required", "Opt in before sending sanitized scan metadata.")
            return
        endpoint, model = self.endpoint.get().strip(), self.model.get().strip()
        try:
            chat_endpoint(endpoint)
        except ValueError as exc:
            messagebox.showerror("AI endpoint", str(exc))
            return
        if model == "enter-model-id-from-LM-Studio" or not model:
            messagebox.showerror("Model required", "Enter the actual model ID loaded in LM Studio.")
            return
        self.ai_running = True
        self.ai_button.configure(state="disabled")
        self._set_ai("Requesting a defensive explanation from the selected model…")
        threading.Thread(target=self._ai_worker, args=(self.report, endpoint, model),
                         daemon=True).start()

    def _ai_worker(self, report, endpoint, model):
        try:
            value = explain_scan(report, endpoint=endpoint, model=model, consent=True)
            self.events.put(("ai_result", "AI-generated guidance — verify independently:\n\n" + value))
        except Exception as exc:
            self.events.put(("ai_result", "AI request failed: " + str(exc)))
        finally:
            self.events.put(("ai_done", None))


def main():
    root = tk.Tk()
    NetworkScannerGUI(root)
    root.mainloop()
