"""Thread-safe Tkinter interface for authorized network diagnostics."""
import json
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from scanners.diagnostics import FAST_PORTS, STANDARD_PORTS, scan_ports

class QueueOutput:
    """Legacy scanner adapter: relay insert() calls to the main Tk thread."""
    def __init__(self, messages):
        self.messages = messages

    def insert(self, _index, value):
        self.messages.put(("text", str(value)))

class NetworkScannerGUI:
    MODES = ("Fast Scan", "Standard Ports", "OS Detection", "SMB Enumeration", "FTP Enumeration")

    def __init__(self, master):
        self.master = master
        master.title("Network Scanner Enumerator")
        master.geometry("780x620")
        self.messages = queue.Queue()
        self.stop = threading.Event()
        self.running = False
        self.report = None
        frame = ttk.Frame(master, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Target hostname, IP or HTTPS URL").pack(anchor="w")
        self.target = ttk.Entry(frame)
        self.target.insert(0, "127.0.0.1")
        self.target.pack(fill="x", pady=6)
        self.mode = tk.StringVar(value=self.MODES[0])
        ttk.Combobox(frame, values=self.MODES, state="readonly", textvariable=self.mode).pack(fill="x", pady=6)
        self.permission = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="I own this system or have explicit permission to scan it",
                        variable=self.permission).pack(anchor="w", pady=6)
        actions = ttk.Frame(frame)
        actions.pack(fill="x")
        self.start_button = ttk.Button(actions, text="Start", command=self.start)
        self.start_button.pack(side="left")
        self.cancel_button = ttk.Button(actions, text="Cancel", command=self.cancel, state="disabled")
        self.cancel_button.pack(side="left", padx=8)
        self.export_button = ttk.Button(actions, text="Export JSON", command=self.export, state="disabled")
        self.export_button.pack(side="left")
        self.progress = ttk.Progressbar(frame, maximum=100)
        self.progress.pack(fill="x", pady=8)
        self.output = ScrolledText(frame, height=23)
        self.output.pack(fill="both", expand=True)
        master.after(80, self.poll)

    def start(self):
        if self.running:
            return
        target = self.target.get().strip()
        if not target:
            messagebox.showerror("Target required", "Enter a hostname or IP.")
            return
        if not self.permission.get():
            messagebox.showerror("Permission required", "Confirm scan authorization.")
            return
        self.stop.clear()
        self.running = True
        self.report = None
        self.progress["value"] = 0
        self.output.delete("1.0", "end")
        self.export_button.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        threading.Thread(target=self.worker, args=(target, self.mode.get()), daemon=True).start()

    def worker(self, target, mode):
        try:
            if mode in ("Fast Scan", "Standard Ports"):
                ports = FAST_PORTS if mode == "Fast Scan" else STANDARD_PORTS
                report = scan_ports(target, ports, authorized=True, cancel_event=self.stop,
                                    progress=lambda done, total: self.messages.put(("progress", 100 * done / total)))
                self.messages.put(("report", report))
                for result in report.results:
                    self.messages.put(("text", f"{result.port}/tcp {result.state}: {result.service}\n"))
                    if result.tls is not None:
                        self.messages.put(("text", json.dumps(result.tls, ensure_ascii=False) + "\n"))
            else:
                from scanners.diagnostics import normalize_target, resolve_target
                ip = resolve_target(normalize_target(target))
                output = QueueOutput(self.messages)
                if mode == "OS Detection":
                    from scanners.os_scanner import OSDetector
                    OSDetector().detect_os(ip, output)
                elif mode == "SMB Enumeration":
                    from scanners.smb_scanner import SMBEnumerator
                    SMBEnumerator().enum_smb(ip, output)
                elif mode == "FTP Enumeration":
                    from scanners.ftp_scanner import FTPEnumerator
                    FTPEnumerator().enum_ftp(ip, output)
        except Exception as error:
            self.messages.put(("text", f"Error: {error}\n"))
        finally:
            self.messages.put(("done", None))

    def poll(self):
        try:
            while True:
                kind, value = self.messages.get_nowait()
                if kind == "text":
                    self.output.insert("end", value)
                    self.output.see("end")
                elif kind == "progress":
                    self.progress["value"] = value
                elif kind == "report":
                    self.report = value
                    self.export_button.configure(state="normal")
                elif kind == "done":
                    self.running = False
                    self.start_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
        except queue.Empty:
            pass
        self.master.after(80, self.poll)

    def cancel(self):
        self.stop.set()
        self.cancel_button.configure(state="disabled")
        self.messages.put(("text", "Cancellation requested; in-flight connections may finish.\n"))

    def export(self):
        if self.report is None:
            return
        destination = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if destination:
            try:
                with open(destination, "w", encoding="utf-8") as handle:
                    json.dump(self.report.to_dict(), handle, indent=2, ensure_ascii=False)
            except OSError as error:
                messagebox.showerror("Export failed", str(error))

def main():
    root = tk.Tk()
    NetworkScannerGUI(root)
    root.mainloop()
