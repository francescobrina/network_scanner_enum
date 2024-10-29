# gui/gui.py

import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk
import threading
import socket

from scanners.port_scanner import PortScanner
from scanners.smb_scanner import SMBEnumerator
from scanners.ftp_scanner import FTPEnumerator
from scanners.os_scanner import OSDetector


class NetworkScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Network Scanner")
        master.resizable(False, False)

        # Frame principale
        main_frame = tk.Frame(master, padx=10, pady=10)
        main_frame.pack()

        # Input dell'indirizzo IP o URL
        ip_frame = tk.Frame(main_frame)
        ip_frame.pack(pady=5)
        self.ip_label = tk.Label(ip_frame, text="Indirizzo IP o URL:")
        self.ip_label.pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(ip_frame, width=30)
        self.ip_entry.pack(side=tk.LEFT, padx=5)

        # Selettore del tipo di scansione
        self.scan_types = [
            "Fast Scan",
            "Ports Scan",
            "OS Detection",
            "SMB Enumeration",
            "FTP Enumeration"
        ]
        self.selected_scan_type = tk.StringVar(master)
        self.selected_scan_type.set(self.scan_types[0])

        scan_type_frame = tk.Frame(main_frame)
        scan_type_frame.pack(pady=5)
        self.scan_type_label = tk.Label(scan_type_frame, text="Tipo di scansione:")
        self.scan_type_label.pack(side=tk.LEFT)
        self.scan_type_menu = tk.OptionMenu(
            scan_type_frame, self.selected_scan_type, *self.scan_types
        )
        self.scan_type_menu.pack(side=tk.LEFT, padx=5)

        # Pulsante di avvio scansione
        self.scan_button = tk.Button(
            main_frame, text="Avvia Scansione", command=self.start_scan_thread
        )
        self.scan_button.pack(pady=10)

        # Barra di progressione
        self.progress = ttk.Progressbar(main_frame, orient='horizontal', mode='determinate', length=400)
        self.progress.pack(pady=5)
        self.progress['value'] = 0

        # Output della scansione
        self.output_text = ScrolledText(main_frame, height=20, width=80)
        self.output_text.pack()

    def start_scan_thread(self):
        # Avvia la scansione in un thread separato
        threading.Thread(target=self.start_scan).start()

    def start_scan(self):
        user_input = self.ip_entry.get().strip()
        if not user_input:
            messagebox.showerror("Errore", "Inserisci un indirizzo IP o URL valido.")
            return

        # Prova a risolvere l'input come indirizzo IP o nome host
        try:
            ip_address = socket.gethostbyname(user_input)
            domain_name = user_input if self.is_domain(user_input) else None
        except socket.gaierror:
            messagebox.showerror("Errore", "Indirizzo IP o URL non valido.")
            return

        selected_type = self.selected_scan_type.get()
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(
            tk.END, f"Avvio {selected_type} su {user_input} ({ip_address})...\n\n"
        )

        # Reset della barra di progressione
        self.progress['value'] = 0
        self.master.update_idletasks()

        if selected_type in ["Fast Scan", "Ports Scan"]:
            # Inizializza lo scanner con parametri predefiniti
            scanner = PortScanner()
            scan_function = scanner.fast_scan if selected_type == "Fast Scan" else scanner.scan_ports
            self.run_scan(scan_function, ip_address, domain_name)
        elif selected_type == "OS Detection":
            OSDetector().detect_os(ip_address, self.output_text)
            self.progress['value'] = 100
        elif selected_type == "SMB Enumeration":
            SMBEnumerator().enum_smb(ip_address, self.output_text)
            self.progress['value'] = 100
        elif selected_type == "FTP Enumeration":
            FTPEnumerator().enum_ftp(ip_address, self.output_text)
            self.progress['value'] = 100

    def run_scan(self, scan_function, ip_address, domain_name):
        """
        Esegue una funzione di scansione e aggiorna la barra di progressione.
        """
        def target():
            scan_function(ip_address, self.output_text, domain_name)
            self.progress['value'] = 100
            self.master.update_idletasks()

        threading.Thread(target=target).start()

    @staticmethod
    def is_domain(input_str):
        """
        Determina se l'input è un nome di dominio.
        """
        try:
            socket.gethostbyname(input_str)
            return any(c.isalpha() for c in input_str)
        except socket.gaierror:
            return False


def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
