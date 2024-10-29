# scanners/os_scanner.py

import subprocess
import tkinter as tk
import platform
from datetime import datetime


class OSDetector:
    """
    Classe per rilevare il sistema operativo di un host remoto basato sul TTL.
    """

    def detect_os(self, ip_address, output_text_widget):
        output_text_widget.insert(tk.END, f"[{datetime.now()}] Inizio rilevamento OS...\n")
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            ping_cmd = ["ping", param, "1", ip_address]
            ping_result = subprocess.run(ping_cmd, capture_output=True, text=True)
            ttl_index = ping_result.stdout.lower().find("ttl=")
            if ttl_index != -1:
                ttl_value = ping_result.stdout[ttl_index + 4:].split()[0]
                ttl = int(''.join(filter(str.isdigit, ttl_value)))
                output_text_widget.insert(tk.END, f"TTL rilevato: {ttl}\n")
                if ttl <= 64:
                    output_text_widget.insert(tk.END, "Possibile sistema operativo: Linux/Unix\n")
                elif ttl <= 128:
                    output_text_widget.insert(tk.END, "Possibile sistema operativo: Windows\n")
                else:
                    output_text_widget.insert(tk.END, "Sistema operativo non determinato.\n")
            else:
                output_text_widget.insert(tk.END, "Impossibile determinare il TTL.\n")
        except Exception as e:
            output_text_widget.insert(tk.END, f"Errore durante il rilevamento OS: {e}\n")
        output_text_widget.insert(tk.END, f"[{datetime.now()}] Rilevamento OS completato.\n")
