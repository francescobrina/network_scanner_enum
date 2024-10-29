# scanners/smb_scanner.py

from smb.SMBConnection import SMBConnection
import tkinter as tk
from datetime import datetime


class SMBEnumerator:
    """
    Classe per effettuare l'enumerazione dei servizi SMB su un indirizzo IP specifico.
    """

    def enum_smb(self, ip_address, output_text_widget):
        output_text_widget.insert(tk.END, f"[{datetime.now()}] Inizio enumerazione SMB...\n")
        try:
            conn = SMBConnection('', '', 'scanner', ip_address, use_ntlm_v2=True)
            conn.connect(ip_address, 139, timeout=5)
            shares = conn.listShares()
            if shares:
                output_text_widget.insert(tk.END, "Condivisioni SMB disponibili:\n")
                for share in shares:
                    output_text_widget.insert(tk.END, f"- {share.name}\n")
            else:
                output_text_widget.insert(tk.END, "Nessuna condivisione SMB trovata.\n")
            conn.close()
        except Exception as e:
            output_text_widget.insert(tk.END, f"Errore durante l'enumerazione SMB: {e}\n")
        output_text_widget.insert(tk.END, f"[{datetime.now()}] Enumerazione SMB completata.\n")
