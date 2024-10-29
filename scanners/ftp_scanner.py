# scanners/ftp_scanner.py

import ftplib
import socket
import tkinter as tk
from datetime import datetime


class FTPEnumerator:
    """
    Classe per effettuare l'enumerazione dei servizi FTP su un indirizzo IP o dominio specifico.
    """

    def enum_ftp(self, ip_address, output_text_widget):
        output_text_widget.insert(tk.END, f"[{datetime.now()}] Inizio enumerazione FTP...\n")
        try:
            ftp = ftplib.FTP()
            # Aumentiamo il timeout per gestire server lenti
            ftp.connect(ip_address, 21, timeout=10)
            output_text_widget.insert(tk.END, f"Connesso a {ip_address}\n")
            try:
                # Tenta di effettuare il login anonimo con credenziali esplicite
                ftp.login(user='anonymous', passwd='anonymous@domain.com')
                output_text_widget.insert(tk.END, "Login anonimo effettuato con successo.\n")
            except ftplib.error_perm as e:
                output_text_widget.insert(tk.END, f"Login anonimo fallito: {e}\n")
                ftp.quit()
                output_text_widget.insert(tk.END, "Enumerazione FTP terminata.\n")
                return

            # Tenta di elencare le directory
            try:
                ftp.cwd('/')
                files = ftp.nlst()
                if files:
                    output_text_widget.insert(tk.END, "Elenco dei file nella directory FTP:\n")
                    for file in files:
                        output_text_widget.insert(tk.END, f"- {file}\n")
                else:
                    output_text_widget.insert(tk.END, "La directory FTP è vuota.\n")
            except ftplib.error_perm as e:
                output_text_widget.insert(tk.END, f"Permesso negato durante l'elenco dei file: {e}\n")
            except ftplib.error_temp as e:
                output_text_widget.insert(tk.END, f"Errore temporaneo durante l'elenco dei file: {e}\n")
            ftp.quit()
        except socket.timeout:
            output_text_widget.insert(tk.END, "Errore: Connessione scaduta (timeout).\n")
        except ftplib.all_errors as e:
            output_text_widget.insert(tk.END, f"Errore durante l'enumerazione FTP: {e}\n")
        except Exception as e:
            output_text_widget.insert(tk.END, f"Errore generale: {e}\n")
        output_text_widget.insert(tk.END, f"[{datetime.now()}] Enumerazione FTP completata.\n")
