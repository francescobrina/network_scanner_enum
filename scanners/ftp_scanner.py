import ftplib
import tkinter as tk

class FTPEnumerator:
    def enum_ftp(self, ip_address, output_text_widget):
        output_text_widget.delete("1.0", tk.END)
        output_text_widget.insert(tk.END, f"FTP Enumeration on {ip_address}...\n\n")
        try:
            ftp = ftplib.FTP(ip_address)
            ftp.login()
            files = ftp.nlst()
            if files:
                output_text_widget.insert(tk.END, "FTP Directory Listing: ")
                for file in files:
                    output_text_widget.insert(tk.END, f"{file}\n")
            else:
                output_text_widget.insert(tk.END, "FTP Directory is empty.")
            ftp.quit()
        except Exception as e:
            output_text_widget.insert(tk.END, f"Error enumerating FTP: {e}\n")
