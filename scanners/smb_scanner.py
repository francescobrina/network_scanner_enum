from smb.SMBConnection import SMBConnection
import tkinter as tk

class SMBEnumerator:
    def enum_smb(self, ip_address, output_text_widget):
        output_text_widget.delete("1.0", tk.END)
        output_text_widget.insert(tk.END, f"SMB Enumeration on {ip_address}...\n\n")
        try:
            conn = SMBConnection('guest', '', 'my_client', ip_address, use_ntlm_v2=True)
            conn.connect(ip_address, 445)
            shares = conn.listShares()
            if shares:
                output_text_widget.insert(tk.END, "SMB Shares:\n")
                for share in shares:
                    output_text_widget.insert(tk.END, f"{share.name}\n")
            else:
                output_text_widget.insert(tk.END, "No SMB shares found.\n")

            users = conn.listUsers()
            if users:
                output_text_widget.insert(tk.END, "\nSMB Users:\n")
                for user in users:
                    output_text_widget.insert(tk.END, f"{user}\n")
            else:
                output_text_widget.insert(tk.END, "No SMB users found.\n")

            conn.close()
        except Exception as e:
            output_text_widget.insert(tk.END, f"Error enumerating SMB: {e}\n")