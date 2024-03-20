import subprocess
import tkinter as tk

class OSDetector:
    def detect_os(self, ip_address, output_text_widget):
        output_text_widget.delete("1.0", tk.END)
        output_text_widget.insert(tk.END, f"OS Detection on {ip_address}...\n\n")
        try:
            ping_result = subprocess.run(["ping", "-c", "1", ip_address], capture_output=True, text=True)
            ttl_index = ping_result.stdout.find("ttl=")
            if ttl_index != -1:
                ttl = int(ping_result.stdout[ttl_index + 4:].split()[0])
                if 64 <= ttl <= 128:
                    output_text_widget.insert(tk.END, "OS detected: Linux or Unix-like OS\n")
                elif 128 < ttl <= 255:
                    output_text_widget.insert(tk.END, "OS detected: Windows\n")
                else:
                    output_text_widget.insert(tk.END, "OS detection failed: TTL value out of range\n")
            else:
                output_text_widget.insert(tk.END, "OS detection failed: Unable to determine TTL\n")
        except Exception as e:
            output_text_widget.insert(tk.END, f"Error detecting OS: {e}\n")
