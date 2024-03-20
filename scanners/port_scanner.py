import socket
import tkinter as tk

class PortScanner:

    def scan_ports(self, ip_address, output_text_widget):
        target_ports = [1, 5, 7, 18, 20, 20, 21, 21, 21, 22, 22, 22, 22, 23, 23, 23, 25, 25, 25, 29, 37, 42, 43, 49, 53, 53, 53, 69, 70, 79, 80, 80, 80, 103, 108, 109, 110, 110, 110, 115, 118, 119, 137, 139, 143, 143, 143, 150, 156, 161, 161, 162, 179, 190, 194, 197, 389, 396, 443, 443, 443, 443, 444, 445, 445, 458, 465, 465, 546, 547, 563, 569, 587, 587, 993, 993, 995, 995, 1080, 1723, 3306]
        """
        target_ports = [
            20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389, 5900,
            8080, 8443, 8888, 3306, 5432, 27017, 22, 80, 443, 21, 22, 23, 25, 53, 110,
            143, 161, 162, 443, 445, 465, 587, 993, 995, 1723, 3306, 3389, 5900, 8080,
            27017, 1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79,
            80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143, 150, 156, 161, 179, 190,
            194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080
        ]
        """

        output_text_widget.delete("1.0", tk.END)
        output_text_widget.insert(tk.END, f"Ports scan on {ip_address}...\n\n")
        for port in target_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    output_text_widget.insert(tk.END, f"Port {port} is open\n")
                else:
                    output_text_widget.insert(tk.END, f"Port {port} is closed\n")
                sock.close()
            except Exception as e:
                output_text_widget.insert(tk.END, f"Error scanning port {port}: {e}\n")

    def fast_scan(self, ip_address, output_text_widget):
        target_ports = [80, 443, 22, 21, 25, 53, 3389, 3306, 1433, 8080]
        output_text_widget.delete("1.0", tk.END)
        output_text_widget.insert(tk.END, f"Ports scan on {ip_address}...\n\n")
        for port in target_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    output_text_widget.insert(tk.END, f"Port {port} is open\n")
                else:
                    output_text_widget.insert(tk.END, f"Port {port} is closed\n")
                sock.close()
            except Exception as e:
                output_text_widget.insert(tk.END, f"Error scanning port {port}: {e}\n")
