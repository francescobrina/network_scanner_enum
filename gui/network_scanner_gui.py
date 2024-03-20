import tkinter as tk
from scanners.port_scanner import PortScanner
from scanners.smb_scanner import SMBEnumerator
from scanners.ftp_scanner import FTPEnumerator
from scanners.os_scanner import OSDetector

class NetworkScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Network Scanner")

        self.ip_label = tk.Label(master, text="IP Address:")
        self.ip_label.pack()
        self.ip_entry = tk.Entry(master)
        self.ip_entry.pack()

        self.scan_types = ["Fast Scan", "Ports Scan", "OS Detection", "SMB Enumeration", "FTP Enumeration"]
        self.selected_scan_type = tk.StringVar(master)
        self.selected_scan_type.set(self.scan_types[0])

        self.scan_type_menu = tk.OptionMenu(master, self.selected_scan_type, *self.scan_types)
        self.scan_type_menu.pack()

        self.scan_button = tk.Button(master, text="Start Scan", command=self.start_scan)
        self.scan_button.pack()

        self.output_text = tk.Text(master, height=10, width=50)
        self.output_text.pack()

    def start_scan(self):
        selected_type = self.selected_scan_type.get()
        ip_address = self.ip_entry.get()
        if selected_type == "Fast Scan":
            PortScanner().fast_scan(ip_address, self.output_text)
        elif selected_type == "Ports Scan":
            PortScanner().scan_ports(ip_address, self.output_text)
        elif selected_type == "OS Detection":
            OSDetector().detect_os(ip_address, self.output_text)
        elif selected_type == "SMB Enumeration":
            SMBEnumerator().enum_smb(ip_address, self.output_text)
        elif selected_type == "FTP Enumeration":
            FTPEnumerator().enum_ftp(ip_address, self.output_text)

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
