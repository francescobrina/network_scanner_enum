import tkinter as tk
from gui.network_scanner_gui import NetworkScannerGUI

def main():
    root = tk.Tk()

    app = NetworkScannerGUI(root)

    root.mainloop()

if __name__ == "__main__":
    main()
