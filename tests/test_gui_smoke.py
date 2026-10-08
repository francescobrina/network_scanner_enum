"""Desktop window smoke test requires a virtual display in CI."""
import os
import tkinter as tk
import unittest
from gui.gui import NetworkScannerGUI

@unittest.skipUnless(os.environ.get("GUI_SMOKE") == "1", "Requires a GUI display")
class DesktopSmokeTests(unittest.TestCase):
    def test_window_startup_and_controls(self):
        root = tk.Tk()
        try:
            app = NetworkScannerGUI(root)
            root.update_idletasks()
            root.update()
            self.assertEqual(app.target.get(), "127.0.0.1")
            self.assertFalse(app.permission.get())
            self.assertFalse(app.ai_consent.get())
            self.assertEqual(app.start_button["state"], "normal")
            self.assertEqual(app.ai_button["state"], "disabled")
        finally:
            root.destroy()

if __name__ == "__main__":
    unittest.main()
