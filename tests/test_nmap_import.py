"""Nmap test fixtures never contact a network."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from import_nmap import read_nmap_xml


XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun start="1791450000">
  <host><status state="up"/>
    <address addr="192.0.2.5" addrtype="ipv4"/>
    <hostnames><hostname name="lab.example.test"/></hostnames>
    <ports>
      <extraports state="closed" count="996"/>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="443"><state state="filtered"/><service name="https"/></port>
      <port protocol="udp" portid="53"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>"""

class NmapImporterTests(unittest.TestCase):
    def parse(self, text):
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "report.xml"
            src.write_text(text, encoding="utf-8")
            return read_nmap_xml(src)

    def test_import_explicit_tcp_ports(self):
        report = self.parse(XML)
        self.assertEqual(report.target, "lab.example.test")
        self.assertEqual(report.resolved_ip, "192.0.2.5")
        self.assertEqual([p.port for p in report.results], [22,443])
        self.assertEqual([p.state for p in report.results], ["open","filtered"])
        self.assertFalse(report.completed)

    def test_entity_blocked(self):
        src = '<!DOCTYPE nmaprun [<!ENTITY x "evil">]><nmaprun></nmaprun>'
        with self.assertRaises(ValueError):
            self.parse(src)

    def test_multi_host_rejected(self):
        with self.assertRaises(ValueError):
            self.parse('<nmaprun><host/><host/></nmaprun>')

    def test_basic_open_host_is_completed(self):
        text = '<nmaprun start="1791450000"><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port portid="80" protocol="tcp"><state state="closed"/></port></ports></host></nmaprun>'
        r = self.parse(text)
        self.assertTrue(r.completed)
        self.assertEqual(r.results[0].state, "closed")

if __name__ == "__main__":
    unittest.main()
