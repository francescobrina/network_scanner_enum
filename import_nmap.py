"""Import authorized, one-host Nmap -oX XML without guessing omitted port states."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

from scanners.diagnostics import PortResult, ScanReport

MAX_XML_BYTES = 8 * 1024 * 1024
DOCTYPE = re.compile(r"<!DOCTYPE\s+nmaprun\s*(?:SYSTEM\s+[\"'][^\"']+[\"']\s*)?>", re.I)


def read_nmap_xml(path: Path) -> ScanReport:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ValueError(f"Cannot read Nmap XML: {exc}") from exc
    if len(raw) > MAX_XML_BYTES:
        raise ValueError("Nmap XML must be no larger than 8 MiB.")
    if b"<!ENTITY" in raw.upper() or b"<![CDATA[" in raw.upper():
        raise ValueError("Entity or CDATA declarations are not permitted.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ValueError("Nmap XML must be UTF-8.") from exc
    # Nmap may include a DOCTYPE reference to its documented DTD. Remove it
    # before parsing so no DTD is interpreted or external entity fetched.
    text = DOCTYPE.sub("", text)
    if "<!DOCTYPE" in text.upper():
        raise ValueError("Unsupported XML doctype.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("Expected an nmaprun document.")
    hosts = root.findall("host")
    if len(hosts) != 1:
        raise ValueError("Only one-host Nmap XML files are supported; scan one permitted host.")
    host = hosts[0]
    hostnames = host.findall("./hostnames/hostname")
    addr = next((a.get("addr") for a in host.findall("address")
                 if a.get("addrtype") in ("ipv4", "ipv6") and a.get("addr")), "")
    if not addr:
        raise ValueError("No IPv4/IPv6 address found.")
    target = next((h.get("name") for h in hostnames if h.get("name")), addr)
    started = root.get("start", "")
    try:
        started_at = datetime.fromtimestamp(int(started), timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        started_at = datetime.now(timezone.utc).isoformat()
    results = []
    used = set()
    for item in host.findall("./ports/port"):
        if item.get("protocol") != "tcp":
            continue
        try:
            port = int(item.get("portid", ""))
        except ValueError as exc:
            raise ValueError("Invalid TCP port number.") from exc
        if port < 1 or port > 65535 or port in used:
            raise ValueError("Invalid or duplicate TCP port.")
        used.add(port)
        state = item.find("state")
        value = state.get("state") if state is not None else "error"
        if value not in ("open", "closed", "filtered", "error"):
            value = "error"
        service = item.find("service")
        name = service.get("name", "unknown") if service is not None else "unknown"
        results.append(PortResult(port, value, name[:80]))
    results.sort(key=lambda item: item.port)
    # Sparse Nmap XML often collapses unlisted ports into extraports. Their
    # individual identities are unknown; we must never infer closure.
    completed = not bool(host.findall("./ports/extraports"))
    if host.find("status") is not None and host.find("status").get("state") != "up":
        completed = False
    return ScanReport(target, addr, started_at, 0.0, completed, results)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Convert one-host Nmap XML to conservative PortDrift JSON")
    parser.add_argument("input", type=Path, help="Single authorized target XML from nmap -oX")
    parser.add_argument("--json", required=True, type=Path, help="Output JSON path")
    args = parser.parse_args(argv)
    try:
        report = read_nmap_xml(args.input)
        args.json.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"Imported {len(report.results)} explicitly listed TCP ports to {args.json}")
        if not report.completed:
            print("NOTE: Aggregate/excluded ports or down host; missing ports are not treated as closed.")
        return 0
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
