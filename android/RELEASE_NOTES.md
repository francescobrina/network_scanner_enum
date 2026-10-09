# PortDrift Mobile v0.5.1-beta.2 — LAN and LM Studio reliability fixes

Verified Android SDK 37 debug build. This is a test build and requires real-device verification.

## Improvements

- Distinguish the **physical Wi-Fi network** from active VPN/Tailscale, preventing a 100.64/10 VPN address from being treated as the Wi-Fi /24.
- Bind LAN TCP probes to the selected physical Wi-Fi Network, even when Android also uses a VPN.
- Discover only hosts responding to authorized bounded TCP probes; report the limitations without claiming complete discovery.
- Fix Android 15+ edge-to-edge status-bar header overlap.
- Accept an LM Studio IP without the port/path; automatically normalize HTTP to `:1234/v1`.
- Add an explicit **Verify server and detect models** button; automatically fetch the first available model when the ID is left blank.
- Surface connection and authorization errors directly, preserving the input dialog on missing consent.
- Add tests for subnet selection and AI endpoint handling; keep reports and model payload limited to scan metadata.

## Installation

Download `app-debug.apk`, then install it on an authorized Android device. It uses a **temporary debug signing identity**: if the existing beta cannot be updated because of mismatched signatures, uninstall the old PortDrift Mobile first (export any reports you need), then install the new version.

## Notes

Use solely on devices and networks you own or have explicit authorization to assess. This is not Nmap and not a vulnerability scanner. Open TCP ports, or missing responses to TCP probes, do not prove security or vulnerability. The optional LM Studio connection requires a running model server and an accessible network route. No adoption metrics are claimed.
