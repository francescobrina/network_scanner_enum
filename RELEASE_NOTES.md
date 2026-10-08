# Network Scanner Enumerator v0.3.0

Network diagnostics for explicitly authorized targets, with a dark desktop dashboard, local-first AI explanations, reproducible Python packaging and standard-library TCP diagnostics.

## Highlights
- New single-host Nmap XML report adapter: `network-scan-nmap scan.xml --json snapshot.json`, plus direct browser import.
- New PortDrift responsive dashboard for local-only two-snapshot comparison, exposure changes and evidence export. Run: `python -m http.server 8000 -d dashboard`. No Node, server cloud, data upload or API key required for end users.
- TCP fast/standard scan of one IPv4, IPv6 or hostname target with bounded concurrency and authorization gates.
- Structured results, JSON export and baseline port-state comparisons.
- TLS verification details and safe failure reporting.
- Updated desktop dashboard and scan activity console with thread-safe updates.
- Optional AI guidance through LM Studio or a compatible endpoint after explicit consent; the API payload excludes target hostnames and IP addresses.
- Installable wheel and source archive; CI covers Python 3.11-3.13 plus GUI startup on virtual display.

## Install
```sh
python -m pip install brina_network_scanner-0.3.0-py3-none-any.whl
network-scan 127.0.0.1 --authorized
network-scan-gui
```
Legacy SMB diagnostics require `python -m pip install 'brina-network-scanner[smb]'` (or `pip install '.[smb]'` from source).

## Important limitations
- Use only with explicit permission.
- An open port is not a vulnerability finding; AI advice is not verified.
- Full manual desktop smoke testing on native Windows/macOS has not been completed.
- No external adoption or download metrics are claimed.
