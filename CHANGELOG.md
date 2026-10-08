# Changelog

## 0.3.0 — 2026-10-08

- Extracted a bounded, testable TCP diagnostic engine with IPv4/IPv6 support.
- Added command-line scanning and machine-readable JSON export.
- Added an offline-capable baseline comparator, distinguishing unscanned from closed ports.
- Added TLS handshake/certificate diagnostics without disabling certificate checks.
- Reworked Tkinter threading and status reporting.
- Added explicit scan authorization, capped concurrency and port counts.
- Added packaging metadata, MIT license, contributor/security guidance, GitHub Actions and regression tests.
- Added a timeout to legacy TTL-based OS detection.
- Added a GUI smoke test with a virtual display and a dedicated scan activity log.
- Introduced an updated dark desktop dashboard with service inventory, progress and JSON export.
- Added an opt-in LM Studio/OpenAI-compatible AI explanation panel, with allowlisted and target-redacted scan metadata.

**Limitations:** TLS inspection only on TCP 443/8443; OS detection is heuristic; legacy SMB and FTP modes remain optional and have not been fully integration-tested on every platform. The tool has no real user adoption statistics to report.
