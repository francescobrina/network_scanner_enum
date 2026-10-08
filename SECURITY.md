# Security policy

This utility is intended solely for network troubleshooting and security assessments performed with explicit authorization. Never scan systems you do not control or have permission to test.

## Scope and limitations

- No exploit execution, brute force, credential guessing, or stealth scanning.
- DNS is resolved once per run; TCP probes use the selected numeric address.
- TLS certificate verification remains enabled. Untrusted certificates are reported, not silently accepted.
- Scan concurrency is limited to 32 workers and 128 ports per invocation.
- Legacy FTP and SMB modules can interact with services; use them only when explicitly authorized.
- TTL-based OS detection is heuristic; do not treat it as reliable OS attribution.

## Reporting vulnerabilities

Please report vulnerabilities privately through the maintainer's GitHub profile contact details, without posting exploit details to a public issue. Include affected version, reproduction steps, and potential impact. Do not include credentials, access tokens, or live target data.

Security reports will be acknowledged and assessed as maintainer capacity allows; no SLA is currently guaranteed.
