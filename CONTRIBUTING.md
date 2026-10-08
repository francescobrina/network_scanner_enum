# Contributing

Bug reports, tests, documentation improvements and feature proposals are welcome.

1. Open an issue describing the use case or reproducible bug (remove real hostnames, credentials and scan results).
2. Fork the repository and branch from main.
3. Run: python -m unittest discover -s tests -v
4. Run: python -m compileall -q cli.py scanners gui
5. Add tests for new diagnostics. Network tests must operate against loopback only; no public host scans in CI.
6. In a pull request, describe scope, security implications, and how you tested the change.

Respect the authorization requirement and do not propose credential attacks, exploitation, evasion or unbounded internet-wide scanning functionality.
