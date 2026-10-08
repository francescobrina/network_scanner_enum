# Network Scanner Enumerator

Version **0.3.0** — an open-source Python desktop GUI and headless CLI for **authorized, bounded network diagnostics**. No cloud account, API key, or telemetry is required. Maintained by [Francesco Brina](https://github.com/francescobrina).

![Python](https://img.shields.io/badge/Python-3.11%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green)

## Features

- **Bounded TCP checks** on a single IPv4, IPv6 or DNS target, with fast or extended standard ports.
- **Verified TLS certificate inspection** for 443 and 8443 (protocol, cipher, issuer, subject and expiry). Failed certificate checks are reported, never bypassed.
- **Responsive GUI**, with progress bar, cancellation and JSON export.
- **Headless CLI** for scripts and JSON reports.
- **Baseline comparisons** that highlight TCP state changes without mistaking unscanned ports for closed ports.
- **Optional local AI explanation** of sanitized findings using LM Studio or another OpenAI-compatible server. Explicit consent is required; the target name/IP and certificate details are excluded from AI requests. No AI dependency, API key or subscription is required.
- **Installable Python package** with a versioned command-line entry point and reproducible build checks.
- Existing **OS TTL heuristic, SMB enumeration, and anonymous FTP enumeration** remain available as legacy GUI modes. TTL heuristics are not reliable OS identification.

## Installation

Requires Python 3.11 or later.

    git clone https://github.com/francescobrina/network_scanner_enum.git
    cd network_scanner_enum
    python -m venv .venv
    # Linux/macOS: source .venv/bin/activate
    # Windows: .venv\Scripts\activate
    python -m pip install .

Optional legacy SMB enumeration requires the pysmb package:

    python -m pip install '.[smb]'

If running directly from the source checkout without installation, `python cli.py` and `python main.py` also work.

Tkinter may require a separate system package (python3-tk on Debian/Ubuntu).
The pysmb dependency is used only by the optional legacy SMB mode.

## Desktop app

    python main.py

Enter one target, select a mode, and confirm authorization before starting.
Export JSON reports after a Fast Scan or Standard Ports scan. Cancel to stop early.

## Command-line usage

    python cli.py 127.0.0.1 --authorized
    python cli.py localhost --standard --authorized --json scan-report.json
    python cli.py https://example.org --ports 80,443 --authorized
    python cli.py localhost --authorized --baseline old-report.json --json new-report.json

Installed package entry points:

    network-scan 127.0.0.1 --authorized
    network-scan-gui

Options include timeout (0.1-10s), workers (1-32), --no-tls and --baseline. For consistency, use the same target and ports when comparing reports; changing DNS resolution produces a warning.
The CLI requires --authorized and scans only one DNS-resolved numeric address.

Status meanings: **open** = TCP connection succeeded; **closed** = connection refused; **timeout** = no reply before timeout; **error** = another network error. No result alone proves a vulnerability, and this utility does not assess UDP.

## Development and test

    python -m unittest discover -s tests -v
    python -m compileall -q cli.py scanners gui

GitHub Actions tests on Python 3.11, 3.12 and 3.13, builds Python distributions and verifies installed command entry points; automated network tests only use loopback or mocks.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
Licensed under [MIT](LICENSE).

## Roadmap

- [ ] Expand tests for cancellation and legacy diagnostic modules.
- [x] Publish installable package metadata and automated build checks.
- [ ] Validate desktop GUI on Windows/Linux; tag a downloadable release after smoke testing.
- [ ] Add internationalization and GUI accessibility refinements.

Feedback and contributions are welcome through GitHub Issues. Usage statistics are not claimed without evidence.

## Maintainer workflow

Open a bug report with minimal reproduction steps and sanitized outputs; use pull requests for targeted fixes. [See the roadmap](https://github.com/francescobrina/network_scanner_enum/issues/2), the [changelog](CHANGELOG.md) and the [contribution guide](CONTRIBUTING.md). We welcome reliable tests for network edge cases. Please do not report fictitious adoption or download counts.

## Local AI assistant (optional)

1. Install [LM Studio](https://lmstudio.ai/), load an instruct model and enable its OpenAI-compatible server on port 1234.
2. Launch `network-scan-gui`, run an authorized TCP scan, then enter the **actual model ID** from LM Studio.
3. Keep the default endpoint `http://127.0.0.1:1234/v1` (same machine). Other HTTPS endpoints and Tailscale 100.64.0.0/10 addresses can be configured explicitly.
4. Check the separate consent option **Send only sanitized port data**, then click **Explain scan with AI**.

The AI request includes only port number, inferred service label, TCP state and a boolean TLS verification flag; **no target name/IP, raw banners, certificate subjects or credentials**. Do not point the endpoint at a cloud provider without reviewing its terms and data handling. AI explanations are unverified advice, never evidence that a host is vulnerable. Models are not downloaded by this project and there is no auto-execution of recommendations.

The desktop GUI uses built-in dark-styled Tkinter/ttk, and works without AI setup. Headless scans remain available via CLI. Visual testing across all platforms is ongoing; if you find layout issues, please open a reproducible issue.
