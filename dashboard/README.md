# PortDrift — local-first network drift dashboard

An installable, offline-first progressive web app (PWA) built with HTML, CSS and JavaScript for **authorized** Network Scanner Enumerator reports. No web framework, CDN, JavaScript dependency, telemetry, external fonts, account or cloud processing. The offline service worker caches only the static app shell and bundled fictional sample data; imported scans are never cached or uploaded. All report comparison happens in the browser.

## Try it

From the repository root:

```sh
python -m http.server 8000 -d dashboard
```

Open http://127.0.0.1:8000 then click **Load sample workspace** (fictional TEST-NET target). You can also choose one current JSON or Nmap XML report, or compare before and after reports of the same target. Reports can be produced by:

```sh
python cli.py 127.0.0.1 --authorized --json before.json
# Repeat after a maintenance change, on an authorized target:
python cli.py 127.0.0.1 --authorized --json after.json
```

This is a **passive analysis interface**; it does not scan hosts itself. The browser never uploads your files. The demo loader accesses only bundled fictional sample data from the same origin. Do not host production reports publicly.

## What it does

- Compares matched TCP ports between two snapshots, showing newly open ports and state changes.
- Highlights failed TLS verification where captured.
- Warns about changed DNS resolution, partial scans and mismatched port coverage.
- Produces a JSON evidence package for internal issue triage.
- Offers single-snapshot review and accessible mobile layouts.

**Important:** an open port is not proof of a vulnerability. A port missing from a snapshot was not scanned and is never marked closed. For AI explanations use the optional desktop LM Studio panel. The web dashboard intentionally does not transmit scan contents to any AI service.

## Development

```sh
node --test dashboard/tests/*.test.mjs
```

Node.js 22+ is needed for development tests only; end users need just a browser.

### Import existing Nmap results

You may select *single-host* XML reports from `nmap -oX scan.xml <authorized-host>` directly in the browser. Parsing happens offline, and only explicitly reported TCP ports are considered. Nmap's aggregate `extraports` values do not specify which ports they represent; PortDrift conservatively treats those as missing coverage rather than marking individual ports closed. Alternatively run `network-scan-nmap scan.xml --json snapshot.json` for a normalized JSON report.

## Android installation (PWA)

Deploy the `dashboard/` directory over **HTTPS** (or open it on `http://localhost` when developing on that same device). In Chrome on Android, open the URL and choose **Install app** or **Add to Home screen** from the menu if available. Installation availability and icon handling vary by browser; this PWA is **not a native APK**. You may also open it as an ordinary mobile site.

The browser tool is *passive*: it does not access Wi-Fi scanning APIs or Android permissions and cannot scan your network itself. You must import one or two authorized JSON/Nmap XML reports. The imported files remain in memory until you clear/reload the page. Only the app shell and fictional samples are cached for offline use.

## CSV export

Export findings as a simple CSV suitable for help-desk / admin triage. It excludes the target hostname/IP from file contents by default and escapes formula-like spreadsheet cell values. The filename is generated from the target name locally, so consider renaming it before sharing.

## Contributor focus

Useful contributions include deterministic fixtures from Nmap XML (with all real host identities replaced), accessibility and Android browser QA, performance tests for large but bounded JSON snapshots, and documentation of legitimate administrative workflows.
