# PortDrift — local-first network drift dashboard

A standalone modern HTML, CSS and JavaScript dashboard for **authorized** Network Scanner Enumerator reports. No web framework, CDN, JavaScript dependency, telemetry, external fonts, account or cloud processing. All report comparison happens in the browser.

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
