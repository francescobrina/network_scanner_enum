# PortDrift Mobile v0.5.0-beta.1 — first native Android scanner

**Native Android debug APK**, produced by GitHub Actions after automated compilation and JVM unit tests.

### Features

- Direct, bounded **TCP-connect scans** of 24 common ports on user-authorized private and Tailscale IPv4 targets.
- Discover responsive devices on the phone's private Wi-Fi /24 using bounded TCP/reachability probes. The results are **not** a complete device inventory.
- User-initiated, cancellable scans; responsive native dark UI with open/closed/timeout results.
- Save a JSON report compatible with PortDrift's browser dashboard.
- Optional **LM Studio** analysis with user consent; sends only ports, service names and states, never IPs or hostnames.
- Respects Android 17 `ACCESS_LOCAL_NETWORK` runtime permission, in addition to explicit confirmation of scanning authorization.
- No root, shell access, exploitation, telemetry, account or subscription required.

### Install on Android

1. Download `app-debug.apk` from this release using Chrome on the phone.
2. Open the APK. If Android asks for permission to install from Chrome, grant permission **only if you trust this GitHub project and verified release**, then install.
3. Connect to your own Wi-Fi, launch PortDrift and accept the OS local-network permission when prompted.
4. Tick the application authorization checkbox, then tap **Trova dispositivi Wi-Fi**.
5. Tap an address to scan its common TCP ports, or enter an explicit private/Tailscale IP.
6. Use **Esporta JSON** to review the results in PortDrift Web.

### Honest limitations

This is a **beta**, not a tested Play Store production release. Native Android 17 device smoke testing, accessibility testing, long-scan resilience and external security review have not yet been completed. Device discovery can miss firewalled or silent hosts. Unlike Nmap, the app does not perform raw-SYN, UDP, NSE, OS fingerprinting or comprehensive host fingerprinting. It does not establish CVEs or exploitable vulnerabilities merely from open ports.

The APK is built with the Android debug key on GitHub Actions. Subsequent CI runs may not preserve signing identity, so Android might require uninstall/reinstall for future updates; production signing is a later milestone.
