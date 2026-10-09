# PortDrift Mobile — Android native beta

An open-source Java Android app with a native dark-themed UI, direct **authorized IPv4 LAN discovery**, TCP port checks, JSON export for PortDrift Web and optional LM Studio analysis.

## Features

- Identify responsive hosts in the phone's private Wi-Fi /24 using short bounded TCP checks (80, 443, 22, 445, 8080, 1234) and a reachability fallback.
- Select a discovered host or manually enter a private/Tailscale IPv4 address and test 24 common TCP ports.
- Cancel scans. Export structured JSON compatible with the existing PortDrift browser dashboard.
- Review deterministic defensive suggestions and optionally request an explanation from your own OpenAI-compatible LM Studio server using explicit consent.
- AI receives only port number, service and state, **never a target IP or hostname**. AI access tokens are not persisted.
- Scans require a user authorization checkbox. Target SDK 37 explicitly requests the Android 17 `ACCESS_LOCAL_NETWORK` runtime permission.

## Build and test

CI: [PortDrift Android APK workflow](../../.github/workflows/android-ci.yml), Android SDK 37 + Java 17 + Gradle 9.3.1.

```sh
cd android
gradle :app:testDebugUnitTest :app:assembleDebug
```

Install the **debug-signed APK** from the [v0.5.0 beta.1 prerelease](https://github.com/francescobrina/network_scanner_enum/releases/tag/v0.5.0-beta.1) after GitHub Actions finishes. The APK is a prerelease test build and may require a manual Android install permission. Testing on a real Android 17 device is still needed before production claims.

## Limitations

Not Nmap or Metasploit. No root, ICMP raw socket scanning, UDP scanning, SYN scans, OS fingerprinting, exploitation, NSE scripts, stealth or arbitrary internet scanning. Host discovery will miss silent/firewalled equipment and cannot guarantee a full inventory. Public IP scanning is deliberately disabled; all probes are bounded. No real-world adoption figures are claimed.

HTTP LM Studio connections on a LAN do not provide TLS; prefer Tailscale connectivity and LM Studio authentication or an HTTPS endpoint. Only connect to services you administer.

## Android 17 VPN / LM Studio fixes (0.5.1-beta.2)

- The app now explicitly selects a **physical Wi-Fi network, excluding VPN transports**. A 100.64.0.0/10 Tailscale or CGNAT address is still supported as a **manual target**, but must never drive an automatic Wi-Fi /24 discovery.
- Wi-Fi sockets are bound to the physical network so a default-route VPN does not redirect local probes.
- For LM Studio, enter either the bare IP or the complete OpenAI-compatible URL. Port `1234` and `/v1` are added automatically for HTTP. Click **Verifica server e rileva modelli** to populate the model ID.
- You must still deliberately enable sharing before asking AI to interpret scan findings. HTTP is restricted to loopback, RFC1918, or Tailscale/CGNAT; use only servers you trust.
- The new system-insets handling prevents the Android status bar from covering the app header.

The true Wi-Fi discovery only reports **TCP-responsive** addresses. Devices that decline these probes will remain invisible; this is not a full host census.
