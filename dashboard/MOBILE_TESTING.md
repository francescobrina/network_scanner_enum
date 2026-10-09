# PortDrift Mobile HTTPS demonstration

Deployment is available through GitHub Pages, a static HTTPS host.

## One-time setup for the repository maintainer

1. In **Settings > Pages**, choose **Build and deployment > Source: GitHub Actions**.
2. Merge the tested PWA pull request into `main`.
3. In **Actions**, open **Deploy PortDrift Mobile demo** and check that deployment succeeds.
4. Open the exact URL returned by the deployment job (normally https://francescobrina.github.io/network_scanner_enum/).
5. On Android Chrome, use the menu's **Install app** or **Add to Home screen** where supported.

Important: the app is a passive report inspector. It cannot scan Wi-Fi networks or other devices. The demo uses fictional sample JSON; imported report files are processed in browser memory only and are not uploaded. The service worker caches ONLY the static app shell and fictional samples. Avoid putting private scan reports in the public Git repository.

## Device acceptance checklist

- [ ] Install opens in standalone mode or Home-screen shortcut as supported.
- [ ] Fictional sample report loads and indicates exactly 2 newly open ports (443 and 445).
- [ ] Import two local JSON files and compare without page errors.
- [ ] Export changes in JSON and CSV.
- [ ] Stop Internet access: the cached demo still loads after one successful initial online visit.
- [ ] Refresh page: private uploaded reports are not persisted.
- [ ] Test responsive layout at phone width; save screenshots without real IPs.

Note: enabling GitHub Pages is a repository administrative setting that cannot be changed by the currently connected GitHub integration. No public site exists until setup and deployment succeed.
