import {compare, summary, normalizeReport, safeFilename, changesToCsv} from "./logic.mjs";
const $ = id => document.getElementById(id);
let current = null, baseline = null, computed = null;
function text(id, value) { $(id).textContent = String(value); }
function clearNode(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function el(name, content, cls) {
  const element = document.createElement(name);
  if (cls) element.className = cls;
  if (content !== undefined) element.textContent = String(content);
  return element;
}
function message(value) { $("alert").textContent = value || ""; $("alert").hidden = !value; }
function filename(id, file) { text(id, file || "No report selected"); }
function readNmapXml(xml) {
  if (/<!(?:ENTITY|\[CDATA\[)/i.test(xml)) throw new Error("XML entities and CDATA are unsupported.");
  // Strip Nmap's external DTD declaration before DOM parsing.
  xml = xml.replace(/<!DOCTYPE\s+nmaprun\s*(?:SYSTEM\s+["'][^"']+["']\s*)?>/i, "");
  if (/<!DOCTYPE/i.test(xml)) throw new Error("Unsupported XML DTD declaration.");
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  if (doc.querySelector("parsererror") || doc.documentElement?.tagName !== "nmaprun")
    throw new Error("Invalid Nmap XML.");
  const hosts = [...doc.querySelectorAll("nmaprun > host")];
  if (hosts.length !== 1) throw new Error("Nmap XML must contain exactly one host.");
  const host = hosts[0];
  const address = [...host.querySelectorAll("address")].find(
    a => ["ipv4","ipv6"].includes(a.getAttribute("addrtype")));
  const resolvedIp = address?.getAttribute("addr") || "";
  if (!resolvedIp) throw new Error("Nmap XML is missing an IPv4/IPv6 address.");
  const hostname = host.querySelector("hostnames > hostname")?.getAttribute("name") || resolvedIp;
  const ports = [...host.querySelectorAll("ports > port")].filter(
    p => p.getAttribute("protocol") === "tcp");
  if (ports.length > 65535) throw new Error("Too many listed ports.");
  const records = ports.map(p => ({
    port: Number(p.getAttribute("portid")),
    state: p.querySelector("state")?.getAttribute("state") || "error",
    service: p.querySelector("service")?.getAttribute("name") || "unknown",
  }));
  const timestamp = Number(doc.documentElement.getAttribute("start"));
  const started = Number.isFinite(timestamp) && timestamp > 0
    ? new Date(timestamp * 1000).toISOString() : "";
  return normalizeReport({
    target: hostname, resolved_ip: resolvedIp,
    started_at: started, duration_s: null,
    completed: !host.querySelector("ports > extraports") &&
      host.querySelector("status")?.getAttribute("state") === "up",
    results: records
  });
}
async function readFile(file) {
  if (!file || file.size > 8 * 1024 * 1024)
    throw new Error("Choose a JSON or Nmap XML file smaller than 8 MB.");
  const raw = await file.text();
  if (file.name.toLowerCase().endsWith(".xml"))
    return readNmapXml(raw);
  let data;
  try { data = JSON.parse(raw); } catch { throw new Error("Invalid JSON file."); }
  return normalizeReport(data);
}
function render() {
  message("");
  $("empty-changes").hidden = !!current;
  $("changes-content").hidden = !current;
  $("export").disabled = !current;
  $("export-csv").disabled = !current;
  if (!current) {
    for (const id of ["count-checked", "count-open", "count-new", "count-drift", "donut-value", "legend-open", "legend-other"]) text(id, "—");
    text("comparison-mode", "Awaiting snapshot");
    $("donut").style.setProperty("--percent", "0%");
    $("donut").setAttribute("aria-label", "No scan loaded");
    const rows = $("ports"); clearNode(rows);
    const tr = el("tr"), td = el("td", "No current scan has been loaded.", "table-empty");
    td.colSpan = 5; tr.append(td); rows.append(tr);
    return;
  }
  try { computed = baseline ? compare(baseline, current) : summary(current); }
  catch (err) { computed = null; message(err.message); return; }
  const c = computed;
  text("comparison-mode", baseline ? "Comparison ready" : "Single snapshot");
  text("count-checked", c.checked_count); text("count-open", c.open_count);
  text("count-new", baseline ? c.findings.filter(f => f.kind === "new-exposure").length : "—");
  text("count-drift", baseline ? c.changes.length : "—");
  text("target", c.target);
  text("donut-value", c.checked_count ? Math.round(100 * c.open_count / c.checked_count) + "%" : "0%");
  text("legend-open", c.open_count); text("legend-other", c.checked_count - c.open_count);
  const pct = c.checked_count ? Math.round(100 * c.open_count / c.checked_count) : 0;
  $("donut").style.setProperty("--percent", pct + "%");
  $("donut").setAttribute("aria-label", c.open_count + " open of " + c.checked_count + " observed TCP ports.");
  const warn = $("warning-list"); clearNode(warn);
  for (const line of c.warnings) warn.append(el("div", "⚠ " + line, "warning"));
  const findings = $("findings"); clearNode(findings);
  if (!c.findings.length) findings.append(el("p", "No change findings in the compared ports. This does not prove the target is secure.", "no-changes"));
  for (const f of c.findings.slice(0, 80)) {
    const row = el("article", undefined, "finding" + (f.kind === "new-exposure" ? " alerting" : ""));
    row.append(el("div", f.port + "/tcp", "port-num"));
    const info = el("div");
    info.append(el("strong", f.title));
    info.append(el("small", [f.service, f.previous + " → " + f.current].join("  ·  ")));
    row.append(info); findings.append(row);
  }
  if (c.findings.length > 80) findings.append(el("p", "Additional findings available in JSON export.", "no-changes"));
  const rows = $("ports"); clearNode(rows);
  for (const p of c.latest_ports) {
    const row = el("tr");
    const port = el("td", p.port + "/tcp");
    const state = el("td"); state.append(el("span", p.state.toUpperCase(), "state " + p.state));
    const svc = el("td", p.service);
    const tls = el("td", p.tls_verified === null ? "—" : p.tls_verified ? "YES" : "NO");
    const latency = el("td", p.latency_ms == null ? "—" : p.latency_ms.toFixed(1) + " ms");
    row.append(port, state, svc, tls, latency); rows.append(row);
  }
}
for (const [input, type, label] of [["baseline", "baseline", "baseline-name"], ["current", "current", "current-name"]]) {
  $(input).addEventListener("change", async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const value = await readFile(file);
      if (type === "baseline") baseline = value; else current = value;
      filename(label, file.name); render();
    } catch (err) { message(err.message); }
  });
}
$("demo").addEventListener("click", async () => {
  try {
    const raw = await Promise.all(["./samples/before.json", "./samples/after.json"].map(async url => {
      const response = await fetch(url);
      if (!response.ok) throw Error("Cannot load sample. Start a local server: python -m http.server 8000 -d dashboard");
      return response.json();
    }));
    baseline = normalizeReport(raw[0]); current = normalizeReport(raw[1]);
    filename("baseline-name", "Fictional example / before");
    filename("current-name", "Fictional example / after");
    render();
  } catch(err) { message(err.message); }
});
$("reset").addEventListener("click", () => {
  current = baseline = computed = null;
  $("baseline").value = ""; $("current").value = "";
  filename("baseline-name", null); filename("current-name", null);
  render();
});
$("export").addEventListener("click", () => {
  if (!computed) return;
  const blob = new Blob([JSON.stringify({
    generated_at: new Date().toISOString(),
    generator: "PortDrift dashboard 0.4.0",
    note: "Observational network scan changes; not confirmed vulnerabilities.",
    ...computed
  }, null, 2)], {type: "application/json"});
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href; a.download = "exposure-" + safeFilename(computed.target) + ".json";
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
});
render();

/** CSV export deliberately uses only observed changes and warning metadata. */
$("export-csv").addEventListener("click", () => {
  if (!computed) return;
  const csv = changesToCsv(computed, { includeTarget: false });
  const blob = new Blob([csv], {type: "text/csv;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "portdrift-changes-" + safeFilename(computed.target) + ".csv";
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

// App shell only. Uploaded scan files live in memory and are never cached.
if ("serviceWorker" in navigator && window.isSecureContext) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js", {scope: "./"}).catch(() => {
      // The dashboard still works without installation / offline caching.
    });
  });
}
