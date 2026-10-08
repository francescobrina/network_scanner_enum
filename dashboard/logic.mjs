// Offline-only, portable and testable exposure-drift comparison logic.
// All comparison results represent observations, never verified vulnerabilities.
export function normalizeReport(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Report must be a JSON object.");
  if (typeof value.target !== "string" || !value.target.trim() || value.target.length > 255)
    throw new Error("Missing or invalid report target.");
  if (!Array.isArray(value.results) || value.results.length > 65535)
    throw new Error("Invalid report results.");
  const results = [];
  const seen = new Set();
  for (const item of value.results) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("Invalid port entry.");
    const port = item.port;
    if (!Number.isInteger(port) || port < 1 || port > 65535 || seen.has(port)) throw new Error("Invalid or duplicate port.");
    if (!["open", "closed", "timeout", "error", "filtered"].includes(item.state)) throw new Error("Invalid TCP state.");
    seen.add(port);
    results.push({
      port, state: item.state,
      service: typeof item.service === "string" ? item.service.slice(0, 80) : "unknown",
      latency_ms: typeof item.latency_ms === "number" && Number.isFinite(item.latency_ms) ? item.latency_ms : null,
      tls_verified: typeof item.tls?.verified === "boolean" ? item.tls.verified : null
    });
  }
  return {
    target: value.target.trim(),
    resolved_ip: typeof value.resolved_ip === "string" ? value.resolved_ip.slice(0, 128) : "",
    started_at: typeof value.started_at === "string" ? value.started_at.slice(0, 50) : "",
    duration_s: typeof value.duration_s === "number" && Number.isFinite(value.duration_s) ? value.duration_s : null,
    completed: value.completed !== false,
    results: results.sort((a, b) => a.port - b.port)
  };
}
export function compare(baseline, latest) {
  const a = normalizeReport(baseline), b = normalizeReport(latest);
  if (a.target !== b.target) throw new Error("Targets differ. Choose snapshots for the same hostname/IP.");
  const old = new Map(a.results.map(p => [p.port, p]));
  const now = new Map(b.results.map(p => [p.port, p]));
  const changes = [], unscanned = [], newlyScanned = [];
  for (const p of b.results) {
    const previous = old.get(p.port);
    if (!previous) { newlyScanned.push(p.port); continue; }
    if (previous.state !== p.state || previous.tls_verified !== p.tls_verified) {
      changes.push({
        port: p.port, service: p.service,
        previous: previous.state, current: p.state,
        previous_tls: previous.tls_verified, current_tls: p.tls_verified,
        kind: p.state === "open" && previous.state !== "open" ? "new-exposure" :
              previous.state === "open" && p.state !== "open" ? "no-longer-open" :
              p.tls_verified === false && previous.tls_verified === true ? "tls-warning" : "state-change"
      });
    }
  }
  for (const p of a.results) if (!now.has(p.port)) unscanned.push(p.port);
  const open = b.results.filter(p => p.state === "open");
  const findings = [];
  for (const c of changes) {
    const title = c.kind === "new-exposure" ? "Newly open TCP port" :
                  c.kind === "no-longer-open" ? "Previously open TCP port changed state" :
                  c.kind === "tls-warning" ? "TLS validation changed to unverified" : "Observed state changed";
    findings.push({...c, title});
  }
  for (const p of open.filter(p => p.tls_verified === false)) {
    if (!findings.some(f => f.port === p.port && f.kind === "tls-warning")) {
      findings.push({port: p.port, service: p.service, kind: "tls-warning",
                     title: "TLS certificate verification was unsuccessful", previous: "—", current: "open"});
    }
  }
  const warnings = [];
  if (a.resolved_ip && b.resolved_ip && a.resolved_ip !== b.resolved_ip)
    warnings.push("DNS resolution changed: snapshots may refer to different hosts.");
  if (!a.completed || !b.completed)
    warnings.push("A snapshot is incomplete. Absence of a port result is NOT evidence of closure.");
  if (unscanned.length || newlyScanned.length)
    warnings.push("Port coverage differs between snapshots; compare only commonly scanned ports.");
  return {
    target: b.target, previous: a.started_at, latest: b.started_at,
    resolved_ip: b.resolved_ip, open_count: open.length, checked_count: b.results.length,
    comparable_count: b.results.filter(p => old.has(p.port)).length,
    changes, findings, unscanned, newlyScanned, warnings,
    latest_ports: b.results, complete: a.completed && b.completed
  };
}
export function summary(report) {
  const r = normalizeReport(report);
  const open = r.results.filter(p => p.state === "open");
  return {target: r.target, checked_count: r.results.length,
          open_count: open.length, latest_ports: r.results,
          findings: open.filter(p => p.tls_verified === false).map(p => ({
            port: p.port, service: p.service, kind: "tls-warning",
            title: "TLS certificate verification was unsuccessful", previous: "—", current: "open"
          })), changes: [], comparable_count: 0, unscanned: [], newlyScanned: [], warnings: [
            "Load a baseline report to distinguish new exposures from existing ports.",
            ...(!r.completed ? ["Snapshot is incomplete."] : [])
          ], complete: r.completed, resolved_ip: r.resolved_ip, previous: "",
          latest: r.started_at
  };
}
export function safeFilename(name) {
  return (name || "report").replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 50);
}
