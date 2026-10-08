"""Compare an authorized scan to a previously saved report.

Only matching TCP ports are compared. An unscanned port is never classified as
closed, preventing misleading 'closed' alerts on partial scans.
"""
from __future__ import annotations
import json
from pathlib import Path
from scanners.diagnostics import ScanReport

STATES = frozenset({"open", "closed", "timeout", "error"})


def read_baseline(path: Path) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot load baseline JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("Baseline must be a JSON object.")
    return value


def compare_reports(current: ScanReport, baseline: dict) -> dict:
    if not isinstance(baseline, dict) or baseline.get("target") != current.target:
        raise ValueError("Baseline target does not match the current target.")
    previous = baseline.get("results")
    if not isinstance(previous, list):
        raise ValueError("Baseline results must be a list.")
    previous_states = {}
    for item in previous:
        if not isinstance(item, dict):
            raise ValueError("Malformed baseline result.")
        port, state = item.get("port"), item.get("state")
        if type(port) is not int or not 1 <= port <= 65535 or state not in STATES:
            raise ValueError("Invalid port or state in baseline.")
        if port in previous_states:
            raise ValueError("Duplicate port in baseline.")
        previous_states[port] = state
    current_states = {r.port: r.state for r in current.results}
    shared = sorted(current_states.keys() & previous_states.keys())
    changes = [{"port": p, "previous": previous_states[p], "current": current_states[p]}
               for p in shared if previous_states[p] != current_states[p]]
    newly_open = [item["port"] for item in changes
                  if item["current"] == "open" and item["previous"] != "open"]
    no_longer_open = [item["port"] for item in changes
                      if item["previous"] == "open" and item["current"] != "open"]
    return {
        "target": current.target,
        "dns_changed": baseline.get("resolved_ip") != current.resolved_ip,
        "compared_ports": len(shared),
        "new_ports_not_in_baseline": sorted(current_states.keys() - previous_states.keys()),
        "baseline_ports_not_scanned": sorted(previous_states.keys() - current_states.keys()),
        "changes": changes,
        "newly_open": newly_open,
        "no_longer_open": no_longer_open,
        "scan_completed": current.completed,
    }
