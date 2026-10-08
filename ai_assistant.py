"""Opt-in, provider-neutral analysis of sanitized network scan metadata.

No target hostname, IP address, raw service banner, credentials or TLS subject
is sent to an AI endpoint. Requests are initiated only by user action in the GUI.
"""
from __future__ import annotations
import ipaddress
import json
from urllib import request
from urllib.parse import urlsplit
from scanners.diagnostics import ScanReport

_MAX_REPLY_BYTES = 128 * 1024
_TAILNET_RANGE = ipaddress.ip_network("100.64.0.0/10")


def chat_endpoint(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("Enter an OpenAI-compatible API base URL.")
    parsed = urlsplit(base_url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Use a valid http(s) API URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Credentials, query parameters and fragments are not supported.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid endpoint port.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid endpoint port.")
    if parsed.path.rstrip("/") not in ("", "/v1"):
        raise ValueError("API base must end in /v1 (or have no path).")
    if parsed.scheme == "http":
        name = parsed.hostname.lower()
        local = name in ("localhost", "127.0.0.1", "::1")
        try:
            local = local or ipaddress.ip_address(name) in _TAILNET_RANGE
        except ValueError:
            pass
        if not local:
            raise ValueError("For nonlocal endpoints, HTTPS is required.")
    root = base_url.strip().rstrip("/")
    if not parsed.path.rstrip("/"):
        root += "/v1"
    return root + "/chat/completions"


def sanitized_scan_metadata(report: ScanReport) -> dict:
    """Allowlisted diagnostic fields only, without the target or IP address."""
    return {
        "scan_complete": bool(report.completed),
        "total_ports": len(report.results),
        "ports": [{
            "port": int(item.port),
            "state": str(item.state)[:20],
            "service": str(item.service)[:32],
            "tls_verified": item.tls.get("verified") if item.tls is not None else None,
        } for item in report.results[:128]],
    }


def explain_scan(report: ScanReport, *, endpoint: str, model: str,
                 consent: bool, timeout: float = 25) -> str:
    if not consent:
        raise PermissionError("Explicit AI sharing consent is required.")
    if not isinstance(model, str) or not model.strip() or len(model) > 150:
        raise ValueError("Enter the name of a model loaded in LM Studio.")
    if not 2 <= timeout <= 60:
        raise ValueError("AI request timeout must be between 2 and 60 seconds.")
    url = chat_endpoint(endpoint)
    observations = sanitized_scan_metadata(report)
    payload = {
        "model": model.strip(),
        "temperature": 0.2,
        "max_tokens": 450,
        "messages": [
            {"role": "system", "content":
             "You explain authorized TCP diagnostics as a defensive networking assistant. "
             "Use only the supplied structured observations. TCP-open does not prove a "
             "vulnerability. If TLS verification fails, advise certificate checks but do "
             "not infer an exploit. A partial scan is inconclusive. Be concise, in Italian, "
             "and give up to five practical validation suggestions. No offensive procedures."},
            {"role": "user", "content":
             "Explain these sanitized scan observations. No hostnames or IPs were provided: "
             + json.dumps(observations, separators=(",", ":"))},
        ],
    }
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    try:
        with request.urlopen(req, timeout=timeout) as response:
            data = response.read(_MAX_REPLY_BYTES + 1)
    except OSError as exc:
        raise RuntimeError(f"AI endpoint unavailable: {exc}") from exc
    if len(data) > _MAX_REPLY_BYTES:
        raise ValueError("AI response is too large.")
    try:
        parsed = json.loads(data.decode("utf-8"))
        text = parsed["choices"][0]["message"]["content"]
    except (ValueError, UnicodeError, TypeError, KeyError, IndexError) as exc:
        raise ValueError("Unexpected OpenAI-compatible API response.") from exc
    if not isinstance(text, str) or not text.strip():
        raise ValueError("AI returned no readable response.")
    return text.strip()[:16000]
