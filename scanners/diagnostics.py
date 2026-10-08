"""Bounded TCP network diagnostics with explicit authorization and DNS pinning."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

FAST_PORTS = (21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 3389, 8080)
STANDARD_PORTS = tuple(sorted(set(FAST_PORTS + (
    20, 23, 69, 79, 111, 123, 135, 389, 465, 636, 873, 995, 1433, 1521,
    1883, 2049, 2375, 2376, 3000, 3306, 5432, 5672, 5900, 6379, 8000,
    8008, 8081, 8443, 8888, 9090, 9200, 11211, 27017,
))))
SERVICE_NAMES = {21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
                 110: 'POP3', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
                 445: 'SMB', 587: 'SMTP submission', 993: 'IMAPS',
                 3389: 'RDP', 8080: 'HTTP alternate', 8443: 'HTTPS alternate'}
_HOST_LABEL = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


@dataclass(frozen=True)
class PortResult:
    port: int
    state: str
    service: str
    latency_ms: float | None = None
    tls: dict | None = None
    error: str | None = None


@dataclass(frozen=True)
class ScanReport:
    target: str
    resolved_ip: str
    started_at: str
    duration_s: float
    completed: bool
    results: list[PortResult]

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_target(raw: str) -> str:
    """Accept one IP / DNS name / http(s) URL, never a CIDR or userinfo."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError('Enter a hostname or IP address.')
    raw = raw.strip()
    if '://' in raw:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in ('http', 'https') or parsed.username or parsed.password:
            raise ValueError('Only http(s) URLs without credentials are supported.')
        if not parsed.hostname:
            raise ValueError('URL must contain a hostname.')
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError('Invalid URL port.') from exc
        host = parsed.hostname
    else:
        host = raw[1:-1] if raw.startswith('[') and raw.endswith(']') else raw
    if any(x in host for x in ('/', '@', '%', '\\')) or any(c.isspace() for c in host):
        raise ValueError('Enter a single hostname or IP, not a subnet or path.')
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.rstrip('.').lower()
    if len(host) > 253 or not host or not all(_HOST_LABEL.fullmatch(s) for s in host.split('.')):
        raise ValueError('Invalid hostname.')
    return host


def resolve_target(host: str) -> str:
    """Resolve once; scan this numeric IP rather than repeating DNS lookups."""
    try:
        info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f'Unable to resolve host: {exc}') from exc
    if not info:
        raise ValueError('Host has no usable address.')
    return info[0][4][0]


def _tls_details(ip: str, hostname: str, port: int, timeout: float) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secured:
                cert = secured.getpeercert()
                return {
                    'verified': True,
                    'protocol': secured.version(),
                    'cipher': secured.cipher()[0] if secured.cipher() else None,
                    'expires': cert.get('notAfter'),
                    'subject': cert.get('subject'),
                    'issuer': cert.get('issuer'),
                }
    except (ssl.SSLError, OSError, ValueError) as exc:
        return {'verified': False, 'error': f'{type(exc).__name__}: {exc}'}


def _probe(ip: str, hostname: str, port: int, timeout: float, tls: bool) -> PortResult:
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            latency = round((time.monotonic() - start) * 1000, 1)
        detail = _tls_details(ip, hostname, port, timeout) if tls and port in (443, 8443) else None
        return PortResult(port, 'open', SERVICE_NAMES.get(port, 'unknown'), latency, detail)
    except socket.timeout:
        return PortResult(port, 'timeout', SERVICE_NAMES.get(port, 'unknown'))
    except ConnectionRefusedError:
        return PortResult(port, 'closed', SERVICE_NAMES.get(port, 'unknown'))
    except OSError as exc:
        return PortResult(port, 'error', SERVICE_NAMES.get(port, 'unknown'), error=str(exc))


def scan_ports(raw_target: str, ports=FAST_PORTS, *, timeout: float = 1.0,
               workers: int = 16, authorized: bool = False,
               cancel_event: threading.Event | None = None, progress=None,
               inspect_tls: bool = True) -> ScanReport:
    """Probe only explicitly authorized targets, with bounded concurrency."""
    if not authorized:
        raise PermissionError('Confirm you are authorized to scan the target.')
    if isinstance(timeout, bool) or not 0.1 <= timeout <= 10:
        raise ValueError('Timeout must be between 0.1 and 10 seconds.')
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 32:
        raise ValueError('Workers must be between 1 and 32.')
    ports = tuple(ports)
    if not ports or len(ports) > 128 or any(type(p) is not int or p < 1 or p > 65535 for p in ports):
        raise ValueError('Specify 1 to 128 valid TCP ports.')
    ports = tuple(sorted(set(ports)))
    hostname = normalize_target(raw_target)
    ip = resolve_target(hostname)
    cancel_event = cancel_event if cancel_event is not None else threading.Event()
    started = datetime.now(timezone.utc).isoformat()
    begin = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as pool:
        futures = {pool.submit(_probe, ip, hostname, p, timeout, inspect_tls): p for p in ports
                   if not cancel_event.is_set()}
        for future in as_completed(futures):
            results.append(future.result())
            if progress:
                progress(len(results), len(futures))
            if cancel_event.is_set():
                for pending in futures:
                    pending.cancel()
                break
    results.sort(key=lambda r: r.port)
    return ScanReport(hostname, ip, started, round(time.monotonic() - begin, 3),
                      not cancel_event.is_set(), results)
