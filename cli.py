"""Headless command-line entry point for Network Scanner Enumerator."""
import argparse
import json
from pathlib import Path
import sys

from scanners.diagnostics import FAST_PORTS, STANDARD_PORTS, scan_ports
from reporting import compare_reports, read_baseline


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Bounded authorized TCP diagnostics')
    parser.add_argument('target', help='Single IPv4/IPv6 address, hostname, or http(s) URL')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--standard', action='store_true', help='Extended common ports')
    group.add_argument('--ports', help='Comma-separated TCP port numbers (max 128)')
    parser.add_argument('--timeout', type=float, default=1.0)
    parser.add_argument('--workers', type=int, default=16)
    parser.add_argument('--no-tls', action='store_true', help='Skip TLS certificate validation')
    parser.add_argument('--json', dest='json_path', type=Path, help='Save a JSON report')
    parser.add_argument('--baseline', type=Path, help='Compare to a previous JSON report of this target')
    parser.add_argument('--authorized', action='store_true', help='Confirm scan authorization')
    args = parser.parse_args(argv)
    if not args.authorized:
        parser.error('--authorized is required: scan only systems you may test.')
    try:
        ports = ([int(part.strip()) for part in args.ports.split(',')]
                 if args.ports is not None else STANDARD_PORTS if args.standard else FAST_PORTS)
        report = scan_ports(args.target, ports, timeout=args.timeout, workers=args.workers,
                            authorized=True, inspect_tls=not args.no_tls)
        print(f'{report.target} ({report.resolved_ip}) - {len(report.results)} ports')
        for result in report.results:
            print(f'{result.port:5d}/tcp {result.state:8s} {result.service}')
            if result.tls is not None:
                print(f'           TLS: {json.dumps(result.tls, ensure_ascii=False)}')
        if args.baseline:
            changes = compare_reports(report, read_baseline(args.baseline))
            print(f'Baseline comparison: {changes["compared_ports"]} common ports; '
                  f'{len(changes["changes"])} state changes')
            for change in changes['changes']:
                print(f'  {change["port"]}/tcp {change["previous"]} -> {change["current"]}')
            if changes['dns_changed']:
                print('WARNING: target resolved to a different IP from baseline.')
            if not changes['scan_completed']:
                print('WARNING: scan was interrupted; this comparison is incomplete.')
        if args.json_path:
            args.json_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
                                      encoding='utf-8')
            print(f'JSON report: {args.json_path}')
        return 0
    except (ValueError, PermissionError, OSError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
