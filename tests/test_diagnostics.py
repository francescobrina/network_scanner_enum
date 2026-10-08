"""Network tests use loopback only; CI never scans public hosts."""
import json
import socket
import unittest
from unittest.mock import patch

from scanners.diagnostics import normalize_target, scan_ports
from cli import main


class TargetTests(unittest.TestCase):
    def test_hostname_and_url(self):
        self.assertEqual(normalize_target('  EXAMPLE.COM. '), 'example.com')
        self.assertEqual(normalize_target('https://example.com/path'), 'example.com')
        self.assertEqual(normalize_target('[::1]'), '::1')

    def test_reject_subnet_bad_url_and_injection(self):
        for target in ('127.0.0.0/8', 'ftp://example.com', 'http://u:p@example.com',
                       'localhost;rm -rf .', 'host name', ''):
            with self.subTest(target=target), self.assertRaises(ValueError):
                normalize_target(target)

    def test_requires_authorization(self):
        with self.assertRaises(PermissionError):
            scan_ports('127.0.0.1')

    def test_bounds(self):
        for kwargs in ({'workers': 0}, {'workers': 33}, {'timeout': 20},
                       {'ports': (0,)}, {'ports': range(1, 200)}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                scan_ports('127.0.0.1', authorized=True, **kwargs)

    def test_real_loopback_open_and_closed(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(('127.0.0.1', 0))
            server.listen(2)
            port = server.getsockname()[1]
            report = scan_ports('127.0.0.1', (port,), authorized=True, inspect_tls=False)
            self.assertEqual(report.results[0].state, 'open')
            self.assertTrue(report.completed)
            self.assertGreaterEqual(report.results[0].latency_ms, 0)
        report = scan_ports('127.0.0.1', (port,), authorized=True, inspect_tls=False)
        self.assertIn(report.results[0].state, ('closed', 'timeout'))

    def test_progress_sorted_and_unique(self):
        steps = []
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(2)
            port = server.getsockname()[1]
            report = scan_ports('127.0.0.1', (port, port), authorized=True,
                                progress=lambda done, total: steps.append((done, total)))
        self.assertEqual([r.port for r in report.results], [port])
        self.assertEqual(steps, [(1, 1)])

    def test_cli_requires_authorization(self):
        with self.assertRaises(SystemExit) as cm:
            main(['127.0.0.1'])
        self.assertEqual(cm.exception.code, 2)

    def test_dns_pinned_to_numeric_ip(self):
        with patch('scanners.diagnostics.resolve_target', return_value='127.0.0.1') as resolver:
            with patch('scanners.diagnostics._probe') as probe:
                from scanners.diagnostics import PortResult
                probe.return_value = PortResult(443, 'closed', 'HTTPS')
                result = scan_ports('https://example.com', (443,), authorized=True)
        resolver.assert_called_once_with('example.com')
        probe.assert_called_once_with('127.0.0.1', 'example.com', 443, 1.0, True)
        json.dumps(result.to_dict())


class ReportingTests(unittest.TestCase):
    def report(self, state='open', port=8080):
        from scanners.diagnostics import ScanReport, PortResult
        return ScanReport('localhost', '127.0.0.1', '2026-10-08T12:00:00+00:00',
                          0.1, True, [PortResult(port, state, 'unknown')])

    def test_baseline_detects_changes_without_false_closed(self):
        from reporting import compare_reports
        baseline = {'target': 'localhost', 'resolved_ip': '127.0.0.1',
                    'results': [{'port': 8080, 'state': 'closed'},
                                {'port': 2222, 'state': 'open'}]}
        diff = compare_reports(self.report(), baseline)
        self.assertEqual(diff['newly_open'], [8080])
        self.assertEqual(diff['baseline_ports_not_scanned'], [2222])
        self.assertNotIn(2222, diff['no_longer_open'])
        self.assertFalse(diff['dns_changed'])

    def test_baseline_rejects_invalid_input(self):
        from reporting import compare_reports
        for data in ({'target': 'wrong', 'results': []},
                     {'target': 'localhost', 'results': [None]},
                     {'target': 'localhost', 'results': [{'port': True, 'state': 'open'}]},
                     {'target': 'localhost', 'results': [{'port': 80, 'state': 'active'}]},
                     {'target': 'localhost', 'results': [
                          {'port': 80, 'state': 'open'}, {'port': 80, 'state': 'closed'}]}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                compare_reports(self.report(), data)

    def test_baseline_different_ip_warns(self):
        from reporting import compare_reports
        data = {'target': 'localhost', 'resolved_ip': '127.0.0.2', 'results': []}
        self.assertTrue(compare_reports(self.report(), data)['dns_changed'])

    def test_baseline_read_error(self):
        from reporting import read_baseline
        from pathlib import Path
        with self.assertRaises(ValueError):
            read_baseline(Path('/no-such-report-507d3c.json'))

    def test_cli_diff_is_exportable(self):
        from reporting import compare_reports
        result = compare_reports(self.report(), {'target': 'localhost',
            'resolved_ip': '127.0.0.1', 'results': []})
        self.assertEqual(result['compared_ports'], 0)
        json.dumps(result)


if __name__ == '__main__':
    unittest.main()
