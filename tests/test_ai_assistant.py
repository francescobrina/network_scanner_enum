"""AI tests are offline: mock the API and inspect the exact outbound payload."""
import json
import unittest
from unittest.mock import patch
from ai_assistant import chat_endpoint, explain_scan, sanitized_scan_metadata
from scanners.diagnostics import PortResult, ScanReport


def fixture():
    return ScanReport("secret.example.internal", "192.168.50.100",
                      "2026-10-08T15:00:00+00:00", 0.5, True, [
                          PortResult(443, "open", "HTTPS", tls={
                              "verified": True, "subject": "confidential-company"}),
                          PortResult(22, "closed", "SSH"),
                      ])


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size):
        return self.payload[:size]


class AssistantTests(unittest.TestCase):
    def test_sanitization(self):
        d = sanitized_scan_metadata(fixture())
        wire = json.dumps(d)
        for secret in ("secret.example.internal", "192.168.50.100",
                       "confidential-company"):
            self.assertNotIn(secret, wire)
        self.assertIn("443", wire)
        self.assertEqual(d["total_ports"], 2)

    def test_endpoint_rules(self):
        self.assertEqual(chat_endpoint("http://127.0.0.1:1234/v1"),
                         "http://127.0.0.1:1234/v1/chat/completions")
        self.assertEqual(chat_endpoint("http://100.104.53.3:1234/v1"),
                         "http://100.104.53.3:1234/v1/chat/completions")
        self.assertEqual(chat_endpoint("https://example.com"),
                         "https://example.com/v1/chat/completions")
        for url in ("http://example.com/v1", "ftp://localhost:1234/v1",
                    "https://u:p@example.com/v1", "https://example.com/v1?key=secret",
                    "https://example.com/api", "http://127.0.0.1:99999"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                chat_endpoint(url)

    def test_consent_required(self):
        with self.assertRaises(PermissionError):
            explain_scan(fixture(), endpoint="http://localhost:1234/v1",
                         model="any", consent=False)

    def test_api_request_contains_only_allowlisted_data(self):
        captured = []
        def fake_urlopen(req, timeout):
            captured.append(req)
            return FakeResponse(json.dumps({"choices": [{"message": {
                "content": "Solo due porte: verifica la configurazione."}}]}).encode())
        with patch("ai_assistant.request.urlopen", side_effect=fake_urlopen):
            result = explain_scan(fixture(), endpoint="http://localhost:1234/v1",
                                  model="local-test-model", consent=True)
        self.assertIn("verifica", result)
        sent = captured[0].data.decode()
        self.assertIn("local-test-model", sent)
        self.assertNotIn("192.168.50.100", sent)
        self.assertNotIn("secret.example.internal", sent)
        self.assertNotIn("confidential-company", sent)

    def test_invalid_response_is_reported(self):
        with patch("ai_assistant.request.urlopen",
                   return_value=FakeResponse(b'{"choices":[]}')):
            with self.assertRaises(ValueError):
                explain_scan(fixture(), endpoint="http://localhost:1234",
                             model="test", consent=True)


if __name__ == "__main__":
    unittest.main()
