import contextlib
import importlib.util
import io
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vpngate", SOURCE / "vpngate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class OptimalEntryTests(unittest.TestCase):
    def test_endpoint_formats_and_comments(self):
        text = "\ufeff# endpoints\n1.1.1.1#default port\nEXAMPLE.COM:8443#name\n[2606:4700::1111]:443\n"
        self.assertEqual(gate.parse_optimal_api_endpoints(text), [
            "1.1.1.1:443", "example.com:8443", "[2606:4700::1111]:443",
        ])

    def test_invalid_response_cannot_become_an_entry(self):
        for value in ("<html>403 Forbidden</html>", "error code: 1034", "1.1.1.1:0", "1.1.1.1:65536", "1.1.1.1:", "999.1.1.1", "user:secret@example.com:443", "2001:db8::1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.parse_optimal_api_endpoints(value)

    def test_entry_override_and_api_merge_preserve_order(self):
        with patch.dict(os.environ, {"HOSTS_ENTRY": "one.example:443,two.example:443"}), patch.object(gate, "OPTIMAL_API", "https://api.example/entries"), patch.object(gate, "fetch_optimal_api_endpoints", return_value=["two.example:443", "1.1.1.1:443"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.get_combined_edge_hosts(), ["one.example:443", "two.example:443", "1.1.1.1:443"])

    def test_disabled_api_does_not_make_a_request(self):
        with patch.object(gate.requests, "get") as get:
            self.assertEqual(gate.fetch_optimal_api_endpoints(""), [])
            get.assert_not_called()

    def test_configured_api_failure_is_reported_without_credentials(self):
        with patch.object(gate.requests, "get", return_value=SimpleNamespace(status_code=403, text="error code: 1034")), contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(RuntimeError, "HTTP 403") as error:
                gate.fetch_optimal_api_endpoints("https://user:secret@api.example/entries?token=private")
            self.assertNotIn("secret", str(error.exception) + output.getvalue())
            self.assertNotIn("private", str(error.exception) + output.getvalue())

    def test_empty_api_is_an_error(self):
        with patch.object(gate.requests, "get", return_value=SimpleNamespace(status_code=200, text="# empty\n")), contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, "没有返回有效入口"):
            gate.fetch_optimal_api_endpoints("https://api.example/entries")

    def test_failed_api_does_not_start_writing_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            public = Path(temp) / "public"
            with patch.object(gate, "PUBLIC_DIR", str(public)), patch.object(gate, "get_combined_edge_hosts", side_effect=RuntimeError("API failed")), self.assertRaises(RuntimeError):
                gate.write_outputs({})
            self.assertFalse(public.exists())

    def test_output_alias_preserves_existing_node_format(self):
        node = {"host": "vpn123456.opengw.net", "port": 443, "residential": "residential", "latency_ms": 50}
        data = {"generated_at": "2026-10-14 00:00:00 UTC", "stats": {}, "countries": {"Japan": {"code": "JP", "count": 1, "residential": 1, "datacenter": 0, "nodes": [node]}}}
        with tempfile.TemporaryDirectory() as temp, patch.object(gate, "PUBLIC_DIR", temp), patch.object(gate, "get_combined_edge_hosts", return_value=["one.example:443"]):
            paths = gate.write_outputs(data)
            hosts = (Path(temp) / "hosts.txt").read_text(encoding="utf-8")
            nodes = (Path(temp) / "nodes.txt").read_text(encoding="utf-8")
            self.assertEqual(len(paths), 5)
            self.assertEqual(nodes.splitlines(), [line for line in hosts.splitlines() if line and not line.startswith("#")])
            self.assertTrue(nodes.startswith("one.example:443#日本-住宅-01$sstp://"))
            self.assertTrue((Path(temp) / "chains.txt").exists())
            self.assertFalse((Path(temp) / "sub.txt").exists())


class WorkerFailureTests(unittest.TestCase):
    def test_http_failure_retains_cloudflare_error_code(self):
        session = Mock()
        session.get.return_value = SimpleNamespace(status_code=500, text="error code: 1101\n")
        result = gate.check_one({"host": "vpn123456.opengw.net", "port": 443}, session)
        self.assertTrue(result["worker_error"])
        self.assertEqual(result["error"], "HTTP 500 (error code: 1101)")

    def test_cloudflare_html_error_code_is_reported(self):
        session = Mock()
        session.get.return_value = SimpleNamespace(status_code=500, text='<span class="cf-error-code">1101</span>')
        result = gate.check_one({"host": "vpn123456.opengw.net", "port": 443}, session)
        self.assertEqual(result["error"], "HTTP 500 (error code: 1101)")

    def test_worker_outage_stops_publication_and_explains_failure(self):
        node = {"host": "vpn123456.opengw.net", "port": 443}
        failure = {**node, "worker_error": True, "error": "HTTP 500 (error code: 1101)"}
        with patch.object(gate, "fetch_vpngate", return_value=([{}], "test")), patch.object(gate, "to_sstp_nodes", return_value=[node]), patch.object(gate, "check_all", return_value=[failure]), patch.object(gate, "write_outputs") as write, contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as error:
                gate.main()
            self.assertEqual(error.exception.code, 1)
            self.assertIn("HTTP 500 (error code: 1101)", output.getvalue())
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
