import io
import json
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from osint_monitor import format_text_report, main, monitor_sources, read_source, scan_content


class ScanContentTests(unittest.TestCase):
    def test_scan_content_finds_case_insensitive_keyword_matches(self) -> None:
        result = scan_content(
            "report.txt",
            "Suspicious chatter\nPossible MALWARE delivery\nmalware reused\n",
            ["Malware", "chatter"],
        )

        self.assertEqual(result["source"], "report.txt")
        self.assertEqual(
            result["matches"],
            [
                {"keyword": "chatter", "line_number": 1, "line": "Suspicious chatter"},
                {
                    "keyword": "malware",
                    "line_number": 2,
                    "line": "Possible MALWARE delivery",
                },
                {"keyword": "malware", "line_number": 3, "line": "malware reused"},
            ],
        )


class MonitorSourcesTests(unittest.TestCase):
    def test_monitor_sources_reads_local_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir, "sample.txt")
            sample.write_text("alert keyword\nbenign\n", encoding="utf-8")

            results = monitor_sources(["keyword"], [str(sample)])

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["source"], str(sample))
        self.assertEqual(results[0]["matches"][0]["line_number"], 1)

    def test_format_text_report_handles_missing_files(self) -> None:
        results = monitor_sources(["threat"], ["/does/not/exist.txt"])
        report = format_text_report(results)

        self.assertIn("Source: /does/not/exist.txt", report)
        self.assertIn("Error:", report)

    @patch("osint_monitor.ValidatedHTTPSConnection")
    @patch("osint_monitor.socket.getaddrinfo")
    def test_read_source_fetches_public_remote_urls(
        self, mock_getaddrinfo, mock_connection_class
    ) -> None:
        mock_getaddrinfo.return_value = [
            (None, None, None, None, ("93.184.216.34", 443))
        ]
        mock_connection = mock_connection_class.return_value
        mock_response = mock_connection.getresponse.return_value
        mock_response.status = 200
        mock_response.read.return_value = b"remote keyword hit"

        content = read_source("https://example.com/feed", allow_remote=True)

        self.assertEqual(content, "remote keyword hit")
        mock_getaddrinfo.assert_called_once_with(
            "example.com", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
        mock_connection_class.assert_called_once()
        mock_connection.request.assert_called_once_with(
            "GET", "/feed", headers={"Host": "example.com"}
        )

    @patch("osint_monitor.ValidatedHTTPSConnection")
    @patch("osint_monitor.socket.getaddrinfo")
    def test_read_source_uses_first_public_remote_address(
        self, mock_getaddrinfo, mock_connection_class
    ) -> None:
        mock_getaddrinfo.return_value = [
            (None, None, None, None, ("127.0.0.1", 443)),
            (None, None, None, None, ("93.184.216.34", 443)),
        ]
        mock_connection = mock_connection_class.return_value
        mock_response = mock_connection.getresponse.return_value
        mock_response.status = 200
        mock_response.read.return_value = b"ok"

        content = read_source("https://example.com/feed", allow_remote=True)

        self.assertEqual(content, "ok")
        mock_connection_class.assert_called_once_with(
            "example.com",
            "93.184.216.34",
            port=443,
            timeout=10,
            context=mock_connection_class.call_args.kwargs["context"],
        )

    @patch("osint_monitor.socket.getaddrinfo")
    def test_monitor_sources_reports_remote_fetch_failures(self, mock_getaddrinfo) -> None:
        mock_getaddrinfo.return_value = [(None, None, None, None, ("127.0.0.1", 80))]

        results = monitor_sources(
            ["keyword"], ["http://localhost/internal"], allow_remote=True
        )

        self.assertEqual(results[0]["matches"], [])
        self.assertIn("Refusing to fetch non-public remote source", results[0]["error"])

    @patch("osint_monitor.ValidatedHTTPSConnection")
    @patch("osint_monitor.socket.getaddrinfo")
    def test_monitor_sources_reports_http_errors(
        self, mock_getaddrinfo, mock_connection_class
    ) -> None:
        mock_getaddrinfo.return_value = [
            (None, None, None, None, ("93.184.216.34", 443))
        ]
        mock_response = mock_connection_class.return_value.getresponse.return_value
        mock_response.status = 503

        results = monitor_sources(
            ["keyword"], ["https://example.com/feed"], allow_remote=True
        )

        self.assertEqual(results[0]["matches"], [])
        self.assertIn("Remote source returned HTTP 503", results[0]["error"])


class CliTests(unittest.TestCase):
    def test_main_emits_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir, "feed.txt")
            sample.write_text("indicator spotted\n", encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["-k", "indicator", "--json", str(sample)])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload[0]["matches"][0]["keyword"], "indicator")

    def test_main_returns_non_zero_when_any_source_fails(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["-k", "indicator", "--json", "/does/not/exist.txt"])

        self.assertEqual(exit_code, 1)
        payload = json.loads(stdout.getvalue())
        self.assertIn("error", payload[0])


if __name__ == "__main__":
    unittest.main()
