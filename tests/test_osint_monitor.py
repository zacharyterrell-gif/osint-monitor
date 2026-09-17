import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from osint_monitor import format_text_report, main, monitor_sources, scan_content


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


if __name__ == "__main__":
    unittest.main()
