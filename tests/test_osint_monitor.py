from pathlib import Path
import json
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET

from osint_monitor import (
    CATEGORY_WEIGHTS,
    FeedItem,
    KEYWORD_CATEGORIES,
    analyze_items,
    build_summary,
    find_keyword_matches,
    log_results,
    parse_feed_items,
)


class OsintMonitorTests(unittest.TestCase):
    def test_find_keyword_matches_groups_keywords_by_category(self):
        text = "A ransomware breach used credential theft techniques."

        matches = find_keyword_matches(text, KEYWORD_CATEGORIES)

        self.assertEqual(matches["malware"], ["ransomware"])
        self.assertEqual(matches["phishing"], ["credential theft"])
        self.assertEqual(matches["data exposure"], ["breach"])

    def test_parse_feed_items_reads_rss_items(self):
        xml_data = """
        <rss>
            <channel>
                <item>
                    <title>New zero-day found</title>
                    <link>https://example.com/1</link>
                    <description>Researchers published a new exploit.</description>
                </item>
            </channel>
        </rss>
        """

        items = parse_feed_items(ET.fromstring(xml_data), "https://example.com/feed")

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].title, "New zero-day found")
        self.assertEqual(items[0].link, "https://example.com/1")

    def test_parse_feed_items_prefers_atom_alternate_link(self):
        xml_data = """
        <feed xmlns="http://www.w3.org/2005/Atom">
            <entry>
                <title>Threat update</title>
                <link rel="self" href="https://example.com/feed-entry" />
                <link rel="alternate" href="https://example.com/article" />
                <summary>Possible breach activity.</summary>
            </entry>
        </feed>
        """

        items = parse_feed_items(ET.fromstring(xml_data), "https://example.com/atom")

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].link, "https://example.com/article")

    def test_analyze_items_sorts_highest_threat_score_first(self):
        items = [
            FeedItem(
                title="Zero-day exploit reported",
                link="https://example.com/a",
                summary="Researchers warn about a new CVE.",
                source="feed-a",
            ),
            FeedItem(
                title="General technology news",
                link="https://example.com/b",
                summary="A product update was released.",
                source="feed-b",
            ),
            FeedItem(
                title="Breach and ransomware campaign",
                link="https://example.com/c",
                summary="The breach involved spyware and credential theft.",
                source="feed-c",
            ),
        ]

        results = analyze_items(items, KEYWORD_CATEGORIES, CATEGORY_WEIGHTS)

        self.assertEqual(len(results), 2)
        self.assertGreaterEqual(results[0].threat_score, results[1].threat_score)
        self.assertEqual(results[0].item.source, "feed-c")

    def test_build_summary_reports_totals(self):
        results = analyze_items(
            [
                FeedItem(
                    title="DNS outage affects services",
                    link="https://example.com/d",
                    summary="The outage followed a DDoS attempt.",
                    source="feed-d",
                )
            ],
            KEYWORD_CATEGORIES,
            CATEGORY_WEIGHTS,
        )

        summary = build_summary(results)

        self.assertIn("Matched 1 item(s).", summary)
        self.assertIn("infrastructure: 1", summary)

    def test_find_keyword_matches_avoids_false_substring_hits(self):
        text = "Analysts receive new notes after the meeting."

        matches = find_keyword_matches(text, KEYWORD_CATEGORIES)

        self.assertEqual(matches, {})

    def test_log_results_writes_json_lines(self):
        results = analyze_items(
            [
                FeedItem(
                    title="Credential theft linked to breach",
                    link="https://example.com/e",
                    summary="Analysts are tracking phishing activity.",
                    source="feed-e",
                )
            ],
            KEYWORD_CATEGORIES,
            CATEGORY_WEIGHTS,
        )

        with tempfile.NamedTemporaryFile("r+", encoding="utf-8") as handle:
            log_results(results, log_file=Path(handle.name))
            log_results(results, log_file=Path(handle.name))
            handle.seek(0)
            log_records = [json.loads(line) for line in handle.readlines()]

        self.assertEqual(len(log_records), 2)
        self.assertEqual(log_records[0]["results"][0]["title"], "Credential theft linked to breach")
        self.assertEqual(log_records[1]["results"][0]["title"], "Credential theft linked to breach")
        self.assertIn("summary", log_records[0])

    def test_log_results_creates_parent_directory(self):
        results = analyze_items(
            [
                FeedItem(
                    title="DNS outage affects services",
                    link="https://example.com/f",
                    summary="A DDoS event caused an outage.",
                    source="feed-f",
                )
            ],
            KEYWORD_CATEGORIES,
            CATEGORY_WEIGHTS,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "logs" / "osint_results.log"
            log_results(results, log_file=log_file)

            self.assertTrue(log_file.exists())

    def test_log_results_keeps_concurrent_appends_as_json_lines(self):
        results = analyze_items(
            [
                FeedItem(
                    title="Zero-day phishing campaign",
                    link="https://example.com/g",
                    summary="Credential theft followed the exploit.",
                    source="feed-g",
                )
            ],
            KEYWORD_CATEGORIES,
            CATEGORY_WEIGHTS,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "osint_results.log"
            threads = [
                threading.Thread(target=log_results, args=(results, log_file))
                for _ in range(10)
            ]

            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            with log_file.open("r", encoding="utf-8") as handle:
                log_records = [json.loads(line) for line in handle.readlines()]

        self.assertEqual(len(log_records), 10)
        self.assertTrue(all(record["results"][0]["title"] == "Zero-day phishing campaign" for record in log_records))


if __name__ == "__main__":
    unittest.main()
