import unittest
import xml.etree.ElementTree as ET

from osint_monitor import (
    CATEGORY_WEIGHTS,
    FeedItem,
    KEYWORD_CATEGORIES,
    analyze_items,
    build_summary,
    find_keyword_matches,
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


if __name__ == "__main__":
    unittest.main()
