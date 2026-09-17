"""Beginner-friendly OSINT RSS monitor.

This script fetches multiple RSS/Atom feeds, checks articles for keywords,
assigns a simple threat score, prints a short summary, and logs matches to a
file for later review.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen
import json
import logging
import threading
import os
import re
import xml.etree.ElementTree as ET


# These are example feeds a beginner can change without touching the logic.
RSS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
]


# More categories make it easier to group findings during triage.
KEYWORD_CATEGORIES = {
    "malware": ["malware", "trojan", "ransomware", "spyware", "botnet"],
    "phishing": ["phishing", "credential theft", "spoofed login", "smishing"],
    "vulnerabilities": ["cve", "zero-day", "vulnerability", "exploit", "patch"],
    "infrastructure": ["ddos", "outage", "service disruption", "cdn", "dns"],
    "data exposure": ["data leak", "breach", "database dump", "exposed bucket"],
    "extremism": ["extremist", "radicalization", "terror threat"],
}


# Different categories can raise different levels of concern.
CATEGORY_WEIGHTS = {
    "malware": 3,
    "phishing": 2,
    "vulnerabilities": 3,
    "infrastructure": 2,
    "data exposure": 4,
    "extremism": 5,
}


DEFAULT_LOG_FILE = Path("osint_results.log")
LOGGER = logging.getLogger(__name__)
WRITE_LOCK = threading.Lock()


@dataclass
class FeedItem:
    """A small container for normalized feed data."""

    title: str
    link: str
    summary: str
    source: str


@dataclass
class MatchResult:
    """Stores the article plus the keyword match details."""

    item: FeedItem
    matched_keywords: dict[str, list[str]]
    threat_score: int


def clean_text(value: str) -> str:
    """Collapse repeated whitespace so matching and output stay readable."""

    return re.sub(r"\s+", " ", value or "").strip()


def fetch_feed(url: str) -> list[FeedItem]:
    """Download and parse one RSS or Atom feed."""

    try:
        with urlopen(url, timeout=15) as response:
            final_url = response.geturl()
            if urlparse(final_url).scheme not in {"http", "https"}:
                LOGGER.warning("Skipped feed %s because it redirected to %s", url, final_url)
                return []
            raw_xml = response.read()
    except (URLError, OSError, TimeoutError) as error:
        LOGGER.warning("Could not fetch feed %s: %s", url, error)
        return []

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as error:
        LOGGER.warning("Could not parse feed %s: %s", url, error)
        return []

    return parse_feed_items(root, url)


def parse_feed_items(root: ET.Element, source: str) -> list[FeedItem]:
    """Normalize RSS <item> entries and Atom <entry> records."""

    items: list[FeedItem] = []

    # RSS feeds usually use <channel><item>.
    for item in root.findall(".//item"):
        items.append(
            FeedItem(
                title=clean_text(item.findtext("title", "")),
                link=clean_text(item.findtext("link", "")),
                summary=clean_text(
                    item.findtext("description", "") or item.findtext("summary", "")
                ),
                source=source,
            )
        )

    if items:
        return items

    # Atom feeds usually use namespaces and <entry>.
    for entry in root.findall(".//{*}entry"):
        link = extract_atom_link(entry)

        items.append(
            FeedItem(
                title=clean_text(entry.findtext("{*}title", "")),
                link=link,
                summary=clean_text(
                    entry.findtext("{*}summary", "") or entry.findtext("{*}content", "")
                ),
                source=source,
            )
        )

    return items


def extract_atom_link(entry: ET.Element) -> str:
    """Prefer the normal article link when an Atom entry has many links."""

    fallback_link = ""

    for link_element in entry.findall("{*}link"):
        href = clean_text(link_element.attrib.get("href", ""))
        rel = clean_text(link_element.attrib.get("rel", "")).lower()

        if not href:
            continue
        if rel in ("", "alternate"):
            return href
        if not fallback_link:
            fallback_link = href

    return fallback_link


def keyword_in_text(text: str, keyword: str) -> bool:
    """Match whole terms or full phrases to avoid substring false positives."""

    pattern = rf"(?<!\w){re.escape(keyword.lower())}(?!\w)"
    return re.search(pattern, text) is not None

def find_keyword_matches(text: str, categories: dict[str, list[str]]) -> dict[str, list[str]]:
    """Return every keyword found in the text, grouped by category."""

    lowered_text = text.lower()
    matches: dict[str, list[str]] = {}

    for category, keywords in categories.items():
        found_keywords = [keyword for keyword in keywords if keyword_in_text(lowered_text, keyword)]
        if found_keywords:
            matches[category] = found_keywords

    return matches


def calculate_threat_score(
    matched_keywords: dict[str, list[str]], weights: dict[str, int]
) -> int:
    """Add up category weights and matched keyword counts."""

    score = 0

    for category, keywords in matched_keywords.items():
        score += weights.get(category, 1)
        score += len(keywords)

    return score


def analyze_items(
    items: Iterable[FeedItem],
    categories: dict[str, list[str]],
    weights: dict[str, int],
) -> list[MatchResult]:
    """Inspect items and keep only articles that matched at least one keyword."""

    results: list[MatchResult] = []

    for item in items:
        search_text = f"{item.title} {item.summary}"
        matches = find_keyword_matches(search_text, categories)
        if matches:
            results.append(
                MatchResult(
                    item=item,
                    matched_keywords=matches,
                    threat_score=calculate_threat_score(matches, weights),
                )
            )

    return sorted(results, key=lambda result: result.threat_score, reverse=True)


def build_summary(results: Iterable[MatchResult]) -> str:
    """Create a short text summary for console output and logs."""

    results = list(results)
    if not results:
        return "No matching items found."

    category_totals: dict[str, int] = {}
    highest_score = 0

    for result in results:
        highest_score = max(highest_score, result.threat_score)
        for category in result.matched_keywords:
            category_totals[category] = category_totals.get(category, 0) + 1

    ordered_categories = ", ".join(
        f"{category}: {count}"
        for category, count in sorted(category_totals.items(), key=lambda item: item[1], reverse=True)
    )

    return (
        f"Matched {len(results)} item(s). "
        f"Highest threat score: {highest_score}. "
        f"Category counts: {ordered_categories}."
    )


def log_results(results: Iterable[MatchResult], log_file: Path = DEFAULT_LOG_FILE) -> None:
    """Append the latest findings to a JSON lines log file."""

    results = list(results)
    log_file = Path(log_file)
    timestamp = datetime.now(timezone.utc).isoformat()
    log_record = {
        "timestamp": timestamp,
        "summary": build_summary(results),
        "results": [
            {
                "title": result.item.title,
                "source": result.item.source,
                "link": result.item.link,
                "threat_score": result.threat_score,
                "matched_keywords": result.matched_keywords,
            }
            for result in results
        ],
    }

    log_file.parent.mkdir(parents=True, exist_ok=True)
    # Writing one full line with O_APPEND keeps each record together across runs.
    log_line = (json.dumps(log_record, ensure_ascii=False) + "\n").encode("utf-8")
    with WRITE_LOCK:
        file_descriptor = os.open(log_file, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644)
        try:
            os.write(file_descriptor, log_line)
        finally:
            os.close(file_descriptor)


def print_results(results: Iterable[MatchResult]) -> None:
    """Show a readable summary on screen."""

    results = list(results)
    print(build_summary(results))

    for result in results:
        matched_text = "; ".join(
            f"{category}: {', '.join(keywords)}"
            for category, keywords in result.matched_keywords.items()
        )
        print(f"\nTitle: {result.item.title}")
        print(f"Source: {result.item.source}")
        print(f"Threat score: {result.threat_score}")
        print(f"Matched: {matched_text}")
        print(f"Link: {result.item.link}")


def main() -> None:
    """Fetch all feeds, analyze items, print a summary, and log results."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    all_items: list[FeedItem] = []

    for feed_url in RSS_FEEDS:
        all_items.extend(fetch_feed(feed_url))

    results = analyze_items(all_items, KEYWORD_CATEGORIES, CATEGORY_WEIGHTS)
    print_results(results)
    log_results(results)


if __name__ == "__main__":
    main()
