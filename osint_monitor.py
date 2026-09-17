from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable
from urllib.error import URLError
from urllib.request import urlopen


def scan_content(source: str, content: str, keywords: Iterable[str]) -> dict:
    normalized_keywords = [keyword.casefold() for keyword in keywords if keyword.strip()]
    matches = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        lowered_line = line.casefold()
        for keyword in normalized_keywords:
            if keyword in lowered_line:
                matches.append(
                    {
                        "keyword": keyword,
                        "line_number": line_number,
                        "line": line,
                    }
                )

    return {"source": source, "matches": matches}


def read_source(source: str) -> str:
    if source == "-":
        return sys.stdin.read()

    if source.startswith(("http://", "https://")):
        with urlopen(source, timeout=10) as response:
            return response.read().decode("utf-8", errors="replace")

    return Path(source).read_text(encoding="utf-8")


def monitor_sources(keywords: Iterable[str], sources: Iterable[str]) -> list[dict]:
    results = []

    for source in sources:
        try:
            content = read_source(source)
        except (OSError, URLError, ValueError) as exc:
            results.append({"source": source, "matches": [], "error": str(exc)})
            continue

        results.append(scan_content(source, content, keywords))

    return results


def format_text_report(results: Iterable[dict]) -> str:
    sections = []

    for result in results:
        header = f"Source: {result['source']}"
        if result.get("error"):
            sections.append(f"{header}\n  Error: {result['error']}")
            continue

        if not result["matches"]:
            sections.append(f"{header}\n  No keyword matches found.")
            continue

        match_lines = [
            f"  - {match['keyword']} (line {match['line_number']}): {match['line']}"
            for match in result["matches"]
        ]
        sections.append("\n".join([header, *match_lines]))

    return "\n\n".join(sections)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Monitor local files or URLs for OSINT keywords."
    )
    parser.add_argument(
        "-k",
        "--keyword",
        action="append",
        dest="keywords",
        required=True,
        help="Keyword to monitor. Repeat for multiple keywords.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a text report.",
    )
    parser.add_argument(
        "sources",
        nargs="+",
        help="File paths, URLs, or '-' to read from standard input.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    results = monitor_sources(args.keywords, args.sources)
    has_error = any(result.get("error") for result in results)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(format_text_report(results))

    return 1 if has_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
