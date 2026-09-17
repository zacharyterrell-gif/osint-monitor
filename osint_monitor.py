from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import socket
import ssl
import sys
from pathlib import Path
from typing import Iterable
from urllib.error import URLError
from urllib.parse import urlparse

DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_REMOTE_BYTES = 1024 * 1024


class ValidatedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, server_hostname: str, resolved_ip: str, **kwargs) -> None:
        self._server_hostname = server_hostname
        super().__init__(host=resolved_ip, **kwargs)

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self.host, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self._server_hostname
        )


class ValidatedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, resolved_ip: str, **kwargs) -> None:
        super().__init__(host=resolved_ip, **kwargs)

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self.host, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


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


def _resolve_remote_target(source: str) -> tuple[str, int, str, str, str]:
    parsed = urlparse(source)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Unsupported URL source: {source}")

    port = parsed.port or DEFAULT_PORTS[parsed.scheme]
    try:
        address_info = socket.getaddrinfo(
            parsed.hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve remote source: {source}") from exc

    resolved_ip = None
    for entry in address_info:
        ip_address = ipaddress.ip_address(entry[4][0])
        if not ip_address.is_global:
            continue
        if resolved_ip is None:
            resolved_ip = entry[4][0]

    if resolved_ip is None:
        raise ValueError(f"Refusing to fetch non-public remote source: {source}")

    request_target = parsed.path or "/"
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"

    return parsed.scheme, port, parsed.hostname, resolved_ip, request_target


def _fetch_remote_source(source: str) -> str:
    scheme, port, hostname, resolved_ip, request_target = _resolve_remote_target(source)
    host_header = hostname
    if port != DEFAULT_PORTS[scheme]:
        host_header = f"{hostname}:{port}"

    if scheme == "https":
        connection = ValidatedHTTPSConnection(
            hostname,
            resolved_ip,
            port=port,
            timeout=10,
            context=ssl.create_default_context(),
        )
    else:
        connection = ValidatedHTTPConnection(hostname, resolved_ip, port=port, timeout=10)

    try:
        connection.request("GET", request_target, headers={"Host": host_header})
        response = connection.getresponse()
        if response.status >= 400:
            raise ValueError(f"Remote source returned HTTP {response.status}: {source}")
        chunks = []
        total_bytes = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_REMOTE_BYTES:
                raise ValueError(
                    f"Remote source exceeds {MAX_REMOTE_BYTES} bytes: {source}"
                )
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except OSError as exc:
        raise URLError(exc) from exc
    finally:
        connection.close()


def read_source(source: str, allow_remote: bool = False) -> str:
    if source == "-":
        return sys.stdin.read()

    if source.startswith(("http://", "https://")):
        if not allow_remote:
            raise ValueError(
                "Remote URL sources are disabled by default. Re-run with --allow-remote."
            )
        return _fetch_remote_source(source)

    return Path(source).read_text(encoding="utf-8")


def monitor_sources(
    keywords: Iterable[str], sources: Iterable[str], allow_remote: bool = False
) -> list[dict]:
    results = []

    for source in sources:
        try:
            content = read_source(source, allow_remote=allow_remote)
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
        description="Monitor local files or HTTP(S) URLs for OSINT keywords."
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
        "--allow-remote",
        action="store_true",
        help="Allow HTTP(S) URL sources after rejecting local or private network targets.",
    )
    parser.add_argument(
        "sources",
        nargs="+",
        help="File paths, HTTP(S) URLs, or '-' to read from standard input.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    results = monitor_sources(args.keywords, args.sources, allow_remote=args.allow_remote)
    has_error = any(result.get("error") for result in results)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(format_text_report(results))

    return 1 if has_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
