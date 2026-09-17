# osint-monitor

A basic OSINT keyword monitoring tool for intelligence analysis.

## Usage

Monitor one or more files or URLs for repeated keywords:

```bash
python osint_monitor.py -k malware -k phishing ./intel_feed.txt https://example.com/feed
```

Read from standard input:

```bash
cat ./intel_feed.txt | python osint_monitor.py -k malware -
```

Emit JSON for downstream tooling:

```bash
python osint_monitor.py -k malware --json ./intel_feed.txt
```
