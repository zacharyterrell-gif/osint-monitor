# osint-monitor

A basic OSINT keyword monitoring tool for intelligence analysis.

## Usage

Monitor one or more files or URLs for repeated keywords:

```bash
python osint_monitor.py -k malware -k phishing ./intel_feed.txt
```

Read from standard input:

```bash
cat ./intel_feed.txt | python osint_monitor.py -k malware -
```

Emit JSON for downstream tooling:

```bash
python osint_monitor.py -k malware --json ./intel_feed.txt
```

Remote URLs are supported only with an explicit opt-in, and local/private network targets are rejected:

```bash
python osint_monitor.py --allow-remote -k malware https://example.com/feed
```
