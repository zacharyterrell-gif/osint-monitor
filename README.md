# osint-monitor

A basic OSINT keyword monitoring tool for intelligence analysis.

## What it does

This beginner-friendly script:

- checks multiple RSS feeds
- looks for keywords across several threat categories
- assigns a simple threat score
- prints a summary to the console
- logs results to a local file

## Files

- `osint_monitor.py` - main monitoring script
- `tests/test_osint_monitor.py` - basic unit tests
- `osint_results.log` - created automatically after the script runs

## How to run

```bash
python osint_monitor.py
```

## How to test

```bash
python -m unittest discover -s tests
```

## Beginner notes

- Edit `RSS_FEEDS` in `osint_monitor.py` to monitor different sources.
- Edit `KEYWORD_CATEGORIES` to add or remove tracking terms.
- Edit `CATEGORY_WEIGHTS` to change how threat scores are calculated.
