#!/usr/bin/env python3
"""Simple Snort alert classifier for quick attack-pattern analysis.

Usage:
  python3 scripts/analyze_alerts.py --file /var/log/snort/alert
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

MSG_RE = re.compile(r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.+?)\s+\[\*\*\]")
CLASS_RE = re.compile(r"\[Classification:\s*(?P<class>.+?)\]")
PRIORITY_RE = re.compile(r"\[Priority:\s*(?P<prio>\d+)\]")
IP_RE = re.compile(r"(?P<src>\d+\.\d+\.\d+\.\d+):\d+\s*->\s*(?P<dst>\d+\.\d+\.\d+\.\d+):\d+")


def parse_alerts(content: str) -> dict[str, Counter]:
    counters = {
        "messages": Counter(),
        "classifications": Counter(),
        "priorities": Counter(),
        "sources": Counter(),
        "destinations": Counter(),
    }

    for line in content.splitlines():
        msg_match = MSG_RE.search(line)
        if msg_match:
            counters["messages"][msg_match.group("msg")] += 1

        cls_match = CLASS_RE.search(line)
        if cls_match:
            counters["classifications"][cls_match.group("class")] += 1

        prio_match = PRIORITY_RE.search(line)
        if prio_match:
            counters["priorities"][prio_match.group("prio")] += 1

        ip_match = IP_RE.search(line)
        if ip_match:
            counters["sources"][ip_match.group("src")] += 1
            counters["destinations"][ip_match.group("dst")] += 1

    return counters


def print_top(counter: Counter, title: str, limit: int = 10) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    if not counter:
        print("No entries found")
        return
    for key, value in counter.most_common(limit):
        print(f"{key}: {value}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze Snort alert file and summarize attack patterns")
    parser.add_argument("--file", required=True, help="Path to Snort alert file")
    args = parser.parse_args()

    alert_path = Path(args.file)
    if not alert_path.exists():
        raise SystemExit(f"Alert file not found: {alert_path}")

    counters = parse_alerts(alert_path.read_text(encoding="utf-8", errors="ignore"))

    print_top(counters["messages"], "Top alert messages")
    print_top(counters["classifications"], "Top classifications")
    print_top(counters["priorities"], "Priority distribution")
    print_top(counters["sources"], "Top source IPs")
    print_top(counters["destinations"], "Top destination IPs")


if __name__ == "__main__":
    main()
