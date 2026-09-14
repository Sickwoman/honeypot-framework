#!/usr/bin/env python3

################################################################################
# Analytics Report Generator
# Prints (or saves) a terminal-style summary of recent honeypot activity.
#
# The Elasticsearch aggregations live in honeypot_stats.py, shared with
# generate-reports.py and generate-pdf-report.py.
################################################################################

import argparse
import json
import sys
from datetime import datetime
from typing import Any, Dict, List

from honeypot_stats import HoneypotStats

WIDTH = 70


def _bar(value: int, maximum: int, width: int = 30) -> str:
    if maximum <= 0:
        return ""
    return "█" * max(0, round(value / maximum * width))


def render_text(stats: Dict[str, Any], days: int) -> str:
    """Build the whole report as a string.

    Returning text rather than printing means `--file` doesn't have to run
    every query a second time to capture stdout, which is what it used to do.
    """
    out: List[str] = []
    add = out.append

    add("=" * WIDTH)
    add("HONEYPOT ANALYTICS REPORT".center(WIDTH))
    add(f"{datetime.now():%Y-%m-%d %H:%M:%S}".center(WIDTH))
    add("=" * WIDTH)

    total = stats["total_events"]
    add(f"\nSUMMARY (last {days} day(s))")
    add(f"  Total events:         {total:,}")
    add(f"  Source addresses:     {stats['unique_source_ips']}")
    add(f"  Failed logins:        {stats['failed_logins']:,}")
    add(f"  Credentials captured: {stats['credentials_captured']:,}")

    add("\nTOP SOURCE ADDRESSES")
    if stats["top_ips"]:
        for index, entry in enumerate(stats["top_ips"], 1):
            add(f"  {index:2d}. {entry['ip']:<16s} {entry['count']:>6,} events")
    else:
        add("  (none recorded)")

    add("\nTARGETED SERVICES")
    if stats["service_breakdown"]:
        busiest = stats["service_breakdown"][0]["count"]
        for entry in stats["service_breakdown"]:
            add(f"  {entry['name']:<16s} {entry['count']:>6,} ({entry['percentage']:5.1f}%) {_bar(entry['count'], busiest)}")
    else:
        add("  (none recorded)")

    threat = stats["threat_intel"]
    add("\nTHREAT INTELLIGENCE")
    if threat.get("threat_levels"):
        for level, count in threat["threat_levels"].items():
            add(f"  {level:<10s} {count:>6,}")
        if threat.get("avg_confidence") is not None:
            add(f"  Mean confidence: {threat['avg_confidence']:.1f}/100")
    else:
        add("  (no enriched events)")

    add("\nHOURLY TREND (last 12 buckets)")
    timeline = stats["hourly_trend"][-12:]
    if timeline:
        peak = max(entry["count"] for entry in timeline) or 0
        for entry in timeline:
            stamp = str(entry["timestamp"] or "")
            hour = stamp.split("T")[1][:2] + ":00" if "T" in stamp else stamp
            add(f"  {hour:<6s} {entry['count']:>6,} {_bar(entry['count'], peak)}")
    else:
        add("  (no events)")

    add("\n" + "=" * WIDTH)
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarise recent honeypot activity")
    parser.add_argument("--days", type=int, default=1, help="How many days back to analyse")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--file", help="Write the report here instead of stdout")
    args = parser.parse_args()

    stats = HoneypotStats().summary(f"{args.days}d")
    document = (
        json.dumps({"generated_at": datetime.now().isoformat(), "period_days": args.days, **stats}, indent=2)
        if args.json else render_text(stats, args.days)
    )

    if args.file:
        with open(args.file, "w", encoding="utf-8") as handle:
            handle.write(document + "\n")
        print(f"✓ Wrote {args.file}")
    else:
        print(document)
    return 0


if __name__ == "__main__":
    sys.exit(main())
