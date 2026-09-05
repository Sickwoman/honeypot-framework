#!/usr/bin/env python3
"""Generate synthetic honeytokens or scan JSON events for tripwire use."""

import argparse
import json
import sys

from threatintel.honeytokens import (
    build_trigger_alert,
    find_triggered_tokens,
    generate_manifest,
    load_manifest,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage synthetic honeypot honeytokens")
    parser.add_argument("--generate", action="store_true", help="Generate a honeytoken manifest")
    parser.add_argument("--count", type=int, default=3, help="Number of tokens to generate")
    parser.add_argument("--manifest", help="Manifest path for event scanning")
    parser.add_argument("--event", help="JSON event to scan; stdin is used when omitted")
    args = parser.parse_args()

    if args.generate:
        print(json.dumps(generate_manifest(args.count), indent=2))
        return 0
    if not args.manifest:
        parser.error("--manifest is required unless --generate is used")

    raw_event = args.event or sys.stdin.read()
    try:
        event = json.loads(raw_event)
        manifest = load_manifest(args.manifest)
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        print(f"tripwire error: {exc}", file=sys.stderr)
        return 2
    alert = build_trigger_alert(event, find_triggered_tokens(event, manifest))
    print(json.dumps(alert) if alert else "No honeytoken triggered")
    return 1 if alert else 0


if __name__ == "__main__":
    sys.exit(main())