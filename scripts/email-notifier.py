#!/usr/bin/env python3

################################################################################
# Email Notification Service
#
# CLI over the shared delivery code in notifiers.py, which also backs the
# Slack and Discord notifiers and the notify-alerts.py fan-out. All message
# bodies are escaped there -- alert text comes from honeypot traffic and is
# attacker-controlled.
################################################################################

import argparse
import sys

from notifiers import EmailNotifier, NotificationError, Severity


def main() -> int:
    parser = argparse.ArgumentParser(description="Send honeypot notifications by email")
    parser.add_argument("--recipient", required=True, help="Recipient address")
    parser.add_argument("--alert", help="Send an alert with this title")
    parser.add_argument("--text", help="Body for --alert (defaults to the title)")
    parser.add_argument("--severity", default="info", choices=[s.value for s in Severity])
    parser.add_argument("--daily-report", action="store_true",
                        help="Email the last 24h of real statistics (requires Elasticsearch)")
    parser.add_argument("--high-risk-ip", metavar="IP,SCORE",
                        help="Send a high-risk IP alert, e.g. 203.0.113.10,95")

    args = parser.parse_args()
    notifier = EmailNotifier()
    severity = Severity.parse(args.severity)

    try:
        if args.alert:
            ok = notifier.send_alert(args.recipient, args.alert, args.text or args.alert, severity)
        elif args.daily_report:
            ok = _send_daily_report(notifier, args.recipient)
        elif args.high_risk_ip:
            ip, _, score = args.high_risk_ip.partition(",")
            ok = notifier.send_fields(args.recipient, "High risk IP detected", {
                "IP Address": ip,
                "Threat Level": "HIGH",
                "Confidence Score": f"{score or 'unknown'}/100",
                "Action Required": "Review and potentially block this IP",
            }, Severity.CRITICAL)
        else:
            parser.print_help()
            return 0
    except NotificationError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1

    print("✓ Sent" if ok else "✗ Delivery failed", file=sys.stderr if not ok else sys.stdout)
    return 0 if ok else 1


def _send_daily_report(notifier: EmailNotifier, recipient: str) -> bool:
    """Email the real last-24h summary.

    This used to email four hardcoded numbers (103 events, 192.168.1.1, ...)
    regardless of what the honeypots had actually seen, which is worse than
    sending nothing. It now queries Elasticsearch, and says so plainly when
    that isn't reachable instead of inventing a report.
    """
    try:
        from honeypot_stats import HoneypotStats
    except ImportError as exc:  # pragma: no cover - dependency issue, not logic
        print(f"✗ Cannot build a report: {exc}", file=sys.stderr)
        return False

    try:
        stats = HoneypotStats().summary("24h")
    except Exception as exc:
        print(f"✗ Could not query Elasticsearch for the report: {exc}", file=sys.stderr)
        return False

    top_ip = stats["top_ips"][0]["ip"] if stats["top_ips"] else "none recorded"
    return notifier.send_fields(recipient, "Honeypot daily report", {
        "Total Events": f"{stats['total_events']:,}",
        "Top Attacking IP": top_ip,
        "Credentials Captured": stats["credentials_captured"],
        "Failed Logins": stats["failed_logins"],
        "Top Country": stats["top_country"],
    }, Severity.INFO)


if __name__ == "__main__":
    sys.exit(main())
