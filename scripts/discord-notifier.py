#!/usr/bin/env python3

################################################################################
# Discord Notification Service
#
# CLI over the shared delivery code in notifiers.py, which also backs the
# Slack and email notifiers and the notify-alerts.py fan-out.
################################################################################

import argparse
import sys

from notifiers import DiscordNotifier, NotificationError, Severity


def main() -> int:
    parser = argparse.ArgumentParser(description="Send honeypot notifications to Discord")
    parser.add_argument("--message", help="Send a plain text message")
    parser.add_argument("--alert", help="Send a formatted alert with this title")
    parser.add_argument("--text", help="Body for --alert (defaults to the title)")
    parser.add_argument("--severity", default="info", choices=[s.value for s in Severity])
    parser.add_argument("--high-risk-ip", metavar="IP,SCORE",
                        help="Send a high-risk IP alert, e.g. 203.0.113.10,95")
    parser.add_argument("--service-down", metavar="SERVICE", help="Send a service-down alert")
    parser.add_argument("--webhook", help="Discord webhook URL (default: $DISCORD_WEBHOOK_URL)")

    args = parser.parse_args()
    notifier = DiscordNotifier(args.webhook)
    severity = Severity.parse(args.severity)

    try:
        if args.message:
            ok = notifier.send_message(args.message)
        elif args.alert:
            ok = notifier.send_alert(args.alert, args.text or args.alert, severity)
        elif args.high_risk_ip:
            ip, _, score = args.high_risk_ip.partition(",")
            ok = notifier.send_fields("🔴 High risk IP detected", {
                "IP Address": ip,
                "Threat Level": "HIGH",
                "Confidence Score": f"{score or 'unknown'}/100",
                "Action Required": "Review and potentially block this IP",
            }, Severity.CRITICAL)
        elif args.service_down:
            ok = notifier.send_fields(f"⛔ Service down: {args.service_down}", {
                "Service": args.service_down,
                "Action": "Restart the service or investigate",
            }, Severity.CRITICAL)
        else:
            parser.print_help()
            return 0
    except NotificationError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1

    print("✓ Sent" if ok else "✗ Delivery failed", file=sys.stderr if not ok else sys.stdout)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
