#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Alert fan-out and threshold monitoring
#
# Sends one alert to every configured channel, and (in `monitor` mode) raises
# alerts when recent honeypot activity crosses a threshold. Delivery itself
# lives in notifiers.py, shared with the per-channel CLIs.
#
#   notify-alerts.py monitor                      # check thresholds, alert if tripped
#   notify-alerts.py send "Title" "Message"       # send to every configured channel
#   notify-alerts.py channels                     # list what is configured
################################################################################

import argparse
import logging
import sys

import es_client
from honeypot_stats import HoneypotStats
from notifiers import Severity, configured_channels, notify_all

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Thresholds that trip an alert. Tuned for a lab honeypot; raise them once the
# sensor is on a public address, where background scanning is constant.
ATTACK_VOLUME_WINDOW = "5m"
ATTACK_VOLUME_THRESHOLD = 100
MALWARE_WINDOW = "1h"


class AlertTypes:
    HIGH_ATTACK_VOLUME = "High attack volume detected"
    MALWARE_DETECTED = "Malware download attempt"
    BRUTE_FORCE = "Brute force attack detected"
    PORT_SCAN = "Port scan detected"
    CREDENTIAL_CAPTURE = "Credentials captured"
    SERVICE_DOWN = "Service down"


def _report(title: str, results: dict) -> bool:
    """Log per-channel delivery and return whether anything got through."""
    if not results:
        logger.warning("No channel configured -- '%s' was not delivered", title)
        return False
    for channel, delivered in results.items():
        logger.info("%s -> %s", channel, "sent" if delivered else "FAILED")
    return any(results.values())


def monitor_and_alert() -> int:
    """Check recent activity against the thresholds and alert on what trips."""
    stats = HoneypotStats()
    tripped = False

    volume = stats.total_events(ATTACK_VOLUME_WINDOW)
    if volume > ATTACK_VOLUME_THRESHOLD:
        tripped = True
        _report(AlertTypes.HIGH_ATTACK_VOLUME, notify_all(
            AlertTypes.HIGH_ATTACK_VOLUME,
            f"{volume} events in the last {ATTACK_VOLUME_WINDOW} "
            f"(threshold {ATTACK_VOLUME_THRESHOLD})",
            Severity.CRITICAL,
        ))

    malware = stats.download_attempts(MALWARE_WINDOW)
    if malware > 0:
        tripped = True
        _report(AlertTypes.MALWARE_DETECTED, notify_all(
            AlertTypes.MALWARE_DETECTED,
            f"{malware} download attempts in the last {MALWARE_WINDOW}",
            Severity.CRITICAL,
        ))

    if not tripped:
        logger.info("No thresholds tripped (%s events in the last %s)", volume, ATTACK_VOLUME_WINDOW)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Honeypot alert fan-out")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("monitor", help="Check activity thresholds and alert if tripped")
    sub.add_parser("channels", help="List the notification channels that are configured")

    send = sub.add_parser("send", help="Send one alert to every configured channel")
    send.add_argument("title")
    send.add_argument("message")
    send.add_argument("--severity", default="info", choices=[s.value for s in Severity])

    args = parser.parse_args()

    if args.command == "monitor":
        try:
            return monitor_and_alert()
        except es_client.ElasticsearchConfigError as exc:
            logger.error("%s", exc)
            return 1
    if args.command == "channels":
        channels = configured_channels()
        print("Configured channels:", ", ".join(channels) if channels else "none")
        return 0 if channels else 1
    if args.command == "send":
        delivered = _report(args.title, notify_all(args.title, args.message, Severity.parse(args.severity)))
        return 0 if delivered else 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
