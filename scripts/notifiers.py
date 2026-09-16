#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Shared notification delivery
#
# slack-notifier.py, discord-notifier.py, email-notifier.py and
# notify-alerts.py each had their own copy of: read the webhook URL from the
# environment, map a severity to a colour, build a payload, POST it, and decide
# whether it worked. The copies had drifted in ways that mattered:
#
#   * notify-alerts.py escaped alert text before putting it in an HTML email;
#     email-notifier.py interpolated it raw. Alert text contains attacker-
#     controlled honeypot data (usernames, commands, requested paths), so the
#     unescaped copy let an attacker inject markup into the operator's inbox.
#   * None of the standalone notifiers passed a timeout to requests.post, so a
#     hung webhook endpoint would hang the notifier -- and these run from cron.
#
# Delivery lives here once. The scripts above are now thin CLIs over it.
################################################################################

import html
import logging
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# A webhook that never answers must not wedge a cron job forever.
WEBHOOK_TIMEOUT_SECONDS = 10


class NotificationError(RuntimeError):
    """Raised when a notifier is asked to send without being configured."""


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def hex_color(self) -> str:
        """Slack/email use a hex string."""
        return {"info": "#36a64f", "warning": "#ff9900", "critical": "#ff0000"}[self.value]

    @property
    def int_color(self) -> int:
        """Discord embeds use an integer."""
        return {"info": 3066993, "warning": 16744192, "critical": 16711680}[self.value]

    @property
    def emoji(self) -> str:
        return {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}[self.value]

    @classmethod
    def parse(cls, value) -> "Severity":
        """Accept a Severity, or any casing of its name; unknown -> INFO."""
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).lower())
        except ValueError:
            return cls.INFO


def post_webhook(url: str, payload: Dict[str, Any]) -> bool:
    """POST a JSON payload to a webhook. Logs and returns False on failure."""
    try:
        response = requests.post(url, json=payload, timeout=WEBHOOK_TIMEOUT_SECONDS)
    except requests.RequestException:
        logger.exception("Webhook request failed")
        return False

    if not response.ok:
        logger.error("Webhook returned HTTP %s: %s", response.status_code, response.text[:200])
        return False
    return True


class SlackNotifier:
    """Slack incoming webhook."""

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    def _post(self, payload: Dict[str, Any]) -> bool:
        if not self.configured:
            raise NotificationError("SLACK_WEBHOOK_URL is not set")
        return post_webhook(self.webhook_url, payload)

    def send_message(self, text: str) -> bool:
        return self._post({"text": text})

    def send_alert(self, title: str, message: str, severity=Severity.INFO) -> bool:
        severity = Severity.parse(severity)
        return self._post({"attachments": [{
            "fallback": title,
            "color": severity.hex_color,
            "title": f"{severity.emoji} {title}",
            "text": message,
            "ts": int(datetime.now().timestamp()),
        }]})

    def send_fields(self, title: str, fields: Dict[str, Any], severity=Severity.INFO) -> bool:
        """A titled card of label/value pairs (reports, IP detail, service state)."""
        severity = Severity.parse(severity)
        return self._post({"attachments": [{
            "fallback": title,
            "color": severity.hex_color,
            "title": title,
            "fields": [{"title": k, "value": str(v), "short": True} for k, v in fields.items()],
            "ts": int(datetime.now().timestamp()),
        }]})


class DiscordNotifier:
    """Discord webhook."""

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.getenv("DISCORD_WEBHOOK_URL")

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    def _post(self, payload: Dict[str, Any]) -> bool:
        if not self.configured:
            raise NotificationError("DISCORD_WEBHOOK_URL is not set")
        return post_webhook(self.webhook_url, payload)

    def send_message(self, content: str) -> bool:
        return self._post({"content": content})

    def send_alert(self, title: str, message: str, severity=Severity.INFO) -> bool:
        severity = Severity.parse(severity)
        return self._post({"embeds": [{
            "title": f"{severity.emoji} {title}",
            "description": message,
            "color": severity.int_color,
            "timestamp": datetime.now().isoformat(),
        }]})

    def send_fields(self, title: str, fields: Dict[str, Any], severity=Severity.INFO) -> bool:
        severity = Severity.parse(severity)
        return self._post({"embeds": [{
            "title": title,
            "color": severity.int_color,
            "fields": [{"name": k, "value": str(v), "inline": True} for k, v in fields.items()],
            "timestamp": datetime.now().isoformat(),
        }]})


class EmailNotifier:
    """SMTP email with an HTML body.

    Every caller-supplied value is escaped before it reaches the markup:
    alert text originates from honeypot traffic, so it is attacker-controlled.
    """

    def __init__(self, smtp_server=None, smtp_port=None, sender=None, password=None):
        self.smtp_server = smtp_server or os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(smtp_port or os.getenv("SMTP_PORT", "587"))
        self.sender = sender or os.getenv("EMAIL_SENDER")
        self.password = password or os.getenv("EMAIL_PASSWORD")

    @property
    def configured(self) -> bool:
        return bool(self.sender and self.password)

    def send_html(self, recipient: str, subject: str, html_body: str) -> bool:
        """Send pre-built HTML. The caller is responsible for escaping it."""
        if not self.configured:
            raise NotificationError("EMAIL_SENDER and EMAIL_PASSWORD must be set")

        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = self.sender
        message["To"] = recipient
        message.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30) as server:
                server.starttls()
                server.login(self.sender, self.password)
                server.send_message(message)
        except (smtplib.SMTPException, OSError):
            logger.exception("Sending mail to %s failed", recipient)
            return False
        return True

    def send_alert(self, recipient: str, title: str, message: str, severity=Severity.INFO) -> bool:
        severity = Severity.parse(severity)
        body = _alert_html(title, message, severity)
        return self.send_html(recipient, f"{severity.emoji} {html.escape(title)}", body)

    def send_fields(self, recipient: str, title: str, fields: Dict[str, Any], severity=Severity.INFO) -> bool:
        severity = Severity.parse(severity)
        rows = "".join(
            f"<tr><td style='padding:8px;border-bottom:1px solid #eee'>{html.escape(str(k))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #eee'><b>{html.escape(str(v))}</b></td></tr>"
            for k, v in fields.items()
        )
        body = (
            "<html><body style=\"font-family:Arial,sans-serif\">"
            f"<div style=\"max-width:600px;margin:0 auto;padding:20px\">"
            f"<div style=\"background:{severity.hex_color};color:#fff;padding:16px;border-radius:5px\">"
            f"<h2 style=\"margin:0\">{html.escape(title)}</h2></div>"
            f"<table style=\"width:100%;border-collapse:collapse;margin-top:16px\">{rows}</table>"
            f"<p style=\"color:#666;font-size:12px\">Generated {datetime.now():%Y-%m-%d %H:%M:%S}</p>"
            "</div></body></html>"
        )
        return self.send_html(recipient, html.escape(title), body)


def _alert_html(title: str, message: str, severity: Severity) -> str:
    """The shared alert email body. Both values are escaped here, once."""
    return (
        "<html><body style=\"font-family:Arial,sans-serif\">"
        "<div style=\"max-width:600px;margin:0 auto;padding:20px\">"
        f"<div style=\"background:{severity.hex_color};color:#fff;padding:20px;border-radius:5px;margin-bottom:20px\">"
        f"<h2 style=\"margin:0\">{severity.emoji} {html.escape(title)}</h2></div>"
        "<div style=\"padding:20px;background:#f5f5f5;border-radius:5px\">"
        f"<p>{html.escape(message)}</p>"
        f"<p style=\"color:#666;font-size:12px\">Generated {datetime.now():%Y-%m-%d %H:%M:%S}</p>"
        "</div></div></body></html>"
    )


def notify_all(title: str, message: str, severity=Severity.INFO,
               recipient: Optional[str] = None) -> Dict[str, bool]:
    """Send one alert to every channel that is configured.

    Channels with no configuration are skipped rather than treated as failures:
    most deployments enable one or two. Returns {channel: delivered}.
    """
    severity = Severity.parse(severity)
    results: Dict[str, bool] = {}

    slack = SlackNotifier()
    if slack.configured:
        results["slack"] = slack.send_alert(title, message, severity)

    discord = DiscordNotifier()
    if discord.configured:
        results["discord"] = discord.send_alert(title, message, severity)

    email = EmailNotifier()
    recipient = recipient or os.getenv("ALERT_EMAIL_TO")
    if email.configured and recipient:
        results["email"] = email.send_alert(recipient, title, message, severity)

    custom = os.getenv("CUSTOM_WEBHOOK_URL")
    if custom:
        results["webhook"] = post_webhook(custom, {
            "title": title,
            "message": message,
            "severity": severity.value,
            "timestamp": datetime.now().isoformat(),
        })

    if not results:
        logger.warning("No notification channel is configured; alert not delivered: %s", title)
    return results


def configured_channels() -> List[str]:
    """Names of the channels that currently have configuration."""
    channels = []
    if SlackNotifier().configured:
        channels.append("slack")
    if DiscordNotifier().configured:
        channels.append("discord")
    if EmailNotifier().configured:
        channels.append("email")
    if os.getenv("CUSTOM_WEBHOOK_URL"):
        channels.append("webhook")
    return channels
