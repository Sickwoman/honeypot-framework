"""Tests for the shared script modules.

scripts/honeypot_stats.py and scripts/notifiers.py replaced code that had been
copy-pasted across three report generators and four notifiers. These tests pin
the behaviour the copies had drifted on:

  * a failing Elasticsearch query degrades to an empty result instead of
    raising, because these run unattended from cron;
  * attacker-controlled values (source IPs, alert text) are escaped before
    they reach an HTML report or an HTML email -- one copy of the email
    notifier escaped and one did not;
  * every webhook POST carries a timeout -- none of the standalone notifiers
    used to set one.
"""
import importlib.util
import os
import sys

import pytest

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

# es_client refuses to hand out a password that isn't configured; the fake
# client below never connects, but importing the module shouldn't explode.
os.environ.setdefault("ELASTICSEARCH_PASSWORD", "test-password-not-used")

import notifiers  # noqa: E402
from honeypot_stats import HoneypotStats  # noqa: E402


def load_script(filename, module_name):
    """Import one of the hyphenated report scripts by path."""
    spec = importlib.util.spec_from_file_location(module_name, os.path.join(SCRIPTS_DIR, filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


HOSTILE = '<script>alert(1)</script>'


class FakeElasticsearch:
    """Answers any aggregation in the query with canned buckets."""

    def __init__(self):
        self.queries = []

    def search(self, index, body):
        self.queries.append((index, body))
        aggs = body.get("aggs", {})
        response = {"hits": {"total": {"value": 1234}}, "aggregations": {}}
        if "top_ips" in aggs:
            response["aggregations"]["top_ips"] = {"buckets": [
                {"key": "203.0.113.10", "doc_count": 500},
                {"key": HOSTILE, "doc_count": 300},
            ]}
        if "services" in aggs:
            response["aggregations"]["services"] = {"buckets": [
                {"key": "ssh", "doc_count": 800},
                {"key": "http", "doc_count": 200},
            ]}
        if "countries" in aggs:
            response["aggregations"]["countries"] = {"buckets": [{"key": "Netherlands", "doc_count": 400}]}
        if "timeline" in aggs:
            response["aggregations"]["timeline"] = {"buckets": [
                {"key_as_string": "2026-09-13T01:00:00Z", "doc_count": 40},
                {"key_as_string": "2026-09-13T02:00:00Z", "doc_count": 80},
            ]}
        if "threat_levels" in aggs:
            response["aggregations"]["threat_levels"] = {"buckets": [{"key": "HIGH", "doc_count": 12}]}
            response["aggregations"]["avg_confidence"] = {"value": 78.5}
        return response


class BrokenElasticsearch:
    def search(self, index, body):
        raise RuntimeError("cluster unreachable")


@pytest.fixture
def summary():
    return HoneypotStats(client=FakeElasticsearch()).summary("24h")


# --------------------------------------------------------------------------- #
# honeypot_stats
# --------------------------------------------------------------------------- #
def test_summary_unpacks_every_aggregation(summary):
    assert summary["total_events"] == 1234
    assert summary["top_ips"][0] == {"ip": "203.0.113.10", "count": 500}
    assert summary["services"] == {"ssh": 800, "http": 200}
    assert summary["top_country"] == "Netherlands"
    assert summary["threat_intel"]["threat_levels"] == {"HIGH": 12}
    assert summary["threat_intel"]["avg_confidence"] == 78.5
    assert len(summary["hourly_trend"]) == 2


def test_service_breakdown_carries_percentages(summary):
    assert summary["service_breakdown"][0] == {"name": "ssh", "count": 800, "percentage": 64.8}


def test_queries_run_against_the_honeypot_index_pattern():
    client = FakeElasticsearch()
    HoneypotStats(client=client).total_events("7d")

    index, body = client.queries[0]
    assert index == "honeypot-*"
    assert body["query"]["range"]["@timestamp"]["gte"] == "now-7d"


def test_a_failing_query_returns_empty_results_rather_than_raising():
    # These generators run from cron; a partial report beats a stack trace.
    stats = HoneypotStats(client=BrokenElasticsearch()).summary("24h")

    assert stats["total_events"] == 0
    assert stats["top_ips"] == []
    assert stats["services"] == {}


# --------------------------------------------------------------------------- #
# Report rendering -- all three generators read the same summary
# --------------------------------------------------------------------------- #
def test_html_report_escapes_an_attacker_chosen_source_ip(summary):
    reports = load_script("generate-reports.py", "gen_reports")
    document = reports.render_html(summary, "last 24 hours")

    assert HOSTILE not in document
    assert "&lt;script&gt;" in document
    assert "1,234" in document


def test_text_report_renders_the_shared_summary(summary):
    analytics = load_script("generate-analytics-report.py", "gen_analytics")
    text = analytics.render_text(summary, 1)

    assert "1,234" in text
    assert "ssh" in text
    assert "64.8%" in text


def test_pdf_report_is_written_and_is_a_pdf(tmp_path):
    pytest.importorskip("reportlab")
    pdf_module = load_script("generate-pdf-report.py", "gen_pdf")
    target = tmp_path / "report.pdf"

    pdf_module.PDFReportGenerator(stats=HoneypotStats(client=FakeElasticsearch())).generate_pdf(str(target), days=1)

    assert target.read_bytes()[:5] == b"%PDF-"
    assert target.stat().st_size > 1000


# --------------------------------------------------------------------------- #
# notifiers
# --------------------------------------------------------------------------- #
class FakeResponse:
    def __init__(self, ok=True, status_code=200, text=""):
        self.ok, self.status_code, self.text = ok, status_code, text


@pytest.fixture
def posted(monkeypatch):
    """Capture webhook POSTs instead of making them."""
    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr(notifiers.requests, "post", fake_post)
    return calls


def test_every_webhook_post_sets_a_timeout(posted):
    # Without one, a hung endpoint wedges the cron job that called it.
    notifiers.SlackNotifier("https://hooks.example.com/x").send_alert("Brute force", "body", "critical")

    assert posted[0]["timeout"] == notifiers.WEBHOOK_TIMEOUT_SECONDS


def test_slack_and_discord_use_their_own_colour_encodings(posted):
    notifiers.SlackNotifier("https://hooks.example.com/x").send_alert("t", "b", "critical")
    notifiers.DiscordNotifier("https://discord.example.com/x").send_alert("t", "b", "warning")

    assert posted[0]["json"]["attachments"][0]["color"] == "#ff0000"
    assert posted[1]["json"]["embeds"][0]["color"] == 16744192


def test_unknown_severity_falls_back_to_info_rather_than_raising():
    assert notifiers.Severity.parse("not-a-severity") is notifiers.Severity.INFO
    assert notifiers.Severity.parse("CRITICAL") is notifiers.Severity.CRITICAL


def test_email_body_escapes_attacker_controlled_alert_text():
    # email-notifier.py used to interpolate this raw while notify-alerts.py
    # escaped it -- the same bug fixed in one copy and not the other.
    body = notifiers._alert_html("Creds captured", '<img src=x onerror=alert(1)>', notifiers.Severity.CRITICAL)

    assert "<img src=x" not in body
    assert "&lt;img src=x" in body


def test_a_non_2xx_response_is_reported_as_failure(monkeypatch):
    monkeypatch.setattr(notifiers.requests, "post", lambda *a, **k: FakeResponse(ok=False, status_code=500, text="nope"))

    assert notifiers.post_webhook("https://x.example.com", {}) is False


def test_a_connection_error_is_reported_as_failure(monkeypatch):
    def boom(*args, **kwargs):
        raise notifiers.requests.RequestException("connection refused")

    monkeypatch.setattr(notifiers.requests, "post", boom)

    assert notifiers.post_webhook("https://x.example.com", {}) is False


def test_an_unconfigured_notifier_raises_instead_of_pretending_to_send(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

    with pytest.raises(notifiers.NotificationError):
        notifiers.SlackNotifier().send_message("hello")


def test_notify_all_skips_channels_that_are_not_configured(monkeypatch, posted):
    for name in ("DISCORD_WEBHOOK_URL", "EMAIL_SENDER", "EMAIL_PASSWORD", "CUSTOM_WEBHOOK_URL", "ALERT_EMAIL_TO"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example.com/only")

    results = notifiers.notify_all("Title", "Message", "warning")

    assert results == {"slack": True}
    assert len(posted) == 1
