from datetime import datetime, timedelta

from analytics.attack_story import build_story
from analytics.correlation_engine import Alert, AttackCampaign, DEFAULT_CONFIG


def test_build_story_preserves_timeline_and_evidence():
    base = datetime(2026, 9, 5, 12, 0, 0)
    alerts = [
        Alert(
            id="recon-1",
            alert_name="PortScan",
            source_ip="203.0.113.8",
            service_name="dns",
            first_seen=base,
            description="network scan probe",
        ),
        Alert(
            id="access-1",
            alert_name="SSHBruteForce",
            source_ip="203.0.113.8",
            service_name="ssh",
            first_seen=base + timedelta(minutes=5),
            description="credential brute force",
        ),
    ]
    campaign = AttackCampaign(
        correlation_type="attack_chain",
        title="Attack chain from 203.0.113.8",
        severity="CRITICAL",
        alert_ids=["recon-1", "access-1"],
        source_ips=["203.0.113.8"],
    )

    story = build_story(campaign, alerts, DEFAULT_CONFIG)

    assert story.phases == ["reconnaissance", "access"]
    assert [event.alert_id for event in story.events] == ["recon-1", "access-1"]
    assert story.evidence == ["alert:recon-1", "alert:access-1"]
    assert 0.7 < story.confidence < 0.9
    assert "Review exposed services" in story.recommendations[0]


def test_story_render_is_human_readable():
    campaign = AttackCampaign(
        correlation_type="shared_indicator",
        title="Shared malware indicator",
        severity="HIGH",
        alert_ids=[],
        source_ips=["198.51.100.10"],
    )

    rendered = build_story(campaign, [], DEFAULT_CONFIG).render()

    assert "Shared malware indicator" in rendered
    assert "Recommended response:" in rendered