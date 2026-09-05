#!/usr/bin/env python3
"""Turn correlated honeypot alerts into evidence-linked attack stories."""

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from analytics.correlation_engine import Alert, AttackCampaign, CorrelationEngine, DEFAULT_CONFIG


@dataclass
class StoryEvent:
    alert_id: str
    timestamp: Optional[str]
    phase: str
    source_ip: Optional[str]
    target: Optional[str]
    severity: str
    summary: str


@dataclass
class AttackStory:
    """An incident narrative whose claims can be traced to alert IDs."""

    id: str
    title: str
    severity: str
    confidence: float
    source_ips: List[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    phases: List[str]
    events: List[StoryEvent] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["confidence"] = round(self.confidence, 3)
        return result

    def render(self) -> str:
        lines = [
            f"{self.title} [{self.severity}]",
            f"Confidence: {self.confidence:.0%} | Sources: {', '.join(self.source_ips) or 'unknown'}",
            f"Window: {self.first_seen or 'unknown'} -> {self.last_seen or 'unknown'}",
            f"Phases: {' -> '.join(self.phases) or 'unclassified'}",
            "Timeline:",
        ]
        for event in self.events:
            lines.append(
                f"  {event.timestamp or '?'} | {event.phase} | "
                f"{event.source_ip or 'unknown'} -> {event.target or 'unknown'} | {event.summary}"
            )
        lines.append("Evidence: " + ", ".join(self.evidence) if self.evidence else "Evidence: none")
        lines.append("Recommended response:")
        lines.extend(f"  - {recommendation}" for recommendation in self.recommendations)
        return "\n".join(lines)


def _text(alert: Alert) -> str:
    return " ".join(
        value.lower()
        for value in (alert.alert_name, alert.description, alert.service_name or "")
        if value
    )


def classify_phase(alert: Alert, config: Dict[str, Any]) -> str:
    """Classify one alert using the same phase vocabulary as correlation."""
    text = _text(alert)
    service = (alert.service_name or "").lower()
    for phase in config.get("attack_phases", []):
        services = {str(value).lower() for value in phase.get("services", [])}
        keywords = [str(value).lower() for value in phase.get("keywords", [])]
        if service in services or any(keyword in text for keyword in keywords):
            return phase["name"]
    return "unclassified"


def _timestamp(alert: Alert) -> Optional[str]:
    value = alert.ts
    return value.isoformat() if isinstance(value, datetime) else None


def _recommendations(phases: Iterable[str]) -> List[str]:
    phase_set = set(phases)
    recommendations = []
    if "reconnaissance" in phase_set:
        recommendations.append("Review exposed services and confirm the honeypot network boundary.")
    if "access" in phase_set:
        recommendations.append("Preserve captured credentials as evidence and rotate any reused decoys.")
    if "exploitation" in phase_set:
        recommendations.append("Isolate the source and inspect the target honeypot for payload activity.")
    if "exfiltration" in phase_set:
        recommendations.append("Check outbound controls and preserve transfer-related logs immediately.")
    return recommendations or ["Review the linked alerts and collect additional telemetry."]


def build_story(campaign: AttackCampaign, alerts: Iterable[Alert], config: Optional[Dict[str, Any]] = None) -> AttackStory:
    """Build a deterministic story from one campaign and its source alerts."""
    config = config or DEFAULT_CONFIG
    campaign_alerts = [alert for alert in alerts if alert.id in set(campaign.alert_ids)]
    campaign_alerts.sort(key=lambda alert: alert.ts or datetime.min)
    events = [
        StoryEvent(
            alert_id=alert.id,
            timestamp=_timestamp(alert),
            phase=classify_phase(alert, config),
            source_ip=alert.source_ip,
            target=alert.target,
            severity=alert.severity,
            summary=alert.description or alert.alert_name or "Observed activity",
        )
        for alert in campaign_alerts
    ]
    phases = []
    for event in events:
        if event.phase not in phases and event.phase != "unclassified":
            phases.append(event.phase)
    confidence = 0.5
    confidence += min(len(events), 4) * 0.08
    confidence += min(len(phases), 3) * 0.07
    confidence += 0.08 if len(campaign.source_ips) > 1 else 0
    confidence = min(confidence, 0.99)
    evidence = [f"alert:{alert.id}" for alert in campaign_alerts]
    return AttackStory(
        id=campaign.id,
        title=campaign.title,
        severity=campaign.severity,
        confidence=confidence,
        source_ips=sorted(set(campaign.source_ips)),
        first_seen=_timestamp(campaign_alerts[0]) if campaign_alerts else None,
        last_seen=_timestamp(campaign_alerts[-1]) if campaign_alerts else None,
        phases=phases,
        events=events,
        evidence=evidence,
        recommendations=_recommendations(phases),
    )


def build_stories(campaigns: Iterable[AttackCampaign], alerts: Iterable[Alert], config: Optional[Dict[str, Any]] = None) -> List[AttackStory]:
    alerts = list(alerts)
    return [build_story(campaign, alerts, config) for campaign in campaigns]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate evidence-linked attack stories")
    parser.add_argument("--db", help="Path to the alerts SQLite database")
    parser.add_argument("--json", action="store_true", help="Print stories as JSON")
    args = parser.parse_args()
    engine = CorrelationEngine(db_path=args.db)
    alerts = engine.load_alerts()
    stories = build_stories(engine.correlate(alerts), alerts, engine.config)
    if args.json:
        print(json.dumps([story.to_dict() for story in stories], indent=2))
    else:
        for index, story in enumerate(stories):
            if index:
                print("\n" + "=" * 72 + "\n")
            print(story.render())
    return 0


if __name__ == "__main__":
    sys.exit(main())