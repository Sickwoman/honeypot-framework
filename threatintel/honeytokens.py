"""Generate and detect synthetic honeytokens without exposing real secrets."""

import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def token_digest(value: str) -> str:
    """Return a stable digest for a random honeytoken value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_manifest(count: int = 3) -> Dict[str, Any]:
    """Create a manifest containing random synthetic values for deployment."""
    if count < 1:
        raise ValueError("count must be at least 1")
    tokens = []
    for index in range(count):
        value = secrets.token_urlsafe(32)
        tokens.append({
            "id": f"honeytoken-{index + 1}",
            "label": f"synthetic-credential-{index + 1}",
            "value": value,
            "digest": token_digest(value),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "enabled": True,
        })
    return {"version": 1, "tokens": tokens}


def load_manifest(path: str) -> Dict[str, Any]:
    with Path(path).open(encoding="utf-8") as manifest_file:
        manifest = json.load(manifest_file)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("tokens"), list):
        raise ValueError("honeytoken manifest must contain a tokens list")
    return manifest


def _flatten_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _flatten_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _flatten_strings(item)


def find_triggered_tokens(event: Any, manifest: Dict[str, Any]) -> List[Dict[str, str]]:
    """Find enabled honeytokens used anywhere in a structured event."""
    event_text = "\n".join(_flatten_strings(event))
    matches = []
    for token in manifest.get("tokens", []):
        value = token.get("value")
        if token.get("enabled", True) and value and value in event_text:
            matches.append({
                "id": str(token.get("id", "unknown")),
                "label": str(token.get("label", token.get("id", "unknown"))),
            })
    return matches


def build_trigger_alert(event: Any, matches: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    """Build an alert payload without copying the honeytoken into the alert."""
    if not matches:
        return None
    source_ip = None
    if isinstance(event, dict):
        source_ip = event.get("src_ip") or event.get("src_ip_address") or event.get("src")
    labels = ", ".join(match["label"] for match in matches)
    return {
        "alert_name": "HoneytokenTriggered",
        "severity": "CRITICAL",
        "status": "active",
        "source_ip": source_ip,
        "honeypot_type": "honeytoken",
        "service_name": "tripwire",
        "description": f"Synthetic honeytoken used: {labels}",
        "metadata": {
            "honeytoken_ids": [match["id"] for match in matches],
            "honeytoken_labels": [match["label"] for match in matches],
            "detection": "exact_value_match",
        },
        "event_count": 1,
        "threat_score": 1.0,
        "threat_level": "CRITICAL",
        "threat_indicators": ["honeytoken_triggered"],
    }