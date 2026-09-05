import json

from monitoring.live_alert_ingestor import parse_honeypot_line
from threatintel.honeytokens import (
    build_trigger_alert,
    find_triggered_tokens,
    generate_manifest,
    token_digest,
)


def test_generated_manifest_contains_random_digest_backed_tokens():
    manifest = generate_manifest(2)

    assert len(manifest["tokens"]) == 2
    for token in manifest["tokens"]:
        assert token["value"]
        assert token["digest"] == token_digest(token["value"])


def test_nested_event_triggers_without_leaking_token_value():
    manifest = generate_manifest(1)
    token = manifest["tokens"][0]
    event = {"src_ip": "203.0.113.20", "logdata": {"PASSWORD": token["value"]}}

    matches = find_triggered_tokens(event, manifest)
    alert = build_trigger_alert(event, matches)

    assert matches[0]["id"] == token["id"]
    assert alert["alert_name"] == "HoneytokenTriggered"
    assert alert["severity"] == "CRITICAL"
    assert token["value"] not in json.dumps(alert)


def test_ingestor_emits_honeytoken_alert_for_json_event(monkeypatch, tmp_path):
    manifest = generate_manifest(1)
    manifest_path = tmp_path / "honeytokens.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("HONEYTOKEN_MANIFEST", str(manifest_path))
    token = manifest["tokens"][0]["value"]

    alert = parse_honeypot_line(json.dumps({"src_ip": "198.51.100.10", "password": token}))

    assert alert["alert_name"] == "HoneytokenTriggered"
    assert alert["source_ip"] == "198.51.100.10"


def test_ingestor_scans_plain_text_cowrie_event(monkeypatch, tmp_path):
    manifest = generate_manifest(1)
    manifest_path = tmp_path / "honeytokens.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("HONEYTOKEN_MANIFEST", str(manifest_path))
    token = manifest["tokens"][0]["value"]

    alert = parse_honeypot_line(f"2026-09-05 cmd: echo {token}")

    assert alert["alert_name"] == "HoneytokenTriggered"