"""Tests for the attack correlation engine (analytics/correlation_engine.py).

Builds a temporary SQLite alert database from the real schema, inserts crafted
alerts, and asserts each correlation rule fires (and doesn't over-fire).
"""

import json
import os
import sqlite3
import tempfile
import uuid
from datetime import datetime, timedelta

import pytest

from analytics.attack_graph import AttackGraph
from analytics.correlation_engine import (
    DEFAULT_CONFIG,
    CorrelationEngine,
    _parse_indicators,
    _parse_ts,
    load_config,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
def _insert_alert(conn, **kw):
    now = datetime.utcnow()
    row = {
        "id": kw.get("id", str(uuid.uuid4())),
        "alert_name": kw.get("alert_name", "TestAlert"),
        "severity": kw.get("severity", "MEDIUM"),
        "status": "active",
        "source_ip": kw.get("source_ip"),
        "source_port": kw.get("source_port"),
        "honeypot_type": kw.get("honeypot_type"),
        "service_name": kw.get("service_name"),
        "threat_level": kw.get("threat_level"),
        "threat_score": kw.get("threat_score", 0.0),
        "threat_indicators": json.dumps(kw.get("threat_indicators", [])),
        "event_count": kw.get("event_count", 1),
        "first_seen": kw.get("ts", now).isoformat(),
        "last_seen": kw.get("ts", now).isoformat(),
        "description": kw.get("description", ""),
    }
    conn.execute(
        """
        INSERT INTO alerts (id, alert_name, severity, status, source_ip,
            source_port, honeypot_type, service_name, threat_level, threat_score,
            threat_indicators, event_count, first_seen, last_seen, description)
        VALUES (:id, :alert_name, :severity, :status, :source_ip, :source_port,
            :honeypot_type, :service_name, :threat_level, :threat_score,
            :threat_indicators, :event_count, :first_seen, :last_seen, :description)
        """,
        row,
    )
    return row["id"]


@pytest.fixture
def db_path():
    """A temp DB created from the real schema.sql."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "alerts.db")
    schema = os.path.join("database", "schema.sql")
    conn = sqlite3.connect(path)
    with open(schema, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    return path


def _engine(db_path):
    # Use defaults directly so tests don't depend on the YAML file.
    return CorrelationEngine(db_path=db_path, config=DEFAULT_CONFIG)


# --------------------------------------------------------------------------- #
# Helper unit tests
# --------------------------------------------------------------------------- #
def test_parse_ts_variants():
    assert _parse_ts("2026-08-31T12:00:00") == datetime(2026, 8, 31, 12, 0, 0)
    assert _parse_ts("2026-08-31 12:00:00") == datetime(2026, 8, 31, 12, 0, 0)
    assert _parse_ts(None) is None
    assert _parse_ts("garbage") is None


def test_parse_indicators_variants():
    assert _parse_indicators('["a", "b"]') == ["a", "b"]
    assert _parse_indicators([]) == []
    assert _parse_indicators(None) == []
    assert _parse_indicators("plain") == ["plain"]


def test_config_fallback_when_missing(tmp_path):
    cfg = load_config(str(tmp_path / "does-not-exist.yml"))
    assert cfg == DEFAULT_CONFIG


# --------------------------------------------------------------------------- #
# Rule 1: multi-target actor
# --------------------------------------------------------------------------- #
def test_multi_target_actor(db_path):
    conn = sqlite3.connect(db_path)
    _insert_alert(conn, source_ip="10.0.0.1", honeypot_type="cowrie")
    _insert_alert(conn, source_ip="10.0.0.1", honeypot_type="opencanary")
    _insert_alert(conn, source_ip="10.0.0.2", honeypot_type="cowrie")  # single target
    conn.commit()
    conn.close()

    campaigns = _engine(db_path).correlate()
    mta = [c for c in campaigns if c.correlation_type == "multi_target_actor"]
    assert len(mta) == 1
    assert mta[0].details["source_ip"] == "10.0.0.1"
    assert set(mta[0].details["targets"]) == {"cowrie", "opencanary"}


# --------------------------------------------------------------------------- #
# Rule 2: coordinated campaign
# --------------------------------------------------------------------------- #
def test_coordinated_campaign(db_path):
    conn = sqlite3.connect(db_path)
    base = datetime.utcnow()
    for i in range(6):  # 6 distinct IPs within 5 minutes on ssh
        _insert_alert(conn, source_ip=f"192.168.1.{i}", service_name="ssh",
                      honeypot_type="cowrie", ts=base + timedelta(minutes=i % 5))
    conn.commit()
    conn.close()

    campaigns = _engine(db_path).correlate()
    coord = [c for c in campaigns if c.correlation_type == "coordinated_campaign"]
    assert len(coord) == 1
    assert len(coord[0].source_ips) >= 5


def test_coordinated_campaign_below_threshold(db_path):
    conn = sqlite3.connect(db_path)
    base = datetime.utcnow()
    for i in range(3):  # only 3 sources -> below min_sources (5)
        _insert_alert(conn, source_ip=f"192.168.2.{i}", service_name="ssh",
                      honeypot_type="cowrie", ts=base + timedelta(minutes=i))
    conn.commit()
    conn.close()

    campaigns = _engine(db_path).correlate()
    assert not [c for c in campaigns if c.correlation_type == "coordinated_campaign"]


# --------------------------------------------------------------------------- #
# Rule 3: attack chain
# --------------------------------------------------------------------------- #
def test_attack_chain(db_path):
    conn = sqlite3.connect(db_path)
    base = datetime.utcnow()
    ip = "172.16.0.9"
    _insert_alert(conn, source_ip=ip, service_name="dns",
                  alert_name="PortScan", description="network scan probe",
                  ts=base)  # reconnaissance
    _insert_alert(conn, source_ip=ip, service_name="ssh",
                  alert_name="SSHBruteForce", description="credential brute force",
                  ts=base + timedelta(minutes=10))  # access
    _insert_alert(conn, source_ip=ip, service_name="http",
                  alert_name="WebExploit", description="rce payload upload",
                  ts=base + timedelta(minutes=20))  # exploitation
    conn.commit()
    conn.close()

    campaigns = _engine(db_path).correlate()
    chains = [c for c in campaigns if c.correlation_type == "attack_chain"]
    assert len(chains) == 1
    assert chains[0].severity == "CRITICAL"
    assert chains[0].details["phases"] == ["reconnaissance", "access", "exploitation"]
    assert chains[0].attack_phase == "exploitation"


def test_attack_chain_respects_gap(db_path):
    conn = sqlite3.connect(db_path)
    base = datetime.utcnow()
    ip = "172.16.0.10"
    _insert_alert(conn, source_ip=ip, service_name="dns",
                  description="scan", ts=base)
    # 5 hours later -> exceeds max_gap_minutes (60), so no chain
    _insert_alert(conn, source_ip=ip, service_name="http",
                  description="exploit", ts=base + timedelta(hours=5))
    conn.commit()
    conn.close()

    campaigns = _engine(db_path).correlate()
    assert not [c for c in campaigns if c.correlation_type == "attack_chain"]


# --------------------------------------------------------------------------- #
# Rule 4: shared indicator
# --------------------------------------------------------------------------- #
def test_shared_indicator(db_path):
    conn = sqlite3.connect(db_path)
    _insert_alert(conn, source_ip="1.1.1.1", threat_indicators=["mirai-c2.example"])
    _insert_alert(conn, source_ip="2.2.2.2", threat_indicators=["mirai-c2.example"])
    _insert_alert(conn, source_ip="3.3.3.3", threat_indicators=["other"])
    conn.commit()
    conn.close()

    campaigns = _engine(db_path).correlate()
    shared = [c for c in campaigns if c.correlation_type == "shared_indicator"]
    assert len(shared) == 1
    assert shared[0].details["indicator"] == "mirai-c2.example"
    assert set(shared[0].source_ips) == {"1.1.1.1", "2.2.2.2"}


# --------------------------------------------------------------------------- #
# Persistence + graph
# --------------------------------------------------------------------------- #
def test_persist_as_incidents(db_path):
    conn = sqlite3.connect(db_path)
    _insert_alert(conn, source_ip="10.0.0.1", honeypot_type="cowrie")
    _insert_alert(conn, source_ip="10.0.0.1", honeypot_type="opencanary")
    conn.commit()
    conn.close()

    engine = _engine(db_path)
    campaigns = engine.correlate()
    written = engine.persist_as_incidents(campaigns)
    assert written == len(campaigns) >= 1

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM incidents").fetchall()
    conn.close()
    assert len(rows) == written
    row = rows[0]
    assert row["created_by"] == "correlation-engine"
    assert json.loads(row["alert_ids"])  # non-empty JSON array


def test_attack_graph_from_campaigns(db_path):
    conn = sqlite3.connect(db_path)
    _insert_alert(conn, source_ip="10.0.0.1", honeypot_type="cowrie")
    _insert_alert(conn, source_ip="10.0.0.1", honeypot_type="opencanary")
    conn.commit()
    conn.close()

    campaigns = _engine(db_path).correlate()
    graph = AttackGraph.from_campaigns(campaigns)
    assert len(graph) > 0
    # DOT and JSON render without error and reference the source IP.
    dot = graph.to_dot()
    assert dot.startswith("digraph attack_graph")
    assert "10.0.0.1" in dot
    data = json.loads(graph.to_json())
    assert data["nodes"] and "edges" in data


def test_no_alerts_no_campaigns(db_path):
    assert _engine(db_path).correlate() == []
