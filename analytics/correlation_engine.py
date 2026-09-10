#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Attack Correlation Engine
#
# Links related attacks across honeypots and time. Reads alerts from the same
# SQLite database used by api/alerts_service.py (the `alerts` table) and emits
# AttackCampaign objects, each grouping a set of related alerts under one of
# four correlation types:
#
#   1. multi_target_actor   - one source IP hitting multiple honeypots/services
#   2. coordinated_campaign - many source IPs hitting one service in a window
#   3. attack_chain         - one IP progressing recon -> exploitation over time
#   4. shared_indicator     - alerts sharing a common threat indicator (IOC)
#
# Rules are tuned via config/correlation_rules.yml; if that file (or PyYAML) is
# missing, built-in defaults matching the YAML are used, so the engine always
# runs. Campaigns can optionally be persisted into the `incidents` table.
#
# Dependency-light: standard library + (optional) PyYAML. No pandas/ES needed.
################################################################################

import argparse
import json
import logging
import os
import sqlite3
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Built-in defaults (mirror config/correlation_rules.yml). Used when the YAML
# file or PyYAML is unavailable so the engine never hard-fails on config.
# --------------------------------------------------------------------------- #
DEFAULT_CONFIG: Dict[str, Any] = {
    "lookback_hours": 168,
    "rules": {
        "multi_target_actor": {"enabled": True, "min_targets": 2, "severity": "HIGH"},
        "coordinated_campaign": {
            "enabled": True, "window_minutes": 10, "min_sources": 5, "severity": "HIGH",
        },
        "attack_chain": {
            "enabled": True, "max_gap_minutes": 60, "min_phases": 2, "severity": "CRITICAL",
        },
        "shared_indicator": {"enabled": True, "min_alerts": 2, "severity": "MEDIUM"},
    },
    "attack_phases": [
        {"name": "reconnaissance",
         "services": ["icmp", "dns", "snmp", "portscan"],
         "keywords": ["scan", "probe", "recon", "enumeration", "sweep", "fingerprint"]},
        {"name": "access",
         "services": ["ssh", "telnet", "ftp", "rdp", "vnc"],
         "keywords": ["login", "brute", "credential", "auth", "password"]},
        {"name": "exploitation",
         "services": ["http", "https", "smb", "mysql", "redis", "elasticsearch"],
         "keywords": ["exploit", "injection", "rce", "upload", "payload", "cve", "shell"]},
        {"name": "exfiltration",
         "services": [],
         "keywords": ["download", "exfil", "transfer", "wget", "curl", "scp", "beacon"]},
    ],
}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Alert:
    """A single alert row, normalized for correlation."""
    id: str
    alert_name: str = ""
    severity: str = "MEDIUM"
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    honeypot_type: Optional[str] = None
    service_name: Optional[str] = None
    threat_level: Optional[str] = None
    threat_score: float = 0.0
    threat_indicators: List[str] = field(default_factory=list)
    event_count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: str = ""

    @property
    def target(self) -> Optional[str]:
        """The thing being attacked: honeypot_type, else service_name."""
        return self.honeypot_type or self.service_name

    @property
    def ts(self) -> Optional[datetime]:
        """Best timestamp for ordering: last_seen, else first_seen."""
        return self.last_seen or self.first_seen


@dataclass
class AttackCampaign:
    """A correlated cluster of alerts."""
    correlation_type: str
    title: str
    severity: str
    alert_ids: List[str]
    source_ips: List[str]
    score: float = 0.0
    attack_phase: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat() if self.first_seen else None
        d["last_seen"] = self.last_seen.isoformat() if self.last_seen else None
        return d


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _parse_ts(value: Any) -> Optional[datetime]:
    """Parse a DB timestamp (ISO 8601 or 'YYYY-MM-DD HH:MM:SS')."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(value).strip(), fmt)
        except ValueError:
            continue
    logger.debug("Could not parse timestamp: %r", value)
    return None


def _parse_indicators(value: Any) -> List[str]:
    """threat_indicators is stored as a JSON array (string) in the DB."""
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(v) for v in parsed]
        return [str(parsed)]
    except (json.JSONDecodeError, TypeError):
        return [str(value)]


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load correlation_rules.yml, falling back to DEFAULT_CONFIG."""
    if config_path is None:
        config_path = os.path.join("config", "correlation_rules.yml")
    if not os.path.exists(config_path):
        logger.info("Correlation config not found at %s; using defaults.", config_path)
        return DEFAULT_CONFIG
    try:
        import yaml  # optional dependency
    except ImportError:
        logger.warning("PyYAML not installed; using default correlation config.")
        return DEFAULT_CONFIG
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f) or {}
    except Exception as e:  # malformed YAML -> defaults, never crash
        logger.warning("Failed to parse %s (%s); using defaults.", config_path, e)
        return DEFAULT_CONFIG
    # Shallow-merge so a partial YAML still gets missing keys from defaults.
    merged = dict(DEFAULT_CONFIG)
    merged.update(loaded)
    rules = dict(DEFAULT_CONFIG["rules"])
    for name, cfg in (loaded.get("rules") or {}).items():
        base = dict(rules.get(name, {}))
        base.update(cfg or {})
        rules[name] = base
    merged["rules"] = rules
    return merged


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class CorrelationEngine:
    """Correlate alerts from the honeypot alert database."""

    def __init__(self, db_path: Optional[str] = None,
                 config_path: Optional[str] = None,
                 config: Optional[Dict[str, Any]] = None):
        if db_path is None:
            # Reuse the framework's config if available; else the documented default.
            try:
                from api.config import get_config
                db_path = get_config().get("ALERTS_DB_PATH")
            except Exception:
                db_path = os.getenv("ALERTS_DB_PATH", "/var/lib/honeypot/alerts.db")
        self.db_path = db_path
        self.config = config if config is not None else load_config(config_path)
        self._phase_index = {p["name"]: i for i, p in enumerate(self.config["attack_phases"])}

    # ----------------------------- data load ----------------------------- #
    def load_alerts(self, lookback_hours: Optional[int] = None) -> List[Alert]:
        """Load alerts from the DB, newest activity first."""
        if lookback_hours is None:
            lookback_hours = self.config.get("lookback_hours", 0)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            sql = (
                "SELECT id, alert_name, severity, source_ip, source_port, "
                "honeypot_type, service_name, threat_level, threat_score, "
                "threat_indicators, event_count, first_seen, last_seen, description "
                "FROM alerts"
            )
            params: tuple = ()
            if lookback_hours and lookback_hours > 0:
                cutoff = (datetime.utcnow() - timedelta(hours=lookback_hours)).isoformat()
                sql += " WHERE COALESCE(last_seen, first_seen, created_at) >= ?"
                params = (cutoff,)
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
        return [self._row_to_alert(r) for r in rows]

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        return Alert(
            id=row["id"],
            alert_name=row["alert_name"] or "",
            severity=row["severity"] or "MEDIUM",
            source_ip=row["source_ip"],
            source_port=row["source_port"],
            honeypot_type=row["honeypot_type"],
            service_name=row["service_name"],
            threat_level=row["threat_level"],
            threat_score=row["threat_score"] or 0.0,
            threat_indicators=_parse_indicators(row["threat_indicators"]),
            event_count=row["event_count"] or 1,
            first_seen=_parse_ts(row["first_seen"]),
            last_seen=_parse_ts(row["last_seen"]),
            description=row["description"] or "",
        )

    # ----------------------------- orchestration ------------------------- #
    def correlate(self, alerts: Optional[List[Alert]] = None) -> List[AttackCampaign]:
        """Run every enabled rule and return all campaigns, most severe first."""
        if alerts is None:
            alerts = self.load_alerts()
        rules = self.config.get("rules", {})
        campaigns: List[AttackCampaign] = []
        if rules.get("multi_target_actor", {}).get("enabled", True):
            campaigns += self._multi_target_actor(alerts)
        if rules.get("coordinated_campaign", {}).get("enabled", True):
            campaigns += self._coordinated_campaign(alerts)
        if rules.get("attack_chain", {}).get("enabled", True):
            campaigns += self._attack_chain(alerts)
        if rules.get("shared_indicator", {}).get("enabled", True):
            campaigns += self._shared_indicator(alerts)

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        campaigns.sort(key=lambda c: (order.get(c.severity, 9), -c.score))
        return campaigns

    # ----------------------------- rule 1 -------------------------------- #
    def _multi_target_actor(self, alerts: List[Alert]) -> List[AttackCampaign]:
        cfg = self.config["rules"]["multi_target_actor"]
        min_targets = cfg.get("min_targets", 2)
        by_ip: Dict[str, List[Alert]] = defaultdict(list)
        for a in alerts:
            if a.source_ip:
                by_ip[a.source_ip].append(a)

        campaigns = []
        for ip, group in by_ip.items():
            targets = {a.target for a in group if a.target}
            if len(targets) >= min_targets:
                campaigns.append(self._make_campaign(
                    "multi_target_actor", cfg.get("severity", "HIGH"), group,
                    title=f"Source {ip} attacked {len(targets)} targets",
                    score=float(len(targets)),
                    details={"source_ip": ip, "targets": sorted(targets)},
                ))
        return campaigns

    # ----------------------------- rule 2 -------------------------------- #
    def _coordinated_campaign(self, alerts: List[Alert]) -> List[AttackCampaign]:
        cfg = self.config["rules"]["coordinated_campaign"]
        window = timedelta(minutes=cfg.get("window_minutes", 10))
        min_sources = cfg.get("min_sources", 5)

        by_service: Dict[str, List[Alert]] = defaultdict(list)
        for a in alerts:
            if a.ts is not None:
                by_service[a.target or a.service_name or "unknown"].append(a)

        seen_sets: set = set()
        campaigns = []
        for service, group in by_service.items():
            group = sorted(group, key=lambda a: a.ts)
            left = 0
            for right in range(len(group)):
                while group[right].ts - group[left].ts > window:
                    left += 1
                windowed = group[left:right + 1]
                ips = {a.source_ip for a in windowed if a.source_ip}
                if len(ips) >= min_sources:
                    key = frozenset(a.id for a in windowed)
                    if key not in seen_sets:
                        seen_sets.add(key)
                        campaigns.append(self._make_campaign(
                            "coordinated_campaign", cfg.get("severity", "HIGH"),
                            windowed,
                            title=(f"Coordinated attack on {service}: "
                                   f"{len(ips)} sources in "
                                   f"{cfg.get('window_minutes', 10)}m"),
                            score=float(len(ips)),
                            details={"service": service,
                                     "source_ips": sorted(ips),
                                     "window_minutes": cfg.get("window_minutes", 10)},
                        ))
        return self._dedupe_by_alertset(campaigns)

    # ----------------------------- rule 3 -------------------------------- #
    def _attack_chain(self, alerts: List[Alert]) -> List[AttackCampaign]:
        cfg = self.config["rules"]["attack_chain"]
        max_gap = timedelta(minutes=cfg.get("max_gap_minutes", 60))
        min_phases = cfg.get("min_phases", 2)

        by_ip: Dict[str, List[Alert]] = defaultdict(list)
        for a in alerts:
            if a.source_ip and a.ts is not None:
                by_ip[a.source_ip].append(a)

        campaigns = []
        for ip, group in by_ip.items():
            group = sorted(group, key=lambda a: a.ts)
            chain: List[Alert] = []
            last_phase = -1
            for a in group:
                pi = self._phase_of(a)
                if pi is None:
                    continue
                if not chain:
                    chain = [a]
                    last_phase = pi
                elif pi > last_phase and (a.ts - chain[-1].ts) <= max_gap:
                    chain.append(a)
                    last_phase = pi
                # else: does not advance the chain; ignore (keep current chain)
            phases = [self.config["attack_phases"][self._phase_of(a)]["name"]
                      for a in chain if self._phase_of(a) is not None]
            distinct_phases = list(dict.fromkeys(phases))
            if len(distinct_phases) >= min_phases:
                campaigns.append(self._make_campaign(
                    "attack_chain", cfg.get("severity", "CRITICAL"), chain,
                    title=(f"Attack chain from {ip}: "
                           f"{' -> '.join(distinct_phases)}"),
                    score=float(len(distinct_phases)),
                    attack_phase=distinct_phases[-1],
                    details={"source_ip": ip, "phases": distinct_phases},
                ))
        return campaigns

    # ----------------------------- rule 4 -------------------------------- #
    def _shared_indicator(self, alerts: List[Alert]) -> List[AttackCampaign]:
        cfg = self.config["rules"]["shared_indicator"]
        min_alerts = cfg.get("min_alerts", 2)

        by_ioc: Dict[str, List[Alert]] = defaultdict(list)
        for a in alerts:
            for ioc in a.threat_indicators:
                by_ioc[ioc].append(a)

        seen_sets: set = set()
        campaigns = []
        for ioc, group in by_ioc.items():
            unique = {a.id: a for a in group}.values()
            if len(unique) >= min_alerts:
                key = frozenset(a.id for a in unique)
                if key in seen_sets:
                    continue
                seen_sets.add(key)
                ips = sorted({a.source_ip for a in unique if a.source_ip})
                campaigns.append(self._make_campaign(
                    "shared_indicator", cfg.get("severity", "MEDIUM"),
                    list(unique),
                    title=f"Shared indicator '{ioc}' across {len(unique)} alerts",
                    score=float(len(unique)),
                    details={"indicator": ioc, "source_ips": ips},
                ))
        return campaigns

    # ----------------------------- shared helpers ------------------------ #
    def _phase_of(self, alert: Alert) -> Optional[int]:
        """Map an alert to a kill-chain phase index, or None if unmatched."""
        service = (alert.service_name or "").lower()
        haystack = f"{alert.alert_name} {alert.description}".lower()
        for i, phase in enumerate(self.config["attack_phases"]):
            if service and service in [s.lower() for s in phase.get("services", [])]:
                return i
            if any(kw.lower() in haystack for kw in phase.get("keywords", [])):
                return i
        return None

    @staticmethod
    def _make_campaign(ctype: str, severity: str, alerts: List[Alert],
                       title: str, score: float = 0.0,
                       attack_phase: Optional[str] = None,
                       details: Optional[Dict[str, Any]] = None) -> AttackCampaign:
        times = [a.ts for a in alerts if a.ts is not None]
        ips = sorted({a.source_ip for a in alerts if a.source_ip})
        return AttackCampaign(
            correlation_type=ctype,
            title=title,
            severity=severity,
            alert_ids=sorted({a.id for a in alerts}),
            source_ips=ips,
            score=score,
            attack_phase=attack_phase,
            first_seen=min(times) if times else None,
            last_seen=max(times) if times else None,
            details=details or {},
        )

    @staticmethod
    def _dedupe_by_alertset(campaigns: List[AttackCampaign]) -> List[AttackCampaign]:
        """Drop campaigns whose alert set is a subset of another's (same type)."""
        by_type: Dict[str, List[AttackCampaign]] = defaultdict(list)
        for c in campaigns:
            by_type[c.correlation_type].append(c)
        kept: List[AttackCampaign] = []
        for group in by_type.values():
            group.sort(key=lambda c: len(c.alert_ids), reverse=True)
            sets: List[set] = []
            for c in group:
                s = set(c.alert_ids)
                if any(s <= bigger for bigger in sets):
                    continue
                sets.append(s)
                kept.append(c)
        return kept

    # ----------------------------- persistence --------------------------- #
    def persist_as_incidents(self, campaigns: List[AttackCampaign]) -> int:
        """Insert campaigns into the `incidents` table. Returns count written."""
        conn = sqlite3.connect(self.db_path)
        try:
            written = 0
            for c in campaigns:
                conn.execute(
                    """
                    INSERT INTO incidents (
                        id, title, description, severity, category, attack_phase,
                        alert_ids, status, created_by, created_at, updated_at,
                        detected_at, start_time, end_time
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', 'correlation-engine',
                              ?, ?, ?, ?, ?)
                    """,
                    (
                        c.id, c.title, json.dumps(c.details), c.severity,
                        c.correlation_type, c.attack_phase,
                        json.dumps(c.alert_ids),
                        datetime.utcnow().isoformat(), datetime.utcnow().isoformat(),
                        datetime.utcnow().isoformat(),
                        c.first_seen.isoformat() if c.first_seen else None,
                        c.last_seen.isoformat() if c.last_seen else None,
                    ),
                )
                written += 1
            conn.commit()
            return written
        finally:
            conn.close()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Honeypot attack correlation engine")
    parser.add_argument("--db", help="Path to the alerts SQLite database")
    parser.add_argument("--config", help="Path to correlation_rules.yml")
    parser.add_argument("--lookback", type=int, default=None,
                        help="Override lookback window in hours (0 = all)")
    parser.add_argument("--format", choices=["text", "json", "dot"], default="text")
    parser.add_argument("--persist", action="store_true",
                        help="Write correlated campaigns into the incidents table")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    engine = CorrelationEngine(db_path=args.db, config_path=args.config)
    alerts = engine.load_alerts(lookback_hours=args.lookback)
    campaigns = engine.correlate(alerts)

    if args.format == "json":
        print(json.dumps([c.to_dict() for c in campaigns], indent=2))
    elif args.format == "dot":
        from analytics.attack_graph import AttackGraph
        print(AttackGraph.from_campaigns(campaigns).to_dot())
    else:
        print(f"Analyzed {len(alerts)} alerts -> {len(campaigns)} campaign(s)\n")
        for c in campaigns:
            print(f"[{c.severity}] {c.correlation_type}: {c.title}")
            print(f"    alerts={len(c.alert_ids)} sources={len(c.source_ips)} "
                  f"score={c.score:g}")

    if args.persist and campaigns:
        n = engine.persist_as_incidents(campaigns)
        logger.info("Persisted %d campaign(s) to the incidents table.", n)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
