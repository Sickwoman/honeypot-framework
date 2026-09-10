#!/usr/bin/env python3

"""Live honeypot log ingestor.

This module watches Cowrie and OpenCanary logs in real time, translates raw log
entries into alert payloads, and inserts them into the framework's alert store.
Because the alert creation path triggers matching playbooks automatically,
newly-detected attacks immediately trigger incident-response automation.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from api.alerts_service import AlertService, enrich_alert_with_threat_intel
from threatintel.honeytokens import build_trigger_alert, find_triggered_tokens, load_manifest

logger = logging.getLogger(__name__)


def parse_honeytoken_event(line: str) -> Optional[Dict]:
    """Return a critical alert when a configured synthetic value is observed."""
    manifest_path = os.getenv("HONEYTOKEN_MANIFEST")
    if not manifest_path:
        return None
    try:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            event = line
        manifest = load_manifest(manifest_path)
    except (OSError, ValueError):
        return None
    return build_trigger_alert(event, find_triggered_tokens(event, manifest))


def parse_cowrie_line(line: str) -> Optional[Dict]:
    """Convert a Cowrie log line into an alert payload when it represents activity."""
    text = (line or "").strip()
    if not text:
        return None

    source_ip = None
    match = re.search(r"\b(?:src|from|remote)\s*[:=]?\s*(\d+\.\d+\.\d+\.\d+)", text, re.IGNORECASE)
    if match:
        source_ip = match.group(1)
    else:
        match = re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b", text)
        if match:
            source_ip = match.group(1)

    lowered = text.lower()
    if "trying auth" in lowered:
        return {
            "alert_name": "SSHBruteForce",
            "severity": "HIGH",
            "status": "active",
            "source_ip": source_ip,
            "honeypot_type": "cowrie",
            "service_name": "ssh",
            "description": text,
            "metadata": {"log_source": "cowrie", "raw_event": text},
            "event_count": 1,
            "threat_score": 0.9,
            "threat_level": "HIGH",
        }

    if re.search(r"cmd:.*(?:wget|curl|nc\s+-e|bash\s+-c|python\s+-c|powershell|chmod)", text, re.IGNORECASE):
        return {
            "alert_name": "MalwareDownloadAttempt",
            "severity": "CRITICAL",
            "status": "active",
            "source_ip": source_ip,
            "honeypot_type": "cowrie",
            "service_name": "ssh",
            "description": text,
            "metadata": {"log_source": "cowrie", "raw_event": text},
            "event_count": 1,
            "threat_score": 0.97,
            "threat_level": "CRITICAL",
        }

    return None


def parse_opencanary_line(line: str) -> Optional[Dict]:
    """Convert an OpenCanary JSON line into an alert payload when it represents activity."""
    text = (line or "").strip()
    if not text:
        return None

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    logdata = payload.get("logdata", {}) if isinstance(payload.get("logdata"), dict) else {}
    user = logdata.get("USERNAME") or payload.get("username")
    password = logdata.get("PASSWORD") or payload.get("password")
    source_ip = payload.get("src_ip") or payload.get("src_ip_address") or payload.get("src")
    if user or password:
        return {
            "alert_name": "CredentialsCaptured",
            "severity": "HIGH",
            "status": "active",
            "source_ip": source_ip,
            "honeypot_type": "opencanary",
            "service_name": payload.get("service") or payload.get("dst_port") or "unknown",
            "description": f"Credentials captured: {user or 'unknown'}:{password or 'unknown'}",
            "metadata": {"log_source": "opencanary", "raw_event": payload},
            "event_count": 1,
            "threat_score": 0.85,
            "threat_level": "HIGH",
            "threat_indicators": ["credential_capture"],
        }

    path = logdata.get("PATH") or logdata.get("path") or payload.get("path") or ""
    if path and any(marker in path.lower() for marker in [".env", "/admin", "/wp-admin", "/config", ".php"]):
        return {
            "alert_name": "WebReconnaissance",
            "severity": "MEDIUM",
            "status": "active",
            "source_ip": source_ip,
            "honeypot_type": "opencanary",
            "service_name": "http",
            "description": f"Suspicious HTTP path requested: {path}",
            "metadata": {"log_source": "opencanary", "raw_event": payload},
            "event_count": 1,
            "threat_score": 0.7,
            "threat_level": "MEDIUM",
        }

    return None


def parse_honeypot_line(line: str) -> Optional[Dict]:
    """Parse a raw honeypot log line into an alert payload if it is suspicious."""
    honeytoken_alert = parse_honeytoken_event(line)
    if honeytoken_alert:
        return honeytoken_alert
    parsed = parse_cowrie_line(line)
    if parsed:
        return parsed
    return parse_opencanary_line(line)


def ingest_honeypot_line(line: str, db_path: str = None) -> Optional[str]:
    """Parse a log line and insert the resulting alert into SQLite. Returns alert ID or None."""
    alert_data = parse_honeypot_line(line)
    if not alert_data:
        return None

    enriched_alert = enrich_alert_with_threat_intel(alert_data) or alert_data
    service = AlertService(db_path=db_path)
    alert_id = service.create_alert(enriched_alert)
    logger.info("Created alert %s from honeypot event: %s", alert_id, enriched_alert.get("alert_name"))
    return alert_id


def tail_log_file(
    path: str,
    db_path: str = None,
    poll_seconds: float = 2.0,
    stop_after_lines: Optional[int] = None,
    from_start: bool = True,
    wait_for_file: bool = False,
) -> Iterable[str]:
    """Read a log file incrementally and yield new lines.

    This is deliberately lightweight so it can run as a background process in the
    framework's monitoring stack without depending on additional packages.

    Args:
        from_start: Read existing content first. Live tailing should pass
            False, otherwise restarting the ingestor re-ingests the whole
            log and duplicates every alert in it.
        wait_for_file: Block until the file appears instead of giving up.
            Needed when the ingestor starts before the honeypot has written
            its first line (e.g. both come up together under Docker).
    """
    file_path = Path(path)

    while not file_path.exists():
        if not wait_for_file:
            logger.warning("Log file not found: %s", path)
            return
        logger.info("Waiting for log file to appear: %s", path)
        time.sleep(poll_seconds)

    seen = 0
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        if not from_start:
            handle.seek(0, os.SEEK_END)

        while True:
            line = handle.readline()
            if not line:
                if stop_after_lines is not None and seen >= stop_after_lines:
                    break
                time.sleep(poll_seconds)
                continue
            seen += 1
            yield line
            if stop_after_lines is not None and seen >= stop_after_lines:
                break


def process_log_file(
    path: str,
    db_path: str = None,
    poll_seconds: float = 2.0,
    max_lines: Optional[int] = None,
    from_start: bool = True,
    wait_for_file: bool = False,
) -> List[str]:
    """Continuously ingest suspicious events from a log file."""
    created_ids: List[str] = []
    for line in tail_log_file(
        path,
        db_path=db_path,
        poll_seconds=poll_seconds,
        stop_after_lines=max_lines,
        from_start=from_start,
        wait_for_file=wait_for_file,
    ):
        alert_id = ingest_honeypot_line(line, db_path=db_path)
        if alert_id:
            created_ids.append(alert_id)
    return created_ids


DEFAULT_LOG_PATHS = (
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.log",
    "/var/tmp/opencanary.log",
)


def _resolve_log_paths(argv: List[str]) -> List[str]:
    """Log paths from argv, else $HONEYPOT_LOG_PATHS, else the defaults."""
    if argv:
        return argv

    from_env = os.getenv("HONEYPOT_LOG_PATHS", "").strip()
    if from_env:
        return [p.strip() for p in from_env.replace(":", ",").split(",") if p.strip()]

    return list(DEFAULT_LOG_PATHS)


def main(argv: Optional[List[str]] = None) -> int:
    """Tail every configured honeypot log concurrently.

    Each log gets its own thread: process_log_file() blocks forever, so
    iterating them in one loop would only ever monitor the first path.
    """
    import threading

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    paths = _resolve_log_paths(list(argv if argv is not None else sys.argv[1:]))
    wait = os.getenv("INGESTOR_WAIT_FOR_LOGS", "true").lower() not in ("false", "0", "no")
    # Live tailing starts at EOF so a restart doesn't replay the whole log.
    from_start = os.getenv("INGESTOR_READ_FROM_START", "false").lower() in ("true", "1", "yes")
    poll_seconds = float(os.getenv("INGESTOR_POLL_SECONDS", "2.0"))

    if not wait:
        paths = [p for p in paths if os.path.exists(p)]

    if not paths:
        logger.warning("No honeypot log files found. Nothing to monitor.")
        return 0

    threads = []
    for path in paths:
        logger.info("Monitoring %s for suspicious activity", path)
        thread = threading.Thread(
            target=process_log_file,
            args=(path,),
            kwargs={
                "db_path": None,
                "poll_seconds": poll_seconds,
                "from_start": from_start,
                "wait_for_file": wait,
            },
            name=f"ingest:{os.path.basename(path)}",
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    try:
        while any(t.is_alive() for t in threads):
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down ingestor")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
