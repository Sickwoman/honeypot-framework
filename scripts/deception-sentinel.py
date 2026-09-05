#!/usr/bin/env python3
"""Validate honeypot reachability, management-plane exposure, and log health."""

import argparse
import base64
import json
import os
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import yaml
except ImportError:  # pragma: no cover - documented runtime dependency
    yaml = None


@dataclass
class CheckResult:
    name: str
    passed: bool
    details: str
    duration_ms: float

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "details": self.details,
            "duration_ms": round(self.duration_ms, 2),
        }


def tcp_connect(host: str, port: int, timeout: float) -> bool:
    """Return whether a TCP endpoint accepts a connection."""
    with socket.create_connection((host, port), timeout=timeout):
        return True


def check_tcp(name: str, host: str, port: int, timeout: float) -> CheckResult:
    started = time.monotonic()
    try:
        tcp_connect(host, port, timeout)
        return CheckResult(name, True, f"{host}:{port} accepted a connection", (time.monotonic() - started) * 1000)
    except OSError as exc:
        return CheckResult(name, False, f"{host}:{port} unavailable: {exc}", (time.monotonic() - started) * 1000)


def check_forbidden_port(name: str, host: str, port: int, timeout: float) -> CheckResult:
    started = time.monotonic()
    try:
        tcp_connect(host, port, timeout)
        return CheckResult(name, False, f"forbidden endpoint {host}:{port} accepted a connection", (time.monotonic() - started) * 1000)
    except OSError:
        return CheckResult(name, True, f"forbidden endpoint {host}:{port} refused the connection", (time.monotonic() - started) * 1000)


def check_elasticsearch(config: Dict[str, Any], timeout: float) -> CheckResult:
    started = time.monotonic()
    url = str(config.get("url", "https://localhost:9200")).rstrip("/")
    request = Request(f"{url}/_cluster/health")
    username = config.get("username") or os.getenv("ELASTICSEARCH_USERNAME")
    password = config.get("password") or os.getenv("ELASTICSEARCH_PASSWORD")
    if username and password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
    context = ssl._create_unverified_context() if config.get("verify_tls", False) is False else None

    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            payload = json.loads(response.read().decode())
        status = payload.get("status", "unknown")
        passed = status in {"green", "yellow"}
        return CheckResult("elasticsearch_health", passed, f"cluster status is {status}", (time.monotonic() - started) * 1000)
    except (HTTPError, URLError, OSError, ValueError) as exc:
        return CheckResult("elasticsearch_health", False, f"health endpoint failed: {exc}", (time.monotonic() - started) * 1000)


def load_config(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    if yaml is None:
        raise RuntimeError("PyYAML is required when --config is used")
    with Path(path).open(encoding="utf-8") as config_file:
        return yaml.safe_load(config_file) or {}


def run_checks(config: Dict[str, Any], timeout: float) -> List[CheckResult]:
    results: List[CheckResult] = []
    for probe in config.get("honeypots", []):
        results.append(check_tcp(probe["name"], probe["host"], int(probe["port"]), timeout))
    for endpoint in config.get("forbidden_ports", []):
        results.append(check_forbidden_port(endpoint["name"], endpoint["host"], int(endpoint["port"]), timeout))
    if config.get("elasticsearch", {}).get("enabled", True):
        results.append(check_elasticsearch(config.get("elasticsearch", {}), timeout))
    return results


def start_metrics_server(port: int):
    try:
        from prometheus_client import Gauge, start_http_server
    except ImportError as exc:
        raise RuntimeError("prometheus-client is required for --metrics-port") from exc

    check_status = Gauge("honeypot_sentinel_check_status", "Sentinel check status", ["check"])
    check_duration = Gauge("honeypot_sentinel_check_duration_seconds", "Sentinel check duration", ["check"])
    overall_status = Gauge("honeypot_sentinel_status", "Overall sentinel status (1=pass, 0=fail)")
    start_http_server(port)

    def update(results: List[CheckResult]) -> None:
        for result in results:
            check_status.labels(result.name).set(1 if result.passed else 0)
            check_duration.labels(result.name).set(result.duration_ms / 1000)
        overall_status.set(1 if all(result.passed for result in results) else 0)

    return update


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate honeypot reachability and isolation")
    parser.add_argument("--config", help="Path to a YAML sentinel configuration")
    parser.add_argument("--timeout", type=float, default=2.0, help="TCP/HTTP timeout in seconds")
    parser.add_argument("--metrics-port", type=int, help="Serve Prometheus metrics on this port")
    parser.add_argument("--interval", type=float, default=60.0, help="Metrics refresh interval in seconds")
    parser.add_argument("--json", action="store_true", help="Print machine-readable results")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        config = load_config(args.config)
        update_metrics = start_metrics_server(args.metrics_port) if args.metrics_port else None
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"sentinel error: {exc}", file=sys.stderr)
        return 2

    while True:
        try:
            results = run_checks(config, args.timeout)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"sentinel error: {exc}", file=sys.stderr)
            return 2
        if update_metrics:
            update_metrics(results)
            time.sleep(args.interval)
            continue

        report = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "passed": all(result.passed for result in results),
            "checks": [result.as_dict() for result in results],
        }
        if args.json:
            print(json.dumps(report, sort_keys=True))
        else:
            for result in results:
                marker = "PASS" if result.passed else "FAIL"
                print(f"[{marker}] {result.name}: {result.details}")
        return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())