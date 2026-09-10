import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "deception-sentinel.py"
SPEC = importlib.util.spec_from_file_location("deception_sentinel", MODULE_PATH)
sentinel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sentinel)


def test_forbidden_port_fails_when_endpoint_is_reachable(monkeypatch):
    monkeypatch.setattr(sentinel, "tcp_connect", lambda host, port, timeout: True)

    result = sentinel.check_forbidden_port("management", "127.0.0.1", 9200, 0.1)

    assert result.passed is False
    assert "accepted a connection" in result.details


def test_forbidden_port_passes_when_endpoint_refuses(monkeypatch):
    def refuse(host, port, timeout):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(sentinel, "tcp_connect", refuse)

    result = sentinel.check_forbidden_port("management", "127.0.0.1", 9200, 0.1)

    assert result.passed is True


def test_run_checks_includes_all_configured_checks(monkeypatch):
    monkeypatch.setattr(sentinel, "check_tcp", lambda *args: sentinel.CheckResult("honeypot", True, "ok", 1))
    monkeypatch.setattr(sentinel, "check_forbidden_port", lambda *args: sentinel.CheckResult("forbidden", True, "ok", 1))
    monkeypatch.setattr(sentinel, "check_elasticsearch", lambda *args: sentinel.CheckResult("elasticsearch_health", True, "ok", 1))

    results = sentinel.run_checks(
        {
            "honeypots": [{"name": "ssh", "host": "host", "port": 2222}],
            "forbidden_ports": [{"name": "es", "host": "host", "port": 9200}],
            "elasticsearch": {"enabled": True},
        },
        0.1,
    )

    assert [result.name for result in results] == ["honeypot", "forbidden", "elasticsearch_health"]