"""Tests for the live honeypot log ingestor's tailing behavior.

These cover the operational bugs that made the ingestor unusable as a
long-running service (it is the component the Docker stack runs continuously):
  * only the first configured log was ever monitored
  * a missing log file made it give up instead of waiting for the honeypot
  * every restart replayed the whole log, duplicating alerts
"""
import threading
import time

from monitoring.live_alert_ingestor import (
    DEFAULT_LOG_PATHS,
    _resolve_log_paths,
    tail_log_file,
)

COWRIE_BRUTE_FORCE = (
    "2026-09-10T10:00:00+0000 [HoneyPotSSHTransport,0,203.0.113.45] "
    "trying auth b'password'\n"
)


# --------------------------------------------------------------------------- #
# Log path resolution
# --------------------------------------------------------------------------- #
def test_paths_come_from_argv_first(monkeypatch):
    monkeypatch.setenv("HONEYPOT_LOG_PATHS", "/from/env.log")
    assert _resolve_log_paths(["/from/argv.log"]) == ["/from/argv.log"]


def test_paths_fall_back_to_env(monkeypatch):
    monkeypatch.setenv("HONEYPOT_LOG_PATHS", "/a.log,/b.log")
    assert _resolve_log_paths([]) == ["/a.log", "/b.log"]


def test_paths_fall_back_to_defaults(monkeypatch):
    monkeypatch.delenv("HONEYPOT_LOG_PATHS", raising=False)
    assert _resolve_log_paths([]) == list(DEFAULT_LOG_PATHS)


# --------------------------------------------------------------------------- #
# Tailing
# --------------------------------------------------------------------------- #
def test_tail_reads_existing_content_when_from_start(tmp_path):
    log = tmp_path / "cowrie.log"
    log.write_text(COWRIE_BRUTE_FORCE, encoding="utf-8")

    lines = list(tail_log_file(str(log), stop_after_lines=1, from_start=True))

    assert lines == [COWRIE_BRUTE_FORCE]


def test_tail_skips_existing_content_when_not_from_start(tmp_path):
    """A restart must not replay the log and duplicate every alert in it."""
    log = tmp_path / "cowrie.log"
    log.write_text(COWRIE_BRUTE_FORCE, encoding="utf-8")

    collected = []

    def consume():
        for line in tail_log_file(
            str(log), poll_seconds=0.01, stop_after_lines=1, from_start=False
        ):
            collected.append(line)

    worker = threading.Thread(target=consume, daemon=True)
    worker.start()
    time.sleep(0.2)

    # Nothing yet: the pre-existing line was skipped.
    assert collected == []

    with log.open("a", encoding="utf-8") as handle:
        handle.write("2026-09-10T10:00:01+0000 [x,1,198.51.100.9] trying auth b'password'\n")

    worker.join(timeout=3)
    assert len(collected) == 1
    assert "198.51.100.9" in collected[0]


def test_tail_gives_up_on_missing_file_by_default(tmp_path):
    missing = tmp_path / "not-there.log"

    assert list(tail_log_file(str(missing), poll_seconds=0.01)) == []


def test_tail_waits_for_a_file_that_appears_later(tmp_path):
    """The ingestor starts before the honeypot has written anything."""
    log = tmp_path / "late.log"
    collected = []

    def consume():
        for line in tail_log_file(
            str(log),
            poll_seconds=0.01,
            stop_after_lines=1,
            from_start=True,
            wait_for_file=True,
        ):
            collected.append(line)

    worker = threading.Thread(target=consume, daemon=True)
    worker.start()
    time.sleep(0.2)

    assert collected == []  # still waiting, not exited

    log.write_text(COWRIE_BRUTE_FORCE, encoding="utf-8")

    worker.join(timeout=3)
    assert collected == [COWRIE_BRUTE_FORCE]
