import os
import tempfile

import pytest

from api import alerts_service as alerts_module
from api.rbac import Permission, Role, ROLE_PERMISSIONS
from playbooks.playbook_model import PlaybookDefinition, PlaybookManager
from playbooks.playbook_executor import PlaybookExecutor


VALID_PLAYBOOK = """
id: brute-force-block
name: Block SSH brute force
description: Blocks an IP after repeated SSH failures
trigger:
  type: alert
  conditions:
    alert_name: SSHBruteForce
    severity: HIGH
actions:
  - id: block_ip_1
    type: block_ip
    name: block ssh attacker
    duration: 24h
  - id: notify_1
    type: notify
    channels: [email]
    recipient: soc@example.com
    message: "{{ source_ip }} attempted SSH brute force"
"""


def test_playbook_schema_validates_basic_definition():
    playbook = PlaybookDefinition.from_yaml_string(VALID_PLAYBOOK)
    assert playbook.id == "brute-force-block"
    assert playbook.trigger["type"] == "alert"
    assert len(playbook.actions) == 2


def test_playbook_manager_loads_yaml_files(tmp_path):
    playbook_path = tmp_path / "custom.yml"
    playbook_path.write_text(VALID_PLAYBOOK, encoding="utf-8")

    manager = PlaybookManager(str(tmp_path))
    assert len(manager.list_playbooks()) == 1
    assert manager.get_playbook("brute-force-block").name == "Block SSH brute force"


def test_executor_can_run_dry_run_for_matching_alert(tmp_path):
    manager = PlaybookManager(str(tmp_path))
    manager.create_playbook(PlaybookDefinition.from_yaml_string(VALID_PLAYBOOK).to_dict())

    executor = PlaybookExecutor(manager, db_path=str(tmp_path / "playbooks.db"))
    alert = {
        "id": "alert-1",
        "alert_name": "SSHBruteForce",
        "severity": "HIGH",
        "source_ip": "203.0.113.50",
        "honeypot_type": "cowrie",
        "service_name": "ssh",
    }

    results = executor.find_and_execute(alert, alert_id="alert-1", dry_run=True)
    assert len(results) == 1
    assert results[0].status.value == "success"
    assert results[0].actions_results[0].status.value == "success"


def test_playbook_permissions_are_defined():
    assert Permission.PLAYBOOKS_READ in ROLE_PERMISSIONS[Role.OBSERVER]
    assert Permission.PLAYBOOKS_EXECUTE in ROLE_PERMISSIONS[Role.RESPONDER]


def test_alert_creation_triggers_matching_playbooks(tmp_path, monkeypatch):
    playbook_dir = tmp_path / "playbooks"
    playbook_dir.mkdir()
    (playbook_dir / "match.yml").write_text(
        """
id: match-alert
name: Match alert
description: Example trigger
trigger:
  type: alert
  conditions:
    alert_name: SSHBruteForce
    severity: HIGH
actions:
  - id: notify_1
    type: notify
    channels: [email]
    recipient: soc@example.com
    message: "alert"
""",
        encoding="utf-8",
    )

    manager = PlaybookManager(str(playbook_dir))
    executor = PlaybookExecutor(manager, db_path=str(tmp_path / "alerts.db"))
    monkeypatch.setattr(alerts_module, "playbook_manager", manager)
    monkeypatch.setattr(alerts_module, "playbook_executor", executor)

    service = alerts_module.AlertService(db_path=str(tmp_path / "alerts.db"))
    alert_id = service.create_alert({
        "alert_name": "SSHBruteForce",
        "severity": "HIGH",
        "source_ip": "198.51.100.12",
        "honeypot_type": "cowrie",
        "service_name": "ssh",
    })

    executions = alerts_module.trigger_matching_playbooks({
        "id": alert_id,
        "alert_name": "SSHBruteForce",
        "severity": "HIGH",
        "source_ip": "198.51.100.12",
        "honeypot_type": "cowrie",
        "service_name": "ssh",
    }, alert_id)

    assert len(executions) == 1
    assert executions[0].playbook_name == "Match alert"
