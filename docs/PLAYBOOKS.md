# Incident Response Playbooks

The framework includes a lightweight playbook engine for automated response workflows. Playbooks are YAML definitions that match alert conditions and execute ordered actions such as block IPs, notify responders, isolate a honeypot, or create incidents.

## Example

```yaml
id: ssh-bruteforce-block
name: SSH Brute Force Block
description: Blocks the IP and notifies the SOC after SSH brute force activity.
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
    message: "{{ source_ip }} attempted SSH brute force"
  - id: block_ip_1
    type: block_ip
    name: block_attacker
    duration: 24h
```

## Supported actions

- `block_ip`
- `notify`
- `create_incident`
- `isolate_honeypot`
- `run_script`
- `http_request`
- `delay`

## Default playbooks

The framework ships with:

- `ssh_bruteforce_block.yml`
- `port_scan_isolate.yml`

## API usage

List playbooks:

```bash
curl -X GET https://localhost:8443/api/v1/playbooks \
  -H "Authorization: Bearer <token>"
```

Execute a playbook:

```bash
curl -X POST https://localhost:8443/api/v1/playbooks/ssh-bruteforce-block/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_data": {
      "id": "alert-1",
      "alert_name": "SSHBruteForce",
      "severity": "HIGH",
      "source_ip": "203.0.113.50",
      "honeypot_type": "cowrie",
      "service_name": "ssh"
    },
    "dry_run": true
  }'
```

## Notes

- `dry_run` validates the playbook and action flow without blocking traffic or sending notifications.
- The executor stores execution metadata in the alert database and logs action results in the local logs directory.
