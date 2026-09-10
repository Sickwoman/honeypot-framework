#!/usr/bin/env python3

################################################################################
# Honeypot Framework - Firewall Block Expiry
# Removes iptables rules added by playbook actions (block_ip, isolate_honeypot)
# once their configured duration has elapsed.
#
# Without this, every automated block is permanent: the playbook records a
# "duration" but nothing ever deletes the rule. Run from cron (see
# config/honeypot-crontab).
################################################################################

import ipaddress
import json
import os
import subprocess
import sys
from datetime import datetime

RULES_FILE = os.getenv(
    'HONEYPOT_FIREWALL_RULES_FILE', '/etc/honeypot-framework/firewall-rules.jsonl'
)


def build_delete_command(entry):
    """Return the iptables -D command undoing `entry`, or None if unsupported."""
    rule_type = entry.get('type')

    if rule_type == 'block_ip':
        ip = str(ipaddress.ip_address(str(entry['ip'])))
        return ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']

    if rule_type == 'isolate_honeypot':
        port = int(entry['port'])
        return ['sudo', 'iptables', '-D', 'INPUT', '-p', 'tcp',
                '--dport', str(port), '-j', 'DROP']

    return None


def remove_rule(entry) -> bool:
    try:
        cmd = build_delete_command(entry)
    except (KeyError, ValueError):
        # Malformed journal entry: no rule we can safely delete.
        return False

    if not cmd:
        return False

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"failed to remove rule {entry}: {result.stderr.strip()}", file=sys.stderr)
        return False
    return True


def main() -> int:
    if not os.path.exists(RULES_FILE):
        return 0

    now = datetime.utcnow()
    remaining = []
    removed = 0

    with open(RULES_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                print(f"skipping malformed journal line: {line!r}", file=sys.stderr)
                continue

            expires_at = entry.get('expires_at')
            try:
                expiry = datetime.fromisoformat(expires_at) if expires_at else None
            except ValueError:
                expiry = None

            if expiry and expiry <= now and remove_rule(entry):
                removed += 1
                continue

            # Still active, or removal failed -- keep it so the next run retries.
            remaining.append(entry)

    tmp_file = RULES_FILE + '.tmp'
    with open(tmp_file, 'w') as f:
        for entry in remaining:
            f.write(json.dumps(entry) + "\n")
    os.replace(tmp_file, RULES_FILE)

    print(f"Expired {removed} firewall rule(s); {len(remaining)} still active")
    return 0


if __name__ == '__main__':
    sys.exit(main())
