# Live alert ingestion and automatic playbook execution

The framework now includes an ingestion pipeline that watches raw honeypot logs and converts suspicious events into real alerts. Because alert creation automatically triggers matching playbooks, this gives you true automated incident response without manual intervention.

## Components

- `monitoring/live_alert_ingestor.py` — reads Cowrie/OpenCanary logs and parses suspicious events
- `api/alerts_service.py` — creates alerts and triggers matching playbooks automatically
- `playbooks/*.yml` — response definitions that run when alert conditions match

## How it works

1. The ingestor reads a log file incrementally.
2. It parses known suspicious patterns such as:
   - Cowrie SSH `trying auth` failures
   - Cowrie `wget`/`curl`/command-exec attempts
   - OpenCanary credential capture events
   - OpenCanary suspicious HTTP path probes
3. It creates a real alert through the framework API/service.
4. Alert creation triggers `trigger_matching_playbooks()`.
5. Matching playbooks execute automatically.

## Recommended usage

Run the ingestor as a background process:

```bash
python3 monitoring/live_alert_ingestor.py
```

Or call it programmatically:

```python
from monitoring.live_alert_ingestor import ingest_honeypot_line

alert_id = ingest_honeypot_line(
    '2026-09-01T12:00:00+00:00 [SSHService ssh-userauth] trying auth ...',
)
print(alert_id)
```

## Example behavior

A Cowrie log line containing `trying auth` creates an alert named `SSHBruteForce`.
The default playbook `ssh-bruteforce-block` matches that alert and automatically:

- notifies responders,
- blocks the source IP,
- creates an incident record.
