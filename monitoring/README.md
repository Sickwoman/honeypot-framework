# Monitoring & Log Aggregation

## Components

**Live alert ingestor** — [`live_alert_ingestor.py`](live_alert_ingestor.py)

Tails honeypot logs, converts events into alert payloads, and inserts them via
`AlertService`. Because alert creation triggers matching playbooks, an ingested
event immediately drives incident-response automation.

It tails every configured log concurrently (one thread each), starts at
end-of-file so a restart doesn't replay history, and waits for a log file to
appear rather than exiting if the honeypot hasn't written yet.

```bash
# Paths from argv, else $HONEYPOT_LOG_PATHS, else the built-in defaults
python -m monitoring.live_alert_ingestor /path/to/cowrie.log
```

| Variable | Default | Purpose |
|---|---|---|
| `HONEYPOT_LOG_PATHS` | Cowrie + OpenCanary defaults | Comma/colon-separated log paths |
| `INGESTOR_WAIT_FOR_LOGS` | `true` | Wait for missing log files instead of exiting |
| `INGESTOR_READ_FROM_START` | `false` | Replay existing log content on start |
| `INGESTOR_POLL_SECONDS` | `2.0` | Poll interval |
| `HONEYTOKEN_MANIFEST` | unset | Enables honeytoken tripwire detection |

**Terminal dashboard** — [`honeypot_dashboard.py`](honeypot_dashboard.py)

A print-based summary of Cowrie/OpenCanary logs, kept for quick shell use. The
[Nightwatch web dashboard](../frontend/) supersedes it for day-to-day work.

## Running the stack

The ELK stack lives in the repo-root [`docker-compose.yml`](../docker-compose.yml)
behind an optional profile (this directory previously held a second, separate
compose file that bind-mounted host paths which don't exist on most machines):

```bash
docker compose --profile elk up     # Elasticsearch :9200, Kibana :5601, Logstash
```

The Logstash pipeline is [`config/logstash-secure.conf`](../config/logstash-secure.conf),
the canonical config — it reads Cowrie's structured `cowrie.json` and
OpenCanary's JSON log, and ships to Elasticsearch over TLS with credentials
from the environment.

Note the core alert loop does **not** require Elasticsearch: alerts are stored
in SQLite by `api/alerts_service.py`. ELK adds search and Kibana dashboards on
top of the raw honeypot logs.

## Log formats

- **Cowrie** — `cowrie.log` is plain text (what the ingestor parses);
  `cowrie.json` is structured (what Logstash consumes).
- **OpenCanary** — JSON, with source/destination IPs, ports, and credentials.

See [docs/QUICKSTART.md](../docs/QUICKSTART.md) for the full walkthrough.
