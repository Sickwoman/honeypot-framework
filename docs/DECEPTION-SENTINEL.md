# Deception Sentinel

The deception sentinel verifies that configured honeypot ports are reachable,
management services are not listening on the honeypot host, and Elasticsearch
is healthy from the monitoring host.

## Run once

From the monitoring host:

```bash
export ELASTICSEARCH_PASSWORD='your-password'
python3 scripts/deception-sentinel.py \
  --config config/sentinel-policy.yml \
  --json
```

The process returns exit code `0` only when every configured check passes. It
returns `1` for a failed check and `2` for a configuration or runtime error.

## Prometheus mode

```bash
python3 scripts/deception-sentinel.py \
  --config config/sentinel-policy.yml \
  --metrics-port 8010 \
  --interval 60
```

The default `config/prometheus.yml` already scrapes `localhost:8010` as the
`deception-sentinel` job.

The process keeps running, refreshes the checks every interval, and serves the
latest metrics. Manage it with a systemd service or container supervisor.

Prometheus loads the matching rules from `config/alert_rules.yml` and alerts
when the sentinel fails, a honeypot probe is unreachable, a management port is
exposed, or sentinel metrics disappear.

## Safety notes

- Run it from the monitoring host, never from an exposed honeypot service.
- Keep the honeypot address in `forbidden_ports`; these checks ensure management
  services are not accidentally running there.
- The checks only open TCP connections and query Elasticsearch health.
- Set `verify_tls: true` after trusted CA configuration is available.