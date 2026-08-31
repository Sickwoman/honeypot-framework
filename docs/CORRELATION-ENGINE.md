# Attack Correlation Engine

Links related attacks across honeypots and time. The engine reads alerts from
the same SQLite database used by the REST API (`api/alerts_service.py`, the
`alerts` table) and groups related alerts into **attack campaigns**.

Source: [`analytics/correlation_engine.py`](../analytics/correlation_engine.py),
[`analytics/attack_graph.py`](../analytics/attack_graph.py).
Rules: [`config/correlation_rules.yml`](../config/correlation_rules.yml).

## Correlation types

| Type | What it finds | Default severity |
|------|---------------|------------------|
| `multi_target_actor`   | One source IP attacking **multiple honeypots/services** | HIGH |
| `coordinated_campaign` | **Many source IPs** hitting one service inside a short window (botnet / password-spray) | HIGH |
| `attack_chain`         | One IP progressing through kill-chain **phases over time** (recon → access → exploitation → exfiltration) | CRITICAL |
| `shared_indicator`     | Otherwise-unrelated alerts sharing a **threat indicator (IOC)** | MEDIUM |

Each campaign records the correlated `alert_ids`, the `source_ips`, a `score`
(higher = stronger signal), the time span, and rule-specific `details`.

## Data source

The engine reads these `alerts` columns: `source_ip`, `honeypot_type`,
`service_name`, `threat_indicators` (JSON array), `severity`, `first_seen` /
`last_seen`, `alert_name`, `description`. No Elasticsearch, pandas, or Docker is
required — just the alert database and the standard library (plus PyYAML for the
config file, already in `requirements.txt`).

## Configuration

All thresholds live in [`config/correlation_rules.yml`](../config/correlation_rules.yml)
and can be tuned without touching code. If the file (or PyYAML) is missing, the
engine falls back to the identical built-in defaults in
`DEFAULT_CONFIG`, so it always runs.

Key knobs:

- `lookback_hours` — only correlate recent alerts (`0` = whole table).
- `multi_target_actor.min_targets` — distinct honeypots/services to flag an actor.
- `coordinated_campaign.window_minutes` / `min_sources` — window size and the
  distinct-IP count that defines a coordinated wave.
- `attack_chain.max_gap_minutes` / `min_phases` — max gap between phases and how
  many distinct phases make a chain.
- `shared_indicator.min_alerts` — how many alerts must share an IOC.
- `attack_phases` — ordered kill-chain phases, each matched by `services` and
  description `keywords`.

## Command-line usage

```bash
# Human-readable summary (uses ALERTS_DB_PATH / api.config for the DB path)
python -m analytics.correlation_engine

# Explicit database + whole-table analysis, JSON output
python -m analytics.correlation_engine --db /var/lib/honeypot/alerts.db \
  --lookback 0 --format json

# Emit a Graphviz graph and render it
python -m analytics.correlation_engine --format dot > graph.dot
dot -Tpng graph.dot -o graph.png

# Persist correlated campaigns into the `incidents` table
python -m analytics.correlation_engine --persist
```

`--format` accepts `text` (default), `json`, or `dot`.

## REST API

Correlations are also reachable through the authenticated API, guarded by the
RBAC `stats:read` permission (observer and above — see
[`docs/RBAC-POLICY.md`](RBAC-POLICY.md)):

```bash
curl -s "https://localhost:8443/api/v1/correlations?lookback=24&graph=true" \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "analyzed_alerts": 128,
  "campaign_count": 3,
  "campaigns": [
    {
      "correlation_type": "attack_chain",
      "severity": "CRITICAL",
      "title": "Attack chain from 9.9.9.9: reconnaissance -> exploitation",
      "alert_ids": ["..."],
      "source_ips": ["9.9.9.9"],
      "attack_phase": "exploitation",
      "score": 2.0,
      "details": {"source_ip": "9.9.9.9", "phases": ["reconnaissance", "exploitation"]}
    }
  ],
  "graph": { "nodes": [ ... ], "edges": [ ... ] }
}
```

Add `?graph=true` to include an attack-graph representation (source IPs →
campaigns → targets/IOCs) suitable for front-end visualization.

## Persisting to incidents

`persist_as_incidents()` (CLI `--persist`) writes each campaign into the
`incidents` table (`database/schema.sql`) with `created_by = "correlation-engine"`,
the correlation type as `category`, the kill-chain phase as `attack_phase`, and
the correlated alert IDs as the JSON `alert_ids` array — so campaigns show up in
the existing incident workflow.

## Attack graph

`analytics/attack_graph.py` builds a directed graph from campaigns:

- **Nodes**: source IPs, campaigns, targets (honeypots/services), and indicators.
- **Edges**: `source_ip → campaign` (relation = correlation type),
  `campaign → target`, `campaign → ioc`.

Export with `to_dict()`, `to_json()`, or `to_dot()` (Graphviz). If `networkx`
is installed, `to_networkx()` returns a `DiGraph`; it is an optional enhancement,
never a hard dependency.

## Extending

1. Add a rule config block under `rules:` in `correlation_rules.yml` (and to
   `DEFAULT_CONFIG` in `correlation_engine.py`).
2. Implement a `_your_rule(self, alerts)` method returning `List[AttackCampaign]`
   via `self._make_campaign(...)`.
3. Call it from `CorrelationEngine.correlate()` behind its `enabled` flag.
4. Add a test to [`tests/test_correlation.py`](../tests/test_correlation.py).

## Testing

```bash
python -m pytest tests/test_correlation.py -v
```

The tests build a temporary database from the real `database/schema.sql`,
insert crafted alerts, and assert each rule fires (and stays quiet below its
threshold), plus incident persistence and graph export.
