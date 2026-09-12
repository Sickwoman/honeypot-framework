# Compliance Evidence Collection

> **This project has not been audited, and nothing here is an attestation of
> compliance.** It is a personal honeypot framework. A real SOC 2, PCI-DSS or
> HIPAA position requires an independent assessor plus organizational policies,
> personnel controls and evidence retention that live entirely outside this
> repository. What this repo provides is a script that collects *some* of the
> technical evidence such an audit would ask for.

[`scripts/compliance-reporter.py`](../scripts/compliance-reporter.py) queries
Elasticsearch for honeypot and audit events, evaluates nine technical controls,
and emits an evidence trail as JSON, CSV and PDF.

## What it actually checks

Nine controls — three per standard. This is the complete list; anything else
you have seen mapped in older versions of these docs was aspirational.

### SOC 2

| Control | Name | Evidence collected | Passes when |
|---|---|---|---|
| `CC6.1` | Logical Access Controls | Authentication events, last 30 days | Auth events exist and <10% failed |
| `CC7.1` | Change Management | Configuration change events | Changes are logged |
| `A1.1` | Availability | Service uptime / health events | Availability data present |

### PCI-DSS

| Control | Name | Evidence collected | Passes when |
|---|---|---|---|
| `REQ1` | Network Segmentation | Network/connection events | Segmentation evidence present |
| `REQ4` | Encryption in Transit | TLS/transport events | Encrypted transport observed |
| `REQ10` | Logging & Monitoring | Log volume and coverage | Logging is active |

### HIPAA Security Rule

| Control | Name | Evidence collected |
|---|---|---|
| `164.312(a)(2)(i)` | Unique User Identification | Per-user access events |
| `164.312(b)` | Audit Controls | Audit log coverage |
| `164.312(a)(2)(ii)` | Encryption & Decryption | Encryption configuration evidence |

Each check produces a `ComplianceEvidence` record: control id, standard,
evidence type, the underlying data, a pass/fail status, a severity, and a
remediation string. Read the checks themselves — they are short — before
relying on any result.

## Running it

Requires a reachable Elasticsearch with honeypot data indexed, and credentials
in the environment (there is no default password):

```bash
export ELASTICSEARCH_URL=https://localhost:9200
export ELASTICSEARCH_PASSWORD=...

python3 scripts/compliance-reporter.py --standard SOC2
python3 scripts/compliance-reporter.py --standard ALL
```

Output lands in `compliance_reports/<STANDARD>/<timestamp>/`:

| File | Contents |
|---|---|
| `evidence.json` | Full evidence trail, machine-readable |
| `evidence.csv` | Same, spreadsheet-friendly |
| `report.pdf` | Formatted report (needs `reportlab`) |

Options: `--es-url`, `--username`, `--password` override the environment;
`--no-verify-ssl` disables TLS verification (don't).

## Honest limitations

- **Nine controls is not a framework.** SOC 2 alone has dozens of criteria;
  PCI-DSS has twelve requirement families. The gap is not an oversight to be
  filled in later — most of it is organizational, not technical.
- **Pass/fail thresholds are heuristics** chosen by this project (e.g. "fewer
  than 10% failed logins"), not criteria from any standard.
- **Evidence quality depends entirely on what you feed Elasticsearch.** With no
  honeypot data indexed, checks fail for lack of evidence rather than because a
  control is broken.
- **The data is honeypot traffic** — deliberately exposed decoy systems. Be
  careful about reasoning from it to the security posture of real systems.

## If you want to go further

The genuinely useful direction is not more markdown, it is more collected
evidence: wire `audit_log` (already populated by `api/middleware.py`) into the
reporter, and add checks that read from it rather than only from Elasticsearch.

## History

This replaced seven overlapping documents (`COMPLIANCE-SOC2.md`,
`COMPLIANCE-PCI-DSS.md`, `COMPLIANCE-HIPAA.md`, `COMPLIANCE-INDEX.md`,
`COMPLIANCE-README.md`, `COMPLIANCE-QUICK-REFERENCE.md`,
`COMPLIANCE-TEMPLATES.md`) totalling ~2,900 lines. They described control-by-
control mappings that no code implemented and, until recently, ended in status
tables marking controls "✓ Pass" against a date that predated the project.
