# Attack Stories

The Attack Story Engine turns correlated alerts into an incident narrative.
Each story contains:

- an ordered timeline of observed alerts;
- normalized attack phases such as reconnaissance, access, and exploitation;
- source IPs, severity, and a transparent confidence score;
- evidence references back to the original alert IDs;
- response recommendations based only on observed phases.

Generate a readable report:

```bash
python3 analytics/attack_story.py --db /var/lib/honeypot/alerts.db
```

Generate JSON for an API, dashboard, or case-management workflow:

```bash
python3 analytics/attack_story.py \
  --db /var/lib/honeypot/alerts.db \
  --json > attack-stories.json
```

The engine is deterministic and evidence-linked. It does not claim attacker
intent beyond the phases and alerts already present in the correlation data.