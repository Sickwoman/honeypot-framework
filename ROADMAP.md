# Roadmap

What's planned and what's still open. What already shipped is in
[CHANGELOG.md](CHANGELOG.md).

Status is deliberately honest: items are marked done only when code in this
repo implements them, not when a design for them exists.

## Open — security hardening

These are the gaps that matter most; several are also tracked in
[SECURITY-CHECKLIST.md](SECURITY-CHECKLIST.md).

| Item | Status | Notes |
|---|---|---|
| End-to-end TLS | ⬜ Open | The API can serve TLS (`SSL_API_CERT_PATH`), and `scripts/generate-ssl-certificates.sh` issues a local CA, but the full chain — honeypot → Logstash → Elasticsearch → Kibana → API → browser — is not verified end to end. |
| Encryption at rest | ⬜ Open | Honeypot logs and the SQLite alert store are unencrypted. S3 SSE and CloudWatch retention are configured in Terraform but unverified against a live deployment. |
| MFA for operator accounts | ⬜ Open | `users` has `mfa_enabled` / `mfa_secret` columns; nothing implements TOTP enrolment or verification. |
| Secrets management | ⬜ Open | Credentials come from `.env`. A real deployment should use AWS Secrets Manager or Vault. |
| Independent penetration test | ⬜ Open | Never performed. |

## Open — operability

| Item | Status | Notes |
|---|---|---|
| Verify the Docker stack end to end | ⬜ Open | `docker-compose.yml` and its images are authored but have never been built — Docker isn't installed on the dev machine. First person with Docker should run `docker compose up --build` and report breakage. |
| Real captured attack data | ⬜ Open | The framework has never faced live internet traffic. Everything downstream — correlation, attack stories, the ML scripts — has only ever seen synthetic input. A cheap public VPS for a week or two would be the single highest-value addition to this project. |
| ML model evaluation | ⬜ Open | `scripts/ml-anomaly-detection.py` runs Isolation Forest and DBSCAN, but the models are unsupervised with no labelled ground truth, so there are no real precision/recall numbers. See [docs/ML-ANALYTICS.md](docs/ML-ANALYTICS.md). |
| PostgreSQL option | ⬜ Open | SQLite is fine for a single host; the driver pins are ready but commented out in `requirements.txt`. |
| Frontend test coverage | ⬜ Open | `frontend/src/main.ts` is untested, including the `esc()` XSS guard. |
| Consolidate duplicated scripts | ⬜ Open | Three report generators re-implement the same Elasticsearch aggregations; four separate Slack/Discord/email notifier implementations exist. |

## Open — AWS deployment

Terraform for single- and multi-region AWS is written and validated in CI, but
has not been applied against a live account. Prerequisites before a first
`terraform apply`:

- AWS account activated with billing verified and free-tier eligibility confirmed
- IAM user for Terraform with least-privilege policy; `aws configure` completed
- An EC2 key pair created and referenced in `terraform.tfvars`
- S3 bucket for remote state (names are globally unique and region-suffixed)
- CloudWatch alarms and SNS topics for alerting

Deployment guide: [docs/PHASE2-DEPLOYMENT.md](docs/PHASE2-DEPLOYMENT.md).

## Longer term

Not started, roughly in order of how much they'd add:

1. **Post-quantum honeypot expansion** — `pqc-poc/` observes which attackers
   negotiate PQC key exchange. This is the most genuinely novel thing here;
   building the containers and collecting real kex data would make it
   publishable.
2. **Log retention & archival policies** — lifecycle rules, cold storage,
   defensible deletion.
3. **Behavioural analytics** — session-level attacker profiling rather than
   per-event scoring.
4. **SOAR integration** — push incidents to TheHive/Cortex or similar instead
   of the built-in playbook runner alone.
5. **Zero-trust network segmentation** — stronger isolation guarantees between
   the honeypot and any management plane.
6. **Kubernetes deployment** — Helm chart as an alternative to Compose.
7. **Multi-cloud** — Azure and GCP alongside AWS.
8. **Advanced visualisation** — attack-graph rendering in the dashboard.
9. **Attack simulation platform** — a richer harness than
   `scripts/simulate-attacks.sh`.
10. **Mobile alerting** — push notifications; likely not worth it over
    Slack/webhook delivery that already exists.

## Non-goals

- **Being a compliance product.** The reporter collects evidence for nine
  technical controls; it is not an audit tool. See
  [docs/COMPLIANCE.md](docs/COMPLIANCE.md).
- **Production use as-is.** This is a lab and portfolio project. Treat the open
  security items above as blocking for anything else.
