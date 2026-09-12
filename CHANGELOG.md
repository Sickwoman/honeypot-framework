# Changelog

What has actually shipped, newest first. Roadmap and open work live in
[ROADMAP.md](ROADMAP.md).

## Unreleased

### Added
- One-command local stack: `docker compose up --build` runs Cowrie, the log
  ingestor, the alert API and the Nightwatch dashboard together. Elasticsearch,
  Kibana and Logstash sit behind an optional `--profile elk`.
  ([docs/QUICKSTART.md](docs/QUICKSTART.md))
- CI (`.github/workflows/ci.yml`): pytest on Python 3.11 and 3.12 with
  coverage, ruff, mypy (advisory), the frontend build, and a shell-script
  syntax pass. Previously nothing ran the test suite.
- Route-level API tests covering all protected endpoints through the real
  Flask app: RBAC enforcement, the full alert lifecycle, validation and 404
  paths, and that 500s don't leak internal detail.
- Ingestor tests covering multi-log tailing, waiting for a log that doesn't
  exist yet, and not replaying history on restart.
- `requirements-dev.txt` and `pyproject.toml` (ruff/mypy/pytest config).
- `scripts/expire-firewall-blocks.py`: removes expired playbook firewall
  rules, so automated blocks are no longer permanent.

### Fixed
- **`pip install -r requirements.txt` failed outright.** Four pinned versions
  didn't exist on PyPI (`openpyxl==3.10.10`, `PyJWT==2.8.1`, `uuid6==1.0.3`,
  plus `PyJWT` pinned twice at conflicting versions) and two more had no wheel
  for current Python. Requirements are now scoped to what the code imports;
  ~22 never-imported packages moved to a commented optional section.
- **The ingestor only ever monitored the first configured log** — the loop
  never reached the second path because tailing blocks forever. Each log now
  gets its own thread.
- **The ingestor replayed the whole log on every restart**, duplicating every
  alert. Live tailing now starts at end-of-file.
- The ingestor gave up when a log file didn't exist yet — the normal case when
  the honeypot and ingestor start together. It now waits.
- Importing `api.middleware` required write access to a root-owned log
  directory, making the API un-importable as an unprivileged user.
- The test suite wrote to real system paths (`/var/lib/honeypot`,
  `/var/log/honeypot`) and failed to collect without them.
- SQLite now uses WAL and a busy timeout: the API and ingestor are separate
  processes sharing one database file.
- `config/logstash-secure.conf` parsed `cowrie.log` with a JSON codec, but
  that file is plain text — the structured log is `cowrie.json`.
- OpenCanary's decoy SSH and the PQC SSH honeypot both bound port 2223, so
  co-provisioning silently dropped one. OpenCanary moved to 2224.
- `make test` ran attack simulations instead of the test suite (now
  `make simulate`); removed a hardcoded `~/Desktop` path from `make validate`.
- README's architecture diagram wasn't code-fenced, so GitHub rendered 49
  box-drawing lines as mangled prose.
- All 435 ruff findings, including a `dataclasses.field` import shadowed by a
  loop variable, dead code in the rate-limit decorator, bare excepts, and nine
  exception re-raises that dropped the original cause.
- **`.env` was silently ignored unless you ran from the repo root.** `api/auth.py`
  reads `JWT_SECRET_KEY` from `os.environ` at import time, before anything
  loads `.env` — and `ConfigManager` resolved `.env` and `database/schema.sql`
  relative to the current working directory, not the repo. Following the
  Quickstart's `cp .env.example .env` and then running the API from anywhere
  else raised `JWT_SECRET_KEY is not set` or `no such table: users` with no
  clue why. Added `api/env.py`, which loads the repo-root `.env` on import of
  `api.auth`, and made every schema/data path (`database/schema.sql`,
  `playbooks/`, the default alerts DB) resolve from the repo root regardless
  of cwd.
- **A real environment variable was silently overridden by `.env`.** `.env`
  loaded with `override=True`, so e.g. an explicitly-exported `ALERTS_DB_PATH`
  was discarded in favor of `.env`'s default and the API wrote to
  `/var/lib/honeypot/alerts.db` anyway, with no warning. `.env` now only fills
  in what isn't already set.
- `playbooks/playbook_executor.py` crashed on import if `./logs` (relative to
  the current working directory) wasn't writable — the same class of bug
  already fixed in `api/middleware.py`. Now best-effort, like the API logger.

### Security
- **Command injection in the auto-response playbook.** `BlockIPHandler` built
  a shell string from attacker-controlled `source_ip` and ran it with
  `shell=True`. Now validated with `ipaddress.ip_address()` and run as an
  argument list.
- **`IsolateHoneypotHandler` issued a blanket `iptables -I INPUT -j DROP`**,
  cutting off management access with no rollback. Now scoped to honeypot
  service ports, with an expiry.
- **The JWT signing secret silently fell back to a hardcoded default.** The API
  now refuses to start without `JWT_SECRET_KEY`.
- **A placeholder login endpoint accepted any username/password** and issued a
  valid analyst+responder token. Removed.
- **Rate limiting never worked** — a fresh limiter was constructed per request,
  so the counter was always empty. Login is now rate-limited and accounts lock
  after repeated failures.
- API keys were held in a per-process dict; they now persist (hashed) in the
  database, so they survive restarts and work across workers.
- Removed hardcoded `elastic`/`changeme` credentials and
  `verify_certs=False` defaults from ~15 scripts and the monitoring configs;
  credentials now come from the environment with no insecure fallback.
- API error responses no longer return raw exception text to callers.
- Path traversal in playbook save/delete (filenames were built from the
  user-supplied playbook name).
- Unescaped attacker-controlled data in alert emails, in a dashboard HTML
  attribute, and in outbound threat-intel request URLs.
- Audit events now persist to the `audit_log` table rather than only a logger.

### Changed
- Documentation consolidated: seven overlapping `COMPLIANCE-*.md` files
  (~2,900 lines describing controls no code implemented) replaced by one
  honest [docs/COMPLIANCE.md](docs/COMPLIANCE.md); four overlapping status
  trackers replaced by this file and [ROADMAP.md](ROADMAP.md).
- Removed unsubstantiated claims: "100+ attacks logged", fabricated SOC 2 /
  PCI-DSS / HIPAA "✓ Pass" tables, and invented ML precision/recall figures
  with no evaluation code behind them.

## Earlier work

Reconstructed from commit history; dates omitted where unreliable.

- **Incident response** — command center and attack replay UI.
- **Nightwatch dashboard** — TypeScript/Vite operator console (`frontend/`).
- **Deception** — honeytoken tripwires, deception sentinel monitoring, attack
  story engine.
- **Compliance reporting** — evidence collection for nine technical controls.
- **Threat intelligence** — AbuseIPDB/VirusTotal enrichment and live alert
  scoring.
- **Automation** — playbook response engine and live honeypot log ingestion.
- **Correlation** — attack correlation engine and attack graph.
- **RBAC** — roles, permissions and the `require_permission` decorator.
- **Post-quantum SSH honeypot** (`pqc-poc/`) — observes which attackers
  negotiate PQC key exchange. Authored and locally verified for crypto
  primitives; containers not yet built.
- **Monitoring** — Prometheus/Grafana, Slack/Discord/email/webhook
  integrations.
- **Infrastructure** — Terraform for AWS single- and multi-region deployment.
