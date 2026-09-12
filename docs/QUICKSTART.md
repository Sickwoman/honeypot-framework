# Quickstart

Run the whole framework locally with Docker: a real Cowrie SSH honeypot, the
log ingestor, the RBAC-protected alert API, and the Nightwatch dashboard.

> **Status:** the Compose stack and its Dockerfiles are authored but have not
> been built end-to-end by the maintainer (no Docker on the dev machine). If
> you hit a build error, please open an issue — the individual pieces are
> tested (`pytest`, `npm run build`) but the assembled stack is not yet
> verified. See [Without Docker](#without-docker) for the parts that are.

## 1. Configure

```bash
cp .env.example .env
```

Set a JWT signing key — the API refuses to start without one:

```bash
python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(32))" >> .env
```

Optionally set `ADMIN_PASSWORD` in `.env`. If you leave it blank a strong
random password is generated and printed **once** in the API logs.

## 2. Start the stack

```bash
docker compose up --build
```

| Service | Where | What it is |
|---|---|---|
| Cowrie honeypot | `localhost:2222` | The trap. Point attack traffic here. |
| Nightwatch dashboard | http://localhost:8080 | Operator UI |
| Alert API | http://localhost:8000 | REST API (`/health` needs no auth) |

The ingestor tails Cowrie's log, turns events into alerts, and those alerts
automatically fire any matching playbook in `playbooks/`.

Elasticsearch, Kibana and Logstash are **optional** — the core loop stores
alerts in SQLite and doesn't need them:

```bash
docker compose --profile elk up    # adds ES :9200 and Kibana :5601
```

## 3. Log in

Get the bootstrap admin password (skip if you set `ADMIN_PASSWORD`):

```bash
docker compose logs api | grep -i "password"
```

Get a token:

```bash
curl -s -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}'
```

In the dashboard, click the ⚙ button and paste the `token` value. Until you
do, the dashboard shows clearly-labeled demo data rather than live alerts.

## 4. Generate some attacks

Without a public IP you won't get real attackers, so drive traffic yourself:

```bash
# Brute-force the honeypot; each attempt becomes an alert
for i in $(seq 1 10); do
  sshpass -p "wrong$i" ssh -o StrictHostKeyChecking=no \
    -o PreferredAuthentications=password \
    -p 2222 root@localhost 2>/dev/null
done
```

Then watch alerts arrive:

```bash
curl -s http://localhost:8000/api/v1/alerts \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

> Alerts produced this way come from your own traffic, not real attackers.
> Don't present them as captured attack data.

## Without Docker

The API itself runs fine with no containers -- verified end to end (login,
RBAC, alert creation, playbook loading) against a plain `python -m flask` /
`app.run()` process:

```bash
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(32))" >> .env

pytest                          # 91 tests
ruff check .                    # lint
cd frontend && npm ci && npm run build && npm test   # 31 tests
```

To actually serve the API without Docker (e.g. to drive traffic at it with
curl while developing), run it directly rather than via the `if __name__`
block in `api/alerts_service.py` -- that block forces TLS and calls
`validate_production()`, which is meant for a real deployment, not a laptop:

```bash
python3 -c "
from api.alerts_service import app
app.run(host='127.0.0.1', port=8000, use_reloader=False)
"
```

Then `curl http://127.0.0.1:8000/health` and log in as described in step 3
above (the bootstrap admin password is printed to stderr on first run).

Config precedence: a real environment variable always wins over `.env` --
`.env` only fills in whatever isn't already set. So `ALERTS_DB_PATH=/tmp/x.db
python3 ...` overrides the `.env` default without editing the file.

## Troubleshooting

**API exits with "JWT_SECRET_KEY is not set"** — expected. Set it in `.env`;
there is deliberately no default.

**Dashboard shows demo data** — you haven't set a token (step 3), or the API
is unreachable. Check `curl http://localhost:8000/health`.

**No alerts appearing** — confirm Cowrie is writing:
`docker compose exec cowrie ls -l /cowrie/cowrie-git/var/log/cowrie/`, then
check the ingestor: `docker compose logs ingestor`. The ingestor starts
tailing at end-of-file, so only activity *after* it starts becomes an alert.

**"database is locked"** — the API and ingestor share one SQLite file. WAL
mode is enabled to avoid this; if it persists, move to PostgreSQL (see the
commented block in `requirements.txt`).
