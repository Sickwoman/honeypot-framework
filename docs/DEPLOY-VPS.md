# Deploying to a public VPS — capturing real attacks

This is the runbook for getting the honeypot in front of the actual internet on
a cheap VPS, so it captures real attacker traffic instead of your own
simulated traffic. Everything here uses the same Docker stack that CI builds
and smoke-tests on every push (see [QUICKSTART.md](QUICKSTART.md)); the only new
work is exposure and host hardening.

> **What "real results" requires.** A honeypot only sees real attackers when it
> sits on a public IP and waits for the internet to find it. There is no
> shortcut and no simulation that substitutes for it. `scripts/simulate-attacks.sh`
> is a pipeline check, not attack data — do not present its output as captured
> attacks. This document is how you get the real thing.

---

## Before you start

- **A VPS with a public IPv4.** A $4–6/month instance (DigitalOcean, Hetzner,
  Vultr, Linode) with 1 GB RAM is enough for the core stack. Skip the ELK
  profile on a box this size — it wants far more RAM and you don't need it to
  capture attacks.
- **Check the provider's acceptable-use policy.** Most allow honeypots; a
  couple don't. Two minutes now avoids a suspended account later.
- **Treat this box as disposable and isolated.** It is deliberately exposing a
  door to the internet. Use a throwaway VPS with no credentials, keys, or
  network access to anything you care about. Cowrie gives attackers a *fake*
  shell (an emulator, not your real host), but the host's own management ports
  still have to be locked down — which is most of what this runbook does.

---

## 1. The trap-vs-management port problem (read this first)

Real SSH scanners hammer **port 22**. If you leave Cowrie on 2222 you'll get a
fraction of the traffic. So you want Cowrie on 22 — but that's also the port
*you* use to administer the box. Putting both on 22 locks the trap and yourself
onto the same door.

The fix: **move your own SSH to a high port first, then give 22 to Cowrie.**

On the VPS, edit the real SSH daemon:

```bash
sudo sed -i 's/^#\?Port .*/Port 2202/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

**Open a second terminal and confirm you can still get in on the new port
BEFORE you close your current session:**

```bash
ssh -p 2202 youruser@YOUR_VPS_IP
```

Only once that works should you continue. If you lock yourself out, most
providers offer a web console to recover.

---

## 2. Firewall: only the trap faces the world

Install Docker and Docker Compose (provider one-liners exist; on Ubuntu
`curl -fsSL https://get.docker.com | sh`), then set up `ufw` so that **only
Cowrie is public** and the API/dashboard are reachable only by you.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow 2202/tcp comment 'my SSH admin'   # your real SSH
sudo ufw allow 22/tcp   comment 'cowrie trap'    # the honeypot, public

# API and dashboard: bind to your IP only, never the world.
# Replace 203.0.113.5 with your home/office IP (curl ifconfig.me).
sudo ufw allow from 203.0.113.5 to any port 8000 proto tcp comment 'alert API - me only'
sudo ufw allow from 203.0.113.5 to any port 8080 proto tcp comment 'dashboard - me only'

sudo ufw enable
sudo ufw status numbered
```

If your home IP is dynamic, an SSH tunnel is safer than a firewall hole — see
the note at the end.

---

## 3. Configure the stack

```bash
git clone https://github.com/Sickwoman/honeypot-framework.git
cd honeypot-framework
cp .env.example .env
```

Edit `.env` and set these:

```bash
# Required — the API refuses to start without it.
JWT_SECRET_KEY=<paste output of: python3 -c "import secrets;print(secrets.token_urlsafe(32))">

# Put Cowrie on 22 so real scanners find it. This is the whole point.
COWRIE_PORT=22

# Set a real admin password so you're not fishing it out of the logs.
ADMIN_PASSWORD=<a long random password you'll keep>

# Optional but worth it: free API keys that enrich each source IP with
# reputation data. Makes the captured results much more interesting.
ABUSEIPDB_API_KEY=<free key from abuseipdb.com>
VT_API_KEY=<free key from virustotal.com>
```

Leave `API_HOST_PORT=8000` and `DASHBOARD_HOST_PORT=8080` as they are — the
firewall above is what keeps them private.

---

## 4. Launch and confirm

```bash
docker compose up -d --build
docker compose ps          # every service should be "Up"
curl -fsS http://localhost:8000/health   # {"status":"healthy",...}
```

Confirm Cowrie is actually listening on 22 from *outside* the box (run this
from your laptop, not the VPS):

```bash
ssh -p 22 root@YOUR_VPS_IP    # you should get Cowrie's fake prompt, not a real login
```

---

## 5. Watch real attacks arrive

Open the dashboard from your machine (allowed by the firewall rule):

```
http://YOUR_VPS_IP:8080
```

Log in with `admin` / the `ADMIN_PASSWORD` you set, via Settings → paste a token
from:

```bash
curl -s -X POST http://YOUR_VPS_IP:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_ADMIN_PASSWORD"}'
```

Then watch. Internet background scanning is relentless — on port 22 you
typically see the first automated login attempts **within minutes to an hour**.
Within a day you'll have real captured credentials, real source IPs, and real
post-login commands.

Tail it live from the shell too:

```bash
docker compose logs -f ingestor    # alerts being created from Cowrie events
docker compose logs -f cowrie      # raw session activity
```

---

## 6. Pull results out for a writeup

Once real data has accumulated, the report generators turn it into something
presentable (they read from Elasticsearch, so this step needs the ELK profile —
see below — or you can query the SQLite alert store directly):

```bash
# Straight from the alert API — real numbers, no ELK needed:
curl -s http://YOUR_VPS_IP:8000/api/v1/alerts?limit=500 \
  -H "Authorization: Bearer $TOKEN" > captured-alerts.json
```

Every alert carries the real source IP, service, captured credentials, and
(if you set the threat-intel keys) reputation enrichment. That JSON is your
evidence.

---

## Notes

- **Dynamic home IP?** Don't open 8000/8080 to the world. Instead SSH-tunnel
  them over your admin port:
  ```bash
  ssh -p 2202 -L 8080:localhost:8080 -L 8000:localhost:8000 youruser@YOUR_VPS_IP
  ```
  then use `http://localhost:8080` locally. Remove the two `ufw allow from ...`
  rules entirely.
- **Costs.** The core stack on a 1 GB VPS is a few dollars a month. Leave it up
  for a week or two to gather a meaningful dataset, then `docker compose down`
  and destroy the VPS.
- **ELK is optional and heavy.** The core capture loop stores alerts in SQLite
  and needs no Elasticsearch. Only add
  `-f docker-compose.yml -f docker-compose.elk.yml` on a box with real RAM
  (≥4 GB) if you specifically want Kibana dashboards.
