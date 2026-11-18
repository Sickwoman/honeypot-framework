#!/bin/bash
# Start the honeypot demo: the Docker stack, a public link to the dashboard,
# and a live feed of alerts in this window.
#
# Run it from Windows by double-clicking demo\start-demo.cmd.
#
# Keep the window open for the whole demo. WSL shuts Ubuntu down (and Docker
# and the honeypot with it) shortly after its last open window closes.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Waiting for Docker..."
for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 1; done

echo "==> Starting the honeypot stack (Cowrie, ingestor, API, dashboard)..."
docker compose up -d --build

echo "==> Waiting for the API..."
for _ in $(seq 1 60); do
  curl -fsS http://localhost:8000/health >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://localhost:8000/health >/dev/null || {
  echo "The API did not come up. See: docker compose logs api"; exit 1;
}

# Public HTTPS link to the dashboard through a Cloudflare quick tunnel. No
# account is needed; the link changes every time this script runs. Only the
# dashboard is published. The SSH trap stays reachable from this laptop only.
#
# Some networks block trycloudflare.com (the connection gets reset). If that
# happens and Cloudflare WARP is installed, turn WARP on, which gets around the
# block. stop-demo turns it back off only if this script turned it on.
WARP_CLI="/mnt/c/Program Files/Cloudflare/Cloudflare WARP/warp-cli.exe"
WARP_MARKER="demo/.warp-turned-on-by-demo"
tunnel_api_reachable() {
  [ "$(curl -s -m 8 -o /dev/null -w '%{http_code}' https://api.trycloudflare.com/ || true)" != "000" ]
}
echo "==> Opening a public link to the dashboard..."
if ! tunnel_api_reachable && [ -x "$WARP_CLI" ]; then
  if ! "$WARP_CLI" status 2>/dev/null | grep -q "Status update: Connected"; then
    echo "    This network blocks Cloudflare tunnels. Turning on Cloudflare WARP..."
    "$WARP_CLI" connect >/dev/null 2>&1 && touch "$WARP_MARKER"
    for _ in $(seq 1 20); do tunnel_api_reachable && break; sleep 1; done
  fi
fi
docker rm -f honeypot-tunnel >/dev/null 2>&1 || true
docker run -d --name honeypot-tunnel --network honeypot-framework_default \
  cloudflare/cloudflared:latest tunnel --no-autoupdate --url http://dashboard:80 >/dev/null
PUBLIC_URL=""
for _ in $(seq 1 45); do
  # Skip api.trycloudflare.com: it appears in the log when the request fails.
  PUBLIC_URL=$(docker logs honeypot-tunnel 2>&1 | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' \
    | grep -v '^https://api\.' | head -1 || true)
  [ -n "$PUBLIC_URL" ] && break
  sleep 1
done

# Log in as admin (password from .env) to get a token for the dashboard.
ADMIN_PASSWORD=$(grep -E '^ADMIN_PASSWORD=' .env | tail -1 | cut -d= -f2- | tr -d '\r')
LOGIN_BODY=$(python3 -c 'import json, sys; print(json.dumps({"username": "admin", "password": sys.argv[1]}))' "$ADMIN_PASSWORD")
TOKEN=$(curl -fsS -X POST http://localhost:8000/auth/login -H 'Content-Type: application/json' -d "$LOGIN_BODY" \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])') || TOKEN=""
COPIED=""
if [ -n "$TOKEN" ] && printf '%s' "$TOKEN" | clip.exe 2>/dev/null; then
  COPIED=" (it is already on your clipboard)"
fi

cat <<MSG

==================================================================
 HONEYPOT DEMO IS RUNNING
==================================================================
 Dashboard, this laptop:  http://localhost:8080
 Dashboard, public link:  ${PUBLIC_URL:-not available (the local one still works)}
 SSH honeypot (the trap): ssh -p 2222 root@localhost

 To see live alerts: open the dashboard, click the gear button,
 paste this token${COPIED}, and save:

${TOKEN:-LOGIN FAILED, check ADMIN_PASSWORD in .env}

 To attack the honeypot, double-click demo\\attack-demo.cmd, or run
   ssh -p 2222 root@localhost
 in PowerShell. Password 123456 is rejected; almost any other
 password gets in to Cowrie's FAKE shell.

 KEEP THIS WINDOW OPEN. Closing it stops the honeypot.
==================================================================
 New alerts appear below as the honeypot catches them:

MSG

docker compose logs -f --tail=0 --no-log-prefix ingestor 2>&1 \
  | grep --line-buffered -E "Created alert|Playbook execution completed"
