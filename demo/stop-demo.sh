#!/bin/bash
# Stop the demo. Captured alerts are kept for next time.
cd "$(dirname "$0")/.."
docker rm -f honeypot-tunnel >/dev/null 2>&1 || true
docker compose down

# Turn Cloudflare WARP back off, but only if start-demo turned it on.
WARP_CLI="/mnt/c/Program Files/Cloudflare/Cloudflare WARP/warp-cli.exe"
WARP_MARKER="demo/.warp-turned-on-by-demo"
if [ -f "$WARP_MARKER" ] && [ -x "$WARP_CLI" ]; then
  "$WARP_CLI" disconnect >/dev/null 2>&1 && echo "Turned Cloudflare WARP back off."
  rm -f "$WARP_MARKER"
fi

echo
echo "Stopped. Captured alerts are kept. 'docker compose down -v' would erase them."
