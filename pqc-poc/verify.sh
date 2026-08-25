#!/usr/bin/env bash
# =============================================================================
# End-to-end verification of ALL running honeypot variants. REQUIRES DOCKER.
#
# Builds + starts the stack, then for each variant connects while forcing an
# appropriate key exchange and asserts the honeypot logged the expected
# `kex_negotiated` event:
#     classical (2222)  -- forces curve25519       -> expect post_quantum:false
#     hybrid    (2223)  -- forces mlkem768x25519    -> expect post_quantum:true
# Authentication is expected to FAIL; key exchange happens first and is all we
# are measuring.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

command -v docker >/dev/null || { echo "Docker not found. Use ./local-verify.sh for the no-Docker primitive proof."; exit 2; }

echo "[*] Building + starting stack..."
docker compose up --build -d
cleanup(){ echo; echo "[*] Stack logs (tail):"; docker compose logs --no-color --tail 40 || true; docker compose down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
sleep 3

# variant | service | port | forced kex | expected post_quantum
CASES="classical|classical|2222|curve25519-sha256|false
hybrid|hybrid|2223|mlkem768x25519-sha256|true"

rc=0
# here-string (not a pipe) so $rc updates survive the loop
while IFS='|' read -r variant service port kex expect; do
    echo
    echo "=== $variant : port $port : forcing $kex (expect post_quantum:$expect) ==="
    ssh -vv -p "$port" \
        -o KexAlgorithms="$kex" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=8 \
        probe@localhost true 2>"ssh_${variant}.log" || true

    echo "  client negotiated: $(grep -Eo 'kex: algorithm: [^ ]+' "ssh_${variant}.log" | head -1 || echo '??')"

    ev=$(docker compose logs --no-color "$service" 2>/dev/null | grep -m1 '"event":"kex_negotiated"' || true)
    echo "  honeypot event  : ${ev:-<none>}"
    if printf '%s' "$ev" | grep -q "\"post_quantum\":$expect"; then
        echo "  [PASS] $variant negotiated as expected"
    else
        echo "  [FAIL] $variant did not report post_quantum:$expect"
        rc=1
    fi
done <<EOF
$CASES
EOF

echo
[ "$rc" -eq 0 ] && echo "[PASS] all variants verified" || { echo "[FAIL] see above"; exit 1; }
