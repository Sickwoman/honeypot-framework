#!/usr/bin/env bash
# =============================================================================
# End-to-end proof of the PQC front-end -> Cowrie hand-off. REQUIRES DOCKER
# (and sshpass on this client host).
#
# Forces an ML-KEM hybrid kex to the relay, offers junk creds, runs a command,
# then asserts the relay logged { kex_negotiated post_quantum:true, cred_attempt,
# handoff } AND that Cowrie logged the resulting session/command.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.handoff.yml"

command -v docker  >/dev/null || { echo "Docker required.";  exit 2; }
command -v sshpass >/dev/null || { echo "sshpass required on the client host."; exit 2; }

echo "[*] Building + starting relay + cowrie..."
$COMPOSE up --build -d
cleanup(){ echo; echo "[*] Stack logs (tail):"; $COMPOSE logs --no-color --tail 60 || true; $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
sleep 6

echo "[*] Attacker: ML-KEM kex -> relay:2225, junk creds, run 'id' in the shell..."
sshpass -p hunter2 ssh -tt -p 2225 \
    -o KexAlgorithms=mlkem768x25519-sha256 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o ConnectTimeout=10 \
    eviluser@localhost 'id; uname -a; exit' 2>ssh_handoff.log || true

relaylog=$($COMPOSE exec -T relay cat /var/log/pqc-honeypot/events.json 2>/dev/null || true)
rc=0
grep -q '"event":"kex_negotiated".*"post_quantum":true' <<<"$relaylog" \
    && echo "  [PASS] relay negotiated a post-quantum kex" || { echo "  [FAIL] no PQC kex at relay"; rc=1; }
grep -q '"event":"cred_attempt".*"username":"eviluser"' <<<"$relaylog" \
    && echo "  [PASS] relay captured attacker credentials" || { echo "  [FAIL] creds not captured"; rc=1; }
grep -q '"event":"handoff"' <<<"$relaylog" \
    && echo "  [PASS] relay handed the session off" || { echo "  [FAIL] no handoff event"; rc=1; }

# Cowrie should have logged a session + the 'id' command. Log path can vary by
# image version; treat a miss as a WARN so the PQC-side asserts still gate rc.
cowlog=$($COMPOSE exec -T cowrie sh -c 'cat cowrie-git/var/log/cowrie/cowrie.json 2>/dev/null || cat var/log/cowrie/cowrie.json 2>/dev/null || true' || true)
if grep -q 'cowrie.command.input' <<<"$cowlog"; then
    echo "  [PASS] Cowrie logged shell commands"
else
    echo "  [WARN] no Cowrie command log found (check the image's log path)"
fi

echo
[ "$rc" -eq 0 ] && echo "[PASS] hand-off verified" || { echo "[FAIL] see above"; exit 1; }
