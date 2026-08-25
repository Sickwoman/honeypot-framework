#!/bin/sh
# =============================================================================
# ForceCommand on the relay front-end. Runs after the front-end "accepts" the
# login. Mints a session_id, logs the hand-off, then opens a second SSH hop into
# Cowrie over the internal-only network. Cowrie provides the fake shell and its
# own command/TTY logging; correlate on session_id + timestamp + src.
#
# Defaults below match the compose service name, so this works even though sshd
# does not export the daemon's environment into the forced session.
# =============================================================================
set -eu
LOGFILE=/var/log/pqc-honeypot/events.json
COWRIE_HOST="${COWRIE_HOST:-cowrie}"
COWRIE_PORT="${COWRIE_PORT:-2222}"

# session_id without Date/random: connection 4-tuple from sshd + our PID.
conn="${SSH_CONNECTION:-0 0 0 0}"
sid="$(printf '%s' "$conn" | tr ' .' '__')_$$"

esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
printf '{"event":"handoff","variant":"relay","session_id":"%s","src":"%s","cowrie":"%s:%s"}\n' \
    "$(esc "$sid")" "$(esc "$conn")" "$COWRIE_HOST" "$COWRIE_PORT" \
    | tee -a "$LOGFILE" >/dev/null

# Hand the session to Cowrie. Cowrie accepts root/any-password (see userdb.txt),
# so sshpass drives it non-interactively. SESSION_ID is offered via SetEnv so a
# joiner can line up this relay event with the Cowrie session if Cowrie logs it.
exec sshpass -p relay ssh -tt \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o SetEnv="SESSION_ID=$sid" \
    -p "$COWRIE_PORT" "root@${COWRIE_HOST}"
