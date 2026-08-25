#!/bin/sh
# =============================================================================
# Invoked by pam_exec during the auth phase of the relay front-end.
# PAM sets PAM_USER / PAM_RHOST in the environment; the offered password arrives
# on stdin via `expose_authtok`. We emit a single JSON `cred_attempt` event.
#
# This DELIBERATELY records attacker-supplied credentials -- that capture is the
# honeypot's purpose. It logs attacker input only, never any secret of ours.
# The username/password are JSON-escaped (backslash + double-quote) before
# interpolation so a crafted value cannot break out of the JSON string.
# =============================================================================
set -eu
LOGFILE=/var/log/pqc-honeypot/events.json

# authtok (password) is the first line on stdin; may be absent for empty pw.
IFS= read -r password 2>/dev/null || password=""

esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
u=$(esc "${PAM_USER:-}")
h=$(esc "${PAM_RHOST:-}")
p=$(esc "$password")

printf '{"event":"cred_attempt","variant":"relay","username":"%s","password":"%s","src_ip":"%s"}\n' \
    "$u" "$p" "$h" | tee -a "$LOGFILE" >/dev/null

exit 0   # never block: we want the hand-off to proceed regardless
