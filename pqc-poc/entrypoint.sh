#!/bin/sh
# =============================================================================
# Multi-variant SSH honeypot -- entrypoint
# =============================================================================
# Selected by the VARIANT env var: classical | hybrid | pqc-only.
#   1. Picks /etc/ssh/sshd_config.$VARIANT
#   2. Ensures an ed25519 host key exists (regenerated per run when on tmpfs)
#   3. Runs sshd (foreground, DEBUG1) and turns each negotiated-KEX log line
#      into a structured JSON event, written to BOTH stdout and
#      /var/log/pqc-honeypot/events.json (the latter is what Logstash tails).
#
# POSIX sh (busybox ash on Alpine). No bashisms.
# =============================================================================
set -eu

VARIANT="${VARIANT:-hybrid}"
KEYDIR=/etc/ssh/keys
CONF="/etc/ssh/sshd_config.${VARIANT}"
LOGDIR=/var/log/pqc-honeypot
LOGFILE="${LOGDIR}/events.json"

[ -f "$CONF" ] || { echo "FATAL: unknown VARIANT '$VARIANT' (no $CONF)" >&2; exit 2; }
mkdir -p "$KEYDIR" "$LOGDIR"

if [ ! -f "$KEYDIR/ssh_host_ed25519_key" ]; then
    ssh-keygen -t ed25519 -f "$KEYDIR/ssh_host_ed25519_key" -N "" -C "pqc-honeypot-$VARIANT" >/dev/null
fi
chmod 600 "$KEYDIR/ssh_host_ed25519_key"

# Emit a JSON event to stdout AND append it to the tailed log file.
emit() { printf '%s\n' "$1" | tee -a "$LOGFILE"; }

port=$(awk '/^Port /{print $2; exit}' "$CONF")
emit "{\"event\":\"honeypot_start\",\"variant\":\"${VARIANT}\",\"port\":${port:-0}}"

# -D foreground, -e log to stderr. Fold stderr into the pipe and parse it.
/usr/sbin/sshd -D -e -f "$CONF" 2>&1 | while IFS= read -r line; do
    printf '%s\n' "$line" >&2          # keep the raw sshd line for forensics
    case "$line" in
        *"kex: algorithm:"*)
            # e.g. "debug1: kex: algorithm: mlkem768x25519-sha256 [preauth]"
            kex=${line##*kex: algorithm: }
            kex=${kex%% *}
            case "$kex" in
                *mlkem*|*sntrup*|*kyber*) pq=true ;;
                *)                        pq=false ;;
            esac
            emit "{\"event\":\"kex_negotiated\",\"variant\":\"${VARIANT}\",\"kex_algorithm\":\"${kex}\",\"post_quantum\":${pq}}"
            ;;
    esac
done
