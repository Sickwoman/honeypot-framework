# Step 4 — PQC front-end → Cowrie hand-off (Docker-Compose prototype)

Implements **Option B** from [`../COWRIE-HANDOFF.md`](../COWRIE-HANDOFF.md): a
post-quantum OpenSSH **relay** terminates the ML-KEM handshake and captures
credentials, then relays the "authenticated" session into **Cowrie** for the
fake shell + command/TTY logging. Cowrie can't speak PQC itself, so it stays the
deception backend behind a PQC front door.

```
attacker ──PQC SSH (ML-KEM kex)──▶  relay  (public :2225, Debian+OpenSSH≥9.9)
                                     • logs kex_negotiated (post_quantum:true)
                                     • captures creds via PAM (cred_attempt)
                                     • accepts ANY username (libnss-ato)
                                     • ForceCommand → relay.sh
                                          │  (deception net: internal, no egress)
                                          ▼
                                     cowrie (internal :2222, no host port)
                                     • fake shell, command + TTY logging
```

## Run

```bash
docker compose -f docker-compose.handoff.yml up --build -d
./verify-handoff.sh
```

`verify-handoff.sh` forces `mlkem768x25519-sha256` to the relay, offers junk
creds, runs `id`, and asserts the relay logged the PQC kex + captured creds +
handed off, and that Cowrie logged the shell command. (Needs Docker + `sshpass`
on the client host.)

## How each requirement is met

| Requirement | Mechanism |
|---|---|
| Terminate a **post-quantum** handshake | Debian trixie OpenSSH ≥ 9.9; `KexAlgorithms mlkem768x25519-sha256,…` |
| Log the negotiated kex | reused [`../entrypoint.sh`](../entrypoint.sh) → `kex_negotiated` event |
| Accept **any** username | `libnss-ato` maps unknown users → the `sensor` account (glibc NSS; musl/Alpine can't) |
| Capture the password | PAM `pam_exec.so expose_authtok` → [`relay/capture-creds.sh`](relay/capture-creds.sh) → `cred_attempt` |
| Reach Cowrie's shell | `ForceCommand` → [`relay/relay.sh`](relay/relay.sh) → `sshpass ssh root@cowrie` (userdb accepts root/any) |
| Correlate the two logs | relay mints `session_id` (conn 4-tuple + PID), logs `handoff`, offers it via `SetEnv=SESSION_ID` |
| Isolation | `deception` network is `internal: true` (no egress); relay `cap_drop: ALL`, `no-new-privileges` |

Events land in the `handoff-logs` volume at `/var/log/pqc-honeypot/events.json`
— same schema as the base variants, so the existing
[`../logstash-pqc.conf`](../logstash-pqc.conf) pipeline ingests them unchanged
(new `event` types: `cred_attempt`, `handoff`).

## Status & honest limitations

- **Authored, NOT run here** — no Docker on the dev machine. `verify-handoff.sh`
  is the one-command proof on a Docker host.
- **`cowrie/cowrie:latest`** is unpinned and the `userdb.txt`/log paths assume
  the current image layout (`/cowrie/cowrie-git/…`); confirm + pin on first run.
- **Cleartext credential logging is intended** (attacker input, not our secrets)
  — the honeypot's purpose. Restrict access to the `handoff-logs` volume.
- **`PermitRootLogin yes`** maximizes data fidelity; the session is contained by
  `ForceCommand` + `cap_drop` + `no-new-privileges` + no forwarding, and the OS
  identity is the unprivileged `sensor` (via libnss-ato), not real root.
- **`session_id` correlation** is best-effort: it's logged on the relay and
  offered to Cowrie via `SetEnv`; whether Cowrie persists it depends on its
  config. Fallback join key = timestamp + the relay being the only client IP
  Cowrie sees.

## Production hardening (deferred from this prototype)
Pin all images by digest; move creds off the shared JSON into a restricted sink;
add `read_only` + explicit `tmpfs` to the relay; consider replacing `sshpass`
with a key-based hop; rate-limit the front door upstream (not in-container).
