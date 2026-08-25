# Decision: PQC front-end → Cowrie hand-off

**Question:** the PoC proves we can negotiate a post-quantum SSH handshake and
log the algorithm — but a bare `sshd` isn't a honeypot. How do we keep the
**PQC handshake + credential capture** *and* get Cowrie's rich post-auth
deception (fake filesystem, command logging)?

## Why not just "add PQC to Cowrie"

Cowrie implements SSH itself in Python via Twisted `conch`. `conch` has **no
ML-KEM / SNTRUP** and no OpenSSL/liboqs binding for the transport, so it cannot
negotiate a post-quantum key exchange. Patching PQC primitives into `conch` is
a large, fragile effort with no upstream path. **Rejected.**

## Options considered

| Option | PQC handshake | Cowrie deception | Verdict |
|---|---|---|---|
| A. Patch Cowrie/conch for PQC | ✔ (huge effort) | ✔ | Rejected — infeasible |
| B. PQC OpenSSH front terminates SSH, relays authed session into Cowrie | ✔ | ✔ | **Recommended** |
| C. PQC OpenSSH front with its own `ForceCommand` fake shell (no Cowrie) | ✔ | ✗ (low fidelity) | Fallback |
| D. Two separate endpoints (PQC front *and* classical Cowrie), no relay | ✔ (front only) | ✔ (separately) | Simplest, loses per-session linkage |

## Recommended architecture (Option B)

```
attacker ──PQC SSH (ML-KEM kex)──▶  OpenSSH front-end (this PoC's image)
                                     • negotiates + logs the PQC kex
                                     • captures the offered credentials
                                     • ForceCommand: ssh into the backend
                                          │
                                          ▼  (isolated internal docker network)
                                     Cowrie  ── classical SSH, fake shell,
                                                 command + session logging
```

- The **front-end** is exactly the container in this directory. It owns the
  post-quantum handshake and the `kex_negotiated` event, and is where the
  attacker's **username/password attempts are logged** (auth happens at the
  front).
- After "auth", the front-end's `ForceCommand` opens a second SSH hop to
  **Cowrie** on an internal-only network (no host port). Cowrie provides the
  emulated shell and logs commands/downloads as it does today.
- Correlate the two logs on a shared `session_id` (front-end generates it and
  passes it to the backend, e.g. via `SendEnv`/a wrapper) so each session's
  PQC handshake, credentials, and shell activity join up.

### Trade-offs / open items
- The front→Cowrie hop is classical SSH inside an isolated network — acceptable
  (the PQC property is a client-facing measurement, not an internal transport
  requirement).
- Credential capture at OpenSSH needs a custom PAM module or an
  `AuthorizedKeysCommand`/auth-logging shim — Cowrie captures creds natively, so
  if front-end cred capture proves fiddly, let Cowrie capture creds and keep the
  front-end purely for the PQC handshake + relay.
- Egress from both containers stays blocked (honeypot isolation).

## Next implementation step
Prototype B with a two-service compose (front-end + Cowrie on an internal
network), wire `session_id` correlation, and confirm a forced ML-KEM client
reaches the Cowrie shell end-to-end.
