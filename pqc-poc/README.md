# PQC SSH Honeypot — Multi-Variant Proof of Concept

De-risks and builds out the **cryptographic core** of the post-quantum honeypot
plan: SSH endpoints that genuinely negotiate a post-quantum handshake, log the
algorithm each attacker's client used, and feed the framework's ELK pipeline —
across three comparable **variants** for A/B(/C) research.

## Variants

| Variant | Port | Key exchange | Base image | Purpose |
|---|---|---|---|---|
| `classical` | 2222 | classical only (curve25519, ecdh, dh) | Alpine + stock OpenSSH | control group |
| `hybrid` | 2223 | ML-KEM-768 + X25519 (`mlkem768x25519-sha256`) | Alpine + stock OpenSSH | measure PQC-capable clients |
| `pqc-only` | 2224 | pure PQC, **no** classical fallback | OQS-OpenSSH (opt-in) | measure "hard" PQC failures |

The key finding that makes this cheap: **classical and hybrid differ only by one
`KexAlgorithms` line** — modern OpenSSH (≥ 9.9) + OpenSSL (≥ 3.5) do ML-KEM
hybrid natively. **No liboqs / OQS-OpenSSL is needed** except for the pure
`pqc-only` variant (which needs OQS-OpenSSH). OQS-OpenSSL is for *TLS*, not SSH,
and is dropped from the SSH path.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | classical + hybrid (stock OpenSSH); variant chosen by `VARIANT` env |
| `Dockerfile.pqc-only` | pure-PQC variant on OQS-OpenSSH (authored, unverified) |
| `sshd_config.classical` / `.hybrid` / `.pqc-only` | per-variant kex + honeypot hardening |
| `entrypoint.sh` | picks config by `VARIANT`, runs sshd, emits `kex_negotiated` JSON |
| `docker-compose.yml` | runs classical + hybrid side-by-side; shared log volume; opt-in pqc-only & logstash |
| `logstash-pqc.conf` | pipeline into the framework's `honeypot-*` Elasticsearch index |
| `kibana-dashboard-pqc.json` | Kibana saved-object: PQC-vs-classical dashboard (6 panels) |
| `local-verify.sh` | **no Docker** — offline crypto-primitive proof (runs today) |
| `verify.sh` | **Docker** — end-to-end handshake proof for every variant |
| `COWRIE-HANDOFF.md` | decision: how the PQC front-end feeds Cowrie for post-auth capture |

## Run

```bash
# 1. Primitive proof — works right now, no Docker:
./local-verify.sh

# 2. Full multi-variant handshake — on any Docker host:
docker compose up --build -d      # classical:2222 + hybrid:2223
./verify.sh                       # asserts classical->post_quantum:false, hybrid->true
```

Each connection produces a single-line JSON event (also written to
`/var/log/pqc-honeypot/events.json` for Logstash):

```json
{"event":"kex_negotiated","variant":"hybrid","kex_algorithm":"mlkem768x25519-sha256","post_quantum":true}
```

That `post_quantum` boolean per connection is the core research signal: **which
attacker tools already speak post-quantum SSH, and which fall back to classical.**

## Verification status (dev machine)

- ✅ **`local-verify.sh` — PASS (offline, no Docker).** ML-KEM-768 round-trip
  secrets matched (ciphertext 1088 B, secret 32 B); `ssh -Q kex` lists
  `mlkem768x25519-sha256`; ML-DSA-44/65/87 present in OpenSSL 3.5.7. Shell
  scripts pass `bash -n`.
- ⚠️ **Containers — AUTHORED, NOT BUILT HERE.** Docker is not installed on the
  dev machine. `Dockerfile`/`docker-compose.yml`/`verify.sh` are ready; run
  `./verify.sh` on a Docker host to close this gap. `Dockerfile.pqc-only` uses
  the only published OQS tag (`latest`, ~12 mo old); its pure-PQC kex names
  (`mlkem768-sha256`, `kyber-768-sha384`) are now verified against the
  open-quantum-safe/openssh repo, but the older image may support only a subset
  — trim to `ssh -Q kex` output on first build.

## ELK integration (step 3)

`logstash-pqc.conf` follows the repo's existing `logstash.conf` conventions
(file+json input, `honeypot_type`/`service`/`event_type` fields, the shared
`honeypot-%{+YYYY.MM.dd}` index). Mount the `pqc-logs` volume into a Logstash
container at `/var/log/pqc-honeypot` — the commented `logstash` service in
`docker-compose.yml` shows the wiring. It maps every event onto the framework's
`event_type` vocabulary: `kex_negotiated`→`key_exchange`, `cred_attempt`→
`login_attempt`, `handoff`→`session_handoff`.

`kibana-dashboard-pqc.json` is the **PQC-vs-classical dashboard** (mirrors the
nested saved-object style of the repo's `config/kibana-dashboard.json`; reads
the same `honeypot-*` index). Six panels:

1. **Total Key Exchanges** — metric
2. **PQC vs Classical** — donut on `post_quantum` (the headline signal)
3. **Negotiated Algorithms** — table on `kex_algorithm.keyword`
4. **Key Exchanges by Variant** — bar on `variant.keyword`, split by `post_quantum`
5. **PQC Adoption Over Time** — line, `post_quantum` split over `@timestamp`
6. **Captured Usernames (PQC relay)** — table on `username.keyword` (hand-off `cred_attempt`s)

Load it once Elasticsearch/Kibana are up (Kibana ≥ 8, `honeypot-*` receiving data):

```bash
curl -s -u elastic:$ELASTIC_PW -X POST "$KIBANA/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" --form file=@kibana-dashboard-pqc.json
```

or **Stack Management → Saved Objects → Import**. (The file uses the repo's
readable nested style; if your Kibana rejects inline `visState`, recreate the
data view `honeypot-*` and import — Kibana migrates legacy visualizations.)

## Post-auth capture (step 5)

See `COWRIE-HANDOFF.md`. Decision: a **PQC OpenSSH front-end terminates the
post-quantum handshake and captures credentials, then relays the authenticated
session into Cowrie** over an isolated internal network, correlated by
`session_id`. Cowrie can't do PQC itself (Twisted `conch` has no ML-KEM), so it
stays the deception backend rather than the transport.

## Remaining next steps

1. Build + run `verify.sh` on a Docker host (closes the "not built here" gap).
2. On a Docker host, build `Dockerfile.pqc-only`, run `ssh -Q kex` in the image
   to confirm which of the verified pure names it supports, trim
   `sshd_config.pqc-only` to match, then enable the opt-in service.
3. ~~Add a Kibana PQC-vs-classical split~~ — **authored**: `logstash-pqc.conf`
   (maps `kex_negotiated`/`cred_attempt`/`handoff` onto the framework's
   `event_type` vocab) + `kibana-dashboard-pqc.json` (6-panel dashboard on the
   `honeypot-*` index). Stand up a Logstash container against `pqc-logs` and
   import the dashboard (see [ELK integration](#elk-integration-step-3)) to
   validate end-to-end.
4. ~~Prototype the Cowrie hand-off~~ — **authored** in [`handoff/`](handoff/)
   (two-service compose: PQC relay → Cowrie, Option B). Run `handoff/verify-handoff.sh`
   on a Docker host to validate end-to-end.

> Flagged for the broader plan: it pins Elasticsearch 7.14.0 (2021, has CVEs)
> and disables `xpack.security`, contradicting its own "zero vulnerabilities"
> mandate; and `ubuntu:22.04-minimal` is not a real image tag. This PoC uses
> Logstash 8.15.3 in the sample wiring instead.
