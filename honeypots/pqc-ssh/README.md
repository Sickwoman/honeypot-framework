# PQC SSH Honeypot (EC2-native)

The **production form** of [`pqc-poc/`](../../pqc-poc/) (the Docker proof-of-concept).
A dedicated, observation-only OpenSSH endpoint that advertises a **post-quantum
key exchange** on port **2223** and logs which kex each attacker's client
negotiates — the same `kex_negotiated` signal the PoC emits — deployed the way
this repo actually ships honeypots: **Terraform + AWS EC2 + cloud-init**, not
Docker.

```
attacker ──SSH──▶  :2223 dedicated sshd (PQC KexAlgorithms, LogLevel DEBUG1)
                     │  observation only — no accounts, auth always fails
                     ▼
             /var/log/pqc-honeypot/events.json   ({"event":"kex_negotiated",…})
                     │  CloudWatch agent / Logstash ships it
                     ▼
             honeypot-*  (Elasticsearch)  →  the PQC-vs-classical dashboard
```

The admin sshd on port 22 is **untouched** — this runs as a separate service
with its own host key, config, and systemd unit.

## Files

| File | Purpose |
|---|---|
| `user_data.pqc.sh` | cloud-init provisioning: installs sshd, picks supported PQC kex, runs the observation service |
| `terraform.tf` | reference-doc `locals`/outputs (mirrors [`../cowrie/terraform.tf`](../cowrie/terraform.tf)) |
| `README.md` | this file |

## How it works

1. Chooses `KexAlgorithms` from what the installed sshd reports via `ssh -Q kex`:
   `sntrup761x25519-sha512@openssh.com` is **always** advertised (post-quantum,
   present since OpenSSH 8.5); `mlkem768x25519-sha256` is added **only if
   listed** — sshd refuses to start on an unknown kex name.
2. Writes `/etc/ssh/sshd_config.pqc-honeypot` (port 2223, `LogLevel DEBUG1`, no
   accounts, forwarding off), validates it with `sshd -t`.
3. A systemd service runs `sshd -D -e` and pipes its output through the **same
   kex parser as [`../../pqc-poc/entrypoint.sh`](../../pqc-poc/entrypoint.sh)**,
   turning each `debug1: kex: algorithm: …` line into
   `{"event":"kex_negotiated","variant":"ec2-hybrid","kex_algorithm":…,"post_quantum":…}`.

Because the kex is negotiated **pre-auth**, we get the research signal without
any accounts or a fake shell — auth simply fails. Credential capture and the
Cowrie hand-off are the separate Docker relay in [`../../pqc-poc/handoff/`](../../pqc-poc/handoff/).

## ⚠️ OpenSSH version reality

The EC2 module's AMI is **Ubuntu 22.04 (jammy) → OpenSSH 8.9**, which has
`sntrup761x25519-sha512@openssh.com` (genuinely post-quantum) but **not** ML-KEM.
`mlkem768x25519-sha256` needs **OpenSSH ≥ 9.9**. The script auto-detects and
degrades gracefully; to advertise ML-KEM specifically, bump the AMI to a release
that ships OpenSSH ≥ 9.9 (or install a backport) and the same script picks it up
with no edits. Pure non-hybrid `pqc-only` still needs OQS-OpenSSH (out of scope
for stock OpenSSH — see the PoC).

## Wiring it into the framework (two edits)

This folder is self-contained and additive; deploying it takes two changes to
existing Terraform, kept here as explicit steps rather than applied blindly:

**1. Provision it** — append the script to the EC2 module's user_data. Add to
the end of [`../../terraform/modules/aws-ec2/user_data.sh`](../../terraform/modules/aws-ec2/user_data.sh):

```bash
# --- PQC SSH honeypot (observation, :2223) ---
# paste the body of honeypots/pqc-ssh/user_data.pqc.sh here, or fetch+run it
```

(cloud-init runs a single `user_data.sh`, so the PQC block lives inline there
alongside the Cowrie/OpenCanary setup.)

**2. Open the port** — add to [`../../terraform/modules/aws-security-group/main.tf`](../../terraform/modules/aws-security-group/main.tf):

```hcl
resource "aws_vpc_security_group_ingress_rule" "pqc_ssh" {
  security_group_id = aws_security_group.honeypot.id
  description       = "PQC SSH honeypot (observation)"
  from_port         = 2223
  to_port           = 2223
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}
```

Egress stays denied (the module already isolates outbound except CloudWatch on
443), so the honeypot can ship logs but not reach out.

## Verify (once deployed)

```bash
# Force the PQC kex from a client and confirm it's recorded:
ssh -o KexAlgorithms=sntrup761x25519-sha512@openssh.com -p 2223 nobody@<instance-ip>
# (auth fails — expected). On the instance:
tail -n1 /var/log/pqc-honeypot/events.json
# -> {"event":"kex_negotiated","variant":"ec2-hybrid","kex_algorithm":"sntrup761x25519-sha512@openssh.com","post_quantum":true}
systemctl status pqc-honeypot.service
```

## Relationship to the other honeypots

| | Cowrie (`../cowrie`) | PQC SSH (this) | PoC relay (`../../pqc-poc/handoff`) |
|---|---|---|---|
| Transport | classical SSH | **post-quantum** SSH | **post-quantum** SSH |
| Captures | creds + shell + TTY | kex negotiated only | creds, then → Cowrie |
| Deploy | EC2 (source) | **EC2 (this)** | Docker Compose |
| Port | 2222 | 2223 | 2225 |

Port allocation across honeypots: 2222 Cowrie, 2223 PQC SSH (this), 2224
OpenCanary decoy SSH (`../dionaea/opencanary.conf`), 2225 PoC relay. Two
honeypots bound to the same port silently shrinks the trap surface — one of
them just fails to bind.
