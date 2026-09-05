# Honeytoken Tripwires

Honeytoken Tripwires create synthetic credentials that are safe to place in a
honeypot or decoy file. If a token appears in a honeypot event, the ingestor
creates a `HoneytokenTriggered` `CRITICAL` alert and the existing playbook path
can respond to it.

## Generate tokens

```bash
python3 scripts/honeytoken-tripwire.py \
  --generate --count 3 > /etc/honeypot-framework/honeytokens.json
chmod 600 /etc/honeypot-framework/honeytokens.json
```

Place the generated synthetic values only in decoy locations. Never use them as
real credentials or grant them access to production systems.

## Enable live detection

```bash
export HONEYTOKEN_MANIFEST=/etc/honeypot-framework/honeytokens.json
python3 monitoring/live_alert_ingestor.py
```

The manifest is loaded only when the environment variable is set. Triggered
alerts include token IDs and labels but never include the token value itself.
The alert is persisted through the normal alert service and can activate
existing playbooks.

## Test a manifest

```bash
python3 scripts/honeytoken-tripwire.py \
  --manifest /etc/honeypot-framework/honeytokens.json \
  --event '{"src_ip":"203.0.113.10","password":"paste-a-token-here"}'
```