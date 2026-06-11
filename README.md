# 🍯 Honeypot Framework

A scalable, cloud-native honeypot deployment framework using Terraform.
Captures attacker TTPs across multiple geographic regions.

## Project Status
🟡 Phase 1 — Local Lab (In Progress)

## Structure
| Folder | Purpose |
|---|---|
| `terraform/` | All infrastructure-as-code |
| `honeypots/` | Honeypot configs (Cowrie, Dionaea) |
| `monitoring/` | Dashboards and alerting rules |
| `docs/` | Architecture and setup guides |
| `scripts/` | Deployment helper scripts |

## Phases
- [x] Phase 0 — Repo setup
- [ ] Phase 1 — Local VirtualBox lab
- [ ] Phase 2 — Single-region AWS deploy
- [ ] Phase 3 — Multi-region + logging
- [ ] Phase 4 — Threat intel enrichment
- [ ] Phase 5 — Multi-cloud + auto-rotation

## Security Notice
This repository is **private**. Never commit AWS keys,
passwords, or sensitive config. Use `.gitignore` and
environment variables only.
