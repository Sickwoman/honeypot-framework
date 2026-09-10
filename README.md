# 🍯 Honeypot Framework

[![CI](https://github.com/Sickwoman/honeypot-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/Sickwoman/honeypot-framework/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12-green.svg)](https://www.python.org/)
[![Terraform](https://img.shields.io/badge/terraform-1.0+-orange.svg)](https://www.terraform.io/)

A **cloud-native honeypot deployment framework** for capturing, analyzing, and visualizing cyber attacks across multiple geographic regions.

## ✨ Features

### 🎯 Honeypot Services
- **Cowrie SSH Honeypot** — Captures SSH login attempts and command execution
- **OpenCanary Multi-Service** — Simulates FTP, HTTP, MySQL, SSH, Telnet services
- **Attack Simulation Harness** — `scripts/simulate-attacks.sh` drives traffic at the honeypot so you can exercise the full detection pipeline locally

### 📊 Log Aggregation & Visualization
- **Elasticsearch 7.14.0** — Centralized log storage and indexing
- **Kibana 7.14.0** — Interactive dashboards and attack visualization
- **Logstash Pipeline** — Real-time event parsing and enrichment

### ☁️ Cloud Infrastructure
- **Terraform IaC** — Modular infrastructure as code (validated in CI)
- **Multi-Region** — Deploy to AWS us-east-1, eu-west-1, ap-south-1
- **Automated Deployment** — One command to deploy entire stack

### 🔐 Security
- **Least-Privilege IAM** — Minimal permissions for services
- **VPC Isolation** — Honeypots isolated in dedicated VPC
- **Log Encryption** — S3 encryption and retention policies
- **Systemd Hardening** — Service sandboxing and restrictions

### ⚙️ Automation
- **Systemd Services** — Auto-start and auto-restart honeypots
- **Health Monitoring** — Hourly automated health checks
- **Log Rotation** — 30-day retention with compression
- **CI/CD Pipeline** — GitHub Actions for Terraform validation

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose (any OS), **or** Python 3.11+ for the test suite alone
- Terraform 1.0+ and an AWS account (only for the cloud deployment)

### Local stack (one command)

```bash
git clone https://github.com/Sickwoman/honeypot-framework.git
cd honeypot-framework

cp .env.example .env
python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(32))" >> .env

docker compose up --build
```

| Service | Where |
|---|---|
| Cowrie SSH honeypot (the trap) | `localhost:2222` |
| Nightwatch dashboard | http://localhost:8080 |
| Alert API | http://localhost:8000 |

Elasticsearch and Kibana are optional — the core loop stores alerts in SQLite:

```bash
docker compose --profile elk up     # adds Elasticsearch :9200, Kibana :5601
```

Full walkthrough, including how to log in and generate test traffic:
**[docs/QUICKSTART.md](docs/QUICKSTART.md)**.

> The Compose stack is authored but not yet built end-to-end by the maintainer
> (no Docker on the dev machine). The test suite, linting and the frontend
> build are verified in CI.

### Native install (Ubuntu/Kali)

Cowrie and OpenCanary installed natively, driven by systemd, are documented in
[docs/SETUP.md](docs/SETUP.md). `scripts/deploy.sh` expects Cowrie already
present at `/home/cowrie/cowrie`.

### AWS Deployment (15 minutes)

```bash
# Configure AWS credentials
aws configure

# Deploy to AWS us-east-1
cd terraform/environments/aws-us-east
terraform init
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars

# Verify deployment
aws ec2 describe-instances --region us-east-1
```

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| [SETUP.md](docs/SETUP.md) | Installation and configuration guide |
| [ARCHITECTURE.md](docs/architecture.md) | System design and components |
| [PHASE2-DEPLOYMENT.md](docs/PHASE2-DEPLOYMENT.md) | AWS deployment guide |
| [SYSTEMD-SERVICES.md](docs/SYSTEMD-SERVICES.md) | Service management |
| [INCIDENT-RESPONSE-PLAYBOOK.md](docs/INCIDENT-RESPONSE-PLAYBOOK.md) | Attack response procedures |
| [GEOIP-ENRICHMENT.md](docs/GEOIP-ENRICHMENT.md) | Location-based log enrichment |
| [THREAT-INTELLIGENCE.md](docs/THREAT-INTELLIGENCE.md) | IP threat scoring integration |

## 🛠️ Tools & Scripts

| Script | Purpose |
|--------|---------|
| `deploy.sh` | Start all honeypot services |
| `check-services.sh` | Monitor service health and logs |
| `simulate-attacks.sh` | Generate test attack traffic |
| `estimate-aws-costs.py` | Calculate AWS deployment costs |
| `backup-honeypot.sh` | Backup all data and configs |
| `restore-honeypot.sh` | Restore from backup |

## 📊 Project Status

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ Complete | Local honeypot lab with Cowrie + OpenCanary |
| **Phase 1.5** | ✅ Complete | ELK Stack visualization |
| **Phase 2** | ✅ Complete | AWS single-region deployment |
| **Phase 3** | ✅ Complete| Multi-region deployment |
| **Phase 4** | ✅ Complete | Threat intelligence integration |
| **Phase 5** | 📋 Planned | Multi-cloud and auto-rotation |

## 🏗️ Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                   HONEYPOT FRAMEWORK                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  LOCAL LAB (Phase 1 & 1.5)                             │
│  ┌──────────────┐  ┌──────────────┐                   │
│  │ Cowrie SSH   │  │ OpenCanary   │                   │
│  │ (port 2222)  │  │ (5 services) │                   │
│  └──────┬───────┘  └──────┬───────┘                   │
│         │                 │                            │
│         └────────┬────────┘                            │
│                  ▼                                      │
│         ┌──────────────┐                               │
│         │  Log Files   │                               │
│         └──────┬───────┘                               │
│                ▼                                       │
│  ┌────────────────────────────────┐                   │
│  │      ELK STACK (Docker)        │                   │
│  │  ┌──────────────────────────┐  │                   │
│  │  │ Logstash (Parse Logs)    │  │                   │
│  │  └──────┬───────────────────┘  │                   │
│  │         ▼                       │                   │
│  │  ┌──────────────────────────┐  │                   │
│  │  │ Elasticsearch (Index)    │  │                   │
│  │  └──────┬───────────────────┘  │                   │
│  │         ▼                       │                   │
│  │  ┌──────────────────────────┐  │                   │
│  │  │ Kibana (Visualize)       │  │                   │
│  │  └──────────────────────────┘  │                   │
│  └────────────────────────────────┘                   │
│                                                         │
│  AWS CLOUD (Phase 2+)                                  │
│  ┌──────────────────────────────────┐                 │
│  │ VPC (10.0.0.0/16)               │                 │
│  │  ┌────────────────────────────┐  │                 │
│  │  │ EC2 Honeypots (t3.micro)  │  │                 │
│  │  │ └─ Cowrie & OpenCanary    │  │                 │
│  │  └────────────┬───────────────┘  │                 │
│  │               ▼                   │                 │
│  │  ┌────────────────────────────┐  │                 │
│  │  │ CloudWatch Logs            │  │                 │
│  │  └────────────┬───────────────┘  │                 │
│  │               ▼                   │                 │
│  │  ┌────────────────────────────┐  │                 │
│  │  │ S3 (Long-term Storage)     │  │                 │
│  │  └────────────────────────────┘  │                 │
│  └──────────────────────────────────┘                 │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## 📈 Statistics

- **103+** attack events captured
- **2** active honeypot services
- **11** monitored ports
- **6** documentation files
- **15+** git commits
- **40+** configuration files

## 🔒 Security Features

Implemented:

✅ Least-privilege IAM policies
✅ VPC network isolation
✅ Security groups with port restrictions
✅ Systemd service sandboxing
✅ .gitignore blocking secrets
✅ Non-root service execution
✅ RBAC with bcrypt-hashed accounts, JWT/API-key auth, and login lockout
✅ Persisted audit trail (`audit_log` table)
✅ Duration-bounded automated firewall blocks (expiry job in cron)

Not yet complete — see [SECURITY-CHECKLIST.md](SECURITY-CHECKLIST.md) and
[IMPROVEMENTS-AND-FEATURES.md](IMPROVEMENTS-AND-FEATURES.md):

⬜ End-to-end TLS across every component
⬜ Log encryption at rest (S3 SSE + CloudWatch retention policies)
⬜ MFA for operator accounts
⬜ Independent penetration test

## 💰 Cost Estimation

| Service | Free Tier | Monthly Cost |
|---------|-----------|--------------|
| EC2 (t3.micro) | 750 hrs/month | ~$0 |
| CloudWatch Logs | 5 GB/month | ~$0 |
| S3 Storage | 5 GB | ~$0 |
| Data Transfer | 1 GB/month | ~$0 |
| **Total** | **Within free tier** | **~$0/month** |

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

## 📝 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🙋 Support

- 📖 Read the [documentation](docs/)
- 🐛 Report bugs via [GitHub Issues](https://github.com/Sickwoman/honeypot-framework/issues)
- 💬 Discuss via [GitHub Discussions](https://github.com/Sickwoman/honeypot-framework/discussions)

## 🔗 Links

- [GitHub Repository](https://github.com/Sickwoman/honeypot-framework)
- [AWS Terraform Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Cowrie Documentation](https://cowrie.readthedocs.io/)
- [OpenCanary GitHub](https://github.com/thinkst/opencanary)
- [ELK Stack Documentation](https://www.elastic.co/guide/en/elastic-stack/current/index.html)

---

**Status**: Working lab/portfolio deployment. Terraform, honeypots, alerting
and the RBAC API run end to end; the hardening items listed under Security
Features remain open, so treat this as pre-production.
**Last Updated**: September 10, 2026
**Maintainer**: Security Team

