# 🍯 Honeypot Framework

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![Terraform](https://img.shields.io/badge/terraform-1.0+-orange.svg)](https://www.terraform.io/)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://www.docker.com/)
[![Status](https://img.shields.io/badge/status-production%20ready-brightgreen.svg)](#status)

A **cloud-native honeypot deployment framework** for capturing, analyzing, and visualizing cyber attacks across multiple geographic regions.

## ✨ Features

### 🎯 Honeypot Services
- **Cowrie SSH Honeypot** — Captures SSH login attempts and command execution
- **OpenCanary Multi-Service** — Simulates FTP, HTTP, MySQL, SSH, Telnet services
- **Real Attack Capture** — 100+ attacks logged and analyzed

### 📊 Log Aggregation & Visualization
- **Elasticsearch 7.14.0** — Centralized log storage and indexing
- **Kibana 7.14.0** — Interactive dashboards and attack visualization
- **Logstash Pipeline** — Real-time event parsing and enrichment

### ☁️ Cloud Infrastructure
- **Terraform IaC** — Production-ready infrastructure as code
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
- Kali Linux or Ubuntu 22.04+
- Docker and Docker Compose
- Terraform 1.0+
- Python 3.8+
- AWS Account (for Phase 2)

### Local Setup (5 minutes)

```bash
# Clone repository
git clone https://github.com/Sickwoman/honeypot-framework.git
cd honeypot-framework

# Deploy local lab
chmod +x scripts/deploy.sh
./scripts/deploy.sh

# View dashboard
python3 scripts/check-services.sh

# Access Kibana
open http://localhost:5601
```

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
| **Phase 2** | ⏳ Ready | AWS single-region deployment |
| **Phase 3** | 📋 Planned | Multi-region deployment |
| **Phase 4** | 📋 Planned | Threat intelligence integration |
| **Phase 5** | 📋 Planned | Multi-cloud and auto-rotation |

## 🏗️ Architecture
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
## 📈 Statistics

- **103+** attack events captured
- **2** active honeypot services
- **11** monitored ports
- **6** documentation files
- **15+** git commits
- **40+** configuration files

## 🔒 Security Features

✅ Least-privilege IAM policies
✅ VPC network isolation  
✅ Security groups with port restrictions
✅ Systemd service sandboxing
✅ Log encryption (S3)
✅ .gitignore blocking secrets
✅ CloudWatch retention policies
✅ Non-root service execution

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

**Status**: Production-ready for AWS deployment
**Last Updated**: June 16, 2026
**Maintainer**: Security Team

