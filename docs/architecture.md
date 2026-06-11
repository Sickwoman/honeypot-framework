# Architecture Overview

## Phase 1 — Local Lab (Current)

Honeypot VM: 192.168.56.101
- Cowrie SSH honeypot
- Dionaea malware capture
- Open bait ports: 22, 23, 80, 443, 21

Monitoring VM: 192.168.56.102
- ELK Stack / Grafana
- Log aggregation
- Alert rules

Logs flow from Honeypot VM to Monitoring VM via syslog/filebeat.

## Network Isolation (Critical)
- VMs on host-only network 192.168.56.0/24
- No bridge to host or internet from honeypot
- Monitoring VM has internet for threat intel feeds only

## Phase 2 Preview - AWS
- VPC per region with isolated subnets
- EC2 honeypot instances (t3.micro)
- CloudWatch log aggregation
- S3 for long-term log storage
