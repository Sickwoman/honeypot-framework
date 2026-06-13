# Monitoring & Log Aggregation

## Phase 1.5 — Local Lab Visualization

### Components

**ELK Stack (Docker)**
- Elasticsearch 7.14.0 on port 9200
- Kibana 7.14.0 on port 5601
- Logstash 7.14.0 on port 5000

**Log Sources**
- Cowrie SSH honeypot: `/home/cowrie/cowrie/var/log/cowrie/cowrie.log`
- OpenCanary multi-service: `/var/tmp/opencanary.log`

### Setup

```bash
cd ~/elk-stack
docker-compose up -d
```

### Access

- **Kibana Dashboard**: http://localhost:5601
- **Elasticsearch API**: http://localhost:9200

### Dashboard Script

Quick view of all honeypot attacks:

```bash
cd ~/elk-stack
python3 honeypot_dashboard.py
```

Shows:
- Cowrie SSH attempts and commands
- OpenCanary port scans and login attempts
- Captured credentials
- HTTP requests
- Overall attack statistics

### Log Format

**Cowrie**: Text logs with timestamps and event details
**OpenCanary**: JSON format with source/destination IPs, ports, and credentials

### Next Steps

- Phase 2: Migrate logs to CloudWatch (AWS)
- Phase 3: Add GeoIP enrichment
- Phase 4: Threat intelligence integration
