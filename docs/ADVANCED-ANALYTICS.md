# Advanced Analytics & Reporting Guide

## Overview

Comprehensive analytics and reporting for honeypot attack data with custom dashboards, automated reports, and threat intelligence correlation.

---

## 1. Generate Text Analytics Report

### Quick Report (Last 24 Hours)

```bash
python3 ~/Desktop/honeypot-framework/scripts/generate-analytics-report.py
```

Output shows:
- Total events captured
- Top 10 attacking IPs
- Service distribution
- Hourly trend
- Threat intelligence stats

### Report for Specific Period

```bash
# Last 7 days
python3 ~/Desktop/honeypot-framework/scripts/generate-analytics-report.py --days 7

# Last 30 days
python3 ~/Desktop/honeypot-framework/scripts/generate-analytics-report.py --days 30
```

---

## 2. Generate JSON Report

### Export as JSON

```bash
# Output to console
python3 scripts/generate-analytics-report.py --json

# Save to file
python3 scripts/generate-analytics-report.py --json --file report.json

# Parse with jq
python3 scripts/generate-analytics-report.py --json | jq '.summary'
```

### JSON Report Structure

```json
{
  "generated_at": "2026-06-16T10:30:00",
  "period_days": 1,
  "summary": {
    "total_events": 103,
    "credentials_captured": 5
  },
  "top_ips": [
    {
      "ip": "192.168.1.1",
      "count": 45
    }
  ],
  "service_distribution": {
    "SSH": 92,
    "FTP": 11
  },
  "threat_intelligence": {
    "threat_levels": {
      "HIGH": 10,
      "MEDIUM": 5,
      "LOW": 3
    },
    "avg_confidence": 65.5
  }
}
```

---

## 3. Generate PDF Reports

### Install Dependencies

```bash
pip3 install reportlab --break-system-packages
```

### Generate Professional PDF

```bash
# Default (last 24 hours)
python3 scripts/generate-pdf-report.py

# Custom filename
python3 scripts/generate-pdf-report.py --output custom-report.pdf

# Specific period
python3 scripts/generate-pdf-report.py --days 7 --output weekly-report.pdf
```

### PDF Report Contents

1. **Title Page**
   - Report title and date
   - Analysis period
   - Status indicator

2. **Executive Summary**
   - High-level overview
   - Key metrics
   - Threat assessment

3. **Statistics**
   - Total attack events
   - Unique IPs
   - Credentials captured
   - Services targeted

4. **Top Attacking IPs**
   - Ranked list
   - Event counts
   - Threat levels

5. **Service Analysis**
   - Attack distribution
   - Service breakdown
   - Percentage breakdown

6. **Recommendations**
   - Security improvements
   - Mitigation strategies
   - Best practices

---

## 4. Kibana Dashboard Usage

### Access Dashboard
### Available Visualizations

1. **Top 10 Attacking IPs**
   - Bar chart showing most active attackers
   - Click to drill down

2. **Attack Timeline**
   - Line chart of attacks over time
   - Identify attack patterns
   - Spot peaks and valleys

3. **Service Distribution**
   - Pie chart of targeted services
   - See which services are most attacked
   - Allocate resources accordingly

4. **Threat Levels**
   - Distribution of threat levels
   - HIGH/MEDIUM/LOW/SAFE breakdown
   - Risk assessment

### Create Custom Visualizations

```json
// Example: Failed login attempts
GET honeypot-*/_search
{
  "query": {
    "term": {
      "event_type": "login_attempt"
    }
  },
  "aggs": {
    "by_hour": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "1h"
      }
    }
  }
}
```

---

## 5. Attack Pattern Analysis

### Identify Attack Waves

```bash
# Check for sudden spikes
python3 scripts/generate-analytics-report.py --days 7

# Look at hourly trend graph
# Identifies coordinated attacks
# Detects botnet activity
```

### Geographic Analysis

```json
// Top countries attacking
GET honeypot-*/_search
{
  "size": 0,
  "aggs": {
    "by_country": {
      "terms": {
        "field": "geoip.country_name",
        "size": 20
      }
    }
  }
}
```

### Command Analysis

```json
// Most executed commands
GET honeypot-*/_search
{
  "query": {
    "exists": {
      "field": "logdata.CMD"
    }
  },
  "aggs": {
    "commands": {
      "terms": {
        "field": "logdata.CMD",
        "size": 20
      }
    }
  }
}
```

---

## 6. Threat Intelligence Analytics

### High Risk IP Summary

```json
// IPs with HIGH threat level
GET honeypot-*/_search
{
  "query": {
    "term": {
      "threat_intel.threat_level": "HIGH"
    }
  },
  "aggs": {
    "top_high_risk": {
      "terms": {
        "field": "src_ip",
        "size": 10
      }
    }
  }
}
```

### Threat Score Distribution

```json
// Average threat scores
GET threat-intel/_search
{
  "size": 0,
  "aggs": {
    "avg_threat": {
      "avg": {
        "field": "threat_data.confidence_score"
      }
    },
    "percentiles": {
      "percentiles": {
        "field": "threat_data.confidence_score"
      }
    }
  }
}
```

---

## 7. Automated Report Scheduling

### Daily Report Generation

```bash
# Add to crontab
crontab -e

# Add this line to run daily at 9 AM
0 9 * * * python3 ~/Desktop/honeypot-framework/scripts/generate-pdf-report.py --days 1 --output ~/reports/daily-$(date +\%Y-\%m-\%d).pdf
```

### Weekly Report

```bash
# Every Monday at 8 AM
0 8 * * 1 python3 ~/Desktop/honeypot-framework/scripts/generate-pdf-report.py --days 7 --output ~/reports/weekly-$(date +\%Y-W\%V).pdf
```

### Monthly Report

```bash
# First day of month at 7 AM
0 7 1 * * python3 ~/Desktop/honeypot-framework/scripts/generate-pdf-report.py --days 30 --output ~/reports/monthly-$(date +\%Y-\%m).pdf
```

---

## 8. Performance Metrics

### Query Performance

```bash
# Measure query response time
time python3 scripts/generate-analytics-report.py --days 1

# Typical: < 5 seconds for 24-hour report
```

### Report Generation Time

| Report Type | Time | Size |
|------------|------|------|
| Text (24h) | 2-3s | 5KB |
| JSON (24h) | 2-3s | 10KB |
| PDF (24h) | 5-10s | 50KB |
| PDF (30d) | 10-15s | 100KB |

---

## 9. Report Distribution

### Email Reports

```bash
# Send PDF report via email
cat > send-report.sh << 'SCRIPT'
#!/bin/bash

python3 ~/Desktop/honeypot-framework/scripts/generate-pdf-report.py \
  --days 1 --output /tmp/report.pdf

# Use mailx or sendmail
echo "Daily honeypot report attached" | \
  mail -s "Honeypot Report - $(date +%Y-%m-%d)" \
  -a /tmp/report.pdf \
  security-team@example.com
SCRIPT

chmod +x send-report.sh
```

### Slack Notifications

```bash
# Send report summary to Slack
curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "Daily Honeypot Report",
    "attachments": [
      {
        "text": "Total Events: 103\nTop IP: 192.168.1.1\nHIGH Risk IPs: 5"
      }
    ]
  }'
```

---

## 10. Analytics Best Practices

### Regular Review Schedule

- **Daily**: Quick text report check
- **Weekly**: Detailed PDF analysis
- **Monthly**: Comprehensive trend analysis
- **Quarterly**: Security assessment review

### Key Metrics to Monitor

✅ Total attack volume (should be consistent)
✅ Top attacking IPs (watch for patterns)
✅ Service distribution (identify vulnerabilities)
✅ Credential attempts (assess password strength)
✅ Threat intelligence scores (identify botnets)
✅ Geographic distribution (detect coordinated attacks)

### Actions Based on Reports

1. **HIGH volume spike** → Investigate cause, check for DDoS
2. **NEW IP clusters** → Block IP ranges, update rules
3. **Credential patterns** → Strengthen passwords, implement MFA
4. **Service targeting** → Patch vulnerabilities, update configs
5. **Geographic patterns** → Implement geo-blocking if needed

---

## Quick Reference

| Task | Command |
|------|---------|
| Generate text report | `python3 scripts/generate-analytics-report.py` |
| Generate JSON report | `python3 scripts/generate-analytics-report.py --json` |
| Generate PDF report | `python3 scripts/generate-pdf-report.py` |
| 7-day analysis | `--days 7` |
| Save to file | `--file filename` or `--output filename` |
| View in Kibana | `http://localhost:5601` |

---

## Troubleshooting

### Report Generation Fails

```bash
# Verify Elasticsearch connection
curl -k -u elastic:changeme https://localhost:9200/_cluster/health

# Check Python dependencies
pip3 list | grep -E "elasticsearch|reportlab"

# Test with small dataset
python3 scripts/generate-analytics-report.py --days 1
```

### No Data in Report

```bash
# Verify documents in honeypot index
curl -k -u elastic:changeme https://localhost:9200/honeypot-*/_count

# Check timestamp range
curl -k -u elastic:changeme https://localhost:9200/honeypot-*/_search?size=1
```

---

## Next Steps

1. ✅ Generate first report
2. ✅ Review findings
3. ✅ Set up automated scheduling
4. ✅ Integrate with team notifications
5. ✅ Create custom dashboards
6. ✅ Establish baseline metrics

