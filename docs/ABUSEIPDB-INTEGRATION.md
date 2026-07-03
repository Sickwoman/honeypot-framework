# AbuseIPDB Integration Guide

## Overview

AbuseIPDB is a free IP reputation service that provides real-time threat intelligence. This integration enriches honeypot logs with IP abuse scores and threat metadata.

---

## 1. Getting Started

### Get Free API Key

1. Go to: https://www.abuseipdb.com/register
2. Sign up for free account
3. Verify email
4. Go to Account Settings → API
5. Copy your API Key

### Set API Key

```bash
# Add to ~/.bashrc or ~/.zshrc
export ABUSEIPDB_API_KEY="your-api-key-here"

# Or set temporarily
export ABUSEIPDB_API_KEY="your-api-key-here"

# Verify
echo $ABUSEIPDB_API_KEY
```

---

## 2. Check Single IP

### Quick Check

```bash
# Check one IP
python3 ~/Desktop/honeypot-framework/scripts/abuseipdb-checker.py --check 192.168.1.1

# Output:
# 🔍 IP REPUTATION REPORT - 192.168.1.1
# Threat Level: HIGH
# Confidence Score: 85/100
# Total Reports: 45
# Last Reported: 2026-06-16T10:30:00Z
```

### Understanding the Report

| Field | Meaning |
|-------|---------|
| **Threat Level** | HIGH (75+), MEDIUM (50-74), LOW (25-49), SAFE (<25) |
| **Confidence Score** | 0-100, higher = more malicious |
| **Total Reports** | Number of times reported by AbuseIPDB users |
| **Last Reported** | Most recent report timestamp |
| **Whitelisted** | Known legitimate service |
| **Blacklisted** | Known malicious IP |

---

## 3. Batch Check Multiple IPs

### From File

```bash
# Create IP list
cat > /tmp/ips.txt << 'IPLIST'
192.168.1.1
10.0.0.5
172.16.0.1
IPLIST

# Check batch
python3 ~/Desktop/honeypot-framework/scripts/abuseipdb-checker.py --batch /tmp/ips.txt
```

---

## 4. Check Honeypot Attacking IPs

### Automatic Honeypot Analysis

```bash
# Check top attacking IPs from honeypot
python3 ~/Desktop/honeypot-framework/scripts/abuseipdb-checker.py --honeypot

# Shows:
# - Top 20 attacking IPs
# - Reputation scores
# - Threat levels
# - Risk summary
```

---

## 5. Enrich Elasticsearch with Threat Intelligence

### Add Threat Data to Logs

```bash
# Check IP and enrich Elasticsearch
python3 ~/Desktop/honeypot-framework/scripts/abuseipdb-checker.py --enrich 192.168.1.1

# This will:
# 1. Check IP on AbuseIPDB
# 2. Create threat-intel index document
# 3. Update all honeypot-* documents with threat data
# 4. Display report
```

### Query Threat Intel in Kibana

```json
// Find all HIGH risk IPs
GET threat-intel/_search
{
  "query": {
    "match": {
      "threat_data.threat_level": "HIGH"
    }
  }
}

// Find IPs with >50 confidence score
GET threat-intel/_search
{
  "query": {
    "range": {
      "threat_data.confidence_score": {
        "gte": 50
      }
    }
  }
}

// Join with honeypot events
GET honeypot-*/_search
{
  "query": {
    "exists": {
      "field": "threat_intel"
    }
  }
}
```

---

## 6. Automated Threat Intelligence Pipeline

### Create Logstash Enrichment Filter

```conf
# Add to logstash-optimized.conf

filter {
  # Enrich with AbuseIPDB data
  if [src_ip] {
    # Call external script or API
    # For now, this would require additional setup
    mutate {
      add_field => { "threat_check_needed" => true }
    }
  }
}

output {
  # Send to threat intel index
  if [threat_check_needed] {
    elasticsearch {
      hosts => ["https://elasticsearch:9200"]
      index => "threat-intel-%{+YYYY.MM.dd}"
    }
  }
  
  # Normal honeypot index
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    index => "honeypot-%{+YYYY.MM.dd}"
  }
}
```

---

## 7. Threat Intelligence Alerting

### Create Alert Rules

```bash
# High risk IP detected
GET honeypot-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "threat_intel.confidence_score": { "gte": 75 } } }
      ]
    }
  }
}

// Alert: Medium risk IP
GET honeypot-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "threat_intel.confidence_score": { "gte": 50, "lt": 75 } } }
      ]
    }
  }
}

// Alert: Blacklisted IP
GET honeypot-*/_search
{
  "query": {
    "match": { "threat_intel.is_blacklisted": true }
  }
}
```

---

## 8. Rate Limiting

### Free Tier Limits

- **Requests per day**: 50
- **Requests per hour**: 10
- **Concurrent requests**: 1

### Best Practices

```bash
# Add delay between requests (free tier)
for ip in $(cat ips.txt); do
  python3 abuseipdb-checker.py --check $ip
  sleep 2  # Wait 2 seconds between requests
done

# Or use batch file with automatic delays built-in
python3 abuseipdb-checker.py --batch ips.txt
```

---

## 9. Caching Strategy

### In-Memory Cache (24 hours)

```python
# Cache stores results for 24 hours
# Reduces API calls for same IPs
# Automatic cleanup of old entries

cache = {
  '192.168.1.1': (data, timestamp),
  '10.0.0.5': (data, timestamp)
}

# Cache hit = no API call
# Cache miss = API call + cache update
```

### Database Cache (Optional)

```bash
# Store results in Elasticsearch
GET threat-intel/_search
{
  "query": {
    "match": { "ip": "192.168.1.1" }
  }
}

# Check cache before API
# Only call API if >24h old
```

---

## 10. Integration with Incident Response

### Automated Response Workflow
### Manual Investigation

```bash
# 1. Check honeypot logs
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log

# 2. Extract attacker IP
ATTACKER_IP="192.168.1.1"

# 3. Get threat intel
python3 abuseipdb-checker.py --check $ATTACKER_IP

# 4. Query Elasticsearch
curl -s "https://localhost:9200/honeypot-*/_search?q=src_ip:$ATTACKER_IP"

# 5. Take action
# - Block in firewall
# - Update honeypot rules
# - Document incident
```

---

## 11. Reporting and Analytics

### Generate Threat Report

```bash
# Check top 20 attacking IPs
python3 abuseipdb-checker.py --honeypot

# Shows:
# - Threat distribution
# - HIGH risk IPs
# - Geographic distribution
# - Attack patterns
```

### Kibana Dashboard Query

```json
GET threat-intel/_search
{
  "size": 0,
  "aggs": {
    "threat_levels": {
      "terms": {
        "field": "threat_data.threat_level"
      }
    },
    "top_countries": {
      "terms": {
        "field": "threat_data.country",
        "size": 10
      }
    },
    "avg_confidence": {
      "avg": {
        "field": "threat_data.confidence_score"
      }
    }
  }
}
```

---

## 12. Troubleshooting

### API Key Not Working

```bash
# Verify API key is set
echo $ABUSEIPDB_API_KEY

# Test API directly
curl -G https://api.abuseipdb.com/api/v2/check \
  -d ipAddress=8.8.8.8 \
  -d maxAgeInDays=90 \
  -H "Key: your-api-key" \
  -H "Accept: application/json"
```

### Rate Limit Exceeded

```bash
# Wait and retry (50 requests/day limit)
# Implement exponential backoff
# Use cache for repeated IPs
```

### Elasticsearch Connection Error

```bash
# Verify Elasticsearch is running
curl -k -u elastic:changeme https://localhost:9200/_cluster/health

# Check credentials
# Verify SSL certificates
```

---

## 13. Advanced: Custom Scoring

### Create Threat Score Formula

```python
def calculate_threat_score(abuseipdb_data):
    score = 0
    
    # Confidence score (0-50 points)
    score += abuseipdb_data['confidence_score'] / 2
    
    # Report count (0-30 points)
    reports = min(abuseipdb_data['total_reports'], 30)
    score += reports
    
    # Blacklist status (+20 points)
    if abuseipdb_data['is_blacklisted']:
        score += 20
    
    # Whitelisted (-10 points)
    if abuseipdb_data['is_whitelisted']:
        score -= 10
    
    return min(100, max(0, score))  # Normalize 0-100
```

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `--check IP` | Check single IP |
| `--batch FILE` | Check IPs from file |
| `--honeypot` | Check honeypot IPs |
| `--enrich IP` | Check and enrich Elasticsearch |

---

## Support & Resources

- AbuseIPDB: https://www.abuseipdb.com
- API Docs: https://docs.abuseipdb.com
- Free Tier: 50 requests/day
- Premium Tier: Unlimited requests

