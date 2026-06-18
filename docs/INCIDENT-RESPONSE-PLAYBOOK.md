# Incident Response Playbook

## Overview
Documented procedures for responding to detected attacks and security incidents in the honeypot framework.

---

## Incident Types & Responses

### 1. High-Volume Login Attack (Brute Force)

**Trigger**: >100 failed login attempts in 5 minutes

**Immediate Actions**:
```bash
# 1. Query Kibana for attack details
GET honeypot-*/_search
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-5m"
      }
    }
  },
  "aggs": {
    "by_ip": {
      "terms": {
        "field": "src_ip",
        "size": 5
      }
    }
  }
}

# 2. Identify attacker IP
ATTACKER_IP="X.X.X.X"

# 3. Get geolocation
geoiplookup $ATTACKER_IP

# 4. Check for known malicious IP
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$ATTACKER_IP" \
  -H "Key: YOUR_API_KEY" | jq '.data.abuseConfidenceScore'
```

**Investigation**:
- [ ] What username was targeted?
- [ ] What passwords were attempted?
- [ ] What country is the attacker from?
- [ ] Is the IP known to be malicious?

**Documentation**:
```json
{
  "incident_id": "INC-001",
  "date": "2026-06-16",
  "type": "brute_force",
  "attacker_ip": "X.X.X.X",
  "country": "CN",
  "attempts": 150,
  "duration": "5 minutes",
  "targeted_service": "SSH",
  "action_taken": "Logged and monitored"
}
```

**Prevention**:
- Add IP to blocklist (if using WAF)
- Increase log retention for this IP
- Set alert threshold for future attacks

---

### 2. Malware Download Attempt

**Trigger**: Cowrie logs `wget` or `curl` command to external URL

**Immediate Actions**:
```bash
# 1. Extract download URL from logs
DOWNLOAD_URL="http://malware.test/evil.sh"

# 2. Check URL against VirusTotal
curl -s -X POST "https://www.virustotal.com/api/v3/urls" \
  -H "x-apikey: YOUR_API_KEY" \
  -d "url=$DOWNLOAD_URL" | jq '.data'

# 3. Check file hash if available
FILE_HASH="abc123def456..."
curl -s "https://www.virustotal.com/api/v3/files/$FILE_HASH" \
  -H "x-apikey: YOUR_API_KEY" | jq '.data.attributes.last_analysis_stats'

# 4. Query Kibana for related activity
GET honeypot-*/_search
{
  "query": {
    "match": {
      "logdata.CMD": "wget"
    }
  }
}
```

**Investigation**:
- [ ] What is the malware URL?
- [ ] Has it been seen before?
- [ ] What VirusTotal detection rate?
- [ ] What commands were executed after download?

**Documentation**:
```json
{
  "incident_id": "INC-002",
  "date": "2026-06-16",
  "type": "malware_download",
  "malware_url": "http://malware.test/evil.sh",
  "virustotal_detections": 12,
  "attacker_ip": "X.X.X.X",
  "action_taken": "Reported to VirusTotal"
}
```

**Prevention**:
- Add URL to blocklist
- Alert on similar URLs
- Monitor for related campaigns

---

### 3. Successful Command Execution

**Trigger**: Cowrie logs command execution from attacker

**Immediate Actions**:
```bash
# 1. Query for all commands from attacker
GET honeypot-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "src_ip": "X.X.X.X" } },
        { "exists": { "field": "logdata.CMD" } }
      ]
    }
  }
}

# 2. Analyze command sequence
# - What files were accessed?
# - What directories were listed?
# - What environment variables were checked?

# 3. Check for persistence mechanisms
# - Cron job creation?
# - SSH key installation?
# - Script downloads?
```

**Investigation**:
- [ ] What was the attacker trying to do?
- [ ] What information were they gathering?
- [ ] Were they attempting persistence?
- [ ] What tools did they use?

**Documentation**:
```json
{
  "incident_id": "INC-003",
  "date": "2026-06-16",
  "type": "command_execution",
  "attacker_ip": "X.X.X.X",
  "commands_executed": ["whoami", "ls -la", "cat /etc/passwd"],
  "persistence_attempted": false,
  "threat_level": "medium",
  "action_taken": "Analyzed and archived"
}
```

---

### 4. Unusual Service Access Pattern

**Trigger**: Access to multiple honeypot ports from single IP in short time

**Immediate Actions**:
```bash
# 1. Identify reconnaissance activity
GET honeypot-*/_search
{
  "query": {
    "match": { "src_ip": "X.X.X.X" }
  },
  "aggs": {
    "ports_accessed": {
      "terms": {
        "field": "dst_port",
        "size": 10
      }
    }
  }
}

# 2. Check for port scanning tools
GET honeypot-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "src_ip": "X.X.X.X" } },
        { "term": { "port_scan": true } }
      ]
    }
  }
}

# 3. Timeline of access
GET honeypot-*/_search
{
  "query": { "match": { "src_ip": "X.X.X.X" } },
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
```

**Investigation**:
- [ ] How many different ports accessed?
- [ ] In what order?
- [ ] Time between attempts?
- [ ] Is this a known scanner?

**Documentation**:
```json
{
  "incident_id": "INC-004",
  "date": "2026-06-16",
  "type": "reconnaissance",
  "attacker_ip": "X.X.X.X",
  "ports_scanned": [21, 22, 23, 80, 3306, 2222, 2223],
  "scan_type": "likely_nmap",
  "threat_level": "low",
  "action_taken": "Monitored for follow-up attacks"
}
```

---

## Response Workflow
