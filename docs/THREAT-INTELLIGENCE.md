# Threat Intelligence Integration

## Overview
Cross-reference attacker IPs against threat intelligence feeds to identify known malicious actors.

## Option 1: VirusTotal Integration

### Setup
```bash
# 1. Get free API key from: https://www.virustotal.com/gui/home/upload
# 2. Create Python script for enrichment

cat > /usr/local/bin/vt-enrichment.py << 'PYTHON'
#!/usr/bin/env python3
import requests
import sys
import os

VT_API_KEY = os.getenv('VT_API_KEY')
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses"

def check_ip(ip):
    """Check IP against VirusTotal"""
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_URL}/{ip}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        attributes = data['data']['attributes']
        return {
            'ip': ip,
            'reputation': attributes.get('reputation', 0),
            'last_analysis_stats': attributes.get('last_analysis_stats', {})
        }
    return None

if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = check_ip(sys.argv[1])
        if result:
            print(result)
PYTHON

chmod +x /usr/local/bin/vt-enrichment.py
```

### Usage in Logstash
```logstash
ruby {
  code => "
    require 'net/http'
    require 'json'
    
    ip = event.get('src_ip')
    if ip
      # Call VirusTotal API
      uri = URI('https://www.virustotal.com/api/v3/ip_addresses/' + ip)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      
      request = Net::HTTP::Get.new(uri)
      request['x-apikey'] = ENV['VT_API_KEY']
      
      response = http.request(request)
      if response.code == '200'
        data = JSON.parse(response.body)
        event.set('threat_intel', data['data']['attributes'])
      end
    end
  "
}
```

## Option 2: AbuseIPDB Integration

### Setup
```bash
# 1. Get free API key from: https://www.abuseipdb.com/api
# 2. Query for known malicious IPs

cat > /usr/local/bin/abuseipdb-check.sh << 'BASH'
#!/bin/bash
IP=$1
API_KEY=$2

curl -G "https://api.abuseipdb.com/api/v2/check" \
  --data-urlencode "ipAddress=$IP" \
  --data-urlencode "maxAgeInDays=90" \
  -H "Key: $API_KEY" \
  -H "Accept: application/json"
BASH

chmod +x /usr/local/bin/abuseipdb-check.sh
```

## Option 3: MISP Integration (Self-Hosted)

### Setup
```bash
# MISP = Malware Information Sharing Platform
# Self-hosted threat intelligence database

# Install MISP (advanced setup)
# Then configure Logstash to query MISP API

ruby {
  code => "
    require 'net/http'
    require 'json'
    
    ip = event.get('src_ip')
    misp_url = 'http://your-misp-instance/attributes/search'
    
    # Query MISP for IP
    # Add results to event
  "
}
```

## Kibana Dashboard Example

Create dashboard showing:
- Top malicious IPs (by threat score)
- Threat intel match percentage
- Attack timeline by threat level
- Country distribution of known threats

## Performance Considerations

- API calls add latency (~100-500ms per request)
- Implement caching to avoid repeated lookups
- Batch requests where possible
- Consider async processing for high volume

## Cost

| Service | Cost | Rate Limit |
|---------|------|-----------|
| VirusTotal | Free | 4 requests/min |
| AbuseIPDB | Free | 50 requests/day |
| MISP | Self-hosted | Unlimited |

## Implementation Priority

1. **Phase 2 (Now)**: Document options
2. **Phase 3 (AWS)**: Integrate one API (AbuseIPDB recommended)
3. **Phase 4**: Add multiple feeds + caching

