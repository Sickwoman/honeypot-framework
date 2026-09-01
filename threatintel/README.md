# Advanced Threat Intelligence Enricher

This directory contains a Node.js threat-intelligence enrichment utility for the honeypot framework. It goes beyond the Python-only integration by allowing enrichment from multiple reputation sources such as AbuseIPDB and VirusTotal without requiring a Python runtime for the enrichment step.

## Features

- Enriches attacker IPs with community abuse intelligence
- Checks VirusTotal reputation and malware signals
- Calculates a blended threat score using both feeds
- Produces structured JSON that can be merged into alerts
- Works as a standalone CLI or can be hooked into an alert pipeline

## Usage

### Single IP lookup

```bash
ABUSEIPDB_API_KEY=your_key VT_API_KEY=your_vt_key \
node threatintel/advanced-threat-intel.js --ip 8.8.8.8
```

### Batch file lookup

```bash
ABUSEIPDB_API_KEY=your_key VT_API_KEY=your_vt_key \
node threatintel/advanced-threat-intel.js --ips-file ips.txt --output threat-intel.json
```

### Enrich an alert JSON document

```bash
ABUSEIPDB_API_KEY=your_key VT_API_KEY=your_vt_key \
node threatintel/advanced-threat-intel.js --alert-file alert.json --output enriched-alert.json
```

## Output shape

```json
{
  "ip": "8.8.8.8",
  "threat_intel": {
    "ip": "8.8.8.8",
    "threat_score": 82,
    "threat_level": "HIGH",
    "threat_indicators": ["blacklisted", "high_abuse_confidence"],
    "providers": {
      "abuseipdb": { "confidence_score": 90 },
      "virustotal": { "malicious": 1 }
    }
  }
}
```

## Notes

- If a provider key is missing, the script still runs with the remaining provider data.
- Both providers are treated as optional, so the module degrades gracefully in partially configured environments.
- The output can be fed into the Python alerting layer as enriched metadata.
